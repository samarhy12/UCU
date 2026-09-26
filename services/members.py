"""Shared member logic used by registration, the administrator screens and the non-member loan form."""
import secrets
import string
from datetime import date, datetime

from flask import current_app
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

import rules
from extensions import db
from image_utils import INVALID, TOO_LARGE, delete_upload, save_document, validate_and_save_image
from models import User, utcnow

COMMON_FIELDS = ["email", "first_name", "last_name", "other_names", "date_of_birth", "national_id",
                 "occupation", "phone_number", "address", "city", "state", "country"]
MEMBER_ONLY_FIELDS = ["hometown", "introducer", "nok_name", "nok_phone", "nok_relationship"]

FIELD_LABELS = {
    "email": "Email", "first_name": "First name", "last_name": "Last name",
    "date_of_birth": "Date of birth", "national_id": "Ghana Card number", "occupation": "Occupation",
    "phone_number": "Phone number", "address": "Address", "city": "Place of living",
    "state": "Region", "country": "Country", "hometown": "Hometown",
    "nok_name": "Next of kin full name", "nok_phone": "Next of kin phone number",
    "nok_relationship": "Relationship to next of kin",
}
REQUIRED_MEMBER = ["email", "first_name", "last_name", "date_of_birth", "national_id", "occupation",
                   "phone_number", "address", "hometown", "city", "state", "country",
                   "nok_name", "nok_phone", "nok_relationship"]
REQUIRED_GUEST = ["email", "first_name", "last_name", "date_of_birth", "national_id", "occupation",
                  "phone_number", "address", "city", "state", "country"]
MAX_LENGTHS = {"email": 120, "first_name": 50, "last_name": 50, "other_names": 50, "occupation": 100,
               "phone_number": 20, "address": 200, "city": 100, "state": 100, "country": 100,
               "hometown": 100, "introducer": 150, "nok_name": 120, "nok_phone": 30,
               "nok_relationship": 50}

GHANA_REGIONS = [
    "Greater Accra", "Ashanti", "Eastern", "Central", "Western", "Western North", "Volta", "Oti",
    "Northern", "Savannah", "North East", "Upper East", "Upper West", "Bono", "Bono East", "Ahafo",
]


def clean_member_details(form, guest=False):
    """Read and check the personal details in a form. Returns (values, errors)."""
    fields = COMMON_FIELDS + ([] if guest else MEMBER_ONLY_FIELDS)
    values = {f: (form.get(f) or "").strip() for f in fields}
    errors = []

    for field in (REQUIRED_GUEST if guest else REQUIRED_MEMBER):
        if not values.get(field):
            errors.append(f"{FIELD_LABELS.get(field, field)} is required.")
    for field, limit in MAX_LENGTHS.items():
        if len(values.get(field, "")) > limit:
            errors.append(f"{FIELD_LABELS.get(field, field)} is too long (most {limit} characters).")

    values["email"] = values["email"].lower()
    if values["email"] and not rules.valid_email(values["email"]):
        errors.append("Enter a valid email address.")

    if values["phone_number"] and not rules.valid_phone(values["phone_number"]):
        errors.append("Enter a valid phone number, for example 0241234567.")
    if not guest and values.get("nok_phone") and not rules.valid_phone(values["nok_phone"]):
        errors.append("Enter a valid phone number for your next of kin.")

    if values["national_id"]:
        card = rules.normalize_ghana_card(values["national_id"])
        if card:
            values["national_id"] = card
        else:
            errors.append("Enter your Ghana Card number like GHA-123456789-0.")

    dob = None
    if values["date_of_birth"]:
        try:
            dob = datetime.strptime(values["date_of_birth"], "%Y-%m-%d").date()
            if dob > date.today():
                errors.append("Date of birth cannot be in the future.")
                dob = None
            elif rules.age_on(dob) < current_app.config["MINIMUM_MEMBER_AGE"]:
                errors.append(f"You must be at least {current_app.config['MINIMUM_MEMBER_AGE']} years old.")
        except ValueError:
            errors.append("Enter a valid date of birth.")
    values["dob"] = dob
    return values, errors


def check_password_rules(password, confirm):
    minimum = current_app.config["PASSWORD_MIN_LENGTH"]
    errors = []
    if len(password or "") < minimum:
        errors.append(f"Password must be at least {minimum} characters.")
    if password != confirm:
        errors.append("Password and confirm password do not match.")
    return errors


def save_member_files(files, id_required=True, photo_required=True):
    """Save the Ghana Card and passport photo uploads.

    Returns (id_file, photo_file, errors). Files saved before an error are removed again.
    """
    cfg = current_app.config
    folder = cfg["UPLOAD_FOLDER"]
    max_bytes = cfg["MAX_UPLOAD_MB"] * 1024 * 1024
    errors, id_file, photo = [], None, None

    card = files.get("national_id_upload")
    if card and card.filename:
        id_file = save_document(card, "id", folder, cfg["ALLOWED_DOCUMENT_EXTENSIONS"], max_bytes)
        if id_file == INVALID:
            errors.append("The Ghana Card file must be a real image (JPG, PNG) or a PDF.")
            id_file = None
        elif id_file == TOO_LARGE:
            errors.append(f"The Ghana Card file must not be more than {cfg['MAX_UPLOAD_MB']} MB.")
            id_file = None
    elif id_required:
        errors.append("Please upload your Ghana Card (image or PDF).")

    pic = files.get("passport_photo")
    if pic and pic.filename:
        photo = validate_and_save_image(pic, "photo", folder, cfg["ALLOWED_IMAGE_EXTENSIONS"],
                                        max_dimension=1200, max_bytes=max_bytes)
        if photo == INVALID:
            errors.append("The passport photo must be a real image (JPG or PNG).")
            photo = None
        elif photo == TOO_LARGE:
            errors.append(f"The passport photo must not be more than {cfg['MAX_UPLOAD_MB']} MB.")
            photo = None
    elif photo_required:
        errors.append("Please upload your passport photo.")

    if errors:
        delete_upload(id_file, folder)
        delete_upload(photo, folder)
        return None, None, errors
    return id_file, photo, []


def delete_member_files(user):
    folder = current_app.config["UPLOAD_FOLDER"]
    delete_upload(user.national_id_file, folder)
    delete_upload(user.passport_photo, folder)


def find_conflicts(email, national_id, ignore_user_id=None):
    """Look for someone who already uses this email or Ghana Card number.

    Returns (by_email, by_national_id): the matching User rows, or None.
    """
    by_email = User.query.filter(func.lower(User.email) == email.lower()).first() if email else None
    by_id = User.query.filter_by(national_id=national_id).first() if national_id else None
    if ignore_user_id:
        by_email = by_email if by_email and by_email.id != ignore_user_id else None
        by_id = by_id if by_id and by_id.id != ignore_user_id else None
    return by_email, by_id


def apply_details(user, values, guest=False):
    user.email = values["email"]
    user.first_name = values["first_name"]
    user.last_name = values["last_name"]
    user.other_names = values["other_names"] or None
    user.date_of_birth = values["dob"]
    user.national_id = values["national_id"]
    user.occupation = values["occupation"]
    user.phone_number = values["phone_number"]
    user.address = values["address"]
    user.city = values["city"]
    user.state = values["state"]
    user.country = values["country"]
    if not guest:
        user.hometown = values["hometown"]
        user.introducer = values["introducer"] or None
        user.nok_name = values["nok_name"]
        user.nok_phone = values["nok_phone"]
        user.nok_relationship = values["nok_relationship"]


def temporary_password(length=10):
    alphabet = string.ascii_letters.replace("l", "").replace("I", "").replace("O", "") + string.digits.replace("0", "")
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------------------------------------------------------------------------
# Verification and account numbers
# ---------------------------------------------------------------------------
def next_member_number():
    return (db.session.query(func.coalesce(func.max(User.member_number), 0)).scalar() or 0) + 1


def verify_member(user, when=None):
    """Mark a member as verified and give them an account number.

    The number is UCU + year + month + member number, for example UCU240822 for the 22nd member,
    verified in August 2024. Returns True when the account was verified.
    """
    when = when or utcnow()
    if user.is_verified and user.account_number:
        return False

    for _ in range(5):
        number = next_member_number()
        account = rules.format_account_number(when.year, when.month, number)
        if User.query.filter_by(account_number=account).first():
            number += 1
            account = rules.format_account_number(when.year, when.month, number)
        user.member_number = number
        user.account_number = account
        user.is_verified = True
        user.verified_at = when
        try:
            db.session.flush()
            return True
        except IntegrityError:
            db.session.rollback()
            db.session.add(user)
    raise RuntimeError("Could not create a unique account number")


def total_members():
    """Verified members that are still active."""
    return (User.query.filter(User.is_verified == True, User.is_admin == False,  # noqa: E712
                              User.is_guest == False, User.is_active_member == True).count())  # noqa: E712


def total_signups():
    """Everyone who has signed up as a member (verified, waiting, or exited)."""
    return User.query.filter(User.is_admin == False, User.is_guest == False).count()  # noqa: E712
