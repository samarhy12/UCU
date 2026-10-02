import hashlib
from datetime import datetime

from flask import (Blueprint, current_app, flash, redirect, render_template, request, session,
                   url_for)
from flask_login import current_user, login_required, login_user, logout_user
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func

from extensions import db
from mailer import send_email
from models import User, log_action, utcnow
from routes import home_for
from security import is_safe_redirect
from services import members as member_service

bp = Blueprint("auth", __name__)


# ---------------------------------------------------------------------------
# Sign in and out (one page for administrators and members)
# ---------------------------------------------------------------------------
@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(home_for(current_user))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        remember = request.form.get("remember") == "on"
        user = User.query.filter(func.lower(User.email) == email).first() if email else None

        if user and user.is_locked:
            minutes = max(1, int((user.locked_until - utcnow()).total_seconds() // 60) + 1)
            flash("This account is locked for a short time after too many wrong passwords. "
                  f"Try again in about {minutes} minute{'s' if minutes != 1 else ''}.", "error")
            return render_template("auth/login.html", email=email)

        if user is None or not user.check_password(password):
            if user is not None and user.password_hash:
                user.register_failed_login(current_app.config["LOGIN_MAX_ATTEMPTS"],
                                           current_app.config["LOGIN_LOCKOUT_MINUTES"])
                db.session.commit()
            flash("Incorrect email or password.", "error")
            return render_template("auth/login.html", email=email)

        if not user.is_active:
            flash("Your membership is not active. Please contact the UCU administrator.", "error")
            return render_template("auth/login.html", email=email)

        user.register_successful_login()
        db.session.commit()
        session.clear()
        login_user(user, remember=remember)
        session.permanent = True
        # Set initial session activity timestamp
        session['last_activity'] = datetime.now().isoformat()

        nxt = request.args.get("next") or request.form.get("next")
        if nxt and is_safe_redirect(nxt):
            return redirect(nxt)
        return redirect(home_for(user))

    return render_template("auth/login.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    session.pop('last_activity', None)
    flash("You have been signed out.", "info")
    return redirect(url_for("public.home"))


# ---------------------------------------------------------------------------
# Membership registration
# ---------------------------------------------------------------------------
@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(home_for(current_user))

    if request.method == "GET":
        return render_template("auth/register.html", form={}, regions=member_service.GHANA_REGIONS)

    form = request.form
    values, errors = member_service.clean_member_details(form)
    errors += member_service.check_password_rules(form.get("password", ""), form.get("confirm_password", ""))

    # Someone who only applied for a non-member loan before may now become a member.
    by_email, by_id = member_service.find_conflicts(values["email"], values["national_id"])
    existing = None
    for match in (by_email, by_id):
        if match is not None:
            if not match.is_guest:
                if match is by_email:
                    errors.append("This email is already registered. Try signing in.")
                else:
                    errors.append("This Ghana Card number is already registered.")
            elif existing is None:
                existing = match
    if by_email is not None and by_id is not None and by_email.id != by_id.id:
        errors.append("This email and Ghana Card number belong to different records. Please contact UCU.")

    id_file = photo = None
    if not errors:
        id_file, photo, file_errors = member_service.save_member_files(request.files)
        errors += file_errors

    if errors:
        for message in dict.fromkeys(errors):
            flash(message, "error")
        return render_template("auth/register.html", form=form, regions=member_service.GHANA_REGIONS), 400

    user = existing or User()
    member_service.apply_details(user, values)
    user.set_password(form["password"])
    user.is_guest = False
    user.is_admin = False
    user.is_verified = False
    user.is_active_member = True
    user.profile_locked = True  # Lock new user profiles by default
    if user.id:                                   # an earlier non-member applicant: replace the old files
        member_service.delete_member_files(user)
    else:
        user.created_at = utcnow()
    user.national_id_file = id_file
    user.passport_photo = photo
    db.session.add(user)
    db.session.commit()

    send_email("Your Unity Credit Union sign-up is waiting for verification", user.email,
               "account_created", user=user)
    send_email("New membership sign-up to verify", current_app.config["ADMIN_EMAIL"],
               "admin_new_signup", user=user, review_url=url_for("admin.member_detail", user_id=user.id, _external=True))

    flash("Thank you for signing up. Your details have been sent to the administrator to verify. "
          "We sent a message to your email. You will get another one as soon as this is done.", "success")
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------------
# Forgotten password
# ---------------------------------------------------------------------------
def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="ucu-password-reset")


def _password_fingerprint(user):
    return hashlib.sha256((user.password_hash or "").encode()).hexdigest()[:16]


def make_reset_token(user):
    return _serializer().dumps({"id": user.id, "h": _password_fingerprint(user)})


def user_from_reset_token(token):
    try:
        data = _serializer().loads(token, max_age=current_app.config["RESET_TOKEN_MAX_AGE"])
    except (BadSignature, SignatureExpired):
        return None
    user = db.session.get(User, data.get("id"))
    # The fingerprint stops a link from being used twice: it stops matching once the password changes.
    if user is None or data.get("h") != _password_fingerprint(user) or not user.is_active:
        return None
    return user


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        user = User.query.filter(func.lower(User.email) == email).first() if email else None
        if user and user.password_hash and user.is_active:
            reset_url = url_for("auth.reset_password", token=make_reset_token(user), _external=True)
            send_email("Reset your Unity Credit Union password", user.email,
                       "password_reset_request", user=user, reset_url=reset_url)
        flash("If that email belongs to a UCU account, we have sent a link to reset the password.", "success")
        return redirect(url_for("auth.login"))
    return render_template("auth/forgot_password.html")


@bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = user_from_reset_token(token)
    if user is None:
        flash("This reset link is not valid any more. Please ask for a new one.", "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        errors = member_service.check_password_rules(request.form.get("password", ""),
                                                     request.form.get("confirm_password", ""))
        if errors:
            for message in errors:
                flash(message, "error")
            return render_template("auth/reset_password.html", token=token), 400
        user.set_password(request.form["password"])
        user.must_change_password = False
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()
        send_email("Your Unity Credit Union password was changed", user.email,
                   "password_reset_confirmation", user=user)
        flash("Your password has been changed. Please sign in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("auth/reset_password.html", token=token)


# ---------------------------------------------------------------------------
# Change password (also used when the administrator has issued a temporary one)
# ---------------------------------------------------------------------------
@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    forced = current_user.must_change_password
    if request.method == "POST":
        errors = []
        if not current_user.check_password(request.form.get("current_password", "")):
            errors.append("Your current password is not correct.")
        new_pw = request.form.get("new_password", "")
        errors += member_service.check_password_rules(new_pw, request.form.get("confirm_password", ""))
        if new_pw and current_user.check_password(new_pw):
            errors.append("Your new password must be different from the current one.")
        if errors:
            for message in errors:
                flash(message, "error")
            return render_template("auth/change_password.html", forced=forced), 400
        current_user.set_password(new_pw)
        current_user.must_change_password = False
        db.session.commit()
        flash("Your password has been changed.", "success")
        return redirect(home_for(current_user))
    return render_template("auth/change_password.html", forced=forced)
