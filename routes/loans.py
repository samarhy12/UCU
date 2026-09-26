from flask import (Blueprint, abort, current_app, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required
from sqlalchemy import func

import rules
from extensions import db
from image_utils import delete_upload
from mailer import send_email
from models import Loan, User, utcnow, log_action
from routes import member_required
from security import throttle
from services import loans as loan_service
from services import members as member_service

bp = Blueprint("loans", __name__)


def _loan_types_payload(audience):
    return [{"key": key, "label": info["label"], "days": info["days"], "rate": info["rate"],
             "description": info["description"]} for key, info in loan_service.available_loan_types(audience)]


def _notify_new_loan(loan):
    """E-mails after a loan application was saved: applicant, guarantors, administrator."""
    applicant = loan.user
    send_email("We received your loan application", applicant.email, "loan_received", loan=loan, user=applicant)

    # Notify first guarantor (UCU member)
    if loan.guarantor:
        send_email("You were named as a loan guarantor", loan.guarantor.email, "guarantor_notice",
                   loan=loan, guarantor=loan.guarantor, applicant=applicant)

    # Notify second guarantor (may be non-member)
    if loan.guarantor2_id:
        second_guarantor = User.query.get(loan.guarantor2_id)
        if second_guarantor:
            send_email("You were named as a loan guarantor", second_guarantor.email, "guarantor_notice",
                       loan=loan, guarantor=second_guarantor, applicant=applicant)
    elif loan.guarantor2_email:
        # Non-member guarantor with email
        class NonMemberGuarantor:
            def __init__(self, email):
                self.email = email
                self.first_name = loan.guarantor2_name.split()[0] if loan.guarantor2_name else "Guarantor"
                self.display_name = loan.guarantor2_name or "Non-Member Guarantor"

        non_member = NonMemberGuarantor(loan.guarantor2_email)
        send_email("You were named as a loan guarantor", loan.guarantor2_email, "guarantor_notice",
                   loan=loan, guarantor=non_member, applicant=applicant)

    send_email("New loan application to verify", current_app.config["ADMIN_EMAIL"], "admin_new_loan",
               loan=loan, review_url=url_for("admin.loan_detail", loan_id=loan.id, _external=True))


# ---------------------------------------------------------------------------
# Member loan portal
# ---------------------------------------------------------------------------
@bp.route("/loans")
@member_required
def portal():
    loans = Loan.query.filter_by(user_id=current_user.id).order_by(Loan.id.desc()).all()
    return render_template("loans/portal.html", loans=loans, open_loan=current_user.open_loan,
                           types=loan_service.available_loan_types("member"))


@bp.route("/loans/new", methods=["GET", "POST"])
@member_required
def new_loan():
    if request.method == "POST":
        loan, errors = loan_service.build_loan(request.form, current_user, "member")
        if errors:
            for message in dict.fromkeys(errors):
                flash(message, "error")
            return render_template("loans/form.html", form=request.form, guest=False,
                                   types=_loan_types_payload("member")), 400
        loan.user_id = current_user.id
        db.session.add(loan)
        db.session.flush()
        loan_service.assign_reference(loan)
        db.session.commit()
        _notify_new_loan(loan)
        flash(f"Your loan application was sent. Your reference is {loan.reference}.", "success")
        return redirect(url_for("loans.view_loan", loan_id=loan.id))

    return render_template("loans/form.html", form={"loan_type": request.args.get("type", "")},
                           guest=False, types=_loan_types_payload("member"))


@bp.route("/loans/<int:loan_id>")
@login_required
def view_loan(loan_id):
    loan = db.get_or_404(Loan, loan_id)
    if current_user.is_admin:
        return redirect(url_for("admin.loan_detail", loan_id=loan.id))
    if loan.user_id != current_user.id:
        abort(403)
    payments = [p for p in loan.payments if not p.is_reversed]
    return render_template("loans/view.html", loan=loan, payments=payments)


@bp.route("/loans/<int:loan_id>/cancel", methods=["POST"])
@member_required
def cancel_loan(loan_id):
    loan = db.get_or_404(Loan, loan_id)
    if loan.user_id != current_user.id:
        abort(403)
    if loan.status != "pending":
        flash("Only a loan that is still waiting for a decision can be cancelled.", "error")
        return redirect(url_for("loans.view_loan", loan_id=loan.id))
    loan.cancel()
    log_action(current_user, "loan_cancelled", loan.reference, "Cancelled by the member")
    db.session.commit()
    flash("Your loan application has been cancelled.", "success")
    return redirect(url_for("loans.portal"))


@bp.route("/loans/history")
@member_required
def history():
    paid = Loan.get_paid_loans(current_user.id)
    return render_template("loans/history.html", loans=paid)


# ---------------------------------------------------------------------------
# NMLOAN: loans for people who are not members
# ---------------------------------------------------------------------------
@bp.route("/guest-loan-application")
def old_guest_link():
    return redirect(url_for("loans.non_member_loan"), code=301)


@bp.route("/nmloan", methods=["GET", "POST"])
def non_member_loan():
    types = _loan_types_payload("guest")
    if request.method == "GET":
        return render_template("loans/form.html", form={}, guest=True, types=types,
                               regions=member_service.GHANA_REGIONS)

    form = request.form
    values, errors = member_service.clean_member_details(form, guest=True)

    by_email, by_id = member_service.find_conflicts(values["email"], values["national_id"])
    existing = None
    for match in (by_email, by_id):
        if match is None:
            continue
        if not match.is_guest:
            errors.append("This email or Ghana Card number belongs to a UCU member. "
                          "Please sign in and use the member loan form.")
            break
        existing = existing or match
    if by_email is not None and by_id is not None and by_email.id != by_id.id:
        errors.append("This email and Ghana Card number belong to different records. Please contact UCU.")

    loan = None
    if not errors:
        loan, loan_errors = loan_service.build_loan(form, existing, "guest")
        errors += loan_errors

    id_file = photo = None
    if not errors:
        id_file, photo, file_errors = member_service.save_member_files(
            request.files,
            id_required=not (existing and existing.national_id_file),
            photo_required=not (existing and existing.passport_photo))
        errors += file_errors

    if errors:
        for message in dict.fromkeys(errors):
            flash(message, "error")
        return render_template("loans/form.html", form=form, guest=True, types=types,
                               regions=member_service.GHANA_REGIONS), 400

    applicant = existing or User(is_guest=True, is_verified=False, is_admin=False, created_at=utcnow())
    member_service.apply_details(applicant, values, guest=True)
    folder = current_app.config["UPLOAD_FOLDER"]
    if id_file:
        delete_upload(applicant.national_id_file, folder)     # replace an older file, if any
        applicant.national_id_file = id_file
    if photo:
        delete_upload(applicant.passport_photo, folder)
        applicant.passport_photo = photo
    db.session.add(applicant)
    db.session.flush()

    loan.user_id = applicant.id
    db.session.add(loan)
    db.session.flush()
    loan_service.assign_reference(loan)
    db.session.commit()
    _notify_new_loan(loan)

    flash(f"Your loan application was sent. Your reference is {loan.reference}. "
          "Keep it safe. You can use it to check your loan on the Verify loan page.", "success")
    return redirect(url_for("loans.verify"))


# ---------------------------------------------------------------------------
# Verify a loan: look up its status with the reference number
# ---------------------------------------------------------------------------
@bp.route("/loans/verify", methods=["GET", "POST"])
def verify():
    result = None
    reference = ""
    if request.method == "POST":
        reference = (request.form.get("reference") or "").strip().upper()
        contact = (request.form.get("contact") or "").strip()
        if throttle(f"verify:{request.remote_addr}", 10, 600):
            flash("Too many tries. Please wait a few minutes and try again.", "error")
        elif not reference or not contact:
            flash("Enter the loan reference and your email or phone number.", "error")
        else:
            loan = Loan.query.filter(func.upper(Loan.reference) == reference).first()
            owner = loan.user if loan else None
            same = bool(owner) and ((owner.email or "").lower() == contact.lower() or
                                    (rules.valid_phone(contact) and
                                     rules.phone_digits(owner.phone_number) == rules.phone_digits(contact)))
            if same:
                result = loan
            else:
                flash("We could not find a loan with those details. Please check and try again.", "error")
    return render_template("loans/verify.html", result=result, reference=reference)


# ---------------------------------------------------------------------------
# Guarantor check used by the loan form (shows a hidden version of the name)
# ---------------------------------------------------------------------------
@bp.route("/api/guarantor")
def guarantor_lookup():
    if throttle(f"guarantor:{request.remote_addr}", 30, 60):
        return jsonify({"found": False, "error": "Too many checks. Please wait a moment."}), 429
    guarantor = loan_service.find_guarantor_by_ucu_number(request.args.get("ucu", ""))
    if guarantor is None:
        return jsonify({"found": False})
    return jsonify({"found": True, "name": rules.mask_name(guarantor.display_name)})


# ---------------------------------------------------------------------------
# Display guarantor agreement form for printing
# ---------------------------------------------------------------------------
@bp.route("/loans/guarantor-form", methods=["POST"])
def guarantor_form():
    """Display guarantor agreement form for printing/saving as PDF."""
    from datetime import datetime

    form = request.form

    # Build context for template
    applicant_name = f"{form.get('first_name', '')} {form.get('last_name', '')} {form.get('other_names', '')}".strip()
    applicant_email = form.get('email', '')
    applicant_phone = form.get('phone_number', '')
    loan_amount = form.get('amount', '')
    loan_purpose = form.get('purpose', '')

    g1_name = form.get('g1_name', '')
    g1_email = form.get('g1_email', '')
    g1_phone = form.get('g1_phone', '')
    g1_ucu_number = form.get('g1_ucu_number', '')
    g1_earnings = form.get('g1_earnings', '')

    g2_name = form.get('g2_name', '')
    g2_email = form.get('g2_email', '')
    g2_phone = form.get('g2_phone', '')
    g2_ucu_number = form.get('g2_ucu_number', '')
    g2_earnings = form.get('g2_earnings', '')

    return render_template('loans/guarantor_pdf.html',
                           applicant_name=applicant_name,
                           applicant_email=applicant_email,
                           applicant_phone=applicant_phone,
                           loan_amount=loan_amount,
                           loan_purpose=loan_purpose,
                           g1_name=g1_name,
                           g1_email=g1_email,
                           g1_phone=g1_phone,
                           g1_ucu_number=g1_ucu_number,
                           g1_earnings=g1_earnings,
                           g2_name=g2_name,
                           g2_email=g2_email,
                           g2_phone=g2_phone,
                           g2_ucu_number=g2_ucu_number,
                           g2_earnings=g2_earnings,
                           current_date=datetime.now().strftime("%B %d, %Y"))
