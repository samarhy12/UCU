from flask import (abort, current_app, flash, redirect, render_template, request, url_for)
from flask_login import current_user
from sqlalchemy import func, or_

import rules
from extensions import db
from image_utils import delete_upload
from mailer import send_email
from models import (Contribution, Dividend, Loan, LoanPayment, MonthlySavingsTarget, User, log_action,
                    utcnow)
from pagination_utils import paginate
from routes import admin_required
from services import members as member_service

from . import bp

STATUS_FILTERS = [("all", "All"), ("active", "Active"), ("pending", "Waiting for verification"),
                  ("inactive", "Exited"), ("guests", "Non-members")]


def _member_or_404(user_id):
    user = db.get_or_404(User, user_id)
    if user.is_admin:
        abort(404)
    return user


def _form_from_user(user):
    """The member's details in the same shape as a submitted form."""
    data = {f: getattr(user, f, None) or "" for f in member_service.COMMON_FIELDS + member_service.MEMBER_ONLY_FIELDS}
    data["date_of_birth"] = user.date_of_birth.isoformat() if user.date_of_birth else ""
    return data


def _open_loans_of(user):
    return (Loan.query.filter(Loan.user_id == user.id)
            .filter((Loan.status == "pending") | ((Loan.status == "approved") & (Loan.remaining_amount > 0)))
            .all())


def _guaranteed_open_loans(user):
    return (Loan.query.filter((Loan.guarantor_id == user.id) | (Loan.guarantor2_id == user.id))
            .filter((Loan.status == "pending") | ((Loan.status == "approved") & (Loan.remaining_amount > 0)))
            .all())


# ---------------------------------------------------------------------------
# List and search
# ---------------------------------------------------------------------------
@bp.route("/members")
@admin_required
def members_list():
    status = request.args.get("status", "all")
    q = (request.args.get("q") or "").strip()

    query = User.query.filter(User.is_admin == False)      # noqa: E712
    if status == "guests":
        query = query.filter(User.is_guest == True)         # noqa: E712
    else:
        query = query.filter(User.is_guest == False)         # noqa: E712
        if status == "active":
            query = query.filter(User.is_verified == True, User.is_active_member == True)   # noqa: E712
        elif status == "pending":
            query = query.filter(User.is_verified == False, User.is_active_member == True)   # noqa: E712
        elif status == "inactive":
            query = query.filter(User.is_active_member == False)                              # noqa: E712
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.first_name.ilike(like), User.last_name.ilike(like),
                                 User.other_names.ilike(like), User.email.ilike(like),
                                 User.phone_number.ilike(like), User.account_number.ilike(like),
                                 User.national_id.ilike(like)))
    pagination = paginate(query.order_by(User.first_name, User.last_name))
    counts = {
        "active": User.query.filter(User.is_admin == False, User.is_guest == False, User.is_verified == True,   # noqa: E712
                                    User.is_active_member == True).count(),                                     # noqa: E712
        "pending": User.query.filter(User.is_admin == False, User.is_guest == False, User.is_verified == False,  # noqa: E712
                                     User.is_active_member == True).count(),                                     # noqa: E712
    }
    return render_template("admin/members.html", pagination=pagination, members=pagination.items,
                           status=status, q=q, filters=STATUS_FILTERS, counts=counts,
                           query_params={k: v for k, v in (("status", status), ("q", q)) if v and v != "all"})


# ---------------------------------------------------------------------------
# Add and edit
# ---------------------------------------------------------------------------
@bp.route("/members/new", methods=["GET", "POST"])
@admin_required
def member_new():
    """The administrator adds a member directly. The account is verified at once."""
    if request.method == "GET":
        return render_template("admin/member_form.html", form={}, editing=False,
                               regions=member_service.GHANA_REGIONS)

    values, errors = member_service.clean_member_details(request.form)
    by_email, by_id = member_service.find_conflicts(values["email"], values["national_id"])
    if by_email:
        errors.append("This email is already registered.")
    if by_id:
        errors.append("This Ghana Card number is already registered.")

    id_file = photo = None
    if not errors:
        id_file, photo, file_errors = member_service.save_member_files(
            request.files, id_required=False, photo_required=False)
        errors += file_errors
    if errors:
        for message in dict.fromkeys(errors):
            flash(message, "error")
        return render_template("admin/member_form.html", form=request.form, editing=False,
                               regions=member_service.GHANA_REGIONS), 400

    user = User(is_guest=False, is_admin=False, is_active_member=True, created_at=utcnow(),
                national_id_file=id_file, passport_photo=photo)
    member_service.apply_details(user, values)
    temp = member_service.temporary_password()
    user.set_password(temp)
    user.must_change_password = True
    db.session.add(user)
    db.session.flush()
    member_service.verify_member(user)
    log_action(current_user, "member_added", user.account_number, user.display_name)
    db.session.commit()

    send_email("Welcome to Unity Credit Union", user.email, "account_added_by_admin", user=user,
               temp_password=temp)
    return render_template("admin/temp_password.html", user=user, temp_password=temp, is_new=True)


@bp.route("/members/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def member_edit(user_id):
    user = _member_or_404(user_id)
    if request.method == "GET":
        return render_template("admin/member_form.html", form=_form_from_user(user), editing=True, member=user,
                               regions=member_service.GHANA_REGIONS)

    values, errors = member_service.clean_member_details(request.form, guest=user.is_guest)
    by_email, by_id = member_service.find_conflicts(values["email"], values["national_id"], ignore_user_id=user.id)
    if by_email:
        errors.append("Another person already uses this email.")
    if by_id:
        errors.append("Another person already uses this Ghana Card number.")

    id_file = photo = None
    if not errors:
        id_file, photo, file_errors = member_service.save_member_files(
            request.files, id_required=False, photo_required=False)
        errors += file_errors
    if errors:
        for message in dict.fromkeys(errors):
            flash(message, "error")
        return render_template("admin/member_form.html", form=request.form, editing=True, member=user,
                               regions=member_service.GHANA_REGIONS), 400

    member_service.apply_details(user, values, guest=user.is_guest)
    folder = current_app.config["UPLOAD_FOLDER"]
    if id_file:
        delete_upload(user.national_id_file, folder)
        user.national_id_file = id_file
    if photo:
        delete_upload(user.passport_photo, folder)
        user.passport_photo = photo
    log_action(current_user, "member_edited", user.account_number or user.email, user.display_name)
    db.session.commit()
    flash("Member details saved.", "success")
    return redirect(url_for("admin.member_detail", user_id=user.id))


# ---------------------------------------------------------------------------
# Member page
# ---------------------------------------------------------------------------
@bp.route("/members/<int:user_id>")
@admin_required
def member_detail(user_id):
    user = _member_or_404(user_id)
    start_year = rules.cycle_start_year_for(utcnow().date())
    loans = Loan.query.filter_by(user_id=user.id).order_by(Loan.id.desc()).all()
    guaranteed = (Loan.query.filter((Loan.guarantor_id == user.id) | (Loan.guarantor2_id == user.id))
                  .order_by(Loan.id.desc()).all())
    recent = (Contribution.query.filter_by(user_id=user.id)
              .order_by(Contribution.date.desc(), Contribution.id.desc()).limit(10).all())
    return render_template("admin/member_detail.html", member=user, loans=loans, guaranteed=guaranteed,
                           recent=recent, total_savings=user.total_contributions(),
                           cycle_savings=user.cycle_contributions(start_year),
                           cycle_label=rules.cycle_label(start_year), target=user.monthly_target,
                           active_loan=user.active_loan)


# ---------------------------------------------------------------------------
# Verify or deny a sign-up
# ---------------------------------------------------------------------------
@bp.route("/members/<int:user_id>/verify", methods=["POST"])
@admin_required
def member_verify(user_id):
    user = _member_or_404(user_id)
    if user.is_guest:
        abort(400)
    if user.is_verified:
        flash("This member is already verified.", "info")
        return redirect(url_for("admin.member_detail", user_id=user.id))
    member_service.verify_member(user)
    log_action(current_user, "member_verified", user.account_number, user.display_name)
    db.session.commit()
    send_email("Your Unity Credit Union account has been verified", user.email, "account_verified", user=user)
    flash(f"{user.display_name} is now a member. Account number: {user.account_number}. "
          "An email was sent to them.", "success")
    return redirect(url_for("admin.members_list", status="pending"))


@bp.route("/members/<int:user_id>/deny", methods=["POST"])
@admin_required
def member_deny(user_id):
    """Deny a sign-up. The person is told by email and the sign-up is removed so they can apply again."""
    user = _member_or_404(user_id)
    if user.is_guest or user.is_verified:
        flash("Only a sign-up that is waiting for verification can be denied.", "error")
        return redirect(url_for("admin.member_detail", user_id=user.id))
    if Loan.query.filter((Loan.user_id == user.id) | (Loan.guarantor_id == user.id)
                         | (Loan.guarantor2_id == user.id)).count():
        flash("This person has loan records, so the sign-up cannot be removed.", "error")
        return redirect(url_for("admin.member_detail", user_id=user.id))

    reason = (request.form.get("reason") or "").strip()[:300]
    name, email = user.display_name, user.email
    member_service.delete_member_files(user)
    log_action(current_user, "signup_denied", email, f"{name}. {reason}")
    db.session.delete(user)
    db.session.commit()
    send_email("Your Unity Credit Union sign-up could not be verified", email, "account_denied",
               user_name=name, reason=reason)
    flash(f"The sign-up of {name} was denied and they were told by email.", "success")
    return redirect(url_for("admin.members_list", status="pending"))


# ---------------------------------------------------------------------------
# Exit, come back, delete
# ---------------------------------------------------------------------------
@bp.route("/members/<int:user_id>/deactivate", methods=["POST"])
@admin_required
def member_deactivate(user_id):
    user = _member_or_404(user_id)
    blockers = _open_loans_of(user)
    if blockers:
        flash("This member has a loan that is not finished. Finish or cancel it before they exit.", "error")
        return redirect(url_for("admin.member_detail", user_id=user.id))
    if _guaranteed_open_loans(user):
        flash("This member is a guarantor on a loan that is not finished, so they cannot exit yet.", "error")
        return redirect(url_for("admin.member_detail", user_id=user.id))
    user.is_active_member = False
    user.deactivated_at = utcnow()
    log_action(current_user, "member_exited", user.account_number or user.email, user.display_name)
    db.session.commit()
    send_email("Your Unity Credit Union membership has ended", user.email, "membership_status", user=user,
               active=False)
    flash(f"{user.display_name} is now marked as exited.", "success")
    return redirect(url_for("admin.member_detail", user_id=user.id))


@bp.route("/members/<int:user_id>/activate", methods=["POST"])
@admin_required
def member_activate(user_id):
    user = _member_or_404(user_id)
    user.is_active_member = True
    user.deactivated_at = None
    log_action(current_user, "member_reactivated", user.account_number or user.email, user.display_name)
    db.session.commit()
    send_email("Welcome back to Unity Credit Union", user.email, "membership_status", user=user, active=True)
    flash(f"{user.display_name} is active again.", "success")
    return redirect(url_for("admin.member_detail", user_id=user.id))


@bp.route("/members/<int:user_id>/delete", methods=["POST"])
@admin_required
def member_delete(user_id):
    """Remove a member who has died. Loans of other people that they guaranteed keep their history."""
    user = _member_or_404(user_id)
    if (request.form.get("confirm") or "").strip().upper() != "DELETE":
        flash("To delete a member, type DELETE in the box.", "error")
        return redirect(url_for("admin.member_detail", user_id=user.id))
    if _open_loans_of(user):
        flash("This member has a loan that is not finished. Finish or cancel it first.", "error")
        return redirect(url_for("admin.member_detail", user_id=user.id))
    if _guaranteed_open_loans(user):
        flash("This member is a guarantor on a loan that is not finished. Wait until it is paid.", "error")
        return redirect(url_for("admin.member_detail", user_id=user.id))

    name, account = user.display_name, user.account_number or user.email
    snapshot = (f"{name}; savings GHS {user.total_contributions():,.2f}; "
                f"{len(user.loans)} loan(s); joined {user.created_at or 'earlier'}")

    # Keep other people's loan history: just remove this person as their guarantor.
    Loan.query.filter(Loan.guarantor_id == user.id).update({"guarantor_id": None})
    Loan.query.filter(Loan.guarantor2_id == user.id).update({"guarantor2_id": None})
    # Anything this person recorded (as administrator) keeps its record.
    Contribution.query.filter(Contribution.recorded_by == user.id).update({"recorded_by": None})
    for loan in Loan.query.filter_by(user_id=user.id).all():
        LoanPayment.query.filter_by(loan_id=loan.id).delete()
        db.session.delete(loan)
    Contribution.query.filter_by(user_id=user.id).delete()
    MonthlySavingsTarget.query.filter_by(user_id=user.id).delete()
    Dividend.query.filter_by(user_id=user.id).delete()
    member_service.delete_member_files(user)
    log_action(current_user, "member_deleted", account, snapshot)
    db.session.delete(user)
    db.session.commit()
    flash(f"{name} has been deleted.", "success")
    return redirect(url_for("admin.members_list"))


# ---------------------------------------------------------------------------
# Password reset by the administrator
# ---------------------------------------------------------------------------
@bp.route("/members/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def member_reset_password(user_id):
    user = _member_or_404(user_id)
    if user.is_guest:
        flash("Non-members do not have a password.", "error")
        return redirect(url_for("admin.member_detail", user_id=user.id))
    temp = member_service.temporary_password()
    user.set_password(temp)
    user.must_change_password = True
    user.failed_login_attempts = 0
    user.locked_until = None
    log_action(current_user, "password_reset", user.account_number or user.email, user.display_name)
    db.session.commit()
    send_email("Your Unity Credit Union password was reset", user.email, "password_reset_by_admin",
               user=user, temp_password=temp)
    return render_template("admin/temp_password.html", user=user, temp_password=temp, is_new=False)


# ---------------------------------------------------------------------------
# Monthly savings target
# ---------------------------------------------------------------------------
@bp.route("/members/<int:user_id>/target", methods=["POST"])
@admin_required
def member_set_target(user_id):
    user = _member_or_404(user_id)
    try:
        amount = round(float((request.form.get("target_amount") or "").replace(",", "")), 2)
    except ValueError:
        amount = 0
    if amount <= 0 or amount > 1_000_000:
        flash("Enter a monthly target amount greater than zero.", "error")
    else:
        MonthlySavingsTarget.query.filter_by(user_id=user.id, is_active=True).update({"is_active": False})
        db.session.add(MonthlySavingsTarget(user_id=user.id, target_amount=amount, is_active=True))
        log_action(current_user, "target_set", user.account_number or user.email, f"GHS {amount:,.2f}")
        db.session.commit()
        send_email("Your monthly savings target was updated", user.email, "monthly_target_update",
                   user=user, target_amount=amount)
        flash(f"Monthly target for {user.display_name} set to GHS {amount:,.2f}.", "success")
    return redirect(request.form.get("next") if request.form.get("next", "").startswith("/")
                    and not request.form.get("next", "").startswith("//")
                    else url_for("admin.member_detail", user_id=user.id))
