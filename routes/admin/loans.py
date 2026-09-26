from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import or_

import rules
from extensions import db
from mailer import send_email
from models import Loan, LoanPayment, User, log_action, utcnow
from pagination_utils import paginate
from routes import admin_required
from services import loans as loan_service

from . import bp

LOAN_FILTERS = [("all", "All"), ("pending", "Waiting"), ("approved", "Running"), ("overdue", "Overdue"),
                ("paid", "Paid"), ("rejected", "Rejected"), ("cancelled", "Cancelled")]


def _back(loan):
    return redirect(url_for("admin.loan_detail", loan_id=loan.id))


@bp.route("/loans")
@admin_required
def loans_list():
    status = request.args.get("status", "all")
    loan_type = request.args.get("type", "")
    q = (request.args.get("q") or "").strip()

    query = Loan.query.join(User, User.id == Loan.user_id)
    if status == "overdue":
        query = query.filter(Loan.status == "approved", Loan.remaining_amount > 0, Loan.repayment_date < utcnow())
    elif status in ("pending", "approved", "paid", "rejected", "cancelled"):
        query = query.filter(Loan.status == status)
    if loan_type in rules.LOAN_TYPES:
        query = query.filter(Loan.loan_type == loan_type)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.first_name.ilike(like), User.last_name.ilike(like),
                                 User.account_number.ilike(like), User.phone_number.ilike(like),
                                 Loan.reference.ilike(like)))
    # Waiting loans first so they are not missed, then newest.
    order = db.case((Loan.status == "pending", 0), else_=1)
    pagination = paginate(query.order_by(order, Loan.application_date.desc(), Loan.id.desc()))
    return render_template("admin/loans.html", pagination=pagination, loans=pagination.items, status=status,
                           loan_type=loan_type, q=q, filters=LOAN_FILTERS, types=rules.LOAN_TYPES,
                           query_params={k: v for k, v in (("status", status), ("type", loan_type), ("q", q))
                                         if v and v != "all"})


@bp.route("/loans/<int:loan_id>")
@admin_required
def loan_detail(loan_id):
    loan = db.get_or_404(Loan, loan_id)
    checklist = loan_service.review_checklist(loan) if loan.status == "pending" else []
    return render_template("admin/loan_detail.html", loan=loan, checklist=checklist,
                           blocking=any(not item["ok"] for item in checklist))


@bp.route("/loans/<int:loan_id>/approve", methods=["POST"])
@admin_required
def approve_loan(loan_id):
    loan = db.get_or_404(Loan, loan_id)
    if loan.status != "pending":
        flash("Only a loan that is waiting can be verified.", "error")
        return _back(loan)
    applicant = loan.user
    if not applicant.is_guest and not applicant.can_use_member_services:
        flash("The applicant is not a verified, active member.", "error")
        return _back(loan)
    other = (Loan.query.filter(Loan.user_id == applicant.id, Loan.id != loan.id, Loan.status == "approved",
                               Loan.remaining_amount > 0).first())
    if other:
        flash(f"The applicant still owes on another loan ({other.reference or other.id}).", "error")
        return _back(loan)

    loan.approve()
    log_action(current_user, "loan_approved", loan.reference,
               f"GHS {loan.amount:,.2f}, {loan.type_label}, for {applicant.display_name}")
    db.session.commit()
    send_email("Your loan has been approved", applicant.email, "loan_approved", loan=loan, user=applicant)
    flash(f"Loan {loan.reference} verified and approved. It is due on {loan.repayment_date:%d %B %Y}.", "success")
    return _back(loan)


@bp.route("/loans/<int:loan_id>/reject", methods=["POST"])
@admin_required
def reject_loan(loan_id):
    loan = db.get_or_404(Loan, loan_id)
    if loan.status != "pending":
        flash("Only a loan that is waiting can be rejected.", "error")
        return _back(loan)
    loan.reject(note=request.form.get("reason"))
    log_action(current_user, "loan_rejected", loan.reference, loan.decision_note)
    db.session.commit()
    send_email("An update on your loan application", loan.user.email, "loan_rejected", loan=loan, user=loan.user)
    flash(f"Loan {loan.reference} was rejected and the applicant was told by email.", "success")
    return _back(loan)


@bp.route("/loans/<int:loan_id>/cancel", methods=["POST"])
@admin_required
def cancel_loan(loan_id):
    loan = db.get_or_404(Loan, loan_id)
    if loan.status != "pending":
        flash("Only a loan that is waiting can be cancelled.", "error")
        return _back(loan)
    loan.cancel()
    log_action(current_user, "loan_cancelled", loan.reference, "Cancelled by the administrator")
    db.session.commit()
    flash(f"Loan {loan.reference} was cancelled.", "success")
    return _back(loan)


@bp.route("/loans/<int:loan_id>/payment", methods=["POST"])
@admin_required
def record_payment(loan_id):
    loan = db.get_or_404(Loan, loan_id)
    try:
        amount = round(float((request.form.get("amount") or "").replace(",", "")), 2)
    except ValueError:
        amount = 0
    if loan.status != "approved":
        flash("Payments can only be recorded on a running loan.", "error")
        return _back(loan)
    payment = loan.apply_payment(amount, recorded_by=current_user.id,
                                 note=(request.form.get("note") or "").strip()[:200] or None)
    if payment is None:
        flash(f"Enter an amount greater than zero and not more than the balance of GHS {loan.remaining_amount:,.2f}.",
              "error")
        return _back(loan)
    log_action(current_user, "loan_payment", loan.reference, f"GHS {amount:,.2f}, receipt {payment.receipt_no}")
    db.session.commit()
    send_email(f"Loan payment receipt {payment.receipt_no}", loan.user.email, "loan_payment",
               loan=loan, user=loan.user, payment=payment)
    flash(f"Payment of GHS {amount:,.2f} recorded. Receipt {payment.receipt_no}."
          f"{' The loan is now fully paid.' if loan.status == 'paid' else ''}", "success")
    return _back(loan)


@bp.route("/loans/<int:loan_id>/payments/<int:payment_id>/reverse", methods=["POST"])
@admin_required
def reverse_payment(loan_id, payment_id):
    loan = db.get_or_404(Loan, loan_id)
    payment = db.get_or_404(LoanPayment, payment_id)
    if not loan.reverse_payment(payment, reversed_by=current_user.id):
        flash("This payment cannot be reversed.", "error")
        return _back(loan)
    log_action(current_user, "loan_payment_reversed", loan.reference,
               f"GHS {payment.amount:,.2f}, receipt {payment.receipt_no}")
    db.session.commit()
    send_email("A loan payment was reversed", loan.user.email, "loan_payment_reversal",
               loan=loan, user=loan.user, payment=payment)
    flash(f"Payment {payment.receipt_no} was reversed.", "success")
    return _back(loan)
