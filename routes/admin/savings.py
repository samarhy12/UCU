from datetime import date

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import func, or_

import rules
from extensions import db
from mailer import send_email
from models import Contribution, Cycle, User, log_action, make_receipt_no, utcnow
from pagination_utils import paginate
from routes import admin_required

from . import bp


def _recordable_months(today=None):
    """Months the administrator may record a payment for: the last 14 months up to this month."""
    today = today or date.today()
    months, year, month = [], today.year, today.month
    for _ in range(14):
        months.append(f"{year}-{month:02d}")
        month -= 1
        if month == 0:
            month, year = 12, year - 1
    return months


def _cycle_is_locked(month):
    """Once dividends are declared for a cycle, its contributions no longer change."""
    cycle = Cycle.query.filter_by(start_year=rules.cycle_start_year_from_month(month)).first()
    return bool(cycle and cycle.dividend_declared_at)


def _safe_next(default):
    target = request.form.get("next", "")
    return target if target.startswith("/") and not target.startswith("//") else default


# ---------------------------------------------------------------------------
# Record monthly contributions, member after member
# ---------------------------------------------------------------------------
@bp.route("/contributions")
@admin_required
def contributions():
    months = _recordable_months()
    month = request.args.get("month", months[0])
    if month not in months:
        month = months[0]
    q = (request.args.get("q") or "").strip()
    show = request.args.get("show", "all")          # all | unpaid

    query = User.query.filter(User.is_admin == False, User.is_guest == False,           # noqa: E712
                              User.is_verified == True, User.is_active_member == True)    # noqa: E712
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.first_name.ilike(like), User.last_name.ilike(like),
                                 User.account_number.ilike(like), User.phone_number.ilike(like)))
    if show == "unpaid":
        paid_ids = db.session.query(Contribution.user_id).filter(Contribution.month == month)
        query = query.filter(~User.id.in_(paid_ids))
    pagination = paginate(query.order_by(User.first_name, User.last_name), per_page=25)

    ids = [u.id for u in pagination.items]
    paid = dict(db.session.query(Contribution.user_id, func.sum(Contribution.amount))
                .filter(Contribution.month == month, Contribution.user_id.in_(ids))
                .group_by(Contribution.user_id).all()) if ids else {}
    cycle_months = rules.cycle_months(rules.cycle_start_year_from_month(month))
    cycle_totals = dict(db.session.query(Contribution.user_id, func.sum(Contribution.amount))
                        .filter(Contribution.month.in_(cycle_months), Contribution.user_id.in_(ids))
                        .group_by(Contribution.user_id).all()) if ids else {}
    rows = [{"user": u, "target": u.monthly_target, "paid": float(paid.get(u.id, 0) or 0),
             "cycle_total": float(cycle_totals.get(u.id, 0) or 0)} for u in pagination.items]

    month_total = float(db.session.query(func.coalesce(func.sum(Contribution.amount), 0.0))
                        .filter(Contribution.month == month).scalar() or 0)
    return render_template("admin/contributions.html", rows=rows, pagination=pagination, month=month,
                           months=[(m, rules.month_label(m)) for m in months], q=q, show=show,
                           month_total=month_total, locked=_cycle_is_locked(month),
                           cycle_label=rules.cycle_label(rules.cycle_start_year_from_month(month)),
                           query_params={k: v for k, v in (("month", month), ("q", q), ("show", show)) if v})


@bp.route("/contributions/record/<int:user_id>", methods=["POST"])
@admin_required
def record_contribution(user_id):
    user = db.get_or_404(User, user_id)
    fallback = url_for("admin.contributions")
    month = request.form.get("month", "")

    try:
        amount = round(float((request.form.get("amount") or "").replace(",", "")), 2)
    except ValueError:
        amount = 0

    if not user.can_use_member_services:
        flash("Contributions can only be recorded for verified, active members.", "error")
    elif month not in _recordable_months():
        flash("Choose a valid month.", "error")
    elif amount <= 0 or amount > 1_000_000:
        flash("Enter an amount greater than zero.", "error")
    elif _cycle_is_locked(month):
        flash("Dividends were already declared for that cycle, so its contributions are closed.", "error")
    else:
        note = (request.form.get("note") or "").strip()[:200] or None
        now = utcnow()
        contribution = Contribution(user_id=user.id, amount=amount, month=month, date=now,
                                    contribution_type="monthly_savings", recorded_by=current_user.id, note=note)
        db.session.add(contribution)
        db.session.flush()
        contribution.receipt_no = make_receipt_no("CT", now, contribution.id)
        log_action(current_user, "contribution_recorded", user.account_number,
                   f"GHS {amount:,.2f} for {month}, receipt {contribution.receipt_no}")
        db.session.commit()

        start_year = rules.cycle_start_year_from_month(month)
        sent = send_email(f"Contribution receipt {contribution.receipt_no}", user.email, "monthly_contribution",
                          user=user, contribution=contribution, amount=amount,
                          month_label=rules.month_label(month),
                          month_total=user.month_contributions(month), target=user.monthly_target,
                          cycle_label=rules.cycle_label(start_year),
                          cycle_total=user.cycle_contributions(start_year),
                          total_savings=user.total_contributions())
        flash(f"Recorded GHS {amount:,.2f} for {user.display_name}. Receipt {contribution.receipt_no}"
              f"{' was emailed.' if sent else '. (Email is not set up, so no receipt was sent.)'}", "success")
    return redirect(_safe_next(fallback))


# ---------------------------------------------------------------------------
# All recorded contributions, and reversing a wrong one
# ---------------------------------------------------------------------------
@bp.route("/contributions/log")
@admin_required
def contribution_log():
    q = (request.args.get("q") or "").strip()
    month = request.args.get("month", "")
    query = Contribution.query.join(User, User.id == Contribution.user_id)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.first_name.ilike(like), User.last_name.ilike(like),
                                 User.account_number.ilike(like), Contribution.receipt_no.ilike(like)))
    if month:
        query = query.filter(Contribution.month == month)
    pagination = paginate(query.order_by(Contribution.date.desc(), Contribution.id.desc()))
    all_months = [m for (m,) in db.session.query(Contribution.month).distinct().order_by(Contribution.month.desc())]
    return render_template("admin/contribution_log.html", pagination=pagination, items=pagination.items,
                           q=q, month=month, all_months=[(m, rules.month_label(m)) for m in all_months],
                           query_params={k: v for k, v in (("q", q), ("month", month)) if v})


@bp.route("/contributions/<int:contribution_id>/reverse", methods=["POST"])
@admin_required
def reverse_contribution(contribution_id):
    contribution = db.get_or_404(Contribution, contribution_id)
    user = contribution.user
    if _cycle_is_locked(contribution.month):
        flash("Dividends were already declared for that cycle, so this payment can no longer be reversed.", "error")
        return redirect(_safe_next(url_for("admin.contribution_log")))

    amount, month, receipt = contribution.amount, contribution.month, contribution.receipt_no or f"#{contribution.id}"
    log_action(current_user, "contribution_reversed", user.account_number or user.email,
               f"GHS {amount:,.2f} for {month}, receipt {receipt}")
    db.session.delete(contribution)
    db.session.commit()
    send_email("A contribution was reversed", user.email, "monthly_contribution_reversal", user=user,
               amount=amount, month_label=rules.month_label(month), receipt=receipt,
               total_savings=user.total_contributions())
    flash(f"Payment {receipt} of GHS {amount:,.2f} for {user.display_name} was reversed.", "success")
    return redirect(_safe_next(url_for("admin.contribution_log")))
