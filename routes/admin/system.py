from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import func

import rules
from extensions import db
from mailer import send_email
from models import Contribution, Cycle, Dividend, User, get_setting, log_action, set_setting, utcnow, AuditLog
from pagination_utils import paginate
from routes import admin_required

from . import bp


# ---------------------------------------------------------------------------
# Cycles and dividends
# ---------------------------------------------------------------------------
@bp.route("/cycles")
@admin_required
def cycles():
    items = Cycle.query.order_by(Cycle.start_year.desc()).all()
    rows = []
    for c in items:
        rows.append({"cycle": c, "total": c.total_contributions(),
                     "dividend_total": float(db.session.query(func.coalesce(func.sum(Dividend.amount), 0.0))
                                             .filter(Dividend.cycle_id == c.id).scalar() or 0)})
    return render_template("admin/cycles.html", rows=rows)


@bp.route("/cycles/<int:cycle_id>")
@admin_required
def cycle_detail(cycle_id):
    cycle = db.get_or_404(Cycle, cycle_id)
    dividends = (Dividend.query.filter_by(cycle_id=cycle.id).join(User, User.id == Dividend.user_id)
                 .order_by(User.first_name, User.last_name).all())
    return render_template("admin/cycle_detail.html", cycle=cycle, dividends=dividends,
                           total=cycle.total_contributions(),
                           dividend_total=sum(d.amount for d in dividends),
                           paid_count=sum(1 for d in dividends if d.status == "paid"))


@bp.route("/cycles/<int:cycle_id>/dividends", methods=["POST"])
@admin_required
def declare_dividends(cycle_id):
    """Work out each active member's dividend as a percentage of what they saved in the cycle."""
    cycle = db.get_or_404(Cycle, cycle_id)
    if cycle.status != "closed":
        flash("Dividends can only be declared after the cycle has closed (after 31 August).", "error")
        return redirect(url_for("admin.cycle_detail", cycle_id=cycle.id))
    if Dividend.query.filter_by(cycle_id=cycle.id, status="paid").count():
        flash("Some dividends are already paid, so the rate can no longer be changed.", "error")
        return redirect(url_for("admin.cycle_detail", cycle_id=cycle.id))
    try:
        rate = round(float((request.form.get("rate") or "").replace(",", "")), 2)
    except ValueError:
        rate = -1
    if rate <= 0 or rate > 100:
        flash("Enter a dividend rate between 0 and 100 percent.", "error")
        return redirect(url_for("admin.cycle_detail", cycle_id=cycle.id))

    Dividend.query.filter_by(cycle_id=cycle.id).delete()
    totals = (db.session.query(Contribution.user_id, func.sum(Contribution.amount))
              .filter(Contribution.month.in_(cycle.months)).group_by(Contribution.user_id).all())
    active_ids = {u.id for u in User.query.filter(User.is_verified == True, User.is_active_member == True,   # noqa: E712
                                                  User.is_guest == False, User.is_admin == False)}         # noqa: E712
    count = 0
    for user_id, total in totals:
        if user_id not in active_ids or not total:
            continue
        db.session.add(Dividend(cycle_id=cycle.id, user_id=user_id, contribution_total=rules.money(total),
                                rate=rate, amount=rules.money(total * rate / 100), status="pending"))
        count += 1
    cycle.dividend_rate = rate
    cycle.dividend_declared_at = utcnow()
    log_action(current_user, "dividends_declared", cycle.label, f"{rate}% for {count} members")
    db.session.commit()
    flash(f"Dividend of {rate}% declared for {count} members.", "success")
    return redirect(url_for("admin.cycle_detail", cycle_id=cycle.id))


@bp.route("/dividends/<int:dividend_id>/paid", methods=["POST"])
@admin_required
def dividend_paid(dividend_id):
    dividend = db.get_or_404(Dividend, dividend_id)
    if dividend.status != "paid":
        dividend.status = "paid"
        dividend.paid_at = utcnow()
        log_action(current_user, "dividend_paid", dividend.user.account_number, f"GHS {dividend.amount:,.2f}")
        db.session.commit()
        send_email(f"Your {dividend.cycle.label} dividend", dividend.user.email, "dividend_notice",
                   user=dividend.user, dividend=dividend, cycle=dividend.cycle)
        flash(f"Marked as paid for {dividend.user.display_name}.", "success")
    return redirect(url_for("admin.cycle_detail", cycle_id=dividend.cycle_id))


# ---------------------------------------------------------------------------
# Settings: open and close the seasonal loans
# ---------------------------------------------------------------------------
@bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    if request.method == "POST":
        for key in rules.SEASONAL_LOAN_TYPES:
            set_setting(f"loan_open_{key}", "1" if request.form.get(f"open_{key}") == "on" else "0")
        log_action(current_user, "settings_changed", "seasonal loans",
                   ", ".join(f"{k}={get_setting(f'loan_open_{k}')}" for k in rules.SEASONAL_LOAN_TYPES))
        db.session.commit()
        flash("Settings saved.", "success")
        return redirect(url_for("admin.settings"))
    return render_template("admin/settings.html", seasonal=[
        (key, rules.LOAN_TYPES[key], get_setting(f"loan_open_{key}", "0") == "1")
        for key in rules.SEASONAL_LOAN_TYPES])


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
@bp.route("/audit")
@admin_required
def audit():
    pagination = paginate(AuditLog.query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()), per_page=30)
    return render_template("admin/audit.html", pagination=pagination, items=pagination.items, query_params={})
