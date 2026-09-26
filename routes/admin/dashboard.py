from datetime import date

from flask import render_template, request
from sqlalchemy import func

import rules
from extensions import db
from models import AuditLog, Contribution, Cycle, Loan, User, utcnow
from routes import admin_required
from services import members as member_service

from . import bp


def _sum(column, *filters):
    return float(db.session.query(func.coalesce(func.sum(column), 0.0)).filter(*filters).scalar() or 0.0)


@bp.route("/")
@admin_required
def dashboard():
    today = date.today()
    start_year = rules.cycle_start_year_for(today)
    this_month = today.strftime("%Y-%m")
    cycle_months = rules.cycle_months(start_year)

    pending_members = (User.query.filter(User.is_admin == False, User.is_guest == False,      # noqa: E712
                                         User.is_verified == False, User.is_active_member == True)  # noqa: E712
                       .order_by(User.id.desc()))
    pending_loans = Loan.query.filter_by(status="pending").order_by(Loan.application_date.desc())
    overdue = (Loan.query.filter(Loan.status == "approved", Loan.remaining_amount > 0,
                                 Loan.repayment_date < utcnow()).order_by(Loan.repayment_date).all())

    end = rules.cycle_bounds(start_year)[1]
    stats = {
        "members": member_service.total_members(),
        "signups": member_service.total_signups(),
        "pending_members": pending_members.count(),
        "pending_loans": pending_loans.count(),
        "exited": User.query.filter(User.is_admin == False, User.is_guest == False,   # noqa: E712
                                    User.is_active_member == False).count(),           # noqa: E712
        "month_total": _sum(Contribution.amount, Contribution.month == this_month),
        "cycle_total": _sum(Contribution.amount, Contribution.month.in_(cycle_months)),
        "all_time": _sum(Contribution.amount),
        "loan_balance": _sum(Loan.remaining_amount, Loan.status == "approved"),
        "overdue": len(overdue),
        "days_to_cycle_end": (end - today).days,
    }
    recent = (Contribution.query.order_by(Contribution.date.desc(), Contribution.id.desc()).limit(8).all())
    return render_template("admin/dashboard.html", stats=stats, pending_members=pending_members.limit(5).all(),
                           pending_loans=pending_loans.limit(5).all(), overdue=overdue[:5],
                           recent=recent, cycle=Cycle.current(), cycle_label=rules.cycle_label(start_year),
                           this_month_label=rules.month_label(this_month))


@bp.route("/reports")
@admin_required
def reports():
    today = date.today()
    current_start = rules.cycle_start_year_for(today)
    start_year = request.args.get("cycle", current_start, type=int)
    months = rules.cycle_months(start_year)

    rows = dict(db.session.query(Contribution.month, func.sum(Contribution.amount))
                .filter(Contribution.month.in_(months)).group_by(Contribution.month).all())
    monthly = [{"month": m, "label": rules.month_label(m)[:3], "full_label": rules.month_label(m),
                "total": float(rows.get(m, 0) or 0)} for m in months]
    top = max((m["total"] for m in monthly), default=0) or 1
    for m in monthly:
        m["percent"] = round(m["total"] / top * 100)

    payers = (db.session.query(func.count(func.distinct(Contribution.user_id)))
              .filter(Contribution.month.in_(months)).scalar() or 0)

    by_type = []
    for key, info in rules.LOAN_TYPES.items():
        q = Loan.query.filter(Loan.loan_type == key, Loan.status.in_(("approved", "paid")))
        loans = q.all()
        by_type.append({"label": info["label"], "count": len(loans),
                        "lent": sum(l.amount for l in loans),
                        "paid": sum(l.amount_paid or 0 for l in loans),
                        "owed": sum(l.remaining_amount or 0 for l in loans)})

    status_counts = dict(db.session.query(Loan.status, func.count(Loan.id)).group_by(Loan.status).all())
    loan_totals = {
        "lent": _sum(Loan.amount, Loan.status.in_(("approved", "paid"))),
        "collected": _sum(Loan.amount_paid, Loan.status.in_(("approved", "paid"))),
        "outstanding": _sum(Loan.remaining_amount, Loan.status == "approved"),
    }
    cycles = Cycle.query.order_by(Cycle.start_year.desc()).all()
    return render_template("admin/reports.html", monthly=monthly, start_year=start_year,
                           cycle_label=rules.cycle_label(start_year), cycles=cycles, payers=payers,
                           cycle_total=sum(m["total"] for m in monthly), by_type=by_type,
                           status_counts=status_counts, loan_totals=loan_totals,
                           members=member_service.total_members(),
                           guests=User.query.filter_by(is_guest=True).count())
