import os
from datetime import date

from flask import (Blueprint, abort, current_app, flash, redirect, render_template, request,
                   send_from_directory, url_for)
from flask_login import current_user, login_required

import rules
from extensions import db
from models import Advert, Contribution, Cycle, Dividend, Executive, Loan, User
from routes import member_required
from services import members as member_service

bp = Blueprint("member", __name__)


@bp.route("/dashboard")
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for("admin.dashboard"))

    today = date.today()
    start_year = rules.cycle_start_year_for(today)
    this_month = today.strftime("%Y-%m")
    user = current_user

    data = {
        "cycle": Cycle.current(),
        "cycle_label": rules.cycle_label(start_year),
        "total_members": member_service.total_members(),
        "total_signups": member_service.total_signups(),
        "adverts": Advert.running(),
        "executives": Executive.listing(),
    }
    if user.can_use_member_services:
        target = user.monthly_target
        paid_this_month = user.month_contributions(this_month)
        data.update({
            "total_savings": user.total_contributions(),
            "cycle_savings": user.cycle_contributions(start_year),
            "target": target,
            "paid_this_month": paid_this_month,
            "this_month_label": rules.month_label(this_month),
            "active_loan": user.active_loan,
            "open_loan": user.open_loan,
            "recent_contributions": (Contribution.query.filter_by(user_id=user.id)
                                     .order_by(Contribution.date.desc(), Contribution.id.desc()).limit(5).all()),
        })
    return render_template("member/dashboard.html", **data)


@bp.route("/my/contributions")
@member_required
def contributions():
    today = date.today()
    current_start = rules.cycle_start_year_for(today)
    start_year = request.args.get("cycle", current_start, type=int)

    rows = (Contribution.query.filter(Contribution.user_id == current_user.id,
                                      Contribution.month.in_(rules.cycle_months(start_year)))
            .order_by(Contribution.month, Contribution.date, Contribution.id).all())
    by_month = {}
    for row in rows:
        by_month.setdefault(row.month, []).append(row)

    months = []
    running = 0.0
    target = current_user.monthly_target
    for month in rules.cycle_months(start_year):
        entries = by_month.get(month, [])
        total = sum(e.amount for e in entries)
        running += total
        months.append({"month": month, "label": rules.month_label(month), "entries": entries,
                       "total": total, "running": running,
                       "is_future": month > today.strftime("%Y-%m")})

    # Cycles this member can look at: every cycle they saved in, plus the current one.
    used = {rules.cycle_start_year_from_month(m) for (m,) in
            db.session.query(Contribution.month).filter_by(user_id=current_user.id).distinct()}
    cycle_choices = sorted(used | {current_start}, reverse=True)

    cycle = Cycle.query.filter_by(start_year=start_year).first()
    dividend = None
    if cycle:
        dividend = Dividend.query.filter_by(cycle_id=cycle.id, user_id=current_user.id).first()

    return render_template("member/contributions.html", months=months, start_year=start_year,
                           cycle_label=rules.cycle_label(start_year), cycle_choices=cycle_choices,
                           cycle_total=running, all_time_total=current_user.total_contributions(),
                           target=target, dividend=dividend, cycle=cycle,
                           rules=rules)


@bp.route("/my/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user
    if user.is_admin:
        return render_template("member/profile.html", user=user, editable=False,
                               regions=member_service.GHANA_REGIONS)

    if request.method == "POST":
        form = request.form
        values = {f: (form.get(f) or "").strip() for f in
                  ("occupation", "phone_number", "address", "hometown", "city", "state", "country",
                   "nok_name", "nok_phone", "nok_relationship")}
        errors = []
        for field in ("occupation", "phone_number", "address", "hometown", "city", "state", "country",
                      "nok_name", "nok_phone", "nok_relationship"):
            if not values[field]:
                errors.append(f"{member_service.FIELD_LABELS.get(field, field)} is required.")
            elif len(values[field]) > member_service.MAX_LENGTHS[field]:
                errors.append(f"{member_service.FIELD_LABELS.get(field, field)} is too long.")
        if values["phone_number"] and not rules.valid_phone(values["phone_number"]):
            errors.append("Enter a valid phone number, for example 0241234567.")
        if values["nok_phone"] and not rules.valid_phone(values["nok_phone"]):
            errors.append("Enter a valid phone number for your next of kin.")
        if errors:
            for message in errors:
                flash(message, "error")
            return render_template("member/profile.html", user=user, editable=True, form=form,
                                   regions=member_service.GHANA_REGIONS), 400
        for field, value in values.items():
            setattr(user, field, value)
        db.session.commit()
        flash("Your details have been updated.", "success")
        return redirect(url_for("member.profile"))

    return render_template("member/profile.html", user=user, editable=True, form={},
                           regions=member_service.GHANA_REGIONS)


@bp.route("/documents/<int:user_id>/<doc_type>")
@login_required
def document(user_id, doc_type):
    """Ghana Card and passport photo files. Only the owner and administrators may open them."""
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    user = db.get_or_404(User, user_id)
    filename = {"national_id": user.national_id_file, "passport": user.passport_photo}.get(doc_type)
    if doc_type not in ("national_id", "passport"):
        abort(404)
    if not filename:
        abort(404)

    folder = current_app.config["UPLOAD_FOLDER"]
    if not os.path.isfile(os.path.join(folder, os.path.basename(filename))):
        abort(404)
    response = send_from_directory(folder, os.path.basename(filename))
    response.headers["Cache-Control"] = "private, no-store"
    return response
