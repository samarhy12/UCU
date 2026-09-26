"""Annual cycle handling: a new cycle opens every 1 September and the old one closes."""
from datetime import date

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

import rules
from extensions import db
from models import Contribution, Cycle, utcnow

_last_checked = None


def ensure_cycles(force=False, today=None):
    """Make sure a cycle exists for every year from the first contribution to today.

    Past cycles are closed and the current one is open. Safe to call often: it does real work
    at most once a day per process, and running it twice does no harm.
    """
    global _last_checked
    today = today or date.today()
    if not force and _last_checked == today:
        return
    try:
        current_start = rules.cycle_start_year_for(today)
        first_month = db.session.query(func.min(Contribution.month)).scalar()
        first_start = current_start
        if first_month:
            first_start = min(current_start, rules.cycle_start_year_from_month(first_month))

        existing = {c.start_year: c for c in Cycle.query.all()}
        for year in range(first_start, current_start + 1):
            cycle = existing.get(year)
            if cycle is None:
                start, end = rules.cycle_bounds(year)
                db.session.add(Cycle(
                    start_year=year, label=rules.cycle_label(year), start_date=start, end_date=end,
                    status="open" if year == current_start else "closed",
                    closed_at=None if year == current_start else utcnow()))
            elif year < current_start and cycle.status == "open":
                cycle.status = "closed"
                cycle.closed_at = utcnow()
        db.session.commit()
        _last_checked = today
    except IntegrityError:
        db.session.rollback()          # another worker did the same work first
    except (OperationalError, ProgrammingError):
        db.session.rollback()          # the database has not been migrated yet


def reset_cycle_check():
    global _last_checked
    _last_checked = None


def cycle_summary(today=None):
    """Facts about the current cycle for display: label, dates, progress and the twelve months."""
    today = today or date.today()
    start_year = rules.cycle_start_year_for(today)
    start, end = rules.cycle_bounds(start_year)
    total_days = (end - start).days + 1
    elapsed = (today - start).days + 1
    current_month = today.strftime("%Y-%m")
    import calendar
    part_of_month = today.day / calendar.monthrange(today.year, today.month)[1]
    months = []
    for m in rules.cycle_months(start_year):
        state = "past" if m < current_month else ("current" if m == current_month else "future")
        months.append({"key": m, "short": rules.month_label(m)[:3], "state": state,
                       "fill": 1 if state == "past" else (round(part_of_month, 2) if state == "current" else 0)})
    return {"label": rules.cycle_label(start_year), "start": start, "end": end,
            "days_left": max(0, (end - today).days), "percent": max(0, min(100, round(elapsed / total_days * 100))),
            "months": months, "month_number": next((i + 1 for i, m in enumerate(months) if m["state"] == "current"), 1)}
