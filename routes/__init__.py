from functools import wraps

from flask import abort, flash, redirect, url_for
from flask_login import current_user, login_required


def admin_required(view):
    """Only administrators may open the page."""
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def member_required(view):
    """Only verified, active members may open the page."""
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if current_user.is_admin:
            return redirect(url_for("admin.dashboard"))
        if not current_user.can_use_member_services:
            flash("Your membership is still waiting to be verified. "
                  "You will get an email as soon as it is done.", "info")
            return redirect(url_for("member.dashboard"))
        return view(*args, **kwargs)
    return wrapped


def home_for(user):
    return url_for("admin.dashboard") if user.is_admin else url_for("member.dashboard")
