from flask import Blueprint

bp = Blueprint("admin", __name__, url_prefix="/admin")

# The views live in these modules; importing them attaches the routes to the blueprint.
from . import dashboard, members, savings, loans, content, system  # noqa: E402,F401
