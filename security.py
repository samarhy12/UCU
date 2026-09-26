import secrets
from urllib.parse import urlparse

from flask import abort, request, session


def get_csrf_token():
    """Return the current session's CSRF token, creating one if needed."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def init_csrf(app):
    """Add csrf_token() to templates and check it on every request that changes data."""

    @app.context_processor
    def inject_csrf():
        return {"csrf_token": get_csrf_token}

    @app.before_request
    def verify_csrf():
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        if request.endpoint == "static":
            return None

        submitted = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        expected = session.get("_csrf_token")

        if not expected or not submitted or not secrets.compare_digest(submitted, expected):
            abort(400, description="Your session has expired or the form was sent incorrectly. "
                                   "Please go back, refresh the page and try again.")
        return None


def is_safe_redirect(target):
    """Only allow redirects to pages on this site (stops 'open redirect' tricks)."""
    if not target:
        return False
    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc and target.startswith("/") and not target.startswith("//")


_attempts = {}


def throttle(key, limit, seconds):
    """Very small in-memory rate limit. Returns True when the caller is over the limit.

    It is per process, which is enough to slow down guessing on the public look-up forms.
    """
    import time
    now = time.time()
    recent = [t for t in _attempts.get(key, []) if now - t < seconds]
    over = len(recent) >= limit
    if not over:
        recent.append(now)
    _attempts[key] = recent
    if len(_attempts) > 5000:            # keep memory small
        for k in list(_attempts)[:2500]:
            _attempts.pop(k, None)
    return over
