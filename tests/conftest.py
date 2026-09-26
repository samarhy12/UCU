import io
import os
import sys
import tempfile
from datetime import date

import pytest
from PIL import Image

_tmp = tempfile.mkdtemp(prefix="ucu-test-")
os.environ.update({
    "SECRET_KEY": "test-secret-key",
    "DATABASE_URL": f"sqlite:///{os.path.join(_tmp, 'test.db')}",
    "MAIL_USERNAME": "no-reply@test.local",
    "MAIL_PASSWORD": "x",
})
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app as flask_app        # noqa: E402
from flask import g                     # noqa: E402
from flask.testing import FlaskClient   # noqa: E402
from extensions import db, mail          # noqa: E402
from models import User, utcnow          # noqa: E402
import services.cycles as cycles_service  # noqa: E402


class IsolatedClient(FlaskClient):
    """The fixture keeps one app context open for the whole test, so Flask-Login's cached user
    would leak from one request (or one client) to the next. Forget it before every request."""

    def open(self, *args, **kwargs):
        g.pop("_login_user", None)
        return super().open(*args, **kwargs)


flask_app.test_client_class = IsolatedClient


@pytest.fixture()
def app():
    flask_app.config.update(TESTING=True, MAIL_ASYNC=False,
                            UPLOAD_FOLDER=os.path.join(_tmp, "uploads"),
                            EXECUTIVE_PHOTO_FOLDER=os.path.join(_tmp, "exec"),
                            ADVERT_IMAGE_FOLDER=os.path.join(_tmp, "adv"))
    flask_app.extensions["mail"].suppress = True
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
        cycles_service.reset_cycle_check()
        yield flask_app
        db.session.remove()


@pytest.fixture()
def client(app):
    return app.test_client()


def png_bytes(color=(200, 30, 30)):
    buf = io.BytesIO()
    Image.new("RGB", (60, 40), color).save(buf, "PNG")
    buf.seek(0)
    return buf


def post(client, url, data=None, **kwargs):
    """POST with a valid CSRF token."""
    with client.session_transaction() as s:
        s["_csrf_token"] = "tok"
    data = dict(data or {})
    data["csrf_token"] = "tok"
    return client.post(url, data=data, **kwargs)


def make_user(email, first="Test", last="User", admin=False, verified=True, guest=False, password="password123",
              national_id=None, phone="0241234567", **extra):
    n = User.query.count() + 1
    u = User(email=email, first_name=first, last_name=last, is_admin=admin, is_verified=verified, is_guest=guest,
             is_active_member=True, national_id=national_id or f"GHA-{n:09d}-1", date_of_birth=date(1990, 1, 1),
             occupation="Trader", phone_number=phone, address="Somewhere", city="Koforidua", state="Eastern",
             country="Ghana", created_at=utcnow(), **extra)
    if password and not guest:
        u.set_password(password)
    db.session.add(u)
    db.session.commit()
    return u


def login(client, email, password="password123"):
    return post(client, "/login", {"email": email, "password": password})


def make_member(email="member@test.com", first="Ama", last="Mensah", **kw):
    """A verified member with an account number, created the same way the app does."""
    from services import members as ms
    u = make_user(email, first, last, verified=False, **kw)
    ms.verify_member(u)
    db.session.commit()
    return u


@pytest.fixture()
def admin(app):
    return make_user("admin@test.com", "Admin", "Boss", admin=True)


@pytest.fixture()
def admin_client(client, admin):
    login(client, "admin@test.com")
    return client


@pytest.fixture()
def mailbox():
    with mail.record_messages() as outbox:
        yield outbox
