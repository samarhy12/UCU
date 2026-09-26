import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

DEFAULT_DB_FILE = "credit_union.db"


def _normalize_database_uri(database_url):
    """Return a database URI.

    The original UCU app kept its SQLite file at instance/credit_union.db.
    Relative SQLite paths (for example sqlite:///credit_union.db) are placed in the
    instance folder so that an existing database keeps being found.

    For MySQL, the URI should be in the format:
    mysql+pymysql://user:password@host/dbname
    """
    default = f"sqlite:///{Path(BASE_DIR) / 'instance' / DEFAULT_DB_FILE}"
    if not database_url:
        return default

    # Handle MySQL connections with pymysql
    if database_url.startswith("mysql://"):
        # Convert mysql:// to mysql+pymysql:// for SQLAlchemy to use pymysql
        database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)
        return database_url

    if database_url.startswith("sqlite:///") and not database_url.startswith("sqlite:////"):
        relative_path = database_url[len("sqlite:///"):]
        if not relative_path:
            return default
        if relative_path == ":memory:":
            return database_url
        candidate = Path(relative_path)
        if not candidate.is_absolute():
            if relative_path.replace("\\", "/").startswith("instance/"):
                candidate = Path(BASE_DIR) / candidate
            else:
                candidate = Path(BASE_DIR) / "instance" / candidate
        return f"sqlite:///{candidate}"

    return database_url


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY must be set in the environment or in the .env file. "
            "Copy .env.example to .env and fill it in."
        )

    SQLALCHEMY_DATABASE_URI = _normalize_database_uri(os.environ.get("DATABASE_URL"))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = (
        {"connect_args": {"check_same_thread": False}}
        if SQLALCHEMY_DATABASE_URI.startswith("sqlite")
        else {"pool_pre_ping": True}
    )

    # ---- Organisation details (shown in the footer and on public pages) ----
    ORG_NAME = "Unity Credit Union"
    ORG_SHORT = "UCU"
    ORG_MOTTO = "Your membership, our proud concern"
    CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL", "agyareemmanuelosei@gmail.com")
    CONTACT_PHONE = os.environ.get("CONTACT_PHONE", "+233247767438")
    WHATSAPP_URL = os.environ.get("WHATSAPP_URL", "https://wa.me/233247767438")
    FACEBOOK_URL = os.environ.get("FACEBOOK_URL", "#")
    TIKTOK_URL = os.environ.get("TIKTOK_URL", "#")
    SITE_URL = os.environ.get("SITE_URL", "https://ucu.raydexhub.com").rstrip("/")
    ORG_ADDRESS = "Head office: Mpraeso-Kwahu, P.O. Box 19"

    # ---- Email ----
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "mail.raydexhub.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "465"))
    MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", "1") == "1"
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "0") == "1"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = (ORG_NAME, os.environ.get("MAIL_USERNAME") or "no-reply@example.com")
    MAIL_ASYNC = True          # send in a background thread so pages stay fast
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL") or CONTACT_EMAIL

    # ---- Uploads ----
    # Same folder the original app used, so existing Ghana Card and passport files keep working.
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    EXECUTIVE_PHOTO_FOLDER = os.path.join(BASE_DIR, "static", "uploads", "executives")
    ADVERT_IMAGE_FOLDER = os.path.join(BASE_DIR, "static", "uploads", "adverts")
    GALLERY_FOLDER = os.path.join(BASE_DIR, "static", "uploads", "gallery")
    CAROUSEL_FOLDER = os.path.join(BASE_DIR, "static", "uploads", "carousel")
    GREETING_FOLDER = os.path.join(BASE_DIR, "static", "uploads", "greeting")
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg"}
    ALLOWED_DOCUMENT_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}
    MAX_UPLOAD_MB = 12                                   # per file (Ghana Card and passport photo)
    MAX_CONTENT_LENGTH = 30 * 1024 * 1024                # whole request (two files plus form)

    # ---- Security ----
    PASSWORD_MIN_LENGTH = 8
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15
    RESET_TOKEN_MAX_AGE = 3600

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FORCE_HTTPS", "0") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    REMEMBER_COOKIE_DURATION = timedelta(days=14)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE

    DEFAULT_PAGE_SIZE = 20
    MINIMUM_MEMBER_AGE = 18
