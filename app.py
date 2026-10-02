import os
from datetime import date, datetime, timedelta

import click
from flask import Flask, redirect, render_template, request, session, url_for
from flask_login import current_user, logout_user
from flask_migrate import Migrate

import rules
from config import Config
from extensions import db, login_manager, mail
from models import Loan, User, utcnow
from security import init_csrf
from services.cycles import ensure_cycles


def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    os.makedirs(app.instance_path, exist_ok=True)
    for key in ("UPLOAD_FOLDER", "EXECUTIVE_PHOTO_FOLDER", "ADVERT_IMAGE_FOLDER", "GALLERY_FOLDER",
                "CAROUSEL_FOLDER", "GREETING_FOLDER"):
        os.makedirs(app.config[key], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    init_csrf(app)
    Migrate(app, db)      # the database structure is managed with: flask db upgrade

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from routes.public import bp as public_bp
    from routes.auth import bp as auth_bp
    from routes.member import bp as member_bp
    from routes.loans import bp as loans_bp
    from routes.admin import bp as admin_bp

    for blueprint in (public_bp, auth_bp, member_bp, loans_bp, admin_bp):
        app.register_blueprint(blueprint)

    # -----------------------------------------------------------------
    # Access rules that apply to every page
    # -----------------------------------------------------------------
    open_endpoints = {"static", "auth.logout", "auth.change_password", "auth.login"}

    @app.before_request
    def housekeeping():
        if request.endpoint == "static":
            return None
        ensure_cycles()          # opens the new cycle every September, closes the old one

        if not current_user.is_authenticated:
            return None
        if not current_user.is_active:           # a member who exited while signed in
            logout_user()
            return redirect(url_for("auth.login"))
        if current_user.must_change_password and request.endpoint not in open_endpoints:
            return redirect(url_for("auth.change_password"))

        # Session timeout - auto-logout after inactivity
        session_timeout = app.config.get("SESSION_TIMEOUT_MINUTES", 30)
        if session_timeout > 0:
            last_activity = session.get('last_activity')
            if last_activity:
                try:
                    last_activity_time = datetime.fromisoformat(last_activity)
                    if datetime.now() - last_activity_time > timedelta(minutes=session_timeout):
                        logout_user()
                        session.clear()
                        return redirect(url_for("auth.login"))
                except (ValueError, TypeError):
                    # If timestamp is invalid, reset it
                    pass
            # Update last activity time
            session['last_activity'] = datetime.now().isoformat()

        return None

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "0"
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.context_processor
    def inject_globals():
        cfg = app.config
        data = {
            "current_year": date.today().year,
            "org": {"name": cfg["ORG_NAME"], "short": cfg["ORG_SHORT"], "motto": cfg["ORG_MOTTO"],
                    "email": cfg["CONTACT_EMAIL"], "phone": cfg["CONTACT_PHONE"],
                    "whatsapp": cfg["WHATSAPP_URL"], "address": cfg["ORG_ADDRESS"], "facebook": cfg["FACEBOOK_URL"],
                    "tiktok": cfg["TIKTOK_URL"], "site": cfg["SITE_URL"]},
            "rules": rules,
            "current_cycle_label": rules.cycle_label(rules.cycle_start_year_for(date.today())),
            "pending_members_badge": 0,
            "pending_loans_badge": 0,
        }
        if current_user.is_authenticated and current_user.is_admin:
            try:
                data["pending_members_badge"] = User.query.filter(
                    User.is_admin == False, User.is_guest == False, User.is_verified == False,   # noqa: E712
                    User.is_active_member == True).count()                                         # noqa: E712
                data["pending_loans_badge"] = Loan.query.filter_by(status="pending").count()
            except Exception:
                db.session.rollback()
        return data

    # -----------------------------------------------------------------
    # Template filters
    # -----------------------------------------------------------------
    @app.template_filter("money")
    def money_filter(value):
        return f"{float(value or 0):,.2f}"

    @app.template_filter("dmy")
    def dmy_filter(value):
        if isinstance(value, (datetime, date)):
            return value.strftime("%d %b %Y")
        return ""

    @app.template_filter("dmyhm")
    def dmyhm_filter(value):
        return value.strftime("%d %b %Y, %H:%M") if isinstance(value, datetime) else ""

    @app.template_filter("month_label")
    def month_label_filter(value):
        try:
            return rules.month_label(value)
        except (ValueError, TypeError):
            return value or ""

    # -----------------------------------------------------------------
    # Error pages
    # -----------------------------------------------------------------
    @app.errorhandler(400)
    def bad_request(e):
        return render_template("errors/400.html", message=getattr(e, "description", None)), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(413)
    def too_large(e):
        return render_template("errors/400.html",
                               message="The files you sent are too large. Each file must be 12 MB or less."), 413

    @app.errorhandler(500)
    def server_error(e):
        db.session.rollback()
        return render_template("errors/500.html"), 500

    register_cli(app)
    return app


def register_cli(app):
    @app.cli.command("create-admin")
    @click.option("--email", prompt=True)
    @click.option("--name", prompt="Full name", default="UCU Administrator")
    @click.password_option()
    def create_admin(email, name, password):
        """Create an administrator account."""
        email = email.strip().lower()
        if User.query.filter_by(email=email).first():
            raise click.ClickException("A user with that email already exists.")
        first, _, last = name.strip().partition(" ")
        admin = User(email=email, first_name=first or "UCU", last_name=last or "Admin", is_admin=True,
                     is_verified=True, is_guest=False, is_active_member=True, national_id=f"ADMIN-{utcnow():%y%m%d%H%M%S}",
                     date_of_birth=date(1990, 1, 1), occupation="Administrator", phone_number=app.config["CONTACT_PHONE"],
                     address="UCU", city="UCU", state="UCU", country="Ghana", created_at=utcnow())
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        click.echo(f"Administrator {email} created.")

    @app.cli.command("cycle-rollover")
    def cycle_rollover():
        """Open the current annual cycle and close old ones (also runs by itself once a day)."""
        ensure_cycles(force=True)
        click.echo("Cycles are up to date.")


app = create_app()
application = app        # some hosts (for example cPanel/Passenger) look for this name

if __name__ == "__main__":
    app.run()
