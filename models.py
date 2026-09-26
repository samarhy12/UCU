from datetime import date, datetime, timedelta, timezone

from flask_login import UserMixin
from sqlalchemy import func, true, false
from werkzeug.security import check_password_hash, generate_password_hash

import rules
from extensions import db


def utcnow():
    """Current UTC time without timezone info (Ghana time is UTC)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Members, guests and administrators (existing table: "user")
# ---------------------------------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = "user"

    # ---- columns that already exist in the live database ----
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_guest = db.Column(db.Boolean, default=False)   # non-member loan applicant
    national_id = db.Column(db.String(20), unique=True, nullable=False)   # Ghana Card number
    account_number = db.Column(db.String(20), unique=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    other_names = db.Column(db.String(50), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=False)
    occupation = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    city = db.Column(db.String(100), nullable=False)       # shown as "Place of living"
    state = db.Column(db.String(100), nullable=False)      # shown as "Region"
    country = db.Column(db.String(100), nullable=False)
    national_id_file = db.Column(db.String(255), nullable=True)
    passport_photo = db.Column(db.String(255), nullable=True)

    # ---- columns added by the "ucu v2" migration ----
    is_active_member = db.Column("is_active", db.Boolean, nullable=False, default=True, server_default=true())
    hometown = db.Column(db.String(100), nullable=True)
    introducer = db.Column(db.String(150), nullable=True)
    nok_name = db.Column(db.String(120), nullable=True)
    nok_phone = db.Column(db.String(30), nullable=True)
    nok_relationship = db.Column(db.String(50), nullable=True)
    member_number = db.Column(db.Integer, nullable=True, unique=True, index=True)
    created_at = db.Column(db.DateTime, nullable=True, default=utcnow)
    verified_at = db.Column(db.DateTime, nullable=True)
    deactivated_at = db.Column(db.DateTime, nullable=True)
    must_change_password = db.Column(db.Boolean, nullable=False, default=False, server_default=false())
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)

    contributions = db.relationship("Contribution", backref="user", lazy=True,
                                    foreign_keys="Contribution.user_id")
    loans = db.relationship("Loan", backref="user", lazy=True, foreign_keys="Loan.user_id")
    guarantees = db.relationship("Loan", backref="guarantor", lazy=True, foreign_keys="Loan.guarantor_id")
    guarantees_second = db.relationship("Loan", backref="guarantor2", lazy=True,
                                        foreign_keys="Loan.guarantor2_id")

    # ---- password handling ----
    def set_password(self, raw_password):
        # pbkdf2 keeps the hash short and matches the hashes already stored in the database.
        self.password_hash = generate_password_hash(raw_password, method="pbkdf2:sha256")

    def check_password(self, raw_password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, raw_password)

    @property
    def is_locked(self):
        return bool(self.locked_until and self.locked_until > utcnow())

    def register_failed_login(self, max_attempts, lockout_minutes):
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = utcnow() + timedelta(minutes=lockout_minutes)
            self.failed_login_attempts = 0

    def register_successful_login(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login_at = utcnow()

    # Flask-Login uses is_active to decide whether an account may sign in.
    @property
    def is_active(self):
        return bool(self.is_active_member)

    # ---- descriptive helpers ----
    @property
    def full_name(self):
        return " ".join(p for p in (self.first_name, self.other_names, self.last_name) if p)

    @property
    def display_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def initials(self):
        return ((self.first_name or "?")[:1] + (self.last_name or "")[:1]).upper()

    @property
    def is_member(self):
        return not self.is_guest and not self.is_admin

    @property
    def status(self):
        if self.is_admin:
            return "admin"
        if self.is_guest:
            return "guest"
        if not self.is_active_member:
            return "inactive"
        if not self.is_verified:
            return "pending"
        return "active"

    @property
    def role_label(self):
        return {"admin": "Administrator", "guest": "Non-member", "pending": "Pending member",
                "inactive": "Exited member", "active": "Member"}[self.status]

    @property
    def can_use_member_services(self):
        return self.is_member and self.is_verified and self.is_active_member

    # ---- money helpers ----
    def total_contributions(self):
        return float(db.session.query(func.coalesce(func.sum(Contribution.amount), 0.0))
                     .filter(Contribution.user_id == self.id).scalar() or 0.0)

    def cycle_contributions(self, start_year):
        months = rules.cycle_months(start_year)
        return float(db.session.query(func.coalesce(func.sum(Contribution.amount), 0.0))
                     .filter(Contribution.user_id == self.id, Contribution.month.in_(months)).scalar() or 0.0)

    def month_contributions(self, month):
        return float(db.session.query(func.coalesce(func.sum(Contribution.amount), 0.0))
                     .filter(Contribution.user_id == self.id, Contribution.month == month).scalar() or 0.0)

    @property
    def monthly_target(self):
        target = (MonthlySavingsTarget.query.filter_by(user_id=self.id, is_active=True)
                  .order_by(MonthlySavingsTarget.id.desc()).first())
        return target.target_amount if target else None

    @property
    def active_loan(self):
        return Loan.get_active_loan(self.id)

    @property
    def open_loan(self):
        """A loan that is waiting for a decision or is still being repaid."""
        return (Loan.query.filter(Loan.user_id == self.id)
                .filter((Loan.status == "pending") |
                        ((Loan.status == "approved") & (Loan.remaining_amount > 0)))
                .order_by(Loan.id.desc()).first())

    def __repr__(self):
        return f"<User {self.account_number or self.email}>"


# ---------------------------------------------------------------------------
# Savings
# ---------------------------------------------------------------------------
class MonthlySavingsTarget(db.Model):
    __tablename__ = "monthly_savings_target"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    target_amount = db.Column(db.Float, nullable=False)
    start_date = db.Column(db.DateTime, default=utcnow)
    is_active = db.Column(db.Boolean, default=True)


class Contribution(db.Model):
    __tablename__ = "contribution"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=utcnow)
    contribution_type = db.Column(db.String(20), default="regular")   # regular | monthly_savings
    month = db.Column(db.String(7), nullable=False)                   # YYYY-MM

    # added by the "ucu v2" migration
    receipt_no = db.Column(db.String(30), nullable=True, unique=True, index=True)
    recorded_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    note = db.Column(db.String(200), nullable=True)

    recorder = db.relationship("User", foreign_keys=[recorded_by])

    @property
    def cycle_start_year(self):
        return rules.cycle_start_year_from_month(self.month)

    @property
    def month_label(self):
        return rules.month_label(self.month)


# ---------------------------------------------------------------------------
# Loans
# ---------------------------------------------------------------------------
class Loan(db.Model):
    __tablename__ = "loan"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=True)     # stored as a fraction, 0.05 = 5%
    total_amount = db.Column(db.Float, nullable=True)
    amount_paid = db.Column(db.Float, default=0.0)
    remaining_amount = db.Column(db.Float, nullable=True)
    purpose = db.Column(db.String(200), nullable=False)
    guarantor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    term = db.Column(db.Integer, nullable=False)           # days
    income = db.Column(db.Float, nullable=False)           # applicant's monthly income
    status = db.Column(db.String(20), default="pending")  # pending | approved | rejected | paid | cancelled
    application_date = db.Column(db.DateTime, default=utcnow)
    approval_date = db.Column(db.DateTime, nullable=True)
    repayment_date = db.Column(db.DateTime, nullable=True)
    paid_date = db.Column(db.DateTime, nullable=True)

    # added by the "ucu v2" migration
    loan_type = db.Column(db.String(20), nullable=True)
    reference = db.Column(db.String(20), nullable=True, unique=True, index=True)
    guarantor_earnings = db.Column(db.Float, nullable=True)      # first guarantor's yearly earnings
    guarantor2_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    guarantor2_earnings = db.Column(db.Float, nullable=True)
    cancelled_date = db.Column(db.DateTime, nullable=True)
    decision_note = db.Column(db.String(255), nullable=True)

    # Non-member guarantor details (for guest loans)
    guarantor2_name = db.Column(db.String(255), nullable=True)
    guarantor2_email = db.Column(db.String(255), nullable=True)
    guarantor2_phone = db.Column(db.String(50), nullable=True)

    payments = db.relationship("LoanPayment", backref="loan", lazy=True,
                               order_by="LoanPayment.id")

    # ---- lookups ----
    @staticmethod
    def get_active_loan(user_id):
        return Loan.query.filter(Loan.user_id == user_id, Loan.status == "approved",
                                 Loan.remaining_amount > 0).first()

    @staticmethod
    def get_paid_loans(user_id=None):
        q = Loan.query.filter(Loan.status == "paid")
        if user_id:
            q = q.filter(Loan.user_id == user_id)
        return q.order_by(Loan.paid_date.desc()).all()

    # ---- display helpers ----
    @property
    def type_info(self):
        return rules.LOAN_TYPES.get(self.loan_type or "")

    @property
    def type_label(self):
        info = self.type_info
        if info:
            return info["label"]
        return f"{self.term}-day loan"

    @property
    def rate_percent(self):
        if self.interest_rate is not None:
            return round(self.interest_rate * 100, 2)
        info = self.type_info
        return info["rate"] if info else None

    @property
    def is_overdue(self):
        return bool(self.status == "approved" and (self.remaining_amount or 0) > 0
                    and self.repayment_date and self.repayment_date < utcnow())

    @property
    def days_left(self):
        if not self.repayment_date:
            return None
        return (self.repayment_date.date() - utcnow().date()).days

    @property
    def display_status(self):
        return "overdue" if self.is_overdue else (self.status or "pending")

    @property
    def progress_percent(self):
        if not self.total_amount:
            return 0
        return max(0, min(100, round((self.amount_paid or 0) / self.total_amount * 100)))

    @property
    def guarantors(self):
        return [g for g in (self.guarantor, self.guarantor2) if g is not None]

    @property
    def cover_limit(self):
        return rules.guarantor_cover_limit(self.guarantor_earnings)

    @property
    def is_guest_loan(self):
        return bool(self.user and self.user.is_guest)

    # ---- state changes ----
    def approve(self, when=None):
        when = when or utcnow()
        # Loans keep the terms they were applied for. Older loans without a type fall back to the
        # rate that matches their number of days.
        if self.loan_type in rules.LOAN_TYPES:
            rate, total, _ = rules.compute_loan(self.amount, self.loan_type)
            self.term = rules.LOAN_TYPES[self.loan_type]["days"]
        else:
            rate = {30: 0.055, 31: 0.05, 47: 0.03, 150: 0.10}.get(self.term, 0.05)
            total = rules.money(self.amount * (1 + rate))
        self.interest_rate = rate
        self.total_amount = total
        self.amount_paid = 0.0
        self.remaining_amount = total
        self.status = "approved"
        self.approval_date = when
        self.repayment_date = when + timedelta(days=self.term)

    def reject(self, note=None, when=None):
        self.status = "rejected"
        self.approval_date = when or utcnow()
        self.decision_note = (note or "")[:255] or None

    def cancel(self, when=None):
        self.status = "cancelled"
        self.cancelled_date = when or utcnow()

    def apply_payment(self, amount, recorded_by=None, when=None, note=None):
        """Record a repayment. Returns the LoanPayment, or None when the amount is not valid."""
        amount = rules.money(amount)
        remaining = rules.money(self.remaining_amount)
        if self.status != "approved" or amount <= 0 or amount > remaining + 0.005:
            return None
        when = when or utcnow()
        self.amount_paid = rules.money((self.amount_paid or 0) + amount)
        self.remaining_amount = rules.money(remaining - amount)
        if self.remaining_amount <= 0.004:
            self.remaining_amount = 0.0
            self.status = "paid"
            self.paid_date = when
        payment = LoanPayment(loan=self, amount=amount, date=when, recorded_by=recorded_by, note=note)
        db.session.add(payment)
        db.session.flush()
        payment.receipt_no = make_receipt_no("LP", when, payment.id)
        return payment

    def reverse_payment(self, payment, reversed_by=None):
        if payment.is_reversed or payment.loan_id != self.id:
            return False
        payment.is_reversed = True
        payment.reversed_at = utcnow()
        payment.reversed_by = reversed_by
        self.amount_paid = max(0.0, rules.money((self.amount_paid or 0) - payment.amount))
        self.remaining_amount = rules.money((self.remaining_amount or 0) + payment.amount)
        if self.status == "paid" and self.remaining_amount > 0:
            self.status = "approved"
            self.paid_date = None
        return True


class LoanPayment(db.Model):
    __tablename__ = "loan_payment"

    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey("loan.id"), nullable=False, index=True)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=utcnow)
    receipt_no = db.Column(db.String(30), nullable=True, unique=True, index=True)
    recorded_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    note = db.Column(db.String(200), nullable=True)
    is_reversed = db.Column(db.Boolean, nullable=False, default=False, server_default=false())
    reversed_at = db.Column(db.DateTime, nullable=True)
    reversed_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    recorder = db.relationship("User", foreign_keys=[recorded_by])


class MonthlyTransaction(db.Model):
    """Monthly Excel statements uploaded by the administrator (existing table)."""
    __tablename__ = "monthly_transaction"

    id = db.Column(db.Integer, primary_key=True)
    month = db.Column(db.String(7), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


def make_receipt_no(prefix, when, record_id):
    return f"{prefix}{when:%y%m%d}-{record_id:05d}"


# ---------------------------------------------------------------------------
# Annual cycle and dividends (new)
# ---------------------------------------------------------------------------
class Cycle(db.Model):
    __tablename__ = "cycle"

    id = db.Column(db.Integer, primary_key=True)
    start_year = db.Column(db.Integer, nullable=False, unique=True)
    label = db.Column(db.String(9), nullable=False, unique=True)     # 2025/2026
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False, default="open")   # open | closed
    closed_at = db.Column(db.DateTime, nullable=True)
    dividend_rate = db.Column(db.Float, nullable=True)                 # percent
    dividend_declared_at = db.Column(db.DateTime, nullable=True)

    dividends = db.relationship("Dividend", backref="cycle", lazy=True)

    @property
    def months(self):
        return rules.cycle_months(self.start_year)

    @staticmethod
    def current():
        return Cycle.query.filter_by(start_year=rules.cycle_start_year_for(date.today())).first()

    def total_contributions(self):
        return float(db.session.query(func.coalesce(func.sum(Contribution.amount), 0.0))
                     .filter(Contribution.month.in_(self.months)).scalar() or 0.0)


class Dividend(db.Model):
    __tablename__ = "dividend"
    __table_args__ = (db.UniqueConstraint("cycle_id", "user_id", name="uq_dividend_cycle_user"),)

    id = db.Column(db.Integer, primary_key=True)
    cycle_id = db.Column(db.Integer, db.ForeignKey("cycle.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    contribution_total = db.Column(db.Float, nullable=False)
    rate = db.Column(db.Float, nullable=False)              # percent
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(10), nullable=False, default="pending")   # pending | paid
    paid_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)

    user = db.relationship("User", foreign_keys=[user_id])


# ---------------------------------------------------------------------------
# Public content managed by the administrator (new)
# ---------------------------------------------------------------------------
EXECUTIVE_POSITIONS = ["Chairman", "Secretary", "Loan Officer", "Finance Director",
                       "Auditor", "PRO", "Trustee"]


class Executive(db.Model):
    __tablename__ = "executive"

    id = db.Column(db.Integer, primary_key=True)
    position = db.Column(db.String(60), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    title = db.Column(db.String(20), nullable=True)          # Mr., Mrs., Dr. ...
    bio = db.Column(db.String(300), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    photo = db.Column(db.String(255), nullable=True)
    display_order = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default=true())

    @property
    def display_name(self):
        return f"{self.title} {self.full_name}".strip() if self.title else self.full_name

    @staticmethod
    def listing():
        return (Executive.query.filter_by(is_active=True)
                .order_by(Executive.display_order, Executive.id).all())


class Advert(db.Model):
    __tablename__ = "advert"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    body = db.Column(db.String(500), nullable=True)
    image = db.Column(db.String(255), nullable=True)
    link_url = db.Column(db.String(255), nullable=True)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default=true())
    display_order = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    created_at = db.Column(db.DateTime, default=utcnow)

    @property
    def is_running(self):
        today = date.today()
        return bool(self.is_active and (not self.start_date or self.start_date <= today)
                    and (not self.end_date or self.end_date >= today))

    @staticmethod
    def running():
        today = date.today()
        return (Advert.query.filter(Advert.is_active == true())
                .filter((Advert.start_date.is_(None)) | (Advert.start_date <= today))
                .filter((Advert.end_date.is_(None)) | (Advert.end_date >= today))
                .order_by(Advert.display_order, Advert.id.desc()).all())


class GalleryPhoto(db.Model):
    __tablename__ = "gallery_photo"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    caption = db.Column(db.String(300), nullable=True)
    photo = db.Column(db.String(255), nullable=False)
    display_order = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default=true())
    created_at = db.Column(db.DateTime, default=utcnow)

    @staticmethod
    def listing(limit=None):
        q = (GalleryPhoto.query.filter(GalleryPhoto.is_active == true())
             .order_by(GalleryPhoto.display_order, GalleryPhoto.id))
        return q.limit(limit).all() if limit else q.all()


class HomeSlide(db.Model):
    """A slide in the carousel on the home page."""
    __tablename__ = "home_slide"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    caption = db.Column(db.String(200), nullable=True)
    image = db.Column(db.String(255), nullable=False)
    link_url = db.Column(db.String(255), nullable=True)
    display_order = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default=true())
    created_at = db.Column(db.DateTime, default=utcnow)

    @staticmethod
    def listing():
        return (HomeSlide.query.filter(HomeSlide.is_active == true())
                .order_by(HomeSlide.display_order, HomeSlide.id).all())


# ---------------------------------------------------------------------------
# Settings and audit trail (new)
# ---------------------------------------------------------------------------
class AppSetting(db.Model):
    __tablename__ = "app_setting"

    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(255), nullable=True)


def get_setting(key, default=None):
    row = db.session.get(AppSetting, key)
    return row.value if row and row.value is not None else default


def set_setting(key, value):
    row = db.session.get(AppSetting, key)
    if row is None:
        row = AppSetting(key=key)
        db.session.add(row)
    row.value = value


def loan_type_is_open(loan_type):
    """Seasonal loans (DS and ECA) are opened and closed by the administrator."""
    info = rules.LOAN_TYPES.get(loan_type)
    if not info:
        return False
    if not info["seasonal"]:
        return True
    return get_setting(f"loan_open_{loan_type}", "0") == "1"


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(120), nullable=True)
    detail = db.Column(db.String(500), nullable=True)

    actor = db.relationship("User", foreign_keys=[actor_id])


def log_action(actor, action, target=None, detail=None):
    db.session.add(AuditLog(actor_id=getattr(actor, "id", None), action=action,
                            target=(target or "")[:120] or None, detail=(detail or "")[:500] or None))


GREETING_FIELDS = ("title", "intro", "callout", "closing", "date", "signoff", "image", "active")


def get_greeting(only_active=True):
    """The season greeting shown on the home page, or None when it is switched off or empty."""
    data = {f: get_setting(f"greeting_{f}", "") or "" for f in GREETING_FIELDS}
    if only_active and (data["active"] != "1" or not data["title"]):
        return None
    data["paragraphs"] = [p.strip() for p in data["intro"].split("\n\n") if p.strip()]
    return data
