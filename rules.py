"""Business rules for Unity Credit Union.

Everything in this file is plain Python (no database, no Flask), so the rules are
easy to read, change and test.
"""
import re
from datetime import date, datetime

# ---------------------------------------------------------------------------
# Loan products
# ---------------------------------------------------------------------------
# rate is the flat interest charged on the amount borrowed, in percent.
LOAN_TYPES = {
    "emergency": {
        "label": "Emergency Loan",
        "short": "Emergency",
        "days": 31,
        "rate": 5.0,
        "audience": "member",
        "seasonal": False,
        "description": "Quick help for urgent needs. Repay within 31 days.",
    },
    "installment": {
        "label": "Installment Loan",
        "short": "Installment",
        "days": 150,
        "rate": 10.0,
        "audience": "member",
        "seasonal": False,
        "description": "A longer loan for bigger plans. Repay within 150 days.",
    },
    "ds": {
        "label": "December Special (DS) Loan",
        "short": "DS Loan",
        "days": 47,
        "rate": 3.0,
        "audience": "member",
        "seasonal": True,
        "description": "A low-rate festive season loan. Repay within 47 days.",
    },
    "eca": {
        "label": "Easter Credit Aid (ECA)",
        "short": "ECA",
        "days": 47,
        "rate": 3.0,
        "audience": "member",
        "seasonal": True,
        "description": "A low-rate Easter season loan. Repay within 47 days.",
    },
    "nm_emergency": {
        "label": "Non-Member Emergency Loan",
        "short": "NM Emergency",
        "days": 31,
        "rate": 10.0,
        "audience": "guest",
        "seasonal": False,
        "description": "For non-members. Repay within 31 days.",
    },
    "nm_installment": {
        "label": "Non-Member Installment Loan",
        "short": "NM Installment",
        "days": 120,
        "rate": 20.0,
        "audience": "guest",
        "seasonal": False,
        "description": "For non-members. Repay within 120 days.",
    },
}

MEMBER_LOAN_TYPES = [k for k, v in LOAN_TYPES.items() if v["audience"] == "member"]
GUEST_LOAN_TYPES = [k for k, v in LOAN_TYPES.items() if v["audience"] == "guest"]
SEASONAL_LOAN_TYPES = [k for k, v in LOAN_TYPES.items() if v["seasonal"]]

# A guarantor's yearly earnings must cover the loan: the loan may not be more than this
# share of the guarantor's yearly earnings, otherwise a second guarantor is required.
GUARANTOR_COVER_FRACTION = 2 / 3


def loan_type_info(loan_type):
    return LOAN_TYPES.get(loan_type)


def legacy_loan_type(term_days, is_guest, application_date=None):
    """Work out the loan type of a loan that was recorded before loan types existed."""
    if is_guest:
        return "nm_installment" if term_days and term_days >= 100 else "nm_emergency"
    if term_days and term_days >= 100:
        return "installment"
    if term_days and term_days <= 35:
        return "emergency"
    month = application_date.month if application_date else 12
    return "eca" if month in (2, 3, 4, 5) else "ds"


def money(value):
    return round(float(value or 0) + 1e-9, 2)


def compute_loan(amount, loan_type):
    """Return (rate_as_fraction, total_repayable, interest_amount) for a loan."""
    info = LOAN_TYPES[loan_type]
    rate = info["rate"] / 100.0
    amount = money(amount)
    interest = money(amount * rate)
    return rate, money(amount + interest), interest


def needs_second_guarantor(amount, guarantor_yearly_earnings):
    """True when the loan is more than 2/3 of the first guarantor's yearly earnings."""
    earnings = float(guarantor_yearly_earnings or 0)
    return float(amount) > earnings * GUARANTOR_COVER_FRACTION + 1e-9


def guarantor_cover_limit(guarantor_yearly_earnings):
    return money(float(guarantor_yearly_earnings or 0) * GUARANTOR_COVER_FRACTION)


# ---------------------------------------------------------------------------
# Annual cycle (1 September to 31 August)
# ---------------------------------------------------------------------------
CYCLE_START_MONTH = 9


def cycle_start_year_for(d):
    """The calendar year in which the cycle containing date d started."""
    return d.year if d.month >= CYCLE_START_MONTH else d.year - 1


def cycle_label(start_year):
    return f"{start_year}/{start_year + 1}"


def cycle_bounds(start_year):
    return date(start_year, 9, 1), date(start_year + 1, 8, 31)


def cycle_start_year_from_month(month_str):
    """month_str looks like '2025-06'."""
    year, month = int(month_str[:4]), int(month_str[5:7])
    return year if month >= CYCLE_START_MONTH else year - 1


def cycle_months(start_year):
    """The twelve 'YYYY-MM' strings of a cycle, September first."""
    months = []
    for i in range(12):
        m = CYCLE_START_MONTH + i
        y = start_year + (m - 1) // 12
        m = (m - 1) % 12 + 1
        months.append(f"{y}-{m:02d}")
    return months


def month_label(month_str):
    return datetime.strptime(month_str, "%Y-%m").strftime("%B %Y")


# ---------------------------------------------------------------------------
# Account numbers: UCU + year (2 digits) + month verified (2 digits) + member number
# ---------------------------------------------------------------------------
def format_account_number(year, month, member_number):
    return f"UCU{year % 100:02d}{month:02d}{member_number:02d}"


# ---------------------------------------------------------------------------
# Validators and cleaners
# ---------------------------------------------------------------------------
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_GHANA_CARD_RE = re.compile(r"^GHA-?(\d{9})-?(\d)$")


def valid_email(value):
    return bool(value and len(value) <= 120 and _EMAIL_RE.match(value))


def normalize_ghana_card(value):
    """Return GHA-123456789-0 style text, or None when the number is not valid."""
    cleaned = re.sub(r"[\s]", "", (value or "").upper())
    match = _GHANA_CARD_RE.match(cleaned)
    if not match:
        return None
    return f"GHA-{match.group(1)}-{match.group(2)}"


def phone_digits(value):
    """Last nine digits of a phone number, used to compare numbers written in different ways."""
    digits = re.sub(r"\D", "", value or "")
    return digits[-9:] if len(digits) >= 9 else digits


def valid_phone(value):
    return len(phone_digits(value)) == 9


def age_on(dob, today=None):
    today = today or date.today()
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


def mask_name(full_name):
    """K*** M*** style text, used when confirming that a UCU number exists."""
    parts = [p for p in (full_name or "").split() if p]
    return " ".join(p[0] + "***" for p in parts) or "***"
