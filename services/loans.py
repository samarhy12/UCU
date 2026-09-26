"""Loan application rules shared by the member loan form and the non-member (NMLOAN) form."""
from sqlalchemy import func

import rules
from extensions import db
from models import Loan, User, loan_type_is_open, utcnow

MAX_LOAN_AMOUNT = 1_000_000      # a typing-mistake guard, not a business limit


def available_loan_types(audience):
    """Loan types that can be applied for right now, as a list of (key, info)."""
    return [(key, info) for key, info in rules.LOAN_TYPES.items()
            if info["audience"] == audience and loan_type_is_open(key)]


def find_guarantor_by_ucu_number(ucu_number):
    ucu = (ucu_number or "").strip().upper().replace(" ", "")
    if not ucu:
        return None
    return (User.query.filter(func.upper(User.account_number) == ucu)
            .filter(User.is_guest == False, User.is_admin == False,      # noqa: E712
                    User.is_verified == True, User.is_active_member == True)  # noqa: E712
            .first())


def _to_float(value):
    try:
        return float((value or "").replace(",", "").strip())
    except ValueError:
        return None


def read_guarantor(form, prefix, applicant_id, label, optional_email=False, allow_non_member=False):
    """Read one guarantor block from the form.

    A guarantor must be a UCU member, identified by their UCU number. Their email or phone number
    must match what UCU has on record, so a loan cannot name someone who did not agree to it.
    For non-member loans, the second guarantor can be a non-member (close friend/family).
    Returns (user, yearly_earnings, errors).
    """
    ucu = form.get(f"{prefix}_ucu_number", "")
    name = (form.get(f"{prefix}_name") or "").strip()
    email = (form.get(f"{prefix}_email") or "").strip().lower()
    phone = (form.get(f"{prefix}_phone") or "").strip()
    earnings = _to_float(form.get(f"{prefix}_earnings"))
    acknowledgment = form.get(f"{prefix}_acknowledgment")

    errors = []
    if not name:
        errors.append(f"{label}: full name is required.")
    if not optional_email:
        if not rules.valid_email(email):
            errors.append(f"{label}: enter a valid email address.")
    else:
        # If email is optional, only validate it if provided
        if email and not rules.valid_email(email):
            errors.append(f"{label}: enter a valid email address if provided.")
    if not rules.valid_phone(phone):
        errors.append(f"{label}: enter a valid telephone number.")
    if not allow_non_member and not (ucu or "").strip():
        errors.append(f"{label}: UCU number is required.")
    if earnings is None or earnings <= 0:
        errors.append(f"{label}: enter the guarantor's total yearly earnings.")
    if not acknowledgment:
        errors.append(f"{label}: the guarantor must acknowledge their legal liability.")
    if errors:
        return None, earnings, errors

    # For non-member guarantors (close friend/family), skip UCU validation
    if allow_non_member and not (ucu or "").strip():
        # Return a placeholder object for non-member guarantors
        class NonMemberGuarantor:
            def __init__(self, name, email, phone):
                self.id = None
                self.display_name = name
                self.email = email
                self.phone_number = phone
                self.account_number = "N/A (Non-Member)"
                self.can_use_member_services = False
                self.first_name = name.split()[0] if name else ""
                self.last_name = " ".join(name.split()[1:]) if len(name.split()) > 1 else ""

        placeholder = NonMemberGuarantor(name, email, phone)
        return placeholder, earnings, []

    guarantor = find_guarantor_by_ucu_number(ucu)
    if guarantor is None:
        return None, earnings, [f"{label}: that UCU number was not found, or the member is not active."]
    if applicant_id and guarantor.id == applicant_id:
        return None, earnings, [f"{label}: you cannot guarantee your own loan."]

    name_words = {w.lower().strip(".,") for w in name.split()}
    record_words = {w.lower() for w in (guarantor.first_name, guarantor.last_name) if w}
    # If email is optional, don't require email match, only phone match
    if optional_email:
        contact_matches = rules.phone_digits(guarantor.phone_number) == rules.phone_digits(phone)
    else:
        contact_matches = (guarantor.email or "").lower() == email or \
            rules.phone_digits(guarantor.phone_number) == rules.phone_digits(phone)
    if not (name_words & record_words) or not contact_matches:
        return None, earnings, [f"{label}: the details do not match our records for that UCU number."]
    return guarantor, earnings, []


def build_loan(form, applicant, audience):
    """Check a loan form and build (but do not save) a Loan.

    Returns (loan, errors). `loan` is None when there are errors.
    """
    errors = []

    loan_type = form.get("loan_type", "")
    info = rules.LOAN_TYPES.get(loan_type)
    if not info or info["audience"] != audience:
        errors.append("Choose a loan type.")
    elif not loan_type_is_open(loan_type):
        errors.append(f"The {info['label']} is not open for applications at the moment.")

    amount = _to_float(form.get("amount"))
    if amount is None or amount <= 0:
        errors.append("Enter the loan amount you need.")
    elif amount > MAX_LOAN_AMOUNT:
        errors.append("That loan amount is too large. Please check it.")

    income = _to_float(form.get("income"))
    if income is None or income <= 0:
        errors.append("Enter your monthly income.")

    purpose = (form.get("purpose") or "").strip()
    if not purpose:
        errors.append("Tell us what the loan is for.")
    elif len(purpose) > 200:
        errors.append("The purpose is too long (most 200 characters).")

    applicant_id = applicant.id if applicant is not None else None
    if applicant is not None and applicant.open_loan:
        errors.append("You already have a loan that is waiting for a decision or is not fully paid. "
                      "Please finish it before you apply again.")

    g1, g1_earnings, g1_errors = read_guarantor(form, "g1", applicant_id, "Guarantor")
    errors.extend(g1_errors)

    g2 = g2_earnings = None
    is_guest_loan = audience == "guest"
    # All loans require a second guarantor
    needs_second = True
    if needs_second:
        g2, g2_earnings, g2_errors = read_guarantor(form, "g2", applicant_id, "Second guarantor",
                                               optional_email=is_guest_loan, allow_non_member=is_guest_loan)
        errors.extend(g2_errors)
        if g2 is not None and g1 is not None and g2.id == g1.id:
            errors.append("The second guarantor must be a different person.")

    if errors:
        return None, errors

    loan = Loan(
        amount=rules.money(amount), purpose=purpose, income=rules.money(income), status="pending",
        loan_type=loan_type, term=info["days"], guarantor_id=g1.id,
        guarantor_earnings=rules.money(g1_earnings),
        guarantor2_id=g2.id if g2 and g2.id else None,
        guarantor2_earnings=rules.money(g2_earnings) if g2 else None,
        guarantor2_name=g2.display_name if g2 and not g2.id else None,
        guarantor2_email=g2.email if g2 and not g2.id else None,
        guarantor2_phone=g2.phone_number if g2 and not g2.id else None,
        application_date=utcnow())
    rate, total, _ = rules.compute_loan(loan.amount, loan_type)
    loan.interest_rate = rate
    loan.total_amount = total
    loan.amount_paid = 0.0
    loan.remaining_amount = total
    return loan, []


def assign_reference(loan):
    """Give a saved loan its reference, for example LN260012. Call after the loan has an id."""
    loan.reference = f"LN{(loan.application_date or utcnow()):%y}{loan.id:04d}"


def review_checklist(loan):
    """Facts the administrator checks before verifying a loan. Returns a list of dicts."""
    items = []
    applicant = loan.user
    if applicant.is_guest:
        items.append({"ok": True, "text": "Non-member applicant (non-member rates apply)."})
    else:
        ok = applicant.can_use_member_services
        items.append({"ok": ok, "text": "Applicant is a verified, active member." if ok
                      else "Applicant is not a verified, active member."})
        items.append({"ok": True, "text": f"Savings so far: GHS {applicant.total_contributions():,.2f}."})

    other = (Loan.query.filter(Loan.user_id == applicant.id, Loan.id != loan.id)
             .filter((Loan.status == "pending") | ((Loan.status == "approved") & (Loan.remaining_amount > 0)))
             .first())
    items.append({"ok": other is None, "text": "No other open loan." if other is None
                  else f"Applicant has another open loan ({other.reference or other.id})."})

    for label, g, earnings in (("Guarantor", loan.guarantor, loan.guarantor_earnings),
                               ("Second guarantor", loan.guarantor2, loan.guarantor2_earnings)):
        if g is None:
            continue
        ok = g.can_use_member_services
        items.append({"ok": ok, "text": f"{label} {g.display_name} ({g.account_number}) is "
                      f"{'an active member' if ok else 'not an active member'}."})

    limit = loan.cover_limit
    if loan.guarantor2 is None:
        covered = loan.amount <= limit + 0.005
        items.append({"ok": covered, "text": f"Loan is {'within' if covered else 'above'} 2/3 of the "
                      f"guarantor's yearly earnings (limit GHS {limit:,.2f})."})
    else:
        items.append({"ok": True, "text": f"Second guarantor added because the loan is above 2/3 of the first "
                      f"guarantor's yearly earnings (limit GHS {limit:,.2f})."})
    return items
