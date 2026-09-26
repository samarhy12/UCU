from datetime import date

import rules


def test_loan_products():
    assert rules.compute_loan(1000, "emergency")[:2] == (0.05, 1050.0)
    assert rules.LOAN_TYPES["installment"]["days"] == 150 and rules.LOAN_TYPES["installment"]["rate"] == 10
    assert rules.LOAN_TYPES["ds"]["days"] == 47 and rules.LOAN_TYPES["eca"]["rate"] == 3
    assert rules.LOAN_TYPES["nm_emergency"]["days"] == 31 and rules.LOAN_TYPES["nm_emergency"]["rate"] == 10
    assert rules.LOAN_TYPES["nm_installment"]["days"] == 120 and rules.LOAN_TYPES["nm_installment"]["rate"] == 20
    assert len(rules.LOAN_TYPES) == 6


def test_second_guarantor_rule():
    assert not rules.needs_second_guarantor(6000, 9000)     # exactly 2/3 is allowed
    assert rules.needs_second_guarantor(6001, 9000)
    assert rules.needs_second_guarantor(100, 0)


def test_cycle_september_to_august():
    assert rules.cycle_start_year_for(date(2026, 9, 1)) == 2026
    assert rules.cycle_start_year_for(date(2026, 8, 31)) == 2025
    assert rules.cycle_label(2025) == "2025/2026"
    assert rules.cycle_months(2025)[0] == "2025-09" and rules.cycle_months(2025)[-1] == "2026-08"
    assert rules.cycle_start_year_from_month("2026-01") == 2025


def test_account_number_format():
    assert rules.format_account_number(2024, 8, 22) == "UCU240822"
    assert rules.format_account_number(2026, 9, 134) == "UCU2609134"


def test_cleaners():
    assert rules.normalize_ghana_card("gha123456789-0") == "GHA-123456789-0"
    assert rules.normalize_ghana_card("12345") is None
    assert rules.phone_digits("+233 24 123 4567") == rules.phone_digits("0241234567")
    assert rules.valid_email("a@b.co") and not rules.valid_email("a@b")
    assert rules.mask_name("Kwame Mensah") == "K*** M***"
