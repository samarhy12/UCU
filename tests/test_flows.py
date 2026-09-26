import io
import re

import pytest

from extensions import db
from models import (Advert, Contribution, Cycle, Dividend, Executive, Loan, User, get_setting, set_setting)
from tests.conftest import login, make_member, make_user, png_bytes, post

PUBLIC = ["/", "/gallery", "/about", "/services", "/faqs", "/contact", "/login", "/register", "/nmloan", "/loans/verify",
          "/forgot-password", "/static/manifest.json"]


@pytest.mark.parametrize("url", PUBLIC)
def test_public_pages_open(client, url):
    assert client.get(url).status_code == 200


def test_home_has_footer_contact_and_socials(client):
    html = client.get("/").get_data(as_text=True)
    assert "agyareemmanuelosei@gmail.com" in html and "+233247767438" in html
    for word in ("About us", "Services", "FAQs", "Facebook", "WhatsApp", "TikTok", "Forgot password", "Click to register"):
        assert word in html


def test_private_pages_need_login(client):
    for url in ("/dashboard", "/loans", "/admin/", "/admin/members"):
        r = client.get(url)
        assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_csrf_is_enforced(client):
    assert client.post("/login", data={"email": "a@b.co", "password": "x"}).status_code == 400


# ---------------------------------------------------------------- sign in and portals
def test_same_login_page_two_portals(client, admin):
    make_member("m@test.com")
    r = login(client, "admin@test.com")
    assert r.status_code == 302 and r.headers["Location"].endswith("/admin/")
    client.get("/logout")
    r = login(client, "m@test.com")
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")


def test_member_cannot_open_admin(client):
    make_member("m@test.com")
    login(client, "m@test.com")
    assert client.get("/admin/").status_code == 403
    assert client.get("/admin/members").status_code == 403


def test_login_lockout_and_open_redirect(client):
    make_member("m@test.com")
    for _ in range(5):
        login(client, "m@test.com", "wrong")
    assert b"locked" in login(client, "m@test.com").data
    other = make_member("n@test.com", "Kofi", "Boateng")
    r = post(client, "/login?next=https://evil.example", {"email": "n@test.com", "password": "password123"})
    assert "evil.example" not in r.headers["Location"]


def test_wrong_password_and_guest_cannot_sign_in(client):
    make_user("g@test.com", guest=True, verified=False, password=None)
    assert b"Incorrect" in login(client, "g@test.com", "anything").data


# ---------------------------------------------------------------- registration and verification
REG = {"email": "new@test.com", "password": "secret123", "confirm_password": "secret123", "first_name": "Kofi",
       "last_name": "Asante", "other_names": "", "date_of_birth": "1990-05-05", "national_id": "gha123456789-0",
       "occupation": "Farmer", "phone_number": "0244000111", "address": "Main St", "hometown": "Nsawam",
       "city": "Koforidua", "state": "Eastern", "country": "Ghana", "introducer": "",
       "nok_name": "Abena Asante", "nok_phone": "0244000222", "nok_relationship": "Wife"}


def register(client, **over):
    data = dict(REG, **over)
    data["national_id_upload"] = (png_bytes(), "card.png")
    data["passport_photo"] = (png_bytes((10, 90, 10)), "me.png")
    return post(client, "/register", data, content_type="multipart/form-data")


def test_registration_verification_and_account_number(client, admin, mailbox):
    r = register(client)
    assert r.status_code == 302
    user = User.query.filter_by(email="new@test.com").first()
    assert user.status == "pending" and user.national_id == "GHA-123456789-0"
    subjects = [m.subject for m in mailbox]
    assert any("waiting for verification" in s for s in subjects)          # message to the new member
    assert any("New membership sign-up" in s for s in subjects)            # message to the administrator

    # pending members can sign in, but see the pending notice and cannot borrow
    login(client, "new@test.com", "secret123")
    assert b"waiting for verification" in client.get("/dashboard").data
    assert client.get("/loans").status_code == 302
    client.get("/logout")

    mailbox.clear()
    login(client, "admin@test.com")
    r = post(client, f"/admin/members/{user.id}/verify")
    assert r.status_code == 302
    db.session.refresh(user)
    assert re.fullmatch(r"UCU\d{2}\d{2}\d{2,}", user.account_number)
    assert user.account_number.endswith(f"{user.member_number:02d}")
    assert any(user.account_number in m.html for m in mailbox)


def test_registration_validation(client):
    assert register(client, first_name="").status_code == 400
    assert register(client, date_of_birth="2015-01-01").status_code == 400          # under 18
    assert register(client, national_id="12345").status_code == 400
    assert register(client, confirm_password="different").status_code == 400
    r = post(client, "/register", dict(REG), content_type="multipart/form-data")     # no files
    assert r.status_code == 400
    bad = dict(REG, national_id_upload=(io.BytesIO(b"not an image"), "x.png"), passport_photo=(png_bytes(), "p.png"))
    assert post(client, "/register", bad, content_type="multipart/form-data").status_code == 400
    assert User.query.count() == 0


def test_registration_accepts_pdf_ghana_card(client):
    data = dict(REG, national_id_upload=(io.BytesIO(b"%PDF-1.4 fake but has the header"), "card.pdf"),
                passport_photo=(png_bytes(), "me.png"))
    assert post(client, "/register", data, content_type="multipart/form-data").status_code == 302
    assert User.query.filter_by(email="new@test.com").first().national_id_file.endswith(".pdf")


def test_duplicate_email_rejected(client):
    assert register(client).status_code == 302
    assert register(client, national_id="GHA-999999999-9").status_code == 400


def test_deny_signup_emails_and_removes(client, admin, mailbox):
    register(client)
    user = User.query.filter_by(email="new@test.com").first()
    login(client, "admin@test.com")
    mailbox.clear()
    post(client, f"/admin/members/{user.id}/deny", {"reason": "Blurry card"})
    assert User.query.filter_by(email="new@test.com").first() is None
    assert any("could not be verified" in m.subject and "Blurry card" in m.html for m in mailbox)


# ---------------------------------------------------------------- password reset
def test_password_reset_link_works_once(client, mailbox):
    make_member("m@test.com")
    post(client, "/forgot-password", {"email": "m@test.com"})
    link = re.search(r'href="([^"]*reset-password/[^"]+)"', mailbox[-1].html).group(1)
    path = link.split("localhost", 1)[-1]
    assert post(client, path, {"password": "brandnew99", "confirm_password": "brandnew99"}).status_code == 302
    assert login(client, "m@test.com", "brandnew99").status_code == 302
    client.get("/logout")
    assert client.get(path).status_code == 302        # link no longer valid
    # unknown email gives the same answer
    r = post(client, "/forgot-password", {"email": "nobody@test.com"}, follow_redirects=True)
    assert b"If that email belongs" in r.data


def test_admin_reset_forces_password_change(admin_client, mailbox):
    m = make_member("m@test.com")
    r = post(admin_client, f"/admin/members/{m.id}/reset-password")
    temp = re.search(r"select-all\">([^<]+)<", r.get_data(as_text=True)).group(1)
    admin_client.get("/logout")
    login(admin_client, "m@test.com", temp)
    assert "/change-password" in admin_client.get("/dashboard").headers["Location"]


# ---------------------------------------------------------------- monthly contributions
def test_record_contribution_receipt_and_totals(admin_client, mailbox):
    m = make_member("m@test.com")
    month = __import__("datetime").date.today().strftime("%Y-%m")
    post(admin_client, f"/admin/contributions/record/{m.id}", {"amount": "100", "month": month})
    post(admin_client, f"/admin/contributions/record/{m.id}", {"amount": "50.50", "month": month})
    rows = Contribution.query.filter_by(user_id=m.id).all()
    assert [r.amount for r in rows] == [100.0, 50.5] and all(r.receipt_no for r in rows)
    assert len({r.receipt_no for r in rows}) == 2
    last = mailbox[-1]
    assert "Total savings so far" in last.html and "150.50" in last.html
    assert m.total_contributions() == 150.5


def test_record_rejects_bad_input(admin_client):
    m = make_member("m@test.com")
    for data in ({"amount": "0", "month": "2026-09"}, {"amount": "abc", "month": "2026-09"}, {"amount": "10", "month": "1999-01"}):
        post(admin_client, f"/admin/contributions/record/{m.id}", data)
    assert Contribution.query.count() == 0


def test_reverse_contribution(admin_client, mailbox):
    m = make_member("m@test.com")
    month = __import__("datetime").date.today().strftime("%Y-%m")
    post(admin_client, f"/admin/contributions/record/{m.id}", {"amount": "80", "month": month})
    c = Contribution.query.first()
    post(admin_client, f"/admin/contributions/{c.id}/reverse")
    assert Contribution.query.count() == 0 and "reversed" in mailbox[-1].subject


def test_member_sees_contributions_by_cycle(client):
    from datetime import date
    m = make_member("m@test.com")
    db.session.add(Contribution(user_id=m.id, amount=70, month="2025-09", contribution_type="monthly_savings"))
    db.session.add(Contribution(user_id=m.id, amount=30, month="2026-08", contribution_type="monthly_savings"))
    db.session.commit()
    login(client, "m@test.com")
    html = client.get("/my/contributions?cycle=2025").get_data(as_text=True)
    assert "2025/2026" in html and "100.00" in html


# ---------------------------------------------------------------- cycles and dividends
def test_cycles_open_automatically_and_dividend(admin_client, mailbox):
    from datetime import date
    from services.cycles import ensure_cycles
    m = make_member("m@test.com")
    db.session.add(Contribution(user_id=m.id, amount=200, month="2023-10", contribution_type="monthly_savings"))
    db.session.commit()
    ensure_cycles(force=True)
    cycles = Cycle.query.order_by(Cycle.start_year).all()
    assert cycles[0].label == "2023/2024" and cycles[0].status == "closed"
    assert cycles[-1].start_year >= date.today().year - 1 and cycles[-1].status == "open"
    assert len({c.start_year for c in cycles}) == len(cycles)

    first = cycles[0]
    assert post(admin_client, f"/admin/cycles/{cycles[-1].id}/dividends", {"rate": "10"}).status_code == 302
    assert Dividend.query.count() == 0                                # open cycle: refused
    post(admin_client, f"/admin/cycles/{first.id}/dividends", {"rate": "10"})
    d = Dividend.query.one()
    assert d.amount == 20.0
    # contributions of a declared cycle are locked
    c = Contribution.query.first()
    post(admin_client, f"/admin/contributions/{c.id}/reverse")
    assert Contribution.query.count() == 1
    post(admin_client, f"/admin/dividends/{d.id}/paid")
    assert Dividend.query.one().status == "paid" and "dividend" in mailbox[-1].subject.lower()


# ---------------------------------------------------------------- loans
def guarantor_fields(g, prefix="g1", earnings="12000"):
    return {f"{prefix}_name": g.display_name, f"{prefix}_email": g.email, f"{prefix}_phone": g.phone_number,
            f"{prefix}_ucu_number": g.account_number, f"{prefix}_earnings": earnings}


def loan_form(g, **over):
    data = {"loan_type": "emergency", "amount": "1000", "income": "2000", "purpose": "School fees"}
    data.update(guarantor_fields(g))
    data.update(over)
    return data


def test_member_loan_full_lifecycle(client, admin, mailbox):
    borrower = make_member("b@test.com", "Kojo", "Borrower", phone="0200000001")
    guarantor = make_member("g@test.com", "Yaw", "Guarantor", phone="0200000002")
    login(client, "b@test.com")
    r = post(client, "/loans/new", loan_form(guarantor))
    assert r.status_code == 302
    loan = Loan.query.one()
    assert loan.status == "pending" and loan.reference.startswith("LN") and loan.term == 31
    assert loan.total_amount == 1050 and loan.guarantor_id == guarantor.id and loan.guarantor2_id is None
    assert any("named as a loan guarantor" in m.subject for m in mailbox)
    assert any("New loan application" in m.subject for m in mailbox)

    # only one open loan at a time
    assert post(client, "/loans/new", loan_form(guarantor)).status_code == 400
    # a stranger cannot look at it
    make_member("x@test.com", "Other", "Person", phone="0200000003")
    other = client.application.test_client()
    login(other, "x@test.com")
    assert other.get(f"/loans/{loan.id}").status_code == 403

    # admin approves
    adm = client.application.test_client()
    login(adm, "admin@test.com")
    html = adm.get(f"/admin/loans/{loan.id}").get_data(as_text=True)
    assert "Verify &amp; approve" in html
    post(adm, f"/admin/loans/{loan.id}/approve")
    db.session.refresh(loan)
    assert loan.status == "approved" and loan.remaining_amount == 1050
    assert (loan.repayment_date - loan.approval_date).days == 31

    # payments, over-payment refused, reversal, full payment
    post(adm, f"/admin/loans/{loan.id}/payment", {"amount": "500"})
    post(adm, f"/admin/loans/{loan.id}/payment", {"amount": "9999"})
    db.session.refresh(loan)
    assert loan.amount_paid == 500 and loan.remaining_amount == 550
    pay = loan.payments[0]
    post(adm, f"/admin/loans/{loan.id}/payments/{pay.id}/reverse")
    db.session.refresh(loan)
    assert loan.amount_paid == 0 and loan.remaining_amount == 1050
    post(adm, f"/admin/loans/{loan.id}/payment", {"amount": "1050"})
    db.session.refresh(loan)
    assert loan.status == "paid" and loan.paid_date is not None
    assert "fully paid" in mailbox[-1].html.lower()


def test_second_guarantor_required_above_two_thirds(client, admin):
    borrower = make_member("b@test.com", "Kojo", "Borrower", phone="0200000001")
    g1 = make_member("g@test.com", "Yaw", "One", phone="0200000002")
    g2 = make_member("g2@test.com", "Efua", "Two", phone="0200000003")
    login(client, "b@test.com")
    # 1000 is more than 2/3 of 1200 (=800): a second guarantor is needed
    r = post(client, "/loans/new", loan_form(g1, **{"g1_earnings": "1200"}))
    assert r.status_code == 400 and Loan.query.count() == 0
    data = loan_form(g1, **{"g1_earnings": "1200"})
    data.update(guarantor_fields(g2, "g2", "5000"))
    assert post(client, "/loans/new", data).status_code == 302
    loan = Loan.query.one()
    assert loan.guarantor2_id == g2.id and loan.guarantor2_earnings == 5000


def test_guarantor_must_be_real_matching_member(client, admin):
    borrower = make_member("b@test.com", "Kojo", "Borrower", phone="0200000001")
    g = make_member("g@test.com", "Yaw", "Guarantor", phone="0200000002")
    login(client, "b@test.com")
    wrong = loan_form(g, g1_ucu_number="UCU000000")
    assert post(client, "/loans/new", wrong).status_code == 400
    wrong = loan_form(g, g1_email="other@x.com", g1_phone="0209999999")
    assert post(client, "/loans/new", wrong).status_code == 400
    assert post(client, "/loans/new", loan_form(borrower)).status_code == 400          # own loan
    assert Loan.query.count() == 0


def test_seasonal_loans_follow_admin_switch(client, admin):
    make_member("b@test.com", "Kojo", "Borrower", phone="0200000001")
    g = make_member("g@test.com", "Yaw", "Guarantor", phone="0200000002")
    login(client, "b@test.com")
    assert post(client, "/loans/new", loan_form(g, loan_type="ds")).status_code == 400
    set_setting("loan_open_ds", "1")
    db.session.commit()
    assert post(client, "/loans/new", loan_form(g, loan_type="ds")).status_code == 302
    assert Loan.query.one().term == 47


def test_cancel_loan_only_while_pending(client, admin):
    make_member("b@test.com", "Kojo", "Borrower", phone="0200000001")
    g = make_member("g@test.com", "Yaw", "Guarantor", phone="0200000002")
    login(client, "b@test.com")
    post(client, "/loans/new", loan_form(g))
    loan = Loan.query.one()
    post(client, f"/loans/{loan.id}/cancel")
    db.session.refresh(loan)
    assert loan.status == "cancelled"
    post(client, "/loans/new", loan_form(g))                     # can apply again


def test_non_member_loan_and_verify(client, admin, mailbox):
    g = make_member("g@test.com", "Yaw", "Guarantor", phone="0200000002")

    def form(**over):
        data = {"email": "guest@test.com", "first_name": "Guest", "last_name": "Person", "other_names": "",
                "date_of_birth": "1985-02-02", "national_id": "GHA-555555555-5", "occupation": "Driver",
                "phone_number": "0555000111", "address": "Road 1", "city": "Accra", "state": "Greater Accra",
                "country": "Ghana"}
        data.update(loan_form(g, loan_type="nm_installment", amount="500"))
        data.update(over)
        data["national_id_upload"] = (png_bytes(), "id.png")      # fresh files for every request
        data["passport_photo"] = (png_bytes(), "p.png")
        return data

    r = post(client, "/nmloan", form(), content_type="multipart/form-data")
    assert r.status_code == 302
    loan = Loan.query.one()
    assert loan.user.is_guest and loan.term == 120 and loan.total_amount == 600 and loan.interest_rate == 0.2

    # public verify with reference and contact
    ref = loan.reference
    ok = post(client, "/loans/verify", {"reference": ref, "contact": "guest@test.com"})
    assert ref.encode() in ok.data and b"500.00" in ok.data
    ok = post(client, "/loans/verify", {"reference": ref.lower(), "contact": "0555000111"})
    assert b"500.00" in ok.data
    bad = post(client, "/loans/verify", {"reference": ref, "contact": "someone@else.com"})
    assert b"could not find" in bad.data

    # member loan types are not allowed on the non-member form
    assert post(client, "/nmloan", form(loan_type="emergency", email="guest2@test.com", national_id="GHA-666666666-6"),
                content_type="multipart/form-data").status_code == 400
    # the same guest cannot open a second loan while the first is open
    assert post(client, "/nmloan", form(), content_type="multipart/form-data").status_code == 400
    # a member cannot use the non-member form
    m = make_member("mm@test.com", "Some", "Member", phone="0200000009")
    assert post(client, "/nmloan", form(email="mm@test.com", national_id=m.national_id),
                content_type="multipart/form-data").status_code == 400
    assert Loan.query.count() == 1


def test_guarantor_lookup_hides_identity(client):
    g = make_member("g@test.com", "Yaw", "Guarantor", phone="0200000002")
    body = client.get(f"/api/guarantor?ucu={g.account_number}").get_json()
    assert body == {"found": True, "name": "Y*** G***"}
    assert client.get("/api/guarantor?ucu=UCU0").get_json() == {"found": False}


# ---------------------------------------------------------------- member management
def test_deactivate_activate_and_login_block(admin_client):
    m = make_member("m@test.com")
    post(admin_client, f"/admin/members/{m.id}/deactivate")
    db.session.refresh(m)
    assert m.status == "inactive"
    other = admin_client.application.test_client()
    assert b"not active" in login(other, "m@test.com").data
    post(admin_client, f"/admin/members/{m.id}/activate")
    db.session.refresh(m)
    assert m.status == "active"


def test_cannot_deactivate_with_open_loan(admin_client):
    b = make_member("b@test.com", "Kojo", "B", phone="0200000001")
    g = make_member("g@test.com", "Yaw", "G", phone="0200000002")
    loan = Loan(user_id=b.id, guarantor_id=g.id, amount=100, purpose="x", term=31, income=100, status="pending",
                loan_type="emergency")
    db.session.add(loan); db.session.commit()
    post(admin_client, f"/admin/members/{b.id}/deactivate")
    post(admin_client, f"/admin/members/{g.id}/deactivate")
    db.session.refresh(b); db.session.refresh(g)
    assert b.is_active_member and g.is_active_member


def test_delete_member_keeps_other_peoples_loans(admin_client):
    dead = make_member("d@test.com", "Late", "Member", phone="0200000001")
    b = make_member("b@test.com", "Kojo", "Borrower", phone="0200000002")
    db.session.add(Contribution(user_id=dead.id, amount=50, month="2025-10"))
    loan = Loan(user_id=b.id, guarantor_id=dead.id, amount=100, purpose="x", term=31, income=100, status="paid",
                loan_type="emergency", remaining_amount=0)
    db.session.add(loan); db.session.commit()
    assert "/admin/members/" in post(admin_client, f"/admin/members/{dead.id}/delete", {"confirm": "no"}).headers["Location"]
    assert User.query.filter_by(email="d@test.com").count() == 1              # not confirmed
    post(admin_client, f"/admin/members/{dead.id}/delete", {"confirm": "DELETE"})
    assert User.query.filter_by(email="d@test.com").count() == 0
    assert Contribution.query.count() == 0
    db.session.refresh(loan)
    assert loan.guarantor_id is None and Loan.query.count() == 1


def test_admin_adds_member_directly(admin_client, mailbox):
    data = dict(REG, email="direct@test.com")
    data.pop("password"); data.pop("confirm_password")
    r = post(admin_client, "/admin/members/new", data, content_type="multipart/form-data")
    assert r.status_code == 200 and b"Temporary password" in r.data
    u = User.query.filter_by(email="direct@test.com").one()
    assert u.is_verified and u.account_number and u.must_change_password


def test_member_search(admin_client):
    make_member("a@test.com", "Alice", "Zed", phone="0200000001")
    make_member("b@test.com", "Bob", "Yaw", phone="0200000002")
    html = admin_client.get("/admin/members?q=alice").get_data(as_text=True)
    assert "Alice" in html and "Bob" not in html


# ---------------------------------------------------------------- content
def test_adverts_and_executives_on_dashboard(admin_client):
    m = make_member("m@test.com")
    post(admin_client, "/admin/adverts/new", {"title": "Annual meeting", "body": "Saturday 10am", "is_active": "on"},
         content_type="multipart/form-data")
    post(admin_client, "/admin/executives/new", {"position": "Auditor", "full_name": "Ama Auditor", "is_active": "on"},
         content_type="multipart/form-data")
    assert Advert.query.count() == 1 and Executive.query.count() == 1
    member = admin_client.application.test_client()
    login(member, "m@test.com")
    html = member.get("/dashboard").get_data(as_text=True)
    assert "Annual meeting" in html and "Ama Auditor" in html and "Members in UCU" in html
    assert "Ama Auditor" in member.get("/about").get_data(as_text=True)


def test_document_access_control(client, admin):
    from image_utils import save_document
    m = make_member("m@test.com")
    other = make_member("o@test.com", "Other", "One", phone="0200000005")
    from werkzeug.datastructures import FileStorage
    f = save_document(FileStorage(png_bytes(), "a.png"), "id", client.application.config["UPLOAD_FOLDER"], {"png"})
    m.national_id_file = f; db.session.commit()
    login(client, "o@test.com")
    assert client.get(f"/documents/{m.id}/national_id").status_code == 403
    client.get("/logout")
    login(client, "m@test.com")
    assert client.get(f"/documents/{m.id}/national_id").status_code == 200
    client.get("/logout")
    login(client, "admin@test.com")
    r = client.get(f"/documents/{m.id}/national_id")
    assert r.status_code == 200 and "no-store" in r.headers["Cache-Control"]


def test_all_admin_pages_render(admin_client):
    m = make_member("m@test.com")
    urls = ["/admin/", "/admin/reports", "/admin/members", "/admin/members?status=pending", "/admin/members/new",
            f"/admin/members/{m.id}", f"/admin/members/{m.id}/edit", "/admin/contributions", "/admin/contributions/log",
            "/admin/loans", "/admin/cycles", "/admin/executives", "/admin/executives/new", "/admin/adverts",
            "/admin/adverts/new", "/admin/carousel", "/admin/carousel/new", "/admin/greeting", "/admin/gallery", "/admin/gallery/new", "/admin/statements", "/admin/settings", "/admin/audit"]
    for url in urls:
        assert admin_client.get(url).status_code == 200, url


def test_all_member_pages_render(client):
    make_member("m@test.com")
    login(client, "m@test.com")
    for url in ["/dashboard", "/my/contributions", "/my/profile", "/loans", "/loans/new", "/loans/history", "/about"]:
        assert client.get(url).status_code == 200, url


def test_security_headers_and_404(client):
    r = client.get("/nope")
    assert r.status_code == 404 and r.headers["X-Frame-Options"] == "DENY"


def test_gallery_admin_and_public(admin_client):
    from models import GalleryPhoto
    r = post(admin_client, "/admin/gallery/new", {"title": "Annual meeting", "caption": "Members gathered", "is_active": "on",
             "photo": (png_bytes(), "a.png")}, content_type="multipart/form-data")
    assert r.status_code == 302 and GalleryPhoto.query.count() == 1
    assert post(admin_client, "/admin/gallery/new", {"title": "No file"}, content_type="multipart/form-data").status_code == 400
    bad = post(admin_client, "/admin/gallery/new", {"title": "Bad", "photo": (io.BytesIO(b"nope"), "x.png")}, content_type="multipart/form-data")
    assert bad.status_code == 400 and GalleryPhoto.query.count() == 1
    public = admin_client.application.test_client()
    html = public.get("/").get_data(as_text=True)
    assert "Annual meeting" in html and "Moments from the union" in html and "Head office" not in html
    assert "Annual meeting" in public.get("/gallery").get_data(as_text=True)
    item = GalleryPhoto.query.one()
    post(admin_client, f"/admin/gallery/{item.id}/delete")
    assert GalleryPhoto.query.count() == 0
    assert "Moments from the union" not in public.get("/").get_data(as_text=True)


def test_home_shows_current_cycle(client):
    from datetime import date
    import rules
    html = client.get("/").get_data(as_text=True)
    label = rules.cycle_label(rules.cycle_start_year_for(date.today()))
    assert "Current savings cycle" in html and label in html and "days left" in html
    assert html.count('class="cyc-m ') == 12


def test_cycle_summary_dates():
    from datetime import date
    from services.cycles import cycle_summary
    s = cycle_summary(date(2026, 9, 24))
    assert s["label"] == "2026/2027" and s["start"] == date(2026, 9, 1) and s["end"] == date(2027, 8, 31)
    assert s["month_number"] == 1 and s["months"][0]["state"] == "current" and s["months"][1]["state"] == "future"
    s = cycle_summary(date(2027, 1, 10))
    assert s["label"] == "2026/2027" and s["month_number"] == 5 and s["months"][3]["state"] == "past"
    s = cycle_summary(date(2027, 8, 31))
    assert s["label"] == "2026/2027" and s["days_left"] == 0 and s["percent"] == 100
    assert cycle_summary(date(2027, 9, 1))["label"] == "2027/2028"


def test_carousel_admin_and_home(admin_client):
    from models import HomeSlide
    r = post(admin_client, "/admin/carousel/new", {"title": "Annual meeting", "caption": "See you there", "is_active": "on",
             "image": (png_bytes(), "a.png")}, content_type="multipart/form-data")
    assert r.status_code == 302 and HomeSlide.query.count() == 1
    assert post(admin_client, "/admin/carousel/new", {"title": "No picture"}, content_type="multipart/form-data").status_code == 400
    assert post(admin_client, "/admin/carousel/new", {"title": "Bad", "image": (io.BytesIO(b"x"), "b.png")},
                content_type="multipart/form-data").status_code == 400
    public = admin_client.application.test_client()
    html = public.get("/").get_data(as_text=True)
    assert "Annual meeting" in html and 'aria-roledescription="carousel"' in html
    slide = HomeSlide.query.one()
    post(admin_client, f"/admin/carousel/{slide.id}/edit", {"title": "Hidden now", "display_order": "1"},
         content_type="multipart/form-data")                     # is_active not sent, so it is switched off
    assert "Hidden now" not in public.get("/").get_data(as_text=True)
    post(admin_client, f"/admin/carousel/{slide.id}/delete")
    assert HomeSlide.query.count() == 0


def test_season_greeting_admin_and_home(admin_client):
    from models import get_greeting
    public = admin_client.application.test_client()
    assert "Season greetings" not in public.get("/").get_data(as_text=True)        # nothing saved yet
    data = {"active": "on", "title": "A Season of Thanks", "intro": "First paragraph.\n\nSecond paragraph.",
            "callout": "All persons have been served.", "closing": "See you on", "date": "1st October 2026",
            "signoff": "From the Executives", "image": (png_bytes(), "poster.png")}
    assert post(admin_client, "/admin/greeting", data, content_type="multipart/form-data").status_code == 302
    g = get_greeting()
    assert g["title"] == "A Season of Thanks" and len(g["paragraphs"]) == 2 and g["image"].endswith(".jpg")
    html = public.get("/").get_data(as_text=True)
    assert "A Season of Thanks" in html and "All persons have been served." in html and "1st October 2026" in html
    off = {k: v for k, v in data.items() if k not in ("active", "image")}
    post(admin_client, "/admin/greeting", off, content_type="multipart/form-data")
    assert get_greeting() is None and "A Season of Thanks" not in public.get("/").get_data(as_text=True)
    assert post(admin_client, "/admin/greeting", {"active": "on", "title": ""}, content_type="multipart/form-data").status_code == 400
