from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

import rules
from mailer import send_email
from models import Executive, GalleryPhoto, HomeSlide, get_greeting
from services import members as member_service
from services.cycles import cycle_summary

bp = Blueprint("public", __name__)

FAQS = [
    ("What is Unity Credit Union (UCU)?",
     "UCU is a susu savings and loan union. Members save every month, can borrow at low rates, and share "
     "in the dividend at the end of each year. We started with 4 members and now serve well over a hundred."),
    ("How do I become a member?",
     "Click Register, fill in the form, and upload your Ghana Card and a passport photo. The administrator "
     "checks your details. When you are accepted you get an email with your UCU account number."),
    ("What is my UCU account number?",
     "It looks like UCU240822. UCU is the union, 24 is the year you joined, 08 is the month you were verified, "
     "and 22 is your number in the union. You need it when you guarantee a loan for someone."),
    ("How do monthly contributions work?",
     "You pay your contribution to the administrator in the way that suits you. The administrator records each "
     "payment and the system sends you an email receipt with your total savings so far. You can also sign in "
     "at any time to see every payment."),
    ("What is the annual cycle?",
     "Our year runs from 1 September to 31 August. A new cycle opens automatically each September and the old "
     "one closes. At the end of each cycle, members receive their interest or dividend."),
    ("Can I take part of my savings out?",
     "No. Partial withdrawals are not allowed, so that the union's savings stay strong for everyone. "
     "You are always free to exit the union."),
    ("What loans can members take?",
     "Emergency loan: 31 days at 5%. Installment loan: 150 days at 10%. December Special (DS): 47 days at 3%. "
     "Easter Credit Aid (ECA): 47 days at 3%. The DS and ECA loans open only in their season."),
    ("Can someone who is not a member get a loan?",
     "Yes. Use the NMLOAN button. Non-member loans are 31 days at 10% (emergency) or 120 days at 20% "
     "(installment). A UCU member must guarantee the loan."),
    ("Who can be my guarantor?",
     "A UCU member in good standing. You give their full name, email, telephone and UCU number. If your loan is "
     "more than two thirds of your guarantor's total yearly earnings, you must add a second guarantor."),
    ("I forgot my password. What do I do?",
     "Click Forgot password on the sign-in page and enter your email. We send you a link to set a new password. "
     "You can also ask the administrator to reset it."),
    ("Can I use UCU on my phone?",
     "Yes. The website is made for phones as well as computers. On most phones you can also add it to your "
     "home screen from the browser menu, so it opens like an app."),
]


@bp.route("/")
def home():
    return render_template("public/home.html", total_members=member_service.total_members(),
                           executives=Executive.listing(), gallery=GalleryPhoto.listing(limit=7),
                           slides=HomeSlide.listing(), greeting=get_greeting(), cycle=cycle_summary(),
                           gallery_total=GalleryPhoto.query.filter_by(is_active=True).count())


@bp.route("/about")
def about():
    return render_template("public/about.html", executives=Executive.listing(),
                           total_members=member_service.total_members())


@bp.route("/gallery")
def gallery():
    return render_template("public/gallery.html", photos=GalleryPhoto.listing())


@bp.route("/services")
def services():
    return render_template("public/services.html")


@bp.route("/faqs")
def faqs():
    return render_template("public/faqs.html", faqs=FAQS)


@bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = (request.form.get("full_name") or "").strip()
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        message = (request.form.get("message") or "").strip()

        if request.form.get("website"):            # hidden field that only bots fill in
            return redirect(url_for("public.contact"))

        errors = []
        if not name:
            errors.append("Please enter your full name.")
        if not rules.valid_email(email):
            errors.append("Please enter a valid email address.")
        if len(message) < 5:
            errors.append("Please write your message.")
        if len(message) > 2000 or len(name) > 120:
            errors.append("Your message or name is too long.")
        if errors:
            for text in errors:
                flash(text, "error")
            return render_template("public/contact.html", form=request.form), 400

        send_email(f"New message from {name}", current_app.config["ADMIN_EMAIL"],
                   "admin_contact_notification", user_name=name, user_email=email,
                   user_phone=phone, message=message)
        send_email("Thank you for contacting Unity Credit Union", email,
                   "user_contact_confirmation", user_name=name)
        flash("Thank you. We received your message and will reply soon.", "success")
        return redirect(url_for("public.contact"))
    return render_template("public/contact.html", form={})
