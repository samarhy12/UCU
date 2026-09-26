import os
import re
from datetime import date, datetime

from flask import abort, current_app, flash, redirect, render_template, request, send_from_directory, url_for
from flask_login import current_user

from extensions import db
from image_utils import INVALID, TOO_LARGE, delete_upload, validate_and_save_image
from models import (EXECUTIVE_POSITIONS, Advert, Executive, GalleryPhoto, HomeSlide, MonthlyTransaction,
                    get_greeting, get_setting, log_action, set_setting, utcnow)
from routes import admin_required

from . import bp

MAX_IMAGE_BYTES = 8 * 1024 * 1024


def _to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date() if value else None
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Executives
# ---------------------------------------------------------------------------
@bp.route("/executives")
@admin_required
def executives():
    items = Executive.query.order_by(Executive.display_order, Executive.id).all()
    filled = {e.position for e in items if e.is_active}
    vacant = [p for p in EXECUTIVE_POSITIONS if p not in filled]
    return render_template("admin/executives.html", items=items, vacant=vacant)


def _save_executive(item):
    form = request.form
    position = (form.get("position") or "").strip()
    if position == "__other__":
        position = (form.get("other_position") or "").strip()
    full_name = (form.get("full_name") or "").strip()
    errors = []
    if not position or len(position) > 60:
        errors.append("Choose or enter a position.")
    if not full_name or len(full_name) > 120:
        errors.append("Enter the full name.")
    email = (form.get("email") or "").strip()
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        errors.append("Enter a valid email address or leave it empty.")

    photo = validate_and_save_image(request.files.get("photo"), "exec",
                                    current_app.config["EXECUTIVE_PHOTO_FOLDER"],
                                    current_app.config["ALLOWED_IMAGE_EXTENSIONS"], 900, MAX_IMAGE_BYTES)
    if photo == INVALID:
        errors.append("The photo must be a real JPG or PNG image.")
    elif photo == TOO_LARGE:
        errors.append("The photo is too large (most 8 MB).")
    if errors:
        if photo not in (None, INVALID, TOO_LARGE):
            delete_upload(photo, current_app.config["EXECUTIVE_PHOTO_FOLDER"])
        for message in errors:
            flash(message, "error")
        return False

    item.position = position
    item.full_name = full_name
    item.title = (form.get("title") or "").strip()[:20] or None
    item.bio = (form.get("bio") or "").strip()[:300] or None
    item.phone = (form.get("phone") or "").strip()[:30] or None
    item.email = email[:120] or None
    item.display_order = _to_int(form.get("display_order"))
    item.is_active = form.get("is_active") == "on"
    if photo:
        delete_upload(item.photo, current_app.config["EXECUTIVE_PHOTO_FOLDER"])
        item.photo = photo
    return True


@bp.route("/executives/new", methods=["GET", "POST"])
@admin_required
def executive_new():
    if request.method == "POST":
        item = Executive()
        if _save_executive(item):
            db.session.add(item)
            log_action(current_user, "executive_added", item.position, item.full_name)
            db.session.commit()
            flash("Executive added.", "success")
            return redirect(url_for("admin.executives"))
        return render_template("admin/executive_form.html", item=None, form=request.form,
                               positions=EXECUTIVE_POSITIONS), 400
    return render_template("admin/executive_form.html", item=None,
                           form={"is_active": "on", "position": request.args.get("position", "")},
                           positions=EXECUTIVE_POSITIONS)


@bp.route("/executives/<int:item_id>/edit", methods=["GET", "POST"])
@admin_required
def executive_edit(item_id):
    item = db.get_or_404(Executive, item_id)
    if request.method == "POST":
        if _save_executive(item):
            log_action(current_user, "executive_edited", item.position, item.full_name)
            db.session.commit()
            flash("Executive saved.", "success")
            return redirect(url_for("admin.executives"))
        db.session.rollback()
        return render_template("admin/executive_form.html", item=item, form=request.form,
                               positions=EXECUTIVE_POSITIONS), 400
    return render_template("admin/executive_form.html", item=item, positions=EXECUTIVE_POSITIONS,
                           form={"position": item.position if item.position in EXECUTIVE_POSITIONS else "__other__",
                                 "other_position": "" if item.position in EXECUTIVE_POSITIONS else item.position,
                                 "title": item.title, "full_name": item.full_name, "bio": item.bio,
                                 "phone": item.phone, "email": item.email,
                                 "display_order": item.display_order,
                                 "is_active": "on" if item.is_active else ""})


@bp.route("/executives/<int:item_id>/delete", methods=["POST"])
@admin_required
def executive_delete(item_id):
    item = db.get_or_404(Executive, item_id)
    delete_upload(item.photo, current_app.config["EXECUTIVE_PHOTO_FOLDER"])
    log_action(current_user, "executive_deleted", item.position, item.full_name)
    db.session.delete(item)
    db.session.commit()
    flash("Executive removed.", "success")
    return redirect(url_for("admin.executives"))


# ---------------------------------------------------------------------------
# Adverts shown on the member dashboard
# ---------------------------------------------------------------------------
@bp.route("/adverts")
@admin_required
def adverts():
    items = Advert.query.order_by(Advert.is_active.desc(), Advert.display_order, Advert.id.desc()).all()
    return render_template("admin/adverts.html", items=items)


def _save_advert(item):
    form = request.form
    title = (form.get("title") or "").strip()
    body = (form.get("body") or "").strip()
    link = (form.get("link_url") or "").strip()
    start, end = _to_date(form.get("start_date")), _to_date(form.get("end_date"))
    errors = []
    if not title or len(title) > 120:
        errors.append("Enter a title (most 120 characters).")
    if len(body) > 500:
        errors.append("The message is too long (most 500 characters).")
    if link and not re.match(r"^(https?://|/)", link):
        errors.append("The link must start with http://, https:// or /.")
    if start is False or end is False:
        errors.append("Enter valid dates.")
    elif start and end and end < start:
        errors.append("The end date must not be before the start date.")

    image = validate_and_save_image(request.files.get("image"), "ad", current_app.config["ADVERT_IMAGE_FOLDER"],
                                    current_app.config["ALLOWED_IMAGE_EXTENSIONS"], 1400, MAX_IMAGE_BYTES)
    if image == INVALID:
        errors.append("The picture must be a real JPG or PNG image.")
    elif image == TOO_LARGE:
        errors.append("The picture is too large (most 8 MB).")
    if errors:
        if image not in (None, INVALID, TOO_LARGE):
            delete_upload(image, current_app.config["ADVERT_IMAGE_FOLDER"])
        for message in errors:
            flash(message, "error")
        return False

    item.title, item.body, item.link_url = title, body or None, link or None
    item.start_date, item.end_date = start or None, end or None
    item.display_order = _to_int(form.get("display_order"))
    item.is_active = form.get("is_active") == "on"
    if image:
        delete_upload(item.image, current_app.config["ADVERT_IMAGE_FOLDER"])
        item.image = image
    return True


@bp.route("/adverts/new", methods=["GET", "POST"])
@admin_required
def advert_new():
    if request.method == "POST":
        item = Advert()
        if _save_advert(item):
            db.session.add(item)
            log_action(current_user, "advert_added", item.title)
            db.session.commit()
            flash("Advert saved.", "success")
            return redirect(url_for("admin.adverts"))
        return render_template("admin/advert_form.html", item=None, form=request.form), 400
    return render_template("admin/advert_form.html", item=None, form={"is_active": "on"})


@bp.route("/adverts/<int:item_id>/edit", methods=["GET", "POST"])
@admin_required
def advert_edit(item_id):
    item = db.get_or_404(Advert, item_id)
    if request.method == "POST":
        if _save_advert(item):
            log_action(current_user, "advert_edited", item.title)
            db.session.commit()
            flash("Advert saved.", "success")
            return redirect(url_for("admin.adverts"))
        db.session.rollback()
        return render_template("admin/advert_form.html", item=item, form=request.form), 400
    return render_template("admin/advert_form.html", item=item, form={
        "title": item.title, "body": item.body, "link_url": item.link_url,
        "start_date": item.start_date.isoformat() if item.start_date else "",
        "end_date": item.end_date.isoformat() if item.end_date else "",
        "display_order": item.display_order, "is_active": "on" if item.is_active else ""})


@bp.route("/adverts/<int:item_id>/toggle", methods=["POST"])
@admin_required
def advert_toggle(item_id):
    item = db.get_or_404(Advert, item_id)
    item.is_active = not item.is_active
    db.session.commit()
    flash(f"Advert {'switched on' if item.is_active else 'switched off'}.", "success")
    return redirect(url_for("admin.adverts"))


@bp.route("/adverts/<int:item_id>/delete", methods=["POST"])
@admin_required
def advert_delete(item_id):
    item = db.get_or_404(Advert, item_id)
    delete_upload(item.image, current_app.config["ADVERT_IMAGE_FOLDER"])
    log_action(current_user, "advert_deleted", item.title)
    db.session.delete(item)
    db.session.commit()
    flash("Advert removed.", "success")
    return redirect(url_for("admin.adverts"))


# ---------------------------------------------------------------------------
# Gallery (shown on the home page and the Gallery page)
# ---------------------------------------------------------------------------
@bp.route("/gallery")
@admin_required
def gallery():
    items = GalleryPhoto.query.order_by(GalleryPhoto.display_order, GalleryPhoto.id).all()
    return render_template("admin/gallery.html", items=items)


def _save_gallery(item, is_new):
    form = request.form
    title = (form.get("title") or "").strip()
    caption = (form.get("caption") or "").strip()
    errors = []
    if not title or len(title) > 120:
        errors.append("Enter a title (most 120 characters).")
    if len(caption) > 300:
        errors.append("The caption is too long (most 300 characters).")

    photo = validate_and_save_image(request.files.get("photo"), "gal", current_app.config["GALLERY_FOLDER"],
                                    current_app.config["ALLOWED_IMAGE_EXTENSIONS"], 1800, MAX_IMAGE_BYTES)
    if photo == INVALID:
        errors.append("The photo must be a real JPG or PNG image.")
    elif photo == TOO_LARGE:
        errors.append("The photo is too large (most 8 MB).")
    elif photo is None and is_new:
        errors.append("Choose a photo.")
    if errors:
        if photo not in (None, INVALID, TOO_LARGE):
            delete_upload(photo, current_app.config["GALLERY_FOLDER"])
        for message in errors:
            flash(message, "error")
        return False

    item.title, item.caption = title, caption or None
    item.display_order = _to_int(form.get("display_order"))
    item.is_active = form.get("is_active") == "on"
    if photo:
        delete_upload(item.photo, current_app.config["GALLERY_FOLDER"])
        item.photo = photo
    return True


@bp.route("/gallery/new", methods=["GET", "POST"])
@admin_required
def gallery_new():
    if request.method == "POST":
        item = GalleryPhoto()
        if _save_gallery(item, True):
            db.session.add(item)
            log_action(current_user, "gallery_photo_added", item.title)
            db.session.commit()
            flash("Photo added to the gallery.", "success")
            return redirect(url_for("admin.gallery"))
        return render_template("admin/gallery_form.html", item=None, form=request.form), 400
    return render_template("admin/gallery_form.html", item=None, form={"is_active": "on"})


@bp.route("/gallery/<int:item_id>/edit", methods=["GET", "POST"])
@admin_required
def gallery_edit(item_id):
    item = db.get_or_404(GalleryPhoto, item_id)
    if request.method == "POST":
        if _save_gallery(item, False):
            log_action(current_user, "gallery_photo_edited", item.title)
            db.session.commit()
            flash("Photo saved.", "success")
            return redirect(url_for("admin.gallery"))
        db.session.rollback()
        return render_template("admin/gallery_form.html", item=item, form=request.form), 400
    return render_template("admin/gallery_form.html", item=item, form={
        "title": item.title, "caption": item.caption, "display_order": item.display_order,
        "is_active": "on" if item.is_active else ""})


@bp.route("/gallery/<int:item_id>/delete", methods=["POST"])
@admin_required
def gallery_delete(item_id):
    item = db.get_or_404(GalleryPhoto, item_id)
    delete_upload(item.photo, current_app.config["GALLERY_FOLDER"])
    log_action(current_user, "gallery_photo_deleted", item.title)
    db.session.delete(item)
    db.session.commit()
    flash("Photo removed.", "success")
    return redirect(url_for("admin.gallery"))


# ---------------------------------------------------------------------------
# Home page carousel
# ---------------------------------------------------------------------------
@bp.route("/carousel")
@admin_required
def carousel():
    items = HomeSlide.query.order_by(HomeSlide.display_order, HomeSlide.id).all()
    return render_template("admin/carousel.html", items=items)


def _save_slide(item, is_new):
    form = request.form
    title = (form.get("title") or "").strip()
    caption = (form.get("caption") or "").strip()
    link = (form.get("link_url") or "").strip()
    errors = []
    if not title or len(title) > 120:
        errors.append("Enter a title (most 120 characters).")
    if len(caption) > 200:
        errors.append("The caption is too long (most 200 characters).")
    if link and not re.match(r"^(https?://|/)", link):
        errors.append("The link must start with http://, https:// or /.")

    image = validate_and_save_image(request.files.get("image"), "slide", current_app.config["CAROUSEL_FOLDER"],
                                    current_app.config["ALLOWED_IMAGE_EXTENSIONS"], 1800, MAX_IMAGE_BYTES)
    if image == INVALID:
        errors.append("The picture must be a real JPG or PNG image.")
    elif image == TOO_LARGE:
        errors.append("The picture is too large (most 8 MB).")
    elif image is None and is_new:
        errors.append("Choose a picture.")
    if errors:
        if image not in (None, INVALID, TOO_LARGE):
            delete_upload(image, current_app.config["CAROUSEL_FOLDER"])
        for message in errors:
            flash(message, "error")
        return False

    item.title, item.caption, item.link_url = title, caption or None, link or None
    item.display_order = _to_int(form.get("display_order"))
    item.is_active = form.get("is_active") == "on"
    if image:
        delete_upload(item.image, current_app.config["CAROUSEL_FOLDER"])
        item.image = image
    return True


@bp.route("/carousel/new", methods=["GET", "POST"])
@admin_required
def carousel_new():
    if request.method == "POST":
        item = HomeSlide()
        if _save_slide(item, True):
            db.session.add(item)
            log_action(current_user, "carousel_slide_added", item.title)
            db.session.commit()
            flash("Slide added.", "success")
            return redirect(url_for("admin.carousel"))
        return render_template("admin/carousel_form.html", item=None, form=request.form), 400
    return render_template("admin/carousel_form.html", item=None, form={"is_active": "on"})


@bp.route("/carousel/<int:item_id>/edit", methods=["GET", "POST"])
@admin_required
def carousel_edit(item_id):
    item = db.get_or_404(HomeSlide, item_id)
    if request.method == "POST":
        if _save_slide(item, False):
            log_action(current_user, "carousel_slide_edited", item.title)
            db.session.commit()
            flash("Slide saved.", "success")
            return redirect(url_for("admin.carousel"))
        db.session.rollback()
        return render_template("admin/carousel_form.html", item=item, form=request.form), 400
    return render_template("admin/carousel_form.html", item=item, form={
        "title": item.title, "caption": item.caption, "link_url": item.link_url,
        "display_order": item.display_order, "is_active": "on" if item.is_active else ""})


@bp.route("/carousel/<int:item_id>/delete", methods=["POST"])
@admin_required
def carousel_delete(item_id):
    item = db.get_or_404(HomeSlide, item_id)
    delete_upload(item.image, current_app.config["CAROUSEL_FOLDER"])
    log_action(current_user, "carousel_slide_deleted", item.title)
    db.session.delete(item)
    db.session.commit()
    flash("Slide removed.", "success")
    return redirect(url_for("admin.carousel"))


# ---------------------------------------------------------------------------
# Season greeting on the home page
# ---------------------------------------------------------------------------
@bp.route("/greeting", methods=["GET", "POST"])
@admin_required
def greeting():
    if request.method == "POST":
        form = request.form
        title = (form.get("title") or "").strip()
        limits = {"title": 120, "intro": 1200, "callout": 500, "closing": 400, "date": 60, "signoff": 120}
        values = {k: (form.get(k) or "").strip() for k in limits}
        errors = [f"{k.capitalize()} is too long." for k, n in limits.items() if len(values[k]) > n]
        if form.get("active") == "on" and not title:
            errors.append("Enter a title, or switch the greeting off.")

        image = validate_and_save_image(request.files.get("image"), "greet", current_app.config["GREETING_FOLDER"],
                                        current_app.config["ALLOWED_IMAGE_EXTENSIONS"], 1800, MAX_IMAGE_BYTES)
        if image == INVALID:
            errors.append("The poster must be a real JPG or PNG image.")
        elif image == TOO_LARGE:
            errors.append("The poster is too large (most 8 MB).")
        if errors:
            if image not in (None, INVALID, TOO_LARGE):
                delete_upload(image, current_app.config["GREETING_FOLDER"])
            for message in errors:
                flash(message, "error")
            current = get_greeting(only_active=False)
            return render_template("admin/greeting.html", form=form, current=current), 400

        for key, value in values.items():
            set_setting(f"greeting_{key}", value)
        set_setting("greeting_active", "1" if form.get("active") == "on" else "0")
        if image:
            delete_upload(get_setting("greeting_image", ""), current_app.config["GREETING_FOLDER"])
            set_setting("greeting_image", image)
        elif form.get("remove_image") == "on":
            delete_upload(get_setting("greeting_image", ""), current_app.config["GREETING_FOLDER"])
            set_setting("greeting_image", "")
        log_action(current_user, "greeting_saved", title)
        db.session.commit()
        flash("The season greeting was saved.", "success")
        return redirect(url_for("admin.greeting"))

    current = get_greeting(only_active=False)
    form = {**current, "active": "on" if current["active"] == "1" else ""}
    return render_template("admin/greeting.html", form=form, current=current)


# ---------------------------------------------------------------------------
# Monthly statement files (Excel sheets kept by the administrator)
# ---------------------------------------------------------------------------
def _statement_folder():
    return os.path.join(current_app.config["UPLOAD_FOLDER"], "transactions")


@bp.route("/statements")
@admin_required
def statements():
    items = MonthlyTransaction.query.order_by(MonthlyTransaction.month.desc(), MonthlyTransaction.id.desc()).all()
    return render_template("admin/statements.html", items=items, default_month=date.today().strftime("%Y-%m"))


@bp.route("/statements/upload", methods=["POST"])
@admin_required
def statement_upload():
    month = (request.form.get("month") or "").strip()
    upload = request.files.get("transaction_file")
    if not re.match(r"^\d{4}-(0[1-9]|1[0-2])$", month):
        flash("Choose a month.", "error")
    elif not upload or not upload.filename:
        flash("Choose a file.", "error")
    elif not upload.filename.lower().endswith((".xlsx", ".xls")):
        flash("Please upload an Excel file (.xlsx or .xls).", "error")
    else:
        head = upload.stream.read(8)
        upload.stream.seek(0)
        # .xlsx files are zip files; old .xls files start with the OLE2 marker.
        if not (head.startswith(b"PK") or head.startswith(b"\xd0\xcf\x11\xe0")):
            flash("That does not look like a real Excel file.", "error")
        else:
            os.makedirs(_statement_folder(), exist_ok=True)
            ext = "xlsx" if upload.filename.lower().endswith(".xlsx") else "xls"
            filename = f"transactions_{month}_{utcnow():%Y%m%d_%H%M%S}.{ext}"
            upload.save(os.path.join(_statement_folder(), filename))
            db.session.add(MonthlyTransaction(month=month, file_name=filename, uploaded_by=current_user.id))
            log_action(current_user, "statement_uploaded", month, filename)
            db.session.commit()
            flash("The file was uploaded.", "success")
    return redirect(url_for("admin.statements"))


@bp.route("/statements/<int:item_id>/download")
@admin_required
def statement_download(item_id):
    item = db.get_or_404(MonthlyTransaction, item_id)
    name = os.path.basename(item.file_name)
    if not os.path.isfile(os.path.join(_statement_folder(), name)):
        abort(404)
    return send_from_directory(_statement_folder(), name, as_attachment=True,
                               download_name=f"transactions_{item.month}{os.path.splitext(name)[1]}")


@bp.route("/statements/<int:item_id>/delete", methods=["POST"])
@admin_required
def statement_delete(item_id):
    item = db.get_or_404(MonthlyTransaction, item_id)
    path = os.path.join(_statement_folder(), os.path.basename(item.file_name))
    if os.path.isfile(path):
        os.remove(path)
    log_action(current_user, "statement_deleted", item.month, item.file_name)
    db.session.delete(item)
    db.session.commit()
    flash("The file was deleted.", "success")
    return redirect(url_for("admin.statements"))
