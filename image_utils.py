import os
import uuid

from werkzeug.utils import secure_filename

try:
    from PIL import Image, ImageOps, UnidentifiedImageError
except ImportError:  # pragma: no cover
    Image = None
    UnidentifiedImageError = Exception

INVALID = "__invalid__"
TOO_LARGE = "__too_large__"


def _extension(filename):
    return filename.rsplit(".", 1)[-1].lower() if filename and "." in filename else ""


def _size_of(file_storage):
    stream = file_storage.stream
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(0)
    return size


def validate_and_save_image(file_storage, prefix, upload_folder, allowed_extensions,
                            max_dimension=1600, max_bytes=None):
    """Check that an upload is a real image, then save it as a clean JPEG.

    Re-encoding removes hidden data (such as GPS position in the photo) and stops files that
    only pretend to be images. Phone photos are also scaled down so pages load quickly.

    Returns the stored file name, INVALID if the file is not a real image, TOO_LARGE if it is
    over max_bytes, or None if no file was sent.
    """
    if not file_storage or not file_storage.filename:
        return None
    if _extension(file_storage.filename) not in allowed_extensions:
        return INVALID
    if max_bytes and _size_of(file_storage) > max_bytes:
        return TOO_LARGE

    try:
        file_storage.stream.seek(0)
        image = Image.open(file_storage.stream)
        image.verify()                       # raises if the file is not a genuine image

        file_storage.stream.seek(0)
        image = Image.open(file_storage.stream)
        image = ImageOps.exif_transpose(image)   # keep phone photos the right way up
        image = image.convert("RGB")
    except (UnidentifiedImageError, OSError, ValueError, AttributeError, SyntaxError):
        return INVALID

    if max(image.size) > max_dimension:
        image.thumbnail((max_dimension, max_dimension))

    os.makedirs(upload_folder, exist_ok=True)
    filename = secure_filename(f"{prefix}-{uuid.uuid4().hex[:10]}.jpg")
    image.save(os.path.join(upload_folder, filename), "JPEG", quality=88)
    return filename


def save_document(file_storage, prefix, upload_folder, allowed_extensions, max_bytes=None):
    """Save a Ghana Card upload. Images are cleaned like photos; PDFs are checked and kept as they are."""
    if not file_storage or not file_storage.filename:
        return None
    ext = _extension(file_storage.filename)
    if ext not in allowed_extensions:
        return INVALID
    if ext != "pdf":
        return validate_and_save_image(file_storage, prefix, upload_folder, allowed_extensions,
                                       max_dimension=2200, max_bytes=max_bytes)

    if max_bytes and _size_of(file_storage) > max_bytes:
        return TOO_LARGE
    file_storage.stream.seek(0)
    header = file_storage.stream.read(5)
    file_storage.stream.seek(0)
    if header != b"%PDF-":
        return INVALID
    os.makedirs(upload_folder, exist_ok=True)
    filename = secure_filename(f"{prefix}-{uuid.uuid4().hex[:10]}.pdf")
    file_storage.save(os.path.join(upload_folder, filename))
    return filename


def delete_upload(filename, upload_folder):
    if not filename:
        return
    path = os.path.join(upload_folder, os.path.basename(filename))
    if os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass
