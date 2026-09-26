"""Sending e-mail. Failures are logged and never stop the page the person is on."""
import re
import threading

from flask import current_app, render_template
from flask_mail import Message

from extensions import mail


def _plain_text(html):
    text = re.sub(r"(?is)<(script|style).*?</\1>", "", html)
    text = re.sub(r"(?i)<br\s*/?>|</p>|</tr>|</h\d>|</li>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def _deliver(app, message):
    with app.app_context():
        try:
            mail.send(message)
        except Exception as exc:  # network or login problems must never break the site
            app.logger.error("Could not send e-mail to %s: %s", message.recipients, exc)


def send_email(subject, recipient, template, **context):
    """Render email_templates/<template>.html and send it. Returns True when it was handed over."""
    app = current_app._get_current_object()
    if not recipient:
        return False
    if not app.config.get("MAIL_USERNAME"):
        app.logger.warning("E-mail not sent to %s (%s): MAIL_USERNAME is not set.", recipient, subject)
        return False

    context.setdefault("recipient_email", recipient)
    html = render_template(f"email_templates/{template}.html", subject=subject, **context)
    message = Message(subject, recipients=[recipient], html=html, body=_plain_text(html))

    if app.config.get("MAIL_ASYNC", True) and not app.testing:
        threading.Thread(target=_deliver, args=(app, message), daemon=True).start()
    else:
        _deliver(app, message)
    return True
