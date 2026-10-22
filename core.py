"""Helpers shared by ticket routes (app.py), the approval engine (workflow.py) and admin routes (admin.py)."""
import logging
import mimetypes
import os
import smtplib
import uuid
from datetime import date, datetime
from email.message import EmailMessage

from flask import abort, current_app, g
from werkzeug.datastructures import MultiDict

from models import Attachment, TicketHistory, User, db, utcnow

log = logging.getLogger("cmi")

STATUS_CLASS = {"New": "info", "In Progress": "info", "Pending Approval": "critical", "Returned": "critical",
                "Approved": "positive", "Rejected": "negative", "Closed": "neutral"}
PRIORITY_CLASS = {"Critical": "negative", "High": "negative", "Medium": "critical", "Low": "neutral"}
# Statuses a user may pick by hand; the approval engine owns Pending Approval / Returned / Approved / Rejected.
MANUAL_STATUSES = ["New", "In Progress", "Closed"]

MIN_PASSWORD = 10
MB = 1024 * 1024
IMAGE_TYPES = ["png", "jpg", "jpeg", "webp"]
FILE_TYPES = ["pdf", "png", "jpg", "jpeg", "webp", "txt", "csv", "docx", "xlsx", "pptx", "zip"]  # upload allowlist
_SIGNATURES = {"png": b"\x89PNG\r\n\x1a\n", "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff", "pdf": b"%PDF-",
               "docx": b"PK\x03\x04", "xlsx": b"PK\x03\x04", "pptx": b"PK\x03\x04", "zip": b"PK\x03\x04"}


# ---------------------------------------------------------------- mail

def send_mail(to, subject, body):
    cfg = current_app.config
    if not cfg["MAIL_SERVER"] or cfg["SHOW_OTP"]:  # dev / test mode: never touch SMTP, print to the console
        log.warning("MAIL to=%s | %s\n%s", to, subject, body)
        return
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = cfg["MAIL_FROM"], to, subject
    msg.set_content(body)
    with smtplib.SMTP(cfg["MAIL_SERVER"], cfg["MAIL_PORT"], timeout=20) as smtp:
        if cfg["MAIL_TLS"]:
            smtp.starttls()
        if cfg["MAIL_USER"]:
            smtp.login(cfg["MAIL_USER"], cfg["MAIL_PASSWORD"])
        smtp.send_message(msg)


# Events a form's notify list can subscribe to.
EVENTS = {
    "new": "New requests",
    "comment": "Comments",
    "status": "Status changes & approval decisions",
    "update": "Edits, assignment & priority changes",
}


def subscribers(t, event):
    """Active users on the ticket's form notify list for this event."""
    ids = [s["user_id"] for s in t.form_version.form.notify if event in s["events"]]
    return User.query.filter(User.id.in_(ids), User.active.is_(True)).all() if ids else []


def notify(users, subject, body, skip=()):
    """Workflow mail: a mail outage must not undo or hide a saved change.
    Never mails the person acting, or anyone in skip (they got a more specific mail)."""
    skip_ids = {u.id for u in skip if u} | {g.user.id}
    for u in {u.id: u for u in users if u and u.active and u.id not in skip_ids}.values():
        try:
            send_mail(u.email, subject, body)
        except Exception:
            log.exception("notification to %s failed", u.email)


# ---------------------------------------------------------------- permissions

def need(perm):
    if not g.user.can(perm):
        abort(403)


def asked_for_priority(user, t):
    return any(r.requested_to_id == user.id for r in t.open_priority_requests)


def can_view(user, t):
    return (user.can("ticket.view") or user.id in (t.requester_id, t.assignee_id) or user in t.watchers
            or asked_for_priority(user, t) or any(a.approver_id == user.id for a in t.approvals)
            or any(s["user_id"] == user.id for s in t.form_version.form.notify))  # on the form's notify list


def participants(t):
    """Everyone involved in a request: they all get its comment emails."""
    people = [t.requester, t.assignee, *t.watchers, *(c.author for c in t.comments),
              *(a.approver for a in t.round_approvals), *(r.requested_to for r in t.open_priority_requests)]
    return list({u.id: u for u in people if u}.values())


def can_set_priority(user, t):
    """Global permission, or an open request asking this user to set it on this ticket."""
    return user.can("ticket.set_priority") or asked_for_priority(user, t)


def can_edit_values(user, t):
    if t.status == "Closed":
        return False
    return user.can("ticket.edit") or (user.id == t.requester_id and t.status in ("New", "Returned"))


def can_submit(user, t):
    if t.status not in ("New", "In Progress", "Returned"):
        return False
    return user.can("ticket.edit") or (user.id == t.requester_id and t.status == "Returned")


# ---------------------------------------------------------------- audit

def record(t, action, field=None, old=None, new=None, note=None):
    db.session.add(TicketHistory(ticket_id=t.id, actor_id=g.user.id, action=action, field=field, note=note or None,
                                 old=None if old is None else str(old), new=None if new is None else str(new)))


def change(t, field, new, show=lambda v: v):
    old = getattr(t, field)
    if old == new:
        return False
    record(t, "updated", field.replace("_", " "), show(old), show(new))
    setattr(t, field, new)
    return True


def set_status(t, status):
    if change(t, "status", status):
        t.closed_at = utcnow() if status == "Closed" else None
        return True
    return False


# ---------------------------------------------------------------- form values

class Invalid(ValueError):
    pass


def show_value(f, v):
    """Human-readable value of one form field."""
    if f["type"] == "checkbox":
        return "Yes" if v else "No"
    if v is None or v == "" or v == []:
        return "—"
    if f["type"] in ("file", "image"):
        return f"{len(v)} file(s)"
    if f["type"] == "multi_select":
        return ", ".join(v)
    if f["type"] == "datetime":
        return v.replace("T", ", ")
    return str(v)


def as_form_data(schema, values):
    """Stored ticket values -> the shape request.form has, so one template renders both."""
    md = MultiDict()
    for f in schema["fields"]:
        v = values.get(f["id"])
        if f["type"] in ("file", "image", "section") or v in (None, False):
            continue
        for item in (v if isinstance(v, list) else ["yes" if v is True else v]):
            md.add(f["id"], item)
    return md


def check_file(fs, accept, max_mb):
    name = os.path.basename((fs.filename or "").replace("\\", "/"))[:200]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in accept or ext not in FILE_TYPES:
        raise Invalid(f"Allowed file types: {', '.join(accept)}")
    data = fs.read(max_mb * MB + 1)
    if len(data) > max_mb * MB:
        raise Invalid(f"{name} is larger than {max_mb} MB")
    if not data:
        raise Invalid(f"{name} is empty")
    if ext == "webp":
        ok = data[:4] == b"RIFF" and data[8:12] == b"WEBP"
    elif ext in ("txt", "csv"):
        try:
            ok = b"\x00" not in data and bool(data.decode("utf-8"))
        except UnicodeDecodeError:
            ok = False
    else:
        ok = data.startswith(_SIGNATURES[ext])
    if not ok:
        raise Invalid(f"{name} is not a valid .{ext} file")
    return name, data


def validate(schema, form, files=None, existing=None):
    """Server-side check of a submission against a published form schema.
    Returns (values, errors, uploads); uploads are (field_id, filename, bytes) to store once the ticket exists."""
    values, errors, uploads, shown = {}, {}, [], set()
    existing = existing or {}
    for f in schema["fields"]:
        fid, typ = f["id"], f["type"]
        cond = f.get("show_if")
        if typ == "section" or (cond and not (cond["field"] in shown and cond["equals"] in form.getlist(cond["field"]))):
            continue  # hidden by its condition: not required, not stored
        shown.add(fid)
        try:
            if typ in ("file", "image"):
                new = [fs for fs in (files.getlist(fid) if files else []) if fs and fs.filename]
                kept = existing.get(fid) or []
                if len(kept) + len(new) > f.get("max_count", 5):
                    raise Invalid(f"At most {f.get('max_count', 5)} files")
                checked = [check_file(fs, f.get("accept") or (IMAGE_TYPES if typ == "image" else FILE_TYPES),
                                      f.get("max_mb", 10)) for fs in new]
                if f.get("required") and not (kept or checked):
                    raise Invalid("Required")
                values[fid] = list(kept)
                uploads += [(fid, name, data) for name, data in checked]
                continue
            if typ == "checkbox":
                values[fid] = "yes" in form.getlist(fid)
                if f.get("required") and not values[fid]:
                    raise Invalid("Required")
                continue
            raw = form.getlist(fid) if typ == "multi_select" else form.get(fid, "").strip()
            if not raw:
                if f.get("required"):
                    raise Invalid("Required")
                continue
            if typ == "select" and raw not in f["options"]:
                raise Invalid("Choose one of the listed options")
            if typ == "multi_select" and not set(raw) <= set(f["options"]):
                raise Invalid("Choose from the listed options")
            if typ == "number":
                n = float(raw)
                if not f.get("min", n) <= n <= f.get("max", n):
                    raise Invalid(f"Must be between {f.get('min', '…')} and {f.get('max', '…')}")
            if typ == "date":
                date.fromisoformat(raw)
            if typ == "datetime":
                datetime.fromisoformat(raw)
            if isinstance(raw, str) and len(raw) > f.get("max_length", 4000):
                raise Invalid(f"Maximum {f.get('max_length', 4000)} characters")
            values[fid] = raw
        except Invalid as e:
            errors[fid] = str(e)
        except ValueError:
            errors[fid] = "Invalid value"
    return values, errors, uploads


def store_upload(t, field_id, name, data):
    """Save bytes under a generated name outside the web root; the caller commits."""
    folder = current_app.config["UPLOAD_DIR"]
    os.makedirs(folder, exist_ok=True)
    stored = uuid.uuid4().hex
    with open(os.path.join(folder, stored), "xb") as fh:  # ponytail: file survives a failed commit as an orphan; sweep if it matters
        fh.write(data)
    a = Attachment(ticket=t, field_id=field_id, filename=name, stored_name=stored, size=len(data),
                   mime=mimetypes.guess_type(name)[0] or "application/octet-stream", uploaded_by_id=g.user.id)
    db.session.add(a)
    db.session.flush()
    return a
