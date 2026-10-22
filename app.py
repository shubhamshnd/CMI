"""CMI - Change Management Interface.

First run:  flask --app app db upgrade     (create / migrate the database)
            flask --app app seed           (permission profiles, demo forms, demo users)
Dev:        flask --app app run --debug
Production: waitress-serve --port 8080 app:app
"""
import csv
import io
import logging
import os
import secrets
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import date, datetime, timedelta

import click
from dotenv import load_dotenv

# Settings live in .env next to this file (see .env.example). Real environment variables win over it.
load_dotenv(os.environ.get("CMI_ENV_FILE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from flask import (Flask, Response, abort, flash, g, redirect, render_template, request, send_file, session,
                   url_for)
from flask_migrate import Migrate
from werkzeug.security import check_password_hash, generate_password_hash

import core
from core import (MANUAL_STATUSES, MIN_PASSWORD, PRIORITY_CLASS, STATUS_CLASS, Invalid, as_form_data, asked_for_priority,
                  can_edit_values, can_set_priority, can_submit, can_view, change, need, notify, participants, record,
                  set_status,
                  show_value, store_upload, validate)
from models import (LINK_KINDS, PERMISSIONS, PRIORITIES, STATUSES, Attachment, Comment, Form, FormVersion,
                    OtpChallenge, PermissionProfile, PriorityRequest, Ticket, TicketApproval, TicketLink, User, db,
                    utcnow)
from workflow import current_stage, decide, pending_for, start_approval

OTP_TTL = timedelta(minutes=5)
OTP_RESEND_AFTER = timedelta(seconds=60)
OTP_MAX_ATTEMPTS = 5
LOGIN_MAX_FAILS = 5
LOCKOUT = timedelta(minutes=15)
PUBLIC_ENDPOINTS = {"login", "otp_send", "otp_verify", "core_login", "static"}

log = logging.getLogger("cmi")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("CMI_SECRET_KEY") or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=os.environ.get("CMI_DATABASE_URL", "sqlite:///cmi.db"),
    UPLOAD_DIR=os.environ.get("CMI_UPLOAD_DIR") or os.path.join(app.instance_path, "uploads"),
    MAX_CONTENT_LENGTH=60 * core.MB,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("CMI_SECURE_COOKIES") == "1",  # set to 1 behind HTTPS
    ALLOWED_EMAIL_DOMAINS=[d.strip().lower() for d in os.environ.get("CMI_ALLOWED_DOMAINS", "").split(",") if d.strip()],
    MAIL_SERVER=os.environ.get("CMI_MAIL_SERVER"),
    MAIL_PORT=int(os.environ.get("CMI_MAIL_PORT", 25)),
    MAIL_TLS=os.environ.get("CMI_MAIL_TLS") == "1",
    MAIL_USER=os.environ.get("CMI_MAIL_USER"),
    MAIL_PASSWORD=os.environ.get("CMI_MAIL_PASSWORD"),
    MAIL_FROM=os.environ.get("CMI_MAIL_FROM", "cmi@localhost"),
)
if "CMI_SECRET_KEY" not in os.environ:
    log.warning("CMI_SECRET_KEY not set: using a random key, sessions reset on restart.")
db.init_app(app)
Migrate(app, db, render_as_batch=True)  # batch mode: SQLite needs table rebuilds for ALTERs
app.jinja_env.globals.update(STATUS_CLASS=STATUS_CLASS, PRIORITY_CLASS=PRIORITY_CLASS, PRIORITIES=PRIORITIES,
                             STATUSES=STATUSES, MANUAL_STATUSES=MANUAL_STATUSES, LINK_KINDS=LINK_KINDS,
                             PERMISSIONS=PERMISSIONS, show_value=show_value)


# ---------------------------------------------------------------- request guards

@app.before_request
def guard():
    if request.method == "POST":
        token = session.get("_csrf")
        if not token or not secrets.compare_digest(request.form.get("_csrf", ""), token):
            abort(400, "Form expired. Reload the page and try again.")
    g.user = db.session.get(User, session["uid"]) if "uid" in session else None
    if g.user and not g.user.active:
        session.clear()
        g.user = None
    if not g.user and request.endpoint not in PUBLIC_ENDPOINTS:
        return redirect(url_for("login"))


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                            "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    return resp


@app.context_processor
def template_globals():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return dict(csrf=session["_csrf"])


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def error_page(e):
    if e.code == 413:
        e.description = "The upload is too large (60 MB maximum per submission)."
    return render_template("error.html", e=e), e.code


@app.template_filter("dt")
def fmt_dt(value):
    return value.strftime("%d %b %Y, %H:%M UTC") if value else "—"


@app.template_filter("d")
def fmt_d(value):
    return value.strftime("%d %b %Y") if value else "—"


# ---------------------------------------------------------------- auth

def start_session(user):
    session.clear()  # fresh session contents on login: no fixation, new CSRF token
    session.permanent = True
    session["uid"] = user.id
    return redirect(url_for("home"))


@app.get("/login")
def login():
    if request.args.get("reset"):
        session.pop("otp_email", None)
    return render_template("login.html", mode=request.args.get("mode", "otp"), otp_email=session.get("otp_email"))


@app.post("/login/otp/send")
def otp_send():
    email = request.form.get("email", "").strip().lower()
    domains = app.config["ALLOWED_EMAIL_DOMAINS"]
    if "@" not in email or (domains and email.rsplit("@", 1)[1] not in domains):
        flash("Enter a valid work email address.", "error")
        return redirect(url_for("login"))
    last = OtpChallenge.query.filter_by(email=email).order_by(OtpChallenge.created_at.desc()).first()
    if last and utcnow() - last.created_at < OTP_RESEND_AFTER:
        flash("A code was sent recently. Wait a minute before requesting another.", "error")
    else:
        code = f"{secrets.randbelow(10**6):06d}"
        db.session.add(OtpChallenge(email=email, code_hash=generate_password_hash(code), expires_at=utcnow() + OTP_TTL))
        db.session.commit()
        core.send_mail(email, "Your CMI sign-in code", f"Your CMI sign-in code is {code}. It expires in 5 minutes.")
        flash(f"We sent a 6-digit code to {email}.", "success")
    session["otp_email"] = email
    return redirect(url_for("login"))


@app.post("/login/otp/verify")
def otp_verify():
    email = session.get("otp_email")
    ch = email and OtpChallenge.query.filter_by(email=email, used=False).order_by(OtpChallenge.created_at.desc()).first()
    if not ch or ch.expires_at < utcnow() or ch.attempts >= OTP_MAX_ATTEMPTS:
        flash("The code has expired or had too many attempts. Request a new code.", "error")
        return redirect(url_for("login"))
    ch.attempts += 1
    if not check_password_hash(ch.code_hash, request.form.get("code", "").strip()):
        db.session.commit()
        flash("Incorrect code.", "error")
        return redirect(url_for("login"))
    ch.used = True
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, name=email.split("@")[0])
        requester = PermissionProfile.query.filter_by(name="Requester").first()
        user.profiles = [requester] if requester else []
        db.session.add(user)
    db.session.commit()
    if not user.active or user.is_core:
        flash("This account cannot sign in with an email code." if user.active else "This account is deactivated.", "error")
        return redirect(url_for("login"))
    return start_session(user)


@app.post("/login/core")
def core_login():
    email = request.form.get("email", "").strip().lower()
    user = User.query.filter_by(email=email, is_core=True).first()
    if user and user.locked_until and user.locked_until > utcnow():
        flash("Too many failed attempts. Try again in 15 minutes.", "error")
    elif user and user.active and user.password_hash and check_password_hash(user.password_hash, request.form.get("password", "")):
        user.failed_logins = 0
        db.session.commit()
        return start_session(user)
    else:
        if user:
            user.failed_logins += 1
            if user.failed_logins >= LOGIN_MAX_FAILS:
                user.failed_logins, user.locked_until = 0, utcnow() + LOCKOUT
            db.session.commit()
        flash("Invalid email or password.", "error")
    return redirect(url_for("login", mode="core"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
def account():
    u = g.user
    if request.method == "POST":
        new = request.form.get("new", "")
        if not u.is_core:
            abort(403)
        elif not check_password_hash(u.password_hash or "", request.form.get("current", "")):
            flash("Current password is incorrect.", "error")
        elif len(new) < MIN_PASSWORD:
            flash(f"Use at least {MIN_PASSWORD} characters.", "error")
        elif new != request.form.get("confirm"):
            flash("The new passwords do not match.", "error")
        else:
            u.password_hash = generate_password_hash(new)
            db.session.commit()
            flash("Password changed.", "success")
            return redirect(url_for("home"))
    return render_template("account.html")


# ---------------------------------------------------------------- helpers

def get_ticket(tid):
    t = db.session.get(Ticket, tid) or abort(404)
    if not can_view(g.user, t):
        abort(403)
    return t


def stale(t):
    """True (and flashes) if the ticket changed since the user loaded the page."""
    if request.form.get("rv") != str(t.row_version):
        flash("Someone else changed this ticket. Review the latest version and try again.", "error")
        return True
    return False


def back(t, anchor=None):
    return redirect(url_for("ticket_detail", tid=t.id, _anchor=anchor))


def link(t, anchor=None):
    return url_for("ticket_detail", tid=t.id, _external=True, _anchor=anchor)


def parse_number(text):
    text = (text or "").strip().upper().removeprefix("CHG-")
    return int(text) if text.isdigit() else None


def awaiting_my_approval(u):
    candidates = Ticket.query.filter(Ticket.status == "Pending Approval", Ticket.approvals.any(
        (TicketApproval.approver_id == u.id) & TicketApproval.decision.is_(None))).all()
    return [t for t in candidates if pending_for(u, t)]


def counts(u):
    return dict(
        mine=Ticket.query.filter_by(requester_id=u.id).count(),
        assigned=Ticket.query.filter(Ticket.assignee_id == u.id, Ticket.status != "Closed").count(),
        priority=PriorityRequest.query.filter_by(requested_to_id=u.id, status="open").count(),
        approvals=len(awaiting_my_approval(u)),
        all=Ticket.query.count() if u.can("ticket.view") else None,
    )


def csv_cell(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # stop spreadsheet formula injection


# ---------------------------------------------------------------- pages

@app.get("/")
def home():
    forms = Form.query.filter_by(archived=False).order_by(Form.name).all()
    return render_template("home.html", counts=counts(g.user), forms=[f for f in forms if f.latest])


TABS = {"mine": "Mine", "assigned": "Assigned to Me", "priority": "Priority Requests",
        "approvals": "Pending My Approval", "all": "All Permitted"}


@app.get("/tickets")
def tickets():
    u, args = g.user, request.args
    tab = args.get("tab", "mine")
    if tab not in TABS or (tab == "all" and not u.can("ticket.view")):
        tab = "mine"
    q = Ticket.query
    if tab == "mine":
        q = q.filter(Ticket.requester_id == u.id)
    elif tab == "assigned":
        q = q.filter(Ticket.assignee_id == u.id)
    elif tab == "priority":
        q = q.filter(Ticket.priority_requests.any(
            (PriorityRequest.requested_to_id == u.id) & (PriorityRequest.status == "open")))
    elif tab == "approvals":
        q = q.filter(Ticket.id.in_([t.id for t in awaiting_my_approval(u)]))
    text = args.get("q", "").strip()
    if parse_number(text) and text.upper().startswith("CHG-"):
        q = q.filter(Ticket.id == parse_number(text))
    elif text:
        q = q.filter(Ticket.title.ilike(f"%{text}%"))
    if args.get("status"):
        q = q.filter(Ticket.status == args["status"])
    if args.get("priority"):
        q = q.filter(Ticket.priority.is_(None) if args["priority"] == "Not set" else Ticket.priority == args["priority"])
    if args.get("form"):
        q = q.join(FormVersion).join(Form).filter(Form.key == args["form"])
    if args.get("overdue"):
        q = q.filter(Ticket.due_date < date.today(), Ticket.status.notin_(["Closed", "Rejected"]))
    rows = q.order_by(Ticket.id.desc()).limit(5000 if args.get("export") else 500).all()  # ponytail: add paging past 500
    if args.get("export") == "csv":
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["Number", "Title", "Form", "Version", "Status", "Priority", "Requester", "Assignee", "Due",
                    "Created (UTC)", "Closed (UTC)"])
        for t in rows:
            w.writerow([csv_cell(v) for v in (t.number, t.title, t.form_version.form.name, t.form_version.version,
                                                t.status, t.priority, t.requester.name, t.assignee and t.assignee.name,
                                                t.due_date, t.created_at, t.closed_at)])
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=cmi-{tab}-{date.today()}.csv"})
    tabs = {k: v for k, v in TABS.items() if k != "all" or u.can("ticket.view")}
    return render_template("tickets.html", rows=rows, tab=tab, tabs=tabs, counts=counts(u),
                           forms=Form.query.order_by(Form.name).all())


@app.route("/tickets/new", methods=["GET", "POST"])
def ticket_new():
    need("ticket.create")
    form = Form.query.filter_by(key=request.args.get("form", ""), archived=False).first()
    if not form or not form.latest:
        forms = Form.query.filter_by(archived=False).order_by(Form.name).all()
        return render_template("ticket_new.html", forms=[f for f in forms if f.latest])
    fv, errors = form.latest, {}
    source = get_ticket(request.args.get("from", type=int)) if request.args.get("from") else None
    kind = request.args.get("link") if source and request.args.get("link") in LINK_KINDS else None
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        values, errors, uploads = validate(fv.schema, request.form, request.files)
        if not title:
            errors["title"] = "Required"
        if not errors:
            t = Ticket(title=title[:200], form_version=fv, values={}, requester=g.user,
                       assignee=form.default_assignee if form.default_assignee and form.default_assignee.active else None)
            db.session.add(t)
            db.session.flush()
            for fid, name, data in uploads:
                values[fid].append(store_upload(t, fid, name, data).id)
            t.values = values
            record(t, "created the request")
            if t.assignee:
                record(t, "updated", "assignee", None, t.assignee.name, note="Default assignee for this form")
            if kind:
                db.session.add(TicketLink(from_ticket_id=t.id, to_ticket_id=source.id, kind=kind, created_by_id=g.user.id))
                record(t, "linked", None, None, f"{LINK_KINDS[kind][0]} {source.number}")
                record(source, "linked", None, None, f"{LINK_KINDS[kind][1]} {t.number}")
            db.session.commit()
            flash(f"{t.number} created.", "success")
            notify([t.assignee], f"{t.number} assigned to you", f"New request {t.number} – {t.title}.\n\n{link(t)}")
            return back(t)
        data = request.form
    elif source:  # carry forward matching fields from the earlier ticket
        data = as_form_data(fv.schema, source.values)
        data["title"] = f"{LINK_KINDS[kind][0] if kind else 'Copy of'}: {source.title}"[:200]
    else:
        data = request.form
    return render_template("ticket_new.html", form=form, fv=fv, errors=errors, data=data, source=source, kind=kind)


@app.route("/tickets/<int:tid>/edit", methods=["GET", "POST"])
def ticket_edit(tid):
    t = get_ticket(tid)
    if not can_edit_values(g.user, t):
        abort(403)
    fields, errors = t.form_version.schema["fields"], {}
    if request.method == "POST" and not stale(t):
        title = request.form.get("title", "").strip()
        values, errors, uploads = validate(t.form_version.schema, request.form, request.files, existing=t.values)
        if not title:
            errors["title"] = "Required"
        if not errors:
            for fid, name, data in uploads:
                values[fid].append(store_upload(t, fid, name, data).id)
            reason = request.form.get("reason", "").strip()[:1000]
            change(t, "title", title[:200])
            material = False
            for f in fields:
                old, new = t.values.get(f["id"]), values.get(f["id"])
                if f["type"] != "section" and old != new and not (old in (None, "", []) and new in (None, "", [])):
                    record(t, "updated", f["label"], show_value(f, old), show_value(f, new), note=reason)
                    material = material or bool(f.get("material"))
            if values != t.values:
                t.values = values
                t.data_version += 1
            t.row_version += 1
            if material and t.status in ("Pending Approval", "Approved"):
                try:
                    start_approval(t, "approval restarted after a material change")
                    flash("A material field changed, so approval has restarted.", "warning")
                except Invalid as e:
                    for r in t.round_approvals:
                        r.decision = r.decision or "skipped"
                    set_status(t, "In Progress")
                    flash(f"Approval was invalidated by a material change. {e}", "warning")
            db.session.commit()
            flash("Changes saved.", "success")
            return back(t)
    data = request.form if request.method == "POST" else as_form_data(t.form_version.schema, t.values)
    if request.method == "GET":
        data["title"] = t.title
    return render_template("ticket_new.html", form=t.form_version.form, fv=t.form_version, errors=errors, data=data,
                           editing=t, attachments={a.id: a for a in t.attachments})


@app.get("/tickets/<int:tid>")
def ticket_detail(tid):
    t = get_ticket(tid)
    core_users = User.query.filter_by(is_core=True, active=True).order_by(User.name).all()
    links = [(LINK_KINDS[l.kind][0], l.to_ticket, l) for l in TicketLink.query.filter_by(from_ticket_id=t.id)]
    links += [(LINK_KINDS[l.kind][1], l.from_ticket, l) for l in TicketLink.query.filter_by(to_ticket_id=t.id)]
    rounds = {}
    for a in t.approvals:
        rounds.setdefault(a.round, []).append(a)
    return render_template(
        "ticket.html", t=t, core_users=core_users, links=links, rounds=rounds,
        attachments={a.id: a for a in t.attachments}, my_approval=pending_for(g.user, t),
        field_labels={f["id"]: f["label"] for f in t.form_version.schema["fields"]},
        current_stage_index=next((r.stage_index for r in current_stage(t)), None) if t.status == "Pending Approval" else None,
        my_requests=[r for r in t.open_priority_requests if r.requested_to_id == g.user.id],
        can_set_priority=can_set_priority(g.user, t), can_edit_values=can_edit_values(g.user, t),
        can_submit=can_submit(g.user, t), can_view=lambda other: can_view(g.user, other),
        participants=participants(t), all_users=User.query.filter_by(active=True).order_by(User.name).all())


@app.post("/tickets/<int:tid>/assign")
def ticket_assign(tid):
    t = get_ticket(tid)
    need("ticket.assign")
    if stale(t):
        return back(t)
    aid = request.form.get("assignee_id", type=int)
    assignee = db.session.get(User, aid) if aid else None
    if aid and not (assignee and assignee.is_core and assignee.active):
        abort(400)
    try:
        due = date.fromisoformat(request.form["due_date"]) if request.form.get("due_date") else None
    except ValueError:
        abort(400)
    reassigned = change(t, "assignee", assignee, lambda u: u.name if u else None)
    if change(t, "due_date", due) or reassigned:
        t.row_version += 1
        db.session.commit()
        flash("Assignment saved.", "success")
        if reassigned:
            notify([assignee], f"{t.number} assigned to you", f"{g.user.name} assigned you {t.number} – {t.title}.\n\n{link(t)}")
    return back(t)


@app.post("/tickets/<int:tid>/priority")
def ticket_priority(tid):
    t = get_ticket(tid)
    if not can_set_priority(g.user, t):
        abort(403)
    priority = request.form.get("priority")
    if priority not in PRIORITIES:
        abort(400)
    if stale(t):
        return back(t)
    change(t, "priority", priority)
    closed = t.open_priority_requests
    for r in closed:
        r.status, r.resolved_at = "done", utcnow()
        record(t, "priority request completed", None, None, f"{r.requested_to.name} (asked by {r.requested_by.name})")
    t.row_version += 1
    db.session.commit()
    flash(f"Priority set to {priority}.", "success")
    notify([r.requested_by for r in closed], f"{t.number}: priority set to {priority}",
           f"{g.user.name} set the priority of {t.number} – {t.title} to {priority}.\n\n{link(t)}")
    return back(t)


@app.post("/tickets/<int:tid>/priority-request")
def priority_request(tid):
    """An assigner asks someone else to set the priority instead of setting it themselves."""
    t = get_ticket(tid)
    need("ticket.assign")
    to = db.session.get(User, request.form.get("requested_to_id", type=int) or 0)
    if not (to and to.is_core and to.active):
        abort(400)
    if to.id == g.user.id:
        flash("Choose someone other than yourself.", "error")
    elif asked_for_priority(to, t):
        flash(f"{to.name} has already been asked to set the priority.", "error")
    else:
        note = request.form.get("note", "").strip()[:1000]
        db.session.add(PriorityRequest(ticket=t, requested_by=g.user, requested_to=to, note=note))
        record(t, "asked for a priority from", None, None, to.name, note=note)
        db.session.commit()
        flash(f"Asked {to.name} to set the priority.", "success")
        notify([to], f"{t.number}: please set the priority",
               f"{g.user.name} asked you to set the priority of {t.number} – {t.title}."
               + (f"\n\nNote: {note}" if note else "") + f"\n\n{link(t)}")
    return back(t)


@app.post("/tickets/<int:tid>/status")
def ticket_status(tid):
    t = get_ticket(tid)
    need("ticket.edit")
    status = request.form.get("status")
    if status not in MANUAL_STATUSES or t.status == "Pending Approval":
        abort(400)
    if t.status == "Closed" and status != "Closed":
        need("ticket.reopen")
    if stale(t):
        return back(t)
    reopened = t.status == "Closed"
    if set_status(t, status):
        if reopened:
            record(t, "reopened the request", note=request.form.get("reason", "").strip()[:1000])
        t.row_version += 1
        db.session.commit()
        flash(f"Status changed to {status}.", "success")
        notify([t.requester, t.assignee], f"{t.number}: {status}", f"{g.user.name} changed {t.number} to {status}.\n\n{link(t)}")
    return back(t)


@app.post("/tickets/<int:tid>/submit")
def ticket_submit(tid):
    t = get_ticket(tid)
    if not can_submit(g.user, t):
        abort(403)
    if stale(t):
        return back(t)
    try:
        start_approval(t)
    except Invalid as e:
        db.session.rollback()
        flash(str(e), "error")
        return back(t)
    t.row_version += 1
    db.session.commit()
    flash("Submitted for approval." if t.status == "Pending Approval" else "No approval stages apply: approved.", "success")
    return back(t, "approvals")


@app.post("/tickets/<int:tid>/decide")
def ticket_decide(tid):
    t = get_ticket(tid)
    need("ticket.approve")
    row = pending_for(g.user, t)
    if not row or stale(t):  # not your turn, already decided, or the ticket changed under you
        if not row:
            flash("There is no approval waiting for you on this ticket.", "error")
        return back(t, "approvals")
    decision = request.form.get("decision")
    comment = request.form.get("comment", "").strip()[:2000]
    if decision not in ("approved", "rejected", "returned"):
        abort(400)
    if decision != "approved" and not comment:
        flash("Add a comment explaining why you reject or return the request.", "error")
        return back(t, "approvals")
    decide(t, row, decision, comment, g.user)
    t.row_version += 1
    db.session.commit()
    flash(f"You {decision} {t.number}.", "success")
    return back(t, "approvals")


@app.post("/tickets/<int:tid>/comment")
def ticket_comment(tid):
    t = get_ticket(tid)
    need("ticket.comment")
    body = request.form.get("body", "").strip()[:5000]
    if body:
        db.session.add(Comment(ticket_id=t.id, author_id=g.user.id, body=body))
        record(t, "added a comment")
        db.session.commit()
        notify(participants(t), f"[{t.number}] {t.title}",
               f"{g.user.name} commented on {t.number}:\n\n{body}\n\n"
               f"Reply in CMI (replies to this email are not read): {link(t, 'comments')}")
    return back(t, "comments")


@app.post("/tickets/<int:tid>/watchers")
def watcher_add(tid):
    """Add someone to the request so they get every comment and can view it."""
    t = get_ticket(tid)
    need("ticket.comment")
    email = request.form.get("email", "").strip().lower()
    u = User.query.filter_by(email=email, active=True).first()
    if not u:
        flash(f"No active CMI user with email {email}. Requesters appear after they sign in once.", "error")
    elif u in participants(t):
        flash(f"{u.name} already receives comments on this request.", "info")
    else:
        t.watchers.append(u)
        record(t, "added to comment notifications", None, None, u.name)
        db.session.commit()
        flash(f"{u.name} will now get comment emails for {t.number}.", "success")
        notify([u], f"[{t.number}] {t.title}", f"{g.user.name} added you to {t.number} – {t.title}.\n\n{link(t)}")
    return back(t, "comments")


@app.post("/tickets/<int:tid>/watchers/<int:uid>/delete")
def watcher_remove(tid, uid):
    t = get_ticket(tid)
    u = db.session.get(User, uid)
    if not u or u not in t.watchers:
        abort(404)
    if u.id != g.user.id and not g.user.can("ticket.assign"):
        abort(403)  # people may remove themselves; assigners may remove anyone
    t.watchers.remove(u)
    record(t, "removed from comment notifications", None, None, u.name)
    db.session.commit()
    return back(t, "comments") if can_view(g.user, t) else redirect(url_for("home"))


@app.post("/tickets/<int:tid>/attachments")
def ticket_upload(tid):
    t = get_ticket(tid)
    need("ticket.comment")
    try:
        files = [core.check_file(fs, core.FILE_TYPES, 10) for fs in request.files.getlist("files") if fs.filename]
    except Invalid as e:
        flash(str(e), "error")
        return back(t, "attachments")
    for name, data in files:
        store_upload(t, None, name, data)
        record(t, "uploaded evidence", None, None, name)
    db.session.commit()
    if files:
        flash(f"Uploaded {len(files)} file(s).", "success")
    return back(t, "attachments")


@app.get("/attachments/<int:aid>")
def attachment(aid):
    a = db.session.get(Attachment, aid) or abort(404)
    t = get_ticket(a.ticket_id)  # same access rule as the ticket
    record(t, "downloaded", None, None, a.filename)
    db.session.commit()
    return send_file(os.path.join(app.config["UPLOAD_DIR"], a.stored_name), mimetype=a.mime,
                     as_attachment=True, download_name=a.filename)


@app.post("/tickets/<int:tid>/links")
def ticket_link(tid):
    t = get_ticket(tid)
    need("ticket.link")
    kind = request.form.get("kind")
    other = db.session.get(Ticket, parse_number(request.form.get("number")) or 0)
    if kind not in LINK_KINDS:
        abort(400)
    error = None
    if not other or not can_view(g.user, other):
        error = "Ticket not found."
    elif other.id == t.id:
        error = "A ticket cannot be linked to itself."
    elif TicketLink.query.filter_by(from_ticket_id=t.id, to_ticket_id=other.id, kind=kind).first():
        error = "That link already exists."
    elif kind == "child_of":
        if TicketLink.query.filter_by(from_ticket_id=t.id, kind="child_of").first():
            error = f"{t.number} already has a parent."
        else:  # walk up from the new parent; reaching this ticket would make a loop
            node, seen = other, set()
            while node and node.id not in seen:
                if node.id == t.id:
                    error = "That would make a ticket its own ancestor."
                    break
                seen.add(node.id)
                parent = TicketLink.query.filter_by(from_ticket_id=node.id, kind="child_of").first()
                node = parent and parent.to_ticket
    if error:
        flash(error, "error")
    else:
        db.session.add(TicketLink(from_ticket_id=t.id, to_ticket_id=other.id, kind=kind, created_by_id=g.user.id))
        record(t, "linked", None, None, f"{LINK_KINDS[kind][0]} {other.number}")
        record(other, "linked", None, None, f"{LINK_KINDS[kind][1]} {t.number}")
        db.session.commit()
        flash(f"Linked: {LINK_KINDS[kind][0]} {other.number}.", "success")
    return back(t, "relationships")


@app.post("/tickets/<int:tid>/links/<int:lid>/delete")
def ticket_unlink(tid, lid):
    t = get_ticket(tid)
    need("ticket.link")
    lk = db.session.get(TicketLink, lid)
    if not lk or t.id not in (lk.from_ticket_id, lk.to_ticket_id):
        abort(404)
    record(lk.from_ticket, "unlinked", None, None, f"{LINK_KINDS[lk.kind][0]} {lk.to_ticket.number}")
    record(lk.to_ticket, "unlinked", None, None, f"{LINK_KINDS[lk.kind][1]} {lk.from_ticket.number}")
    db.session.delete(lk)
    db.session.commit()
    return back(t, "relationships")


from admin import bp as admin_bp  # noqa: E402  (admin imports helpers defined above)

app.register_blueprint(admin_bp)


# ---------------------------------------------------------------- CLI: seed, backup, restore

SEED_PROFILES = {
    "Requester": ["ticket.create", "ticket.comment"],
    "Viewer": ["ticket.view"],
    "Assigner": ["ticket.view", "ticket.assign", "ticket.set_priority", "ticket.comment", "ticket.link"],
    "Assignee": ["ticket.view", "ticket.edit", "ticket.comment", "ticket.link"],
    "Approver": ["ticket.view", "ticket.approve", "ticket.comment"],
    "Form Administrator": ["ticket.view", "form.publish"],
    "System Administrator": list(PERMISSIONS),
}
SEED_USERS = [  # email, name, profiles
    ("admin@cmi.local", "CMI Admin", ["System Administrator"]),
    ("assigner@cmi.local", "Asha Assigner", ["Assigner", "Requester"]),
    ("engineer@cmi.local", "Rohit Engineer", ["Assignee", "Requester"]),
    ("lead@cmi.local", "Neha Lead", ["Viewer", "Assignee", "Approver"]),
    ("cab@cmi.local", "Change Advisory Board", ["Approver"]),
]
SEED_FORMS = {
    "INFRA_CHANGE": ("Infrastructure Change", "Servers, network, storage and platform changes", [
        {"id": "affected_systems", "label": "Affected Systems", "type": "multi_select", "required": True, "material": True,
         "options": ["Server", "Network", "Database", "Storage", "Application"]},
        {"id": "description", "label": "Description", "type": "textarea", "required": True, "max_length": 4000},
        {"id": "schedule", "label": "Schedule", "type": "section"},
        {"id": "planned_start", "label": "Planned Start", "type": "datetime", "required": True, "material": True},
        {"id": "planned_end", "label": "Planned End", "type": "datetime", "material": True},
        {"id": "risk", "label": "Risk", "type": "select", "required": True, "material": True, "options": ["Low", "Medium", "High"]},
        {"id": "risk_mitigation", "label": "Risk Mitigation", "type": "textarea", "required": True,
         "show_if": {"field": "risk", "equals": "High"}},
        {"id": "rollback_plan", "label": "Rollback Plan", "type": "textarea", "required": True, "material": True},
        {"id": "evidence", "label": "Supporting Image", "type": "image", "max_count": 3},
    ]),
    "FIREWALL_RULE": ("Firewall Rule Request", "Open, change or close firewall ports", [
        {"id": "source", "label": "Source (IP / subnet)", "type": "text", "required": True, "max_length": 200, "material": True},
        {"id": "destination", "label": "Destination (IP / subnet)", "type": "text", "required": True, "max_length": 200, "material": True},
        {"id": "port", "label": "Port", "type": "number", "required": True, "min": 1, "max": 65535, "material": True},
        {"id": "protocol", "label": "Protocol", "type": "select", "required": True, "options": ["TCP", "UDP"], "material": True},
        {"id": "justification", "label": "Business Justification", "type": "textarea", "required": True},
        {"id": "temporary", "label": "Temporary rule", "type": "checkbox"},
        {"id": "expires_on", "label": "Remove On", "type": "date", "required": True, "show_if": {"field": "temporary", "equals": "yes"}},
    ]),
}


@app.cli.command("seed")
def seed():
    """Create permission profiles, demo forms with workflows and demo core users (safe to re-run)."""
    profiles = {}
    for name, perms in SEED_PROFILES.items():
        p = PermissionProfile.query.filter_by(name=name).first() or PermissionProfile(name=name)
        p.permissions = perms
        db.session.add(p)
        profiles[name] = p
    password = os.environ.get("CMI_SEED_PASSWORD") or secrets.token_urlsafe(9)
    created = []
    for email, name, pnames in SEED_USERS:
        if not User.query.filter_by(email=email).first():
            db.session.add(User(email=email, name=name, is_core=True, password_hash=generate_password_hash(password),
                                profiles=[profiles[p] for p in pnames]))
            created.append(email)
    db.session.flush()
    uid = {u.email: u.id for u in User.query}
    workflows = {
        "INFRA_CHANGE": [
            {"name": "Technical Review", "mode": "any", "approvers": [uid["lead@cmi.local"]], "condition": None},
            {"name": "CAB", "mode": "any", "approvers": [uid["cab@cmi.local"]], "condition": {"field": "risk", "equals": "High"}},
        ],
        "FIREWALL_RULE": [{"name": "Security Review", "mode": "any", "approvers": [uid["lead@cmi.local"]], "condition": None}],
    }
    for key, (name, desc, fields) in SEED_FORMS.items():
        if not Form.query.filter_by(key=key).first():
            schema = {"fields": fields}
            db.session.add(Form(key=key, name=name, description=desc, draft=schema, workflow=workflows[key],
                                default_assignee_id=uid["assigner@cmi.local"] if key == "FIREWALL_RULE" else None,
                                versions=[FormVersion(version=1, schema=schema)]))
    db.session.commit()
    print("Seeded profiles, forms and workflows.")
    if created:
        print(f"Core users {', '.join(created)} created with password: {password}")


def sqlite_path():
    path = db.engine.url.database
    if not path or path == ":memory:":
        raise click.ClickException("Backup and restore need a file-based SQLite database.")
    return path


def backup_to(db_path, upload_dir, dest_dir):
    """Consistent snapshot of the database plus every upload, in one zip."""
    os.makedirs(dest_dir, exist_ok=True)
    archive = os.path.join(dest_dir, f"cmi-backup-{datetime.now():%Y%m%d-%H%M%S}.zip")
    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, "cmi.db")
        src, dst = sqlite3.connect(db_path), sqlite3.connect(snap)
        with dst:
            src.backup(dst)  # online backup API: safe while the app is running
        src.close()
        dst.close()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(snap, "cmi.db")
            if os.path.isdir(upload_dir):
                for name in os.listdir(upload_dir):
                    z.write(os.path.join(upload_dir, name), f"uploads/{name}")
    return archive


def restore_from(archive, db_path, upload_dir):
    """Replace the database and uploads with a backup. Stop the app first."""
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        if "cmi.db" not in names or any(n != "cmi.db" and not (n.startswith("uploads/") and "/" not in n[8:] and ".." not in n)
                                         for n in names):
            raise ValueError("Not a CMI backup archive.")
        with tempfile.TemporaryDirectory() as tmp:
            z.extractall(tmp)
            for suffix in ("", "-wal", "-shm"):
                if os.path.exists(db_path + suffix):
                    os.remove(db_path + suffix)
            shutil.copyfile(os.path.join(tmp, "cmi.db"), db_path)
            shutil.rmtree(upload_dir, ignore_errors=True)
            if os.path.isdir(os.path.join(tmp, "uploads")):
                shutil.copytree(os.path.join(tmp, "uploads"), upload_dir)
            else:
                os.makedirs(upload_dir)


@app.cli.command("backup")
@click.argument("dest_dir", default="backups")
def backup_cmd(dest_dir):
    """Back up the database and uploaded files to DEST_DIR."""
    print(backup_to(sqlite_path(), app.config["UPLOAD_DIR"], dest_dir))


@app.cli.command("restore")
@click.argument("archive")
@click.confirmation_option(prompt="This replaces the current database and uploads. Is the app stopped?")
def restore_cmd(archive):
    """Restore the database and uploaded files from a backup ARCHIVE."""
    path = sqlite_path()
    db.engine.dispose()
    restore_from(archive, path, app.config["UPLOAD_DIR"])
    print(f"Restored {archive}.")
