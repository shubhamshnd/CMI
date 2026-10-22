"""Administration: form builder and versions, approval workflows, users, permission profiles, reports."""
import copy
import re
import secrets
from collections import Counter, defaultdict
from datetime import date, timedelta
from statistics import mean

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from core import FILE_TYPES, MIN_PASSWORD, need
from models import (FIELD_TYPES, PERMISSIONS, Form, FormVersion, PermissionProfile, Ticket, TicketApproval, User, db,
                    utcnow)

bp = Blueprint("admin", __name__, url_prefix="/admin")

FIELD_ID = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
FORM_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,59}$")
BUILDER_KEYS = ["id", "label", "type", "required", "material", "options", "min", "max", "max_length", "accept",
                "max_mb", "max_count", "show_field", "show_value"]


# ---------------------------------------------------------------- form builder

def parse_fields(form):
    """Builder rows (parallel f_* lists, one entry per row) -> field definitions."""
    cols = {k: form.getlist("f_" + k) for k in BUILDER_KEYS}
    fields, errors = [], []
    for i in range(len(cols["id"])):
        v = {k: (cols[k][i].strip() if i < len(cols[k]) else "") for k in BUILDER_KEYS}
        f = {"id": v["id"], "label": v["label"], "type": v["type"]}
        if v["required"] == "yes":
            f["required"] = True
        if v["material"] == "yes":
            f["material"] = True
        if v["options"] and f["type"] in ("select", "multi_select"):
            f["options"] = list(dict.fromkeys(o.strip() for o in v["options"].split(",") if o.strip()))
        try:
            for k in ("min", "max"):
                if v[k] and f["type"] == "number":
                    n = float(v[k])
                    f[k] = int(n) if n.is_integer() else n
            for k in ("max_length", "max_mb", "max_count"):
                if v[k]:
                    f[k] = int(v[k])
        except ValueError:
            errors.append(f"Field {i + 1}: limits must be numbers.")
        if v["accept"] and f["type"] in ("file", "image"):
            f["accept"] = [e.strip().lower().lstrip(".") for e in v["accept"].split(",") if e.strip()]
        if v["show_field"]:
            f["show_if"] = {"field": v["show_field"], "equals": v["show_value"]}
        fields.append(f)
    return fields, errors


def validate_schema(fields):
    errors, seen = [], {}
    for n, f in enumerate(fields, 1):
        where = f"Field {n} ({f['label'] or f['id'] or 'unnamed'})"
        if not FIELD_ID.match(f["id"]):
            errors.append(f"{where}: ID must start with a lowercase letter and use only a–z, 0–9 and _.")
        elif f["id"] in seen or f["id"] == "title":
            errors.append(f"{where}: ID “{f['id']}” is already used.")
        if not f["label"]:
            errors.append(f"{where}: label is required.")
        if f["type"] not in FIELD_TYPES:
            errors.append(f"{where}: unknown type.")
        if f["type"] in ("select", "multi_select") and not f.get("options"):
            errors.append(f"{where}: add at least one option.")
        if f["type"] in ("file", "image"):
            if not set(f.get("accept", [])) <= set(FILE_TYPES):
                errors.append(f"{where}: allowed file types are {', '.join(FILE_TYPES)}.")
            if not 1 <= f.get("max_mb", 10) <= 25:
                errors.append(f"{where}: size limit must be 1–25 MB.")
        cond = f.get("show_if")
        if cond and (seen.get(cond["field"]) in (None, "file", "image", "section") or not cond["equals"]):
            errors.append(f"{where}: “show when” must name an earlier field and a value.")
        seen[f["id"]] = f["type"]
    if not any(f["type"] != "section" for f in fields):
        errors.append("Add at least one input field.")
    return errors


@bp.get("/forms")
def forms():
    need("form.publish")
    usage = Counter(fid for (fid,) in db.session.query(FormVersion.form_id).join(Ticket, Ticket.form_version_id == FormVersion.id))
    return render_template("admin_forms.html", forms=Form.live().order_by(Form.archived, Form.name).all(), usage=usage)


@bp.post("/forms/new")
def form_new():
    need("form.publish")
    key = request.form.get("key", "").strip().upper()
    name = request.form.get("name", "").strip()[:120]
    if not FORM_KEY.match(key):
        flash("Key must start with a letter and use only A–Z, 0–9 and _ (e.g. ACCESS_CHANGE).", "error")
    elif Form.query.filter_by(key=key).first():  # deleted forms keep their key
        flash(f"A form with key {key} already exists (it may be a deleted form).", "error")
    elif not name:
        flash("Name is required.", "error")
    else:
        f = Form(key=key, name=name, description=request.form.get("description", "").strip()[:255], draft={"fields": []})
        db.session.add(f)
        db.session.commit()
        return redirect(url_for("admin.form_edit", fid=f.id))
    return redirect(url_for("admin.forms"))


@bp.route("/forms/<int:fid>", methods=["GET", "POST"])
def form_edit(fid):
    need("form.publish")
    form = Form.live().filter_by(id=fid).first_or_404()
    fields = form.draft["fields"]
    if request.method == "POST":
        fields, errors = parse_fields(request.form)
        errors += validate_schema(fields)
        name = request.form.get("name", "").strip()[:120]
        if not name:
            errors.append("Name is required.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("admin_form_edit.html", form=form, fields=fields, name=name), 400
        form.name, form.description = name, request.form.get("description", "").strip()[:255]
        form.draft = {"fields": fields}
        action = request.form.get("action")
        if action == "publish":
            if form.has_unpublished_changes:
                version = form.latest.version + 1 if form.latest else 1
                db.session.add(FormVersion(form=form, version=version, schema=copy.deepcopy(form.draft),
                                           published_by_id=g.user.id))
                flash(f"Published version {version}. New requests use it; existing tickets keep their version.", "success")
            else:
                flash("Nothing new to publish.", "info")
        else:
            flash("Draft saved.", "success")
        db.session.commit()
        if action == "preview":
            return redirect(url_for("admin.form_preview", fid=form.id))
        return redirect(url_for("admin.form_edit", fid=form.id))
    return render_template("admin_form_edit.html", form=form, fields=fields, name=form.name)


@bp.get("/forms/<int:fid>/preview")
def form_preview(fid):
    need("form.publish")
    form = Form.live().filter_by(id=fid).first_or_404()
    version = request.args.get("version", type=int)
    fv = next((v for v in form.versions if v.version == version), None) if version else None
    if version and not fv:
        abort(404)
    return render_template("admin_form_preview.html", form=form, schema=fv.schema if fv else form.draft, fv=fv)


@bp.post("/forms/<int:fid>/duplicate")
def form_duplicate(fid):
    need("form.publish")
    src = Form.live().filter_by(id=fid).first_or_404()
    key, n = f"{src.key}_COPY"[:56], 1
    while Form.query.filter_by(key=key if n == 1 else f"{key}{n}").first():
        n += 1
    f = Form(key=key if n == 1 else f"{key}{n}", name=f"Copy of {src.name}"[:120], description=src.description,
             draft=copy.deepcopy(src.draft), workflow=copy.deepcopy(src.workflow), default_assignee_id=src.default_assignee_id)
    db.session.add(f)
    db.session.commit()
    flash(f"Created {f.key} as an unpublished draft.", "success")
    return redirect(url_for("admin.form_edit", fid=f.id))


@bp.post("/forms/<int:fid>/archive")
def form_archive(fid):
    need("form.publish")
    form = Form.live().filter_by(id=fid).first_or_404()
    form.archived = not form.archived
    db.session.commit()
    flash(f"{form.name} {'archived: hidden from the catalogue' if form.archived else 'restored to the catalogue'}.", "success")
    return redirect(url_for("admin.forms"))


@bp.post("/forms/<int:fid>/delete")
def form_delete(fid):
    need("form.publish")
    form = Form.live().filter_by(id=fid).first_or_404()
    form.deleted_at = utcnow()  # soft delete: existing tickets keep working; restore in the DB
    db.session.commit()
    flash(f"Deleted {form.name}.", "success")
    return redirect(url_for("admin.forms"))


@bp.route("/forms/<int:fid>/workflow", methods=["GET", "POST"])
def form_workflow(fid):
    need("form.publish")
    form = Form.live().filter_by(id=fid).first_or_404()
    schema_fields = {f["id"]: f for v in [*form.versions, None] for f in (v.schema if v else form.draft)["fields"]
                     if f["type"] not in ("file", "image", "section")}
    approvers = [u for u in User.query.filter_by(active=True).order_by(User.name) if u.can("ticket.approve")]
    core_users = User.query.filter_by(is_core=True, active=True).order_by(User.name).all()
    if request.method == "POST":
        by_email = {u.email: u for u in approvers}
        cols = {k: request.form.getlist("s_" + k) for k in ("name", "mode", "approvers", "cond_field", "cond_value")}
        stages, errors = [], []
        for i in range(len(cols["name"])):
            v = {k: cols[k][i].strip() for k in cols}
            emails = [e.lower() for e in re.split(r"[,\s;]+", v["approvers"]) if e]
            unknown = [e for e in emails if e not in by_email]
            if not v["name"]:
                errors.append(f"Stage {i + 1}: name is required.")
            if not emails or unknown:
                errors.append(f"Stage {i + 1}: approvers must be active users with approval permission"
                              + (f" (not: {', '.join(unknown)})." if unknown else "."))
            if v["cond_field"] and (v["cond_field"] not in schema_fields or not v["cond_value"]):
                errors.append(f"Stage {i + 1}: condition needs a form field and a value.")
            stages.append({"name": v["name"][:120], "mode": "all" if v["mode"] == "all" else "any",
                           "approvers": list(dict.fromkeys(by_email[e].id for e in emails if e in by_email)),
                           "condition": {"field": v["cond_field"], "equals": v["cond_value"]} if v["cond_field"] else None})
        da = request.form.get("default_assignee_id", type=int)
        if da and da not in {u.id for u in core_users}:
            errors.append("Default assignee must be an active core user.")
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            form.workflow, form.default_assignee_id = stages, da
            db.session.commit()
            flash("Workflow saved. It applies to requests submitted for approval from now on.", "success")
            return redirect(url_for("admin.form_workflow", fid=form.id))
    else:
        stages = form.workflow
    names = {u.id: u.email for u in User.query}
    return render_template("admin_workflow.html", form=form, stages=stages, schema_fields=schema_fields,
                           approvers=approvers, core_users=core_users, names=names)


# ---------------------------------------------------------------- users & profiles

def managers_left():
    return sum(1 for u in User.query.filter_by(active=True) if u.can("user.manage"))


@bp.get("/users")
def users():
    need("user.manage")
    q = User.live()
    text = request.args.get("q", "").strip()
    if text:
        q = q.filter(User.name.ilike(f"%{text}%") | User.email.ilike(f"%{text}%"))
    return render_template("admin_users.html", users=q.order_by(User.is_core.desc(), User.name).limit(500).all(), now=utcnow())


@bp.route("/users/new", methods=["GET", "POST"])
@bp.route("/users/<int:uid>", methods=["GET", "POST"])
def user_edit(uid=None):
    need("user.manage")
    u = User.live().filter_by(id=uid).first_or_404() if uid else User(is_core=True, active=True)
    profiles = PermissionProfile.query.order_by(PermissionProfile.name).all()
    if request.method == "POST":
        errors = []
        name = request.form.get("name", "").strip()[:120]
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name:
            errors.append("Name is required.")
        if not uid:
            if "@" not in email or User.query.filter_by(email=email).first():  # includes deleted users
                errors.append("Enter an email address that is not already in use (it may belong to a deleted user).")
            u.email = email
        if password and len(password) < MIN_PASSWORD:
            errors.append(f"Passwords need at least {MIN_PASSWORD} characters.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("admin_user_edit.html", u=u, profiles=profiles), 400
        u.name = name
        u.is_core = "is_core" in request.form
        u.active = "active" in request.form or not uid
        chosen = set(request.form.getlist("profiles", type=int))
        u.profiles = [p for p in profiles if p.id in chosen]
        if "unlock" in request.form:
            u.locked_until, u.failed_logins = None, 0
        generated = None
        if u.is_core and (password or not u.password_hash):
            generated = None if password else secrets.token_urlsafe(9)
            u.password_hash = generate_password_hash(password or generated)
        db.session.add(u)
        db.session.flush()
        if managers_left() == 0:
            db.session.rollback()
            flash("At least one active user must keep the user.manage permission.", "error")
            return redirect(url_for("admin.user_edit", uid=uid) if uid else url_for("admin.users"))
        db.session.commit()
        flash(f"Saved {u.name}." + (f" Temporary password: {generated} (shown once; ask them to change it)." if generated else ""),
              "success")
        return redirect(url_for("admin.users"))
    return render_template("admin_user_edit.html", u=u, profiles=profiles)


@bp.post("/users/<int:uid>/delete")
def user_delete(uid):
    need("user.manage")
    u = User.live().filter_by(id=uid).first_or_404()
    if u.id == g.user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin.user_edit", uid=uid))
    u.deleted_at, u.active = utcnow(), False  # soft delete: cannot sign in, hidden everywhere; restore in the DB
    db.session.flush()
    if managers_left() == 0:
        db.session.rollback()
        flash("At least one active user must keep the user.manage permission.", "error")
        return redirect(url_for("admin.user_edit", uid=uid))
    db.session.commit()
    flash(f"Deleted {u.name}.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/profiles", methods=["GET", "POST"])
def profiles():
    need("user.manage")
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:80]
        if not name or PermissionProfile.query.filter_by(name=name).first():
            flash("Enter a profile name that is not already in use.", "error")
        else:
            p = PermissionProfile(name=name, permissions=[])
            db.session.add(p)
            db.session.commit()
            return redirect(url_for("admin.profile_edit", pid=p.id))
    return render_template("admin_profiles.html", profiles=PermissionProfile.query.order_by(PermissionProfile.name).all())


@bp.route("/profiles/<int:pid>", methods=["GET", "POST"])
def profile_edit(pid):
    need("user.manage")
    p = db.session.get(PermissionProfile, pid) or abort(404)
    if request.method == "POST":
        if request.form.get("action") == "delete":
            if p.users:
                flash("Remove this profile from all users before deleting it.", "error")
                return redirect(url_for("admin.profile_edit", pid=p.id))
            db.session.delete(p)
            db.session.commit()
            flash("Profile deleted.", "success")
            return redirect(url_for("admin.profiles"))
        name = request.form.get("name", "").strip()[:80]
        if not name or PermissionProfile.query.filter(PermissionProfile.name == name, PermissionProfile.id != p.id).first():
            flash("Enter a profile name that is not already in use.", "error")
            return redirect(url_for("admin.profile_edit", pid=p.id))
        p.name = name
        p.permissions = [k for k in PERMISSIONS if k in request.form.getlist("permissions")]
        db.session.flush()
        if managers_left() == 0:
            db.session.rollback()
            flash("At least one active user must keep the user.manage permission.", "error")
            return redirect(url_for("admin.profile_edit", pid=pid))
        db.session.commit()
        flash("Profile saved.", "success")
        return redirect(url_for("admin.profiles"))
    return render_template("admin_profile_edit.html", p=p)


# ---------------------------------------------------------------- reports

@bp.get("/reports")
def reports():
    need("report.view")
    tickets = Ticket.query.all()  # ponytail: aggregates in Python; move to SQL GROUP BY if tickets reach ~50k
    today = date.today()
    open_ = [t for t in tickets if t.status not in ("Closed", "Rejected")]
    closed = [t for t in tickets if t.closed_at]
    kpis = [
        ("Open", len(open_), url_for("tickets", tab="all")),
        ("Overdue", sum(1 for t in open_ if t.due_date and t.due_date < today), url_for("tickets", tab="all", overdue=1)),
        ("Pending approval", sum(1 for t in open_ if t.status == "Pending Approval"), url_for("tickets", tab="all", status="Pending Approval")),
        ("Unassigned", sum(1 for t in open_ if not t.assignee_id), None),
        ("Closed, last 30 days", sum(1 for t in closed if t.closed_at >= utcnow() - timedelta(days=30)), None),
    ]
    rounds = defaultdict(list)
    for a in TicketApproval.query:
        rounds[(a.ticket_id, a.round)].append(a)
    approval_hours = [(max(r.decided_at for r in rows if r.decided_at) - min(r.created_at for r in rows)).total_seconds() / 3600
                      for rows in rounds.values()
                      if all(r.decision for r in rows) and any(r.decided_at for r in rows)]
    times = {
        "Average resolution (days)": round(mean((t.closed_at - t.created_at).total_seconds() / 86400 for t in closed), 1) if closed else "—",
        "Average approval round (hours)": round(mean(approval_hours), 1) if approval_hours else "—",
    }
    groups = {
        "Open by form": Counter(t.form_version.form.name for t in open_),
        "Open by priority": Counter(t.priority or "Not set" for t in open_),
        "Open by assignee": Counter(t.assignee.name if t.assignee else "Unassigned" for t in open_),
        "All by status": Counter(t.status for t in tickets),
    }
    return render_template("reports.html", kpis=kpis, times=times, groups=groups)
