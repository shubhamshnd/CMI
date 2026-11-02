"""Approval engine: ordered stages (sequential), each needing one ('any') or every ('all') listed approver.
A stage may instead name its approver through an email field on the request (e.g. the requester's HOD):
that person gets a single-use link and decides without signing in."""
import hashlib
import logging
import secrets
from datetime import timedelta

from flask import url_for

import core
from core import Invalid, notify, record, set_status, show_value, subscribers, user_for_email
from models import TicketApproval, User, db, utcnow

LINK_TTL = timedelta(days=7)
log = logging.getLogger("cmi")


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def condition_met(values, cond):
    if not cond:
        return True
    v = values.get(cond["field"])
    v = (["yes"] if v else []) if isinstance(v, bool) else v if isinstance(v, list) else [v]
    return cond["equals"] in v


def stage_done(rows):
    approved = [r for r in rows if r.decision == "approved"]
    return bool(approved) if rows[0].mode == "any" else len(approved) == len(rows)


def current_stage(t):
    """Approval rows of the first unfinished stage in the current round ([] when all are done)."""
    rows = t.round_approvals
    for i in sorted({r.stage_index for r in rows}):
        stage = [r for r in rows if r.stage_index == i]
        if not stage_done(stage):
            return stage
    return []


def pending_for(user, t):
    """The approval row this user must act on now, if any."""
    if t.status != "Pending Approval":
        return None
    return next((r for r in current_stage(t) if r.approver_id == user.id and r.decision is None), None)


def _link(t):
    return url_for("ticket_detail", tid=t.id, _external=True)


def send_link(t, row, reminder=False):
    """Email a fresh approval link to an approver named by email; any earlier link for this row stops working.
    Needs a request context (url_for); the caller commits."""
    token = secrets.token_urlsafe(32)
    row.token_hash, row.link_sent_at, row.link_expires = token_hash(token), utcnow(), utcnow() + LINK_TTL
    details = [f"  {f['label']}: {show_value(f, t.values[f['id']])}" for f in t.form_version.schema["fields"]
               if f["id"] in t.values and f["type"] not in ("section", "file", "image", "approver_email")]
    body = (f"{t.requester.name} has asked for your approval ({row.stage_name}):\n\n"
            f"{t.number} – {t.title}\n{t.form_version.form.name}\n\n" + "\n".join(details) +
            f"\n\nReview and decide (no sign-in needed):\n{url_for('approval_link', token=token, _external=True)}\n\n"
            f"This link is for you only and works once. It expires on {row.link_expires:%d %b %Y}. Do not forward it.")
    try:
        core.send_mail(row.approver.email, f"{'Reminder: ' if reminder else ''}Approval needed: {t.number} {t.title}", body)
    except Exception:
        log.exception("approval link to %s failed", row.approver.email)


def _ask(t, stage):
    notify([r.approver for r in stage if not r.via_email], f"{t.number}: approval needed ({stage[0].stage_name})",
           f"{t.number} – {t.title} is waiting for your approval.\n\n{_link(t)}")
    for r in stage:
        if r.via_email:
            send_link(t, r)


def stage_approvers(t, s):
    """Who approves one stage: its named users, or the person whose email the requester typed into s["approver_field"]."""
    if not s.get("approver_field"):
        users = User.query.filter(User.id.in_(s["approvers"]), User.active.is_(True)).all()
        if not users:
            raise Invalid(f"Approval stage “{s['name']}” has no active approvers. Ask a form administrator to fix the workflow.")
        return users
    email = t.values.get(s["approver_field"])
    if not email:
        raise Invalid(f"Approval stage “{s['name']}” needs an approver's email on the request. Edit the request and add it.")
    if email == t.requester.email:
        raise Invalid("You cannot approve your own request. Enter your HOD's email address.")
    user = user_for_email(email)
    if not user.active:
        raise Invalid(f"{email} cannot approve: that account is deactivated in CMI.")
    return [user]


def start_approval(t, reason="submitted for approval"):
    """Open a new approval round from the form's current workflow. Raises Invalid if a stage has nobody to approve."""
    stages = []
    for s in t.form_version.form.workflow:
        if condition_met(t.values, s.get("condition")):
            stages.append((s, stage_approvers(t, s)))
    for r in t.round_approvals:
        if r.decision is None:
            r.decision = "skipped"
    t.approval_round += 1
    for i, (s, users) in enumerate(stages):
        for u in users:
            db.session.add(TicketApproval(ticket=t, round=t.approval_round, stage_index=i, stage_name=s["name"],
                                          mode=s.get("mode", "any"), approver=u, via_email=bool(s.get("approver_field"))))
    record(t, reason, None, None, ", ".join(s["name"] for s, _ in stages) or "no approval stages apply")
    set_status(t, "Pending Approval" if stages else "Approved")
    if stages:
        _ask(t, current_stage(t))
    notify(subscribers(t, "status"), f"{t.number}: {t.status}",
           f"{t.number} – {t.title}: {reason}" + (" (no approval stages apply, so it is approved)" if not stages else "")
           + f".\n\n{_link(t)}", skip=[r.approver for r in current_stage(t)])


def decide(t, row, decision, comment, actor):
    row.decision, row.comment, row.decided_at, row.data_version = decision, comment, utcnow(), t.data_version
    row.token_hash = None  # an emailed link works once
    record(t, decision, None, None, row.stage_name, note=comment)
    if decision in ("rejected", "returned"):
        for r in t.round_approvals:
            if r.decision is None:
                r.decision = "skipped"
        set_status(t, "Rejected" if decision == "rejected" else "Returned")
        notify([t.requester, t.assignee, *subscribers(t, "status")], f"{t.number}: {decision} by {actor.name}",
               f"{actor.name} {decision} {t.number} – {t.title} at stage {row.stage_name}."
               + (f"\n\nComment: {comment}" if comment else "") + f"\n\n{_link(t)}")
        return
    stage = [r for r in t.round_approvals if r.stage_index == row.stage_index]
    if not stage_done(stage):
        return
    for r in stage:
        if r.decision is None:
            r.decision = "skipped"
    nxt = current_stage(t)
    if nxt:
        _ask(t, nxt)
    else:
        set_status(t, "Approved")
        notify([t.requester, t.assignee, *subscribers(t, "status")], f"{t.number}: approved",
               f"{t.number} – {t.title} is fully approved.\n\n{_link(t)}")
