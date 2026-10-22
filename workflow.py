"""Approval engine: ordered stages (sequential), each needing one ('any') or every ('all') listed approver."""
from flask import url_for

from core import Invalid, notify, record, set_status, subscribers
from models import TicketApproval, User, db, utcnow


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


def _ask(t, stage):
    notify([r.approver for r in stage], f"{t.number}: approval needed ({stage[0].stage_name})",
           f"{t.number} – {t.title} is waiting for your approval.\n\n{_link(t)}")


def start_approval(t, reason="submitted for approval"):
    """Open a new approval round from the form's current workflow. Raises Invalid if a stage has nobody to approve."""
    stages = []
    for s in t.form_version.form.workflow:
        if condition_met(t.values, s.get("condition")):
            users = User.query.filter(User.id.in_(s["approvers"]), User.active.is_(True)).all()
            if not users:
                raise Invalid(f"Approval stage “{s['name']}” has no active approvers. Ask a form administrator to fix the workflow.")
            stages.append((s, users))
    for r in t.round_approvals:
        if r.decision is None:
            r.decision = "skipped"
    t.approval_round += 1
    for i, (s, users) in enumerate(stages):
        for u in users:
            db.session.add(TicketApproval(ticket=t, round=t.approval_round, stage_index=i, stage_name=s["name"],
                                          mode=s.get("mode", "any"), approver=u))
    record(t, reason, None, None, ", ".join(s["name"] for s, _ in stages) or "no approval stages apply")
    set_status(t, "Pending Approval" if stages else "Approved")
    if stages:
        _ask(t, current_stage(t))
    notify(subscribers(t, "status"), f"{t.number}: {t.status}",
           f"{t.number} – {t.title}: {reason}" + (" (no approval stages apply, so it is approved)" if not stages else "")
           + f".\n\n{_link(t)}", skip=[r.approver for r in current_stage(t)])


def decide(t, row, decision, comment, actor):
    row.decision, row.comment, row.decided_at, row.data_version = decision, comment, utcnow(), t.data_version
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
