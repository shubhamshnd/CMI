from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()

STATUSES = ["New", "In Progress", "Pending Approval", "Returned", "Approved", "Rejected", "Closed"]
PRIORITIES = ["Critical", "High", "Medium", "Low"]

# Every permission key the app checks. Profiles are editable lists of these.
PERMISSIONS = {
    "ticket.create": "Create requests",
    "ticket.view": "View all tickets",
    "ticket.edit": "Edit tickets, change status, submit for approval",
    "ticket.assign": "Assign tickets, ask others to set priority",
    "ticket.set_priority": "Set priority",
    "ticket.comment": "Comment and upload evidence",
    "ticket.reopen": "Reopen closed tickets",
    "ticket.link": "Link related tickets",
    "ticket.approve": "Act as an approver",
    "form.publish": "Build and publish forms, configure workflows",
    "user.manage": "Manage users and permission profiles",
    "report.view": "View reports and export",
}

FIELD_TYPES = ["text", "textarea", "select", "multi_select", "date", "datetime", "number", "checkbox",
               "file", "image", "section"]

LINK_KINDS = {  # kind: (label from the linking ticket, label from the linked ticket)
    "child_of": ("Child of", "Parent of"),
    "related": ("Related to", "Related to"),
    "duplicate_of": ("Duplicate of", "Has duplicate"),
    "follow_up_to": ("Follow-up to", "Has follow-up"),
}


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)  # stored as naive UTC


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(conn, _record):
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.close()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    is_core = db.Column(db.Boolean, default=False, nullable=False)
    password_hash = db.Column(db.String(255))
    active = db.Column(db.Boolean, default=True, nullable=False)
    failed_logins = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    profiles = db.relationship("PermissionProfile", secondary="user_profile", back_populates="users")

    def can(self, perm):
        return any(perm in p.permissions for p in self.profiles)


class OtpChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    code_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class PermissionProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    permissions = db.Column(db.JSON, default=list, nullable=False)
    users = db.relationship("User", secondary="user_profile", back_populates="profiles")


# ponytail: profiles are global; add scope_type/scope_id columns when per-form scoping is needed
user_profile = db.Table(
    "user_profile",
    db.Column("user_id", db.ForeignKey("user.id"), primary_key=True),
    db.Column("profile_id", db.ForeignKey("permission_profile.id"), primary_key=True),
)


# People who get every comment on a ticket (and may view it) in addition to its requester, assignee, etc.
ticket_watcher = db.Table(
    "ticket_watcher",
    db.Column("ticket_id", db.ForeignKey("ticket.id"), primary_key=True),
    db.Column("user_id", db.ForeignKey("user.id"), primary_key=True),
)


class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(60), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(255), default="", nullable=False)
    draft = db.Column(db.JSON, default=lambda: {"fields": []}, nullable=False)  # edited freely, published as a version
    archived = db.Column(db.Boolean, default=False, nullable=False)
    # Approval stages: [{"name", "mode": "any"|"all", "approvers": [user ids], "condition": {"field", "equals"} | None}]
    workflow = db.Column(db.JSON, default=list, nullable=False)
    default_assignee_id = db.Column(db.ForeignKey("user.id"))
    versions = db.relationship("FormVersion", order_by="FormVersion.version", back_populates="form")
    default_assignee = db.relationship("User")

    @property
    def latest(self):
        return self.versions[-1] if self.versions else None

    @property
    def has_unpublished_changes(self):
        return not self.latest or self.latest.schema != self.draft


class FormVersion(db.Model):
    """Published versions are immutable; tickets keep pointing at the one they were created with."""
    id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.ForeignKey("form.id"), nullable=False)
    version = db.Column(db.Integer, nullable=False)
    schema = db.Column(db.JSON, nullable=False)  # {"fields": [{id, label, type, required, options, ...}]}
    published_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    published_by_id = db.Column(db.ForeignKey("user.id"))
    form = db.relationship("Form", back_populates="versions")
    published_by = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("form_id", "version"),)


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    form_version_id = db.Column(db.ForeignKey("form_version.id"), nullable=False)
    values = db.Column(db.JSON, default=dict, nullable=False)
    status = db.Column(db.String(30), default="New", nullable=False)
    priority = db.Column(db.String(20))  # None = not set yet
    requester_id = db.Column(db.ForeignKey("user.id"), nullable=False)
    assignee_id = db.Column(db.ForeignKey("user.id"))
    due_date = db.Column(db.Date)
    row_version = db.Column(db.Integer, default=1, nullable=False)   # bumped on every change: conflict detection
    data_version = db.Column(db.Integer, default=1, nullable=False)  # bumped when form values change: what approvers reviewed
    approval_round = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    closed_at = db.Column(db.DateTime)

    form_version = db.relationship("FormVersion")
    requester = db.relationship("User", foreign_keys=[requester_id])
    assignee = db.relationship("User", foreign_keys=[assignee_id])
    comments = db.relationship("Comment", order_by="Comment.created_at")
    history = db.relationship("TicketHistory", order_by="TicketHistory.id.desc()")
    priority_requests = db.relationship("PriorityRequest", order_by="PriorityRequest.created_at.desc()",
                                        back_populates="ticket")
    approvals = db.relationship("TicketApproval", order_by="(TicketApproval.round.desc(), TicketApproval.stage_index)",
                                back_populates="ticket")
    attachments = db.relationship("Attachment", order_by="Attachment.id", back_populates="ticket")
    watchers = db.relationship("User", secondary="ticket_watcher", order_by="User.name")

    @property
    def number(self):
        return f"CHG-{self.id:04d}"

    @property
    def open_priority_requests(self):
        return [r for r in self.priority_requests if r.status == "open"]

    @property
    def round_approvals(self):
        return [a for a in self.approvals if a.round == self.approval_round]


class PriorityRequest(db.Model):
    """An assigner asking someone else to set a ticket's priority.
    While open, the requested user may set priority on this ticket even without ticket.set_priority."""
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.ForeignKey("ticket.id"), nullable=False, index=True)
    requested_by_id = db.Column(db.ForeignKey("user.id"), nullable=False)
    requested_to_id = db.Column(db.ForeignKey("user.id"), nullable=False, index=True)
    note = db.Column(db.Text, default="")
    status = db.Column(db.String(20), default="open", nullable=False)  # open | done
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    resolved_at = db.Column(db.DateTime)

    ticket = db.relationship("Ticket", back_populates="priority_requests")
    requested_by = db.relationship("User", foreign_keys=[requested_by_id])
    requested_to = db.relationship("User", foreign_keys=[requested_to_id])


class TicketApproval(db.Model):
    """One approver's slot in one stage of one approval round. Rows are never deleted."""
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.ForeignKey("ticket.id"), nullable=False, index=True)
    round = db.Column(db.Integer, nullable=False)
    stage_index = db.Column(db.Integer, nullable=False)
    stage_name = db.Column(db.String(120), nullable=False)
    mode = db.Column(db.String(10), default="any", nullable=False)  # any = one approval completes the stage; all = everyone
    approver_id = db.Column(db.ForeignKey("user.id"), nullable=False, index=True)
    decision = db.Column(db.String(20))  # None (waiting) | approved | rejected | returned | skipped
    comment = db.Column(db.Text, default="")
    data_version = db.Column(db.Integer)  # ticket data version the approver reviewed
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    decided_at = db.Column(db.DateTime)

    ticket = db.relationship("Ticket", back_populates="approvals")
    approver = db.relationship("User")


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.ForeignKey("ticket.id"), nullable=False, index=True)
    field_id = db.Column(db.String(40))  # form field it belongs to; None = evidence upload
    filename = db.Column(db.String(255), nullable=False)  # original name, display only
    stored_name = db.Column(db.String(64), unique=True, nullable=False)  # server-generated
    mime = db.Column(db.String(100), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    uploaded_by_id = db.Column(db.ForeignKey("user.id"), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    ticket = db.relationship("Ticket", back_populates="attachments")
    uploaded_by = db.relationship("User")


class TicketLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_ticket_id = db.Column(db.ForeignKey("ticket.id"), nullable=False, index=True)
    to_ticket_id = db.Column(db.ForeignKey("ticket.id"), nullable=False, index=True)
    kind = db.Column(db.String(20), nullable=False)  # see LINK_KINDS
    created_by_id = db.Column(db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    from_ticket = db.relationship("Ticket", foreign_keys=[from_ticket_id])
    to_ticket = db.relationship("Ticket", foreign_keys=[to_ticket_id])
    __table_args__ = (db.UniqueConstraint("from_ticket_id", "to_ticket_id", "kind"),)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.ForeignKey("ticket.id"), nullable=False, index=True)
    author_id = db.Column(db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    author = db.relationship("User")


class TicketHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.ForeignKey("ticket.id"), nullable=False, index=True)
    actor_id = db.Column(db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(60), nullable=False)
    field = db.Column(db.String(120))
    old = db.Column(db.Text)
    new = db.Column(db.Text)
    note = db.Column(db.Text)  # reason given for the change, if any
    at = db.Column(db.DateTime, default=utcnow, nullable=False)
    actor = db.relationship("User")
