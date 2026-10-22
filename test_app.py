import io
import os
import re
import tempfile

os.environ["CMI_ENV_FILE"] = os.devnull  # tests must not pick up this machine's .env (mail server, domains…)
os.environ["CMI_DATABASE_URL"] = "sqlite://"
os.environ["CMI_SEED_PASSWORD"] = "pw-test-123"
os.environ["CMI_UPLOAD_DIR"] = tempfile.mkdtemp(prefix="cmi-test-uploads-")

import pytest
from werkzeug.datastructures import MultiDict

import app as cmi
import core
from models import PriorityRequest, Ticket, TicketHistory, TicketLink, User, db

INFRA = {"title": "Upgrade core switch", "affected_systems": ["Server", "Network"], "description": "Firmware 9.4",
         "planned_start": "2026-10-27T22:00", "risk": "Medium", "rollback_plan": "Restore 9.3"}
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


@pytest.fixture
def mail(monkeypatch):
    sent = []
    monkeypatch.setattr(core, "send_mail", lambda to, subject, body: sent.append((to, subject, body)))
    with cmi.app.app_context():
        db.drop_all()
        db.create_all()
    assert cmi.app.test_cli_runner().invoke(args=["seed"]).exit_code == 0
    return sent


def post(client, url, **data):
    with client.session_transaction() as s:
        token = s.setdefault("_csrf", "test-token")
    return client.post(url, data={"_csrf": token, **data})


def login(email):
    c = cmi.app.test_client()
    r = post(c, "/login/core", email=email, password="pw-test-123")
    assert r.status_code == 302 and r.location == "/", f"login failed for {email}"
    return c


def requester(mail, email="req@corp.com"):
    c = cmi.app.test_client()
    post(c, "/login/otp/send", email=email)
    code = re.search(r"\b(\d{6})\b", mail[-1][2]).group(1)
    assert post(c, "/login/otp/verify", code=code).location == "/"
    return c


def ticket(tid=1):
    return db.session.get(Ticket, tid)


def rv(tid=1):
    with cmi.app.app_context():
        return ticket(tid).row_version


def uid(email):
    with cmi.app.app_context():
        return User.query.filter_by(email=email).one().id


def create(client, form="INFRA_CHANGE", **overrides):
    r = post(client, f"/tickets/new?form={form}", **{**INFRA, **overrides})
    assert r.status_code == 302, r.get_data(as_text=True)[:2000]
    return int(r.location.rsplit("/", 1)[1])


# ---------------------------------------------------------------- auth

def test_post_without_csrf_rejected(mail):
    assert cmi.app.test_client().post("/login/core", data={"email": "x"}).status_code == 400


def test_otp_login_is_single_use(mail):
    c = cmi.app.test_client()
    post(c, "/login/otp/send", email="Req@Corp.com")
    code = re.search(r"\b(\d{6})\b", mail[-1][2]).group(1)
    assert post(c, "/login/otp/verify", code="000000" if code != "000000" else "111111").location == "/login"
    assert post(c, "/login/otp/verify", code=code).location == "/"
    assert c.get("/").status_code == 200
    c2 = cmi.app.test_client()
    with c2.session_transaction() as s:
        s["otp_email"] = "req@corp.com"
    assert post(c2, "/login/otp/verify", code=code).location == "/login"


def test_core_user_cannot_use_otp(mail):
    c = cmi.app.test_client()
    post(c, "/login/otp/send", email="admin@cmi.local")
    code = re.search(r"\b(\d{6})\b", mail[-1][2]).group(1)
    assert post(c, "/login/otp/verify", code=code).location == "/login"


def test_deactivated_user_cannot_sign_in_and_last_manager_is_protected(mail):
    admin = login("admin@cmi.local")
    post(admin, f"/admin/users/{uid('engineer@cmi.local')}", name="Rohit Engineer", is_core="on")  # no "active"
    r = post(cmi.app.test_client(), "/login/core", email="engineer@cmi.local", password="pw-test-123")
    assert r.location.endswith("mode=core")
    # the only user.manage holder cannot strip their own profiles
    post(admin, f"/admin/users/{uid('admin@cmi.local')}", name="CMI Admin", is_core="on", active="on")
    with cmi.app.app_context():
        assert db.session.get(User, uid("admin@cmi.local")).can("user.manage")


def test_soft_delete_hides_users_and_forms_but_keeps_records(mail):
    admin = login("admin@cmi.local")
    tid = create(admin)
    with cmi.app.app_context():
        from models import Form
        fid = Form.query.filter_by(key="INFRA_CHANGE").one().id
    # users
    assert post(admin, f"/admin/users/{uid('admin@cmi.local')}/delete").location.endswith(f"/admin/users/{uid('admin@cmi.local')}")
    eid = uid("engineer@cmi.local")
    post(admin, f"/admin/users/{eid}/delete")
    assert "engineer@cmi.local" not in admin.get("/admin/users").get_data(as_text=True)
    assert admin.get(f"/admin/users/{eid}").status_code == 404
    assert post(cmi.app.test_client(), "/login/core", email="engineer@cmi.local", password="pw-test-123").location.endswith("mode=core")
    assert "Rohit Engineer" not in admin.get(f"/tickets/{tid}").get_data(as_text=True).split('id="assignee"')[1].split("</select>")[0]
    # forms
    post(admin, f"/admin/forms/{fid}/delete")
    for page in ("/", "/tickets/new", "/admin/forms"):
        assert "INFRA_CHANGE" not in admin.get(page).get_data(as_text=True), page  # key, not name: the flash says the name
    assert admin.get(f"/admin/forms/{fid}").status_code == 404
    assert "Upgrade core switch" in admin.get(f"/tickets/{tid}").get_data(as_text=True)  # old tickets still work
    with cmi.app.app_context():  # rows are still in the database
        assert db.session.get(User, eid).deleted_at and db.session.get(Form, fid).deleted_at


# ---------------------------------------------------------------- forms

def test_validate_rules_and_conditions():
    schema = {"fields": [
        {"id": "risk", "type": "select", "required": True, "options": ["Low", "High"]},
        {"id": "plan", "type": "textarea", "required": True, "show_if": {"field": "risk", "equals": "High"}},
        {"id": "port", "type": "number", "min": 1, "max": 65535},
        {"id": "tmp", "type": "checkbox"},
    ]}
    _, errors, _ = core.validate(schema, MultiDict({"risk": "Huge", "port": "70000"}))
    assert set(errors) == {"risk", "port"}
    values, errors, _ = core.validate(schema, MultiDict({"risk": "Low", "port": "443", "tmp": "yes", "plan": "x"}))
    assert errors == {} and values == {"risk": "Low", "port": "443", "tmp": True}  # hidden "plan" dropped
    _, errors, _ = core.validate(schema, MultiDict({"risk": "High"}))
    assert errors == {"plan": "Required"}


def test_publish_new_version_keeps_old_tickets_on_their_version(mail):
    admin = login("admin@cmi.local")
    create(admin)
    with cmi.app.app_context():
        from models import Form
        form = Form.query.filter_by(key="FIREWALL_RULE").one()
        fid, fields = form.id, form.draft["fields"]
    rows = MultiDict({"_csrf": "test-token", "name": "Firewall Rule Request", "action": "publish"})
    for f in fields + [{"id": "ticket_ref", "label": "Change Ref", "type": "text"}]:
        for k in ("id", "label", "type"):
            rows.add("f_" + k, f[k])
        rows.add("f_required", "yes" if f.get("required") else "no")
        rows.add("f_options", ", ".join(f.get("options", [])))
        rows.add("f_show_field", f.get("show_if", {}).get("field", ""))
        rows.add("f_show_value", f.get("show_if", {}).get("equals", ""))
        for k in ("material", "min", "max", "max_length", "accept", "max_mb", "max_count"):
            rows.add("f_" + k, str(f.get(k, "")) if k not in ("material",) else ("yes" if f.get(k) else "no"))
    with admin.session_transaction() as s:
        s["_csrf"] = "test-token"
    fw = dict(title="Open 443", source="10.0.0.0/24", destination="10.1.1.1", port="443", protocol="TCP", justification="Web")
    old = create(admin, "FIREWALL_RULE", **fw)
    assert admin.post(f"/admin/forms/{fid}", data=rows).status_code == 302
    new = create(admin, "FIREWALL_RULE", **fw)
    with cmi.app.app_context():
        assert ticket(old).form_version.version == 1 and ticket(new).form_version.version == 2
    # duplicate field IDs are refused
    bad = MultiDict(rows)
    bad.add("f_id", "port")
    for k in ("label", "type", "required", "material", "options", "min", "max", "max_length", "accept", "max_mb",
              "max_count", "show_field", "show_value"):
        bad.add("f_" + k, {"label": "Dup", "type": "text", "required": "no", "material": "no"}.get(k, ""))
    assert admin.post(f"/admin/forms/{fid}", data=bad).status_code == 400


# ---------------------------------------------------------------- priority request

def test_assigner_asks_someone_else_to_set_priority(mail):
    tid = create(login("admin@cmi.local"))
    assigner = login("assigner@cmi.local")
    post(assigner, f"/tickets/{tid}/assign", rv=rv(), assignee_id=uid("engineer@cmi.local"))
    post(assigner, f"/tickets/{tid}/priority-request", requested_to_id=uid("cab@cmi.local"), note="Please assess impact")
    assert mail[-1][0] == "cab@cmi.local" and "set the priority" in mail[-1][1]
    with cmi.app.app_context():
        assert ticket().priority is None and len(ticket().open_priority_requests) == 1

    cab = login("cab@cmi.local")  # Approver profile only: no ticket.set_priority
    assert "asked you to set the priority" in cab.get(f"/tickets/{tid}").get_data(as_text=True)
    assert post(login("engineer@cmi.local"), f"/tickets/{tid}/priority", rv=rv(), priority="High").status_code == 403
    post(cab, f"/tickets/{tid}/priority", rv=rv() - 1, priority="High")  # stale form
    with cmi.app.app_context():
        assert ticket().priority is None
    post(cab, f"/tickets/{tid}/priority", rv=rv(), priority="High")
    assert mail[-1][0] == "assigner@cmi.local" and "High" in mail[-1][1]
    with cmi.app.app_context():
        assert ticket().priority == "High" and PriorityRequest.query.one().status == "done"
        assert {"asked for a priority from", "priority request completed"} <= {h.action for h in TicketHistory.query}
    assert post(cab, f"/tickets/{tid}/priority", rv=rv(), priority="Low").status_code == 403  # one-off grant used


def test_requester_cannot_ask_for_priority(mail):
    tid = create(login("admin@cmi.local"))
    assert post(login("engineer@cmi.local"), f"/tickets/{tid}/priority-request", requested_to_id=1).status_code == 403


# ---------------------------------------------------------------- approvals

def test_sequential_conditional_approval_with_return_and_reapproval(mail):
    tid = create(login("admin@cmi.local"), risk="High", risk_mitigation="Change window, vendor on call")
    engineer, lead, cab = login("engineer@cmi.local"), login("lead@cmi.local"), login("cab@cmi.local")
    post(engineer, f"/tickets/{tid}/submit", rv=rv())
    assert mail[-1][0] == "lead@cmi.local"  # stage 1 asked first
    with cmi.app.app_context():
        assert ticket().status == "Pending Approval" and {a.stage_name for a in ticket().approvals} == {"Technical Review", "CAB"}
    post(cab, f"/tickets/{tid}/decide", rv=rv(), decision="approved")  # not CAB's turn yet
    with cmi.app.app_context():
        assert all(a.decision is None for a in ticket().approvals)
    post(lead, f"/tickets/{tid}/decide", rv=rv(), decision="approved")
    assert mail[-1][0] == "cab@cmi.local"
    post(cab, f"/tickets/{tid}/decide", rv=rv(), decision="returned")  # comment required
    with cmi.app.app_context():
        assert ticket().status == "Pending Approval"
    post(cab, f"/tickets/{tid}/decide", rv=rv(), decision="returned", comment="Add rollback timing")
    with cmi.app.app_context():
        assert ticket().status == "Returned"
    post(cab, f"/tickets/{tid}/decide", rv=rv(), decision="approved")  # duplicate action ignored
    with cmi.app.app_context():
        assert ticket().status == "Returned"
    # resubmit -> round 2, approve both stages
    post(engineer, f"/tickets/{tid}/submit", rv=rv())
    post(lead, f"/tickets/{tid}/decide", rv=rv(), decision="approved")
    post(cab, f"/tickets/{tid}/decide", rv=rv(), decision="approved", comment="OK")
    with cmi.app.app_context():
        t = ticket()
        assert t.status == "Approved" and t.approval_round == 2
        assert all(a.data_version == t.data_version for a in t.round_approvals)
    # a material change after approval restarts approval
    post(engineer, f"/tickets/{tid}/edit", rv=rv(), **{**INFRA, "risk": "High", "risk_mitigation": "x",
                                                        "planned_start": "2026-11-03T22:00"}, reason="Moved window")
    with cmi.app.app_context():
        t = ticket()
        assert t.status == "Pending Approval" and t.approval_round == 3
        assert any(h.note == "Moved window" and h.field == "Planned Start" for h in t.history)


def test_low_risk_skips_conditional_stage(mail):
    tid = create(login("admin@cmi.local"), risk="Low")
    post(login("engineer@cmi.local"), f"/tickets/{tid}/submit", rv=rv())
    post(login("lead@cmi.local"), f"/tickets/{tid}/decide", rv=rv(), decision="approved")
    with cmi.app.app_context():
        assert ticket().status == "Approved" and {a.stage_name for a in ticket().approvals} == {"Technical Review"}


# ---------------------------------------------------------------- attachments & links

def test_attachments_are_checked_and_access_controlled(mail):
    tid = create(login("admin@cmi.local"))
    engineer = login("engineer@cmi.local")
    post(engineer, f"/tickets/{tid}/attachments", files=(io.BytesIO(b"MZ fake exe"), "shot.png"))
    with cmi.app.app_context():
        assert ticket().attachments == []
    post(engineer, f"/tickets/{tid}/attachments", files=(io.BytesIO(PNG), "shot.png"))
    with cmi.app.app_context():
        aid = ticket().attachments[0].id
    assert requester(mail).get(f"/attachments/{aid}").status_code == 403  # unrelated requester
    r = engineer.get(f"/attachments/{aid}")
    assert r.status_code == 200 and r.data == PNG and "attachment" in r.headers["Content-Disposition"]
    with cmi.app.app_context():
        assert any(h.action == "downloaded" for h in ticket().history)


def test_links_follow_up_and_no_parent_loops(mail):
    admin = login("admin@cmi.local")
    a, b = create(admin), create(admin, title="Second")
    post(admin, f"/tickets/{a}/links", kind="child_of", number=f"CHG-{b:04d}")
    post(admin, f"/tickets/{b}/links", kind="child_of", number=f"CHG-{a:04d}")  # would loop
    r = post(admin, f"/tickets/new?form=INFRA_CHANGE&from={a}&link=follow_up_to", **INFRA)
    c = int(r.location.rsplit("/", 1)[1])
    with cmi.app.app_context():
        kinds = {(l.from_ticket_id, l.to_ticket_id, l.kind) for l in TicketLink.query}
        assert kinds == {(a, b, "child_of"), (c, a, "follow_up_to")}


# ---------------------------------------------------------------- comment conversation

def test_comments_email_everyone_on_the_request(mail):
    tid = create(login("admin@cmi.local"))
    assigner = login("assigner@cmi.local")
    post(assigner, f"/tickets/{tid}/assign", rv=rv(), assignee_id=uid("engineer@cmi.local"))
    req = requester(mail, "colleague@corp.com")  # exists once signed in
    assert req.get(f"/tickets/{tid}").status_code == 403
    post(assigner, f"/tickets/{tid}/watchers", email="colleague@corp.com")
    assert req.get(f"/tickets/{tid}").status_code == 200  # watchers can follow the request
    mail.clear()
    post(login("engineer@cmi.local"), f"/tickets/{tid}/comment", body="Vendor confirmed the window.")
    to = {m[0] for m in mail}
    assert to == {"admin@cmi.local", "colleague@corp.com"}  # requester + watcher; not the author
    assert all(m[1] == f"[CHG-{tid:04d}] Upgrade core switch" and "Vendor confirmed" in m[2] for m in mail)
    mail.clear()
    post(req, f"/tickets/{tid}/comment", body="x")  # requesters have ticket.comment
    # earlier commenter (engineer), assignee (engineer), requester (admin); watcher is the author
    assert {m[0] for m in mail} == {"admin@cmi.local", "engineer@cmi.local"}
    assert post(login("lead@cmi.local"), f"/tickets/{tid}/watchers/{uid('colleague@corp.com')}/delete").status_code == 403


def test_form_notify_list_gets_chosen_events_only(mail):
    admin = login("admin@cmi.local")
    with cmi.app.app_context():
        from models import Form
        fid = Form.query.filter_by(key="INFRA_CHANGE").one().id
    post(admin, f"/admin/forms/{fid}/notify", new_email="engineer@cmi.local", new_events=["new", "status"])
    post(admin, f"/admin/forms/{fid}/notify", uid=str(uid("engineer@cmi.local")), **{f"ev_{uid('engineer@cmi.local')}": ["new", "status"]},
         new_email="cab@cmi.local", new_events="comment")
    with cmi.app.app_context():
        assert {s["user_id"]: s["events"] for s in db.session.get(Form, fid).notify} == {
            uid("engineer@cmi.local"): ["new", "status"], uid("cab@cmi.local"): ["comment"]}
    mail.clear()
    tid = create(login("assigner@cmi.local"))  # Medium risk: CAB is not an approver here
    assert [m[0] for m in mail] == ["engineer@cmi.local"] and "New request" in mail[0][1]
    cab = login("cab@cmi.local")
    assert cab.get(f"/tickets/{tid}").status_code == 200  # on the notify list, so the email link works
    mail.clear()
    post(admin, f"/tickets/{tid}/comment", body="Window confirmed")
    assert sorted(m[0] for m in mail) == ["assigner@cmi.local", "cab@cmi.local"]  # requester + comment subscriber
    mail.clear()
    post(admin, f"/tickets/{tid}/status", rv=rv(tid), status="In Progress")
    assert sorted(m[0] for m in mail) == ["assigner@cmi.local", "engineer@cmi.local"]  # requester + status subscriber
    # remove
    post(admin, f"/admin/forms/{fid}/notify", uid=[str(uid("engineer@cmi.local")), str(uid("cab@cmi.local"))],
         **{f"ev_{uid('engineer@cmi.local')}": "new", f"ev_{uid('cab@cmi.local')}": "comment"}, remove=str(uid("cab@cmi.local")))
    with cmi.app.app_context():
        assert [s["user_id"] for s in db.session.get(Form, fid).notify] == [uid("engineer@cmi.local")]


def test_admin_soft_deletes_a_request(mail):
    admin = login("admin@cmi.local")
    keep, gone = create(admin, title="Keep me"), create(admin, title="Remove me")
    post(admin, f"/tickets/{keep}/links", kind="related", number=f"CHG-{gone:04d}")
    assert post(login("engineer@cmi.local"), f"/tickets/{gone}/delete").status_code == 403
    post(admin, f"/tickets/{gone}/delete")
    assert admin.get(f"/tickets/{gone}").status_code == 404
    assert "Remove me" not in admin.get("/tickets?tab=all").get_data(as_text=True)
    assert "Remove me" not in admin.get(f"/tickets/{keep}").get_data(as_text=True)  # link hidden too
    assert "Remove me" not in admin.get("/tickets?tab=all&export=csv").get_data(as_text=True)
    with cmi.app.app_context():
        assert ticket(gone).deleted_at and ticket(gone).title == "Remove me"  # still in the database


# ---------------------------------------------------------------- export & backup

def test_csv_export_neutralises_formulas(mail):
    admin = login("admin@cmi.local")
    create(admin, title="=HYPERLINK(\"http://evil\")")
    body = admin.get("/tickets?tab=all&export=csv").get_data(as_text=True)
    assert "'=HYPERLINK" in body


def test_backup_and_restore_roundtrip(tmp_path):
    import sqlite3
    from contextlib import closing

    def sql(query):
        with closing(sqlite3.connect(db_path)) as con, con:
            return con.execute(query).fetchall()
    db_path, uploads = tmp_path / "cmi.db", tmp_path / "uploads"
    uploads.mkdir()
    (uploads / "abc").write_bytes(b"file")
    sql("create table t (x)")
    sql("insert into t values (1)")
    archive = cmi.backup_to(str(db_path), str(uploads), str(tmp_path / "bk"))
    sql("delete from t")
    (uploads / "abc").unlink()
    cmi.restore_from(archive, str(db_path), str(uploads))
    assert sql("select x from t") == [(1,)]
    assert (uploads / "abc").read_bytes() == b"file"
