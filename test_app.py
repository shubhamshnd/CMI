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
    assert r.status_code == 302 and r.location == "/home", f"login failed for {email}"
    return c


def requester(mail, email="req@corp.com"):
    c = cmi.app.test_client()
    post(c, "/login/otp/send", email=email)
    code = re.search(r"\b(\d{6})\b", mail[-1][2]).group(1)
    assert post(c, "/login/otp/verify", code=code).location == "/home"
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


def test_login_page_never_redirects_and_offers_continue_when_signed_in(mail):
    admin = login("admin@cmi.local")
    for url in ("/login", "/login?mode=core", "/login?reset=1"):
        r = admin.get(url)
        assert r.status_code == 200 and "Continue to CMI" in r.get_data(as_text=True), url
    assert admin.get("/").status_code == 200
    page = cmi.app.test_client().get("/login").get_data(as_text=True)
    assert "Send Code" in page and "Continue to CMI" not in page  # signed-out users get the form


def test_home_lives_at_slash_home_and_slash_still_works(mail):
    admin = login("admin@cmi.local")  # login() already checks the post-login redirect goes to /home
    assert admin.get("/home").status_code == 200 and admin.get("/").status_code == 200
    page = admin.get("/login").get_data(as_text=True)
    assert 'href="/home"' in page  # "Continue to CMI" avoids the bare "/"


def test_form_link_survives_otp_login(mail):
    c = cmi.app.test_client()
    assert c.get("/tickets/new?form=ACCESS_REQUEST").location == "/login"
    post(c, "/login/otp/send", email="req@corp.com")
    code = re.search(r"\b(\d{6})\b", mail[-1][2]).group(1)
    assert post(c, "/login/otp/verify", code=code).location == "/tickets/new?form=ACCESS_REQUEST"
    assert c.get("/tickets/new?form=ACCESS_REQUEST").status_code == 200
    c.get("/logout")
    assert post(c, "/login/core", email="admin@cmi.local", password="pw-test-123").location == "/home"  # used once


def test_session_cookie_has_its_own_name(mail):
    c = cmi.app.test_client()
    post(c, "/login/core", email="admin@cmi.local", password="pw-test-123")
    assert c.get_cookie("cmi_session") is not None and c.get_cookie("session") is None


def test_otp_login_is_single_use(mail):
    c = cmi.app.test_client()
    post(c, "/login/otp/send", email="Req@Corp.com")
    code = re.search(r"\b(\d{6})\b", mail[-1][2]).group(1)
    assert post(c, "/login/otp/verify", code="000000" if code != "000000" else "111111").location == "/login"
    assert post(c, "/login/otp/verify", code=code).location == "/home"
    assert c.get("/").status_code == 200
    c2 = cmi.app.test_client()
    with c2.session_transaction() as s:
        s["otp_email"] = "req@corp.com"
    assert post(c2, "/login/otp/verify", code=code).location == "/login"


def test_show_otp_toggle_puts_code_on_screen_only_when_on(mail, monkeypatch):
    c = cmi.app.test_client()
    post(c, "/login/otp/send", email="off@corp.com")
    code = re.search(r"\b(\d{6})\b", mail[-1][2]).group(1)
    assert code not in c.get("/login").get_data(as_text=True)  # default: off
    monkeypatch.setitem(cmi.app.config, "SHOW_OTP", True)
    c = cmi.app.test_client()
    post(c, "/login/otp/send", email="on@corp.com")
    code = re.search(r"\b(\d{6})\b", mail[-1][2]).group(1)
    page = c.get("/login").get_data(as_text=True)
    assert f"your code is {code}" in page and "Testing mode" in page
    assert post(c, "/login/otp/verify", code=code).location == "/home"


def test_test_mode_never_opens_smtp(monkeypatch):
    def no_smtp(*a, **k):
        raise AssertionError("SMTP must not be used in test mode")
    monkeypatch.setattr(core.smtplib, "SMTP", no_smtp)
    monkeypatch.setitem(cmi.app.config, "MAIL_SERVER", "smtp.unreachable.example")
    monkeypatch.setitem(cmi.app.config, "SHOW_OTP", True)
    with cmi.app.app_context():
        core.send_mail("x@jsw.in", "subject", "body")  # printed to the console instead


def test_core_user_can_sign_in_with_code_but_test_mode_hides_it(mail, monkeypatch):
    c = cmi.app.test_client()
    post(c, "/login/otp/send", email="admin@cmi.local")
    code = re.search(r"\b(\d{6})\b", mail[-1][2]).group(1)
    assert post(c, "/login/otp/verify", code=code).location == "/home"
    assert c.get("/admin/users").status_code == 200  # same rights as with the password
    monkeypatch.setitem(cmi.app.config, "SHOW_OTP", True)
    c = cmi.app.test_client()
    post(c, "/login/otp/send", email="lead@cmi.local")
    code = re.search(r"\b(\d{6})\b", mail[-1][2]).group(1)
    page = c.get("/login").get_data(as_text=True)
    assert code not in page and "not shown here" in page


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


# ---------------------------------------------------------------- sections (home page tiles)

ACCESS = {"title": "VPN access", "subcategory": "VPN", "system": "Corp VPN", "justification": "Remote work",
          "hod_email": "hod@corp.com"}


def hod_link(mail, to="hod@corp.com"):
    """Path of the newest approval link mailed to the HOD."""
    body = next(m[2] for m in reversed(mail) if m[0] == to and "/approve/" in m[2])
    return re.search(r"(/approve/[\w-]+)", body).group(1)


def test_end_users_see_requests_and_incidents_but_not_change_management(mail):
    req = requester(mail)
    home = req.get("/home").get_data(as_text=True)
    assert "<h2>IT Requests</h2>" in home and "<h2>IT Incidents</h2>" in home and "<h2>Change Management</h2>" not in home
    assert "Normal Change" not in req.get("/tickets/new").get_data(as_text=True)  # catalogue hides it too
    assert req.get("/tickets/new?form=NORMAL_CHANGE").status_code == 403
    assert post(req, "/tickets/new?form=NORMAL_CHANGE", title="x").status_code == 403  # not just hidden: refused
    core_home = login("engineer@cmi.local").get("/home").get_data(as_text=True)
    assert all(f"<h2>{s}</h2>" in core_home for s in ("IT Requests", "IT Incidents", "Change Management"))


def test_ticket_numbered_and_closed_by_section(mail):
    req = requester(mail)
    tid = create(req, form="ACCESS_REQUEST", **ACCESS)
    page = req.get(f"/tickets/{tid}").get_data(as_text=True)
    assert f"REQ-{tid:04d}" in page
    admin = login("admin@cmi.local")
    assert f"REQ-{tid:04d}" in admin.get(f"/tickets?tab=all&q=REQ-{tid:04d}").get_data(as_text=True)
    post(cmi.app.test_client(), hod_link(mail), decision="approved")
    post(admin, f"/tickets/{tid}/status", status="Closed", rv=rv(tid))
    assert ">Fulfilled<" in admin.get(f"/tickets/{tid}").get_data(as_text=True)
    with cmi.app.app_context():
        assert ticket(tid).status == "Closed"  # the label is display only; filters and reports still see Closed


def test_admin_manages_sections(mail):
    admin = login("admin@cmi.local")
    assert post(admin, "/admin/sections/new", name="IT Requests", prefix="REQ").status_code == 400  # name taken
    assert post(admin, "/admin/sections/new", name="Problems", prefix="P1").status_code == 400  # letters only
    r = post(admin, "/admin/sections/new", name="Problems", prefix="prb", visible_to="core", closed_label="Solved",
             color="purple", icon="gear", position="4")
    assert r.status_code == 302
    with cmi.app.app_context():
        from models import Form, Section
        s = Section.query.filter_by(name="Problems").one()
        assert (s.prefix, s.core_only, s.closed_label) == ("PRB", True, "Solved")
        sid, fid = s.id, Form.query.filter_by(key="OTHER_INCIDENT").one().id
    page = admin.get(f"/admin/forms/{fid}").get_data(as_text=True)
    assert "Problems (core users only)" in page
    fields = [("f_" + k, v) for k, v in {"id": "description", "label": "What happened?", "type": "textarea"}.items()]
    admin.post(f"/admin/forms/{fid}", data=MultiDict([("_csrf", "test-token"), ("name", "Other Incident"),
                                                       ("section_id", str(sid)), ("action", "save"), *fields]))
    assert "Other Incident" not in requester(mail).get("/home").get_data(as_text=True)  # now core users only
    assert post(admin, f"/admin/sections/{sid}", action="delete").status_code == 302
    assert "Move this section" in admin.get(f"/admin/sections/{sid}").get_data(as_text=True)  # still has a form


# ---------------------------------------------------------------- HOD approval by email link

def test_hod_approves_from_email_link_without_signing_in(mail):
    req = requester(mail)
    tid = create(req, form="ACCESS_REQUEST", **ACCESS)
    with cmi.app.app_context():
        assert ticket(tid).status == "Pending Approval"  # the form starts approval on submit
    link = hod_link(mail)
    hod = cmi.app.test_client()  # nobody signed in
    assert "VPN access" in hod.get(link).get_data(as_text=True)
    assert "can no longer be used" in post(hod, link, decision="approved").get_data(as_text=True)
    with cmi.app.app_context():
        t = ticket(tid)
        assert t.status == "Approved" and t.approvals[0].approver.email == "hod@corp.com" and t.approvals[0].via_email
        assert TicketHistory.query.filter_by(ticket_id=tid, action="approved").one().actor.email == "hod@corp.com"
    assert any(m[0] == "req@corp.com" and "approved" in m[1] for m in mail)
    assert hod.get(link).status_code == 410  # works once


def test_hod_must_comment_to_reject_or_send_back(mail):
    tid = create(requester(mail), form="ACCESS_REQUEST", **ACCESS)
    hod, link = cmi.app.test_client(), hod_link(mail)
    assert "Add a comment" in post(hod, link, decision="returned").get_data(as_text=True)
    post(hod, link, decision="returned", comment="Which VPN profile?")
    with cmi.app.app_context():
        assert ticket(tid).status == "Returned"


def test_hod_email_rules_and_remembered(mail, monkeypatch):
    req = requester(mail)
    r = post(req, "/tickets/new?form=ACCESS_REQUEST", **{**ACCESS, "hod_email": "req@corp.com"})
    assert r.status_code == 200 and "not your own" in r.get_data(as_text=True)
    monkeypatch.setitem(cmi.app.config, "ALLOWED_EMAIL_DOMAINS", ["corp.com"])
    r = post(req, "/tickets/new?form=ACCESS_REQUEST", **{**ACCESS, "hod_email": "boss@gmail.com"})
    assert "company email address" in r.get_data(as_text=True)
    create(req, form="ACCESS_REQUEST", **ACCESS)
    page = req.get("/tickets/new?form=SOFTWARE_INSTALL").get_data(as_text=True)  # any form with a HOD field
    assert 'value="hod@corp.com"' in page and "Remembered from your last request" in page
    admin = login("admin@cmi.local")
    with cmi.app.app_context():
        from models import PermissionProfile
        requester_profile = str(PermissionProfile.query.filter_by(name="Requester").one().id)
    post(admin, f"/admin/users/{uid('req@corp.com')}", name="Req", hod_email="new.hod@corp.com", active="on",
         profiles=requester_profile)
    assert 'value="new.hod@corp.com"' in req.get("/tickets/new?form=ACCESS_REQUEST").get_data(as_text=True)


def test_resend_replaces_the_link_and_reminders_go_out(mail):
    from datetime import timedelta
    from models import TicketApproval, utcnow
    req = requester(mail)
    tid = create(req, form="ACCESS_REQUEST", **ACCESS)
    old = hod_link(mail)
    with cmi.app.app_context():
        aid = TicketApproval.query.filter_by(ticket_id=tid).one().id
    post(req, f"/tickets/{tid}/approvals/{aid}/resend")  # too soon: refused
    assert hod_link(mail) == old

    def age(**fields):
        with cmi.app.app_context():
            row = db.session.get(TicketApproval, aid)
            for k, v in fields.items():
                setattr(row, k, v)
            db.session.commit()
    age(link_sent_at=utcnow() - timedelta(hours=1))
    post(req, f"/tickets/{tid}/approvals/{aid}/resend")
    new = hod_link(mail)
    assert new != old and cmi.app.test_client().get(old).status_code == 410
    assert cmi.app.test_client().get(new).status_code == 200
    age(link_expires=utcnow() - timedelta(minutes=1))
    assert "expired" in cmi.app.test_client().get(new).get_data(as_text=True)
    age(link_sent_at=utcnow() - timedelta(days=3))
    result = cmi.app.test_cli_runner().invoke(args=["remind-approvers"])
    assert "Sent 1 reminder" in result.output
    assert mail[-1][0] == "hod@corp.com" and mail[-1][1].startswith("Reminder:")
    assert cmi.app.test_client().get(hod_link(mail)).status_code == 200  # the reminder carries a fresh link


# ---------------------------------------------------------------- support groups

INCIDENT = {"title": "Outlook keeps crashing", "subcategory": "Email", "affected": "Just me", "can_work": "No",
            "description": "Since this morning"}


def test_support_group_queue_and_take(mail):
    tid = create(requester(mail), form="IT_ISSUE", **INCIDENT)
    with cmi.app.app_context():
        assert ticket(tid).group.name == "Service Desk" and ticket(tid).assignee is None
    assert any(m[0] == "engineer@cmi.local" and "Service Desk queue" in m[1] for m in mail)
    eng = login("engineer@cmi.local")
    assert f"INC-{tid:04d}" in eng.get("/tickets?tab=group").get_data(as_text=True)
    assert post(login("lead@cmi.local"), f"/tickets/{tid}/take", rv=rv(tid)).status_code == 403  # not a member
    post(eng, f"/tickets/{tid}/take", rv=rv(tid))
    with cmi.app.app_context():
        assert ticket(tid).assignee.email == "engineer@cmi.local"
    assert post(login("assigner@cmi.local"), f"/tickets/{tid}/take", rv=rv(tid)).status_code == 403  # already taken


def test_admin_creates_support_group(mail):
    admin = login("admin@cmi.local")
    assert post(admin, "/admin/groups/new", name="Service Desk").status_code == 400  # name taken
    assert post(admin, "/admin/groups/new", name="Applications", members=str(uid("lead@cmi.local"))).status_code == 302
    assert "Neha Lead" in admin.get("/admin/groups").get_data(as_text=True)


# ---------------------------------------------------------------- SLA

def test_office_hours_maths():
    from datetime import date, datetime, time, timedelta
    import sla
    cal = sla.Calendar(time(9, 30), time(18, 30), {0, 1, 2, 3, 4, 5}, set(), timedelta(minutes=330))  # Mon-Sat, IST
    mon = date(2026, 11, 2)
    assert mon.weekday() == 0
    utc = lambda d, h, m=0: datetime.combine(d, time(h, m))
    assert sla.working_minutes(utc(mon, 4), utc(mon, 5), cal) == 60  # 09:30-10:30 IST
    sat = mon + timedelta(days=5)
    assert sla.working_minutes(utc(sat, 12), utc(mon + timedelta(days=7), 5), cal) == 120  # Sat 17:30-18:30 + Mon 9:30-10:30
    assert sla.add_working(utc(sat, 12), 120, cal) == utc(mon + timedelta(days=7), 5)  # Sunday skipped
    cal.holidays.add(mon + timedelta(days=7))
    assert sla.working_minutes(utc(sat, 12), utc(mon + timedelta(days=7), 5), cal) == 60  # holiday Monday
    assert sla.working_minutes(utc(mon, 4), utc(mon, 5), cal, round_the_clock=True) == 60
    assert (sla.parse_duration("2d", cal), sla.parse_duration("30m", cal), sla.parse_duration("1d", cal, True)) == (1080, 30, 1440)
    with pytest.raises(ValueError):
        sla.parse_duration("soon", cal)


def test_clock_pauses_while_waiting():
    from datetime import datetime, timedelta
    from types import SimpleNamespace as NS
    import sla
    t0 = datetime(2026, 11, 2, 4, 0)
    at = lambda m: t0 + timedelta(minutes=m)
    t = NS(created_at=t0, history=[NS(field="status", at=at(10), new="Pending Approval"),
                                   NS(field="status", at=at(70), new="In Progress"), NS(field="status", at=at(100), new="Closed")])
    assert sla.running_intervals(t, at(200)) == [(t0, at(10)), (at(70), at(100))]


def test_incident_priority_from_answers_and_sla_shown(mail):
    req = requester(mail)
    tid = create(req, form="IT_ISSUE", **{**INCIDENT, "affected": "Whole site / many users"})
    with cmi.app.app_context():
        assert ticket(tid).priority == "Critical"  # whole site + cannot work
    eng = login("engineer@cmi.local")
    page = eng.get(f"/tickets/{tid}").get_data(as_text=True)
    assert "SLA · Respond" in page and "SLA · Resolve" in page
    post(eng, f"/tickets/{tid}/take", rv=rv(tid))
    with cmi.app.app_context():
        assert ticket(tid).responded_at  # taking it is the response
    tid2 = create(req, form="IT_ISSUE", **{**INCIDENT, "can_work": "Yes, with a workaround"})
    with cmi.app.app_context():
        assert ticket(tid2).priority == "Low"


def test_sla_check_warns_then_escalates_once(mail):
    from datetime import timedelta
    tid = create(requester(mail), form="IT_ISSUE", **{**INCIDENT, "affected": "Whole site / many users"})  # 15m / 4h, 24x7

    def age(minutes):
        with cmi.app.app_context():
            ticket(tid).created_at -= timedelta(minutes=minutes)
            db.session.commit()
    run = lambda: cmi.app.test_cli_runner().invoke(args=["sla-check"]).output
    age(30)  # respond (15 min) breached; resolve at 30 / 240 min: fine
    del mail[:]
    assert "Sent 1 SLA alert" in run()
    to = {m[0] for m in mail}
    assert {"assigner@cmi.local", "engineer@cmi.local"} <= to  # the Service Desk group: nobody is assigned yet
    assert "admin@cmi.local" in to  # System Administrator has sla.escalate
    assert all("respond breached" in m[1] for m in mail)
    assert "Sent 0" in run()  # each alert goes out once
    age(180)  # resolve now at 210 / 240 min: warning, not escalated
    del mail[:]
    assert "Sent 1 SLA alert" in run()
    assert mail and all("resolve" in m[1] and "breaching" in m[1] for m in mail) and "admin@cmi.local" not in {m[0] for m in mail}


def test_on_hold_pauses_the_clock(mail):
    tid = create(requester(mail), form="IT_ISSUE", **INCIDENT)
    eng = login("engineer@cmi.local")
    post(eng, f"/tickets/{tid}/status", status="On Hold", rv=rv(tid))
    assert "clock paused while on hold" in eng.get(f"/tickets/{tid}").get_data(as_text=True)


def test_raise_change_from_incident(mail):
    req = requester(mail)
    iid = create(req, form="NETWORK_ISSUE", **{**INCIDENT, "subcategory": "Wi-Fi", "location": "Tower B"})
    assert "Raise Change" not in req.get(f"/tickets/{iid}").get_data(as_text=True)  # end users can't raise changes
    eng = login("engineer@cmi.local")
    assert "Raise Change" in eng.get(f"/tickets/{iid}").get_data(as_text=True)
    url = f"/tickets/new?form=EMERGENCY_CHANGE&from={iid}&link=change_for"
    assert f'value="INC-{iid:04d}"' in eng.get(url).get_data(as_text=True)  # incident number carried over
    r = post(eng, url, title="Replace Wi-Fi controller", incident=f"INC-{iid:04d}", systems="Network",
             reason="Controller failing", planned_start="2026-11-20T22:00", rollback_plan="Old controller")
    cid = int(r.location.rsplit("/", 1)[1])
    with cmi.app.app_context():
        lk = TicketLink.query.filter_by(from_ticket_id=cid).one()
        assert (lk.to_ticket_id, lk.kind) == (iid, "change_for")
    del mail[:]
    post(login("admin@cmi.local"), f"/tickets/{cid}/status", status="Closed", rv=rv(cid))
    assert any(m[0] == "engineer@cmi.local" and "You can now resolve" in m[2] for m in mail)  # the incident's group


def test_change_calendar(mail):
    eng = login("engineer@cmi.local")
    create(eng, form="NORMAL_CHANGE", title="Core switch firmware", systems="Network", reason="Bug fix", risk="Medium",
           planned_start="2026-11-20T22:00", planned_end="2026-11-20T23:00", rollback_plan="Previous image",
           hod_email="hod@corp.com")
    assert "Core switch firmware" in eng.get("/changes/calendar?month=2026-11").get_data(as_text=True)
    assert "Core switch firmware" not in eng.get("/changes/calendar?month=2026-12").get_data(as_text=True)
    assert requester(mail).get("/changes/calendar").status_code == 403


def test_admin_edits_sla_rules(mail):
    admin = login("admin@cmi.local")
    with cmi.app.app_context():
        from models import Section, SlaRule
        sid = Section.query.filter_by(name="IT Incidents").one().id
        before = SlaRule.query.count()
    form = lambda respond: MultiDict([("_csrf", "test-token"), ("r_where", f"section:{sid}"), ("r_priority", "High"),
                                      ("r_respond", respond), ("r_resolve", "1d"), ("r_clock", "office")])
    with admin.session_transaction() as s:
        s["_csrf"] = "test-token"
    assert "write times like" in admin.post("/admin/sla", data=form("soon"), follow_redirects=True).get_data(as_text=True)
    with cmi.app.app_context():
        assert SlaRule.query.count() == before  # nothing saved
    admin.post("/admin/sla", data=form("2h"))
    with cmi.app.app_context():
        (r,) = SlaRule.query.all()
        assert (r.section_id, r.priority, r.respond_minutes, r.resolve_minutes) == (sid, "High", 120, 540)
    assert 'value="2h"' in admin.get("/admin/sla").get_data(as_text=True)


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
