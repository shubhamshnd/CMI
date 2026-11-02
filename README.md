# CMI – Change Management Interface

Flask + SQLite portal for submitting, assigning, approving and tracking change requests.

## Run

```
pip install -r requirements.txt
flask --app app db upgrade        # create the database (python app.py also does this)
flask --app app seed              # permission profiles, sections + their forms/workflows, demo core users
flask --app app run --debug       # development
python app.py                     # production: applies migrations, then serves on CMI_HOST:CMI_PORT (default 8080)
```

`seed` prints the demo users' password (or uses `CMI_SEED_PASSWORD`). Change or deactivate the demo users before going live.

## Settings

Put settings in `.env` next to `app.py` (copy `.env.example`; it is loaded automatically by `flask`, `waitress-serve` and the app). Real environment variables override `.env`. Never commit `.env`.

| Variable | Purpose |
|---|---|
| `CMI_SECRET_KEY` | **Required in production.** Signs sessions; without it sessions reset on restart. |
| `CMI_DATABASE_URL` | Default `sqlite:///cmi.db` (stored in `instance/`). |
| `CMI_UPLOAD_DIR` | Where attachments are stored. Default `instance/uploads` (not web-served). |
| `CMI_ALLOWED_DOMAINS` | Comma-separated email domains allowed to request a sign-in code, e.g. `corp.com`. Empty = any. |
| `CMI_MAIL_SERVER`, `CMI_MAIL_PORT`, `CMI_MAIL_TLS=1`, `CMI_MAIL_USER`, `CMI_MAIL_PASSWORD`, `CMI_MAIL_FROM` | SMTP for sign-in codes and notifications. Without a server, mail is printed to the console. |
| `CMI_SECURE_COOKIES=1` | Set when served over HTTPS. |
| `CMI_BASE_URL` | Address users open CMI at, e.g. `https://cmi.corp.com`. Used for links in emails sent by `remind-approvers` and `sla-check`. |
| `CMI_OFFICE_HOURS`, `CMI_OFFICE_DAYS`, `CMI_HOLIDAYS`, `CMI_UTC_OFFSET_MINUTES` | SLA office hours. Defaults: `09:30-18:30`, `Mon,Tue,Wed,Thu,Fri,Sat`, none, `330` (IST). Holidays: `2026-11-08,2026-12-25`. |

## Operations

```
flask --app app remind-approvers         # re-send HOD approval links unanswered for 2 days: schedule daily
flask --app app sla-check                # SLA warnings (75%) and escalations (100%): schedule every 15 minutes
flask --app app backup backups/          # database + uploads in one zip; safe while running
flask --app app restore backups/<file>   # stop the app first
flask --app app db migrate -m "change"   # after editing models.py, then: db upgrade
python -m pytest test_app.py
```

Test a restore regularly on a spare machine.

## Who can do what

Permissions come from editable profiles (Administration → Permission Profiles), not fixed roles. Seeded profiles: Requester, Viewer, Assigner, Assignee, Approver, Form Administrator, System Administrator.

The home page shows one tile per section (Administration → Sections): IT Requests, IT Incidents and Change Management are seeded. A section marked "core users only" (Change Management) is hidden from end users, who sign in with an email code, and they cannot raise its forms. Each section sets its ticket prefix (REQ-0012) and what "Closed" is shown as (Fulfilled, Resolved, Implemented).

Requests can be approved by the requester's HOD without a CMI account: give the form an "approver email" field and a workflow stage whose approver is "Email typed in" that field. The HOD gets a single-use link (valid 7 days) and decides on a page that needs no sign-in. CMI remembers each requester's HOD (editable on the user's page) and pre-fills it. Support groups (Administration → Support Groups) hold the IT team's queues: a form's default group receives its new tickets, and any member can take one.

SLA rules (Administration → SLA Rules) set respond and resolve targets per form, or per section and priority; the most specific rule wins. The clock counts office hours (or 24×7 for rules marked so) and pauses while a ticket waits for approval, is returned to the requester, or is On Hold. "Respond" is met when someone in IT other than the requester assigns, takes, updates or answers the ticket. Breaches are emailed to the team and to everyone with the "Receive SLA escalations" permission. Incident forms set their priority from the requester's answers (a form's Workflow tab → Automatic Priority). Core users can raise a linked change from any ticket ("Raise Change"); when the change is closed, the original ticket's team is told. The Change Calendar shows changes by their Planned Start.
