# CMI – Change Management Interface

Flask + SQLite portal for submitting, assigning, approving and tracking change requests.

## Run

```
pip install -r requirements.txt
flask --app app db upgrade        # create the database (python app.py also does this)
flask --app app seed              # permission profiles, demo forms/workflows, demo core users
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

## Operations

```
flask --app app backup backups/          # database + uploads in one zip; safe while running
flask --app app restore backups/<file>   # stop the app first
flask --app app db migrate -m "change"   # after editing models.py, then: db upgrade
python -m pytest test_app.py
```

Test a restore regularly on a spare machine.

## Who can do what

Permissions come from editable profiles (Administration → Permission Profiles), not fixed roles. Seeded profiles: Requester, Viewer, Assigner, Assignee, Approver, Form Administrator, System Administrator.
