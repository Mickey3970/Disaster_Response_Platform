## Disaster Response Platform

A Flask-based web application to report incidents, classify urgency, and manage public safety alerts. It provides user registration/login, incident reporting with optional images and geolocation, basic NLP-based urgency detection, and an admin dashboard to verify reports and broadcast geo-targeted alerts.

### Features
- **User Accounts**: Register, login, and manage your own incident reports.
- **Incident Reporting**: Submit reports with title, description, optional coordinates, and image upload.
- **Urgency Classification**: Simple keyword-based NLP flags potentially urgent reports.
- **Admin Dashboard**: Verify/unverify reports, view statistics, and see reports on a map.
- **Public Alerts**: Admins can create red/orange/yellow alerts with optional location and radius.
- **JSON APIs**: Fetch active alerts publicly; admin-only endpoint for reports.

### Tech Stack
- **Backend**: Python, Flask, Flask-Login, Flask-SQLAlchemy
- **Database**: SQLite (default)
- **Templates**: Jinja2 (`templates/`), static assets in `static/`

### Repository Structure
```
app.py                # Flask app (routes, models, CLI bootstrap)
config.py             # Configuration (env-driven)
requirements.txt      # Python dependencies
templates/            # Jinja2 templates (HTML)
static/               # Static files (CSS, JS, uploads)
instance/             # SQLite databases (created at runtime)
```

---

## Getting Started

### Prerequisites
- Python 3.10+
- Git Bash or a terminal

### 1) Clone and enter the project
```bash
git clone <your-repo-url> SIH && cd SIH
```

### 2) Create and activate a virtual environment
```bash
python -m venv venv
source venv/Scripts/activate  # On Windows Git Bash
# On cmd.exe: venv\Scripts\activate.bat
# On PowerShell: venv\Scripts\Activate.ps1
```

### 3) Install dependencies
```bash
pip install -r requirements.txt
```

### 4) Configure environment variables
Create a `.env` file in the project root (same folder as `app.py`) with at least:
```bash
SECRET_KEY=change-me-in-production
DATABASE_URL=sqlite:///SIH.db
UPLOAD_FOLDER=static/uploads
# Optional (for Flask CLI):
FLASK_APP=app.py
FLASK_ENV=development
```

Notes:
- When using SQLite, the file will be created automatically. Default path is under the project root; `instance/` may also contain DB files.
- Ensure `static/uploads` exists; the app will attempt to create it on start.

### 5) Initialize the database and seed admin
Just run the app once; it will create tables and, if missing, an admin user:
```bash
python app.py
```

Seeded admin credentials (change after first login):
- Username: `admin`
- Password: `admin123`

### 6) Run the application
```bash
python app.py
```
The server starts in debug mode at `http://127.0.0.1:5000/`.

---

## Usage
- Visit `/register` to create a new user, then `/login`.
- Submit an incident at `/report` (logged-in users). Images are optional; allowed types: png, jpg, jpeg, gif.
- The dashboard at `/dashboard` shows your reports and active alerts.
- Admins can open `/admin` for stats, verification, and map; create alerts at `/admin/create_alert`.

### Urgency Classification
The app performs basic keyword matching over the report title+description to flag urgency. This is heuristic; verify manually for critical cases.

---

## API Endpoints

- `GET /api/alerts` — Returns all active alerts in JSON. Public.
- `GET /api/reports` — Returns reports with coordinates in JSON. Requires authentication and admin role.

Example response (alerts):
```json
[
  {
    "id": 1,
    "title": "Flood Warning",
    "message": "River level rising",
    "alert_type": "orange",
    "latitude": 12.97,
    "longitude": 77.59,
    "radius": 5.0,
    "created_at": "2025-10-17 14:35"
  }
]
```

---

## Configuration Reference (`config.Config`)
- `SECRET_KEY` — Flask session secret. Set via `SECRET_KEY` env; defaults to a dev key.
- `SQLALCHEMY_DATABASE_URI` — Set via `DATABASE_URL`; defaults to `sqlite:///SIH.db`.
- `SQLALCHEMY_TRACK_MODIFICATIONS` — Disabled by default.
- `UPLOAD_FOLDER` — Where uploads are stored. Defaults to `static/uploads`.
- `MAX_CONTENT_LENGTH` — 16MB upload limit.

---

## Troubleshooting
- "Module not found": Ensure the virtualenv is activated and `pip install -r requirements.txt` succeeded.
- "Database errors": Delete any stale `instance/*.db` if needed and restart; the app calls `db.create_all()` on boot.
- "Cannot upload image": Verify file type is allowed and `UPLOAD_FOLDER` exists and is writable.
- "Admin access denied": Log in with the seeded admin, or set an existing user’s `is_admin` to `1` in the DB.

---

## Security Notes
- Change `SECRET_KEY` and the seeded admin password before any real deployment.
- Do not run with `debug=True` in production.
- Consider moving to a managed database and adding proper role-based access control for production use.

---

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
No license specified. Add a `LICENSE` file if you plan to open-source.