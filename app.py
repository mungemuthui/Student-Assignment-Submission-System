#!/usr/bin/env python3
"""Student Assignment Submission System.

Standard library only (Python 3.9+).

Usage:
    python3 app.py create-lecturer "Dr Jane Doe" jane@uni.edu "a-strong-password"
    python3 app.py                 # starts the server on http://127.0.0.1:8000
"""
import hashlib
import hmac
import html
import http.server
import os
import re
import secrets
import sqlite3
import sys
import uuid
from contextlib import closing
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, quote, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SAS_DB", os.path.join(BASE_DIR, "sas.db"))
UPLOAD_DIR = os.environ.get("SAS_UPLOADS", os.path.join(BASE_DIR, "uploads"))
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".zip", ".txt", ".py", ".java", ".c", ".cpp", ".js"}
ALLOWED_TEXT = ", ".join(sorted(ALLOWED_EXTENSIONS))
PBKDF2_ITERATIONS = 200_000
SESSION_COOKIE = "sas_session"
DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
STUDENT_EMAIL_DOMAIN = "uni.edu"
STUDENT_MIN_PASSWORD_LENGTH = 12

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('student', 'lecturer')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lecturer_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    due_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL REFERENCES assignments(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    submitted_at TEXT NOT NULL,
    updated_at TEXT,
    edit_count INTEGER NOT NULL DEFAULT 0,
    is_late INTEGER NOT NULL DEFAULT 0
);
"""

ROUTES = [
    ("GET", r"/", "home"),
    ("GET", r"/register", "register_form"),
    ("POST", r"/register", "register_submit"),
    ("GET", r"/login", "login_form"),
    ("POST", r"/login", "login_submit"),
    ("POST", r"/logout", "logout"),
    ("GET", r"/assignments", "assignment_list"),
    ("GET", r"/assignments/(?P<aid>\d+)", "assignment_detail"),
    ("POST", r"/assignments/(?P<aid>\d+)/submit", "submit_assignment"),
    ("POST", r"/assignments/(?P<aid>\d+)/edit", "edit_submission"),
    ("GET", r"/my-submissions", "my_submissions"),
    ("GET", r"/lecturer/assignments/new", "new_assignment_form"),
    ("POST", r"/lecturer/assignments", "create_assignment"),
    ("GET", r"/lecturer/assignments/(?P<aid>\d+)/submissions", "view_submissions"),
    ("GET", r"/submissions/(?P<sid>\d+)/download", "download_submission"),
]


# ---------------------------------------------------------------- helpers

def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with closing(connect()) as conn:
        conn.executescript(SCHEMA)
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(submissions)").fetchall()}
        if "updated_at" not in cols:
            conn.execute("ALTER TABLE submissions ADD COLUMN updated_at TEXT")
        if "edit_count" not in cols:
            conn.execute("ALTER TABLE submissions ADD COLUMN edit_count INTEGER NOT NULL DEFAULT 0")
        conn.commit()


def now_iso():
    return datetime.now(timezone.utc).strftime(DATE_FMT)


def display_time(stored):
    dt = datetime.strptime(stored, DATE_FMT)
    return dt.strftime("%d %b %Y, %H:%M UTC")


def format_time_delta(due_iso, now_dt=None):
    if now_dt is None:
        now_dt = datetime.now(timezone.utc)
    due_dt = datetime.strptime(due_iso, DATE_FMT).replace(tzinfo=timezone.utc)
    seconds = int((due_dt - now_dt).total_seconds())
    if seconds >= 0:
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        mins = rem // 60
        if days >= 1:
            return f"Due in {days}d {hours}h"
        if hours >= 1:
            return f"Due in {hours}h {mins}m"
        return f"Due in {max(1, mins)}m"
    overdue = abs(seconds)
    days, rem = divmod(overdue, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    if days >= 1:
        return f"Overdue by {days}d {hours}h"
    if hours >= 1:
        return f"Overdue by {hours}h {mins}m"
    return f"Overdue by {max(1, mins)}m"


def esc(value):
    return html.escape(str(value), quote=True)


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex() + "$" + digest.hex()


def verify_password(password, stored):
    salt_hex, digest_hex = stored.split("$")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), PBKDF2_ITERATIONS)
    return hmac.compare_digest(digest.hex(), digest_hex)


def validate_account(name, email, password, student_registration=False):
    if not name:
        return "Please enter your name."
    if not EMAIL_RE.match(email):
        return "Please enter a valid email address."
    if student_registration and email.rsplit("@", 1)[1].lower() != STUDENT_EMAIL_DOMAIN:
        return "Please use your @uni.edu email address."
    min_password_length = STUDENT_MIN_PASSWORD_LENGTH if student_registration else 8
    if len(password) < min_password_length:
        return f"Password must be at least {min_password_length} characters."
    return ""


def sanitize_filename(name):
    return re.sub(r"[^A-Za-z0-9._\- ]", "_", os.path.basename(name))[:120]


def parse_multipart(content_type, body):
    """Return (fields, files). files maps name -> (filename, bytes)."""
    match = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', content_type)
    if not match:
        raise ValueError("multipart request has no boundary")
    boundary = (match.group(1) or match.group(2)).encode()
    fields, files = {}, {}
    for part in body.split(b"--" + boundary):
        if not part.startswith(b"\r\n"):
            continue  # preamble or closing marker
        part = part[2:]
        if part.endswith(b"\r\n"):
            part = part[:-2]
        head, sep, value = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        disposition = ""
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-disposition"):
                disposition = line.decode("utf-8", "replace")
        name_match = re.search(r';\s*name="([^"]*)"', disposition)
        if not name_match:
            continue
        file_match = re.search(r'filename="([^"]*)"', disposition)
        if file_match:
            files[name_match.group(1)] = (file_match.group(1), value)
        else:
            fields[name_match.group(1)] = value.decode("utf-8", "replace")
    return fields, files


# ---------------------------------------------------------------- HTML

CSS = """
body{font-family:system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1d1d1f}
header{background:#1f3a5f;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
header a{color:#fff;margin-left:14px;text-decoration:none}
nav{display:flex;align-items:center;flex-wrap:wrap}
nav form{display:inline;margin:0 0 0 14px}
nav button{background:none;border:1px solid #fff;color:#fff;border-radius:4px;padding:3px 10px;cursor:pointer;font:inherit}
main{max-width:960px;margin:24px auto;background:#fff;padding:24px 32px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
h1{margin-top:0;font-size:1.6rem}
label{display:block;margin:12px 0}
input,textarea{display:block;width:100%;box-sizing:border-box;padding:8px;margin-top:4px;border:1px solid #bbb;border-radius:4px;font:inherit}
textarea{min-height:120px}
button,.btn{background:#1f3a5f;color:#fff;border:0;border-radius:4px;padding:9px 16px;font:inherit;cursor:pointer;text-decoration:none;display:inline-block;margin-top:8px}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #e3e3e3;vertical-align:middle}
.notice{background:#e8f4ea;border-left:4px solid #2e7d32;padding:10px 14px;border-radius:4px}
.error{background:#fdecea;border-left:4px solid #c62828;padding:10px 14px;border-radius:4px}
.late{color:#b26a00;font-weight:600}
.muted{color:#666}
.small{font-size:.82rem}
.time-hint{display:block;font-size:.82rem;color:#555;margin-top:2px}
.badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:.82rem;font-weight:600;white-space:nowrap}
.badge-open{background:#e6f4ea;color:#1e6e34}
.badge-past-due{background:#fdecea;color:#b71c1c}
.badge-submitted{background:#e6f4ea;color:#1e6e34}
.badge-missing{background:#fff4e5;color:#9a5b00}
.badge-late{background:#fff4e5;color:#9a5b00}
.badge-edited{background:#e8f0fe;color:#174ea6;margin-left:6px}
.edit-box{background:#f8fafc;border:1px solid #d8e1eb;border-radius:6px;padding:14px 18px;margin-top:16px}
.summary-bar{display:flex;gap:12px;margin:12px 0 18px;flex-wrap:wrap}
.summary-card{flex:1;min-width:150px;background:#f8fafc;border:1px solid #d8e1eb;border-radius:6px;padding:12px 16px}
.summary-card span{font-size:.85rem;color:#555}
.summary-card strong{display:block;font-size:1.45rem;color:#1f3a5f;margin-top:2px}
.summary-card.card-submitted{border-left:4px solid #2e7d32}
.summary-card.card-pending{border-left:4px solid #ed6c02}
.summary-card.card-missing{border-left:4px solid #c62828}
"""


def error_block(message):
    return f'<p class="error">{esc(message)}</p>' if message else ""


def layout(title, body, user, msg="", err=""):
    if user:
        links = ['<a href="/assignments">Assignments</a>']
        if user["role"] == "student":
            links.append('<a href="/my-submissions">My submissions</a>')
        else:
            links.append('<a href="/lecturer/assignments/new">New assignment</a>')
        links.append(f"<span>{esc(user['name'])} ({esc(user['role'])})</span>")
        links.append('<form method="post" action="/logout"><button>Log out</button></form>')
    else:
        links = ['<a href="/login">Log in</a>', '<a href="/register">Register</a>']
    nav_html = "".join(links)
    notices = ""
    if msg:
        notices += f'<p class="notice">{esc(msg)}</p>'
    if err:
        notices += f'<p class="error">{esc(err)}</p>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} | Assignment Submission</title>
<style>{CSS}</style></head>
<body>
<header><strong>Assignment Submission System</strong><nav>{nav_html}</nav></header>
<main>{notices}<h1>{esc(title)}</h1>{body}</main>
</body></html>"""


def register_form_html(error="", name="", email=""):
    return f"""{error_block(error)}
<form method="post" action="/register">
<label>Full name <input name="name" value="{esc(name)}" maxlength="100" required></label>
<label>Email (@uni.edu) <input type="email" name="email" value="{esc(email)}" required></label>
<label>Password (at least 12 characters) <input type="password" name="password" minlength="12" required></label>
<button>Create account</button>
</form>
<p class="muted">Lecturer accounts are created by the system administrator.</p>"""


def login_form_html(error=""):
    return f"""{error_block(error)}
<form method="post" action="/login">
<label>Email <input type="email" name="email" required></label>
<label>Password <input type="password" name="password" required></label>
<button>Log in</button>
</form>
<p>No account yet? <a href="/register">Register as a student</a></p>"""


def assignment_form_html(error="", title="", description="", due_raw=""):
    return f"""{error_block(error)}
<form method="post" action="/lecturer/assignments">
<label>Title <input name="title" value="{esc(title)}" maxlength="200" required></label>
<label>Description and instructions <textarea name="description" required>{esc(description)}</textarea></label>
<label>Due date and time (UTC) <input type="datetime-local" name="due_at" value="{esc(due_raw)}" required></label>
<button>Create assignment</button>
</form>"""


def edited_badge_html(edit_count, updated_at=None):
    count = edit_count or 0
    if count > 0:
        return f'<span class="badge badge-edited">Edited {count}x</span>'
    if updated_at:
        return '<span class="badge badge-edited">Edited</span>'
    return ""


def student_assignments_html(rows):
    if not rows:
        return "<p>No assignments have been published yet.</p>"
    now = now_iso()
    now_dt = datetime.now(timezone.utc)
    items = []
    for a in rows:
        is_past_due = now > a["due_at"]
        deadline = ('<span class="badge badge-past-due">Past due</span>'
                    if is_past_due else '<span class="badge badge-open">Open</span>')
        countdown = format_time_delta(a["due_at"], now_dt)
        if a["mine"]:
            edited_tag = edited_badge_html(a["edit_count"], a["updated_at"])
            status = f'<span class="badge badge-submitted">Submitted</span>{edited_tag}'
            action = (f'<a href="/assignments/{a["id"]}">View</a>'
                      if is_past_due else f'<a href="/assignments/{a["id"]}">Edit submission</a>')
        elif is_past_due:
            status = '<span class="badge badge-past-due">Missing (Past due)</span>'
            action = f'<a href="/assignments/{a["id"]}">Submit late</a>'
        else:
            status = '<span class="badge badge-missing">Not submitted</span>'
            action = f'<a href="/assignments/{a["id"]}">Submit</a>'
        items.append(
            f'<tr><td><a href="/assignments/{a["id"]}">{esc(a["title"])}</a></td>'
            f'<td>{display_time(a["due_at"])}<span class="time-hint">{esc(countdown)}</span></td>'
            f'<td>{deadline}</td><td>{status}</td><td>{action}</td></tr>'
        )
    return ("<table><tr><th>Assignment</th><th>Due (UTC)</th><th>Deadline</th>"
            "<th>Your status</th><th>Action</th></tr>" + "".join(items) + "</table>")


def lecturer_assignments_html(rows):
    button = '<p><a class="btn" href="/lecturer/assignments/new">New assignment</a></p>'
    if not rows:
        return button + "<p>You have not created any assignments yet.</p>"
    now = now_iso()
    now_dt = datetime.now(timezone.utc)
    items = []
    for a in rows:
        deadline = ('<span class="badge badge-past-due">Past due</span>'
                    if now > a["due_at"] else '<span class="badge badge-open">Open</span>')
        countdown = format_time_delta(a["due_at"], now_dt)
        items.append(
            f'<tr><td>{esc(a["title"])}</td>'
            f'<td>{display_time(a["due_at"])}<span class="time-hint">{esc(countdown)}</span></td>'
            f'<td>{deadline}</td><td>{a["n"]}</td>'
            f'<td><a href="/lecturer/assignments/{a["id"]}/submissions">View submissions</a></td></tr>'
        )
    return (button + "<table><tr><th>Assignment</th><th>Due (UTC)</th><th>Window</th>"
            "<th>Submissions</th><th></th></tr>" + "".join(items) + "</table>")


def my_submissions_html(rows):
    if not rows:
        return "<p>There are no assignments yet.</p>"
    now = now_iso()
    now_dt = datetime.now(timezone.utc)
    submitted_count = 0
    pending_count = 0
    missing_count = 0
    items = []
    for r in rows:
        is_past_due = now > r["due_at"]
        countdown = format_time_delta(r["due_at"], now_dt)
        if r["sid"] is None:
            if is_past_due:
                missing_count += 1
                status = '<span class="badge badge-past-due">Not submitted &middot; Past due</span>'
                action = f'<a href="/assignments/{r["id"]}">Submit late</a>'
            else:
                pending_count += 1
                status = '<span class="badge badge-missing">Not submitted</span>'
                action = f'<a href="/assignments/{r["id"]}">Submit</a>'
            file_cell = "&mdash;"
            when = "&mdash;"
        else:
            submitted_count += 1
            base_badge = ('<span class="badge badge-late">Submitted late</span>'
                          if r["is_late"] else '<span class="badge badge-submitted">Submitted on time</span>')
            edited_badge = edited_badge_html(r["edit_count"], r["updated_at"])
            status = base_badge + edited_badge
            file_cell = f'<a href="/submissions/{r["sid"]}/download">{esc(r["original_name"])}</a>'
            when = display_time(r["submitted_at"])
            if r["updated_at"]:
                when += f'<br><span class="muted small">Last updated {display_time(r["updated_at"])}</span>'
            action = ('<span class="muted">Locked (past due)</span>'
                      if is_past_due else f'<a href="/assignments/{r["id"]}">Edit submission</a>')
        items.append(
            f'<tr><td><a href="/assignments/{r["id"]}">{esc(r["title"])}</a></td>'
            f'<td>{display_time(r["due_at"])}<span class="time-hint">{esc(countdown)}</span></td>'
            f"<td>{status}</td><td>{when}</td><td>{file_cell}</td>"
            f"<td>{r['attempts']}</td><td>{action}</td></tr>"
        )
    summary = (
        '<div class="summary-bar">'
        f'<div class="summary-card card-submitted"><span>Submitted</span><strong>{submitted_count}</strong></div>'
        f'<div class="summary-card card-pending"><span>Pending (Open)</span><strong>{pending_count}</strong></div>'
        f'<div class="summary-card card-missing"><span>Past Due / Missing</span><strong>{missing_count}</strong></div>'
        "</div>"
    )
    return (summary + "<table><tr><th>Assignment</th><th>Due (UTC)</th><th>Status</th><th>Submitted</th>"
            "<th>Latest file</th><th>Attempts</th><th>Action</th></tr>" + "".join(items) + "</table>")


def submissions_table_html(rows, show_student):
    if not rows:
        return "<p>No submissions yet.</p>"
    items = []
    for r in rows:
        keys = set(r.keys())
        edit_count = r["edit_count"] if "edit_count" in keys else 0
        updated_at = r["updated_at"] if "updated_at" in keys else None
        base_badge = ('<span class="badge badge-late">Late</span>'
                      if r["is_late"] else '<span class="badge badge-submitted">On time</span>')
        edited_badge = edited_badge_html(edit_count, updated_at)
        status = base_badge + edited_badge
        when = display_time(r["submitted_at"])
        if updated_at:
            when += f'<br><span class="muted small">Last updated {display_time(updated_at)}</span>'
        who = ""
        if show_student:
            who = f'<td>{esc(r["student_name"])}<br><span class="muted">{esc(r["student_email"])}</span></td>'
        items.append(
            f"<tr>{who}<td>{when}</td><td>{status}</td>"
            f'<td><a href="/submissions/{r["id"]}/download">{esc(r["original_name"])}</a></td>'
            f"<td>{r['size_bytes'] // 1024} KB</td></tr>"
        )
    student_head = "<th>Student</th>" if show_student else ""
    return (f"<table><tr>{student_head}<th>Submitted</th><th>Status</th><th>File</th><th>Size</th></tr>"
            + "".join(items) + "</table>")


# ---------------------------------------------------------------- server

class RequestTooLarge(Exception):
    pass


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "SAS/1.0"

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def dispatch(self, method):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        self.query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        try:
            for route_method, pattern, handler_name in ROUTES:
                if route_method != method:
                    continue
                match = re.fullmatch(pattern, path)
                if match:
                    kwargs = {k: int(v) for k, v in match.groupdict().items()}
                    getattr(self, handler_name)(**kwargs)
                    return
            self.deny(404, "Not found", "That page does not exist.")
        except RequestTooLarge:
            self.close_connection = True
            self.deny(413, "Upload too large", "Files must be 10 MB or smaller.")
        except ValueError as exc:
            self.deny(400, "Bad request", f"The request could not be read ({exc}).")
        except Exception as exc:  # keep the server running; log for the developer
            sys.stderr.write(f"Unhandled error on {method} {path}: {exc!r}\n")
            self.deny(500, "Server error", "Something went wrong. Please try again.")

    # ----- response helpers

    def send_page(self, title, body, status=200, headers=()):
        user = self.current_user()
        data = layout(title, body, user, self.query.get("msg", ""),
                      self.query.get("err", "")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def send_redirect(self, location, headers=()):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()

    def deny(self, status, title, message):
        self.send_page(title, f"<p>{esc(message)}</p>", status=status)

    def read_form(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD_BYTES + 64 * 1024:
            raise RequestTooLarge()
        body = self.rfile.read(length)
        ctype = self.headers.get("Content-Type", "")
        if ctype.startswith("multipart/form-data"):
            return parse_multipart(ctype, body)
        fields = {k: v[0] for k, v in
                  parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True).items()}
        return fields, {}

    def validate_upload(self, files):
        original, data = files.get("file", ("", b""))
        ext = os.path.splitext(original)[1].lower()
        if not original or not data:
            return None, None, None, "Please choose a file to upload."
        if ext not in ALLOWED_EXTENSIONS:
            return None, None, None, f"File type '{ext or 'none'}' is not allowed. Allowed types: {ALLOWED_TEXT}."
        if len(data) > MAX_UPLOAD_BYTES:
            return None, None, None, "File must be 10 MB or smaller."
        return original, ext, data, ""

    # ----- auth helpers

    def current_user(self):
        if hasattr(self, "_user_cache"):
            return self._user_cache
        user = None
        morsel = SimpleCookie(self.headers.get("Cookie", "")).get(SESSION_COOKIE)
        if morsel:
            with closing(connect()) as conn:
                user = conn.execute(
                    "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
                    (morsel.value,),
                ).fetchone()
        self._user_cache = user
        return user

    def require_user(self, role=None):
        user = self.current_user()
        if user is None:
            self.send_redirect("/login?err=" + quote("Please log in first."))
            return None
        if role and user["role"] != role:
            self.deny(403, "Forbidden", "You do not have access to this page.")
            return None
        return user

    def start_session(self, user_id):
        token = secrets.token_urlsafe(32)
        with closing(connect()) as conn:
            conn.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                         (token, user_id, now_iso()))
            conn.commit()
        return f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax"

    # ----- routes: home and accounts

    def home(self):
        self.send_redirect("/assignments" if self.current_user() else "/login")

    def register_form(self):
        if self.current_user():
            return self.send_redirect("/assignments")
        self.send_page("Create a student account", register_form_html())

    def register_submit(self):
        fields, _ = self.read_form()
        name = fields.get("name", "").strip()
        email = fields.get("email", "").strip().lower()
        password = fields.get("password", "")
        error = validate_account(name, email, password, student_registration=True)
        user_id = None
        if not error:
            try:
                with closing(connect()) as conn:
                    cur = conn.execute(
                        "INSERT INTO users (name, email, password_hash, role, created_at) "
                        "VALUES (?, ?, ?, 'student', ?)",
                        (name, email, hash_password(password), now_iso()),
                    )
                    conn.commit()
                    user_id = cur.lastrowid
            except sqlite3.IntegrityError:
                error = "An account with that email already exists."
        if error:
            return self.send_page("Create a student account",
                                  register_form_html(error, name, email), status=400)
        cookie = self.start_session(user_id)
        self.send_redirect("/assignments?msg=" + quote("Welcome! Your account is ready."),
                           [("Set-Cookie", cookie)])

    def login_form(self):
        if self.current_user():
            return self.send_redirect("/assignments")
        self.send_page("Log in", login_form_html())

    def login_submit(self):
        fields, _ = self.read_form()
        email = fields.get("email", "").strip().lower()
        password = fields.get("password", "")
        with closing(connect()) as conn:
            row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if row is None:
            hash_password(password)  # equalise timing with the real-account path
            valid = False
        else:
            valid = verify_password(password, row["password_hash"])
        if not valid:
            return self.send_page("Log in", login_form_html("Invalid email or password."),
                                  status=401)
        cookie = self.start_session(row["id"])
        self.send_redirect("/assignments", [("Set-Cookie", cookie)])

    def logout(self):
        morsel = SimpleCookie(self.headers.get("Cookie", "")).get(SESSION_COOKIE)
        if morsel:
            with closing(connect()) as conn:
                conn.execute("DELETE FROM sessions WHERE token = ?", (morsel.value,))
                conn.commit()
        clear = f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
        self.send_redirect("/login?msg=" + quote("You have been logged out."),
                           [("Set-Cookie", clear)])

    # ----- routes: assignments

    def assignment_list(self):
        user = self.require_user()
        if user is None:
            return
        with closing(connect()) as conn:
            if user["role"] == "lecturer":
                rows = conn.execute(
                    "SELECT a.*, (SELECT COUNT(*) FROM submissions s WHERE s.assignment_id = a.id) AS n "
                    "FROM assignments a WHERE a.lecturer_id = ? ORDER BY a.due_at",
                    (user["id"],),
                ).fetchall()
                body = lecturer_assignments_html(rows)
            else:
                rows = conn.execute(
                    """
                    SELECT a.*,
                           (SELECT COUNT(*) FROM submissions s
                             WHERE s.assignment_id = a.id AND s.student_id = ?) AS mine,
                           (SELECT MAX(COALESCE(s.edit_count, 0)) FROM submissions s
                             WHERE s.assignment_id = a.id AND s.student_id = ?) AS edit_count,
                           (SELECT MAX(s.updated_at) FROM submissions s
                             WHERE s.assignment_id = a.id AND s.student_id = ?) AS updated_at
                    FROM assignments a ORDER BY a.due_at
                    """,
                    (user["id"], user["id"], user["id"]),
                ).fetchall()
                body = student_assignments_html(rows)
        self.send_page("Assignments", body)

    def assignment_detail(self, aid):
        user = self.require_user()
        if user is None:
            return
        with closing(connect()) as conn:
            a = conn.execute(
                "SELECT a.*, u.name AS lecturer_name FROM assignments a "
                "JOIN users u ON u.id = a.lecturer_id WHERE a.id = ?", (aid,)
            ).fetchone()
            if a is None:
                return self.deny(404, "Not found", "That assignment does not exist.")
            own_rows = []
            if user["role"] == "student":
                own_rows = conn.execute(
                    "SELECT * FROM submissions WHERE assignment_id = ? AND student_id = ? "
                    "ORDER BY id DESC", (aid, user["id"])
                ).fetchall()
        is_past_due = now_iso() > a["due_at"]
        deadline_badge = ('<span class="badge badge-past-due">Past due</span>'
                          if is_past_due else '<span class="badge badge-open">Open</span>')
        countdown = format_time_delta(a["due_at"])
        description_html = esc(a["description"]).replace("\n", "<br>")
        body = (f'<p class="muted">Due {display_time(a["due_at"])} ({esc(countdown)}) &middot; '
                f'Set by {esc(a["lecturer_name"])} &nbsp;{deadline_badge}</p>'
                f'<div>{description_html}</div>')
        if user["role"] == "student":
            latest = own_rows[0] if own_rows else None
            if latest and not is_past_due:
                rev_note = (f" (edited {latest['edit_count']}x)"
                            if latest["edit_count"] else "")
                body += f"""
<div class="edit-box">
<h2>Edit your submission</h2>
<p>Current file: <strong>{esc(latest["original_name"])}</strong>{rev_note}. You can replace your submission before the UTC deadline ({display_time(a["due_at"])}).</p>
<p class="muted">Allowed file types: {esc(ALLOWED_TEXT)}. Maximum size 10 MB.</p>
<form method="post" action="/assignments/{aid}/edit" enctype="multipart/form-data">
<label>Replacement file <input type="file" name="file" required></label>
<button>Replace submission</button>
</form>
</div>"""
            elif latest and is_past_due:
                body += (
                    '<p class="error">The UTC deadline has passed. Your existing submission is '
                    'locked and can no longer be edited.</p>'
                )
            else:
                late_note = ('<p class="late">This assignment is past due; any new submission will be marked late.</p>'
                             if is_past_due else "")
                body += f"""
<h2>Submit your work</h2>
{late_note}
<p class="muted">Allowed file types: {esc(ALLOWED_TEXT)}. Maximum size 10 MB.</p>
<form method="post" action="/assignments/{aid}/submit" enctype="multipart/form-data">
<label>File <input type="file" name="file" required></label>
<button>Submit</button>
</form>"""
            body += f"""
<h2>Your submissions</h2>
{submissions_table_html(own_rows, show_student=False)}"""
        else:
            body += (f'<p><a class="btn" href="/lecturer/assignments/{aid}/submissions">'
                     "View submissions</a></p>")
        self.send_page(a["title"], body)

    def submit_assignment(self, aid):
        user = self.require_user("student")
        if user is None:
            return
        with closing(connect()) as conn:
            a = conn.execute("SELECT * FROM assignments WHERE id = ?", (aid,)).fetchone()
            if a is None:
                return self.deny(404, "Not found", "That assignment does not exist.")
            existing = conn.execute(
                "SELECT id FROM submissions WHERE assignment_id = ? AND student_id = ? LIMIT 1",
                (aid, user["id"]),
            ).fetchone()
        if existing and now_iso() > a["due_at"]:
            return self.send_redirect(
                f"/assignments/{aid}?err="
                + quote("Deadline has passed; existing submissions cannot be replaced.")
            )
        _, files = self.read_form()
        original, ext, data, error = self.validate_upload(files)
        if error:
            return self.send_redirect(f"/assignments/{aid}?err=" + quote(error))

        stored = f"{uuid.uuid4().hex}{ext}"
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        with open(os.path.join(UPLOAD_DIR, stored), "wb") as fh:
            fh.write(data)
        submitted_at = now_iso()
        is_late = 1 if submitted_at > a["due_at"] else 0
        with closing(connect()) as conn:
            conn.execute(
                "INSERT INTO submissions (assignment_id, student_id, original_name, stored_name, "
                "size_bytes, submitted_at, updated_at, edit_count, is_late) "
                "VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?)",
                (aid, user["id"], sanitize_filename(original), stored, len(data),
                 submitted_at, is_late),
            )
            conn.commit()
        msg = "Submitted late. Your work has been recorded." if is_late else "Assignment submitted."
        self.send_redirect("/my-submissions?msg=" + quote(msg))

    def edit_submission(self, aid):
        user = self.require_user("student")
        if user is None:
            return
        with closing(connect()) as conn:
            a = conn.execute("SELECT * FROM assignments WHERE id = ?", (aid,)).fetchone()
            if a is None:
                return self.deny(404, "Not found", "That assignment does not exist.")
            existing = conn.execute(
                "SELECT * FROM submissions WHERE assignment_id = ? AND student_id = ? "
                "ORDER BY id DESC LIMIT 1",
                (aid, user["id"]),
            ).fetchone()
        if now_iso() > a["due_at"]:
            return self.send_redirect(
                f"/assignments/{aid}?err="
                + quote("Cannot edit submission after the UTC deadline.")
            )
        if existing is None:
            return self.send_redirect(
                f"/assignments/{aid}?err="
                + quote("No existing submission found to edit.")
            )
        _, files = self.read_form()
        original, ext, data, error = self.validate_upload(files)
        if error:
            return self.send_redirect(f"/assignments/{aid}?err=" + quote(error))

        stored = f"{uuid.uuid4().hex}{ext}"
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        with open(os.path.join(UPLOAD_DIR, stored), "wb") as fh:
            fh.write(data)
        updated_at = now_iso()
        with closing(connect()) as conn:
            conn.execute(
                "UPDATE submissions SET original_name = ?, stored_name = ?, "
                "size_bytes = ?, submitted_at = ?, updated_at = ?, "
                "edit_count = COALESCE(edit_count, 0) + 1 WHERE id = ?",
                (sanitize_filename(original), stored, len(data),
                 updated_at, updated_at, existing["id"]),
            )
            conn.commit()
        old_path = os.path.join(UPLOAD_DIR, os.path.basename(existing["stored_name"]))
        if os.path.isfile(old_path):
            try:
                os.remove(old_path)
            except OSError:
                pass
        self.send_redirect("/my-submissions?msg=" + quote("Submission updated before the deadline."))

    def my_submissions(self):
        user = self.require_user("student")
        if user is None:
            return
        with closing(connect()) as conn:
            rows = conn.execute(
                """
                SELECT a.id, a.title, a.due_at, s.id AS sid, s.original_name, s.submitted_at,
                       s.updated_at, COALESCE(s.edit_count, 0) AS edit_count, s.is_late,
                       (SELECT COUNT(*) FROM submissions x
                         WHERE x.assignment_id = a.id AND x.student_id = ?) AS attempts
                FROM assignments a
                LEFT JOIN submissions s ON s.id = (
                    SELECT y.id FROM submissions y
                    WHERE y.assignment_id = a.id AND y.student_id = ?
                    ORDER BY y.id DESC LIMIT 1)
                ORDER BY a.due_at
                """,
                (user["id"], user["id"]),
            ).fetchall()
        self.send_page("My submissions", my_submissions_html(rows))

    # ----- routes: lecturer

    def new_assignment_form(self):
        if self.require_user("lecturer") is None:
            return
        self.send_page("New assignment", assignment_form_html())

    def create_assignment(self):
        user = self.require_user("lecturer")
        if user is None:
            return
        fields, _ = self.read_form()
        title = fields.get("title", "").strip()
        description = fields.get("description", "").strip()
        due_raw = fields.get("due_at", "").strip()
        error, due_at = "", ""
        if not title or len(title) > 200:
            error = "Please enter a title (up to 200 characters)."
        elif not description:
            error = "Please enter a description."
        else:
            try:
                due = datetime.strptime(due_raw, "%Y-%m-%dT%H:%M").replace(tzinfo=timezone.utc)
                due_at = due.strftime(DATE_FMT)
            except ValueError:
                error = "Please enter a valid due date and time."
        if error:
            return self.send_page("New assignment",
                                  assignment_form_html(error, title, description, due_raw),
                                  status=400)
        with closing(connect()) as conn:
            conn.execute(
                "INSERT INTO assignments (lecturer_id, title, description, due_at, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (user["id"], title, description, due_at, now_iso()),
            )
            conn.commit()
        self.send_redirect("/assignments?msg=" + quote("Assignment created."))

    def view_submissions(self, aid):
        user = self.require_user("lecturer")
        if user is None:
            return
        with closing(connect()) as conn:
            a = conn.execute("SELECT * FROM assignments WHERE id = ?", (aid,)).fetchone()
            if a is None:
                return self.deny(404, "Not found", "That assignment does not exist.")
            if a["lecturer_id"] != user["id"]:
                return self.deny(403, "Forbidden", "You can only view submissions for your own assignments.")
            rows = conn.execute(
                "SELECT s.*, u.name AS student_name, u.email AS student_email "
                "FROM submissions s JOIN users u ON u.id = s.student_id "
                "WHERE s.assignment_id = ? ORDER BY s.submitted_at DESC", (aid,)
            ).fetchall()
        count = len(rows)
        students = len({r["student_id"] for r in rows})
        summary = f"<p class=\"muted\">Due {display_time(a['due_at'])}. {count} submission(s) from {students} student(s).</p>"
        self.send_page(f"Submissions: {a['title']}",
                       summary + submissions_table_html(rows, show_student=True))

    def download_submission(self, sid):
        user = self.require_user()
        if user is None:
            return
        with closing(connect()) as conn:
            row = conn.execute(
                "SELECT s.*, a.lecturer_id FROM submissions s "
                "JOIN assignments a ON a.id = s.assignment_id WHERE s.id = ?", (sid,)
            ).fetchone()
        if row is None:
            return self.deny(404, "Not found", "That submission does not exist.")
        allowed = (
            (user["role"] == "student" and row["student_id"] == user["id"])
            or (user["role"] == "lecturer" and row["lecturer_id"] == user["id"])
        )
        if not allowed:
            return self.deny(403, "Forbidden", "You cannot access this file.")
        path = os.path.join(UPLOAD_DIR, os.path.basename(row["stored_name"]))
        if not os.path.isfile(path):
            return self.deny(404, "Not found", "The file is no longer available.")
        with open(path, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{row["original_name"]}"')
        self.end_headers()
        self.wfile.write(data)


# ---------------------------------------------------------------- CLI

def create_lecturer_cli(name, email, password):
    init_db()
    email = email.strip().lower()
    error = validate_account(name.strip(), email, password)
    if error:
        raise SystemExit(error)
    with closing(connect()) as conn:
        try:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, role, created_at) "
                "VALUES (?, ?, ?, 'lecturer', ?)",
                (name.strip(), email, hash_password(password), now_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise SystemExit(f"An account with email {email} already exists.")
    print(f"Lecturer account created for {email}.")


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "create-lecturer":
        return create_lecturer_cli(sys.argv[2], sys.argv[3], sys.argv[4])
    if len(sys.argv) > 1:
        raise SystemExit('Usage: python3 app.py [create-lecturer "Name" email password]')
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Serving on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()