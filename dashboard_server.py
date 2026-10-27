"""
Optional central dashboard for 3EN Inspector Team.
Run with: python dashboard_server.py
Environment:
  INSPECTOR_OWNER_USER (default: owner)
  INSPECTOR_OWNER_PASSWORD (required on first setup; use a strong secret)
  INSPECTOR_API_KEY (required for desktop report ingestion)
  INSPECTOR_SECRET_KEY (random secret for Flask sessions)
  INSPECTOR_DB (optional SQLite path)
This server accepts report metadata/results only from clients presenting the API key.
Do not expose publicly without HTTPS and network-level protections.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("INSPECTOR_DB", APP_DIR / "inspector_dashboard.sqlite3"))
app = Flask(__name__)
app.secret_key = os.environ.get("INSPECTOR_SECRET_KEY") or secrets.token_hex(32)
API_KEY = os.environ.get("INSPECTOR_API_KEY", "")
OWNER_USER = os.environ.get("INSPECTOR_OWNER_USER", "owner")
OWNER_PASSWORD = os.environ.get("INSPECTOR_OWNER_PASSWORD", "")
DEPUTY_PASSWORD = os.environ.get("INSPECTOR_DEPUTY_PASSWORD", "")
TEAM_PASSWORD = os.environ.get("INSPECTOR_TEAM_PASSWORD", "")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('owner','deputy','team','inspector','viewer')),
 can_view INTEGER NOT NULL DEFAULT 1,
 can_ingest INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS inspection_sessions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 code_hash TEXT UNIQUE NOT NULL,
 display_code TEXT NOT NULL,
 created_by TEXT NOT NULL,
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 used_at TEXT,
 status TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 session_id TEXT NOT NULL,
 computer_label TEXT NOT NULL DEFAULT 'Unspecified',
 created_at TEXT NOT NULL,
 summary TEXT NOT NULL DEFAULT '',
 payload TEXT NOT NULL,
 submitted_by TEXT NOT NULL DEFAULT 'desktop-client'
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 actor TEXT NOT NULL,
 action TEXT NOT NULL,
 created_at TEXT NOT NULL
);
"""

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as con:
        con.executescript(SCHEMA)
        schema = con.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
        if schema and "'deputy'" not in (schema['sql'] or ''):
            con.execute('ALTER TABLE users RENAME TO users_old')
            con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','deputy','team','inspector','viewer')), can_view INTEGER NOT NULL DEFAULT 1, can_ingest INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)")
            con.execute('INSERT INTO users SELECT id,username,password_hash,role,can_view,can_ingest,created_at FROM users_old')
            con.execute('DROP TABLE users_old')
        row = con.execute("SELECT id FROM users WHERE role='owner' LIMIT 1").fetchone()
        if not row:
            if not OWNER_PASSWORD:
                print("FIRST RUN: set INSPECTOR_OWNER_PASSWORD to a strong password before logging in.")
                # Create owner only when a password is configured; allow first-run setup below.
            else:
                con.execute("INSERT INTO users(username,password_hash,role,can_view,can_ingest,created_at) VALUES(?,?,?,?,?,?)",
                            (OWNER_USER, generate_password_hash(OWNER_PASSWORD), "owner", 1, 1, now()))

def log_action(actor, action):
    with db() as con:
        con.execute("INSERT INTO audit(actor,action,created_at) VALUES(?,?,?)", (actor, action[:240], now()))

def current_user():
    name = session.get("username")
    if not name:
        return None
    with db() as con:
        return con.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def permission_required(field):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user or (user["role"] != "owner" and not user[field]):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco

BASE = """
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>3EN INSPECTOR TEAM</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#090909;color:#eee;font:15px Segoe UI,Arial,sans-serif}
header{padding:22px 5vw;background:#111;border-bottom:1px solid #6f171d;display:flex;justify-content:space-between;gap:16px;align-items:center}
h1{margin:0;color:#ff3948;font-size:22px}small,.muted{color:#aaa}.wrap{max-width:1180px;margin:28px auto;padding:0 18px}
nav a,.btn{color:#fff;text-decoration:none;background:#6f171d;border:0;border-radius:7px;padding:9px 13px;display:inline-block;margin:3px;cursor:pointer}
.card{background:#141414;border:1px solid #292929;border-radius:12px;padding:18px;margin:12px 0;overflow:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.metric{font-size:27px;color:#ff5260;font-weight:700}
input,select,textarea{background:#090909;border:1px solid #444;color:#fff;border-radius:6px;padding:10px;margin:5px 0;width:100%}
label{display:block;color:#bbb;margin-top:8px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #303030;vertical-align:top}th{color:#ff6a74}
.notice{padding:10px;background:#2a1517;border-radius:7px;margin:10px 0}.danger{color:#ff727c}pre{white-space:pre-wrap;overflow-wrap:anywhere}
</style><header><div><h1>3EN INSPECTOR TEAM</h1><small>Central reports dashboard · by ROITH</small></div>
<nav>{% if user %}<a href="{{ url_for('home') }}">Dashboard</a><a href="{{ url_for('reports') }}">Reports</a>{% if user['role'] in ('owner','inspector') %}<a href="{{ url_for('sessions_page') }}">Sessions</a>{% endif %}{% if user['role']=='owner' %}<a href="{{ url_for('users_page') }}">Staff & permissions</a><a href="{{ url_for('audit_page') }}">Event log</a>{% endif %}<a href="{{ url_for('logout') }}">Logout</a>{% endif %}</nav></header>
<div class="wrap">{% for msg in get_flashed_messages() %}<div class="notice">{{ msg }}</div>{% endfor %}{{ body|safe }}</div></html>
"""

def page(body, **context):
    return render_template_string(BASE, body=render_template_string(body, **context), user=current_user())

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            owners = con.execute("SELECT COUNT(*) n FROM users WHERE role='owner'").fetchone()["n"]
            if not owners and username == OWNER_USER and OWNER_PASSWORD and password == OWNER_PASSWORD:
                con.execute("INSERT INTO users(username,password_hash,role,can_view,can_ingest,created_at) VALUES(?,?,?,?,?,?)",
                            (OWNER_USER, generate_password_hash(OWNER_PASSWORD), "owner", 1, 1, now()))
                user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not user and 2 <= len(username) <= 64:
                role_passwords = [("deputy", DEPUTY_PASSWORD), ("team", TEAM_PASSWORD)]
                matched_role = next((role for role, secret in role_passwords if secret and hmac.compare_digest(password, secret)), None)
                safe_name = username.replace(" ", "_")
                # Owner is provisioned only from the configured owner account/password.
                if matched_role:
                    try:
                        con.execute("INSERT INTO users(username,password_hash,role,can_view,can_ingest,created_at) VALUES(?,?,?,?,?,?)", (safe_name, generate_password_hash(password), matched_role, 1 if matched_role in ("owner","deputy") else 0, 1 if matched_role == "owner" else 0, now()))
                        user = con.execute("SELECT * FROM users WHERE username=?", (safe_name,)).fetchone()
                        log_action(safe_name, "created account with role " + matched_role)
                    except sqlite3.IntegrityError:
                        user = con.execute("SELECT * FROM users WHERE username=?", (safe_name,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["username"] = user["username"]
                log_action(username, "login")
                return redirect(request.args.get("next") or url_for("home"))
        flash("Login failed. Check credentials and server environment configuration.")
    return page("""<div class="card" style="max-width:440px;margin:5vh auto"><h2>Staff login</h2><p class="muted">Owner account is initialized from environment variables.</p><form method="post"><label>Username</label><input name="username" required autocomplete="username"><label>Password</label><input name="password" type="password" required autocomplete="current-password"><button class="btn">Sign in</button></form></div>""")

@app.route("/logout")
def logout():
    name = session.get("username","unknown")
    session.clear()
    log_action(name, "logout")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    user=current_user()
    with db() as con:
        can_see_reports = user["role"] in ("owner", "deputy", "inspector") or bool(user["can_view"])
        count=con.execute("SELECT COUNT(*) n FROM reports").fetchone()["n"] if can_see_reports else 0
        recent=con.execute("SELECT id,session_id,computer_label,created_at,summary FROM reports ORDER BY id DESC LIMIT 8").fetchall() if can_see_reports else []
        staff=con.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] if user["role"]=="owner" else None
    return page("""<div class="grid"><div class="card"><div class="muted">Saved reports</div><div class="metric">{{ count }}</div></div><div class="card"><div class="muted">Signed in as</div><div class="metric" style="font-size:20px">{{ user['username'] }}</div><div>{{ user['role'] }}</div></div>{% if staff is not none %}<div class="card"><div class="muted">Staff accounts</div><div class="metric">{{ staff }}</div></div>{% endif %}</div><div class="card"><h2>Recent reports</h2>{% if recent %}<table><tr><th>ID</th><th>Session</th><th>Computer label</th><th>Received (UTC)</th><th>Summary</th></tr>{% for r in recent %}<tr><td><a class="btn" href="{{ url_for('report_detail', report_id=r['id']) }}">#{{ r['id'] }}</a></td><td>{{ r['session_id'] }}</td><td>{{ r['computer_label'] }}</td><td>{{ r['created_at'] }}</td><td>{{ r['summary'] }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No reports received yet. Configure the desktop client to send an explicitly approved report.</p>{% endif %}</div>""",count=count,user=user,staff=staff,recent=recent)

@app.route("/sessions", methods=["GET", "POST"])
@login_required
def sessions_page():
    user = current_user()
    if user["role"] not in ("owner", "deputy", "team", "inspector"):
        abort(403)
    if request.method == "POST":
        code = secrets.token_urlsafe(6).replace("-", "").replace("_", "")[:8].upper()
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        created = datetime.now(timezone.utc)
        expires = created.timestamp() + 2 * 60 * 60
        expires_at = datetime.fromtimestamp(expires, timezone.utc).isoformat(timespec="seconds")
        with db() as con:
            con.execute("INSERT INTO inspection_sessions(code_hash,display_code,created_by,created_at,expires_at,status) VALUES(?,?,?,?,?,?)",
                        (code_hash, code, user["username"], now(), expires_at, "open"))
        log_action(user["username"], "created two-hour inspection session")
        return page("""<div class="card"><h2>Session created</h2><p>Give this code to the device owner to enter in the desktop app:</p><div class="metric">{{ code }}</div><p class="muted">One report can be submitted with this code. It expires in two hours. Keep it private.</p><a class="btn" href="{{ url_for('sessions_page') }}">Back to sessions</a></div>""", code=code)
    with db() as con:
        rows = con.execute("SELECT display_code,created_by,created_at,expires_at,used_at,status FROM inspection_sessions WHERE created_by=? ORDER BY id DESC LIMIT 100", (user["username"],)).fetchall() if user["role"] == "team" else con.execute("SELECT display_code,created_by,created_at,expires_at,used_at,status FROM inspection_sessions ORDER BY id DESC LIMIT 100").fetchall()
    return page("""<div class="card"><h2>Inspection sessions</h2><p class="muted">Create a short-lived code for a consent-based scan. The code permits one report only.</p><form method="post"><button class="btn">Create session code (2 hours)</button></form></div><div class="card"><table><tr><th>Code</th><th>Created by</th><th>Created (UTC)</th><th>Expires (UTC)</th><th>Used (UTC)</th><th>Status</th></tr>{% for r in rows %}<tr><td>{{ r['display_code'] }}</td><td>{{ r['created_by'] }}</td><td>{{ r['created_at'] }}</td><td>{{ r['expires_at'] }}</td><td>{{ r['used_at'] or '—' }}</td><td>{{ r['status'] }}</td></tr>{% endfor %}</table></div>""", rows=rows)

@app.post("/api/v1/session-report")
def ingest_session_report():
    if not request.is_json:
        abort(415)
    if len(request.get_data()) > 1_000_000:
        abort(413)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400)
    code = str(data.get("session_code", "")).strip().upper()
    if len(code) < 6 or len(code) > 20:
        abort(401)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    with db() as con:
        session_row = con.execute("SELECT * FROM inspection_sessions WHERE code_hash=?", (code_hash,)).fetchone()
        if not session_row or session_row["status"] != "open":
            abort(401, "Invalid or already-used session code.")
        if datetime.fromisoformat(session_row["expires_at"]) < datetime.now(timezone.utc):
            con.execute("UPDATE inspection_sessions SET status='expired' WHERE id=?", (session_row["id"],))
            abort(410, "Session code expired.")
        payload = data.get("report", {})
        if not isinstance(payload, (dict, list)):
            abort(400, "report must be a JSON object or array.")
        label = str(data.get("computer_label", "Unspecified"))[:100]
        summary = str(data.get("summary", ""))[:1000]
        cur = con.execute("INSERT INTO reports(session_id,computer_label,created_at,summary,payload,submitted_by) VALUES(?,?,?,?,?,?)",
                          (session_row["display_code"], label, now(), summary, json.dumps(payload, ensure_ascii=False), "session:" + session_row["created_by"]))
        report_id = cur.lastrowid
        con.execute("UPDATE inspection_sessions SET status='used',used_at=? WHERE id=?", (now(), session_row["id"]))
    log_action("session:" + session_row["display_code"], "received report #" + str(report_id))
    return {"ok": True, "report_id": report_id}, 201

@app.route("/reports")
@login_required
def reports():
    if current_user()["role"] not in ("owner", "deputy", "inspector") and not current_user()["can_view"]:
        abort(403)
    with db() as con:
        rows=con.execute("SELECT id,session_id,computer_label,created_at,summary,submitted_by FROM reports ORDER BY id DESC LIMIT 250").fetchall()
    return page("""<div class="card"><h2>Reports</h2><table><tr><th>ID</th><th>Session</th><th>Computer</th><th>UTC time</th><th>Summary</th><th>Submitted by</th>{% if current_user()['role']=='owner' %}<th>Action</th>{% endif %}</tr>{% for r in rows %}<tr><td><a href="{{ url_for('report_detail',report_id=r['id']) }}">#{{ r['id'] }}</a></td><td>{{ r['session_id'] }}</td><td>{{ r['computer_label'] }}</td><td>{{ r['created_at'] }}</td><td>{{ r['summary'] }}</td><td>{{ r['submitted_by'] }}</td>{% if current_user()['role']=='owner' %}<td><form method="post" action="{{ url_for('delete_report',report_id=r['id']) }}" onsubmit="return confirm('Delete this report permanently?')"><button class="btn danger" type="submit">Delete</button></form></td>{% endif %}</tr>{% endfor %}</table></div>""",rows=rows)

@app.post("/reports/<int:report_id>/delete")
@login_required
def delete_report(report_id):
    actor = current_user()
    if actor["role"] != "owner":
        abort(403)
    with db() as con:
        row = con.execute("SELECT id FROM reports WHERE id=?", (report_id,)).fetchone()
        if not row:
            abort(404)
        con.execute("DELETE FROM reports WHERE id=?", (report_id,))
    log_action(actor["username"], "deleted report #" + str(report_id))
    flash("Report deleted.")
    return redirect(url_for("reports"))

@app.route("/reports/<int:report_id>")
@login_required
def report_detail(report_id):
    if current_user()["role"] not in ("owner", "deputy", "inspector") and not current_user()["can_view"]:
        abort(403)
    with db() as con:
        r=con.execute("SELECT * FROM reports WHERE id=?",(report_id,)).fetchone()
    if not r: abort(404)
    try: payload=json.dumps(json.loads(r["payload"]),indent=2,ensure_ascii=False)
    except Exception: payload=r["payload"]
    return page("""<div class="card"><h2>Report #{{ r['id'] }}</h2><p><b>Session:</b> {{ r['session_id'] }} · <b>Computer:</b> {{ r['computer_label'] }}</p><p><b>Received:</b> {{ r['created_at'] }} UTC</p><p>{{ r['summary'] }}</p><pre>{{ payload }}</pre><a class="btn" href="{{ url_for('reports') }}">Back</a></div>""",r=r,payload=payload)

@app.route("/staff", methods=["GET","POST"])
@login_required
def users_page():
    actor=current_user()
    if actor["role"]!="owner": abort(403)
    if request.method=="POST":
        action=request.form.get("action")
        if action=="create":
            username=request.form.get("username","").strip()
            password=request.form.get("password","")
            role=request.form.get("role","viewer")
            if len(username)<3 or len(password)<12 or role not in ("deputy","team","inspector","viewer"):
                flash("Use username >= 3 chars, password >= 12 chars, and a valid non-owner role.")
            else:
                try:
                    with db() as con:
                        con.execute("INSERT INTO users(username,password_hash,role,can_view,can_ingest,created_at) VALUES(?,?,?,?,?,?)",
                                    (username,generate_password_hash(password),role,1 if request.form.get("can_view") else 0,1 if request.form.get("can_ingest") and role=="inspector" else 0,now()))
                    log_action(actor["username"],"created staff account "+username)
                    flash("Staff account created.")
                except sqlite3.IntegrityError: flash("That username already exists.")
        elif action=="permissions":
            uid=request.form.get("user_id","")
            with db() as con:
                target=con.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
                if target and target["role"]!="owner":
                    con.execute("UPDATE users SET can_view=?,can_ingest=? WHERE id=?",
                                (1 if request.form.get("can_view") else 0,1 if request.form.get("can_ingest") and target["role"]=="inspector" else 0,uid))
                    log_action(actor["username"],"updated permissions for "+target["username"])
                    flash("Permissions updated.")
        elif action=="role":
            uid=request.form.get("user_id","")
            role=request.form.get("role","viewer")
            if role not in ("deputy","team","inspector","viewer"):
                flash("Invalid role.")
            else:
                with db() as con:
                    target=con.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
                    if target and target["role"]!="owner":
                        con.execute("UPDATE users SET role=?,can_ingest=CASE WHEN ?='inspector' THEN can_ingest ELSE 0 END WHERE id=?",
                                    (role,role,uid))
                        log_action(actor["username"],"changed role for "+target["username"]+" to "+role)
                        flash("Role updated.")
        elif action=="delete":
            uid=request.form.get("user_id","")
            with db() as con:
                target=con.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
                if target and target["role"]!="owner" and target["username"]!=actor["username"]:
                    con.execute("DELETE FROM users WHERE id=?",(uid,))
                    log_action(actor["username"],"deleted staff account "+target["username"])
                    flash("Staff account deleted.")
        return redirect(url_for("users_page"))
    with db() as con: users=con.execute("SELECT * FROM users ORDER BY role,username").fetchall()
    return page("""<div class="card"><h2>Create staff account</h2><form method="post"><input type="hidden" name="action" value="create"><label>Username</label><input name="username" minlength="3" required><label>Temporary password (12+ characters)</label><input name="password" type="password" minlength="12" required><label>Role</label><select name="role"><option value="deputy">Deputy / نائب</option><option value="team">Team</option><option value="inspector">Inspector</option><option value="viewer">Viewer</option></select><label><input style="width:auto" type="checkbox" name="can_view" checked> View reports</label><label><input style="width:auto" type="checkbox" name="can_ingest"> Permission flag: submit reports (inspector role only)</label><button class="btn">Create account</button></form></div><div class="card"><h2>Accounts & permissions</h2>{% for u in users %}<form method="post" class="card"><input type="hidden" name="user_id" value="{{ u['id'] }}"><b>{{ u['username'] }}</b> · {{ u['role'] }} {% if u['role']=='owner' %}<p class="muted">Owner permissions are fixed.</p>{% else %}<label>Role</label><select name="role" form="role-{{ u['id'] }}"><option value="viewer" {% if u['role']=='viewer' %}selected{% endif %}>Viewer</option><option value="inspector" {% if u['role']=='inspector' %}selected{% endif %}>Inspector (can create sessions)</option></select><input type="hidden" name="action" value="permissions"><label><input style="width:auto" type="checkbox" name="can_view" {% if u['can_view'] %}checked{% endif %}> View reports</label><label><input style="width:auto" type="checkbox" name="can_ingest" {% if u['can_ingest'] %}checked{% endif %}> Submit reports (future authenticated client accounts)</label><button class="btn">Save permissions</button></form><form method="post" id="role-{{ u['id'] }}"><input type="hidden" name="action" value="role"><input type="hidden" name="user_id" value="{{ u['id'] }}"><label>Change role</label><select name="role"><option value="viewer" {% if u['role']=='viewer' %}selected{% endif %}>Viewer</option><option value="inspector" {% if u['role']=='inspector' %}selected{% endif %}>Inspector</option></select><button class="btn">Save role</button></form><form method="post"><input type="hidden" name="action" value="delete"><input type="hidden" name="user_id" value="{{ u['id'] }}"><button class="btn danger">Delete account</button></form>{% endif %}</form>{% endfor %}</div>""",users=users)

@app.route("/events")
@login_required
def audit_page():
    if current_user()["role"]!="owner": abort(403)
    with db() as con: rows=con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 300").fetchall()
    return page("""<div class="card"><h2>Owner event log</h2><table><tr><th>UTC time</th><th>Actor</th><th>Action</th></tr>{% for r in rows %}<tr><td>{{ r['created_at'] }}</td><td>{{ r['actor'] }}</td><td>{{ r['action'] }}</td></tr>{% endfor %}</table></div>""",rows=rows)

@app.post("/api/v1/reports")
def ingest_report():
    # API key is kept server-side and never displayed in the dashboard.
    if not API_KEY: abort(503, "Report ingestion is disabled: INSPECTOR_API_KEY is not configured.")
    supplied=request.headers.get("X-Inspector-Key","")
    if not hmac.compare_digest(supplied,API_KEY): abort(401)
    if not request.is_json: abort(415)
    data=request.get_json(silent=True)
    if not isinstance(data,dict): abort(400)
    # Bound request size and avoid accepting arbitrary file contents.
    if len(request.get_data()) > 1_000_000: abort(413)
    session_id=str(data.get("session_id","")).strip()[:100]
    if not session_id: abort(400,"session_id is required")
    label=str(data.get("computer_label","Unspecified"))[:100]
    summary=str(data.get("summary",""))[:1000]
    payload=data.get("report",{})
    if not isinstance(payload,(dict,list)): abort(400,"report must be JSON object or array")
    serialized=json.dumps(payload,ensure_ascii=False)
    with db() as con:
        cur=con.execute("INSERT INTO reports(session_id,computer_label,created_at,summary,payload,submitted_by) VALUES(?,?,?,?,?,?)",
                        (session_id,label,now(),summary,serialized,"desktop-client"))
        report_id=cur.lastrowid
    log_action("desktop-client","received report #"+str(report_id))
    return {"ok":True,"report_id":report_id},201

@app.get("/health")
def health():
    return {"ok":True,"service":"3EN Inspector Team dashboard"}

@app.errorhandler(403)
def forbidden(_): return page('<div class="card"><h2 class="danger">Access denied</h2><p>Your account does not have permission for this page.</p></div>'),403

init_db()

if __name__ == "__main__":
    if not OWNER_PASSWORD:
        print("WARNING: INSPECTOR_OWNER_PASSWORD is unset; configure it before first owner login.")
    if not API_KEY:
        print("INFO: report ingestion disabled until INSPECTOR_API_KEY is configured.")
    app.run(host=os.environ.get("INSPECTOR_HOST","127.0.0.1"),port=int(os.environ.get("PORT","5000")),debug=False)
