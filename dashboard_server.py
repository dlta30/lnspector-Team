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

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('owner','inspector','viewer')),
 can_view INTEGER NOT NULL DEFAULT 1,
 can_ingest INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL
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
<nav>{% if user %}<a href="{{ url_for('home') }}">Dashboard</a><a href="{{ url_for('reports') }}">Reports</a>{% if user['role']=='owner' %}<a href="{{ url_for('users_page') }}">Staff & permissions</a><a href="{{ url_for('audit_page') }}">Event log</a>{% endif %}<a href="{{ url_for('logout') }}">Logout</a>{% endif %}</nav></header>
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
        count=con.execute("SELECT COUNT(*) n FROM reports").fetchone()["n"]
        recent=con.execute("SELECT id,session_id,computer_label,created_at,summary FROM reports ORDER BY id DESC LIMIT 8").fetchall()
        staff=con.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] if user["role"]=="owner" else None
    return page("""<div class="grid"><div class="card"><div class="muted">Saved reports</div><div class="metric">{{ count }}</div></div><div class="card"><div class="muted">Signed in as</div><div class="metric" style="font-size:20px">{{ user['username'] }}</div><div>{{ user['role'] }}</div></div>{% if staff is not none %}<div class="card"><div class="muted">Staff accounts</div><div class="metric">{{ staff }}</div></div>{% endif %}</div><div class="card"><h2>Recent reports</h2>{% if recent %}<table><tr><th>ID</th><th>Session</th><th>Computer label</th><th>Received (UTC)</th><th>Summary</th></tr>{% for r in recent %}<tr><td><a class="btn" href="{{ url_for('report_detail', report_id=r['id']) }}">#{{ r['id'] }}</a></td><td>{{ r['session_id'] }}</td><td>{{ r['computer_label'] }}</td><td>{{ r['created_at'] }}</td><td>{{ r['summary'] }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No reports received yet. Configure the desktop client to send an explicitly approved report.</p>{% endif %}</div>""",count=count,user=user,staff=staff,recent=recent)

@app.route("/reports")
@permission_required("can_view")
def reports():
    with db() as con:
        rows=con.execute("SELECT id,session_id,computer_label,created_at,summary,submitted_by FROM reports ORDER BY id DESC LIMIT 250").fetchall()
    return page("""<div class="card"><h2>Reports</h2><table><tr><th>ID</th><th>Session</th><th>Computer</th><th>UTC time</th><th>Summary</th><th>Submitted by</th></tr>{% for r in rows %}<tr><td><a href="{{ url_for('report_detail',report_id=r['id']) }}">#{{ r['id'] }}</a></td><td>{{ r['session_id'] }}</td><td>{{ r['computer_label'] }}</td><td>{{ r['created_at'] }}</td><td>{{ r['summary'] }}</td><td>{{ r['submitted_by'] }}</td></tr>{% endfor %}</table></div>""",rows=rows)

@app.route("/reports/<int:report_id>")
@permission_required("can_view")
def report_detail(report_id):
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
            if len(username)<3 or len(password)<12 or role not in ("inspector","viewer"):
                flash("Use username >= 3 chars, password >= 12 chars, and a non-owner role.")
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
    return page("""<div class="card"><h2>Create staff account</h2><form method="post"><input type="hidden" name="action" value="create"><label>Username</label><input name="username" minlength="3" required><label>Temporary password (12+ characters)</label><input name="password" type="password" minlength="12" required><label>Role</label><select name="role"><option value="inspector">Inspector</option><option value="viewer">Viewer</option></select><label><input style="width:auto" type="checkbox" name="can_view" checked> View reports</label><label><input style="width:auto" type="checkbox" name="can_ingest"> Permission flag: submit reports (inspector role only)</label><button class="btn">Create account</button></form></div><div class="card"><h2>Accounts & permissions</h2>{% for u in users %}<form method="post" class="card"><input type="hidden" name="user_id" value="{{ u['id'] }}"><b>{{ u['username'] }}</b> · {{ u['role'] }} {% if u['role']=='owner' %}<p class="muted">Owner permissions are fixed.</p>{% else %}<input type="hidden" name="action" value="permissions"><label><input style="width:auto" type="checkbox" name="can_view" {% if u['can_view'] %}checked{% endif %}> View reports</label><label><input style="width:auto" type="checkbox" name="can_ingest" {% if u['can_ingest'] %}checked{% endif %}> Submit reports (future authenticated client accounts)</label><button class="btn">Save permissions</button></form><form method="post"><input type="hidden" name="action" value="delete"><input type="hidden" name="user_id" value="{{ u['id'] }}"><button class="btn danger">Delete account</button></form>{% endif %}</form>{% endfor %}</div>""",users=users)

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
