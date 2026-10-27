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
import urllib.request
import urllib.error
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

APP_DIR = Path(__file__).resolve().parent
# Hosted platforms may use an ephemeral app filesystem. Prefer a mounted
# persistent disk when available (Render convention: /var/data).
# INSPECTOR_DB can override this path; local development uses APP_DIR.
PERSISTENT_DATA_DIR = Path('/var/data')
DEFAULT_DB_PATH = (PERSISTENT_DATA_DIR / 'inspector_dashboard.sqlite3') if PERSISTENT_DATA_DIR.is_dir() else (APP_DIR / 'inspector_dashboard.sqlite3')
DB_PATH = Path(os.environ.get('INSPECTOR_DB', str(DEFAULT_DB_PATH)))
app = Flask(__name__)
app.secret_key = os.environ.get("INSPECTOR_SECRET_KEY") or secrets.token_hex(32)
API_KEY = os.environ.get("INSPECTOR_API_KEY", "")
OWNER_USER = os.environ.get("INSPECTOR_OWNER_USER", "owner")
OWNER_PASSWORD = os.environ.get("INSPECTOR_OWNER_PASSWORD", "")
DEPUTY_PASSWORD = os.environ.get("INSPECTOR_DEPUTY_PASSWORD", "")
TEAM_PASSWORD = os.environ.get("INSPECTOR_TEAM_PASSWORD", "")
GITHUB_ACTIONS_TOKEN = os.environ.get("GITHUB_ACTIONS_TOKEN", "").strip()
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "dlta30/lnspector-Team")
PUBLIC_DASHBOARD_URL = os.environ.get("PUBLIC_DASHBOARD_URL", "").strip().rstrip("/")

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
 target_label TEXT NOT NULL DEFAULT '',
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
        session_columns = {row["name"] for row in con.execute("PRAGMA table_info(inspection_sessions)").fetchall()}
        if "target_label" not in session_columns:
            con.execute("ALTER TABLE inspection_sessions ADD COLUMN target_label TEXT NOT NULL DEFAULT ''")
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


def notify_discord(report_id, session_code, computer, summary):
    webhook = os.environ.get('DISCORD_WEBHOOK_URL', '').strip()
    if not webhook.startswith('https://discord.com/api/webhooks/') and not webhook.startswith('https://discordapp.com/api/webhooks/'):
        return False
    message = {'username': '3eN Inspector Team', 'embeds': [{'title': 'New inspection report', 'description': (summary or 'Report received')[:1000], 'color': 16076879, 'fields': [{'name': 'Report ID', 'value': str(report_id), 'inline': True}, {'name': 'Session', 'value': str(session_code)[:100], 'inline': True}, {'name': 'Device', 'value': str(computer)[:100], 'inline': True}], 'footer': {'text': '3eN INSPECTOR TEAM'}}], 'allowed_mentions': {'parse': []}}
    req = urllib.request.Request(webhook, data=json.dumps(message).encode('utf-8'), headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            return 200 <= response.status < 300
    except Exception as exc:
        print('Discord notification failed:', type(exc).__name__)
        return False

def trigger_session_build(code):
    if not GITHUB_ACTIONS_TOKEN or not PUBLIC_DASHBOARD_URL.startswith("https://"):
        return False, "اضبط GITHUB_ACTIONS_TOKEN وPUBLIC_DASHBOARD_URL في إعدادات الاستضافة."
    url = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/actions/workflows/build-windows-client.yml/dispatches"
    body = json.dumps({"ref": os.environ.get("GITHUB_DEFAULT_BRANCH", "main"), "inputs": {"session_code": code, "dashboard_url": PUBLIC_DASHBOARD_URL}}).encode()
    req = urllib.request.Request(url, data=body, headers={"Accept":"application/vnd.github+json","Authorization":"Bearer "+GITHUB_ACTIONS_TOKEN,"X-GitHub-Api-Version":"2022-11-28","Content-Type":"application/json","User-Agent":"3eN-Inceptor-Dashboard"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            return response.status in (201, 204), "تم إرسال طلب بناء ملف الفحص."
    except urllib.error.HTTPError as exc:
        print("GitHub build dispatch failed:", exc.code)
        return False, "تعذر تشغيل البناء تلقائياً؛ تحقق من صلاحيات توكن GitHub وإعدادات الاستضافة."
    except Exception as exc:
        print("GitHub build dispatch failed:", type(exc).__name__)
        return False, "تعذر الاتصال بخدمة بناء ملف الفحص."

def github_api_json(path):
    if not GITHUB_ACTIONS_TOKEN: return None
    url = "https://api.github.com/repos/" + GITHUB_REPOSITORY + path
    req = urllib.request.Request(url, headers={"Accept":"application/vnd.github+json","Authorization":"Bearer "+GITHUB_ACTIONS_TOKEN,"X-GitHub-Api-Version":"2022-11-28","User-Agent":"3eN-Inceptor-Dashboard"})
    with urllib.request.urlopen(req, timeout=12) as response: return json.loads(response.read().decode("utf-8"))

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
<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>3eN INCEPTOR</title>
<style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800;900&display=swap');:root{color-scheme:dark;--red:#ff304f;--muted:#9ca3b5}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 10% 0%,#30101d,transparent 38%),radial-gradient(ellipse at 100% 20%,#151d38,transparent 34%),#08090e;color:#f5f6fb;font:14px Inter,Segoe UI,Tahoma,Arial,sans-serif;direction:rtl;text-align:right}header{position:sticky;top:0;z-index:5;padding:18px 4vw;background:rgba(8,9,14,.9);backdrop-filter:blur(16px);border-bottom:1px solid #49202b;display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap}h1{margin:0;color:#fff;font-size:20px;font-weight:900;letter-spacing:1.5px}h1:before{content:'◈';color:var(--red);margin-right:10px}small,.muted{color:var(--muted)}.wrap{max-width:1240px;margin:30px auto;padding:0 20px}nav{display:flex;gap:6px;flex-wrap:wrap}nav a,.btn{color:#fff;text-decoration:none;background:linear-gradient(135deg,#b71f3b,#6e1427);border:1px solid #ffffff19;border-radius:10px;padding:10px 14px;display:inline-block;margin:3px;cursor:pointer;font:600 12px Inter,Arial;transition:.15s}nav a:hover,.btn:hover{filter:brightness(1.2);transform:translateY(-1px)}.card{background:linear-gradient(145deg,#181a24f5,#0d0e15f5);border:1px solid #ffffff12;border-radius:18px;padding:22px;margin:14px 0;overflow:auto;box-shadow:0 12px 36px #0003}h2{margin:0 0 14px;font-size:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}.metric{font-size:32px;color:#ff4965;font-weight:900;margin:8px 0}input,select,textarea{background:#0b0c12;border:1px solid #343746;color:#fff;border-radius:10px;padding:12px;margin:6px 0;width:100%;outline:none}input:focus,select:focus,textarea:focus{border-color:#ff4965;box-shadow:0 0 0 3px #ff49651f}label{display:block;color:#c0c4d2;margin-top:10px}table{width:100%;border-collapse:collapse;min-width:620px}th,td{text-align:right;padding:13px;border-bottom:1px solid #ffffff12;vertical-align:top}th{color:#ff7084;font-size:11px;text-transform:uppercase;letter-spacing:.7px}.notice{padding:13px 16px;background:#9d163033;border:1px solid #ff49652e;border-radius:12px;margin:12px 0}.danger{color:#ff727c}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b0c12;padding:16px;border-radius:12px;border:1px solid #ffffff12}a{color:#ff8091}@media(max-width:650px){header{padding:16px}.wrap{padding:0 12px;margin:18px auto}.card{padding:16px}h1{font-size:16px}}</style><style>body{background:#07080d;background-image:radial-gradient(ellipse at 12% -10%,#35101d 0,transparent 42%),radial-gradient(ellipse at 95% 8%,#171326 0,transparent 35%);letter-spacing:.1px}header{padding:16px clamp(16px,4vw,56px);border-bottom:1px solid #ffffff12;background:rgba(7,8,13,.88)}h1{font-size:18px;letter-spacing:2px}h1:before{content:'◉';display:inline-grid;place-items:center;width:31px;height:31px;margin-right:11px;border-radius:50%;border:2px solid #ff3656;color:#ff3656;font-size:18px;box-shadow:0 0 18px #ff304f25}.wrap{max-width:1440px;margin:26px auto;padding:0 26px}nav a{background:#11131c;border:1px solid #ffffff12;color:#c9cbd5;border-radius:9px;padding:10px 13px}nav a:hover{background:#27121a;border-color:#612236;color:#fff}.card{background:linear-gradient(145deg,rgba(21,23,33,.96),rgba(12,13,19,.98));border:1px solid #ffffff10;border-radius:17px;padding:24px;box-shadow:0 16px 45px #0002}.metric{color:#ff536d;font-size:35px;letter-spacing:-1px}.grid{gap:16px}.grid>.card{position:relative;min-height:124px}.grid>.card:after{content:'';position:absolute;left:0;top:18px;bottom:18px;width:3px;border-radius:3px;background:#ff304f}h2{font-size:19px;letter-spacing:-.3px}label{font-size:12px;font-weight:600}input,select,textarea{background:#090a10;border-color:#292c38}input:focus,select:focus,textarea:focus{border-color:#a52b43;box-shadow:0 0 0 3px #ff496511}.btn{background:linear-gradient(135deg,#d42b49,#7b172d);border-radius:9px;padding:11px 15px;box-shadow:0 5px 18px #ff304f10}.btn:hover{box-shadow:0 7px 22px #ff304f20}table{border-collapse:separate;border-spacing:0;width:100%;min-width:620px}th{background:#14151e;color:#ff8192;font-size:10px}td{color:#d4d6e0;font-size:12px}tr:hover td{background:#ffffff04}.notice{background:#24111a;border-color:#542033;color:#f5dbe1}.danger{color:#ff7688}pre{color:#d8dbe6;line-height:1.65}.login-shell{max-width:1040px;margin:6vh auto;display:grid;grid-template-columns:1.1fr .9fr;overflow:hidden;border:1px solid #ffffff14;border-radius:24px;background:#0d0e15;box-shadow:0 25px 90px #0008}.login-hero{padding:42px;background:radial-gradient(ellipse at 5% 0%,#461423,transparent 65%),#10111a;display:flex;flex-direction:column;justify-content:space-between;min-height:420px}.login-form{padding:40px 36px}.eyebrow{color:#ff7187;font-size:11px;font-weight:800;letter-spacing:2px}.hero-mark{font-size:64px;font-weight:900;letter-spacing:-5px;color:#fff}.hero-mark span{color:#ff3656}.login-form h2{font-size:26px;margin:8px 0}.login-form .btn{width:100%;margin:18px 0 0;padding:13px}.status-pill{display:inline-flex;align-items:center;gap:8px;border:1px solid #ffffff14;background:#161822;padding:9px 12px;border-radius:99px;color:#b9bdcb;font-size:11px;width:max-content}.status-pill i{width:7px;height:7px;border-radius:50%;background:#ff526c;display:inline-block}@media(max-width:720px){.login-shell{grid-template-columns:1fr;margin:18px}.login-hero{min-height:220px;padding:26px}.login-form{padding:26px}.hero-mark{font-size:48px}.wrap{padding:0 14px;margin:20px auto}.card{padding:17px}}</style><header><div><h1>3eN INCEPTOR</h1><small>منصة الجلسات والتقارير</small></div>
<nav>{% if user %}<a href="{{ url_for('home') }}">الرئيسية</a>{% if user['role']=='owner' %}<a href="{{ url_for('reports') }}">التقارير</a>{% endif %}{% if user['role'] in ('owner','deputy','inspector') %}<a href="{{ url_for('sessions_page') }}">الجلسات</a>{% endif %}{% if user['role']=='owner' %}<a href="{{ url_for('users_page') }}">الصلاحيات</a><a href="{{ url_for('audit_page') }}">سجل الأحداث</a>{% endif %}<a href="{{ url_for('logout') }}">تسجيل الخروج</a>{% endif %}</nav></header>
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
    return page("""<div class="login-shell"><section class="login-hero"><div><div class="eyebrow">SECURITY OPERATIONS PLATFORM</div><div class="hero-mark">3eN<span>.</span></div><h2>INCEPTOR</h2><p class="muted">جلسات الفحص, secure reports, and team access — in one place.</p></div><div class="status-pill"><i></i> PRIVATE TEAM ACCESS</div></section><section class="login-form"><div class="eyebrow">WELCOME BACK</div><h2>Sign in</h2><p class="muted">Use your team credentials to continue.</p><form method="post"><label>Username</label><input name="username" required autocomplete="username" placeholder="Enter username"><label>Password</label><input name="password" type="password" required autocomplete="current-password" placeholder="Enter password"><button class="btn">Sign in securely &rarr;</button></form><p class="muted" style="font-size:11px;margin-top:24px">Access is controlled by your assigned role.</p></section></div>""")

@app.route("/logout")
def logout():
    name = session.get("username","unknown")
    session.clear()
    log_action(name, "logout")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    user = current_user()
    can_see_reports = user["role"] == "owner"
    with db() as con:
        total_sessions = con.execute("SELECT COUNT(*) n FROM inspection_sessions").fetchone()["n"]
        pending_sessions = con.execute("SELECT COUNT(*) n FROM inspection_sessions WHERE status='open' AND expires_at>?", (now(),)).fetchone()["n"]
        completed_reports = con.execute("SELECT COUNT(*) n FROM reports").fetchone()["n"] if can_see_reports else 0
        recent_reports = con.execute("SELECT r.id,r.session_id,r.computer_label,r.created_at,r.summary,s.target_label FROM reports r LEFT JOIN inspection_sessions s ON s.display_code=r.session_id ORDER BY r.id DESC LIMIT 6").fetchall() if can_see_reports else []
        recent_sessions = con.execute("SELECT display_code,created_by,created_at,expires_at,status FROM inspection_sessions ORDER BY id DESC LIMIT 6").fetchall() if user["role"] in ("owner","deputy","team","inspector") else []
        staff_count = con.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] if user["role"] == "owner" else None
    return page("""<section class="card" style="background:radial-gradient(ellipse at 0% 50%,#40101e 0,transparent 58%),linear-gradient(120deg,#17121d,#0c0d14);border-color:#48202c"><div class="eyebrow">3EN SECURITY OPERATIONS</div><h2 style="font-size:25px;margin-top:10px">مرحباً بك في Inceptor</h2><p class="muted">إدارة جلسات الفحص ومراجعة النتائج والتقارير من لوحة واحدة.</p><a class="btn" href="{{ url_for('sessions_page') }}">＋ بدء جلسة فحص جديدة</a></section>
    <div class="grid">
      <div class="card"><div class="muted">إجمالي الجلسات</div><div class="metric">{{ total_sessions }}</div><div class="muted">كل الجلسات المسجلة</div></div>
      <div class="card"><div class="muted">انتظار النتائج</div><div class="metric">{{ pending_sessions }}</div><div class="muted">جلسات لم يصل تقريرها بعد</div></div>
      <div class="card"><div class="muted">التقارير المكتملة</div><div class="metric">{{ completed_reports }}</div><div class="muted">تقارير وصلت إلى اللوحة</div></div>
      {% if staff_count is not none %}<div class="card"><div class="muted">أعضاء الفريق</div><div class="metric">{{ staff_count }}</div><div class="muted">حسابات الفريق المسجلة</div></div>{% endif %}
    </div>
    {% if can_see_reports %}<div class="card"><h2>آخر التقارير</h2>{% if recent_reports %}<table><tr><th>رقم التقرير</th><th>الجلسة</th><th>الجهاز</th><th>وقت الاستلام (UTC)</th><th>الملخص</th></tr>{% for r in recent_reports %}<tr><td><a class="btn" href="{{ url_for('report_detail', report_id=r['id']) }}">#{{ r['id'] }}</a></td><td>{{ r['session_id'] }}</td><td>{{ r['target_label'] or '—' }}</td><td>{{ r['computer_label'] }}</td><td>{{ r['created_at'] }}</td><td>{{ r['summary'] }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">لا توجد تقارير حتى الآن. أنشئ جلسة وشارك ملف الفحص بعد موافقة صاحب الجهاز.</p>{% endif %}</div>{% endif %}
    {% if recent_sessions %}<div class="card"><h2>آخر الجلسات</h2><table><tr><th>كود الجلسة</th><th>أنشأها</th><th>وقت الإنشاء</th><th>الانتهاء</th><th>الحالة</th></tr>{% for s in recent_sessions %}<tr><td>{{ s['display_code'] }}</td><td>{{ s['created_by'] }}</td><td>{{ s['created_at'] }}</td><td>{{ s['expires_at'] }}</td><td>{% if s['status']=='open' %}<span style="color:#ffb454">بانتظار التقرير</span>{% elif s['status']=='used' %}<span style="color:#62d6a7">مكتملة</span>{% else %}<span class="danger">{{ s['status'] }}</span>{% endif %}</td></tr>{% endfor %}</table></div>{% endif %}""", total_sessions=total_sessions, pending_sessions=pending_sessions, completed_reports=completed_reports, recent_reports=recent_reports, recent_sessions=recent_sessions, staff_count=staff_count, can_see_reports=can_see_reports)
 
@app.route("/sessions", methods=["GET", "POST"])
@login_required
def sessions_page():
    user = current_user()
    if user["role"] not in ("owner", "deputy", "inspector"):
        abort(403)
    if request.method == "POST":
        target_label = request.form.get("target_label", "").strip()[:120]
        if len(target_label) < 2:
            flash("اكتب اسم الشخص أو معرّفه قبل إنشاء الجلسة.")
            return redirect(url_for("sessions_page"))
        code = secrets.token_urlsafe(6).replace("-", "").replace("_", "")[:8].upper()
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        created = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(created.timestamp() + 2 * 60 * 60, timezone.utc).isoformat(timespec="seconds")
        with db() as con:
            con.execute("INSERT INTO inspection_sessions(code_hash,display_code,target_label,created_by,created_at,expires_at,status) VALUES(?,?,?,?,?,?,?)",
                        (code_hash, code, target_label, user["username"], now(), expires_at, "open"))
        log_action(user["username"], "created inspection session for " + target_label)
        build_ok, build_message = trigger_session_build(code)
        if build_ok:
            flash("تم إنشاء الجلسة وإرسال طلب بناء EXE الخاص بها.")
        else:
            flash("تم إنشاء الجلسة. " + build_message)
        return page("""<div class="card"><h2>تم إنشاء الجلسة</h2><p><b>الشخص:</b> {{ target_label }}</p><p>كود الجلسة:</p><div class="metric">{{ code }}</div><p class="muted">الكود صالح لساعتين ويقبل تقريراً واحداً. لا تشارك ملف الفحص إلا مع صاحب الجهاز وبموافقته.</p><div class="notice"><b>ملف Inceptor المستقل</b><p>{{ build_message }}</p><p>بعد اكتمال البناء ستجد الملف في <a href="https://github.com/dlta30/lnspector-Team/actions/workflows/build-windows-client.yml" target="_blank" rel="noopener">صفحة بناء Windows</a> ضمن Artifacts. فك ZIP وشغّل EXE.</p></div><a class="btn" href="{{ url_for('sessions_page') }}">العودة إلى الجلسات</a></div>""", code=code, target_label=target_label, build_message=build_message)
    with db() as con:
        rows = con.execute("SELECT display_code,target_label,created_by,created_at,expires_at,used_at,status FROM inspection_sessions ORDER BY id DESC LIMIT 100").fetchall()
    return page("""<div class="card"><h2>جلسات الفحص</h2><p class="muted">أنشئ كوداً مؤقتاً لفحص بموافقة صاحب الجهاز. يلزم أخذ موافقة صاحب الجهاز قبل التشغيل.</p><form method="post"><label>اسم الشخص أو معرّفه</label><input name="target_label" minlength="2" maxlength="120" required placeholder="اسم المستخدم أو ID"><button class="btn">إنشاء جلسة وملف فحص</button></form></div><div class="card"><table><tr><th>الكود</th><th>الشخص</th><th>أنشأها</th><th>الإنشاء (UTC)</th><th>ينتهي (UTC)</th><th>الاستخدام (UTC)</th><th>الحالة</th></tr>{% for r in rows %}<tr><td>{{ r['display_code'] }}</td><td>{{ r['target_label'] }}</td><td>{{ r['created_by'] }}</td><td>{{ r['created_at'] }}</td><td>{{ r['expires_at'] }}</td><td>{{ r['used_at'] or '—' }}</td><td>{{ r['status'] }}</td></tr>{% endfor %}</table></div>""", rows=rows)


@app.get("/api/session-build/<code>")
@login_required
def session_build_status(code):
    if current_user()["role"] not in ("owner", "deputy", "inspector"): abort(403)
    with db() as con:
        row = con.execute("SELECT created_at FROM inspection_sessions WHERE display_code=?", (code.upper(),)).fetchone()
    if not row: return {"state":"missing"}, 404
    if not GITHUB_ACTIONS_TOKEN: return {"state":"needs_setup","message":"اضبط GITHUB_ACTIONS_TOKEN في Render."}
    try:
        runs = github_api_json("/actions/workflows/build-windows-client.yml/runs?event=workflow_dispatch&per_page=20") or {}
        created = datetime.fromisoformat(row["created_at"].replace("Z","+00:00"))
        for run in runs.get("workflow_runs",[]):
            if not run.get("created_at") or datetime.fromisoformat(run["created_at"].replace("Z","+00:00")) < created: continue
            arts = github_api_json("/actions/runs/" + str(run["id"]) + "/artifacts") or {}
            expected = "3eN-Inspector-" + code.upper()
            artifact = next((a for a in arts.get("artifacts",[]) if a.get("name")==expected and not a.get("expired")),None)
            if artifact: return {"state":"ready","download_url":url_for("download_session_build",code=code.upper())}
            if run.get("status") != "completed": return {"state":"building","message":"يتم تجهيز الملف…"}
            if run.get("conclusion") != "success": return {"state":"failed","message":"فشل البناء؛ راجع إعدادات GitHub Actions."}
        return {"state":"building","message":"بانتظار بدء البناء…"}
    except Exception as exc:
        print("Build status lookup failed:", type(exc).__name__)
        return {"state":"checking","message":"جارٍ التحقق من حالة البناء…"}

@app.get("/sessions/<code>/download")
@login_required
def download_session_build(code):
    if current_user()["role"] not in ("owner", "deputy", "inspector"): abort(403)
    if not GITHUB_ACTIONS_TOKEN: abort(503, "GitHub build token is not configured.")
    with db() as con:
        row = con.execute("SELECT created_at FROM inspection_sessions WHERE display_code=?", (code.upper(),)).fetchone()
    if not row: abort(404)
    created = datetime.fromisoformat(row["created_at"].replace("Z","+00:00"))
    try:
        runs = github_api_json("/actions/workflows/build-windows-client.yml/runs?event=workflow_dispatch&per_page=20") or {}
        for run in runs.get("workflow_runs",[]):
            if not run.get("created_at") or datetime.fromisoformat(run["created_at"].replace("Z","+00:00")) < created: continue
            arts = github_api_json("/actions/runs/" + str(run["id"]) + "/artifacts") or {}
            artifact = next((a for a in arts.get("artifacts",[]) if a.get("name")=="3eN-Inspector-"+code.upper() and not a.get("expired")),None)
            if not artifact: continue
            req = urllib.request.Request(artifact["archive_download_url"], headers={"Accept":"application/vnd.github+json","Authorization":"Bearer "+GITHUB_ACTIONS_TOKEN,"X-GitHub-Api-Version":"2022-11-28","User-Agent":"3eN-Inceptor-Dashboard"})
            with urllib.request.urlopen(req, timeout=45) as response: data = response.read()
            from io import BytesIO
            from flask import send_file
            return send_file(BytesIO(data), mimetype="application/zip", as_attachment=True, download_name="3eN-Inspector-"+code.upper()+".zip")
    except Exception as exc:
        print("Artifact download failed:", type(exc).__name__)
        abort(502, "Artifact download failed.")
    abort(404, "Build artifact not found yet.")

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
    notified = notify_discord(report_id, session_row["display_code"], label, summary)
    return {"ok": True, "report_id": report_id, "discord_notified": notified}, 201

@app.route("/reports")
@app.route("/reports/")
@app.route("/report")
@login_required
def reports():
    if current_user()["role"] != "owner":
        abort(403)
    with db() as con:
        rows=con.execute("SELECT r.id,r.session_id,r.computer_label,r.created_at,r.summary,r.submitted_by,s.target_label FROM reports r LEFT JOIN inspection_sessions s ON s.display_code=r.session_id ORDER BY r.id DESC LIMIT 250").fetchall()
    return page("""<div class="card"><h2>التقارير</h2><table><tr><th>رقم</th><th>الجلسة</th><th>الشخص</th><th>الجهاز</th><th>الوقت (UTC)</th><th>الملخص</th><th>أُرسل بواسطة</th><th>PDF</th>{% if is_owner %}<th>Action</th>{% endif %}</tr>{% for r in rows %}<tr><td><a href="{{ url_for('report_detail',report_id=r['id']) }}">#{{ r['id'] }}</a></td><td>{{ r['session_id'] }}</td><td>{{ r['computer_label'] }}</td><td>{{ r['created_at'] }}</td><td>{{ r['summary'] }}</td><td>{{ r['submitted_by'] }}</td><td><a class="btn" href="{{ url_for('report_pdf',report_id=r['id']) }}">تحميل PDF</a></td>{% if is_owner %}<td><form method="post" action="{{ url_for('delete_report',report_id=r['id']) }}" onsubmit="return confirm('حذف this report permanently?')"><button class="btn danger" type="submit">حذف</button></form></td>{% endif %}</tr>{% endfor %}</table></div>""",rows=rows,is_owner=current_user()["role"]=="owner")

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
    if current_user()["role"] != "owner":
        abort(403)
    with db() as con:
        r=con.execute("SELECT * FROM reports WHERE id=?",(report_id,)).fetchone()
    if not r: abort(404)
    try: payload=json.dumps(json.loads(r["payload"]),indent=2,ensure_ascii=False)
    except Exception: payload=r["payload"]
    return page("""<div class="card"><h2>التقرير رقم{{ r['id'] }}</h2><p><b>الجلسة:</b> {{ r['session_id'] }} · <b>الجهاز:</b> {{ r['computer_label'] }}</p><p><b>وقت الاستلام:</b> {{ r['created_at'] }} UTC</p><p>{{ r['summary'] }}</p><pre>{{ payload }}</pre><a class="btn" href="{{ url_for('reports') }}">رجوع</a></div>""",r=r,payload=payload)

@app.route("/reports/<int:report_id>/pdf")
@login_required
def report_pdf(report_id):
    actor = current_user()
    if actor["role"] != "owner":
        abort(403)
    with db() as con:
        r = con.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
    if not r:
        abort(404)
    try:
        payload = json.dumps(json.loads(r["payload"]), indent=2, ensure_ascii=False)
    except Exception:
        payload = str(r["payload"])
    # Generate a PDF in memory; never write report contents to a public file path.
    from io import BytesIO
    from xml.sax.saxutils import escape
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
    output = BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm, title="3eN Inspector التقرير رقم" + str(report_id), author="3eN Inspector Team")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallMeta", parent=styles["BodyText"], fontSize=9, leading=13, textColor=colors.HexColor("#444444"), spaceAfter=5))
    styles.add(ParagraphStyle(name="Payload", parent=styles["الكود"], fontName="Courier", fontSize=7, leading=9, wordWrap="CJK"))
    story = [
        Paragraph("3eN INSPECTOR TEAM", styles["Title"]),
        Paragraph("Inspection التقرير رقم" + str(report_id), styles["Heading1"]),
        Spacer(1, 6*mm),
        Paragraph("<b>الجلسة:</b> " + escape(str(r["session_id"])), styles["SmallMeta"]),
        Paragraph("<b>الجهاز:</b> " + escape(str(r["computer_label"])), styles["SmallMeta"]),
        Paragraph("<b>Received (UTC):</b> " + escape(str(r["created_at"])), styles["SmallMeta"]),
        Paragraph("<b>أُرسل بواسطة:</b> " + escape(str(r["submitted_by"])), styles["SmallMeta"]),
        Paragraph("<b>الملخص:</b> " + escape(str(r["summary"] or "No summary provided")), styles["SmallMeta"]),
        Spacer(1, 4*mm),
        Paragraph("Inspection data", styles["Heading2"]),
        Preformatted(payload[:100000], styles["Payload"], maxLineLength=100),
    ]
    doc.build(story)
    output.seek(0)
    from flask import send_file
    log_action(actor["username"], "downloaded PDF for report #" + str(report_id))
    return send_file(output, mimetype="application/pdf", as_attachment=True, download_name="3eN-report-" + str(report_id) + ".pdf")

@app.route("/staff", methods=["GET","POST"])
@login_required
def users_page():
    actor=current_user()
    if actor["role"] not in ("owner","deputy"): abort(403)
    if request.method=="POST":
        action=request.form.get("action")
        if action=="create":
            username=request.form.get("username","").strip()
            password=request.form.get("password","")
            role=request.form.get("role","viewer")
            allowed_roles = ("inspector", "viewer", "deputy") if actor["role"] == "owner" else ("inspector",)
            if len(username)<3 or len(password)<8 or role not in allowed_roles:
                flash("اسم المستخدم 3 خانات على الأقل، وكلمة المرور 8 خانات على الأقل، والرتبة حسب صلاحيتك.")
            else:
                try:
                    with db() as con:
                        con.execute("INSERT INTO users(username,password_hash,role,can_view,can_ingest,created_at) VALUES(?,?,?,?,?,?)",
                                    (username,generate_password_hash(password),role,1 if request.form.get("can_view") else 0,1 if request.form.get("can_ingest") and role=="inspector" else 0,now()))
                    log_action(actor["username"],"created staff account "+username)
                    flash("Staff account created.")
                except sqlite3.IntegrityError: flash("That username already exists.")
        elif action=="permissions":
            if actor["role"] != "owner": abort(403)
            uid=request.form.get("user_id","")
            with db() as con:
                target=con.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
                if target and target["role"]!="owner":
                    con.execute("UPDATE users SET can_view=?,can_ingest=? WHERE id=?",
                                (1 if request.form.get("can_view") else 0,1 if request.form.get("can_ingest") and target["role"]=="inspector" else 0,uid))
                    log_action(actor["username"],"updated permissions for "+target["username"])
                    flash("Permissions updated.")
        elif action=="role":
            if actor["role"] != "owner": abort(403)
            uid=request.form.get("user_id","")
            role=request.form.get("role","viewer")
            if role not in ("deputy","inspector","viewer"):
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
            if actor["role"] != "owner": abort(403)
            uid=request.form.get("user_id","")
            with db() as con:
                target=con.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
                if target and target["role"]!="owner" and target["username"]!=actor["username"]:
                    con.execute("DELETE FROM users WHERE id=?",(uid,))
                    log_action(actor["username"],"deleted staff account "+target["username"])
                    flash("Staff account deleted.")
        return redirect(url_for("users_page"))
    with db() as con: users=con.execute("SELECT * FROM users ORDER BY role,username").fetchall()
    return page("""<div class="card"><h2>إنشاء حساب موظف</h2><form method="post"><input type="hidden" name="action" value="create"><label>Username</label><input name="username" minlength="3" required><label>كلمة المرور (8 خانات أو أكثر)</label><input name="password" type="password" minlength="8" required><label>Role</label><select name="role"><option value="deputy">Deputy / نائب</option><option value="inspector">Inspector</option><option value="viewer">Viewer</option></select><label><input style="width:auto" type="checkbox" name="can_view" checked> View reports</label><label><input style="width:auto" type="checkbox" name="can_ingest"> Permission flag: submit reports (inspector role only)</label><button class="btn">Create account</button></form></div><div class="card"><h2>الحسابات والصلاحيات</h2>{% for u in users %}<form method="post" class="card"><input type="hidden" name="user_id" value="{{ u['id'] }}"><b>{{ u['username'] }}</b> · {{ u['role'] }} {% if u['role']=='owner' %}<p class="muted">Owner permissions are fixed.</p>{% else %}<label>Role</label><select name="role" form="role-{{ u['id'] }}"><option value="deputy" {% if u['role']=='deputy' %}selected{% endif %}>Deputy / نائب</option><option value="viewer" {% if u['role']=='viewer' %}selected{% endif %}>Viewer</option><option value="inspector" {% if u['role']=='inspector' %}selected{% endif %}>Inspector (can create sessions)</option></select><input type="hidden" name="action" value="permissions"><label><input style="width:auto" type="checkbox" name="can_view" {% if u['can_view'] %}checked{% endif %}> View reports</label><label><input style="width:auto" type="checkbox" name="can_ingest" {% if u['can_ingest'] %}checked{% endif %}> Submit reports (future authenticated client accounts)</label><button class="btn">Save permissions</button></form><form method="post" id="role-{{ u['id'] }}"><input type="hidden" name="action" value="role"><input type="hidden" name="user_id" value="{{ u['id'] }}"><label>Change role</label><select name="role"><option value="deputy" {% if u['role']=='deputy' %}selected{% endif %}>Deputy / نائب</option><option <option value="viewer" {% if u['role']=='viewer' %}selected{% endif %}>Viewer</option><option value="inspector" {% if u['role']=='inspector' %}selected{% endif %}>Inspector</option></select><button class="btn">Save role</button></form><form method="post"><input type="hidden" name="action" value="delete"><input type="hidden" name="user_id" value="{{ u['id'] }}"><button class="btn danger">حذف account</button></form>{% endif %}</form>{% endfor %}</div>""",users=users)

@app.route("/events")
@login_required
def audit_page():
    if current_user()["role"]!="owner": abort(403)
    with db() as con: rows=con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 300").fetchall()
    return page("""<div class="card"><h2>سجل الأحداث</h2><table><tr><th>الوقت (UTC)</th><th>Actor</th><th>Action</th></tr>{% for r in rows %}<tr><td>{{ r['created_at'] }}</td><td>{{ r['actor'] }}</td><td>{{ r['action'] }}</td></tr>{% endfor %}</table></div>""",rows=rows)

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
