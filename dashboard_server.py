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
import re
import psycopg2
from psycopg2.extras import RealDictCursor
import urllib.request
import urllib.error
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

APP_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
# Render may provide postgres://; psycopg2 expects postgresql://.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]
PERSISTENT_DATA_DIR = Path('/var/data')
ON_RENDER = bool(os.environ.get('RENDER') or os.environ.get('RENDER_SERVICE_ID'))
DEFAULT_DB_PATH = (PERSISTENT_DATA_DIR / 'inspector_dashboard.sqlite3') if ON_RENDER else (APP_DIR / 'inspector_dashboard.sqlite3')
DB_PATH = Path(os.environ.get('INSPECTOR_DB', str(DEFAULT_DB_PATH))) if not DATABASE_URL else None

app = Flask(__name__)
# Keep this value stable across deployments by setting INSPECTOR_SECRET_KEY in Render.
# A random fallback is convenient locally but invalidates browser sessions after restart.
app.secret_key = os.environ.get("INSPECTOR_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
)
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
 login_token TEXT,
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
 downloaded_at TEXT,
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

class PgCursor:
    def __init__(self, cursor):
        self._cursor = cursor
        self.lastrowid = None

    def execute(self, sql, params=()):
        sql = sql.replace("?", "%s")
        is_report_insert = bool(re.match(r"\s*INSERT\s+INTO\s+reports\b", sql, re.I))
        if is_report_insert and "RETURNING" not in sql.upper():
            sql += " RETURNING id"
        self._cursor.execute(sql, params)
        if is_report_insert:
            row = self._cursor.fetchone()
            self.lastrowid = row["id"] if row else None
        return self

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def __iter__(self):
        return iter(self._cursor)

class PgConnection:
    def __init__(self, connection):
        self._connection = connection

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            self._connection.rollback()
        else:
            self._connection.commit()
        self._connection.close()
        return False

    def execute(self, sql, params=()):
        cursor = self._connection.cursor(cursor_factory=RealDictCursor)
        return PgCursor(cursor).execute(sql, params)

    def executescript(self, script):
        cursor = self._connection.cursor()
        for statement in script.split(";"):
            if statement.strip():
                cursor.execute(statement)
        return cursor

def db():
    if DATABASE_URL:
        return PgConnection(psycopg2.connect(DATABASE_URL, connect_timeout=10, cursor_factory=RealDictCursor))
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    if DATABASE_URL:
        print("Inspector database: PostgreSQL (DATABASE_URL)")
        schema = """
        CREATE TABLE IF NOT EXISTS users (
          id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('owner','deputy','team','inspector','viewer')),
          can_view INTEGER NOT NULL DEFAULT 1, can_ingest INTEGER NOT NULL DEFAULT 0,
          login_token TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS inspection_sessions (
          id BIGSERIAL PRIMARY KEY, code_hash TEXT UNIQUE NOT NULL, display_code TEXT NOT NULL,
          target_label TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL, created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL, used_at TEXT, downloaded_at TEXT, status TEXT NOT NULL DEFAULT 'open'
        );
        CREATE TABLE IF NOT EXISTS reports (
          id BIGSERIAL PRIMARY KEY, session_id TEXT NOT NULL,
          computer_label TEXT NOT NULL DEFAULT 'Unspecified', created_at TEXT NOT NULL,
          summary TEXT NOT NULL DEFAULT '', payload TEXT NOT NULL,
          submitted_by TEXT NOT NULL DEFAULT 'desktop-client'
        );
        CREATE TABLE IF NOT EXISTS audit (
          id BIGSERIAL PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL
        );
        """
        with db() as con:
            con.executescript(schema)
            # Safe additive migrations for older PostgreSQL deployments.
            con.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS login_token TEXT")
            con.execute("ALTER TABLE inspection_sessions ADD COLUMN IF NOT EXISTS target_label TEXT NOT NULL DEFAULT ''")
            con.execute("ALTER TABLE inspection_sessions ADD COLUMN IF NOT EXISTS downloaded_at TEXT")
            row = con.execute("SELECT id FROM users WHERE role='owner' LIMIT 1").fetchone()
            if not row and OWNER_PASSWORD:
                con.execute("INSERT INTO users(username,password_hash,role,can_view,can_ingest,created_at) VALUES(?,?,?,?,?,?)",
                            (OWNER_USER, generate_password_hash(OWNER_PASSWORD), "owner", 1, 1, now()))
            elif not row:
                print("FIRST RUN: set INSPECTOR_OWNER_PASSWORD to a strong password before logging in.")
        return

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    print(f"Inspector database path: {DB_PATH} (SQLite; persistent storage requires a mounted persistent disk)")
    with db() as con:
        con.executescript(SCHEMA)
        user_columns = {row["name"] for row in con.execute("PRAGMA table_info(users)").fetchall()}
        if "login_token" not in user_columns:
            con.execute("ALTER TABLE users ADD COLUMN login_token TEXT")
        session_columns = {row["name"] for row in con.execute("PRAGMA table_info(inspection_sessions)").fetchall()}
        if "target_label" not in session_columns:
            con.execute("ALTER TABLE inspection_sessions ADD COLUMN target_label TEXT NOT NULL DEFAULT ''")
        if "downloaded_at" not in session_columns:
            con.execute("ALTER TABLE inspection_sessions ADD COLUMN downloaded_at TEXT")
        schema_row = con.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
        if schema_row and "'deputy'" not in (schema_row['sql'] or ''):
            con.execute('ALTER TABLE users RENAME TO users_old')
            con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('owner','deputy','team','inspector','viewer')), can_view INTEGER NOT NULL DEFAULT 1, can_ingest INTEGER NOT NULL DEFAULT 0, login_token TEXT, created_at TEXT NOT NULL)")
            con.execute('INSERT INTO users(id,username,password_hash,role,can_view,can_ingest,created_at) SELECT id,username,password_hash,role,can_view,can_ingest,created_at FROM users_old')
            con.execute('DROP TABLE users_old')
        row = con.execute("SELECT id FROM users WHERE role='owner' LIMIT 1").fetchone()
        if not row:
            if not OWNER_PASSWORD:
                print("FIRST RUN: set INSPECTOR_OWNER_PASSWORD to a strong password before logging in.")
            else:
                con.execute("INSERT INTO users(username,password_hash,role,can_view,can_ingest,created_at) VALUES(?,?,?,?,?,?)",
                            (OWNER_USER, generate_password_hash(OWNER_PASSWORD), "owner", 1, 1, now()))
        con.executescript("""
        DROP TRIGGER IF EXISTS prevent_report_delete;
        DROP TRIGGER IF EXISTS prevent_user_delete;
        CREATE TRIGGER IF NOT EXISTS prevent_session_delete BEFORE DELETE ON inspection_sessions BEGIN
            SELECT RAISE(ABORT, 'Session retention is enabled; DELETE is disabled.');
        END;
        CREATE TRIGGER IF NOT EXISTS prevent_audit_delete BEFORE DELETE ON audit BEGIN
            SELECT RAISE(ABORT, 'Audit retention is enabled; DELETE is disabled.');
        END;
        """)

def notify_discord(report_id, session_code, computer, summary, report=None, verdict="review", reason=""):
    webhook = os.environ.get('DISCORD_WEBHOOK_URL', '').strip().strip('"').strip("'")
    if not webhook.startswith(('https://discord.com/api/webhooks/', 'https://discordapp.com/api/webhooks/')):
        print('Discord notification skipped: DISCORD_WEBHOOK_URL is missing or invalid')
        return False

    report = report if isinstance(report, dict) else {}
    processes = report.get('processes', [])
    if not isinstance(processes, list):
        processes = []
    findings = [p for p in processes if isinstance(p, dict) and p.get('indicator_matches')]

    def safe(value, limit=900):
        return str(value or 'غير متاح').replace('\x00', '')[:limit]

    target_name, report_time, report_source = 'غير مسجل', now(), '3eN Inspector desktop client'
    try:
        with db() as con:
            row = con.execute("SELECT r.created_at,r.submitted_by,s.target_label FROM reports r LEFT JOIN inspection_sessions s ON s.display_code=r.session_id WHERE r.id=?", (report_id,)).fetchone()
        if row:
            report_time = row['created_at'] or report_time
            report_source = row['submitted_by'] or report_source
            target_name = row['target_label'] or target_name
    except Exception as exc:
        print('Discord metadata lookup failed:', type(exc).__name__)
    verdict = verdict if verdict in ('hack', 'clean') else 'review'
    verdict_title = {'hack': '🚨 هاك / مشتبه — قرار المراجع', 'clean': '✅ كلين — قرار المراجع', 'review': '🟡 قيد المراجعة'}[verdict]
    verdict_color = {'hack': 0xE74C3C, 'clean': 0x2ECC71, 'review': 0xF1C40F}[verdict]
    reason = safe(reason.strip(), 900) if isinstance(reason, str) and reason.strip() else 'لم يُذكر سبب.'
    fields = [
        {'name': '🧑‍⚖️ التصنيف النهائي', 'value': verdict_title, 'inline': False},
        {'name': '📝 سبب التصنيف', 'value': reason, 'inline': False},
        {'name': '👤 الاسم المعروف', 'value': safe(target_name, 180), 'inline': True},
        {'name': '🧾 رقم التقرير', 'value': safe(report_id, 80), 'inline': True},
        {'name': '🕒 وقت التقرير (UTC)', 'value': safe(report_time, 100), 'inline': True},
        {'name': '📡 مصدر التقرير', 'value': safe(report_source, 150), 'inline': True},
        {'name': '🎫 الجلسة', 'value': safe(session_code, 100), 'inline': True},
        {'name': '💻 الجهاز', 'value': safe(computer, 100), 'inline': True},
        {'name': '📦 العمليات المفحوصة', 'value': safe(report.get('process_count', len(processes)), 80), 'inline': True},
        {'name': '🔎 مؤشرات تحتاج مراجعة', 'value': safe(len(findings), 80), 'inline': True},
    ]

    # Include a few matched items directly in the Discord embed. A name match is
    # only a review lead, never a definitive malware/cheat verdict.
    for index, item in enumerate(findings[:5], 1):
        matches = item.get('indicator_matches', [])
        if not isinstance(matches, list):
            matches = [matches]
        value = (
            '**اسم العملية:** ' + safe(item.get('process_name') or item.get('name'), 180) + '\n'
            + '**اسم الملف:** ' + safe(item.get('file_name'), 180) + '\n'
            + '**PID:** ' + safe(item.get('pid'), 30) + '\n'
            + '**المسار:** `' + safe(item.get('executable_path'), 300) + '`\n'
            + '**المؤشرات:** ' + safe(', '.join(str(x) for x in matches[:4]), 250)
        )
        fields.append({'name': '⚠️ عنصر مشتبه للمراجعة ' + str(index), 'value': value[:1024], 'inline': False})

    if len(findings) > 5:
        fields.append({'name': 'بقية العناصر', 'value': str(len(findings) - 5) + ' عناصر إضافية — راجع التقرير الكامل في لوحة التحكم.', 'inline': False})

    embed = {
        'title': verdict_title + ' • تقرير الفحص #' + safe(report_id, 50),
        'description': (('اعتمد المراجع تصنيف «كلين». هذا قرار مراجعة يدوي ولا يضمن خلو الجهاز من كل المخاطر.\n\n' if verdict == 'clean' else 'اعتمد المراجع تصنيف «هاك / مشتبه». المؤشرات تحتاج تحققًا يدويًا ولا تُعد وحدها إثباتًا قاطعًا.\n\n' if verdict == 'hack' else 'التقرير بانتظار قرار المراجع.\n\n') + safe(summary or 'تم استلام التقرير وحفظه في لوحة التحكم.', 700)),
        'color': verdict_color,
        'fields': fields[:25],
        'footer': {'text': '3eN INSPECTOR TEAM • مؤشرات الأسماء تحتاج مراجعة يدوية ولا تثبت وحدها وجود هاك.'}
    }
    message = {
        'username': '3eN Inspector Team',
        'embeds': [embed],
        'allowed_mentions': {'parse': []}
    }
    pdf_data = None
    screenshot_data = None
    body = None
    try:
        from io import BytesIO
        from xml.sax.saxutils import escape
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=A4, rightMargin=15*mm, leftMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm, title='3eN report ' + str(report_id))
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='DiscordMeta', parent=styles['BodyText'], fontSize=9, leading=13, spaceAfter=5))
        styles.add(ParagraphStyle(name='DiscordPayload', parent=styles['BodyText'], fontName='Courier', fontSize=6.5, leading=8, wordWrap='CJK'))
        pdf_report = dict(report)
        screenshot_b64 = pdf_report.pop('desktop_screenshot_base64', None)
        screenshot_note = 'Desktop screenshot attached separately to this Discord message.' if screenshot_b64 else 'No desktop screenshot was included.'
        raw = json.dumps(pdf_report, ensure_ascii=False, indent=2, default=str)[:90000]
        story = [Paragraph('3eN INCEPTOR — INSPECTION REPORT', styles['Title']),
            Paragraph('Report #' + escape(str(report_id)), styles['Heading1']), Spacer(1, 4*mm),
            Paragraph('<b>Reviewer classification:</b> ' + escape(verdict_title), styles['DiscordMeta']),
            Paragraph('<b>Reviewer reason:</b> ' + escape(reason), styles['DiscordMeta']),
            Paragraph('<b>Known name:</b> ' + escape(str(target_name)), styles['DiscordMeta']),
            Paragraph('<b>Device:</b> ' + escape(str(computer)), styles['DiscordMeta']),
            Paragraph('<b>Session:</b> ' + escape(str(session_code)), styles['DiscordMeta']),
            Paragraph('<b>Time (UTC):</b> ' + escape(str(report_time)), styles['DiscordMeta']),
            Paragraph('<b>Source:</b> ' + escape(str(report_source)), styles['DiscordMeta']),
            Paragraph('<b>Processes reviewed:</b> ' + escape(str(report.get('process_count', len(processes)))), styles['DiscordMeta']),
            Paragraph('<b>Review leads:</b> ' + escape(str(len(findings))), styles['DiscordMeta']),
            Paragraph('<b>Desktop screenshot:</b> ' + escape(screenshot_note), styles['DiscordMeta']),
            Spacer(1, 3*mm), Paragraph('Collected report data (JSON)', styles['Heading2']),
            Preformatted(raw, styles['DiscordPayload'], maxLineLength=110)]
        doc.build(story)
        pdf_data = pdf_buffer.getvalue()
        import base64
        screenshot_data = None
        if isinstance(screenshot_b64, str) and screenshot_b64:
            try:
                decoded = base64.b64decode(screenshot_b64, validate=True)
                if decoded[:2] == b'\xff\xd8' and len(decoded) <= 7_500_000:
                    screenshot_data = decoded
                else:
                    print('Desktop screenshot rejected: invalid JPEG signature or size')
            except (ValueError, TypeError):
                print('Desktop screenshot rejected: invalid base64 data')
        if screenshot_data:
            message['embeds'][0]['image'] = {'url': 'attachment://3eN-Desktop-Screenshot.jpg'}
        boundary = '----3eNReport' + str(report_id)
        body = (('--' + boundary + '\r\nContent-Disposition: form-data; name="payload_json"\r\nContent-Type: application/json\r\n\r\n').encode()
            + json.dumps(message, ensure_ascii=False).encode('utf-8') + b'\r\n'
            + ('--' + boundary + '\r\nContent-Disposition: form-data; name="files[0]"; filename="3eN-Report-' + str(report_id) + '.pdf"\r\nContent-Type: application/pdf\r\n\r\n').encode()
            + pdf_data + b'\r\n')
        if screenshot_data:
            body += (('--' + boundary + '\r\nContent-Disposition: form-data; name="files[1]"; filename="3eN-Desktop-Screenshot.jpg"\r\nContent-Type: image/jpeg\r\n\r\n').encode()
                + screenshot_data + b'\r\n')
        body += ('--' + boundary + '--\r\n').encode()
        req = urllib.request.Request(webhook, data=body, headers={'Content-Type': 'multipart/form-data; boundary=' + boundary}, method='POST')
    except Exception as exc:
        print('Discord PDF creation failed, sending embed only:', type(exc).__name__, str(exc)[:160])
        req = urllib.request.Request(webhook, data=json.dumps(message, ensure_ascii=False).encode('utf-8'), headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            if 200 <= response.status < 300:
                if isinstance(body, bytes) and isinstance(pdf_data, bytes) and pdf_data:
                    print('Discord report sent:', report_id, 'pdf=True', 'screenshot=' + str(bool(screenshot_data)))
                    return True
                print('Discord sent embed only because PDF generation failed:', report_id)
            else:
                print('Discord report upload returned HTTP', response.status)
    except Exception as exc:
        print('Discord combined attachment upload failed:', type(exc).__name__, str(exc)[:240])

    # If Discord rejects a combined upload, retry the PDF and screenshot separately.
    # This prevents a large screenshot from silently causing both attachments to disappear.
    pdf_sent = False
    screenshot_sent = not bool(screenshot_data)

    def send_single_attachment(filename, content_type, data, include_screenshot=False):
        boundary2 = '----3eNRetry' + secrets.token_hex(12)
        retry_message = dict(message)
        retry_message['embeds'] = [dict(item) for item in message.get('embeds', [])]
        for item in retry_message['embeds']:
            item.pop('image', None)
        if include_screenshot and retry_message['embeds']:
            retry_message['embeds'][0]['image'] = {'url': 'attachment://' + filename}
        payload_part = (
            ('--' + boundary2 + '\r\nContent-Disposition: form-data; name="payload_json"\r\nContent-Type: application/json\r\n\r\n').encode()
            + json.dumps(retry_message, ensure_ascii=False).encode('utf-8') + b'\r\n'
        )
        file_part = (
            ('--' + boundary2 + '\r\nContent-Disposition: form-data; name="files[0]"; filename="' + filename + '"\r\nContent-Type: ' + content_type + '\r\n\r\n').encode()
            + data + b'\r\n'
            + ('--' + boundary2 + '--\r\n').encode()
        )
        retry_req = urllib.request.Request(
            webhook, data=payload_part + file_part,
            headers={'Content-Type': 'multipart/form-data; boundary=' + boundary2, 'User-Agent': '3eN-Inceptor-Dashboard'},
            method='POST'
        )
        with urllib.request.urlopen(retry_req, timeout=25) as response:
            return 200 <= response.status < 300

    if isinstance(pdf_data, bytes) and pdf_data:
        try:
            pdf_sent = send_single_attachment('3eN-Report-' + str(report_id) + '.pdf', 'application/pdf', pdf_data)
            print('Discord PDF retry:', 'sent' if pdf_sent else 'failed', report_id)
        except Exception as exc:
            print('Discord PDF retry failed:', type(exc).__name__, str(exc)[:200])

    if isinstance(screenshot_data, bytes) and screenshot_data:
        try:
            screenshot_sent = send_single_attachment('3eN-Desktop-Screenshot.jpg', 'image/jpeg', screenshot_data, include_screenshot=True)
            print('Discord screenshot retry:', 'sent' if screenshot_sent else 'failed', report_id)
        except Exception as exc:
            print('Discord screenshot retry failed:', type(exc).__name__, str(exc)[:200])

    if pdf_sent and screenshot_sent:
        return True

    # Last-resort text/embed notification; return False so the dashboard doesn't
    # claim that the requested PDF/screenshot attachments were delivered.
    try:
        fallback_message = dict(message)
        fallback_message['embeds'] = [dict(embed_item) for embed_item in message.get('embeds', [])]
        for embed_item in fallback_message['embeds']:
            embed_item.pop('image', None)
        fallback_req = urllib.request.Request(
            webhook,
            data=json.dumps(fallback_message, ensure_ascii=False).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': '3eN-Inceptor-Dashboard'},
            method='POST'
        )
        with urllib.request.urlopen(fallback_req, timeout=15) as response:
            if 200 <= response.status < 300:
                print('Discord embed fallback sent without all attachments:', report_id, 'pdf=' + str(pdf_sent), 'screenshot=' + str(screenshot_sent))
            else:
                print('Discord report embed fallback returned HTTP', response.status)
    except Exception as exc:
        print('Discord report embed fallback failed:', type(exc).__name__, str(exc)[:240])
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
        user = con.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()
        if not user or not session.get("login_token") or not hmac.compare_digest(str(user["login_token"] or ""), str(session.get("login_token") or "")):
            session.clear()
            return None
        return user

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
<nav>{% if user %}<a href="{{ url_for('home') }}">الرئيسية</a>{% if user['role']=='owner' or user['can_view'] %}<a href="{{ url_for('reports') }}">التقارير</a>{% endif %}{% if user['role']=='owner' %}<a href="{{ url_for('discord_test') }}">اختبار Discord</a>{% endif %}{% if user['role'] in ('owner','deputy','inspector') %}<a href="{{ url_for('sessions_page') }}">الجلسات</a>{% endif %}{% if user['role']=='owner' %}<a href="{{ url_for('users_page') }}">الموظفون والحسابات</a><a href="{{ url_for('audit_page') }}">سجل الأحداث</a>{% endif %}<a href="{{ url_for('logout') }}">تسجيل الخروج</a>{% endif %}</nav></header>
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
                    except (sqlite3.IntegrityError, psycopg2.IntegrityError):
                        user = con.execute("SELECT * FROM users WHERE username=?", (safe_name,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                login_token = secrets.token_urlsafe(32)
                with db() as con:
                    con.execute("UPDATE users SET login_token=? WHERE id=?", (login_token, user["id"]))
                session.clear()
                session.permanent = True
                session["username"] = user["username"]
                session["login_token"] = login_token
                log_action(username, "login (single active session; previous session invalidated)")
                return redirect(request.args.get("next") or url_for("home"))
        flash("Login failed. Check credentials and server environment configuration.")
    return page("""<div class="login-shell"><section class="login-hero"><div><div class="eyebrow">SECURITY OPERATIONS PLATFORM</div><div class="hero-mark">3eN<span>.</span></div><h2>INCEPTOR</h2><p class="muted">جلسات الفحص, secure reports, and team access — in one place.</p></div><div class="status-pill"><i></i> PRIVATE TEAM ACCESS</div></section><section class="login-form"><div class="eyebrow">WELCOME BACK</div><h2>Sign in</h2><p class="muted">Use your team credentials to continue.</p><form method="post"><label>Username</label><input name="username" required autocomplete="username" placeholder="Enter username"><label>Password</label><input name="password" type="password" required autocomplete="current-password" placeholder="Enter password"><button class="btn">Sign in securely &rarr;</button></form><p class="muted" style="font-size:11px;margin-top:24px">Access is controlled by your assigned role.</p></section></div>""")

@app.route("/logout")
def logout():
    name = session.get("username","unknown")
    token = session.get("login_token")
    if name != "unknown" and token:
        with db() as con:
            con.execute("UPDATE users SET login_token=NULL WHERE username=? AND login_token=?", (name, token))
    session.clear()
    log_action(name, "logout")
    return redirect(url_for("login"))

@app.route("/discord-test", methods=["GET", "POST"])
@login_required
def discord_test():
    actor = current_user()
    if actor["role"] != "owner":
        abort(403)

    webhook = os.environ.get("DISCORD_WEBHOOK_URL", "").strip().strip('"').strip("'")
    configured = webhook.startswith(("https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/"))
    result_title = ""
    result_detail = ""
    result_color = "#ffbd69"

    if request.method == "POST":
        if not configured:
            result_title = "الويب هوك غير مضبوط"
            result_detail = "أضف DISCORD_WEBHOOK_URL في Environment داخل Render. تأكد من نسخ رابط Webhook كاملًا وليس رابط الروم."
        else:
            test_message = {
                "username": "3eN Inspector Team",
                "embeds": [{
                    "title": "✅ اختبار اتصال 3eN INCEPTOR",
                    "description": "نجح الاتصال بين Render وDiscord. هذا اختبار فقط، ولم يتم إرسال بيانات فحص.",
                    "color": 6475877,
                    "fields": [
                        {"name": "الحالة", "value": "Webhook متصل", "inline": True},
                        {"name": "أُرسل بواسطة", "value": actor["username"][:80], "inline": True}
                    ],
                    "footer": {"text": "3eN INSPECTOR TEAM"}
                }],
                "allowed_mentions": {"parse": []}
            }
            req = urllib.request.Request(
                webhook,
                data=json.dumps(test_message, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "3eN-Inceptor-Dashboard"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=12) as response:
                    if 200 <= response.status < 300:
                        result_title = "✅ تم إرسال رسالة الاختبار"
                        result_detail = "Discord قبل الرسالة. افحص الروم المرتبط بهذا الـ Webhook."
                        result_color = "#62e0b0"
                    else:
                        result_title = "تعذر إرسال الرسالة"
                        result_detail = "Discord أعاد حالة HTTP " + str(response.status) + "."
                        result_color = "#ff7688"
                    log_action(actor["username"], "tested Discord webhook: HTTP " + str(response.status))
            except urllib.error.HTTPError as exc:
                try:
                    body = exc.read(1200).decode("utf-8", "replace")
                    info = json.loads(body) if body else {}
                    discord_message = str(info.get("message", "")) if isinstance(info, dict) else ""
                except Exception:
                    discord_message = ""
                result_title = "❌ Discord رفض الطلب (HTTP " + str(exc.code) + ")"
                if exc.code in (401, 404):
                    result_detail = "الرابط غير صحيح أو تم حذف Webhook أو تجديده. أنشئ Webhook جديدًا وانسخ رابطه الكامل إلى Render."
                elif exc.code == 403:
                    result_detail = "Discord رفض الإرسال بسبب الصلاحيات أو إعدادات Webhook."
                elif exc.code == 429:
                    result_detail = "Discord طلب الانتظار بسبب حد الإرسال. جرّب مرة أخرى بعد قليل."
                else:
                    result_detail = "رد Discord: " + (discord_message[:300] or "تعذر تحديد السبب من الرد.")
                result_color = "#ff7688"
                print("Discord webhook test failed: HTTP", exc.code, discord_message[:200])
                log_action(actor["username"], "Discord webhook test failed: HTTP " + str(exc.code))
            except Exception as exc:
                result_title = "❌ تعذر الاتصال بـ Discord"
                result_detail = "نوع الخطأ: " + type(exc).__name__ + ". راجع Render Logs للتفاصيل."
                result_color = "#ff7688"
                print("Discord webhook test failed:", type(exc).__name__, str(exc)[:200])
                log_action(actor["username"], "Discord webhook test failed: " + type(exc).__name__)

    if not configured and not result_title:
        result_title = "⚠️ رابط Webhook غير مضبوط"
        result_detail = "لا يظهر في إعدادات Render رابط صالح يبدأ بـ https://discord.com/api/webhooks/ أو https://discordapp.com/api/webhooks/."
    return page("""
    <section class="card" style="max-width:850px;margin:25px auto">
      <div class="eyebrow">3eN INCEPTOR · CONNECTION CHECK</div>
      <h2 style="font-size:24px;margin-top:10px">اختبار Webhook ديسكورد</h2>
      <p class="muted">يرسل رسالة اختبار فقط إلى الروم المرتبط بالرابط المخزن في Render، بدون إرسال أي بيانات فحص أو إظهار الرابط السري.</p>
      <div class="card" style="background:#0b0d14">
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
          <span style="color:{{ result_color }};font-weight:800">{{ result_title or ('✅ تم العثور على إعداد Webhook' if configured else '⚠️ الإعداد غير موجود') }}</span>
          <span class="muted">{{ 'رابط موجود وبالصيغة المتوقعة' if configured else 'لم يتم اكتشاف رابط صالح' }}</span>
        </div>
        {% if result_detail %}<p style="margin:14px 0 0;color:{{ result_color }};line-height:1.9">{{ result_detail }}</p>{% endif %}
      </div>
      <form method="post">
        <button class="btn" type="submit">إرسال رسالة اختبار للروم</button>
      </form>
      <p class="muted" style="font-size:12px;margin-top:12px">ملاحظة: وجود الرابط لا يضمن صلاحيته؛ زر الاختبار يتحقق من الرد الفعلي من Discord.</p>
    </section>
    """, configured=configured, result_title=result_title, result_detail=result_detail, result_color=result_color)

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
        build_started, build_message = trigger_session_build(code)
        log_action(user["username"], "requested session-specific client build for " + code)
        return page("""<div class="card"><div class="eyebrow">3eN INCEPTOR · SESSION READY</div><h2>تم إنشاء الجلسة</h2><p><b>الشخص:</b> {{ target_label }}</p><p>كود الجلسة</p><div class="metric" style="font-size:42px;letter-spacing:5px">{{ code }}</div><p class="muted">صالح لمدة ساعتين ويقبل تقريراً واحداً. شارك الملف مع صاحب الجهاز فقط وبعد موافقته.</p><div class="notice"><b>ملف الفحص الخاص بهذه الجلسة</b><p id="build-state">{{ build_message }}</p><a id="download-build" class="btn" style="display:none" href="{{ url_for('download_session_build',code=code) }}">⬇ تحميل حزمة الفحص (ZIP)</a><p class="muted">بعد التحميل، فك ضغط ZIP ثم شغّل 3eN-Inspector-{{ code }}.exe مع إبقاء مجلد الملفات المرفق بجانبه.</p></div><button class="btn" type="button" onclick="navigator.clipboard.writeText('{{ code }}')">نسخ كود الجلسة</button> <a class="btn" href="{{ url_for('sessions_page') }}">العودة إلى الجلسات</a></div><script>
const state=document.getElementById('build-state'), download=document.getElementById('download-build');
async function checkBuild(){try{const r=await fetch('{{ url_for("session_build_status",code=code) }}');const d=await r.json();state.textContent=d.message||({'ready':'اكتمل تجهيز الملف.','building':'يتم تجهيز الملف المخصص…','checking':'جارٍ التحقق من البناء…','failed':'فشل بناء الملف. راجع إعدادات GitHub Actions.','needs_setup':'يلزم ضبط GITHUB_ACTIONS_TOKEN وPUBLIC_DASHBOARD_URL في Render.'}[d.state]||'جارٍ تجهيز الملف…');if(d.state==='ready'){download.style.display='inline-block';state.textContent='اكتمل تجهيز الملف المخصص لهذه الجلسة.';return;}if(d.state==='failed'||d.state==='needs_setup'||d.state==='missing'||d.state==='api_error')return;}catch(e){state.textContent='تعذر الاتصال بحالة البناء. أعد تحميل الصفحة للمحاولة مجدداً.';return;}setTimeout(checkBuild,10000)}checkBuild();
</script>""", code=code, target_label=target_label, build_message=("بدأنا طلب بناء الملف المخصص." if build_started else build_message))
    with db() as con:
        rows = con.execute("SELECT display_code,target_label,created_by,created_at,expires_at,used_at,downloaded_at,status FROM inspection_sessions ORDER BY id DESC LIMIT 100").fetchall()
    return page("""<div class="card"><h2>جلسات الفحص</h2><p class="muted">أنشئ كوداً مؤقتاً لفحص بموافقة صاحب الجهاز. يلزم أخذ موافقة صاحب الجهاز قبل التشغيل.</p><form method="post"><label>اسم الشخص أو معرّفه</label><input name="target_label" minlength="2" maxlength="120" required placeholder="اسم المستخدم أو ID"><button class="btn">إنشاء جلسة وملف فحص</button></form></div><div class="card"><table><tr><th>الكود</th><th>الشخص</th><th>أنشأها</th><th>الإنشاء (UTC)</th><th>ينتهي (UTC)</th><th>تحميل الملف (UTC)</th><th>استلام التقرير (UTC)</th><th>الحالة</th></tr>{% for r in rows %}<tr><td>{{ r['display_code'] }}</td><td>{{ r['target_label'] }}</td><td>{{ r['created_by'] }}</td><td>{{ r['created_at'] }}</td><td>{{ r['expires_at'] }}</td><td>{{ r['downloaded_at'] or '—' }}</td><td>{{ r['used_at'] or '—' }}</td><td>{{ r['status'] }}</td></tr>{% endfor %}</table></div>""", rows=rows)


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
    except urllib.error.HTTPError as exc:
        print("Build status lookup failed: GitHub HTTP", exc.code)
        if exc.code in (401, 403):
            return {"state":"api_error","message":"تعذر قراءة حالة البناء من GitHub (صلاحيات التوكن). تأكد أن GITHUB_ACTIONS_TOKEN يملك Actions: Read and write على المستودع."}
        if exc.code == 404:
            return {"state":"api_error","message":"GitHub لم يجد سير العمل المطلوب. تحقق من وجود build-windows-client.yml على فرع main."}
        if exc.code == 429:
            return {"state":"api_error","message":"GitHub حدّ مؤقتاً من الطلبات. انتظر دقيقة ثم أعد المحاولة."}
        return {"state":"api_error","message":"تعذر قراءة حالة البناء من GitHub (HTTP " + str(exc.code) + ")."}
    except Exception as exc:
        print("Build status lookup failed:", type(exc).__name__)
        return {"state":"api_error","message":"تعذر الاتصال بـ GitHub للتحقق من البناء. تحقق من اتصال الاستضافة ثم أعد المحاولة."}

@app.get("/sessions/<code>/download")
@login_required
def download_session_build(code):
    if current_user()["role"] not in ("owner", "deputy", "inspector"): abort(403)
    if not GITHUB_ACTIONS_TOKEN: abort(503, "GitHub build token is not configured.")
    with db() as con:
        row = con.execute("SELECT id FROM inspection_sessions WHERE display_code=?", (code.upper(),)).fetchone()
    if not row: abort(404)
    try:
        # Deliver only the EXE compiled with this exact session code and dashboard URL.
        runs = github_api_json("/actions/workflows/build-windows-client.yml/runs?event=workflow_dispatch&per_page=30") or {}
        artifact = None
        for run in runs.get("workflow_runs", []):
            if run.get("status") != "completed" or run.get("conclusion") != "success":
                continue
            arts = github_api_json("/actions/runs/" + str(run["id"]) + "/artifacts") or {}
            artifact = next((a for a in arts.get("artifacts", []) if a.get("name") == "3eN-Inspector-" + code.upper() and not a.get("expired")), None)
            if artifact:
                break
        if not artifact:
            abort(503, "لا توجد نسخة عامة جاهزة بعد. شغّل بناء GitHub Actions مرة واحدة.")
        req = urllib.request.Request(artifact["archive_download_url"], headers={"Accept":"application/vnd.github+json","Authorization":"Bearer "+GITHUB_ACTIONS_TOKEN,"X-GitHub-Api-Version":"2022-11-28","User-Agent":"3eN-Inceptor-Dashboard"})
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            with opener.open(req, timeout=20) as response:
                data = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code not in (301, 302, 303, 307, 308):
                raise
            signed_url = exc.headers.get("Location")
            if not signed_url:
                raise RuntimeError("GitHub did not provide a download redirect")
            with urllib.request.urlopen(urllib.request.Request(signed_url, headers={"User-Agent":"3eN-Inceptor-Dashboard"}), timeout=90) as response:
                data = response.read()
        if not data or not data.startswith(b"PK"):
            raise RuntimeError("Downloaded artifact was empty or not a ZIP archive")
        from io import BytesIO
        import zipfile
        from flask import send_file
        with zipfile.ZipFile(BytesIO(data)) as archive:
            package_names = [name for name in archive.namelist()
                             if name.lower().endswith(".zip") and not name.lower().endswith(".sha256")
                             and not name.startswith("__MACOSX/")]
            if not package_names:
                raise RuntimeError("Artifact ZIP contains no portable ZIP package")
            package_data = archive.read(package_names[0])
        if not package_data.startswith(b"PK"):
            raise RuntimeError("Portable package is not a valid ZIP archive")
        with db() as con:
            con.execute("UPDATE inspection_sessions SET downloaded_at=? WHERE display_code=?", (now(), code.upper()))
        log_action("session-download", "downloaded inspection package for session " + code.upper())
        return send_file(BytesIO(package_data), mimetype="application/zip", as_attachment=True, download_name="3eN-INCEPTOR-" + code.upper() + ".zip")
    except Exception as exc:
        if getattr(exc, "code", None) in (503, 404):
            raise
        print("Artifact download failed:", type(exc).__name__, str(exc)[:240])
        abort(502, "تعذر تنزيل النسخة الجاهزة من GitHub. تحقق من صلاحيات التوكن وسجل Render.")

@app.post("/api/v1/session-report")
def ingest_session_report():
    if not request.is_json:
        abort(415)
    # The optional desktop screenshot is base64-encoded inside this JSON request.
    if len(request.get_data()) > 8_000_000:
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
    # Do not post to Discord on intake. An owner must open the report,
    # click "إرسال في Discord", choose hack/clean, and confirm manually.
    return {"ok": True, "report_id": report_id, "discord_notified": False}, 201

@app.route("/reports")
@app.route("/reports/")
@app.route("/report")
@login_required
def reports():
    actor = current_user()
    if actor["role"] != "owner" and not actor["can_view"]:
        abort(403)
    with db() as con:
        rows=con.execute("SELECT r.id,r.session_id,r.computer_label,r.created_at,r.summary,r.submitted_by,s.target_label,r.payload FROM reports r LEFT JOIN inspection_sessions s ON s.display_code=r.session_id ORDER BY r.id DESC").fetchall()
    report_rows = []
    for row in rows:
        item = dict(row)
        try:
            envelope = json.loads(item.get("payload") or "{}")
            data = envelope.get("report") if isinstance(envelope, dict) and isinstance(envelope.get("report"), dict) else envelope
            if not isinstance(data, dict): data = {}
        except Exception:
            data = {}
        matches = data.get("indicator_match_count", 0)
        processes = data.get("processes", [])
        if not isinstance(processes, list): processes = []
        findings = [p for p in processes if isinstance(p, dict) and p.get("indicator_matches")]
        try: matches = max(int(matches or 0), len(findings))
        except (ValueError, TypeError): matches = len(findings)
        file_search_parts = []
        for proc in processes:
            if not isinstance(proc, dict):
                continue
            file_search_parts.extend(str(proc.get(k) or "") for k in (
                "process_name", "file_name", "executable_path", "command_line", "sha256",
                "pid", "name", "source", "assessment"
            ))
            indicators = proc.get("indicator_matches", [])
            if isinstance(indicators, list):
                file_search_parts.extend(str(value) for value in indicators)
            elif indicators:
                file_search_parts.append(str(indicators))
        startup = data.get("startup_entries", [])
        if isinstance(startup, list):
            for entry in startup:
                if isinstance(entry, dict):
                    file_search_parts.extend(str(entry.get(k) or "") for k in ("name", "command", "source", "path"))
                else:
                    file_search_parts.append(str(entry))
        file_search = " ".join(file_search_parts)
        item["search_text"] = " ".join([
            str(item.get("id") or ""), str(item.get("target_label") or ""),
            str(item.get("computer_label") or ""), str(item.get("session_id") or ""),
            str(item.get("summary") or ""), str(item.get("created_at") or ""),
            str(item.get("submitted_by") or ""), str(data.get("platform") or ""),
            file_search
        ])
        item["match_count"] = matches
        item["process_count"] = data.get("process_count", len(processes))
        item["status_label"] = "تحتاج مراجعة" if matches else "لم تظهر مؤشرات"
        item["status_class"] = "warn" if matches else "good"
        report_rows.append(item)
    total = len(report_rows)
    flagged = sum(1 for item in report_rows if item["match_count"])
    clean = total - flagged
    return page("""
    <style>
      .reports-wrap{max-width:1280px;margin:0 auto}
      .reports-head{position:relative;overflow:hidden;padding:28px;border-radius:22px;background:radial-gradient(ellipse at 100% 0%,#92233f55,transparent 45%),linear-gradient(135deg,#171722,#0c0d13);border:1px solid #ff496526;margin-bottom:18px}
      .reports-kicker{font-size:11px;letter-spacing:2px;color:#ff8296;font-weight:900;direction:ltr;text-align:right}
      .reports-head h2{font-size:27px;margin:8px 0}.reports-head p{color:#aeb3c5;line-height:1.8;margin:0}
      .reports-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin:16px 0}
      .reports-stat{padding:17px;border:1px solid #ffffff12;background:linear-gradient(145deg,#171923,#0e1017);border-radius:15px;color:#aeb3c5;font-size:12px}
      .reports-stat strong{display:block;font-size:28px;margin-top:7px;color:#f4f5fa}
      .reports-stat.flagged strong{color:#ff8296}.reports-stat.clean strong{color:#70dfb2}
      .reports-tools{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:15px 0}
      .reports-tools input,.reports-tools select{min-width:180px;flex:1;background:#0b0c12;color:#f4f5fa;border:1px solid #ffffff20;border-radius:10px;padding:12px;outline:none}
      .report-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,440px),1fr));gap:14px}
      .report-item{min-width:0;background:linear-gradient(145deg,#171923,#0e1017);border:1px solid #ffffff12;border-radius:17px;padding:18px;box-shadow:0 12px 30px #0002}
      .report-item:hover{border-color:#ff637955}
      .report-item-top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px}
      .report-id{font-weight:900;color:#f7f7fb;font-size:16px}.report-chip{display:inline-flex;padding:6px 9px;border-radius:8px;font-size:11px;font-weight:800}
      .report-chip.warn{background:#48221e;color:#ffc078;border:1px solid #ffad4a33}.report-chip.good{background:#10372c;color:#75e0b4;border:1px solid #42d99b33}
      .report-person{font-size:19px;font-weight:900;margin:4px 0 3px;overflow-wrap:anywhere}.report-device{color:#aeb3c5;font-size:12px;overflow-wrap:anywhere;direction:ltr;text-align:right}
      .report-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;margin:15px 0}
      .report-meta>div{background:#0b0d13;border:1px solid #ffffff0c;border-radius:10px;padding:10px;min-width:0}
      .report-meta small{display:block;color:#969caf;font-size:10px;margin-bottom:5px}.report-meta span{display:block;font-size:12px;color:#e4e6ee;overflow-wrap:anywhere}
      .report-summary{color:#c4c8d5;font-size:12px;line-height:1.8;margin:10px 0;overflow-wrap:anywhere}
      .report-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:15px}.report-actions .btn{margin:0}
      .reports-empty{padding:35px;text-align:center;border:1px dashed #ffffff24;border-radius:16px;color:#aeb3c5}
      @media(max-width:560px){.reports-head{padding:20px}.reports-meta{grid-template-columns:1fr}.report-meta{grid-template-columns:1fr}.report-item{padding:14px}}
    </style>
    <div class="reports-wrap">
      <div class="reports-head">
        <div class="reports-kicker">3eN INCEPTOR · SECURITY CENTER</div>
        <h2>مركز التقارير</h2>
        <p>سجل منظم لنتائج الفحص، مع بيانات الجهاز والجلسة وحالة المؤشرات وتصدير PDF لكل تقرير.</p>
      </div>
      <div class="reports-stats">
        <div class="reports-stat"><span>إجمالي التقارير المعروضة</span><strong>{{ total }}</strong></div>
        <div class="reports-stat flagged"><span>تقارير تحتاج مراجعة</span><strong>{{ flagged }}</strong></div>
        <div class="reports-stat clean"><span>لم تظهر مؤشرات مطابقة</span><strong>{{ clean }}</strong></div>
      </div>
      <div class="reports-tools">
        <input id="report-search" type="search" placeholder="ابحث برقم التقرير أو الشخص أو الجهاز أو الجلسة أو اسم الملف أو مساره أو الأمر…" aria-label="بحث في التقارير">
        <select id="report-filter" aria-label="تصفية حسب الحالة"><option value="all">كل الحالات</option><option value="warn">تحتاج مراجعة</option><option value="good">لم تظهر مؤشرات</option></select>
        <a class="btn" href="{{ url_for('reports') }}">تحديث</a>
      </div>
      {% if report_rows %}
      <div class="report-list" id="report-list">
      {% for r in report_rows %}
        <article class="report-item" data-search="{{ r['search_text']|e }}" data-status="{{ r['status_class'] }}">
          <div class="report-item-top"><span class="report-id">تقرير #{{ r['id'] }}</span><span class="report-chip {{ r['status_class'] }}">{{ r['status_label'] }}</span></div>
          <div class="report-person">{{ r['target_label'] or 'اسم الشخص غير مسجل' }}</div>
          <div class="report-device">DEVICE · {{ r['computer_label'] or 'غير معروف' }}</div>
          <div class="report-meta">
            <div><small>كود الجلسة</small><span>{{ r['session_id'] }}</span></div>
            <div><small>وقت الاستلام (UTC)</small><span>{{ r['created_at'] }}</span></div>
            <div><small>العمليات المفحوصة</small><span>{{ r['process_count'] }}</span></div>
            <div><small>المؤشرات المطابقة</small><span>{{ r['match_count'] }}</span></div>
            <div><small>مصدر التقرير</small><span>{{ r['submitted_by'] }}</span></div>
          </div>
          <div class="report-summary">{{ r['summary'] or 'لم يرسل البرنامج ملخصًا نصيًا.' }}</div>
          <div class="report-actions">
            <a class="btn" href="{{ url_for('report_detail',report_id=r['id']) }}">عرض التقرير الكامل</a>
            <a class="btn" href="{{ url_for('report_pdf',report_id=r['id']) }}">⬇ تصدير PDF</a>
            {% if is_owner %}<form method="post" action="{{ url_for('delete_report',report_id=r['id']) }}" style="display:inline;margin:0" onsubmit="return confirm('تأكيد حذف التقرير #' + {{ r['id'] }} + ' نهائيًا؟');"><button class="btn" type="submit" style="background:#6d1728;border-color:#b82e49;color:#fff">🗑 حذف التقرير</button></form>{% else %}<span class="tag">محفوظ</span>{% endif %}
          </div>
        </article>
      {% endfor %}
      </div>
      <div class="reports-empty" id="report-none" style="display:none">لا توجد تقارير تطابق البحث الحالي.</div>
      {% else %}
      <div class="reports-empty">لا توجد تقارير محفوظة حتى الآن. بعد إرسال أول فحص ستظهر النتائج هنا.</div>
      {% endif %}
    </div>
    <script>
      (function(){
        const search=document.getElementById('report-search'),filter=document.getElementById('report-filter'),items=Array.from(document.querySelectorAll('.report-item')),none=document.getElementById('report-none');
        if(!search||!filter)return;
        function apply(){const q=search.value.trim().toLocaleLowerCase();let shown=0;items.forEach(el=>{const ok=el.dataset.search.toLocaleLowerCase().includes(q)&&(filter.value==='all'||el.dataset.status===filter.value);el.style.display=ok?'block':'none';if(ok)shown++;});if(none)none.style.display=shown?'none':'block';}
        search.addEventListener('input',apply);filter.addEventListener('change',apply);
      })();
    </script>
    """,report_rows=report_rows,total=total,flagged=flagged,clean=clean,is_owner=current_user()["role"]=="owner")

@app.post("/reports/<int:report_id>/delete")
@login_required
def delete_report(report_id):
    actor = current_user()
    if actor["role"] != "owner":
        abort(403)
    with db() as con:
        row = con.execute("SELECT id,session_id FROM reports WHERE id=?", (report_id,)).fetchone()
        if not row:
            abort(404)
        con.execute("DELETE FROM reports WHERE id=?", (report_id,))
    log_action(actor["username"], "deleted report #" + str(report_id) + " from session " + str(row["session_id"]))
    flash("تم حذف التقرير نهائيًا.")
    return redirect(url_for("reports"))

@app.route("/reports/<int:report_id>")
@login_required
def report_detail(report_id):
    actor = current_user()
    if actor["role"] != "owner" and not actor["can_view"]:
        abort(403)
    with db() as con:
        r=con.execute("SELECT * FROM reports WHERE id=?",(report_id,)).fetchone()
    if not r: abort(404)
    try:
        envelope = json.loads(r["payload"])
        if not isinstance(envelope, dict):
            envelope = {"raw_result": envelope}
    except Exception:
        envelope = {"raw_result": str(r["payload"])}
    # Unwrap actual scan data if it is nested in the submitted report envelope.
    report_data = envelope.get("report") if isinstance(envelope.get("report"), dict) else envelope
    processes = report_data.get("processes", []) if isinstance(report_data.get("processes", []), list) else []
    findings = [p for p in processes if isinstance(p, dict) and p.get("indicator_matches")]
    # Put processes with name-based indicators first, then show all remaining processes.
    processes.sort(key=lambda item: bool(item.get("indicator_matches")), reverse=True)
    # Prepare every running process, not just processes that matched a heuristic.
    for item in processes:
        path = str(item.get("executable_path") or "")
        normalized_path = path.replace(chr(92), "/")
        item["file_name"] = normalized_path.rsplit("/", 1)[-1] if normalized_path else str(item.get("process_name") or "غير متاح")
        item["command_line"] = str(item.get("command_line") or "").strip() or "غير متاح"
        item["file_created_at"] = str(item.get("file_created_at") or "غير متاح")
        item["file_modified_at"] = str(item.get("file_modified_at") or "غير متاح")
        item["process_started_at"] = str(item.get("process_started_at") or "غير متاح")
        item["download_mark"] = bool(item.get("download_mark"))
    startup = []
    match_count = int(report_data.get("indicator_match_count", len(findings)) or 0)
    process_count = int(report_data.get("process_count", len(processes)) or 0)
    if findings or match_count:
        status_title, status_class = ("⚠️ فيه عناصر مشتبه فيها", "warn")
        status_detail = "الفحص وجد مؤشرات مطابقة تستحق المراجعة. هذا اشتباه وليس تأكيدًا نهائيًا بوجود هاك."
    else:
        status_title, status_class = ("✅ ما ظهرت مؤشرات هاك معروفة", "good")
        status_detail = "لم تتطابق العمليات مع قائمة المؤشرات الحالية. النتيجة لا تضمن اكتشاف كل أنواع الهاكات."
    return page("""
    <style>

      .report-hero{position:relative;isolation:isolate;overflow:hidden;padding:clamp(22px,4vw,38px);border-radius:22px;background:radial-gradient(ellipse at 95% 0%,#7f1d3b55,transparent 42%),linear-gradient(135deg,#17131f 0%,#10121c 55%,#0c0e14 100%);border:1px solid #ff49652b;margin-bottom:20px;box-shadow:0 18px 55px #0005}
      .report-hero:after{content:"3eN";position:absolute;z-index:-1;left:18px;bottom:-35px;font-size:clamp(76px,14vw,150px);font-weight:900;letter-spacing:-8px;color:#ffffff06;direction:ltr}
      .report-status{display:inline-flex;align-items:center;gap:8px;padding:10px 15px;border-radius:11px;font-weight:900;font-size:14px;margin:4px 0;border:1px solid transparent}
      .report-status.warn{background:linear-gradient(120deg,#4b201d,#2a171a);color:#ffc078;border-color:#ff9d3b45}
      .report-status.good{background:linear-gradient(120deg,#10372c,#10251f);color:#75e0b4;border-color:#42d99b45}
      .report-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:13px;margin:18px 0}
      .report-metric{position:relative;background:linear-gradient(145deg,#171a25,#0e1017);border:1px solid #ffffff12;border-radius:17px;padding:20px;min-height:112px;color:#aeb3c5;font-size:12px;box-shadow:0 10px 30px #0002}
      .report-metric strong{display:block;font-size:34px;line-height:1.2;margin-top:12px;color:#f5f6fb;font-weight:900;font-variant-numeric:tabular-nums}
      .report-metric:nth-child(2) strong{color:#ff7b91}
      .process-embed{background:linear-gradient(145deg,#171923,#0d0f16);border:1px solid #ffffff16;border-radius:16px;margin:13px 0;overflow:hidden;box-shadow:0 10px 28px #0003}
      .process-embed.flagged{border-color:#ff637966}
      .process-embed-head{display:flex;align-items:center;gap:10px;padding:15px 17px;background:#ffffff05;border-bottom:1px solid #ffffff12;flex-wrap:wrap}
      .process-embed-title{font-weight:800;color:#f4f5fb;overflow-wrap:anywhere}
      .process-embed-meta{margin-right:auto;color:#aeb4c5;font-size:11px}
      .process-embed .field{margin:0;padding:11px 16px;border-bottom:1px solid #ffffff0d;color:#d6d8e2;font-size:12px;line-height:1.9;display:grid;grid-template-columns:minmax(115px,170px) minmax(0,1fr);gap:12px;align-items:start}
      .process-embed .field:last-child{border-bottom:0}
      .process-embed .field b{color:#ff9aaa}
      .process-embed .field span[dir="ltr"]{text-align:left;unicode-bidi:plaintext;overflow-wrap:anywhere;word-break:break-word;color:#dbe1ef}
      .tag{display:inline-block;border:1px solid #67404b;background:#29151d;border-radius:7px;padding:5px 9px;margin:3px;color:#ffc0ca;font-size:11px;direction:ltr;overflow-wrap:anywhere}
      details:not(.finding){margin-top:12px;background:#0e1017;border:1px solid #ffffff10;border-radius:11px;padding:13px;overflow-wrap:anywhere}
      details:not(.finding) summary{cursor:pointer;color:#ff9aaa;font-weight:800;line-height:1.8}
      .raw-report{max-height:0;overflow:hidden}
      @media(max-width:600px){.finding .field,.process-embed .field{grid-template-columns:1fr;gap:4px}}
      .empty-state{padding:28px 18px;text-align:center;border:1px solid #235341;background:radial-gradient(ellipse at top,#17433266,transparent 75%),#10201c;border-radius:15px;color:#8be1b8;line-height:1.9}
      .card:has(.report-hero){border:0;background:transparent;box-shadow:none;padding:0}
      .card:has(.report-hero)>.card{background:linear-gradient(145deg,#151722,#0e1017);border:1px solid #ffffff12;border-radius:18px}
      @media(max-width:600px){.report-hero{padding:20px;border-radius:16px}.report-metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.report-metric{padding:14px;min-width:0}.report-metric strong{font-size:26px}}
    </style>
    <script>
      function chooseDiscordVerdict(form){const nl=String.fromCharCode(10);const answer=window.prompt("اختر تصنيف المراجع:"+nl+"1 = هاك / مشتبه"+nl+"2 = كلين"+nl+nl+"اكتب 1 أو 2:");if(answer===null)return false;const v=answer.trim();if(v!=="1"&&v!=="2"){window.alert("اختيار غير صحيح. اكتب 1 للهاك أو 2 للكلين.");return false;}const reason=window.prompt("اكتب سبب اختيار "+(v==="1"?"هاك / مشتبه":"كلين")+" (مطلوب):");if(reason===null)return false;if(!reason.trim()){window.alert("لازم تكتب سبب التصنيف قبل الإرسال.");return false;}if(!window.confirm("تأكيد إرسال التقرير مع PDF وصورة سطح المكتب (إن وُجدت) وتصنيف "+(v==="1"?"هاك / مشتبه":"كلين")+"؟"))return false;form.querySelector("input[name='verdict']").value=v==="1"?"hack":"clean";form.querySelector("input[name='reason']").value=reason.trim();return true;}
    </script>
    <div class="card">
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px">
        <a class="btn" href="{{ url_for('reports') }}">← رجوع للتقارير</a>
        <a class="btn" href="{{ url_for('report_pdf', report_id=r['id']) }}" style="background:linear-gradient(120deg,#e72f53,#8f1737);color:#fff;border-color:#ff5b78;font-weight:800">⬇ تنزيل التقرير PDF</a>
        <a class="btn" href="#process-list">▤ عرض بطاقات العمليات</a>
        {% if actor_role == 'owner' %}<form method="post" action="{{ url_for('report_send_discord', report_id=r['id']) }}" style="display:inline;margin:0" onsubmit="return chooseDiscordVerdict(this);"><input type="hidden" name="verdict" value=""><input type="hidden" name="reason" value=""><button class="btn" type="submit" style="background:linear-gradient(120deg,#5865F2,#404EED);color:#fff;border-color:#7984ff;font-weight:800">◈ إرسال في Discord</button></form>{% endif %}
      </div>
      <div class="report-hero">
        <div class="muted">3eN INCEPTOR · تقرير فحص #{{ r['id'] }}</div>
        <div class="muted" style="margin-top:5px;font-size:12px;letter-spacing:1px">by:ROITH</div>
        <h2 style="margin-top:10px">نتيجة فحص الجهاز</h2>
        <span class="report-status {{ status_class }}">{{ status_title }}</span>
        <p>{{ status_detail }}</p>
        <p class="muted">الجهاز: {{ r['computer_label'] }} · الجلسة: {{ r['session_id'] }}</p>
        <p class="muted">وقت الاستلام: {{ r['created_at'] }} UTC</p>
      </div>
      <div class="report-metrics">
        <div class="report-metric">العمليات المفحوصة<strong>{{ process_count }}</strong></div>
        <div class="report-metric">مؤشرات المطابقة<strong>{{ match_count }}</strong></div>
        <div class="report-metric">العمليات المعروضة<strong>{{ processes|length }}</strong></div>
      </div>
      <div class="card"><h2>النتيجة والتوصية</h2><p>{{ status_detail }}</p><p class="muted">{{ report_data.get('note', 'النتائج الآلية مؤشرات أولية وتحتاج إلى مراجعة بشرية.') }}</p></div>
      <div class="card" id="process-list">
        <h2>الملفات والعمليات</h2>
        <p class="muted">أسماء الملفات ومساراتها وأوقات التشغيل وتواريخ الملفات المتاحة. تاريخ إنشاء الملف لا يثبت وقت تنزيله بدقة.</p>
        <input id="file-search" type="search" placeholder="ابحث باسم ملف أو مسار…" aria-label="بحث في ملفات التقرير">
        <div id="file-list">
        {% for item in processes %}
          <article class="process-embed {% if item.get('indicator_matches') %}flagged{% endif %}" data-file-search="{{ (item.get('file_name','') ~ ' ' ~ item.get('process_name','') ~ ' ' ~ item.get('executable_path','') ~ ' ' ~ item.get('command_line',''))|e }}">
            <div class="process-embed-head"><span>{% if item.get('indicator_matches') %}⚠️{% else %}📄{% endif %}</span><span class="process-embed-title">{{ item.get('file_name') or item.get('process_name') or 'ملف غير معروف' }}</span><span class="process-embed-meta">PID {{ item.get('pid') or '—' }}</span>{% if item.get('indicator_matches') %}<span class="tag" style="background:#48221e;color:#ffc078">مشتبه به — يحتاج مراجعة</span>{% endif %}</div>
            <div class="field"><b>اسم العملية</b><span dir="ltr">{{ item.get('process_name') or 'غير متاح' }}</span></div>
            <div class="field"><b>اسم الملف</b><span dir="ltr">{{ item.get('file_name') or 'غير متاح' }}</span></div>
            <div class="field"><b>المسار الكامل</b><span dir="ltr">{{ item.get('executable_path') or 'غير متاح' }}</span></div>
            <div class="field"><b>وقت بدء التشغيل (UTC)</b><span dir="ltr">{{ item.get('process_started_at') }}</span></div>
            <div class="field"><b>تاريخ إنشاء الملف (UTC)</b><span dir="ltr">{{ item.get('file_created_at') }}</span></div>
            <div class="field"><b>تاريخ تعديل الملف (UTC)</b><span dir="ltr">{{ item.get('file_modified_at') }}</span></div>
            {% if item.get('download_mark') %}<div class="field"><b>علامة تنزيل من الإنترنت</b><span>موجودة — لا تحدد وقت التنزيل بدقة</span></div>{% endif %}
            {% if item.get('indicator_matches') %}<div class="field"><b>سبب الاشتباه</b><span>{% for indicator in item.get('indicator_matches', []) %}<span class="tag">{{ indicator }}</span>{% endfor %}</span></div>{% endif %}
          </article>
        {% else %}<div class="empty-state">لا توجد بيانات عمليات في هذا التقرير.</div>{% endfor %}
        </div><div class="reports-empty" id="file-none" style="display:none">ما فيه ملفات تطابق البحث.</div>
      </div>
      <script>(function(){const input=document.getElementById('file-search'),items=Array.from(document.querySelectorAll('[data-file-search]')),none=document.getElementById('file-none');if(!input)return;input.addEventListener('input',()=>{const q=input.value.trim().toLocaleLowerCase();let n=0;items.forEach(el=>{const ok=el.dataset.fileSearch.toLocaleLowerCase().includes(q);el.style.display=ok?'block':'none';if(ok)n++;});if(none)none.style.display=n?'none':'block';});})();</script>
    </div>
    """,r=r,report_data=report_data,processes=processes,process_count=process_count,match_count=match_count,startup=startup,findings=findings,status_title=status_title,status_class=status_class,status_detail=status_detail,actor_role=actor["role"])

@app.post("/reports/<int:report_id>/send-discord")
@login_required
def report_send_discord(report_id):
    actor = current_user()
    if actor["role"] != "owner":
        abort(403)
    with db() as con:
        r = con.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
    if not r:
        abort(404)
    try:
        envelope = json.loads(r["payload"])
        if not isinstance(envelope, dict):
            envelope = {"raw_result": envelope}
    except Exception:
        envelope = {"raw_result": str(r["payload"])}
    report_data = envelope.get("report") if isinstance(envelope.get("report"), dict) else envelope
    sent = notify_discord(
        r["id"], r["session_id"], r["computer_label"], r["summary"], report_data,
        verdict=request.form.get("verdict", "review").strip().lower(),
        reason=request.form.get("reason", "").strip()
    )
    if sent:
        log_action(actor["username"], "sent report #" + str(report_id) + " to Discord")
        flash("تم إرسال التقرير إلى روم Discord المرتبط بالويب هوك.")
    else:
        flash("تعذر إرسال التقرير. تأكد من DISCORD_WEBHOOK_URL في Render ثم راجع Logs.")
    return redirect(url_for("report_detail", report_id=report_id))


@app.route("/reports/<int:report_id>/pdf")
@login_required
def report_pdf(report_id):
    actor = current_user()
    if actor["role"] != "owner" and not actor["can_view"]:
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
    styles.add(ParagraphStyle(name="Payload", parent=styles["BodyText"], fontName="Courier", fontSize=7, leading=9, wordWrap="CJK"))
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
            allowed_roles = ("deputy", "team", "inspector", "viewer") if actor["role"] == "owner" else ("team", "inspector")
            if len(username)<3 or len(password)<3 or role not in allowed_roles:
                flash("اسم المستخدم 3 خانات على الأقل، وكلمة المرور 3 خانات على الأقل، والرتبة حسب صلاحيتك.")
            else:
                try:
                    with db() as con:
                        con.execute("INSERT INTO users(username,password_hash,role,can_view,can_ingest,created_at) VALUES(?,?,?,?,?,?)",
                                    (username,generate_password_hash(password),role,1 if request.form.get("can_view") else 0,1 if request.form.get("can_ingest") and role in ("team","inspector") else 0,now()))
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
            if role not in ("deputy","team","inspector","viewer"):
                flash("Invalid role.")
            else:
                with db() as con:
                    target=con.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
                    if target and target["role"]!="owner":
                        con.execute("UPDATE users SET role=?,can_view=?,can_ingest=? WHERE id=?",
                                    (role, 1 if request.form.get("can_view") else 0, 1 if request.form.get("can_ingest") and role in ("team","inspector") else 0, uid))
                        log_action(actor["username"],"changed role for "+target["username"]+" to "+role)
                        flash("Role updated.")
        elif action=="delete":
            if actor["role"] != "owner":
                abort(403)
            uid = request.form.get("user_id", "").strip()
            with db() as con:
                target = con.execute("SELECT id,username,role FROM users WHERE id=?", (uid,)).fetchone()
                if not target:
                    flash("الحساب غير موجود.")
                elif target["role"] == "owner":
                    flash("لا يمكن حذف حساب المالك.")
                elif int(target["id"]) == int(actor["id"]):
                    flash("لا يمكنك حذف حسابك الحالي.")
                else:
                    con.execute("DELETE FROM users WHERE id=?", (uid,))
                    log_action(actor["username"], "deleted staff account " + target["username"])
                    flash("تم حذف حساب الموظف نهائيًا.")

        return redirect(url_for("users_page"))
    with db() as con: users=con.execute("SELECT * FROM users ORDER BY role,username").fetchall()
    return page("""
    <section class="card" style="border-color:#512332;background:linear-gradient(135deg,#17111a,#10131d);padding:26px">
      <div class="eyebrow">TEAM ACCESS / ADMINISTRATION</div>
      <h2 style="font-size:24px;margin:8px 0">إدارة حسابات الموظفين</h2>
      <p class="muted" style="margin:0 0 22px">أنشئ حسابًا جديدًا، حدّد صلاحياته، وراجع أعضاء الفريق من مكان واحد.</p>
      <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px">
        <div style="background:#0b0d14;border:1px solid #303443;border-radius:14px;padding:20px">
          <h3 style="margin:0 0 5px">＋ إنشاء حساب جديد</h3>
          <p class="muted" style="margin:0 0 18px">اسم مستخدم فريد وكلمة مرور لا تقل عن 3 خانات.</p>
          <form method="post" style="display:grid;gap:10px">
            <input type="hidden" name="action" value="create">
            <label>اسم المستخدم</label><input name="username" minlength="3" maxlength="64" autocomplete="off" placeholder="مثال: staff_roith" required>
            <label>كلمة المرور</label><input name="password" type="password" minlength="3" autocomplete="new-password" placeholder="3 خانات أو أكثر" required>
            <label>دور الموظف</label>
            <select name="role">
              {% if actor_role == 'owner' %}<option value="deputy">نائب الإدارة</option>{% endif %}
              <option value="team">موظف فريق</option>
              <option value="inspector">موظف فحص</option>
              {% if actor_role == 'owner' %}<option value="viewer">مشاهدة فقط</option>{% endif %}
            </select>
            <label style="display:flex;gap:9px;align-items:center"><input style="width:auto;margin:0" type="checkbox" name="can_view" checked> السماح بمشاهدة التقارير</label>
            <label style="display:flex;gap:9px;align-items:center"><input style="width:auto;margin:0" type="checkbox" name="can_ingest"> السماح باستقبال التقارير (للموظف المختص فقط)</label>
            <button class="btn" style="margin-top:8px">إنشاء حساب الموظف</button>
          </form>
        </div>
        <div style="background:#0b0d14;border:1px solid #303443;border-radius:14px;padding:20px">
          <h3 style="margin:0 0 12px">مستويات الصلاحيات</h3>
          <div style="padding:12px;border:1px solid #303443;border-radius:10px;margin-bottom:9px"><b style="color:#ff8093">نائب الإدارة</b><p class="muted" style="margin:5px 0 0">إدارة الجلسات وإنشاء حسابات موظفي الفحص.</p></div>
          <div style="padding:12px;border:1px solid #303443;border-radius:10px;margin-bottom:9px"><b style="color:#ffb454">موظف فحص</b><p class="muted" style="margin:5px 0 0">إنشاء جلسات الفحص ومتابعة المهام المسموحة.</p></div>
          <div style="padding:12px;border:1px solid #303443;border-radius:10px"><b style="color:#62d6a7">مشاهدة فقط</b><p class="muted" style="margin:5px 0 0">وصول محدود حسب الصلاحيات الممنوحة للحساب.</p></div>
        </div>
      </div>
    </section>
    <section class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
        <div><h2 style="margin:0">حسابات الفريق</h2><p class="muted" style="margin:6px 0 0">من هنا تقدر تحذف أي تقرير، وتحذف حسابات الموظفين غير المطلوبة. حساب المالك وحسابك الحالي محميان.</p></div>
        <span class="badge">{{ users|length }} حساب</span>
      </div>
      <input id="staff-search" type="search" placeholder="ابحث باسم الموظف أو رتبته…" aria-label="بحث في حسابات الموظفين">
      <div id="staff-list" style="display:grid;gap:14px;margin-top:18px">
      {% for u in users %}
        <article class="staff-item" data-staff-search="{{ (u['username'] ~ ' ' ~ u['role'])|e }}" style="border:1px solid #303443;border-radius:13px;background:#0b0d14;padding:17px">
          <div style="display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px">
            <div><b style="font-size:16px">{{ u['username'] }}</b><div class="muted" style="margin-top:5px">تم إنشاء الحساب: {{ u['created_at'][:10] }}</div></div>
            <span class="badge">{% if u['role']=='owner' %}مالك النظام{% elif u['role']=='deputy' %}نائب الإدارة{% elif u['role']=='team' %}موظف فريق{% elif u['role']=='inspector' %}موظف فحص{% elif u['role']=='viewer' %}مشاهدة فقط{% else %}{{ u['role'] }}{% endif %}</span>
          </div>
          {% if u['role']=='owner' %}
            <p class="muted">صلاحيات المالك محمية ولا يمكن تعديلها من هنا.</p>
          {% else %}
            {% if actor_role == 'owner' %}
            <form method="post" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;align-items:end">
              <input type="hidden" name="action" value="role"><input type="hidden" name="user_id" value="{{ u['id'] }}">
              <div><label>دور الموظف</label><select name="role">
                {% if actor_role == 'owner' %}<option value="deputy" {% if u['role']=='deputy' %}selected{% endif %}>نائب الإدارة</option>{% endif %}
                <option value="team" {% if u['role']=='team' %}selected{% endif %}>موظف فريق</option>
                <option value="inspector" {% if u['role']=='inspector' %}selected{% endif %}>موظف فحص</option>
                {% if actor_role == 'owner' %}<option value="viewer" {% if u['role']=='viewer' %}selected{% endif %}>مشاهدة فقط</option>{% endif %}
              </select></div>
              <div style="display:flex;flex-direction:column;gap:10px"><label style="display:flex;gap:8px;align-items:center"><input style="width:auto;margin:0" type="checkbox" name="can_view" {% if u['can_view'] %}checked{% endif %}> مشاهدة التقارير</label><label style="display:flex;gap:8px;align-items:center"><input style="width:auto;margin:0" type="checkbox" name="can_ingest" {% if u['can_ingest'] %}checked{% endif %}> استقبال التقارير</label></div>
              <button class="btn">حفظ التغييرات</button>
            </form>
            {% if actor_role == 'owner' and u['username'] != actor_username %}
            <form method="post" style="margin-top:12px" onsubmit="return confirm('تأكيد حذف حساب ' + {{ u['username']|tojson }} + ' نهائيًا؟');">
              <input type="hidden" name="action" value="delete"><input type="hidden" name="user_id" value="{{ u['id'] }}">
              <button class="btn" style="background:#6d1728;border-color:#b82e49;color:#fff">🗑 حذف الحساب</button>
            </form>
            {% endif %}
            {% endif %}
          {% endif %}
        </article>
      {% else %}<p class="muted">لا توجد حسابات حتى الآن.</p>{% endfor %}
      </div>
      <p id="staff-none" class="muted" style="display:none;text-align:center;padding:20px">ما فيه حسابات تطابق البحث.</p>
      <script>(function(){const input=document.getElementById('staff-search'),items=Array.from(document.querySelectorAll('.staff-item')),none=document.getElementById('staff-none');if(!input)return;input.addEventListener('input',()=>{const q=input.value.trim().toLocaleLowerCase();let n=0;items.forEach(el=>{const ok=el.dataset.staffSearch.toLocaleLowerCase().includes(q);el.style.display=ok?'block':'none';if(ok)n++;});if(none)none.style.display=n?'none':'block';});})();</script>
    </section>
    """,users=users,actor_role=actor["role"],actor_username=actor["username"])

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

# Fail fast on Render if the configured persistent data disk is missing.
# This prevents silently creating a new empty database on an ephemeral filesystem.
if not DATABASE_URL and os.environ.get("RENDER") and str(DB_PATH).startswith("/var/data/") and not Path("/var/data").is_mount():
    raise RuntimeError(
        "Persistent disk is not mounted at /var/data. Refusing to start with an ephemeral database; "
        "attach the Render persistent disk and set INSPECTOR_DB=/var/data/inspector_dashboard.sqlite3."
    )

init_db()
print("Dashboard database:", "PostgreSQL (DATABASE_URL)" if DATABASE_URL else str(DB_PATH))
print("Persistent disk mounted:", Path("/var/data").is_mount() if os.environ.get("RENDER") else "local development")

if __name__ == "__main__":
    if not OWNER_PASSWORD:
        print("WARNING: INSPECTOR_OWNER_PASSWORD is unset; configure it before first owner login.")
    if not API_KEY:
        print("INFO: report ingestion disabled until INSPECTOR_API_KEY is configured.")
    app.run(host=os.environ.get("INSPECTOR_HOST","127.0.0.1"),port=int(os.environ.get("PORT","5000")),debug=False)
