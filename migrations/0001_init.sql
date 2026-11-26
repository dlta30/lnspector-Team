-- BEV / 3EN Inspect Team - D1 initial schema
-- Fresh database only. This creates empty tables; it does not copy old Render data.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner','deputy','team','inspector','viewer')),
  can_view INTEGER NOT NULL DEFAULT 1,
  can_ingest INTEGER NOT NULL DEFAULT 0,
  login_token TEXT,
  created_by TEXT,
  discord_id TEXT,
  discord_username TEXT,
  discord_server_name TEXT,
  discord_avatar TEXT,
  has_password INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS users_discord_id_unique
  ON users(discord_id) WHERE discord_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS inspection_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash TEXT NOT NULL UNIQUE,
  display_code TEXT NOT NULL,
  target_label TEXT NOT NULL DEFAULT '',
  target_discord_id TEXT NOT NULL DEFAULT '',
  target_nickname TEXT NOT NULL DEFAULT '',
  target_username TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  downloaded_at TEXT,
  status TEXT NOT NULL DEFAULT 'open'
);

CREATE INDEX IF NOT EXISTS inspection_sessions_status_expiry_idx
  ON inspection_sessions(status, expires_at);
CREATE INDEX IF NOT EXISTS inspection_sessions_created_at_idx
  ON inspection_sessions(created_at);

CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  computer_label TEXT NOT NULL DEFAULT 'Unspecified',
  created_at TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  payload TEXT NOT NULL,
  submitted_by TEXT NOT NULL DEFAULT 'desktop-client',
  review_verdict TEXT NOT NULL DEFAULT 'pending',
  review_reason TEXT NOT NULL DEFAULT '',
  reviewed_by TEXT NOT NULL DEFAULT '',
  reviewed_at TEXT,
  discord_sent_at TEXT
);

CREATE INDEX IF NOT EXISTS reports_created_at_idx ON reports(created_at);
CREATE INDEX IF NOT EXISTS reports_session_id_idx ON reports(session_id);
CREATE INDEX IF NOT EXISTS reports_review_verdict_idx ON reports(review_verdict);

CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_created_at_idx ON audit(created_at);
