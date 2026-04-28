-- ResQGrid SQLite Schema v4.0
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE,
  phone TEXT,
  dob TEXT,
  role TEXT DEFAULT 'guest',
  role_label TEXT DEFAULT 'Guest',
  department TEXT DEFAULT 'Guest',
  password_hash TEXT NOT NULL,
  floor TEXT DEFAULT 'Floor 1',
  zone TEXT DEFAULT 'General',
  room_number TEXT,
  can_respond INTEGER DEFAULT 0,
  can_resolve INTEGER DEFAULT 0,
  is_guest INTEGER DEFAULT 1,
  is_admin INTEGER DEFAULT 0,
  is_verified INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  available INTEGER DEFAULT 1,
  active_incident_count INTEGER DEFAULT 0,
  resolved_count INTEGER DEFAULT 0,
  requested_role TEXT DEFAULT 'guest',
  created_at TEXT DEFAULT (datetime('now')),
  last_seen TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS otp_verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  otp TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message TEXT NOT NULL,
  location TEXT DEFAULT 'Unknown Location',
  extracted_room TEXT,
  extracted_floor TEXT,
  confidence REAL DEFAULT 0,
  priority TEXT DEFAULT 'LOW',
  status TEXT DEFAULT 'ACTIVE',
  source TEXT DEFAULT 'user',
  reporter_id TEXT,
  reporter_name TEXT DEFAULT 'Anonymous',
  reporter_phone TEXT,
  reporter_role TEXT,
  reporter_room TEXT,
  assigned_user_id TEXT,
  assigned_at TEXT,
  response_deadline TEXT,
  responder_name TEXT,
  responder_role TEXT,
  responder_phone TEXT,
  responder_eta INTEGER DEFAULT 45,
  responder_status TEXT,
  relay_path TEXT DEFAULT '[]',
  relay_total_delay INTEGER DEFAULT 0,
  confidence_history TEXT DEFAULT '[]',
  matched_signals TEXT DEFAULT '[]',
  explanation TEXT,
  system_analysis TEXT,
  requires_evacuation INTEGER DEFAULT 0,
  resolved_at TEXT,
  resolved_by TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS incident_timeline (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  event TEXT NOT NULL,
  description TEXT,
  actor TEXT DEFAULT 'System',
  icon TEXT DEFAULT '📋',
  confidence REAL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_messages (
  id TEXT PRIMARY KEY,
  incident_id INTEGER NOT NULL,
  sender_id TEXT,
  sender_name TEXT NOT NULL,
  sender_role TEXT,
  message TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_hourly_stats (
  hour_key TEXT PRIMARY KEY,
  count INTEGER DEFAULT 0,
  critical INTEGER DEFAULT 0,
  resolved INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS security_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT,
  endpoint TEXT,
  method TEXT,
  status_code INTEGER,
  user_id TEXT,
  threat_level TEXT DEFAULT 'none',
  threat_type TEXT,
  user_agent TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ip_blocks (
  ip_address TEXT PRIMARY KEY,
  reason TEXT,
  blocked_until TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(priority);
CREATE INDEX IF NOT EXISTS idx_incidents_created  ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_user      ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_timeline_incident  ON incident_timeline(incident_id);
CREATE INDEX IF NOT EXISTS idx_messages_incident  ON incident_messages(incident_id);
CREATE INDEX IF NOT EXISTS idx_security_ip        ON security_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_otp_email          ON otp_verifications(email);
