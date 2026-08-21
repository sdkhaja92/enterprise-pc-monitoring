import sqlite3
from pathlib import Path
from flask import current_app

SCHEMA = """
CREATE TABLE IF NOT EXISTS pcs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pc_name TEXT UNIQUE NOT NULL,
    api_key TEXT NOT NULL,
    ip TEXT,
    cpu REAL DEFAULT 0,
    ram REAL DEFAULT 0,
    disk REAL DEFAULT 0,
    department TEXT DEFAULT 'General',
    software TEXT DEFAULT '',
    gpu TEXT DEFAULT '',
    last_seen TEXT
);

CREATE TABLE IF NOT EXISTS endpoint_hardware (
    pc_name TEXT PRIMARY KEY,
    os_name TEXT DEFAULT '',
    os_version TEXT DEFAULT '',
    architecture TEXT DEFAULT '',
    cpu_model TEXT DEFAULT '',
    cpu_cores INTEGER DEFAULT 0,
    ram_total_gb REAL DEFAULT 0,
    gpu_model TEXT DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pc_name TEXT NOT NULL,
    cpu REAL,
    ram REAL,
    disk REAL,
    gpu REAL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pc_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    resolved INTEGER DEFAULT 0
);


CREATE TABLE IF NOT EXISTS process_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pc_name TEXT NOT NULL,
    pid INTEGER,
    name TEXT NOT NULL,
    username TEXT DEFAULT '',
    cpu_percent REAL DEFAULT 0,
    memory_mb REAL DEFAULT 0,
    status TEXT DEFAULT '',
    collected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS service_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pc_name TEXT NOT NULL,
    service_name TEXT NOT NULL,
    display_name TEXT DEFAULT '',
    state TEXT DEFAULT '',
    start_mode TEXT DEFAULT '',
    collected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pc_name TEXT NOT NULL,
    event_record_id TEXT DEFAULT '',
    event_id INTEGER NOT NULL,
    log_name TEXT DEFAULT '',
    level TEXT DEFAULT '',
    provider TEXT DEFAULT '',
    computer TEXT DEFAULT '',
    account_name TEXT DEFAULT '',
    source_ip TEXT DEFAULT '',
    message TEXT DEFAULT '',
    event_time TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    UNIQUE(pc_name, event_record_id, event_id)
);

CREATE TABLE IF NOT EXISTS endpoint_risk (
    pc_name TEXT PRIMARY KEY,
    score INTEGER NOT NULL DEFAULT 0,
    level TEXT NOT NULL DEFAULT 'Low',
    reasons TEXT DEFAULT '',
    defender_status TEXT DEFAULT 'Unknown',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pc_name TEXT NOT NULL,
    pid INTEGER DEFAULT 0,
    process_name TEXT DEFAULT '',
    local_address TEXT DEFAULT '',
    local_port INTEGER DEFAULT 0,
    remote_address TEXT DEFAULT '',
    remote_port INTEGER DEFAULT 0,
    status TEXT DEFAULT '',
    collected_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_key TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Medium',
    status TEXT NOT NULL DEFAULT 'Open',
    pc_name TEXT DEFAULT '',
    category TEXT DEFAULT 'Security',
    summary TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    assigned_to TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    source_id INTEGER DEFAULT 0,
    event_time TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT DEFAULT '',
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    author TEXT DEFAULT '',
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_type TEXT NOT NULL,
    indicator TEXT NOT NULL,
    normalized TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Medium',
    confidence INTEGER NOT NULL DEFAULT 50,
    source TEXT DEFAULT 'Manual',
    description TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(indicator_type, normalized)
);

CREATE TABLE IF NOT EXISTS ioc_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER NOT NULL,
    pc_name TEXT NOT NULL,
    match_type TEXT NOT NULL,
    matched_value TEXT NOT NULL,
    source_table TEXT DEFAULT '',
    source_id INTEGER DEFAULT 0,
    context TEXT DEFAULT '',
    matched_at TEXT NOT NULL,
    UNIQUE(ioc_id, pc_name, match_type, matched_value, source_table, source_id)
);


CREATE TABLE IF NOT EXISTS soc_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    activity_type TEXT NOT NULL,
    pc_name TEXT DEFAULT '',
    severity TEXT DEFAULT 'Info',
    title TEXT NOT NULL,
    detail TEXT DEFAULT '',
    created_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_key TEXT UNIQUE NOT NULL,
    pc_name TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Medium',
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    mitre_id TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'Open'
);

CREATE TABLE IF NOT EXISTS ai_settings (
    id INTEGER PRIMARY KEY CHECK (id=1),
    enabled INTEGER NOT NULL DEFAULT 0,
    provider TEXT NOT NULL DEFAULT 'ollama',
    base_url TEXT NOT NULL DEFAULT 'http://127.0.0.1:11434',
    model TEXT NOT NULL DEFAULT 'llama3.2',
    api_key_encrypted TEXT DEFAULT '',
    timeout INTEGER NOT NULL DEFAULT 60,
    privacy_mode INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL,
    target_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    analysis TEXT NOT NULL,
    created_by TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pc_name TEXT,
    alert_id INTEGER,
    title TEXT NOT NULL,
    description TEXT,
    priority TEXT DEFAULT 'Medium',
    status TEXT DEFAULT 'Open',
    assignee TEXT DEFAULT 'IT Operations',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

def get_db():
    db_path = Path(current_app.config["DATABASE"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def _table_columns(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _ensure_columns(conn, table, columns):
    existing = _table_columns(conn, table)
    for column, definition in columns.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _migrate_legacy_schema(conn):
    """Additive, idempotent migrations for databases created by older releases."""
    migrations = {
        "tickets": {
            "alert_id": "INTEGER",
            "priority": "TEXT DEFAULT 'Medium'",
            "assignee": "TEXT DEFAULT 'IT Operations'",
            "updated_at": "TEXT",
        },
        "process_inventory": {
            "exe_path": "TEXT DEFAULT ''",
            "command_line": "TEXT DEFAULT ''",
            "parent_pid": "INTEGER DEFAULT 0",
            "create_time": "TEXT DEFAULT ''",
        },
        "ai_settings": {
            "enabled": "INTEGER NOT NULL DEFAULT 0",
            "provider": "TEXT NOT NULL DEFAULT 'ollama'",
            "base_url": "TEXT NOT NULL DEFAULT 'http://127.0.0.1:11434'",
            "model": "TEXT NOT NULL DEFAULT 'llama3.2'",
            "api_key_encrypted": "TEXT DEFAULT ''",
            "timeout": "INTEGER NOT NULL DEFAULT 60",
            "privacy_mode": "INTEGER NOT NULL DEFAULT 1",
            "updated_at": "TEXT",
        },
    }

    for table, columns in migrations.items():
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            _ensure_columns(conn, table, columns)

    # Some legacy databases predate the AI table entirely. CREATE is safe and
    # additive because it only runs when the table is absent.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_settings (
            id INTEGER PRIMARY KEY CHECK (id=1),
            enabled INTEGER NOT NULL DEFAULT 0,
            provider TEXT NOT NULL DEFAULT 'ollama',
            base_url TEXT NOT NULL DEFAULT 'http://127.0.0.1:11434',
            model TEXT NOT NULL DEFAULT 'llama3.2',
            api_key_encrypted TEXT DEFAULT '',
            timeout INTEGER NOT NULL DEFAULT 60,
            privacy_mode INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    conn.execute("UPDATE tickets SET updated_at=COALESCE(updated_at, created_at) WHERE updated_at IS NULL OR updated_at=''")

    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_metrics_pc_time ON metrics(pc_name, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_pc_resolved ON alerts(pc_name, resolved, id)",
        "CREATE INDEX IF NOT EXISTS idx_security_pc_event_time ON security_events(pc_name, event_id, event_time)",
        "CREATE INDEX IF NOT EXISTS idx_network_pc_time ON network_connections(pc_name, collected_at)",
        "CREATE INDEX IF NOT EXISTS idx_process_pc_time ON process_inventory(pc_name, collected_at)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, severity, updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status, severity, last_seen)",
        "CREATE INDEX IF NOT EXISTS idx_ioc_matches_pc_time ON ioc_matches(pc_name, matched_at)",
        "CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status, updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_soc_activity_time ON soc_activity(created_at, id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(created_at, id)",
        "CREATE INDEX IF NOT EXISTS idx_ai_analysis_target ON ai_analysis(target_type, target_id, created_at)",
    ]
    for statement in indexes:
        try:
            conn.execute(statement)
        except sqlite3.OperationalError:
            # A partially migrated legacy DB may not have a dependent table yet;
            # the main schema creation below will create it before retrying.
            pass


def init_db(app):
    db_path = Path(app.config["DATABASE"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)

    # Create legacy/missing tables first, then apply additive migrations.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS software_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pc_name TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT DEFAULT '',
            publisher TEXT DEFAULT '',
            install_date TEXT DEFAULT '',
            architecture TEXT DEFAULT '',
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Viewer',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT NOT NULL,
            ip TEXT,
            created_at TEXT NOT NULL
        )
    """)
    _migrate_legacy_schema(conn)
    conn.commit()
    conn.close()


def database_health():
    conn = get_db()
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    ai_columns = _table_columns(conn, "ai_settings") if "ai_settings" in tables else set()
    conn.close()
    required_ai = {"id", "enabled", "provider", "base_url", "model", "api_key_encrypted", "timeout", "privacy_mode", "updated_at"}
    return {
        "database": str(current_app.config["DATABASE"]),
        "database_ok": True,
        "ai_schema_ok": required_ai.issubset(ai_columns),
        "table_count": len(tables),
    }

def fetch_all(query, params=()):
    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows
