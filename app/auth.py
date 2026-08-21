from functools import wraps
from datetime import datetime, timezone
from flask import session, redirect, url_for, request, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from .database import get_db


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_admin():
    conn = get_db()
    user = conn.execute("SELECT id FROM users LIMIT 1").fetchone()
    if not user:
        conn.execute(
            "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
            ("admin", generate_password_hash("Admin@12345"), "Admin", now_iso())
        )
        conn.commit()
    conn.close()


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    row = conn.execute(
        "SELECT id,username,role,active FROM users WHERE id=?",
        (uid,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("auth.login", next=request.path))
            if user["role"] not in roles:
                return "Forbidden", 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def audit(username, action):
    timestamp = now_iso()
    ip = request.remote_addr or "unknown"
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs(username,action,ip,created_at) VALUES(?,?,?,?)",
        (username, action, ip, timestamp)
    )
    # Feed authentication activity into the existing SOC activity stream too.
    # Windows Event ID 4625 remains the endpoint-login signal; this is the
    # separate web-console authentication signal.
    if action == "LOGIN_FAILED":
        conn.execute(
            """INSERT INTO soc_activity
               (activity_type,pc_name,severity,title,detail,created_at)
               VALUES(?,?,?,?,?,?)""",
            (
                "web_auth", "SOC-WEB", "Warning",
                "Failed SOC console login",
                f"Username={username or 'unknown'}; SourceIP={ip}", timestamp
            )
        )
    elif action == "LOGIN":
        conn.execute(
            """INSERT INTO soc_activity
               (activity_type,pc_name,severity,title,detail,created_at)
               VALUES(?,?,?,?,?,?)""",
            (
                "web_auth", "SOC-WEB", "Info",
                "SOC console login successful",
                f"Username={username or 'unknown'}; SourceIP={ip}", timestamp
            )
        )
    conn.commit()
    conn.close()
