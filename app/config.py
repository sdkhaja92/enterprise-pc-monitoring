import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


def resolve_database():
    """Select the existing database first, then the current default.

    This is intentionally non-destructive: a legacy database is never copied,
    renamed, deleted, or replaced automatically. MONITOR_DB always wins when
    explicitly configured.
    """
    explicit = os.getenv("MONITOR_DB", "").strip()
    if explicit:
        return explicit

    legacy_candidates = [
        DATA_DIR / "enterprise.db",
        BASE_DIR / "enterprise.db",
        DATA_DIR / "enterprise_monitoring.db",
    ]
    for candidate in legacy_candidates:
        if candidate.exists():
            return str(candidate)
    return str(DATA_DIR / "enterprise_monitoring.db")


class Config:
    SECRET_KEY = os.getenv(
        "FLASK_SECRET_KEY",
        "local-enterprise-monitoring-secret-change-me"
    )
    DATABASE = resolve_database()
    MONITOR_API_KEY = os.getenv("MONITOR_API_KEY", "CHANGE-ME-ENTERPRISE-KEY")
    ONLINE_WINDOW_SECONDS = int(os.getenv("ONLINE_WINDOW_SECONDS", "180"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"}
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(2 * 1024 * 1024)))
    AI_DEFAULT_PROVIDER = os.getenv("AI_DEFAULT_PROVIDER", "ollama")
    AI_DEFAULT_MODEL = os.getenv("AI_DEFAULT_MODEL", "llama3.2")
    AI_DEFAULT_TIMEOUT = int(os.getenv("AI_DEFAULT_TIMEOUT", "60"))
    APP_VERSION = os.getenv("APP_VERSION", "1.1.0")
