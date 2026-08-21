"""Analyst-triggered AI integration for SOC-enterprise.

Providers:
- Ollama (local)
- llama.cpp / OpenAI-compatible local servers
- Online OpenAI-compatible APIs
- Google Gemini

AI is never used by endpoint collection automatically. An analyst explicitly
requests an alert or incident analysis. API keys are encrypted at rest using
Fernet derived from the Flask secret.
"""
import base64
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from flask import current_app, session

from .database import get_db

ALLOWED_PROVIDERS = {"ollama", "llama_cpp", "openai_compatible", "gemini"}
LOCAL_PROVIDERS = {"ollama", "llama_cpp"}


def _normalize_settings(settings):
    """Normalize settings coming from SQLite or HTML forms before provider calls.

    HTML form values are strings, while urllib timeout expects a numeric value.
    Keeping this normalization at the AI boundary prevents the same bug in
    Save/Test/Discover flows and also tolerates legacy SQLite rows.
    """
    normalized = dict(settings or {})
    normalized["provider"] = str(normalized.get("provider", "ollama")).strip().lower()
    normalized["base_url"] = str(normalized.get("base_url", "")).strip().rstrip("/")
    normalized["model"] = str(normalized.get("model", "")).strip()
    try:
        normalized["timeout"] = max(5, min(int(float(normalized.get("timeout", 60) or 60)), 300))
    except (TypeError, ValueError):
        normalized["timeout"] = 60
    normalized["enabled"] = 1 if str(normalized.get("enabled", 0)).lower() in {"1", "true", "on", "yes"} else 0
    normalized["privacy_mode"] = 1 if str(normalized.get("privacy_mode", 1)).lower() in {"1", "true", "on", "yes"} else 0
    normalized["api_key"] = str(normalized.get("api_key", "") or "")
    return normalized


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _derive_key(secret):
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())


def encrypt_secret(value):
    if not value:
        return ""
    from cryptography.fernet import Fernet
    return Fernet(_derive_key(current_app.config["SECRET_KEY"])).encrypt(value.encode()).decode()


def decrypt_secret(value):
    if not value:
        return ""
    try:
        from cryptography.fernet import Fernet
        return Fernet(_derive_key(current_app.config["SECRET_KEY"])).decrypt(value.encode()).decode()
    except Exception:
        return ""


def _defaults():
    provider = current_app.config.get("AI_DEFAULT_PROVIDER", "ollama")
    model = current_app.config.get("AI_DEFAULT_MODEL", "llama3.2")
    return {
        "id": 1,
        "enabled": 0,
        "provider": provider if provider in ALLOWED_PROVIDERS else "ollama",
        "base_url": "http://127.0.0.1:11434",
        "model": model,
        "api_key": "",
        "timeout": current_app.config.get("AI_DEFAULT_TIMEOUT", 60),
        "privacy_mode": 1,
        "updated_at": "",
    }


def get_ai_settings(include_secret=False):
    conn = get_db()
    row = conn.execute("SELECT * FROM ai_settings WHERE id=1").fetchone()
    conn.close()
    if not row:
        result = _defaults()
        return result
    data = dict(row)
    encrypted = data.pop("api_key_encrypted", "") or ""
    data["api_key"] = decrypt_secret(encrypted) if include_secret else ("********" if encrypted else "")
    return data


def save_ai_settings(data, username=None):
    provider = str(data.get("provider", "ollama")).strip().lower()
    if provider not in ALLOWED_PROVIDERS:
        raise ValueError("Unsupported AI provider")

    defaults = {
        "ollama": "http://127.0.0.1:11434",
        "llama_cpp": "http://127.0.0.1:8080/v1",
        "openai_compatible": "https://api.openai.com/v1",
        "gemini": "https://generativelanguage.googleapis.com/v1beta",
    }
    base_url = str(data.get("base_url", "")).strip().rstrip("/") or defaults[provider]
    model = str(data.get("model", "")).strip()
    if not model:
        raise ValueError("AI model is required")

    timeout = max(5, min(int(data.get("timeout", 60) or 60), 300))
    enabled = 1 if str(data.get("enabled", "0")).lower() in {"1", "true", "on", "yes"} else 0
    privacy_mode = 1 if str(data.get("privacy_mode", "1")).lower() in {"1", "true", "on", "yes"} else 0

    existing = get_ai_settings(include_secret=True)
    incoming_key = data.get("api_key")
    api_key = existing.get("api_key", "") if incoming_key in (None, "", "********") else str(incoming_key)
    if provider in LOCAL_PROVIDERS:
        # Local providers do not require an API key. Preserve a stored key only
        # if an operator explicitly supplied one; it will not be sent by default.
        pass
    encrypted = encrypt_secret(api_key) if api_key else ""

    conn = get_db()
    conn.execute("""
        INSERT INTO ai_settings(id,enabled,provider,base_url,model,api_key_encrypted,timeout,privacy_mode,updated_at)
        VALUES(1,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            enabled=excluded.enabled, provider=excluded.provider,
            base_url=excluded.base_url, model=excluded.model,
            api_key_encrypted=excluded.api_key_encrypted,
            timeout=excluded.timeout, privacy_mode=excluded.privacy_mode,
            updated_at=excluded.updated_at
    """, (enabled, provider, base_url, model, encrypted, timeout, privacy_mode, _now()))
    if username:
        conn.execute(
            "INSERT INTO audit_logs(username,action,ip,created_at) VALUES(?,?,?,?)",
            (username, "AI_SETTINGS_UPDATED", "local", _now())
        )
    conn.commit()
    conn.close()


def _post_json(url, payload, headers, timeout):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            body = json.loads(body)
        except Exception:
            pass
        raise RuntimeError(f"AI provider HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"AI provider connection failed: {exc.reason}") from exc


def _get_json(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"AI provider HTTP {exc.code}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"AI provider connection failed: {exc.reason}") from exc


def _build_prompt(instruction, context):
    return f"""You are the defensive SOC analyst copilot for SOC-enterprise.
Analyze only the evidence supplied below. Do not invent facts. Clearly separate evidence, inference, confidence, and recommended next steps. Do not provide offensive instructions.

TASK:
{instruction}

EVIDENCE:
{context}

Return concise sections: Assessment, Evidence, Risk, Recommended Investigation, False-Positive Checks."""


def _ollama(settings, prompt):
    url = settings["base_url"].rstrip("/") + "/api/chat"
    payload = {"model": settings["model"], "messages": [{"role": "user", "content": prompt}], "stream": False}
    _, data = _post_json(url, payload, {"Content-Type": "application/json"}, settings["timeout"])
    return data.get("message", {}).get("content", "")


def _openai_compatible(settings, prompt):
    base = settings["base_url"].rstrip("/")
    url = base if base.endswith("/chat/completions") else base + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if settings.get("api_key"):
        headers["Authorization"] = "Bearer " + settings["api_key"]
    payload = {
        "model": settings["model"],
        "messages": [
            {"role": "system", "content": "You are a defensive SOC analyst copilot."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }
    _, data = _post_json(url, payload, headers, settings["timeout"])
    return (data.get("choices") or [{}])[0].get("message", {}).get("content", "")


def _gemini(settings, prompt):
    key = settings.get("api_key")
    if not key:
        raise RuntimeError("Gemini API key is required")
    url = settings["base_url"].rstrip("/") + "/models/" + urllib.parse.quote(settings["model"], safe="") + ":generateContent?key=" + urllib.parse.quote(key)
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    _, data = _post_json(url, payload, {"Content-Type": "application/json"}, settings["timeout"])
    candidates = data.get("candidates") or []
    if not candidates:
        return ""
    parts = candidates[0].get("content", {}).get("parts", [])
    return "\n".join(str(p.get("text", "")) for p in parts if p.get("text"))


def list_models(settings=None):
    settings = _normalize_settings(settings or get_ai_settings(include_secret=True))
    provider = settings["provider"]
    timeout = settings["timeout"]
    if provider == "ollama":
        _, data = _get_json(settings["base_url"].rstrip("/") + "/api/tags", {"Accept": "application/json"}, timeout)
        return [m.get("name") for m in data.get("models", []) if m.get("name")]
    if provider in {"llama_cpp", "openai_compatible"}:
        base = settings["base_url"].rstrip("/")
        url = base + "/models" if not base.endswith("/models") else base
        headers = {"Accept": "application/json"}
        if settings.get("api_key"):
            headers["Authorization"] = "Bearer " + settings["api_key"]
        _, data = _get_json(url, headers, timeout)
        return [m.get("id") for m in data.get("data", []) if m.get("id")]
    if provider == "gemini":
        key = settings.get("api_key")
        if not key:
            raise RuntimeError("Gemini API key is required")
        url = settings["base_url"].rstrip("/") + "/models?key=" + urllib.parse.quote(key)
        _, data = _get_json(url, {"Accept": "application/json"}, timeout)
        return [m.get("name", "").removeprefix("models/") for m in data.get("models", []) if m.get("name")]
    raise RuntimeError("Unsupported AI provider")


def test_ai_connection(settings=None):
    settings = _normalize_settings(settings or get_ai_settings(include_secret=True))
    if not settings.get("model"):
        raise RuntimeError("AI model is not configured")
    if settings["provider"] == "ollama":
        models = list_models(settings)
        if settings["model"] not in models:
            raise RuntimeError(f"Ollama is reachable, but model '{settings['model']}' is not installed. Available: {', '.join(models[:10]) or 'none'}")
    return generate_ai_response("Reply with exactly: SOC-enterprise AI connection successful.", settings=settings)


def generate_ai_response(prompt, settings=None):
    settings = _normalize_settings(settings or get_ai_settings(include_secret=True))
    if not settings.get("enabled"):
        raise RuntimeError("AI integration is disabled. Enable it in AI Settings.")
    if not settings.get("model"):
        raise RuntimeError("AI model is not configured")

    provider = settings["provider"]
    if provider == "ollama":
        result = _ollama(settings, prompt)
    elif provider in {"llama_cpp", "openai_compatible"}:
        result = _openai_compatible(settings, prompt)
    elif provider == "gemini":
        result = _gemini(settings, prompt)
    else:
        raise RuntimeError("Unsupported AI provider")
    if not result:
        raise RuntimeError("AI provider returned an empty response")
    return result.strip()


def _privacy_context(settings, value):
    if settings.get("provider") in LOCAL_PROVIDERS or not settings.get("privacy_mode"):
        return value
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED-IP]", value)
    value = re.sub(r"(?i)(account_name|username|assignee)\s*[:=]\s*[^,;\n]+", r"\1=[REDACTED]", value)
    return value


def _record_analysis(target_type, target_id, result, settings):
    username = session.get("username", "unknown")
    conn = get_db()
    conn.execute("""
        INSERT INTO ai_analysis(target_type,target_id,provider,model,analysis,created_by,created_at)
        VALUES(?,?,?,?,?,?,?)
    """, (target_type, target_id, settings["provider"], settings["model"], result, username, _now()))
    conn.execute(
        "INSERT INTO audit_logs(username,action,ip,created_at) VALUES(?,?,?,?)",
        (username, f"AI_ANALYSIS_{target_type.upper()}", "local", _now())
    )
    conn.commit()
    conn.close()


def analyze_alert(alert_id):
    conn = get_db()
    alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise ValueError("Alert not found")
    pc = alert["pc_name"]
    risk = conn.execute("SELECT * FROM endpoint_risk WHERE pc_name=?", (pc,)).fetchone()
    events = conn.execute("SELECT * FROM security_events WHERE pc_name=? ORDER BY id DESC LIMIT 20", (pc,)).fetchall()
    detections = conn.execute("SELECT * FROM detections WHERE pc_name=? ORDER BY id DESC LIMIT 10", (pc,)).fetchall()
    conn.close()
    settings = get_ai_settings(include_secret=True)
    context = _privacy_context(settings, json.dumps({
        "alert": dict(alert), "endpoint_risk": dict(risk) if risk else {},
        "recent_security_events": [dict(x) for x in events],
        "recent_detections": [dict(x) for x in detections],
    }, indent=2, default=str))
    result = generate_ai_response(_build_prompt("Assess this security alert, correlate the supplied endpoint evidence, and explain what an analyst should investigate next.", context), settings=settings)
    _record_analysis("alert", alert_id, result, settings)
    return result


def analyze_incident(incident_id):
    conn = get_db()
    incident = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not incident:
        conn.close()
        raise ValueError("Incident not found")
    events = conn.execute("SELECT * FROM incident_events WHERE incident_id=? ORDER BY event_time", (incident_id,)).fetchall()
    notes = conn.execute("SELECT * FROM incident_notes WHERE incident_id=? ORDER BY created_at", (incident_id,)).fetchall()
    risk = conn.execute("SELECT * FROM endpoint_risk WHERE pc_name=?", (incident["pc_name"],)).fetchone() if incident["pc_name"] else None
    security = conn.execute("SELECT * FROM security_events WHERE pc_name=? ORDER BY id DESC LIMIT 50", (incident["pc_name"],)).fetchall() if incident["pc_name"] else []
    processes = conn.execute("SELECT name,pid,username,command_line,exe_path FROM process_inventory WHERE pc_name=? ORDER BY id DESC LIMIT 30", (incident["pc_name"],)).fetchall() if incident["pc_name"] else []
    conn.close()
    settings = get_ai_settings(include_secret=True)
    context = _privacy_context(settings, json.dumps({
        "incident": dict(incident),
        "endpoint_risk": dict(risk) if risk else {},
        "timeline": [dict(x) for x in events],
        "notes": [dict(x) for x in notes],
        "security_events": [dict(x) for x in security],
        "processes": [dict(x) for x in processes],
    }, indent=2, default=str))
    result = generate_ai_response(_build_prompt("Analyze this incident, prioritize the evidence, identify likely false-positive checks, and propose defensive investigation and containment steps.", context), settings=settings)
    _record_analysis("incident", incident_id, result, settings)
    return result
