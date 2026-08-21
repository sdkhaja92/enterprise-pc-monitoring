import os
import sqlite3
import tempfile

from app import create_app
from app.config import Config


def make_app():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    Config.DATABASE = path
    Config.MONITOR_API_KEY = "test-key"
    Config.SECRET_KEY = "test-secret-for-tests"
    app = create_app()
    app.config["TESTING"] = True
    app._test_db_path = path
    return app


def cleanup(app):
    try:
        os.unlink(app._test_db_path)
    except FileNotFoundError:
        pass


def test_ai_schema_created_non_destructively():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE pcs(id INTEGER PRIMARY KEY, pc_name TEXT UNIQUE NOT NULL, api_key TEXT NOT NULL, last_seen TEXT)")
    conn.execute("INSERT INTO pcs(pc_name,api_key,last_seen) VALUES('LEGACY-PC','legacy-key','2026-08-21T10:00:00+00:00')")
    conn.commit(); conn.close()

    Config.DATABASE = path
    Config.SECRET_KEY = "test-secret-for-tests"
    app = create_app()
    conn = sqlite3.connect(path)
    ai = {row[1] for row in conn.execute("PRAGMA table_info(ai_settings)").fetchall()}
    pc = conn.execute("SELECT pc_name FROM pcs WHERE id=1").fetchone()
    conn.close()
    assert "api_key_encrypted" in ai
    assert pc == ("LEGACY-PC",)
    os.unlink(path)


def test_ai_settings_save_and_read():
    app = make_app()
    client = app.test_client()
    client.post("/login", data={"username":"admin", "password":"Admin@12345"})
    response = client.post("/ai-settings", data={
        "provider":"ollama",
        "base_url":"http://127.0.0.1:11434",
        "model":"llama3.2",
        "timeout":"60",
        "enabled":"1",
        "privacy_mode":"1",
        "api_key":"",
    })
    assert response.status_code == 302
    conn = sqlite3.connect(app._test_db_path)
    row = conn.execute("SELECT provider,base_url,model,api_key_encrypted,enabled FROM ai_settings WHERE id=1").fetchone()
    conn.close()
    assert row[:3] == ("ollama", "http://127.0.0.1:11434", "llama3.2")
    assert row[3] == ""
    assert row[4] == 1
    cleanup(app)


def test_health_reports_ai_schema():
    app = make_app()
    response = app.test_client().get("/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["ai_schema_ok"] is True
    cleanup(app)


def test_ai_test_normalizes_string_timeout():
    app = make_app()
    client = app.test_client()
    client.post("/login", data={"username":"admin", "password":"Admin@12345"})
    # A real provider is not required: monkeypatch the connection function and
    # assert that the HTML-form timeout reaches it as an integer.
    import app.routes as routes
    captured = {}
    def fake_test(settings):
        captured.update(settings)
        return "ok"
    original = routes.test_ai_connection
    routes.test_ai_connection = fake_test
    try:
        response = client.post("/ai/test", data={
            "provider":"ollama", "base_url":"http://127.0.0.1:11434",
            "model":"llama3.2", "timeout":"60", "privacy_mode":"1"
        })
    finally:
        routes.test_ai_connection = original
    assert response.status_code == 200
    assert captured["timeout"] == 60
    assert isinstance(captured["timeout"], int)
    cleanup(app)
