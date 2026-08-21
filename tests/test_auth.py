import os
import tempfile

from app import create_app
from app.config import Config


def make_app():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    Config.DATABASE = path
    Config.MONITOR_API_KEY = "test-key"
    app = create_app()
    app.config["TESTING"] = True
    app._test_db_path = path
    return app


def test_auth_routes_registered():
    app = make_app()
    rules = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert "auth.login" in rules
    assert "auth.login_post" in rules
    assert "auth.logout" in rules
    os.unlink(app._test_db_path)


def test_login_page():
    app = make_app()
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Sign in" in response.data
    os.unlink(app._test_db_path)
