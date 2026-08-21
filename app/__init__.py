from flask import Flask, jsonify
from dotenv import load_dotenv

load_dotenv()

from .config import Config
from .database import init_db, database_health


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    init_db(app)

    from .routes import web_bp, api_bp
    from .auth_routes import auth_bp
    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(auth_bp)

    @app.get("/health")
    def health():
        health_data = database_health()
        health_data["version"] = app.config.get("APP_VERSION", "unknown")
        health_data["status"] = "ok" if health_data["database_ok"] and health_data["ai_schema_ok"] else "degraded"
        return jsonify(health_data), 200 if health_data["status"] == "ok" else 503

    return app
