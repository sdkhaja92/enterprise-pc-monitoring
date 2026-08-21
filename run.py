import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}
    print(f"SOC-enterprise {app.config.get('APP_VERSION', '')} | DB: {app.config['DATABASE']}")
    app.run(host=host, port=port, debug=debug)
