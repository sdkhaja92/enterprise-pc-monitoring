from app import create_app
from app.database import init_db

app = create_app()
print("Database initialized successfully.")
print("Database:", app.config["DATABASE"])
