"""Non-destructive SOC-enterprise database upgrade/check utility."""
from app import create_app
from app.database import database_health

app = create_app()
with app.app_context():
    health = database_health()
print("SOC-enterprise database upgrade/check complete.")
print("Database:", health["database"])
print("Tables:", health["table_count"])
print("AI schema:", "OK" if health["ai_schema_ok"] else "DEGRADED")
print("No tables or records are deleted by this utility.")
