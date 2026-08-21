# Deployment Guide

## 1. Local Development

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python init_database.py
python run.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## 2. Lab Deployment

A recommended lab topology is:

```text
              SOC Server
            192.168.x.10
                  │
          ┌───────┼────────┐
          │       │        │
          ▼       ▼        ▼
       WIN01    WIN02    WIN03
       Agent    Agent    Agent
```

Keep the SOC server and test endpoints on a private lab network.

---

## 3. Configuration

Create `.env` from `.env.example`.

Example:

```text
FLASK_SECRET_KEY=<random-secret>
MONITOR_API_KEY=<random-agent-key>
MONITOR_DB=data/enterprise_monitoring.db
ONLINE_WINDOW_SECONDS=180
MONITOR_DEPARTMENT=Security Lab
MONITOR_DISK_PATH=/
FLASK_DEBUG=0
SESSION_COOKIE_SECURE=1
```

Use a real TLS reverse proxy before enabling `SESSION_COOKIE_SECURE=1`.

---

## 4. Production Direction

For a larger deployment:

```text
                    Clients
                       │
                       ▼
                  TLS / NGINX
                       │
                       ▼
             Production WSGI Server
                       │
                       ▼
                 Flask Application
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
        PostgreSQL          Worker / Queue
             │                   │
             └─────────┬─────────┘
                       ▼
                SOC Web Console
```

SQLite should be treated as the default small-lab storage engine rather than a large-fleet production datastore.

---

## 5. Backups

Back up:

- Database data
- Configuration/secret references through your secret-management system
- Application source
- Deployment configuration

Do not store `.env` or raw API keys in GitHub backups.

---

## 6. Updating the Application

The database initialization path is designed to make additive schema changes without dropping existing tables. Before a production upgrade:

1. Back up the database.
2. Stop the application/agent ingestion if required by your deployment.
3. Deploy the new source.
4. Run `python init_database.py`.
5. Start the application.
6. Run the test suite.
7. Validate endpoint heartbeat and SOC pages.

For long-term production operation, introduce a formal migration tool and versioned migration files.
