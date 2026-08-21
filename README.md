# SOC-enterprise

## **From Endpoint Event to SOC Incident — One Connected Security Workflow**

> **SOC-enterprise is an open-source endpoint security and SOC platform that turns endpoint telemetry into actionable detections, risk signals, alerts, and investigation-ready incidents.**

**Monitor endpoints. Detect suspicious activity. Correlate threats. Investigate incidents. Track analyst actions — from one SOC command center.**

SOC-enterprise is a Python/Flask-based platform designed for controlled enterprise, lab, and cybersecurity training environments. It connects endpoint telemetry, Windows security-event monitoring, detection rules, MITRE ATT&CK references, IOC correlation, risk scoring, alerting, incident response, help-desk workflows, authentication, audit logging, and SOC operations into a single workflow.

### The core idea

Most endpoint monitoring answers:

> **“What is happening on this machine?”**

SOC-enterprise is designed to take the next step:

> **“What happened, why does it matter, what evidence do we have, and what should the analyst investigate?”**

```text
Endpoint Event
      ↓
Agent Telemetry
      ↓
Authenticated Ingestion
      ↓
Detection + IOC Correlation
      ↓
Risk Context
      ↓
Alert
      ↓
Incident
      ↓
SOC Investigation
      ↓
Ticket / Analyst Action
      ↓
Resolution + Audit Trail
```

### Why this project is different

**One endpoint event can travel through the entire security workflow — from collection to investigation.**

That makes SOC-enterprise useful as a practical platform for:

- 🛡️ SOC / Blue Team labs
- 🔍 Detection-engineering practice
- 🎓 Cybersecurity training environments
- 🧪 Controlled endpoint-security experiments
- 🏢 Small/internal monitoring deployments
- 📚 Learning how telemetry becomes a security incident

> **Project status:** Active development / security-platform prototype. The project is suitable for labs, demonstrations, training, and controlled internal environments. Production deployment requires the hardening steps documented in `docs/SECURITY.md` and `docs/DEPLOYMENT.md`.

---

## 🚀 What SOC-enterprise Does

| Capability | What it provides |
|---|---|
| 🖥️ Endpoint Monitoring | Fleet health, heartbeat, hardware and performance telemetry |
| 🔍 Security Monitoring | Windows Security events, Defender and endpoint activity |
| 🎯 Detection | Rule-based detections with evidence and MITRE ATT&CK references |
| 🧮 Risk | 0–100 endpoint risk scoring and prioritization |
| 🚨 Alerting | Security and resource alerts with lifecycle handling |
| 🌐 Threat Intelligence | IP, domain and hash IOC records and correlation |
| 🧑‍💻 Incident Response | Cases, timelines, evidence, notes and status workflow |
| 🏢 SOC Command Center | Central security operations view |
| 🎫 Help Desk | Alert-to-ticket and endpoint-associated support workflow |
| 🔐 Governance | Authentication, RBAC, API authentication and audit logging |

## 🎯 A Practical SOC Use Case

A controlled Windows lab endpoint generates repeated failed logons:

```text
Windows Event ID 4625
        ↓
Endpoint Agent
        ↓
POST /api/update
        ↓
Security Event Storage
        ↓
Failed-logon Detection
        ↓
Alert
        ↓
Risk Score
        ↓
Incident
        ↓
SOC Command Center
        ↓
Analyst Investigation
        ↓
Ticket / Resolution
        ↓
Audit Trail
```

This is the central value of the project:

> **It connects the pieces instead of treating monitoring, detection, alerting, and incident response as separate screens.**

---

## 👥 Who Is It For?

SOC-enterprise is especially useful for:

- SOC analysts and aspiring SOC analysts
- Blue Team and defensive-security learners
- Detection engineers
- Cybersecurity instructors and training labs
- Security researchers working in authorized environments
- Small organizations that need a lightweight internal monitoring prototype

## 🧩 Core Project Modules

```text
                    SOC-enterprise
                          │
          ┌───────────────┼────────────────┐
          │               │                │
          ▼               ▼                ▼
      Endpoint        Security          SOC Operations
      Monitoring      Monitoring
          │               │                │
          ├─ Hardware     ├─ Events        ├─ Alerts
          ├─ Software     ├─ Defender      ├─ Risk
          ├─ Processes    ├─ Network       ├─ Detection
          ├─ Services     └─ Telemetry     ├─ IOC
          └─ Metrics                       ├─ Incidents
                                           ├─ Tickets
                                           └─ Audit
```

## 🔥 The Hook

> **From endpoint telemetry to an investigation-ready SOC incident — in one connected workflow.**

If you are learning SOC operations, this project lets you see the complete path:

**collect → detect → correlate → prioritize → investigate → resolve → audit**

---

## Features

### Endpoint & Fleet Monitoring

- Fleet dashboard with endpoint online/offline status
- Endpoint detail pages
- CPU, RAM, disk, and GPU telemetry
- Endpoint hardware and OS inventory
- Department tagging
- Last-seen / heartbeat monitoring
- Historical performance metrics

### Endpoint Inventory

- Installed software inventory
- Running process inventory
- Windows service inventory
- Network connection visibility
- Microsoft Defender status telemetry

### Windows Security Monitoring

The agent can collect selected Windows Security events, including:

| Event ID | Purpose |
|---:|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4672 | Special privileges assigned |
| 4688 | Process creation |
| 4720 | User account creation |
| 4728 | Global security group membership change |
| 4732 | Local security group membership change |
| 7045 | Windows service installation |

### Detection & SOC Operations

- Rule-based security detections
- MITRE ATT&CK technique references
- Failed-logon burst detection
- Account-creation detection
- Service-installation detection
- Privileged-logon signals
- PowerShell / command interpreter / Windows Script Host / LOLBin signals
- IOC-based detections
- Detection lifecycle and evidence
- SOC activity stream

### Risk & Alerting

- Endpoint risk scoring from 0–100
- Low / Medium / High / Critical risk levels
- Resource and security alerts
- Alert resolution
- Risk-center views
- Endpoint risk investigation

### Incident Response

- Incident creation and lifecycle
- Incident detail and evidence
- Incident timeline
- Analyst notes
- Status transitions
- Security-event/process/network evidence views

### Threat Intelligence

- IP, domain, and hash IOC records
- Severity and confidence metadata
- IOC source and tags
- IOC match history
- Endpoint/network correlation

### IT Help Desk

- Ticket center
- Alert-to-ticket workflow
- Ticket status management
- Endpoint-associated tickets

### Security & Governance

- Session-based authentication
- Role-based access controls
- Audit logging
- API authentication using API key / Bearer authentication
- Environment-based configuration
- Non-destructive database initialization and additive schema updates

---

## Architecture

```text
                         ┌─────────────────────────┐
                         │     SOC Web Console      │
                         │ Dashboard / SOC / IR     │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │       Flask App         │
                         │ Web Routes + REST API   │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │     Service Layer       │
                         │ Ingestion / Detection   │
                         │ Risk / IOC / Alerts     │
                         └────────────┬────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
              Telemetry          Detection          Enrichment
                    │                 │                 │
                    └─────────────────┼─────────────────┘
                                      ▼
                         ┌─────────────────────────┐
                         │      SQLite Storage     │
                         │ Endpoint / Events / IR  │
                         └─────────────────────────┘
                                      ▲
                                      │
                              Authenticated JSON
                                      │
                         ┌────────────┴────────────┐
                         │     Endpoint Agent      │
                         │ agent/agent.py          │
                         └─────────────────────────┘
```

### Core security workflow

```text
Endpoint
   ↓
Agent Collection
   ↓
Authenticated Ingestion
   ↓
Validation / Storage
   ↓
Security Events + Telemetry
   ↓
Detection Engine + IOC Correlation
   ↓
Risk Engine
   ↓
Alert
   ↓
Incident
   ↓
SOC Investigation
   ↓
Ticket / Analyst Action
   ↓
Resolution + Audit Trail
```

See `docs/ARCHITECTURE.md` for the detailed component model and data flow.

---

## Repository Structure

```text
SOC-enterprise/
│
├── agent/
│   └── agent.py                 # Endpoint telemetry collector
│
├── app/
│   ├── __init__.py              # Flask application factory
│   ├── config.py                # Environment-driven configuration
│   ├── database.py              # DB connection, schema and additive migrations
│   ├── services.py              # Ingestion, detection, risk, IOC and alert logic
│   ├── auth.py                  # Authentication, roles and audit helpers
│   ├── auth_routes.py           # Login / logout routes
│   ├── routes.py                # Web UI and REST API routes
│   ├── templates/               # SOC web UI
│   └── static/css/style.css     # UI styling
│
├── data/
│   └── .gitkeep                 # Runtime database location
│
├── docs/
│   ├── API.md
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   ├── SECURITY.md
│   └── TESTING.md
│
├── tests/
│   ├── test_app.py
│   └── test_auth.py
│
├── init_database.py
├── run.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Requirements

- Python 3.10+ recommended
- Windows endpoint(s) for Windows-specific telemetry
- Network connectivity between agent and SOC server
- Python packages listed in `requirements.txt`

The server can run locally on Windows/Linux/macOS where Python and the required packages are available. Windows-specific event collection is performed by the endpoint agent when running on Windows.

---

## Quick Start — Server

### Windows PowerShell

```powershell
cd SOC-enterprise
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set strong values:

```text
FLASK_SECRET_KEY=<long-random-secret>
MONITOR_API_KEY=<long-random-agent-key>
MONITOR_DB=data/enterprise_monitoring.db
ONLINE_WINDOW_SECONDS=180
MONITOR_DEPARTMENT=General
MONITOR_DISK_PATH=/
FLASK_DEBUG=0
```

Initialize the database:

```powershell
python init_database.py
```

Start the application:

```powershell
python run.py
```

Open:

```text
http://127.0.0.1:5000
```

### Initial local administrator

The development bootstrap creates an administrator account when no administrator exists.

```text
Username: admin
Password: Admin@12345
```

**Change the bootstrap password before using the application outside an isolated local test environment.**

---

## Endpoint Agent

The endpoint agent is located at:

```text
agent/agent.py
```

It collects endpoint telemetry and sends it to the server's authenticated ingestion endpoint:

```text
POST /api/update
```

Typical telemetry includes:

- Endpoint name and IP
- CPU / RAM / disk
- GPU information
- Installed software
- Running processes
- Windows services
- Windows Security events
- Defender status
- Network connections
- Process context such as path, command line, parent PID, and creation time where available

The agent must use the same configured `MONITOR_API_KEY` as the server unless the deployment is customized with another authentication mechanism.

---

## Authentication

The web console uses session authentication.

API authentication supports:

```text
X-API-Key: <MONITOR_API_KEY>
```

or:

```text
Authorization: Bearer <MONITOR_API_KEY>
```

The telemetry update endpoint also accepts the configured API key in its JSON payload for agent compatibility.

Do not commit `.env`, API keys, database files, or runtime logs to GitHub.

---

## SOC Investigation Example

A controlled failed-logon test can validate the complete pipeline:

```text
Test Windows endpoint
       ↓
Windows Event ID 4625
       ↓
Endpoint Agent
       ↓
POST /api/update
       ↓
Security Event Storage
       ↓
Failed-logon Detection
       ↓
Alert
       ↓
Risk Score
       ↓
Incident
       ↓
SOC Command Center
       ↓
Analyst Investigation
       ↓
Ticket / Resolution
```

For a safe lab test, use an isolated VM and a disposable test account. See `docs/TESTING.md` for the recommended validation sequence.

---

## Database Safety

The database initialization logic is intended to be **non-destructive**:

- Existing tables are not dropped during normal initialization.
- Existing records are preserved.
- Missing columns required by newer application code are added through idempotent schema updates.
- Runtime database files are ignored by Git.

For large production fleets, migrate from SQLite to a production database such as PostgreSQL and introduce a formal migration framework before scaling horizontally.

---

## Security Notice

SOC-enterprise is a defensive monitoring platform. Use it only on endpoints and networks you own or are explicitly authorized to monitor.

This repository is not a replacement for a commercial EDR/SIEM and should not be treated as production-hardened without completing the security controls in `docs/SECURITY.md`.

---

## Documentation

- `docs/ARCHITECTURE.md` — architecture, components and data flow
- `docs/API.md` — REST API reference and authentication
- `docs/DEPLOYMENT.md` — local, lab and production deployment guidance
- `docs/SECURITY.md` — security controls and hardening requirements
- `docs/TESTING.md` — end-to-end testing and SOC validation
- `docs/AI.md` — local/online AI providers, privacy model and analyst workflows

---

## Development

Run the test suite after installing dependencies:

```powershell
python -m pytest -q
```

Compile-check the project:

```powershell
python -m compileall app agent tests run.py init_database.py
```

---

## License

No open-source license is declared yet. Until a license is added, the repository should be treated as **all rights reserved** and should not be redistributed or reused beyond the permissions granted by the repository owner.

---

## Author / Project

**SOC-enterprise** — Enterprise Endpoint Monitoring + Security Operations Platform.

## 🤖 AI Sentinel Add-on

SOC-enterprise includes an optional, analyst-triggered AI layer. AI is **not** part of endpoint collection and does not automatically upload telemetry to an online provider.

### Supported runtimes

- **Ollama** — local HTTP API, no API key required for the normal local endpoint
- **llama.cpp** — local OpenAI-compatible server
- **Online OpenAI-compatible APIs** — OpenAI, OpenRouter, Groq, LM Studio-compatible endpoints, and similar services
- **Google Gemini** — API-key authenticated online provider

### AI Settings

Administrators can configure the provider, base URL, model, timeout, API key, AI enablement and privacy mode from **AI Settings**.

The platform can also discover models from supported providers and test the configured connection before an analyst uses AI analysis.

### Analyst workflow

```text
Alert / Incident
      ↓
Analyst requests AI analysis
      ↓
Evidence context assembled
      ↓
Privacy filtering for online providers
      ↓
Selected AI runtime
      ↓
Assessment + Evidence + Risk + Investigation + False-positive checks
      ↓
Analysis stored in audit/history
```

### Local-first security model

- Local Ollama/llama.cpp providers keep evidence on the local environment.
- Online providers are opt-in and analyst-triggered.
- Online privacy mode redacts common IP and user identifiers before transmission.
- API keys are encrypted at rest using Fernet derived from the Flask secret.
- Real API keys must never be committed to Git.

### Database compatibility

The AI add-on is designed for existing SOC-enterprise installations. Database upgrades are **additive and non-destructive**. Existing databases are reused automatically when `data/enterprise.db` is present, unless `MONITOR_DB` explicitly selects another path. Missing AI tables/columns are created without deleting existing SOC data.

Run:

```powershell
python upgrade_database.py
```

to verify the active database and AI schema.
