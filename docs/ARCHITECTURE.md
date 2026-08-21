# SOC-enterprise Architecture

## 1. Architectural Goal

SOC-enterprise is designed as a centralized endpoint monitoring and security operations platform. The architecture separates endpoint collection, server-side ingestion, business/security logic, persistence, and the analyst-facing web console.

The project intentionally keeps the existing Flask application and endpoint agent as the core implementation while organizing the data flow around a SOC lifecycle.

---

## 2. Logical Architecture

```text
┌──────────────────────────────┐
│        Managed Endpoint      │
│                              │
│  agent/agent.py              │
│  ├─ Hardware / OS            │
│  ├─ Performance              │
│  ├─ Software                 │
│  ├─ Processes                │
│  ├─ Services                 │
│  ├─ Security Events          │
│  ├─ Defender                 │
│  └─ Network Connections      │
└──────────────┬───────────────┘
               │ Authenticated JSON
               ▼
┌──────────────────────────────┐
│       Flask Application      │
│                              │
│ Web Blueprint                │
│ API Blueprint                │
│ Authentication / RBAC        │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│        Service Layer         │
│                              │
│ Telemetry Ingestion          │
│ Alert Engine                 │
│ Risk Engine                  │
│ IOC Correlation              │
│ Detection Engine             │
│ Incident Synchronization     │
│ SOC Activity                 │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│       SQLite Database        │
│                              │
│ Endpoints / Metrics          │
│ Inventory / Security Events  │
│ Alerts / Risk                │
│ Incidents / Evidence         │
│ IOCs / Matches               │
│ Detections / SOC Activity    │
│ Tickets / Users / Audit      │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│        SOC Web Console       │
│                              │
│ Dashboard                    │
│ Endpoint Investigation       │
│ Alerts / Risk                │
│ Security Events              │
│ Incidents                    │
│ Threat Intelligence          │
│ Detection Center             │
│ SOC Command Center           │
│ Help Desk                    │
└──────────────────────────────┘
```

---

## 3. Application Layers

### Endpoint layer

`agent/agent.py` is responsible for collecting endpoint state and security telemetry. It should not contain server-side business rules.

### Web/API layer

`app/routes.py` exposes:

- HTML pages for analysts/operators
- REST endpoints for telemetry and dashboard data
- Authenticated API access for endpoint agents

`app/auth_routes.py` handles login/logout.

### Authentication layer

`app/auth.py` provides:

- Login-required checks
- Role checks
- Current-user handling
- Audit logging helpers

### Service layer

`app/services.py` contains the central processing logic. This is the main point where endpoint telemetry becomes stored state, alerts, risk, detections, IOC matches, incidents, and SOC activity.

### Persistence layer

`app/database.py` manages SQLite connections, schema initialization, and additive schema updates.

---

## 4. End-to-End Telemetry Flow

```text
Endpoint Agent
      │
      │ JSON + API authentication
      ▼
POST /api/update
      │
      ▼
Authentication / validation
      │
      ▼
Telemetry storage
      │
      ├── Metrics
      ├── Endpoint hardware
      ├── Software inventory
      ├── Process inventory
      ├── Service inventory
      ├── Security events
      ├── Network connections
      └── Defender state
      │
      ▼
Security processing
      │
      ├── Risk calculation
      ├── IOC correlation
      ├── Detection rules
      ├── Alert generation
      └── Incident synchronization
      │
      ▼
SOC activity / analyst views
```

---

## 5. Detection-to-Incident Lifecycle

```text
Raw Telemetry
     ↓
Detection Rule / IOC Match
     ↓
Detection Record
     ↓
Alert
     ↓
Risk Contribution
     ↓
Incident Creation / Synchronization
     ↓
Evidence + Timeline
     ↓
Analyst Notes / Status
     ↓
Ticket or response workflow
     ↓
Resolution
```

A detection being closed and an incident being resolved are separate concepts. A detection represents the signal; an incident represents the analyst-managed case.

---

## 6. Main Data Domains

```text
Endpoint domain
  pcs
  endpoint_hardware
  metrics
  software_inventory
  process_inventory
  service_inventory
  network_connections

Security domain
  security_events
  alerts
  endpoint_risk
  detections

Incident domain
  incidents
  incident_events
  incident_notes

Threat intelligence domain
  iocs
  ioc_matches

Operations domain
  tickets
  soc_activity

Identity / governance domain
  users
  audit_logs
```

---

## 7. Authentication Boundaries

### Browser

```text
Browser → Session Login → Protected Web Routes
```

### Agent/API

```text
Agent → X-API-Key / Bearer / update payload → API authentication
```

The API must be treated as an explicit security boundary. In production, TLS, credential rotation, network restrictions, and stronger endpoint identity should be added.

---

## 8. Scaling Path

SQLite is appropriate for local development, training, demonstrations, and small lab deployments.

For larger fleets:

```text
NGINX / TLS
      ↓
Production WSGI server
      ↓
Flask application
      ↓
PostgreSQL
      ↓
Queue / worker layer
      ↓
Optional object storage / long-term telemetry storage
```

The service boundaries should be retained while the persistence and asynchronous processing layers evolve.
