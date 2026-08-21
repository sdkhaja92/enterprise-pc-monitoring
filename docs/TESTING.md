# Testing & SOC Validation

## 1. Automated Checks

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Run tests:

```powershell
python -m pytest -q
```

Compile-check:

```powershell
python -m compileall app agent tests run.py init_database.py
```

---

## 2. Basic Runtime Test

1. Start the server.
2. Open `/login`.
3. Log in with the local administrator.
4. Confirm the dashboard loads.
5. Confirm the endpoint list is reachable.
6. Start an authorized endpoint agent.
7. Confirm the endpoint changes to Online.
8. Confirm metrics update.

---

## 3. End-to-End Security Test

Use an isolated Windows VM and a disposable test account.

### Failed logon test

Enable Windows Audit Logon failure auditing in the lab. Generate controlled failed authentication attempts.

Verify the event locally:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10
```

Expected pipeline:

```text
Windows Event 4625
      ↓
Agent
      ↓
POST /api/update
      ↓
security_events
      ↓
Detection
      ↓
Alert
      ↓
Risk
      ↓
Incident
      ↓
SOC Command Center
```

---

## 4. Security Event Tests

| Test | Expected signal |
|---|---|
| Failed logon | Event 4625 / authentication detection |
| Successful logon | Event 4624 visibility |
| Privileged logon | Event 4672 visibility / rule signal |
| Process creation | Event 4688 visibility |
| Account creation | Event 4720 detection |
| Group membership change | Event 4728/4732 visibility |
| Service installation | Event 7045 detection |

Only perform these tests on authorized lab systems.

---

## 5. IOC Test

Use a documentation/test IP such as:

```text
203.0.113.50
```

Add it as an IP IOC in Threat Intelligence, then generate a harmless lab connection to that documentation address.

Verify:

```text
Network telemetry
   ↓
IOC correlation
   ↓
IOC match
   ↓
SOC / Threat Intelligence view
```

Do not use real malicious infrastructure for routine validation.

---

## 6. Incident Workflow Test

From a generated alert:

1. Open Alerts.
2. Review endpoint and evidence.
3. Create a ticket from the alert.
4. Open Incident Response.
5. Review incident timeline.
6. Add an analyst note.
7. Change the incident status.
8. Verify SOC activity/audit entries.
9. Resolve the incident when the lab test is complete.

---

## 7. Authentication Tests

Verify:

- Valid login succeeds.
- Invalid password returns an authentication failure.
- `LOGIN_FAILED` appears in audit activity.
- Logout clears the session.
- Protected pages redirect unauthenticated users.
- Protected APIs return `401` without valid authentication.
- Restricted operations return `403` for insufficient roles.

---

## 8. Acceptance Criteria

The platform should be considered functionally connected when the following chain works in the lab:

```text
Endpoint
 → Agent
 → API authentication
 → Telemetry ingestion
 → Database
 → Security event
 → Detection
 → Alert
 → Risk
 → Incident
 → SOC dashboard
 → Analyst workflow
 → Ticket / resolution
 → Audit trail
```

A feature should not be considered complete merely because its page loads; its underlying data flow must be verified.
