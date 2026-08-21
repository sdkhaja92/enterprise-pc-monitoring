# Security & Hardening Guide

## Scope

SOC-enterprise is a defensive endpoint-monitoring and SOC platform. Deploy it only on systems and networks you own or are explicitly authorized to monitor.

The project is intended for controlled labs, training, demonstrations, and internal environments. Complete the controls below before production use.

---

## Secrets

Never commit:

```text
.env
*.db
*.sqlite
API keys
passwords
runtime logs
```

Generate strong random values for:

```text
FLASK_SECRET_KEY
MONITOR_API_KEY
```

The `.env.example` file contains placeholders only.

---

## Bootstrap Administrator

The development bootstrap credentials are intended only for initial local setup:

```text
admin / Admin@12345
```

Change or replace the bootstrap credential before any non-local deployment.

---

## HTTPS

Production traffic should use TLS:

```text
Endpoint Agent
     ↓ HTTPS
Reverse Proxy / TLS
     ↓
Application Server
```

Do not send endpoint credentials over unencrypted networks.

---

## API Credentials

The current deployment uses a shared configured API key for agent authentication.

For larger or higher-security deployments, move toward:

- Per-endpoint credentials
- Credential rotation
- Credential revocation
- Endpoint enrollment
- Strong endpoint identity
- mTLS where appropriate

---

## Browser Session Security

Recommended production settings include:

```text
SESSION_COOKIE_HTTPONLY=enabled
SESSION_COOKIE_SAMESITE=Lax or stricter where compatible
SESSION_COOKIE_SECURE=enabled behind HTTPS
```

Use a long, unpredictable Flask secret.

---

## Authorization

Use role-based access control for sensitive operations.

Recommended operational model:

```text
Admin
 └─ Full administration

SOC Operator
 ├─ Investigate alerts
 ├─ Manage incidents
 ├─ Manage detections
 └─ Review endpoint telemetry

Viewer
 └─ Read-only access

Agent
 └─ Telemetry ingestion only
```

Do not expose administrative or response actions to read-only users.

---

## Endpoint Trust

Endpoint telemetry must be treated as untrusted input because a compromised endpoint can fabricate values.

Future hardening options include:

- Per-agent credentials
- Certificate-based identity
- Signed telemetry
- Timestamp validation
- Replay protection
- Sequence numbers
- Credential rotation

---

## Database Security

- Keep runtime databases outside source control.
- Restrict filesystem permissions.
- Back up production data securely.
- Define retention periods for high-volume telemetry.
- Move to PostgreSQL for larger deployments.

---

## Logging and Audit

Security-sensitive actions should produce audit records, especially:

- Login success/failure
- Logout
- Incident status changes
- Incident notes
- IOC changes
- Alert actions
- Administrative changes
- Response actions when introduced

Do not log passwords, API keys, or sensitive credentials.

---

## Production Server

Do not use Flask's development server as the production service.

Use:

```text
NGINX / TLS
     ↓
Gunicorn / Waitress / equivalent production WSGI server
     ↓
Flask
```

Set debug mode off.

---

## Network Exposure

Prefer private network access or VPN access for the SOC console. If external access is unavoidable:

- Require HTTPS
- Restrict source networks
- Add strong authentication
- Consider SSO/MFA at the reverse-proxy or identity layer
- Monitor authentication failures

---

## Safe Testing

Use isolated lab endpoints and disposable test accounts when generating security events. Do not test detection rules against systems you are not authorized to monitor.
