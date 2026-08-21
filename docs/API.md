# SOC-enterprise API Reference

## Authentication

Protected API routes accept one of:

```http
X-API-Key: <MONITOR_API_KEY>
```

or:

```http
Authorization: Bearer <MONITOR_API_KEY>
```

The telemetry update endpoint also supports the configured key in the JSON body for endpoint-agent compatibility.

Unauthorized requests should receive HTTP `401`.

---

## Endpoint Telemetry

### `POST /api/update`

Receives endpoint telemetry from the agent.

Example shape:

```json
{
  "api_key": "<configured-key>",
  "pc_name": "LAB-WIN01",
  "ip": "192.168.1.50",
  "cpu": 21.4,
  "ram": 48.2,
  "disk": 31.0,
  "gpu": 12.0,
  "gpu_info": {},
  "department": "Security Lab",
  "software": []
}
```

The complete payload may also include process, service, security-event, Defender, and network telemetry collected by the endpoint agent.

---

## Endpoint APIs

### `GET /api/pcs`

Returns endpoint inventory.

### `GET /api/pcs/<pc_name>/metrics`

Returns historical performance metrics for an endpoint.

### `GET /api/pcs/<pc_name>/processes`

Returns current process inventory.

### `GET /api/pcs/<pc_name>/services`

Returns current Windows service inventory.

### `GET /api/pcs/<pc_name>/security`

Returns security events for an endpoint.

### `GET /api/pcs/<pc_name>/connections`

Returns current network connection telemetry.

### `GET /api/pcs/<pc_name>/software`

Returns installed software inventory.

---

## Alert APIs

### `GET /api/alerts`

Returns unresolved/active alert information.

### `POST /api/alerts/<alert_id>/resolve`

Resolves an alert when the authenticated role is allowed to perform the operation.

---

## Risk APIs

### `GET /api/risk`

Returns endpoint risk information.

---

## Threat Intelligence APIs

### `GET /api/threat-intelligence/iocs`

Returns IOC records.

### `GET /api/threat-intelligence/matches`

Returns IOC correlation matches.

IOC types supported by the application include IP, domain, and hash values.

---

## Detection APIs

### `GET /api/detections`

Returns detection records.

### `GET /api/detections/summary`

Returns detection summary information used by the SOC UI.

---

## SOC APIs

### `GET /api/soc/summary`

Returns SOC summary metrics used by the Command Center.

### `GET /api/soc/activity`

Returns SOC activity information.

---

## Ticket APIs

### `POST /api/tickets`

Creates an endpoint-associated ticket.

Example:

```json
{
  "pc_name": "LAB-WIN01",
  "title": "Investigate endpoint alert",
  "description": "Review the security alert and attached evidence."
}
```

---

## Response Conventions

Successful JSON responses generally use an object containing a status/result field and relevant data. Error responses use an `error` message and an appropriate HTTP status code.

For operational integrations, clients should handle:

- `200` successful reads/actions
- `201` creation responses where applicable
- `400` invalid input
- `401` authentication failure
- `403` insufficient role/permission
- `404` missing resource
- `500` unexpected server-side failure

---

## API Security Notes

- Never expose `MONITOR_API_KEY` in frontend JavaScript.
- Never commit `.env` to Git.
- Use HTTPS outside an isolated local environment.
- Rotate endpoint credentials if they are exposed.
- Treat all endpoint telemetry as untrusted input.
