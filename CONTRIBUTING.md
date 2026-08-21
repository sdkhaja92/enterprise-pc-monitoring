# Contributing to SOC-enterprise

## Development Principles

1. Preserve existing functionality unless a change is explicitly approved.
2. Do not remove existing SOC modules to simplify implementation.
3. Prefer additive, backward-compatible database changes.
4. Keep endpoint collection separate from server-side security logic.
5. Validate all endpoint-supplied data as untrusted input.
6. Add tests for security-sensitive changes.
7. Never commit secrets, databases, logs, or virtual environments.
8. Keep the analyst UI connected to real backend data; avoid hardcoded production values.

## Before Submitting Changes

Run:

```powershell
python -m compileall app agent tests run.py init_database.py
python -m pytest -q
```

For UI/backend changes, also run the application locally and verify the affected workflow end-to-end.

## Database Changes

Do not drop production tables or delete existing records as part of normal initialization. Use additive schema changes and document any migration requirement.

## Security Changes

Document:

- The threat addressed
- The affected component
- The new control
- Compatibility impact
- Test procedure

Never include real API keys, passwords, endpoint data, or security logs in pull requests.
