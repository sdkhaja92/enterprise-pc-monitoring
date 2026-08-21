# Database Migration and Compatibility

## Upgrade principle

SOC-enterprise uses **additive, non-destructive migrations**. The upgrade path does not drop tables, delete records, or replace an existing database automatically.

## Database selection order

1. `MONITOR_DB` environment variable, when explicitly set.
2. Existing `data/enterprise.db` legacy database.
3. Existing root `enterprise.db` legacy database.
4. Existing `data/enterprise_monitoring.db`.
5. New `data/enterprise_monitoring.db` when no database exists.

This prevents the common failure where a new application version silently creates a second empty database while the operator is looking at the original data.

## AI schema migration

The application ensures the `ai_settings` table exists and adds missing columns, including:

- `api_key_encrypted`
- `provider`
- `base_url`
- `model`
- `timeout`
- `privacy_mode`
- `updated_at`

The `ai_analysis` history table is also created if missing.

## Verify an installation

```powershell
python upgrade_database.py
```

Then:

```text
http://127.0.0.1:5000/health
```

A healthy installation reports:

```json
{
  "status": "ok",
  "ai_schema_ok": true
}
```

## Safety

Before a major upgrade, create your own backup copy of the SQLite database. The application itself does not delete or replace it during normal startup migration.
