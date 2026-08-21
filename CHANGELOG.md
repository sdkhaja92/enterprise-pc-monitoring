# Changelog

## 1.1.0 — SOC-enterprise Full Integration Upgrade

### Database and compatibility
- Added automatic legacy database detection.
- Existing `data/enterprise.db` is reused when present unless `MONITOR_DB` is explicitly configured.
- Added idempotent, additive schema migrations.
- Added automatic creation/migration of `ai_settings` including `api_key_encrypted`.
- Added persistent `ai_analysis` history.
- Added health/status endpoint.
- Added `upgrade_database.py` verification utility.
- No tables or records are dropped by the upgrade path.

### AI Sentinel
- Ollama local provider.
- llama.cpp / OpenAI-compatible local provider.
- Generic online OpenAI-compatible provider.
- Google Gemini provider.
- Model discovery for supported providers.
- Connection testing with model validation.
- Encrypted API-key storage.
- Online privacy redaction.
- Analyst-triggered alert analysis.
- Analyst-triggered incident analysis.
- AI analysis audit/history.

### SOC workflow
- Alert analysis now receives endpoint risk, recent security events and detections as context.
- Incident analysis now receives timeline, notes, risk, security-event and process evidence.
- AI settings changes are audit logged.

### Operations
- Startup prints the active database path.
- `.env.example` documents database and AI configuration.
- Expanded automated tests for AI schema migration and health reporting.
