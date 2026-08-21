# SOC-enterprise AI Integration

## Purpose

The AI integration is an optional analyst copilot. It does not automatically send endpoint telemetry to an AI provider and it does not replace deterministic detection, risk scoring, or incident workflows.

## Supported providers

### Ollama

Local model server. Typical URL:

```text
http://127.0.0.1:11434
```

The application uses Ollama's `/api/chat` endpoint.

### llama.cpp

Local llama.cpp server exposing an OpenAI-compatible API. Typical URL:

```text
http://127.0.0.1:8080/v1
```

The application uses `/chat/completions`.

### OpenAI-compatible online API

This generic option can be used with OpenAI or compatible services such as OpenRouter/Groq when their endpoint follows the OpenAI Chat Completions contract.

Example base URL:

```text
https://api.openai.com/v1
```

### Google Gemini

Online Gemini API using the Generative Language API. Configure the API base URL, model and API key in the UI.

## Configuration

Open:

```text
Dashboard → AI Settings
```

The settings page provides:

- Enable / disable AI Sentinel
- Provider selection
- Base URL
- Model
- API key
- Request timeout
- Privacy Mode
- Connection test

The API key is encrypted in the SQLite database using a Fernet key derived from the Flask `SECRET_KEY`. If the application secret changes, previously encrypted AI keys cannot be decrypted and must be configured again.

## Privacy model

AI is analyst-triggered. The platform does not automatically forward endpoint telemetry to the configured provider.

For online providers, Privacy Mode is enabled by default and redacts common IP addresses and user/account fields from the analysis context. Review your organization's data-handling policy before sending security evidence to any external service.

For the strongest data-locality model, use Ollama or llama.cpp on infrastructure you control.

## Analyst workflows

### Alert analysis

From Alert Center:

```text
Alert
 ↓
AI Analyze
 ↓
Assessment
Evidence
Risk
Investigation
False-positive checks
```

### Incident analysis

From an incident case:

```text
Incident
 ↓
AI Analyze Incident
 ↓
Timeline + evidence + notes
 ↓
Analyst-oriented assessment
```

The AI response is advisory. Analysts remain responsible for validation and response decisions.

## Environment variables

Provider settings can be configured in the UI. Optional environment placeholders are documented in `.env.example`.

```text
AI_PROVIDER=ollama
AI_BASE_URL=http://127.0.0.1:11434
AI_MODEL=llama3.2
AI_API_KEY=
AI_TIMEOUT=60
AI_PRIVACY_MODE=1
```

These variables are documented as deployment placeholders; the current UI stores provider settings in the application database.

## Database compatibility and migration

SOC-enterprise uses an additive migration strategy. On startup it:

1. Uses `MONITOR_DB` when explicitly configured.
2. Otherwise reuses an existing `data/enterprise.db` legacy database when present.
3. Creates the current default database only when no existing database is found.
4. Creates missing AI tables/columns such as `api_key_encrypted` without dropping or recreating existing tables.
5. Preserves existing endpoint, alert, incident, ticket, IOC and audit data.

Use `python upgrade_database.py` to verify the active database and AI schema.
