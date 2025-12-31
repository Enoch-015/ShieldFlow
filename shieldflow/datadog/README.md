# ShieldFlow Datadog Integration

This directory contains configuration files for integrating ShieldFlow with Datadog for real-time monitoring and alerting.

## Quick Setup

### 1. Set Environment Variables

```bash
export DATADOG_API_KEY=your-api-key
export DATADOG_APP_KEY=your-app-key  # Required for incidents
export DD_SITE=datadoghq.com  # or datadoghq.eu, us5.datadoghq.com
```

Or add to your `.env` file.

### 2. Import Dashboard

```bash
# Using the Datadog API
curl -X POST "https://api.datadoghq.com/api/v1/dashboard" \
  -H "DD-API-KEY: ${DATADOG_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DATADOG_APP_KEY}" \
  -H "Content-Type: application/json" \
  -d @dashboard.json
```

Or manually:
1. Go to Datadog → Dashboards → New Dashboard
2. Click the gear icon → Import Dashboard JSON
3. Paste contents of `dashboard.json`

### 3. Create Monitors

```bash
# Create all monitors
for monitor in $(cat monitors.json | jq -c '.monitors[]'); do
  curl -X POST "https://api.datadoghq.com/api/v1/monitor" \
    -H "DD-API-KEY: ${DATADOG_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DATADOG_APP_KEY}" \
    -H "Content-Type: application/json" \
    -d "$monitor"
done
```

Or use the setup script:
```bash
python setup_datadog.py
```

## Metrics Reference

| Metric | Type | Description |
|--------|------|-------------|
| `shieldflow.trust_score` | gauge | Current trust score per session |
| `shieldflow.detections.count` | count | Number of detections per request |
| `shieldflow.blocks` | count | Blocked requests |
| `shieldflow.masked` | count | Requests with masked content |
| `shieldflow.detection.{type}` | count | Detections by type (pii, prompt_injection, etc.) |

### Detection Types

- `prompt_injection` - Rule-based injection detection
- `prompt_injection_gemini` - AI-powered injection detection
- `pii` - Personal identifiable information
- `sensitive_api_key_gemini` - API keys/credentials
- `sensitive_internal_data_gemini` - Internal company data
- `high_entropy` - Potential data exfiltration

## Tags

All metrics include these tags:
- `service:shieldflow`
- `session_id:{id}` - Unique session identifier
- `stage:{prompt|response|metadata}` - Processing stage
- `action:{allow|allow_masked|block}` - Decision made

## Logs

ShieldFlow sends structured logs to Datadog with:
- Source: `shieldflow`
- Service: `shieldflow`
- All detection details in `shieldflow.*` attributes

### Log Query Examples

```
# All blocks
service:shieldflow status:error

# Prompt injection attempts
service:shieldflow @shieldflow.detections.kind:prompt_injection*

# Specific session
service:shieldflow @shieldflow.session_id:your-session-id

# High-risk sessions (low trust)
service:shieldflow @shieldflow.trust_score:<30
```

## Monitors

| Monitor | Severity | Trigger |
|---------|----------|---------|
| High Block Rate | Warning/Critical | >5/10 blocks in 5 min |
| Trust Score Critical | Critical | Score < 20 |
| Prompt Injection Spike | Critical | >20 attempts in 10 min |
| Sensitive Data Exposure | Critical | Any API key detected |
| PII Data Leak | Warning/Critical | >25/50 PII in 15 min |
| Service Health | Critical | No metrics for 10 min |

## Dashboard Widgets

The pre-built dashboard includes:

1. **Trust Score Over Time** - Line chart per session
2. **Blocks vs Allowed** - Bar chart of actions
3. **Detection Types** - Top 10 detection types
4. **Detections by Stage** - Sunburst chart
5. **Recent Blocks** - Live log stream
6. **KPI Cards** - Injection, PII, Gemini, Sensitive, Active Sessions, Blocks

## Architecture

```
┌─────────────────┐
│   ShieldFlow    │
│   Inspector     │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌───────┐ ┌───────────┐
│ Kafka │ │  Datadog  │
│       │ │  - Metrics│
│       │ │  - Logs   │
│       │ │  - Events │
└───┬───┘ └───────────┘
    │
    ▼
┌───────┐
│ Flink │ ──▶ (Optional: Aggregated metrics)
└───────┘
```

ShieldFlow sends data directly to Datadog (low-latency metrics/logs) AND to Kafka (for Flink processing and long-term storage).
