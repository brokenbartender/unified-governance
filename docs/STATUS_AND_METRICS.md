# Status & Metrics

## Health endpoints
- `GET /health` ? lightweight status check.
- `GET /v1/health` ? versioned alias.
- `GET /status/live` ? liveness with server time.
- `GET /status/ready` ? readiness with DB check.

## Metrics
- `GET /metrics` ? Prometheus-style counters/gauges.

### Included metrics
- `ug_orgs_total`
- `ug_users_total`
- `ug_policies_total`
- `ug_resources_total`
- `ug_evaluations_total`
- `ug_evidence_exports_total`
- `ug_webhooks_total`

## Request tracing
All responses include `X-Request-Id` for correlation.
