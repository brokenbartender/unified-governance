# Maintenance

## Cleanup
`POST /maintenance/cleanup` prunes:
- decision logs older than `DECISION_LOG_RETENTION_DAYS`
- webhook deliveries older than `WEBHOOK_DELIVERY_RETENTION_DAYS`
- evidence exports older than `RETENTION_DAYS`

## Retention
`POST /evidence/retain` deletes evaluations older than `RETENTION_DAYS`.
