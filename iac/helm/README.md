# Helm Chart

## Install
```bash
helm install unified-governance ./iac/helm/unified-governance \
  --set image.repository=ghcr.io/brokenbartender/unified-governance \
  --set image.tag=latest \
  --set env.EVIDENCE_HMAC_SECRET=change-me
```

## Values
- `env.DB_URL` for Postgres
- `env.RETENTION_DAYS` retention window
