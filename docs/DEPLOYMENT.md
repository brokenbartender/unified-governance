# Deployment

## Docker + Postgres
- Start stack: `docker compose up --build`
- App: http://localhost:8000/docs
- DB: postgres://postgres:postgres@localhost:5432/ugov

## Helm (Kubernetes)
```bash
helm install unified-governance ./iac/helm/unified-governance \
  --set image.repository=ghcr.io/brokenbartender/unified-governance \
  --set image.tag=latest \
  --set env.EVIDENCE_HMAC_SECRET=change-me
```

## Terraform (Helm Release)
```bash
cd iac/terraform
terraform init
terraform apply -var="kubeconfig_path=~/.kube/config" \
  -var="image_repository=ghcr.io/brokenbartender/unified-governance" \
  -var="evidence_hmac_secret=change-me"
```

## Environment Variables
- `DB_URL`: Postgres connection string (when set, Postgres is used)
- `DB_PATH`: SQLite path (default when DB_URL is empty)
- `EVIDENCE_HMAC_SECRET`: HMAC secret for evidence exports
- `RETENTION_DAYS`: retention window for evaluations

## Production Notes
- Set a strong `EVIDENCE_HMAC_SECRET`
- Use managed Postgres
- Put API behind TLS + reverse proxy
- Rotate API keys routinely
