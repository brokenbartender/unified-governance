# Terraform (Helm Release)

## Usage
```bash
terraform init
terraform apply \
  -var="kubeconfig_path=~/.kube/config" \
  -var="image_repository=ghcr.io/brokenbartender/unified-governance" \
  -var="evidence_hmac_secret=change-me"
```

## Notes
- This installs the Helm chart into your cluster.
- Provide `db_url` to connect to Postgres.
