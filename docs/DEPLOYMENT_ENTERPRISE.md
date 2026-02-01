# Enterprise Deployment

## Air-Gapped
- Use offline artifacts and a signed `LICENSE_KEY`.
- See `docs/AIRGAP.md` for step-by-step setup.

## High Availability
- Postgres + optional Redis/MQ for scale.
- Kubernetes via Helm + Terraform in `iac/`.

## Backups
- `POST /backups/create` for SQLite snapshots.
- Production deployments should use managed Postgres backups.
