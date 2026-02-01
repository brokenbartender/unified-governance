# Architecture Overview

## Runtime
- FastAPI application (`src/app.py`)
- SQLite by default, Postgres optional
- Modular connectors for external systems

## Flow
1. **Org + API key** created.
2. **Policy** defines allowed principals/actions/resource constraints.
3. **Resource** registered with source metadata and AI attributes.
4. **Evaluation** performs policy decision and stores evidence chain.
5. **Evidence** exported and verified with HMAC signatures.

## Evidence Integrity
- Each evaluation includes `record_hash` chained to the previous record.
- Hashing uses SHA-256 over the serialized record plus the previous hash.
- Verification endpoint recomputes chain to ensure tamper-evidence.
- Export signatures use HMAC-SHA256 over JSON or CSV payloads.

## Admin Surface
- `/admin` exposes key management, policy playground, evidence search, trust badge.

## Observability
- `/metrics` for Prometheus scraping.
- `/status/live` and `/status/ready` for liveness/readiness probes.

## Enforcement Boundary
- The system returns policy decisions and evidence.
- Enforcement is implemented by the caller (gateway/proxy/app) using the decision results or via webhooks.

## Deployment
- Docker + Postgres (docker compose)
- Helm chart for Kubernetes
- Terraform for Helm install
