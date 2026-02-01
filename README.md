# Unified Governance Layer

Drop-in policy-as-code and evidence engine for third-party + AI data access governance.

## Quick Start (Local)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn src.app:app --reload
```

Open http://127.0.0.1:8000/docs for the API UI.
Open http://127.0.0.1:8000/admin for the admin dashboard.

## Quick Start (Docker + Postgres)

```powershell
docker compose up --build
```

Open http://127.0.0.1:8000/docs for the API UI.
Open http://127.0.0.1:8000/admin for the admin dashboard.

## Auth Flow
1. Create org: `POST /orgs`
2. Create API key: `POST /orgs/{org_id}/keys`
3. Use header: `X-API-Key: <key>` for all protected endpoints

## API Overview
- `POST /orgs`
- `POST /users`
- `POST /orgs/{org_id}/memberships`
- `POST /orgs/{org_id}/teams`
- `POST /orgs/{org_id}/roles`
- `POST /orgs/{org_id}/team-memberships`
- `POST /orgs/{org_id}/keys`
- `POST /orgs/{org_id}/keys/{key_id}/rotate`
- `POST /orgs/{org_id}/keys/{key_id}/revoke`
- `POST /orgs/{org_id}/sso`
- `POST /orgs/{org_id}/usage`
- `POST /policies`
- `POST /policies/generate`
- `GET /policies/{policy_id}/opa`
- `POST /resources`
- `POST /evaluations`
- `GET /evidence/verify`
- `POST /evidence/retain`
- `GET /evidence/export` (JSON) or `?format=csv` (CSV + signature header)
- `GET /evidence/search`
- `GET /connectors`
- `POST /scim/Users`
- `GET /scim/Users`
- `POST /webhooks`
- `POST /webhooks/{id}/test`
- `GET /decision-logs/export`

## SDKs
- Python: `sdk/python`
- TypeScript: `sdk/typescript`

## Integration Guides
- `docs/INTEGRATION_GUIDES.md`

## IaC
- Helm chart: `iac/helm/unified-governance`
- Terraform: `iac/terraform`

## Trust Badge
- `docs/TRUST_BADGE.md`

## Operational Intelligence
- `docs/OPERATIONAL_INTELLIGENCE.md`

## Compliance Docs
- `docs/CONTROL_MATRIX.md`
- `docs/COMPLIANCE_ALIGNMENT.md`
- `docs/SECURITY_MODEL.md`
- `docs/RBAC.md`

## Files
- `src/app.py` FastAPI entrypoint
- `src/policy_engine.py` Policy evaluation logic
- `docs/PRD.md` Product requirements
- `docs/IDENTITY.md` SSO/SCIM notes

## Notes
This is an MVP scaffold intended for demo, pilot, or acquisition discussions.
