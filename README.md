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
Open http://127.0.0.1:8000 for the landing page.

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
- `POST /orgs/{org_id}/break-glass`
- `POST /orgs/{org_id}/sso`
- `GET /orgs/{org_id}/usage`
- `GET /orgs/{org_id}/export`
- `POST /policies`
- `PUT /policies/{policy_id}`
- `GET /policies/{policy_id}/revisions`
- `POST /policies/{policy_id}/rollback`
- `POST /policies/{policy_id}/simulate`
- `GET /policies/{policy_id}/rego`
- `POST /policies/import/rego`
- `POST /policies/generate`
- `GET /policies/{policy_id}/opa`
- `POST /resources`
- `POST /evaluations`
- `GET /evaluations/{id}/replay`
- `POST /enforce`
- `GET /evidence/verify`
- `POST /evidence/retain`
- `GET /evidence/export` (JSON) or `?format=csv` (CSV + signature header)
- `GET /evidence/search` (supports `start`, `end`, `decision`, `policy_id`, `principal`)
- `POST /evidence/attestations`
- `GET /evidence/attestations`
- `GET /connectors`
- `POST /scim/Users`
- `GET /scim/Users`
- `POST /scim/Groups`
- `GET /scim/Groups`
- `POST /webhooks`
- `POST /webhooks/{id}/test`
- `POST /webhooks/{id}/rotate-secret`
- `GET /decision-logs/export`
- `GET /siem/export`
- `POST /catalog/mappings`
- `GET /catalog/mappings`
- `POST /ticketing/exceptions`
- `GET /ticketing/exceptions`
- `GET /abuse/events`
- `POST /maintenance/cleanup`
- `GET /status/live`
- `GET /status/ready`
- `GET /status/synthetic-checks`
- `GET /sla/report`
- `GET /metrics`
- `POST /backups/create`
- `GET /billing/usage`
- `GET /license/status`
- `GET /secrets/status`
- `GET /reports/compliance`
- `GET /evidence/pack`
- `GET /coverage`
- `GET /drift/alerts`
- `GET /policies/bundle`
- `POST /policies/bundle/import`
- `GET /access/query`
- `POST /policies/lint`
- `POST /policies/{policy_id}/simulate/batch`
- `GET /risk/anomalies`
- `GET /evidence/timeline`
- `GET /lineage/resource/{resource_id}`
- `GET /onboarding/checklist`
- `POST /backups/verify`
- `POST /webhooks/rotate-all`
- `POST /orgs/{org_id}/keys/rotate-all`

## SDKs
- Python: `sdk/python`
- TypeScript: `sdk/typescript`

## Integration Guides
- `docs/INTEGRATION_GUIDES.md`

## Status & Metrics
- `docs/STATUS_AND_METRICS.md`

## API Collections
- OpenAPI snapshot: `docs/openapi.json`
- Postman collection: `docs/postman_collection.json`

## IaC
- Helm chart: `iac/helm/unified-governance`
- Terraform: `iac/terraform`

## Trust Badge
- `docs/TRUST_BADGE.md`

## Operational Intelligence
- `docs/OPERATIONAL_INTELLIGENCE.md`
- `docs/MAINTENANCE.md`
- `docs/SYSTEM_STATE.md`
- `docs/CAPABILITIES.md`
- `docs/FEATURE_MATRIX.md`
- `docs/ARCHITECTURE.md`
- `docs/ROI_CALCULATOR.md`
- `docs/PERSONA_SECURITY.md`
- `docs/PERSONA_COMPLIANCE.md`
- `docs/PERSONA_PLATFORM.md`
- `docs/DIFFERENTIATORS.md`
- `docs/PRICING_LICENSING.md`
- `docs/ACQUISITION_DATA_ROOM.md`
- `docs/RISK_REDUCTION_REPORT.md`
- `docs/ENFORCEMENT.md`
- `docs/SECURITY_HARDENING.md`
- `docs/DEPLOYMENT_ENTERPRISE.md`
- `docs/AIRGAP.md`
- `docs/BILLING.md`
- `docs/LICENSE.md`
- `docs/SUPPORT_SLA.md`
- `docs/REFERENCE_ARCHITECTURES.md`
- `docs/COMPLIANCE_REPORTING.md`
- `docs/GATEWAY_INTEGRATIONS.md`
- `docs/BENCHMARKS.md`
- `docs/MARKETPLACE.md`
- `docs/CONTROL_MAPPING_UI.md`

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
