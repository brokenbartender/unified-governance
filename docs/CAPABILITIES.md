# Capabilities Snapshot (Feb 1, 2026)

This document is a machine-readable summary of the current system capabilities.

## Product Summary
- **Name:** Unified Governance Layer
- **Purpose:** Policy-as-code access governance + evidence/audit engine for data + AI systems.
- **Primary Buyers:** Enterprise security, compliance, platform engineering teams.

## Core Capabilities
- **Multi?tenant org model:** Orgs, users, memberships, teams, roles.
- **Policy engine:** Attribute-based policy evaluation with allow/deny decisions.
- **Evidence chain:** Hash?chained evaluations, verification endpoint, export with HMAC signature.
- **Retention:** Evidence retention + admin cleanup endpoints.
- **Usage metering:** Usage summaries for billing integration.
- **Connectors:** Modular connector SDK + sample connectors (Google Drive, Snowflake, Okta, CloudTrail).
- **Webhooks:** Delivery logs, retries, secret rotation.
- **Admin dashboard:** Policy playground, key management, team view, evidence search, trust badge.
- **Identity:** SSO/SCIM stubs, user provisioning flows.
- **Observability:** Health, readiness, metrics, decision log export + SSE.

## API Surface (High Level)
- **Auth:** API keys, scopes, rotation/revocation.
- **Governance:** /policies, /resources, /evaluations.
- **Evidence:** /evidence/export, /evidence/verify, /evidence/search.
- **Identity:** /orgs, /users, /memberships, /teams, /roles, /scim, /sso.
- **Operational:** /metrics, /status/live, /status/ready, /maintenance/cleanup.
- **Integration:** /connectors, /webhooks.

## Data Model Highlights
- Resources include `source_system`, `external_id`, and AI metadata (`model_type`, `model_provider`, `sensitivity_level`, `is_governed`).
- Evaluations store hash chain (`prev_hash`, `record_hash`) and decision logs.

## Deployment
- **Local:** FastAPI + SQLite
- **Docker:** docker-compose with Postgres
- **IaC:** Helm chart + Terraform (Helm release)

## SDKs
- Python and TypeScript SDKs shipped in `sdk/`.

## Documentation Index
- `docs/CONTROL_MATRIX.md`
- `docs/COMPLIANCE_ALIGNMENT.md`
- `docs/SECURITY_MODEL.md`
- `docs/OPERATIONAL_INTELLIGENCE.md`
- `docs/STATUS_AND_METRICS.md`
- `docs/MAINTENANCE.md`
- `docs/INTEGRATION_GUIDES.md`
- `docs/OPENAPI_EXAMPLES.md`
- `docs/CLI.md`

## Generated Artifacts
- OpenAPI snapshot: `docs/openapi.json`
- Postman collection: `docs/postman_collection.json`
