# Roadmap

## Phase 1: MVP (2-4 weeks)
- Core API: orgs, keys, policies, resources, evaluations
- SQLite-based persistence
- Policy engine v0 (allow/deny)
- Evidence export (JSON/CSV + HMAC signature)
- Connector SDK + sample connectors

## Phase 2: Evidence Packs (4-6 weeks)
- Signed evaluation bundles
- Framework mapping templates (SOC2, ISO)

## Phase 3: Connectors (6-10 weeks)
- Connector SDK pattern hardened
- First 2 production connectors (e.g., Snowflake + Google Drive)
- Event ingestion webhook

## Phase 4: Enterprise Readiness (10-14 weeks)
- Multi-tenant hardening
- SSO (SAML/OIDC)
- RBAC for policies
