# Architecture

## Components
- API service (FastAPI)
- SQLite persistence (orgs, users, memberships, api keys, policies, resources with external IDs, evaluations)
- Policy engine (allow/deny with attributes)
- Evidence export (JSON/CSV with HMAC signature + hash chain)
- Retention enforcement (configurable days)

## Flow
1. Create org + API key
2. Create user + membership
3. Create policy
4. Register resource
5. Evaluate access decision
6. Store decision as evidence log
7. Export evidence pack

## Extensibility
- Swap SQLite for Postgres
- Add connector services for ingestion
- Add evidence export service
- Add SSO/SCIM and RBAC enforcement
