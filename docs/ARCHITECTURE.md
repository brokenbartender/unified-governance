# Architecture

## Components
- API service (FastAPI)
- SQLite persistence (orgs, api keys, policies, resources, evaluations)
- Policy engine (allow/deny with attributes)
- Evidence export (JSON/CSV with HMAC signature)

## Flow
1. Create org + API key
2. Create policy
3. Register resource
4. Evaluate access decision
5. Store decision as evidence log
6. Export evidence pack

## Extensibility
- Swap SQLite for Postgres
- Add connector services for ingestion
- Add evidence export service
- Add SSO/SCIM and RBAC
