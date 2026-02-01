# Architecture

## Components
- API service (FastAPI)
- SQLite persistence (policies, resources, evaluations)
- Policy engine (allow/deny with attributes)

## Flow
1. Create policy
2. Register resource
3. Evaluate access decision
4. Store decision as evidence log

## Extensibility
- Swap SQLite for Postgres
- Add connector services for ingestion
- Add evidence export service
