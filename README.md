# Unified Governance Layer

Drop-in policy-as-code and evidence engine for third-party + AI data access governance.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn src.app:app --reload
```

Open http://127.0.0.1:8000/docs for the API UI.

## Auth Flow
1. Create org: `POST /orgs`
2. Create API key: `POST /orgs/{org_id}/keys`
3. Use header: `X-API-Key: <key>` for all protected endpoints

## API Overview
- `POST /orgs`
- `POST /orgs/{org_id}/keys`
- `POST /policies`
- `POST /resources`
- `POST /evaluations`
- `GET /evaluations`
- `GET /evidence/export` (JSON) or `?format=csv` (CSV + signature header)
- `GET /connectors`

## Files
- `src/app.py` FastAPI entrypoint
- `src/policy_engine.py` Policy evaluation logic
- `docs/PRD.md` Product requirements

## Notes
This is an MVP scaffold intended for demo, pilot, or acquisition discussions.
