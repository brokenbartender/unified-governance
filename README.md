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

## API Overview
- `POST /policies`
- `POST /resources`
- `POST /evaluations`
- `GET /evaluations`

## Files
- `src/app.py` FastAPI entrypoint
- `src/policy_engine.py` Policy evaluation logic
- `docs/PRD.md` Product requirements

## Notes
This is an MVP scaffold intended for demo, pilot, or acquisition discussions.
