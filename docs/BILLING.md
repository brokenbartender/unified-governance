# Billing & Usage

## Usage Endpoint
- `GET /orgs/{org_id}/usage` returns raw counts.
- `GET /billing/usage?org_id=...` returns estimated cost.

## Cost Model (default)
- $0.00001 per evaluation
- $0.02 per MB evidence storage
- $0.10 per active API key
