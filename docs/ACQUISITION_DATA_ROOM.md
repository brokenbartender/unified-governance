# Acquisition Data Room

## Export Checklist
- Org export bundle via `GET /orgs/{org_id}/export`
- Evidence exports + signatures via `GET /evidence/export`
- Attestation digests via `POST /evidence/attestations`
- Policy revisions via `GET /policies/{id}/revisions`

## Deliverables
- OpenAPI + Postman collections
- Compliance docs and control matrix
- Evidence chain verification report

## Suggested Bundle Contents
- `docs/` full compliance and architecture documentation
- `output/` evidence exports
- `docs/openapi.json` and `docs/postman_collection.json`
