# Pitch Deck Outline (Acquisition)

## 1. Title
- Unified Governance Layer
- Tagline: Policy-as-code + evidence engine for third-party and AI data access

## 2. Problem
- Enterprises lack a single, enforceable view of vendor and AI data access
- Audits are slow, fragmented, and costly

## 3. Solution
- Drop-in service that enforces policies and generates audit-ready evidence
- API-first, connector-ready

## 4. Product Snapshot
- Org isolation + API key scopes
- Policy engine (allow/deny)
- Evidence export with HMAC signatures
- Hash chain for integrity
- Connector SDK
- OPA export

## 5. Architecture
- FastAPI microservice
- SQLite/Postgres support
- Evidence chain and retention

## 6. Differentiation
- Evidence integrity (hash chain + export signature)
- External ID tracking for sync stability
- Acquisition-ready integration surface

## 7. Compliance Alignment
- SOC2 Security partial coverage (access, logging, integrity)
- ISO 27001 Annex A partial coverage
- NIST AI RMF Govern/Measure foundations

## 8. Go-To-Integration
- Minimal integration steps
- Connector SDK pattern
- SCIM/SSO stubs

## 9. Roadmap (Next 90 Days)
- SSO enforcement
- Monitoring/alerting
- Incident response runbooks
- More production connectors

## 10. Ask
- Acquisition or strategic partnership
- Integrate as governance module within 60-90 days
