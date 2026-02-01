# Security Model

## Access Control
- Org-level isolation via API keys
- Scoped permissions for policies/resources/evidence/connectors
- Key rotation and revocation endpoints

## RBAC
- Teams and roles with permission sets
- Team memberships assign roles to users

## Evidence Integrity
- Per-record hash chain for evaluations
- HMAC signature for exports
- Evidence export records stored for audit reference
- Chain verification endpoint: `GET /evidence/verify`

## Retention
- Configured via `RETENTION_DAYS`
- Manual enforcement endpoint `POST /evidence/retain`

## SSO
- Configuration stub stored per org
- Intended for SAML/OIDC integration
