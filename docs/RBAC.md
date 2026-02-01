# RBAC & Teams

## Overview
RBAC adds teams and role-based permissions within an organization. Roles define permissions and are assigned to users through team memberships.

## Endpoints
- `POST /orgs/{org_id}/teams`
- `GET /orgs/{org_id}/teams`
- `POST /orgs/{org_id}/roles`
- `GET /orgs/{org_id}/roles`
- `POST /orgs/{org_id}/team-memberships`
- `GET /orgs/{org_id}/team-memberships`

## Notes
These endpoints establish the data model for teams and permissions. Enforcement can be layered on top of API keys and user identity.
