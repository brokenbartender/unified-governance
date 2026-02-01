# Identity & SCIM

## SSO Configuration
- `POST /orgs/{org_id}/sso` stores SAML/OIDC metadata per org
- `GET /orgs/{org_id}/sso` lists configured providers

## SCIM Endpoints
- `POST /scim/Users` create user
- `GET /scim/Users` list users
- `GET /scim/Users/{id}` get user
- `DELETE /scim/Users/{id}` delete user

## Notes
These are skeleton endpoints intended for enterprise integration demos. Hook into your IdP and enable SCIM auth in production.
