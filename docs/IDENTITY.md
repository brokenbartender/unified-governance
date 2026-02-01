# Identity & SCIM

## SSO Configuration
- `POST /orgs/{org_id}/sso` stores SAML/OIDC metadata per org
- `GET /orgs/{org_id}/sso` lists configured providers

## SSO Handshake (Skeleton)
- `POST /sso/saml/initiate` returns IdP SSO URL based on stored metadata
- `POST /sso/oidc/initiate` builds authorization URL using stored metadata

## SCIM Endpoints
- `POST /scim/Users` create user
- `GET /scim/Users` list users
- `GET /scim/Users/{id}` get user
- `DELETE /scim/Users/{id}` delete user

## Notes
These are skeleton endpoints intended for enterprise integration demos. Hook into your IdP and enable SCIM auth in production.
