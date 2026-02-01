# Gateway Integrations

## Envoy ext-auth
- Send authz requests to `/enforce`
- Expect JSON response with `decision` allow/deny

## NGINX (auth_request)
- Proxy auth to `/enforce` using internal location

Templates for Envoy and NGINX can be added in `iac/`.
