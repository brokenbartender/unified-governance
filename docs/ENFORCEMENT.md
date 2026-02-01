# Enforcement Boundary

## Modes
- **Decision-only:** caller enforces allow/deny
- **Middleware enforcement:** SDK middleware for FastAPI/Express
- **Gateway enforcement:** Envoy ext?auth compatible endpoint

## Envoy ext-auth example
Point Envoy to `POST /enforce` with JSON body {policy_id, principal, action, resource_id}.

## Risk-based enforcement
`/enforce` applies a risk score. If score >= `RISK_SCORE_THRESHOLD`, it denies even if policy allows.

## Webhook enforcement
`/enforce` supports optional webhook enforcement; the latest enabled webhook can override the decision.
