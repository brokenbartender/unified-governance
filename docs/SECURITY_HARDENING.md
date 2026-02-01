# Security Hardening

## Secret Management
- Configure `SECRET_PROVIDER` for external secret stores (Vault/KMS).
- Default is env-based secrets.

## License Enforcement
- Set `LICENSE_STRICT=true` and `LICENSE_KEY` to enforce licensing.

## Abuse Scoring
- Rate-limit buckets emit `abuse_events` for visibility.
- `GET /abuse/events` provides audit logs.

## Secure Defaults
- CSP, HSTS, X-Frame-Options, and no-referrer by default.
