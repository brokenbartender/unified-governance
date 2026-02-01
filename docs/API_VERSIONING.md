# API Versioning

## Policy
- All new endpoints should be added under `/v1`.
- Current endpoints remain for backward compatibility.
- Deprecations require 90 days notice.

## Migration
- Add `/v1` routes as wrappers to current handlers.
