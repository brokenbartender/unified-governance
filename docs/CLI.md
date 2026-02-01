# CLI Bootstrap

```bash
python scripts/bootstrap.py --base-url http://127.0.0.1:8000 --api-key YOUR_API_KEY
```

Export a full org bundle:

```bash
python scripts/bootstrap.py --base-url http://127.0.0.1:8000 --api-key YOUR_API_KEY --export-org
```

Validate an evidence export:

```bash
python scripts/validate_audit_bundle.py --file evidence.json --secret YOUR_HMAC_SECRET
```
