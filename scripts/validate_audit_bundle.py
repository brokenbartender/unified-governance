import argparse
import hashlib
import hmac
import json


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, help="Path to JSON evidence export")
    parser.add_argument("--secret", required=True, help="HMAC secret")
    args = parser.parse_args()

    with open(args.file, "r", encoding="utf-8") as handle:
        payload = handle.read()
    try:
        json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON: {exc}")

    signature = hmac.new(args.secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    content_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    print(json.dumps({"content_hash": content_hash, "signature": signature}, indent=2))


if __name__ == "__main__":
    main()
