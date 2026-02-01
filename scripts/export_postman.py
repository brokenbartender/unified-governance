import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.app import app


def build_postman_collection(spec: dict) -> dict:
    items = []
    for path, methods in spec.get("paths", {}).items():
        for method, operation in methods.items():
            if method.startswith("x-"):
                continue
            name = operation.get("summary") or f"{method.upper()} {path}"
            params = []
            for param in operation.get("parameters", []):
                if param.get("in") == "query":
                    params.append({"key": param.get("name"), "value": ""})
            url = {
                "raw": "{{base_url}}" + path,
                "host": ["{{base_url}}"],
                "path": [p for p in path.split("/") if p],
            }
            if params:
                url["query"] = params
            request = {
                "method": method.upper(),
                "header": [
                    {"key": "X-API-Key", "value": "{{api_key}}"},
                    {"key": "Content-Type", "value": "application/json"},
                ],
                "url": url,
            }
            if operation.get("requestBody"):
                request["body"] = {
                    "mode": "raw",
                    "raw": "{}",
                }
            items.append({"name": name, "request": request, "response": []})
    return {
        "info": {
            "name": "Unified Governance Layer",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "variable": [
            {"key": "base_url", "value": "http://127.0.0.1:8000"},
            {"key": "api_key", "value": ""},
        ],
        "item": items,
    }


def main() -> None:
    spec = app.openapi()
    collection = build_postman_collection(spec)
    with open("docs/postman_collection.json", "w", encoding="utf-8") as handle:
        json.dump(collection, handle, indent=2)
    print("Wrote docs/postman_collection.json")


if __name__ == "__main__":
    main()
