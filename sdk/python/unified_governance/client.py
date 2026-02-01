from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, Optional


class Client:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None):
        url = f"{self.base_url}{path}"
        headers = {"X-API-Key": self.api_key}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return json.loads(content) if content else None

    def create_policy(self, name: str, rule: Dict[str, Any], description: str | None = None):
        return self._request(
            "POST",
            "/policies",
            {"name": name, "description": description, "rule": rule},
        )

    def list_policies(self):
        return self._request("GET", "/policies")

    def create_resource(self, name: str, type_: str, attributes: Dict[str, Any], source_system: str = "manual", external_id: str | None = None):
        return self._request(
            "POST",
            "/resources",
            {
                "name": name,
                "type": type_,
                "attributes": attributes,
                "source_system": source_system,
                "external_id": external_id,
            },
        )

    def evaluate(self, policy_id: str, principal: str, action: str, resource_id: str):
        return self._request(
            "POST",
            "/evaluations",
            {
                "policy_id": policy_id,
                "principal": principal,
                "action": action,
                "resource_id": resource_id,
            },
        )

    def export_evidence(self):
        return self._request("GET", "/evidence/export")

    def verify_evidence(self):
        return self._request("GET", "/evidence/verify")
