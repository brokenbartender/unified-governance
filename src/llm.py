from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict

from .settings import settings


def generate_policy_from_text(prompt: str) -> Dict[str, Any] | None:
    if not settings.openai_api_key:
        return None
    payload = {
        "model": settings.openai_model,
        "input": [
            {
                "role": "system",
                "content": "You generate policy JSON for an access control engine. Return ONLY valid JSON.",
            },
            {
                "role": "user",
                "content": f"Generate a policy JSON with fields name, description, rule (allowed_principals, allowed_actions, resource_types, required_attributes) from: {prompt}",
            },
        ],
        "temperature": 0.2,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.openai_api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read().decode("utf-8")
    response = json.loads(raw)
    text = ""
    for item in response.get("output", []):
        for content in item.get("content", []):
            if content.get("type") == "output_text":
                text += content.get("text", "")
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
