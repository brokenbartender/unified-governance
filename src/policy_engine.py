from __future__ import annotations

from typing import Any, Dict

from .schemas import PolicyRule, Resource


def _matches(value: str, allowed: list[str]) -> bool:
    return "*" in allowed or value in allowed


def _attributes_match(required: Dict[str, Any], actual: Dict[str, Any]) -> bool:
    for key, required_value in required.items():
        if key not in actual:
            return False
        if actual[key] != required_value:
            return False
    return True


def evaluate_policy(rule: PolicyRule, principal: str, action: str, resource: Resource) -> tuple[str, str]:
    if not _matches(principal, rule.allowed_principals):
        return "deny", "Principal not allowed"
    if not _matches(action, rule.allowed_actions):
        return "deny", "Action not allowed"
    if not _matches(resource.type, rule.resource_types):
        return "deny", "Resource type not allowed"
    if not _attributes_match(rule.required_attributes, resource.attributes):
        return "deny", "Resource attributes do not satisfy policy"
    return "allow", "Policy conditions satisfied"
