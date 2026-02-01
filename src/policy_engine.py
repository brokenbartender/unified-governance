from __future__ import annotations

from typing import Any, Dict

from .schemas import PolicyRule, Resource


def _matches(value: str, allowed: list[str]) -> bool:
    return "*" in allowed or value in allowed


def _matches_any(value: str, candidates: list[str]) -> bool:
    return value in candidates


def _attributes_match(required: Dict[str, Any], actual: Dict[str, Any]) -> bool:
    for key, required_value in required.items():
        if key not in actual:
            return False
        if actual[key] != required_value:
            return False
    return True


def evaluate_policy(rule: PolicyRule, principal: str, action: str, resource: Resource) -> tuple[str, str, dict]:
    combined_attributes = dict(resource.attributes)
    if resource.ai_metadata:
        combined_attributes.update(resource.ai_metadata)
    deny_match = any(
        [
            _matches_any(principal, rule.deny_principals),
            _matches_any(action, rule.deny_actions),
            _matches_any(resource.type, rule.deny_resource_types),
        ]
    )
    exception_match = any(
        [
            _matches_any(principal, rule.exception_principals),
            _matches_any(action, rule.exception_actions),
            _matches_any(resource.type, rule.exception_resource_types),
        ]
    )
    allowed_principal = _matches(principal, rule.allowed_principals)
    allowed_action = _matches(action, rule.allowed_actions)
    allowed_resource = _matches(resource.type, rule.resource_types)
    attributes_match = _attributes_match(rule.required_attributes, combined_attributes)

    explain = {
        "allowed_principal": allowed_principal,
        "allowed_action": allowed_action,
        "allowed_resource": allowed_resource,
        "attributes_match": attributes_match,
        "deny_match": deny_match,
        "exception_match": exception_match,
    }

    if deny_match and not exception_match:
        return "deny", "Explicit deny rule matched", explain
    if exception_match:
        return "allow", "Exception override", explain
    if not allowed_principal:
        return "deny", "Principal not allowed", explain
    if not allowed_action:
        return "deny", "Action not allowed", explain
    if not allowed_resource:
        return "deny", "Resource type not allowed", explain
    if not attributes_match:
        return "deny", "Resource attributes do not satisfy policy", explain
    return "allow", "Policy conditions satisfied", explain
