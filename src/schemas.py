from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PolicyRule(BaseModel):
    allowed_principals: List[str] = Field(default_factory=lambda: ["*"])
    allowed_actions: List[str] = Field(default_factory=lambda: ["*"])
    resource_types: List[str] = Field(default_factory=lambda: ["*"])
    required_attributes: Dict[str, Any] = Field(default_factory=dict)


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rule: PolicyRule


class Policy(PolicyCreate):
    id: str
    created_at: str


class ResourceCreate(BaseModel):
    name: str
    type: str
    attributes: Dict[str, Any] = Field(default_factory=dict)


class Resource(ResourceCreate):
    id: str
    created_at: str


class EvaluationRequest(BaseModel):
    policy_id: str
    principal: str
    action: str
    resource_id: str


class Evaluation(BaseModel):
    id: str
    policy_id: str
    principal: str
    action: str
    resource_id: str
    decision: str
    rationale: Optional[str] = None
    created_at: str
