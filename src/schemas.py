from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class OrgCreate(BaseModel):
    name: str


class Org(OrgCreate):
    id: str
    created_at: str


class ApiKeyCreate(BaseModel):
    name: str


class ApiKey(BaseModel):
    id: str
    org_id: str
    name: str
    created_at: str
    last_used_at: Optional[str] = None


class ApiKeyIssued(ApiKey):
    api_key: str


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
    org_id: str
    created_at: str


class ResourceCreate(BaseModel):
    name: str
    type: str
    attributes: Dict[str, Any] = Field(default_factory=dict)
    source_system: str = "manual"
    external_id: Optional[str] = None


class Resource(ResourceCreate):
    id: str
    org_id: str
    created_at: str


class EvaluationRequest(BaseModel):
    policy_id: str
    principal: str
    action: str
    resource_id: str


class Evaluation(BaseModel):
    id: str
    org_id: str
    policy_id: str
    principal: str
    action: str
    resource_id: str
    decision: str
    rationale: Optional[str] = None
    created_at: str


class EvidenceExport(BaseModel):
    org_id: str
    exported_at: str
    format: str
    signature: str
    evaluations: List[Evaluation]
