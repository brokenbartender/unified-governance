from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class OrgCreate(BaseModel):
    name: str


class Org(OrgCreate):
    id: str
    created_at: str


class UserCreate(BaseModel):
    email: str
    name: str


class User(UserCreate):
    id: str
    created_at: str


class MembershipCreate(BaseModel):
    user_id: str
    role: str


class Membership(BaseModel):
    id: str
    org_id: str
    user_id: str
    role: str
    created_at: str


class ApiKeyCreate(BaseModel):
    name: str
    scopes: List[str] = Field(default_factory=lambda: ["policies:read", "policies:write", "resources:read", "resources:write", "evaluations:read", "evaluations:write", "evidence:read", "connectors:read"])


class ApiKey(BaseModel):
    id: str
    org_id: str
    name: str
    scopes: List[str]
    created_at: str
    last_used_at: Optional[str] = None
    revoked_at: Optional[str] = None


class ApiKeyIssued(ApiKey):
    api_key: str


class SsoConfigCreate(BaseModel):
    provider: str
    metadata: Dict[str, Any]


class SsoConfig(BaseModel):
    id: str
    org_id: str
    provider: str
    metadata: Dict[str, Any]
    created_at: str


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
    prev_hash: Optional[str] = None
    record_hash: Optional[str] = None


class EvidenceExport(BaseModel):
    org_id: str
    exported_at: str
    format: str
    signature: str
    evaluations: List[Evaluation]


class RetentionStatus(BaseModel):
    retention_days: int
    cutoff_timestamp: str
    deleted_records: int


class OpaPolicyExport(BaseModel):
    policy_id: str
    org_id: str
    rule: Dict[str, Any]
    opa_input: Dict[str, Any]
