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


class TeamCreate(BaseModel):
    name: str
    description: Optional[str] = None


class Team(TeamCreate):
    id: str
    org_id: str
    created_at: str


class RoleCreate(BaseModel):
    name: str
    permissions: List[str] = Field(default_factory=list)


class Role(RoleCreate):
    id: str
    org_id: str
    created_at: str


class TeamMembershipCreate(BaseModel):
    user_id: str
    team_id: str
    role_id: str


class TeamMembership(BaseModel):
    id: str
    org_id: str
    user_id: str
    team_id: str
    role_id: str
    created_at: str


class ApiKeyCreate(BaseModel):
    name: str
    scopes: List[str] = Field(
        default_factory=lambda: [
            "orgs:read",
            "orgs:write",
            "policies:read",
            "policies:write",
            "resources:read",
            "resources:write",
            "evaluations:read",
            "evaluations:write",
            "evidence:read",
            "evidence:write",
            "connectors:read",
            "scim:read",
            "scim:write",
            "sso:read",
            "sso:write",
            "rbac:read",
            "rbac:write",
        ]
    )


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


class SamlAuthRequest(BaseModel):
    org_id: str
    relay_state: Optional[str] = None


class SamlAuthResponse(BaseModel):
    org_id: str
    provider: str
    sso_url: str
    relay_state: Optional[str] = None


class OidcAuthRequest(BaseModel):
    org_id: str
    redirect_uri: str
    state: str


class OidcAuthResponse(BaseModel):
    org_id: str
    provider: str
    authorization_url: str


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


class AiMetadata(BaseModel):
    model_type: Optional[str] = None
    model_provider: Optional[str] = None
    sensitivity_level: Optional[int] = None
    is_governed: Optional[bool] = None


class ResourceCreate(BaseModel):
    name: str
    type: str
    attributes: Dict[str, Any] = Field(default_factory=dict)
    source_system: str = "manual"
    external_id: Optional[str] = None
    ai_metadata: Optional[AiMetadata] = None


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
    export_id: str
    org_id: str
    exported_at: str
    format: str
    signature: str
    evaluations: List[Evaluation]


class RetentionStatus(BaseModel):
    retention_days: int
    cutoff_timestamp: str
    deleted_records: int


class EvidenceVerifyResult(BaseModel):
    valid: bool
    checked_records: int
    last_hash: Optional[str] = None


class UsageSummary(BaseModel):
    org_id: str
    period: str
    total_evaluations: int
    total_evidence_stored_mb: float
    active_api_keys: int


class TrustCheck(BaseModel):
    created_at: str
    valid: bool
    checked_records: int


class PlaygroundRequest(BaseModel):
    principal: str
    action: str
    resource_id: str


class PlaygroundDecision(BaseModel):
    policy_id: str
    decision: str
    rationale: str


class OpaPolicyExport(BaseModel):
    policy_id: str
    org_id: str
    rule: Dict[str, Any]
    opa_input: Dict[str, Any]


class ScimUser(BaseModel):
    id: str
    userName: str
    name: Dict[str, Any]
    emails: List[Dict[str, Any]]
    active: bool = True


class ScimUserCreate(BaseModel):
    userName: str
    name: Dict[str, Any]
    emails: List[Dict[str, Any]]
    active: bool = True


class ScimListResponse(BaseModel):
    totalResults: int
    itemsPerPage: int
    startIndex: int
    Resources: List[ScimUser]
