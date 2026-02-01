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
    inherits_from: Optional[str] = None


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
    expires_at: Optional[str] = None


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
    deny_principals: List[str] = Field(default_factory=list)
    deny_actions: List[str] = Field(default_factory=list)
    deny_resource_types: List[str] = Field(default_factory=list)
    exception_principals: List[str] = Field(default_factory=list)
    exception_actions: List[str] = Field(default_factory=list)
    exception_resource_types: List[str] = Field(default_factory=list)


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rule: PolicyRule
    inherits_from: Optional[str] = None


class Policy(PolicyCreate):
    id: str
    org_id: str
    created_at: str
    version: int = 1


class PolicyRevision(BaseModel):
    id: str
    policy_id: str
    org_id: str
    version: int
    rule: PolicyRule
    description: Optional[str] = None
    created_at: str
    approved_by: Optional[str] = None
    approval_signature: Optional[str] = None
    rego_text: Optional[str] = None


class PolicyRevisionCreate(BaseModel):
    description: Optional[str] = None
    rule: PolicyRule
    approved_by: Optional[str] = None
    rego_text: Optional[str] = None


class PolicyApproval(BaseModel):
    id: str
    policy_id: str
    org_id: str
    approved_by: str
    comment: Optional[str] = None
    signature: str
    created_at: str


class PolicyApprovalCreate(BaseModel):
    approved_by: str
    comment: Optional[str] = None


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
    rule_snapshot: Optional[Dict[str, Any]] = None
    created_at: str
    prev_hash: Optional[str] = None
    record_hash: Optional[str] = None
    explain: Optional[Dict[str, Any]] = None


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
    total_policies: int
    total_resources: int
    total_webhooks: int
    total_users: int


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
    matched_attributes: Dict[str, Any] = Field(default_factory=dict)


class EvidenceSearchResult(BaseModel):
    evaluations: List[Evaluation]
    total: int


class WebhookCreate(BaseModel):
    url: str
    secret: Optional[str] = None
    enabled: bool = True


class Webhook(BaseModel):
    id: str
    org_id: str
    url: str
    secret: Optional[str] = None
    enabled: bool
    created_at: str


class WebhookDelivery(BaseModel):
    id: str
    webhook_id: str
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    attempts: int = 0
    next_attempt_at: Optional[str] = None
    success: bool = False
    created_at: str


class DecisionLogExport(BaseModel):
    org_id: str
    exported_at: str
    total: int


class OrgExport(BaseModel):
    org: Org
    users: List[User]
    memberships: List[Membership]
    teams: List[Team]
    roles: List[Role]
    team_memberships: List[TeamMembership]
    policies: List[Policy]
    resources: List[Resource]
    api_keys: List[ApiKey]
    webhooks: List[Webhook]
    created_at: str


class OpaPolicyExport(BaseModel):
    policy_id: str
    org_id: str
    rule: Dict[str, Any]
    opa_input: Dict[str, Any]
    rego: Optional[str] = None


class EvidenceAttestation(BaseModel):
    id: str
    org_id: str
    date: str
    record_count: int
    digest: str
    signature: str
    created_at: str


class EvidenceAttestationCreate(BaseModel):
    date: str


class EnforcementRequest(BaseModel):
    policy_id: str
    principal: str
    action: str
    resource_id: str
    risk_threshold: Optional[int] = None
    webhook_enforcement: bool = False
    mfa_verified: bool = False


class BreakGlassResponse(BaseModel):
    api_key: str
    expires_at: str


class EnforcementDecision(BaseModel):
    decision: str
    rationale: str
    risk_score: int
    enforced: bool
    policy_id: str
    resource_id: str
    principal: str
    action: str
    explain: Optional[Dict[str, Any]] = None


class CatalogMapping(BaseModel):
    id: str
    org_id: str
    mapping: Dict[str, Any]
    created_at: str


class CatalogMappingCreate(BaseModel):
    mapping: Dict[str, Any]


class ExceptionRequest(BaseModel):
    id: str
    org_id: str
    resource_id: str
    principal: str
    reason: str
    status: str
    created_at: str


class ExceptionRequestCreate(BaseModel):
    resource_id: str
    principal: str
    reason: str


class AbuseEvent(BaseModel):
    id: str
    org_id: str
    bucket: str
    score: int
    reason: str
    created_at: str


class BillingUsage(BaseModel):
    org_id: str
    period: str
    total_evaluations: int
    total_evidence_stored_mb: float
    active_api_keys: int
    estimated_cost: float


class LicenseStatus(BaseModel):
    status: str
    detail: str | None = None


class ComplianceReport(BaseModel):
    org_id: str
    generated_at: str
    controls: Dict[str, Any]


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


class ScimGroup(BaseModel):
    id: str
    displayName: str
    members: List[Dict[str, Any]] = Field(default_factory=list)


class ScimGroupCreate(BaseModel):
    displayName: str
    members: List[Dict[str, Any]] = Field(default_factory=list)


class ScimGroupListResponse(BaseModel):
    totalResults: int
    itemsPerPage: int
    startIndex: int
    Resources: List[ScimGroup]
