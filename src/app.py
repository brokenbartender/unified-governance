from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import secrets
import uuid
from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, Header, HTTPException, Response

from .connectors.base import get_connector, list_connectors
from .connectors import google_drive  # noqa: F401
from .connectors import snowflake  # noqa: F401
from .db import get_conn, init_db, now_iso, parse_json_field, row_to_dict, dump_json_field
from .policy_engine import evaluate_policy
from .schemas import (
    ApiKey,
    ApiKeyCreate,
    ApiKeyIssued,
    Evaluation,
    EvaluationRequest,
    EvidenceExport,
    Membership,
    MembershipCreate,
    Org,
    OrgCreate,
    OpaPolicyExport,
    Policy,
    PolicyCreate,
    PolicyRule,
    Resource,
    ResourceCreate,
    RetentionStatus,
    ScimListResponse,
    ScimUser,
    ScimUserCreate,
    SsoConfig,
    SsoConfigCreate,
    User,
    UserCreate,
)
from .settings import settings

app = FastAPI(title=settings.app_name)


@app.on_event("startup")
def _startup() -> None:
    init_db()


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _hash_record(payload: dict, prev_hash: str | None) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    joined = f"{prev_hash or ''}:{data}".encode("utf-8")
    return hashlib.sha256(joined).hexdigest()


def _get_key_row(raw_key: str | None) -> dict:
    if not raw_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    key_hash = _hash_key(raw_key)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ?",
            (key_hash,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid API key")
        if row["revoked_at"]:
            raise HTTPException(status_code=401, detail="API key revoked")
        conn.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
            (now_iso(), row["id"]),
        )
    return row_to_dict(row)


def _require_org_and_scopes(scopes: list[str]):
    def _dependency(x_api_key: str | None = Header(default=None)) -> dict:
        key_row = _get_key_row(x_api_key)
        key_scopes = parse_json_field(key_row["scopes_json"]) or []
        missing = [scope for scope in scopes if scope not in key_scopes]
        if missing:
            raise HTTPException(status_code=403, detail=f"Missing scopes: {','.join(missing)}")
        return key_row

    return _dependency


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/orgs", response_model=Org)
def create_org(payload: OrgCreate) -> Org:
    org_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO orgs (id, name, created_at) VALUES (?, ?, ?)",
            (org_id, payload.name, created_at),
        )
    return Org(id=org_id, created_at=created_at, **payload.model_dump())


@app.post("/users", response_model=User)
def create_user(payload: UserCreate) -> User:
    user_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (id, email, name, created_at) VALUES (?, ?, ?, ?)",
            (user_id, payload.email, payload.name, created_at),
        )
    return User(id=user_id, created_at=created_at, **payload.model_dump())


@app.post("/orgs/{org_id}/memberships", response_model=Membership)
def create_membership(
    org_id: str,
    payload: MembershipCreate,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:write"])),
) -> Membership:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    membership_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO org_memberships (id, org_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (membership_id, org_id, payload.user_id, payload.role, created_at),
        )
    return Membership(
        id=membership_id,
        org_id=org_id,
        user_id=payload.user_id,
        role=payload.role,
        created_at=created_at,
    )


@app.post("/orgs/{org_id}/keys", response_model=ApiKeyIssued)
def create_api_key(org_id: str, payload: ApiKeyCreate) -> ApiKeyIssued:
    api_key = secrets.token_urlsafe(32)
    key_id = str(uuid.uuid4())
    created_at = now_iso()
    key_hash = _hash_key(api_key)
    with get_conn() as conn:
        org_row = conn.execute("SELECT id FROM orgs WHERE id = ?", (org_id,)).fetchone()
        if not org_row:
            raise HTTPException(status_code=404, detail="Org not found")
        conn.execute(
            "INSERT INTO api_keys (id, org_id, name, key_hash, scopes_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (key_id, org_id, payload.name, key_hash, dump_json_field(payload.scopes), created_at),
        )
    return ApiKeyIssued(
        id=key_id,
        org_id=org_id,
        name=payload.name,
        scopes=payload.scopes,
        created_at=created_at,
        last_used_at=None,
        revoked_at=None,
        api_key=api_key,
    )


@app.post("/orgs/{org_id}/keys/{key_id}/rotate", response_model=ApiKeyIssued)
def rotate_api_key(
    org_id: str,
    key_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:write"])),
) -> ApiKeyIssued:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    api_key = secrets.token_urlsafe(32)
    created_at = now_iso()
    key_hash = _hash_key(api_key)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE id = ? AND org_id = ?",
            (key_id, org_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="API key not found")
        conn.execute(
            "UPDATE api_keys SET key_hash = ?, revoked_at = NULL WHERE id = ?",
            (key_hash, key_id),
        )
    return ApiKeyIssued(
        id=key_id,
        org_id=org_id,
        name=row["name"],
        scopes=parse_json_field(row["scopes_json"]) or [],
        created_at=row["created_at"],
        last_used_at=row["last_used_at"],
        revoked_at=None,
        api_key=api_key,
    )


@app.post("/orgs/{org_id}/keys/{key_id}/revoke", response_model=ApiKey)
def revoke_api_key(
    org_id: str,
    key_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:write"])),
) -> ApiKey:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    revoked_at = now_iso()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE id = ? AND org_id = ?",
            (key_id, org_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="API key not found")
        conn.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ?",
            (revoked_at, key_id),
        )
    data = row_to_dict(row)
    return ApiKey(
        id=data["id"],
        org_id=data["org_id"],
        name=data["name"],
        scopes=parse_json_field(data["scopes_json"]) or [],
        created_at=data["created_at"],
        last_used_at=data["last_used_at"],
        revoked_at=revoked_at,
    )


@app.get("/orgs/{org_id}/keys", response_model=list[ApiKey])
def list_api_keys(org_id: str, key_row: dict = Depends(_require_org_and_scopes(["orgs:read"]))) -> list[ApiKey]:
    if org_id != key_row["org_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, org_id, name, scopes_json, created_at, last_used_at, revoked_at FROM api_keys WHERE org_id = ?",
            (org_id,),
        ).fetchall()
    return [
        ApiKey(
            id=row["id"],
            org_id=row["org_id"],
            name=row["name"],
            scopes=parse_json_field(row["scopes_json"]) or [],
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            revoked_at=row["revoked_at"],
        )
        for row in rows
    ]


@app.post("/orgs/{org_id}/sso", response_model=SsoConfig)
def create_sso_config(
    org_id: str,
    payload: SsoConfigCreate,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:write"])),
) -> SsoConfig:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    config_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sso_configs (id, org_id, provider, metadata_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (config_id, org_id, payload.provider, dump_json_field(payload.metadata), created_at),
        )
    return SsoConfig(
        id=config_id,
        org_id=org_id,
        provider=payload.provider,
        metadata=payload.metadata,
        created_at=created_at,
    )


@app.get("/orgs/{org_id}/sso", response_model=list[SsoConfig])
def list_sso_configs(
    org_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:read"])),
) -> list[SsoConfig]:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM sso_configs WHERE org_id = ?",
            (org_id,),
        ).fetchall()
    return [
        SsoConfig(
            id=row["id"],
            org_id=row["org_id"],
            provider=row["provider"],
            metadata=parse_json_field(row["metadata_json"]),
            created_at=row["created_at"],
        )
        for row in rows
    ]


@app.post("/scim/Users", response_model=ScimUser)
def scim_create_user(
    payload: ScimUserCreate,
    key_row: dict = Depends(_require_org_and_scopes(["scim:write"])),
) -> ScimUser:
    _ = key_row
    user_id = str(uuid.uuid4())
    created_at = now_iso()
    email = payload.userName
    display_name = payload.name.get("formatted") or payload.name.get("givenName") or payload.userName
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (id, email, name, created_at) VALUES (?, ?, ?, ?)",
            (user_id, email, display_name, created_at),
        )
    return ScimUser(
        id=user_id,
        userName=payload.userName,
        name=payload.name,
        emails=payload.emails,
        active=payload.active,
    )


@app.get("/scim/Users", response_model=ScimListResponse)
def scim_list_users(
    startIndex: int = 1,
    count: int = 100,
    key_row: dict = Depends(_require_org_and_scopes(["scim:read"])),
) -> ScimListResponse:
    _ = key_row
    offset = max(startIndex - 1, 0)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (count, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) as total FROM users").fetchone()
    users = [
        ScimUser(
            id=row["id"],
            userName=row["email"],
            name={"formatted": row["name"]},
            emails=[{"value": row["email"], "primary": True}],
            active=True,
        )
        for row in rows
    ]
    total_results = total["total"] if isinstance(total, dict) else total[0]
    return ScimListResponse(
        totalResults=total_results,
        itemsPerPage=count,
        startIndex=startIndex,
        Resources=users,
    )


@app.get("/scim/Users/{user_id}", response_model=ScimUser)
def scim_get_user(
    user_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["scim:read"])),
) -> ScimUser:
    _ = key_row
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return ScimUser(
        id=row["id"],
        userName=row["email"],
        name={"formatted": row["name"]},
        emails=[{"value": row["email"], "primary": True}],
        active=True,
    )


@app.delete("/scim/Users/{user_id}", response_model=dict)
def scim_delete_user(
    user_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["scim:write"])),
) -> dict:
    _ = key_row
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return {"deleted": True}


@app.post("/policies", response_model=Policy)
def create_policy(
    payload: PolicyCreate,
    key_row: dict = Depends(_require_org_and_scopes(["policies:write"])),
) -> Policy:
    org_id = key_row["org_id"]
    policy_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO policies (id, org_id, name, description, rule_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                policy_id,
                org_id,
                payload.name,
                payload.description,
                dump_json_field(payload.rule.model_dump()),
                created_at,
            ),
        )
    return Policy(id=policy_id, org_id=org_id, created_at=created_at, **payload.model_dump())


@app.get("/policies", response_model=list[Policy])
def list_policies(key_row: dict = Depends(_require_org_and_scopes(["policies:read"]))) -> list[Policy]:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM policies WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    policies = []
    for row in rows:
        data = row_to_dict(row)
        policies.append(
            Policy(
                id=data["id"],
                org_id=data["org_id"],
                name=data["name"],
                description=data["description"],
                rule=PolicyRule(**parse_json_field(data["rule_json"])),
                created_at=data["created_at"],
            )
        )
    return policies


@app.get("/policies/{policy_id}", response_model=Policy)
def get_policy(
    policy_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["policies:read"])),
) -> Policy:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM policies WHERE id = ? AND org_id = ?",
            (policy_id, org_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    data = row_to_dict(row)
    return Policy(
        id=data["id"],
        org_id=data["org_id"],
        name=data["name"],
        description=data["description"],
        rule=PolicyRule(**parse_json_field(data["rule_json"])),
        created_at=data["created_at"],
    )


@app.get("/policies/{policy_id}/opa", response_model=OpaPolicyExport)
def export_policy_opa(
    policy_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["policies:read"])),
) -> OpaPolicyExport:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM policies WHERE id = ? AND org_id = ?",
            (policy_id, org_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    data = row_to_dict(row)
    rule = parse_json_field(data["rule_json"])
    opa_input = {
        "input": {
            "principal": "example-principal",
            "action": "read",
            "resource": {
                "type": "example-type",
                "attributes": {"sensitivity": "high"},
            },
        }
    }
    return OpaPolicyExport(
        policy_id=policy_id,
        org_id=org_id,
        rule=rule,
        opa_input=opa_input,
    )


@app.post("/resources", response_model=Resource)
def create_resource(
    payload: ResourceCreate,
    key_row: dict = Depends(_require_org_and_scopes(["resources:write"])),
) -> Resource:
    org_id = key_row["org_id"]
    resource_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO resources (id, org_id, name, type, attributes_json, source_system, external_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                resource_id,
                org_id,
                payload.name,
                payload.type,
                dump_json_field(payload.attributes),
                payload.source_system,
                payload.external_id,
                created_at,
            ),
        )
    return Resource(id=resource_id, org_id=org_id, created_at=created_at, **payload.model_dump())


@app.get("/resources", response_model=list[Resource])
def list_resources(key_row: dict = Depends(_require_org_and_scopes(["resources:read"]))) -> list[Resource]:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM resources WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    resources = []
    for row in rows:
        data = row_to_dict(row)
        resources.append(
            Resource(
                id=data["id"],
                org_id=data["org_id"],
                name=data["name"],
                type=data["type"],
                attributes=parse_json_field(data["attributes_json"]),
                source_system=data.get("source_system") or "manual",
                external_id=data.get("external_id"),
                created_at=data["created_at"],
            )
        )
    return resources


@app.get("/resources/{resource_id}", response_model=Resource)
def get_resource(
    resource_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["resources:read"])),
) -> Resource:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM resources WHERE id = ? AND org_id = ?",
            (resource_id, org_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Resource not found")
    data = row_to_dict(row)
    return Resource(
        id=data["id"],
        org_id=data["org_id"],
        name=data["name"],
        type=data["type"],
        attributes=parse_json_field(data["attributes_json"]),
        source_system=data.get("source_system") or "manual",
        external_id=data.get("external_id"),
        created_at=data["created_at"],
    )


@app.post("/evaluations", response_model=Evaluation)
def evaluate(
    payload: EvaluationRequest,
    key_row: dict = Depends(_require_org_and_scopes(["evaluations:write"])),
) -> Evaluation:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        policy_row = conn.execute(
            "SELECT * FROM policies WHERE id = ? AND org_id = ?",
            (payload.policy_id, org_id),
        ).fetchone()
        resource_row = conn.execute(
            "SELECT * FROM resources WHERE id = ? AND org_id = ?",
            (payload.resource_id, org_id),
        ).fetchone()
    if not policy_row:
        raise HTTPException(status_code=404, detail="Policy not found")
    if not resource_row:
        raise HTTPException(status_code=404, detail="Resource not found")

    policy_data = row_to_dict(policy_row)
    resource_data = row_to_dict(resource_row)

    policy_rule = PolicyRule(**parse_json_field(policy_data["rule_json"]))
    resource = Resource(
        id=resource_data["id"],
        org_id=resource_data["org_id"],
        name=resource_data["name"],
        type=resource_data["type"],
        attributes=parse_json_field(resource_data["attributes_json"]),
        source_system=resource_data.get("source_system") or "manual",
        external_id=resource_data.get("external_id"),
        created_at=resource_data["created_at"],
    )

    decision, rationale = evaluate_policy(policy_rule, payload.principal, payload.action, resource)

    evaluation_id = str(uuid.uuid4())
    created_at = now_iso()
    payload_hash = {
        "org_id": org_id,
        "policy_id": payload.policy_id,
        "principal": payload.principal,
        "action": payload.action,
        "resource_id": payload.resource_id,
        "decision": decision,
        "rationale": rationale,
        "created_at": created_at,
    }
    with get_conn() as conn:
        prev_row = conn.execute(
            "SELECT record_hash FROM evaluations WHERE org_id = ? ORDER BY created_at DESC LIMIT 1",
            (org_id,),
        ).fetchone()
        prev_hash = prev_row["record_hash"] if prev_row else None
        record_hash = _hash_record(payload_hash, prev_hash)
        conn.execute(
            """
            INSERT INTO evaluations (id, org_id, policy_id, principal, action, resource_id, decision, rationale, created_at, prev_hash, record_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evaluation_id,
                org_id,
                payload.policy_id,
                payload.principal,
                payload.action,
                payload.resource_id,
                decision,
                rationale,
                created_at,
                prev_hash,
                record_hash,
            ),
        )

    return Evaluation(
        id=evaluation_id,
        org_id=org_id,
        policy_id=payload.policy_id,
        principal=payload.principal,
        action=payload.action,
        resource_id=payload.resource_id,
        decision=decision,
        rationale=rationale,
        created_at=created_at,
        prev_hash=prev_hash,
        record_hash=record_hash,
    )


@app.get("/evaluations", response_model=list[Evaluation])
def list_evaluations(key_row: dict = Depends(_require_org_and_scopes(["evaluations:read"]))) -> list[Evaluation]:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM evaluations WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    return [Evaluation(**row_to_dict(row)) for row in rows]


@app.post("/evidence/retain", response_model=RetentionStatus)
def enforce_retention(key_row: dict = Depends(_require_org_and_scopes(["evidence:write"]))) -> RetentionStatus:
    org_id = key_row["org_id"]
    cutoff = datetime.utcnow() - timedelta(days=settings.retention_days)
    cutoff_iso = cutoff.isoformat() + "Z"
    with get_conn() as conn:
        cursor = conn.execute(
            "DELETE FROM evaluations WHERE org_id = ? AND created_at < ?",
            (org_id, cutoff_iso),
        )
        deleted = cursor.rowcount
    return RetentionStatus(
        retention_days=settings.retention_days,
        cutoff_timestamp=cutoff_iso,
        deleted_records=deleted,
    )


@app.get("/evidence/export", response_model=EvidenceExport)
def export_evidence(format: str = "json", key_row: dict = Depends(_require_org_and_scopes(["evidence:read"]))):
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM evaluations WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    evaluations = [Evaluation(**row_to_dict(row)) for row in rows]
    exported_at = now_iso()

    payload = {
        "org_id": org_id,
        "exported_at": exported_at,
        "evaluations": [e.model_dump() for e in evaluations],
    }
    if format == "csv":
        serialized = io.StringIO()
        writer = csv.DictWriter(serialized, fieldnames=list(Evaluation.model_fields.keys()))
        writer.writeheader()
        for evaluation in evaluations:
            writer.writerow(evaluation.model_dump())
        csv_data = serialized.getvalue()
        signature = hmac.new(
            settings.evidence_hmac_secret.encode("utf-8"),
            csv_data.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"X-Evidence-Signature": signature},
        )

    json_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = hmac.new(
        settings.evidence_hmac_secret.encode("utf-8"),
        json_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return EvidenceExport(
        org_id=org_id,
        exported_at=exported_at,
        format="json",
        signature=signature,
        evaluations=evaluations,
    )


@app.get("/connectors")
def list_connector_metadata(key_row: dict = Depends(_require_org_and_scopes(["connectors:read"]))) -> list[dict]:
    _ = key_row
    return [meta.__dict__ for meta in list_connectors()]


@app.get("/connectors/{connector_name}/sample")
def connector_sample(
    connector_name: str,
    key_row: dict = Depends(_require_org_and_scopes(["connectors:read"])),
) -> list[dict]:
    _ = key_row
    connector = get_connector(connector_name)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    return connector.sample_resources()
