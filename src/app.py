from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import secrets
import uuid
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
    Org,
    OrgCreate,
    Policy,
    PolicyCreate,
    PolicyRule,
    Resource,
    ResourceCreate,
)
from .settings import settings

app = FastAPI(title=settings.app_name)


@app.on_event("startup")
def _startup() -> None:
    init_db()


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _get_org_id_from_key(raw_key: str | None) -> str:
    if not raw_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    key_hash = _hash_key(raw_key)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, org_id FROM api_keys WHERE key_hash = ?",
            (key_hash,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid API key")
        conn.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
            (now_iso(), row["id"]),
        )
    return row["org_id"]


def require_org_id(x_api_key: str | None = Header(default=None)) -> str:
    return _get_org_id_from_key(x_api_key)


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
            "INSERT INTO api_keys (id, org_id, name, key_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (key_id, org_id, payload.name, key_hash, created_at),
        )
    return ApiKeyIssued(
        id=key_id,
        org_id=org_id,
        name=payload.name,
        created_at=created_at,
        last_used_at=None,
        api_key=api_key,
    )


@app.get("/orgs/{org_id}/keys", response_model=list[ApiKey])
def list_api_keys(org_id: str, org_scope: str = Depends(require_org_id)) -> list[ApiKey]:
    if org_id != org_scope:
        raise HTTPException(status_code=403, detail="Forbidden")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, org_id, name, created_at, last_used_at FROM api_keys WHERE org_id = ?",
            (org_id,),
        ).fetchall()
    return [ApiKey(**row_to_dict(row)) for row in rows]


@app.post("/policies", response_model=Policy)
def create_policy(payload: PolicyCreate, org_id: str = Depends(require_org_id)) -> Policy:
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
def list_policies(org_id: str = Depends(require_org_id)) -> list[Policy]:
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
def get_policy(policy_id: str, org_id: str = Depends(require_org_id)) -> Policy:
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


@app.post("/resources", response_model=Resource)
def create_resource(payload: ResourceCreate, org_id: str = Depends(require_org_id)) -> Resource:
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
def list_resources(org_id: str = Depends(require_org_id)) -> list[Resource]:
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
def get_resource(resource_id: str, org_id: str = Depends(require_org_id)) -> Resource:
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
def evaluate(payload: EvaluationRequest, org_id: str = Depends(require_org_id)) -> Evaluation:
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
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO evaluations (id, org_id, policy_id, principal, action, resource_id, decision, rationale, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    )


@app.get("/evaluations", response_model=list[Evaluation])
def list_evaluations(org_id: str = Depends(require_org_id)) -> list[Evaluation]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM evaluations WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    return [Evaluation(**row_to_dict(row)) for row in rows]


@app.get("/evidence/export", response_model=EvidenceExport)
def export_evidence(format: str = "json", org_id: str = Depends(require_org_id)):
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
def list_connector_metadata(org_id: str = Depends(require_org_id)) -> list[dict]:
    _ = org_id
    return [meta.__dict__ for meta in list_connectors()]


@app.get("/connectors/{connector_name}/sample")
def connector_sample(connector_name: str, org_id: str = Depends(require_org_id)) -> list[dict]:
    _ = org_id
    connector = get_connector(connector_name)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    return connector.sample_resources()
