from __future__ import annotations

import uuid
from fastapi import FastAPI, HTTPException

from .db import get_conn, init_db, now_iso, parse_json_field, row_to_dict, dump_json_field
from .policy_engine import evaluate_policy
from .schemas import (
    Evaluation,
    EvaluationRequest,
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


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/policies", response_model=Policy)
def create_policy(payload: PolicyCreate) -> Policy:
    policy_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO policies (id, name, description, rule_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                policy_id,
                payload.name,
                payload.description,
                dump_json_field(payload.rule.model_dump()),
                created_at,
            ),
        )
    return Policy(id=policy_id, created_at=created_at, **payload.model_dump())


@app.get("/policies", response_model=list[Policy])
def list_policies() -> list[Policy]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM policies ORDER BY created_at DESC").fetchall()
    policies = []
    for row in rows:
        data = row_to_dict(row)
        policies.append(
            Policy(
                id=data["id"],
                name=data["name"],
                description=data["description"],
                rule=PolicyRule(**parse_json_field(data["rule_json"])),
                created_at=data["created_at"],
            )
        )
    return policies


@app.get("/policies/{policy_id}", response_model=Policy)
def get_policy(policy_id: str) -> Policy:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    data = row_to_dict(row)
    return Policy(
        id=data["id"],
        name=data["name"],
        description=data["description"],
        rule=PolicyRule(**parse_json_field(data["rule_json"])),
        created_at=data["created_at"],
    )


@app.post("/resources", response_model=Resource)
def create_resource(payload: ResourceCreate) -> Resource:
    resource_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO resources (id, name, type, attributes_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                resource_id,
                payload.name,
                payload.type,
                dump_json_field(payload.attributes),
                created_at,
            ),
        )
    return Resource(id=resource_id, created_at=created_at, **payload.model_dump())


@app.get("/resources", response_model=list[Resource])
def list_resources() -> list[Resource]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM resources ORDER BY created_at DESC").fetchall()
    resources = []
    for row in rows:
        data = row_to_dict(row)
        resources.append(
            Resource(
                id=data["id"],
                name=data["name"],
                type=data["type"],
                attributes=parse_json_field(data["attributes_json"]),
                created_at=data["created_at"],
            )
        )
    return resources


@app.get("/resources/{resource_id}", response_model=Resource)
def get_resource(resource_id: str) -> Resource:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM resources WHERE id = ?", (resource_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Resource not found")
    data = row_to_dict(row)
    return Resource(
        id=data["id"],
        name=data["name"],
        type=data["type"],
        attributes=parse_json_field(data["attributes_json"]),
        created_at=data["created_at"],
    )


@app.post("/evaluations", response_model=Evaluation)
def evaluate(payload: EvaluationRequest) -> Evaluation:
    with get_conn() as conn:
        policy_row = conn.execute("SELECT * FROM policies WHERE id = ?", (payload.policy_id,)).fetchone()
        resource_row = conn.execute("SELECT * FROM resources WHERE id = ?", (payload.resource_id,)).fetchone()
    if not policy_row:
        raise HTTPException(status_code=404, detail="Policy not found")
    if not resource_row:
        raise HTTPException(status_code=404, detail="Resource not found")

    policy_data = row_to_dict(policy_row)
    resource_data = row_to_dict(resource_row)

    policy_rule = PolicyRule(**parse_json_field(policy_data["rule_json"]))
    resource = Resource(
        id=resource_data["id"],
        name=resource_data["name"],
        type=resource_data["type"],
        attributes=parse_json_field(resource_data["attributes_json"]),
        created_at=resource_data["created_at"],
    )

    decision, rationale = evaluate_policy(policy_rule, payload.principal, payload.action, resource)

    evaluation_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO evaluations (id, policy_id, principal, action, resource_id, decision, rationale, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evaluation_id,
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
        policy_id=payload.policy_id,
        principal=payload.principal,
        action=payload.action,
        resource_id=payload.resource_id,
        decision=decision,
        rationale=rationale,
        created_at=created_at,
    )


@app.get("/evaluations", response_model=list[Evaluation])
def list_evaluations() -> list[Evaluation]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM evaluations ORDER BY created_at DESC").fetchall()
    evaluations = []
    for row in rows:
        data = row_to_dict(row)
        evaluations.append(Evaluation(**data))
    return evaluations
