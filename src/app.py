from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
import urllib.request
import time

from .connectors.base import get_connector, list_connectors
from .connectors import google_drive  # noqa: F401
from .connectors import snowflake  # noqa: F401
from .connectors import okta  # noqa: F401
from .connectors import aws_cloudtrail  # noqa: F401
from .db import get_conn, init_db, now_iso, parse_json_field, row_to_dict, dump_json_field
from .llm import generate_policy_from_text
from .policy_engine import evaluate_policy
from .schemas import (
    ApiKey,
    ApiKeyCreate,
    ApiKeyIssued,
    Evaluation,
    EvaluationRequest,
    EvidenceExport,
    EvidenceVerifyResult,
    Membership,
    MembershipCreate,
    OidcAuthRequest,
    OidcAuthResponse,
    Org,
    OrgCreate,
    OrgExport,
    OpaPolicyExport,
    Policy,
    PolicyCreate,
    PolicyRevision,
    PolicyRevisionCreate,
    PolicyRule,
    PlaygroundDecision,
    PlaygroundRequest,
    Resource,
    ResourceCreate,
    RetentionStatus,
    Role,
    RoleCreate,
    SamlAuthRequest,
    SamlAuthResponse,
    ScimListResponse,
    ScimUser,
    ScimUserCreate,
    SsoConfig,
    SsoConfigCreate,
    Team,
    TeamCreate,
    TeamMembership,
    TeamMembershipCreate,
    TrustCheck,
    UsageSummary,
    User,
    UserCreate,
    EvidenceSearchResult,
    Webhook,
    WebhookCreate,
    WebhookDelivery,
    DecisionLogExport,
    EvidenceAttestation,
    EvidenceAttestationCreate,
    EnforcementDecision,
    EnforcementRequest,
)
from .settings import settings

app = FastAPI(title=settings.app_name)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers.setdefault("X-Request-Id", request_id)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    content_type = response.headers.get("content-type", "")
    if content_type.startswith("text/html"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';",
        )
    return response


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _hash_record(payload: dict, prev_hash: str | None) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    joined = f"{prev_hash or ''}:{data}".encode("utf-8")
    return hashlib.sha256(joined).hexdigest()


def _hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _append_to_vault(content: str, export_id: str) -> None:
    path = settings.evidence_vault_path
    if not path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"export_id": export_id, "hash": _hash_content(content)}) + "\n")

def _policy_approval_signature(policy_id: str, version: int, rule_json: str, approved_by: str | None) -> str:
    payload = f"{policy_id}:{version}:{approved_by or ''}:{rule_json}"
    return hmac.new(
        settings.policy_approval_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _merge_rules(parent: PolicyRule, child: PolicyRule) -> PolicyRule:
    merged = PolicyRule(
        allowed_principals=sorted(set(parent.allowed_principals + child.allowed_principals)),
        allowed_actions=sorted(set(parent.allowed_actions + child.allowed_actions)),
        resource_types=sorted(set(parent.resource_types + child.resource_types)),
        required_attributes={**parent.required_attributes, **child.required_attributes},
        deny_principals=sorted(set(parent.deny_principals + child.deny_principals)),
        deny_actions=sorted(set(parent.deny_actions + child.deny_actions)),
        deny_resource_types=sorted(set(parent.deny_resource_types + child.deny_resource_types)),
        exception_principals=sorted(set(parent.exception_principals + child.exception_principals)),
        exception_actions=sorted(set(parent.exception_actions + child.exception_actions)),
        exception_resource_types=sorted(set(parent.exception_resource_types + child.exception_resource_types)),
    )
    return merged


def _compute_risk_score(resource: Resource, action: str) -> int:
    sensitivity = 1
    if resource.ai_metadata and isinstance(resource.ai_metadata, dict):
        sensitivity = int(resource.ai_metadata.get("sensitivity_level") or 1)
    action_weight = 0
    if action in {"write", "delete", "export"}:
        action_weight = 2
    return sensitivity + action_weight


def _rego_from_rule(rule: PolicyRule) -> str:
    lines = [
        "package unified.governance",
        "",
        "default allow = false",
        "",
        "allow {",
        "  # principals",
        f"  input.principal in {json.dumps(rule.allowed_principals)}",
        "  # actions",
        f"  input.action in {json.dumps(rule.allowed_actions)}",
        "  # resource types",
        f"  input.resource.type in {json.dumps(rule.resource_types)}",
        "  # required attributes",
    ]
    for key, value in rule.required_attributes.items():
        lines.append(f"  input.resource.attributes.{key} == {json.dumps(value)}")
    lines.append("}")
    return "\n".join(lines)

def _deliver_webhook(url: str, secret: str | None, payload: dict) -> tuple[int | None, str]:
    if not settings.enable_webhook_delivery:
        return None, "delivery disabled"
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if secret:
        signature = hashlib.sha256((secret + json.dumps(payload)).encode("utf-8")).hexdigest()
        headers["X-Webhook-Signature"] = signature
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, body
    except Exception as exc:  # pragma: no cover - network dependent
        return 0, str(exc)


_rate_limiter: dict[str, list[float]] = {}


def _rate_limit(org_id: str) -> None:
    now = time.time()
    window = 60
    hits = _rate_limiter.get(org_id, [])
    hits = [t for t in hits if now - t < window]
    if len(hits) >= settings.rate_limit_per_min:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    hits.append(now)
    _rate_limiter[org_id] = hits


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


def _policy_model_from_row(data: dict) -> Policy:
    return Policy(
        id=data["id"],
        org_id=data["org_id"],
        name=data["name"],
        description=data["description"],
        rule=PolicyRule(**parse_json_field(data["rule_json"])),
        created_at=data["created_at"],
        inherits_from=data.get("inherits_from"),
        version=int(data.get("version") or 1),
    )


def _evaluation_from_row(data: dict) -> Evaluation:
    return Evaluation(
        id=data["id"],
        org_id=data["org_id"],
        policy_id=data["policy_id"],
        principal=data["principal"],
        action=data["action"],
        resource_id=data["resource_id"],
        decision=data["decision"],
        rationale=data.get("rationale"),
        rule_snapshot=None,
        created_at=data["created_at"],
        prev_hash=data.get("prev_hash"),
        record_hash=data.get("record_hash"),
        explain=parse_json_field(data.get("explain_json", "")) or None,
    )


def _resolve_policy_rule(org_id: str, policy_row: dict) -> PolicyRule:
    policy_data = row_to_dict(policy_row)
    base_rule = PolicyRule(**parse_json_field(policy_data["rule_json"]))
    parent_id = policy_data.get("inherits_from")
    if not parent_id:
        return base_rule
    with get_conn() as conn:
        parent_row = conn.execute(
            "SELECT * FROM policies WHERE id = ? AND org_id = ?",
            (parent_id, org_id),
        ).fetchone()
    if not parent_row:
        return base_rule
    parent_rule = PolicyRule(**parse_json_field(row_to_dict(parent_row)["rule_json"]))
    return _merge_rules(parent_rule, base_rule)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/v1/health")
def v1_health() -> dict:
    return health()


@app.get("/status/live")
def live_status() -> dict:
    return {"status": "ok", "time": now_iso()}


@app.get("/status/ready")
def ready_status() -> dict:
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok", "db": "ok", "time": now_iso()}
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=503, detail=f"db unavailable: {exc}") from exc


@app.get("/metrics")
def metrics() -> Response:
    with get_conn() as conn:
        orgs = conn.execute("SELECT COUNT(*) as total FROM orgs").fetchone()
        users = conn.execute("SELECT COUNT(*) as total FROM users").fetchone()
        policies = conn.execute("SELECT COUNT(*) as total FROM policies").fetchone()
        resources = conn.execute("SELECT COUNT(*) as total FROM resources").fetchone()
        evaluations = conn.execute("SELECT COUNT(*) as total FROM evaluations").fetchone()
        exports = conn.execute("SELECT COUNT(*) as total FROM evidence_exports").fetchone()
        webhooks = conn.execute("SELECT COUNT(*) as total FROM webhooks").fetchone()

    def _count(row) -> int:
        if isinstance(row, dict):
            return int(row.get("total", 0))
        return int(row[0]) if row else 0

    lines = [
        "# HELP ug_orgs_total Total orgs",
        "# TYPE ug_orgs_total gauge",
        f"ug_orgs_total {_count(orgs)}",
        "# HELP ug_users_total Total users",
        "# TYPE ug_users_total gauge",
        f"ug_users_total {_count(users)}",
        "# HELP ug_policies_total Total policies",
        "# TYPE ug_policies_total gauge",
        f"ug_policies_total {_count(policies)}",
        "# HELP ug_resources_total Total resources",
        "# TYPE ug_resources_total gauge",
        f"ug_resources_total {_count(resources)}",
        "# HELP ug_evaluations_total Total evaluations",
        "# TYPE ug_evaluations_total counter",
        f"ug_evaluations_total {_count(evaluations)}",
        "# HELP ug_evidence_exports_total Total evidence exports",
        "# TYPE ug_evidence_exports_total counter",
        f"ug_evidence_exports_total {_count(exports)}",
        "# HELP ug_webhooks_total Total webhooks",
        "# TYPE ug_webhooks_total gauge",
        f"ug_webhooks_total {_count(webhooks)}",
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.get("/", response_class=HTMLResponse)
def root() -> str:
    return """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Unified Governance Layer</title>
    <style>
      :root { color-scheme: light; }
      body {
        margin: 0;
        font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
        background: linear-gradient(135deg, #f6f7fb 0%, #eef1f6 100%);
        color: #0f172a;
      }
      .wrap {
        max-width: 920px;
        margin: 0 auto;
        padding: 64px 24px 80px;
      }
      .card {
        background: #ffffff;
        border-radius: 16px;
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08);
        padding: 32px;
      }
      h1 { font-size: 32px; margin: 0 0 12px; }
      p { font-size: 16px; line-height: 1.6; }
      .links {
        display: grid;
        gap: 12px;
        margin-top: 20px;
      }
      .trust {
        margin-top: 24px;
        padding-top: 16px;
        border-top: 1px solid #e2e8f0;
      }
      .trust table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 8px;
        font-size: 14px;
      }
      .trust th, .trust td {
        text-align: left;
        padding: 8px;
        border-bottom: 1px solid #e2e8f0;
      }
      .badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 10px;
        background: #ecfeff;
        border: 1px solid #a5f3fc;
        border-radius: 999px;
        font-size: 12px;
        color: #0f172a;
      }
      a {
        display: inline-block;
        padding: 10px 14px;
        border-radius: 10px;
        text-decoration: none;
        color: #0f172a;
        background: #e2e8f0;
      }
      a.primary { background: #0f172a; color: #ffffff; }
      .meta {
        margin-top: 18px;
        font-size: 13px;
        color: #475569;
      }
      code { background: #f1f5f9; padding: 2px 6px; border-radius: 6px; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        <h1>Unified Governance Layer</h1>
        <p>Policy-as-code and evidence engine for third-party and AI data access governance.</p>
        <div class="links">
          <a class="primary" href="/docs">Open API Docs</a>
          <a href="/openapi.json">OpenAPI JSON</a>
          <a href="/health">Health Check</a>
        </div>
        <p class="meta">API base: <code>/</code> | Auth: <code>X-API-Key</code> header</p>
        <div class="trust">
          <div class="badge">System Integrity: <strong id="trustStatus">Checking…</strong></div>
          <table>
            <thead>
              <tr><th>Timestamp</th><th>Status</th><th>Records Checked</th></tr>
            </thead>
            <tbody id="trustRows"></tbody>
          </table>
          <p class="meta">Trust badge snippet (embed anywhere):</p>
          <pre><code id="trustSnippet">&lt;script src="/trust-badge.js"&gt;&lt;/script&gt;&lt;div id="ug-trust-badge"&gt;&lt;/div&gt;</code></pre>
        </div>
      </div>
    </div>
    <script>
      async function loadTrust() {
        const res = await fetch('/trust/last-checks');
        const data = res.ok ? await res.json() : [];
        const rows = document.getElementById('trustRows');
        rows.innerHTML = '';
        if (data.length === 0) {
          document.getElementById('trustStatus').textContent = 'No checks yet';
          return;
        }
        const latest = data[0];
        document.getElementById('trustStatus').textContent = latest.valid ? 'Verified' : 'Failed';
        data.forEach(item => {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${item.created_at}</td><td>${item.valid ? 'Verified' : 'Failed'}</td><td>${item.checked_records}</td>`;
          rows.appendChild(tr);
        });
      }
      loadTrust();
    </script>
  </body>
</html>
"""


@app.get("/admin", response_class=HTMLResponse)
def admin() -> str:
    return """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Unified Governance Admin</title>
    <style>
      body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background: #0b1220; color: #e2e8f0; margin: 0; }
      .wrap { max-width: 1100px; margin: 0 auto; padding: 24px 24px 60px; }
      h1 { font-size: 28px; margin-bottom: 8px; }
      .tabs { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
      .tab { padding: 8px 12px; border-radius: 10px; background: #1f2a44; cursor: pointer; }
      .tab.active { background: #38bdf8; color: #0b1220; font-weight: 600; }
      .card { background: #0f172a; border: 1px solid #1f2a44; border-radius: 14px; padding: 18px; margin-bottom: 16px; }
      label { display: block; font-size: 12px; margin-bottom: 6px; color: #94a3b8; }
      input, textarea { width: 100%; padding: 10px; border-radius: 10px; border: 1px solid #1f2a44; background: #0b1220; color: #e2e8f0; }
      button { background: #38bdf8; color: #0b1220; border: none; border-radius: 10px; padding: 8px 12px; cursor: pointer; font-weight: 600; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
      pre { background: #0b1220; padding: 12px; border-radius: 10px; overflow: auto; }
      .muted { color: #94a3b8; font-size: 12px; }
      .hidden { display: none; }
      table { width: 100%; border-collapse: collapse; }
      td, th { padding: 6px; border-bottom: 1px solid #1f2a44; font-size: 13px; text-align: left; }
      .row { display: flex; gap: 10px; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <h1>Unified Governance Admin</h1>
      <p class="muted">API keys, policies, evidence, and RBAC in one place.</p>
      <div class="card">
        <div class="row">
          <div style="flex:2">
            <label>API Key</label>
            <input id="apiKey" placeholder="X-API-Key" />
          </div>
          <div style="flex:1">
            <label>Org ID (for keys/teams)</label>
            <input id="orgId" placeholder="org_id" />
          </div>
        </div>
        <button onclick="saveKey()">Save</button>
      </div>

      <div class="tabs">
        <div class="tab active" data-tab="playground">Policy Playground</div>
        <div class="tab" data-tab="keys">Key Management</div>
        <div class="tab" data-tab="teams">Teams & Roles</div>
        <div class="tab" data-tab="evidence">Evidence Search</div>
        <div class="tab" data-tab="users">Users</div>
        <div class="tab" data-tab="quickstart">Quick Start</div>
      </div>

      <div id="playground" class="tab-panel">
        <div class="grid">
          <div class="card">
            <h3>Create Policy</h3>
            <label>Name</label>
            <input id="policyName" />
            <label>Natural Language</label>
            <textarea id="policyPrompt" rows="3">Users in Marketing cannot use GPT-4 for sensitive data</textarea>
            <button onclick="generatePolicy()">Generate Policy JSON</button>
            <label>Rule (JSON)</label>
            <textarea id="policyRule" rows="6">{\"allowed_principals\":[\"user\"],\"allowed_actions\":[\"read\"],\"resource_types\":[\"file\"],\"required_attributes\":{\"model_type\":\"llm\"}}</textarea>
            <button onclick="createPolicy()">Create Policy</button>
          </div>
          <div class="card">
            <h3>Create Resource</h3>
            <label>Name</label>
            <input id="resourceName" />
            <label>Type</label>
            <input id="resourceType" value="file" />
            <label>Attributes (JSON)</label>
            <textarea id="resourceAttrs" rows="4">{\"sensitivity\":\"high\"}</textarea>
            <label>AI Metadata (JSON)</label>
            <textarea id="resourceAI" rows="4">{\"model_type\":\"llm\",\"model_provider\":\"openai\",\"sensitivity_level\":4,\"is_governed\":true}</textarea>
            <button onclick="createResource()">Create Resource</button>
          </div>
          <div class="card">
            <h3>Playground</h3>
            <label>Resource ID</label>
            <input id="pgResource" />
            <label>Principal</label>
            <input id="pgPrincipal" value="user" />
            <label>Action</label>
            <input id="pgAction" value="read" />
            <button onclick="runPlayground()">Evaluate</button>
            <pre id="playgroundOut">[]</pre>
          </div>
        </div>
      </div>

      <div id="keys" class="tab-panel hidden">
        <div class="card">
          <h3>Create API Key</h3>
          <label>Name</label>
          <input id="keyName" value="admin" />
          <button onclick="createKey()">Create</button>
          <pre id="keyOut">{}</pre>
        </div>
        <div class="card">
          <h3>Existing Keys</h3>
          <button onclick="listKeys()">Refresh</button>
          <div id="keysTable"></div>
        </div>
      </div>

      <div id="teams" class="tab-panel hidden">
        <div class="card">
          <h3>Create Team / Role</h3>
          <label>Team Name</label>
          <input id="teamName" />
          <button onclick="createTeam()">Create Team</button>
          <label>Role Name</label>
          <input id="roleName" />
          <label>Permissions (JSON array)</label>
          <textarea id="rolePerms">[\"policies:write\",\"evidence:read\"]</textarea>
          <button onclick="createRole()">Create Role</button>
        </div>
        <div class="card">
          <h3>Teams</h3>
          <button onclick="listTeams()">Refresh</button>
          <div id="teamsTable"></div>
        </div>
        <div class="card">
          <h3>Roles</h3>
          <button onclick="listRoles()">Refresh</button>
          <div id="rolesTable"></div>
        </div>
        <div class="card">
          <h3>Team Memberships</h3>
          <button onclick="listMemberships()">Refresh</button>
          <div id="membershipsTable"></div>
        </div>
      </div>

      <div id="evidence" class="tab-panel hidden">
        <div class="card">
          <h3>Evidence</h3>
          <label>Principal (optional)</label>
          <input id="evidencePrincipal" />
          <label>Policy ID (optional)</label>
          <input id="evidencePolicy" />
          <label>Decision (optional)</label>
          <input id="evidenceDecision" placeholder="allow/deny" />
          <button onclick="searchEvidence(0)">Search</button>
          <button onclick="prevEvidence()">Prev</button>
          <button onclick="nextEvidence()">Next</button>
          <button onclick="verifyEvidence()">Verify Chain</button>
          <button onclick="exportEvidence()">Export JSON</button>
          <button onclick="exportEvidenceCsv()">Export CSV</button>
          <pre id="evidenceOut">{}</pre>
        </div>
      </div>

      <div id="users" class="tab-panel hidden">
        <div class="card">
          <h3>Users</h3>
          <button onclick="listUsers()">Refresh</button>
          <pre id="usersOut">[]</pre>
        </div>
        <div class="card">
          <h3>Create SCIM User</h3>
          <label>Email</label>
          <input id="scimEmail" />
          <label>Name</label>
          <input id="scimName" />
          <button onclick="createScimUser()">Create</button>
        </div>
      </div>

      <div id="quickstart" class="tab-panel hidden">
        <div class="card">
          <h3>Protect an OpenAI Route (Node.js)</h3>
          <pre>app.post('/openai', async (req, res) => {\n  const policy = await fetch('https://unified-governance.onrender.com/evaluations', {\n    method: 'POST',\n    headers: { 'Content-Type': 'application/json', 'X-API-Key': process.env.UG_API_KEY },\n    body: JSON.stringify({ policy_id, principal: req.user.role, action: 'read', resource_id })\n  });\n  if (!policy.ok) return res.status(403).send('Denied');\n  // call OpenAI\n});</pre>
          <h3>Trust Badge (React)</h3>
          <pre>&lt;script src=\"https://unified-governance.onrender.com/trust-badge.js\"&gt;&lt;/script&gt;\n&lt;div id=\"ug-trust-badge\"&gt;&lt;/div&gt;</pre>
          <h3>SCIM Sync</h3>
          <pre>POST https://unified-governance.onrender.com/scim/Users\nX-API-Key: ...\n{\"userName\":\"alice@example.com\",\"name\":{\"formatted\":\"Alice\"},\"emails\":[{\"value\":\"alice@example.com\",\"primary\":true}],\"active\":true}</pre>
        </div>
      </div>
    </div>

    <script>
      const apiKeyInput = document.getElementById('apiKey');
      const orgInput = document.getElementById('orgId');
      apiKeyInput.value = localStorage.getItem('ug_api_key') || '';
      orgInput.value = localStorage.getItem('ug_org_id') || '';

      document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
          document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
          document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
          tab.classList.add('active');
          document.getElementById(tab.dataset.tab).classList.remove('hidden');
        });
      });

      function saveKey() {
        localStorage.setItem('ug_api_key', apiKeyInput.value.trim());
        localStorage.setItem('ug_org_id', orgInput.value.trim());
        alert('Saved');
      }

      async function api(path, method = 'GET', body) {
        const key = localStorage.getItem('ug_api_key') || '';
        const res = await fetch(path, {
          method,
          headers: { 'Content-Type': 'application/json', 'X-API-Key': key },
          body: body ? JSON.stringify(body) : undefined
        });
        if (!res.ok) throw new Error(`Request failed: ${res.status}`);
        const text = await res.text();
        return text ? JSON.parse(text) : null;
      }

      async function createPolicy() {
        const name = document.getElementById('policyName').value;
        const rule = JSON.parse(document.getElementById('policyRule').value);
        await api('/policies', 'POST', { name, rule });
      }

      async function generatePolicy() {
        const text = document.getElementById('policyPrompt').value;
        const data = await api('/policies/generate', 'POST', { text });
        document.getElementById('policyName').value = data.name || 'Generated Policy';
        document.getElementById('policyRule').value = JSON.stringify(data.rule, null, 2);
      }

      async function createResource() {
        const name = document.getElementById('resourceName').value;
        const type = document.getElementById('resourceType').value;
        const attributes = JSON.parse(document.getElementById('resourceAttrs').value);
        const ai_metadata = JSON.parse(document.getElementById('resourceAI').value || '{}');
        await api('/resources', 'POST', { name, type, attributes, ai_metadata });
      }

      async function runPlayground() {
        const resource_id = document.getElementById('pgResource').value;
        const principal = document.getElementById('pgPrincipal').value;
        const action = document.getElementById('pgAction').value;
        const data = await api('/playground/evaluate', 'POST', { resource_id, principal, action });
        const firstDeny = data.find(d => d.decision === 'deny');
        document.getElementById('playgroundOut').textContent = JSON.stringify({ firstDeny, all: data }, null, 2);
      }

      async function createKey() {
        const org = localStorage.getItem('ug_org_id') || '';
        const name = document.getElementById('keyName').value;
        const data = await api(`/orgs/${org}/keys`, 'POST', { name });
        document.getElementById('keyOut').textContent = JSON.stringify(data, null, 2);
        await listKeys();
      }

      async function listKeys() {
        const org = localStorage.getItem('ug_org_id') || '';
        const data = await api(`/orgs/${org}/keys`);
        const container = document.getElementById('keysTable');
        if (!data || data.length === 0) {
          container.innerHTML = '<p class="muted">No keys</p>';
          return;
        }
        container.innerHTML = `<table><thead><tr><th>ID</th><th>Name</th><th>Scopes</th><th>Actions</th></tr></thead><tbody>${
          data.map(k => `<tr><td>${k.id}</td><td>${k.name}</td><td>${(k.scopes||[]).join(', ')}</td><td>
            <button onclick="rotateKey('${k.id}')">Rotate</button>
            <button onclick="revokeKey('${k.id}')">Revoke</button>
          </td></tr>`).join('')
        }</tbody></table>`;
      }

      async function rotateKey(keyId) {
        const org = localStorage.getItem('ug_org_id') || '';
        const data = await api(`/orgs/${org}/keys/${keyId}/rotate`, 'POST');
        document.getElementById('keyOut').textContent = JSON.stringify(data, null, 2);
        await listKeys();
      }

      async function revokeKey(keyId) {
        const org = localStorage.getItem('ug_org_id') || '';
        const data = await api(`/orgs/${org}/keys/${keyId}/revoke`, 'POST');
        document.getElementById('keyOut').textContent = JSON.stringify(data, null, 2);
        await listKeys();
      }

      async function createTeam() {
        const org = localStorage.getItem('ug_org_id') || '';
        const name = document.getElementById('teamName').value;
        await api(`/orgs/${org}/teams`, 'POST', { name });
        await listTeams();
      }

      async function createRole() {
        const org = localStorage.getItem('ug_org_id') || '';
        const name = document.getElementById('roleName').value;
        const permissions = JSON.parse(document.getElementById('rolePerms').value || '[]');
        await api(`/orgs/${org}/roles`, 'POST', { name, permissions });
        await listRoles();
      }

      async function listTeams() {
        const org = localStorage.getItem('ug_org_id') || '';
        const data = await api(`/orgs/${org}/teams`);
        const container = document.getElementById('teamsTable');
        if (!data || data.length === 0) {
          container.innerHTML = '<p class="muted">No teams</p>';
          return;
        }
        container.innerHTML = `<table><thead><tr><th>ID</th><th>Name</th><th>Description</th></tr></thead><tbody>${
          data.map(t => `<tr><td>${t.id}</td><td>${t.name}</td><td>${t.description || ''}</td></tr>`).join('')
        }</tbody></table>`;
      }

      async function listRoles() {
        const org = localStorage.getItem('ug_org_id') || '';
        const data = await api(`/orgs/${org}/roles`);
        const container = document.getElementById('rolesTable');
        if (!data || data.length === 0) {
          container.innerHTML = '<p class="muted">No roles</p>';
          return;
        }
        container.innerHTML = `<table><thead><tr><th>ID</th><th>Name</th><th>Permissions</th></tr></thead><tbody>${
          data.map(r => `<tr><td>${r.id}</td><td>${r.name}</td><td>${(r.permissions||[]).join(', ')}</td></tr>`).join('')
        }</tbody></table>`;
      }

      async function listMemberships() {
        const org = localStorage.getItem('ug_org_id') || '';
        const data = await api(`/orgs/${org}/team-memberships`);
        const container = document.getElementById('membershipsTable');
        if (!data || data.length === 0) {
          container.innerHTML = '<p class="muted">No memberships</p>';
          return;
        }
        container.innerHTML = `<table><thead><tr><th>User</th><th>Team</th><th>Role</th></tr></thead><tbody>${
          data.map(m => `<tr><td>${m.user_id}</td><td>${m.team_id}</td><td>${m.role_id}</td></tr>`).join('')
        }</tbody></table>`;
      }

      async function verifyEvidence() {
        const data = await api('/evidence/verify');
        document.getElementById('evidenceOut').textContent = JSON.stringify(data, null, 2);
      }

      let evidenceOffset = 0;
      async function searchEvidence(offset = 0) {
        evidenceOffset = offset;
        const principal = document.getElementById('evidencePrincipal').value;
        const policyId = document.getElementById('evidencePolicy').value;
        const decision = document.getElementById('evidenceDecision').value;
        const params = new URLSearchParams();
        if (principal) params.append('principal', principal);
        if (policyId) params.append('policy_id', policyId);
        if (decision) params.append('decision', decision);
        params.append('offset', String(offset));
        const data = await api(`/evidence/search?${params.toString()}`);
        document.getElementById('evidenceOut').textContent = JSON.stringify(data, null, 2);
      }

      function nextEvidence() { searchEvidence(evidenceOffset + 50); }
      function prevEvidence() { searchEvidence(Math.max(0, evidenceOffset - 50)); }

      async function exportEvidence() {
        const data = await api('/evidence/export');
        document.getElementById('evidenceOut').textContent = JSON.stringify(data, null, 2);
      }

      async function exportEvidenceCsv() {
        window.open('/evidence/export?format=csv', '_blank');
      }

      async function listUsers() {
        const data = await api('/users');
        document.getElementById('usersOut').textContent = JSON.stringify(data, null, 2);
      }

      async function createScimUser() {
        const email = document.getElementById('scimEmail').value;
        const name = document.getElementById('scimName').value;
        await api('/scim/Users', 'POST', {
          userName: email,
          name: { formatted: name },
          emails: [{ value: email, primary: true }],
          active: true
        });
        await listUsers();
      }
    </script>
  </body>
</html>
"""


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


@app.get("/users", response_model=list[User])
def list_users(key_row: dict = Depends(_require_org_and_scopes(["orgs:read"]))) -> list[User]:
    _ = key_row
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return [User(**row_to_dict(row)) for row in rows]


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


@app.get("/orgs/{org_id}/memberships", response_model=list[Membership])
def list_memberships(
    org_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:read"])),
) -> list[Membership]:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM org_memberships WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    return [Membership(**row_to_dict(row)) for row in rows]


@app.post("/orgs/{org_id}/teams", response_model=Team)
def create_team(
    org_id: str,
    payload: TeamCreate,
    key_row: dict = Depends(_require_org_and_scopes(["rbac:write"])),
) -> Team:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    team_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO teams (id, org_id, name, description, created_at) VALUES (?, ?, ?, ?, ?)",
            (team_id, org_id, payload.name, payload.description, created_at),
        )
    return Team(id=team_id, org_id=org_id, created_at=created_at, **payload.model_dump())


@app.get("/orgs/{org_id}/teams", response_model=list[Team])
def list_teams(
    org_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["rbac:read"])),
) -> list[Team]:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM teams WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    return [Team(**row_to_dict(row)) for row in rows]


@app.post("/orgs/{org_id}/roles", response_model=Role)
def create_role(
    org_id: str,
    payload: RoleCreate,
    key_row: dict = Depends(_require_org_and_scopes(["rbac:write"])),
) -> Role:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    role_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO roles (id, org_id, name, permissions_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (role_id, org_id, payload.name, dump_json_field(payload.permissions), created_at),
        )
    return Role(id=role_id, org_id=org_id, created_at=created_at, **payload.model_dump())


@app.get("/orgs/{org_id}/roles", response_model=list[Role])
def list_roles(
    org_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["rbac:read"])),
) -> list[Role]:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM roles WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    roles = []
    for row in rows:
        data = row_to_dict(row)
        roles.append(
            Role(
                id=data["id"],
                org_id=data["org_id"],
                name=data["name"],
                permissions=parse_json_field(data["permissions_json"]) or [],
                created_at=data["created_at"],
            )
        )
    return roles


@app.post("/orgs/{org_id}/team-memberships", response_model=TeamMembership)
def create_team_membership(
    org_id: str,
    payload: TeamMembershipCreate,
    key_row: dict = Depends(_require_org_and_scopes(["rbac:write"])),
) -> TeamMembership:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    membership_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        user_row = conn.execute("SELECT id FROM users WHERE id = ?", (payload.user_id,)).fetchone()
        team_row = conn.execute(
            "SELECT id FROM teams WHERE id = ? AND org_id = ?",
            (payload.team_id, org_id),
        ).fetchone()
        role_row = conn.execute(
            "SELECT id FROM roles WHERE id = ? AND org_id = ?",
            (payload.role_id, org_id),
        ).fetchone()
        if not user_row or not team_row or not role_row:
            raise HTTPException(status_code=404, detail="User, team, or role not found")
        conn.execute(
            "INSERT INTO team_memberships (id, org_id, user_id, team_id, role_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (membership_id, org_id, payload.user_id, payload.team_id, payload.role_id, created_at),
        )
    return TeamMembership(
        id=membership_id,
        org_id=org_id,
        user_id=payload.user_id,
        team_id=payload.team_id,
        role_id=payload.role_id,
        created_at=created_at,
    )


@app.get("/orgs/{org_id}/team-memberships", response_model=list[TeamMembership])
def list_team_memberships(
    org_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["rbac:read"])),
) -> list[TeamMembership]:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM team_memberships WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    return [TeamMembership(**row_to_dict(row)) for row in rows]


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
    key_row: dict = Depends(_require_org_and_scopes(["sso:write"])),
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
    key_row: dict = Depends(_require_org_and_scopes(["sso:read"])),
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


@app.post("/sso/saml/initiate", response_model=SamlAuthResponse)
def saml_initiate(
    payload: SamlAuthRequest,
    key_row: dict = Depends(_require_org_and_scopes(["sso:read"])),
) -> SamlAuthResponse:
    _ = key_row
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM sso_configs WHERE org_id = ? AND provider = ?",
            (payload.org_id, "saml"),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="SAML config not found")
    metadata = parse_json_field(row["metadata_json"])
    return SamlAuthResponse(
        org_id=payload.org_id,
        provider="saml",
        sso_url=metadata.get("sso_url", "https://idp.example.com/sso"),
        relay_state=payload.relay_state,
    )


@app.post("/sso/saml/acs")
def saml_acs() -> dict:
    if not settings.enable_sso_enforcement:
        return {"status": "ok", "note": "SSO enforcement disabled"}
    return {"status": "ok", "note": "SAML assertion processed"}


@app.post("/sso/oidc/initiate", response_model=OidcAuthResponse)
def oidc_initiate(
    payload: OidcAuthRequest,
    key_row: dict = Depends(_require_org_and_scopes(["sso:read"])),
) -> OidcAuthResponse:
    _ = key_row
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM sso_configs WHERE org_id = ? AND provider = ?",
            (payload.org_id, "oidc"),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="OIDC config not found")
    metadata = parse_json_field(row["metadata_json"])
    authorize_url = metadata.get("authorize_url", "https://idp.example.com/authorize")
    return OidcAuthResponse(
        org_id=payload.org_id,
        provider="oidc",
        authorization_url=(
            f"{authorize_url}?client_id={metadata.get('client_id','client')}&redirect_uri={payload.redirect_uri}"
            f"&response_type=code&scope=openid%20email%20profile&state={payload.state}"
        ),
    )


@app.get("/sso/oidc/callback")
def oidc_callback(code: str | None = None, state: str | None = None) -> dict:
    if not settings.enable_sso_enforcement:
        return {"status": "ok", "code": code, "state": state, "note": "SSO enforcement disabled"}
    return {"status": "ok", "code": code, "state": state}


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
    version = 1
    rule_json = dump_json_field(payload.rule.model_dump())
    approval_sig = _policy_approval_signature(policy_id, version, rule_json, approved_by=None)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO policies (id, org_id, name, description, rule_json, created_at, inherits_from, version)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                policy_id,
                org_id,
                payload.name,
                payload.description,
                rule_json,
                created_at,
                payload.inherits_from,
                version,
            ),
        )
        conn.execute(
            "INSERT INTO policy_revisions (id, policy_id, org_id, version, description, rule_json, approved_by, approval_signature, rego_text, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                policy_id,
                org_id,
                version,
                payload.description,
                rule_json,
                None,
                approval_sig,
                _rego_from_rule(payload.rule),
                created_at,
            ),
        )
    return Policy(id=policy_id, org_id=org_id, created_at=created_at, version=version, **payload.model_dump())


@app.post("/v1/policies", response_model=Policy)
def v1_create_policy(
    payload: PolicyCreate,
    key_row: dict = Depends(_require_org_and_scopes(["policies:write"])),
) -> Policy:
    return create_policy(payload, key_row)


@app.get("/policies", response_model=list[Policy])
def list_policies(key_row: dict = Depends(_require_org_and_scopes(["policies:read"]))) -> list[Policy]:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM policies WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    return [_policy_model_from_row(row_to_dict(row)) for row in rows]


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
    return _policy_model_from_row(row_to_dict(row))


@app.put("/policies/{policy_id}", response_model=Policy)
def update_policy(
    policy_id: str,
    payload: PolicyRevisionCreate,
    key_row: dict = Depends(_require_org_and_scopes(["policies:write"])),
) -> Policy:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        current = conn.execute(
            "SELECT * FROM policies WHERE id = ? AND org_id = ?",
            (policy_id, org_id),
        ).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="Policy not found")
        current_version = int(row_to_dict(current).get("version") or 1)
        next_version = current_version + 1
        rule_json = dump_json_field(payload.rule.model_dump())
        approval_sig = _policy_approval_signature(policy_id, next_version, rule_json, payload.approved_by)
        conn.execute(
            "UPDATE policies SET description = ?, rule_json = ?, version = ? WHERE id = ?",
            (payload.description, rule_json, next_version, policy_id),
        )
        conn.execute(
            "INSERT INTO policy_revisions (id, policy_id, org_id, version, description, rule_json, approved_by, approval_signature, rego_text, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                policy_id,
                org_id,
                next_version,
                payload.description,
                rule_json,
                payload.approved_by,
                approval_sig,
                payload.rego_text or _rego_from_rule(payload.rule),
                now_iso(),
            ),
        )
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    return _policy_model_from_row(row_to_dict(row))


@app.get("/policies/{policy_id}/revisions", response_model=list[PolicyRevision])
def list_policy_revisions(
    policy_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["policies:read"])),
) -> list[PolicyRevision]:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM policy_revisions WHERE policy_id = ? AND org_id = ? ORDER BY version DESC",
            (policy_id, org_id),
        ).fetchall()
    revisions = []
    for row in rows:
        data = row_to_dict(row)
        revisions.append(
            PolicyRevision(
                id=data["id"],
                policy_id=data["policy_id"],
                org_id=data["org_id"],
                version=int(data["version"]),
                description=data.get("description"),
                rule=PolicyRule(**parse_json_field(data["rule_json"])),
                approved_by=data.get("approved_by"),
                approval_signature=data.get("approval_signature"),
                rego_text=data.get("rego_text"),
                created_at=data["created_at"],
            )
        )
    return revisions


@app.post("/policies/{policy_id}/rollback", response_model=Policy)
def rollback_policy(
    policy_id: str,
    version: int,
    key_row: dict = Depends(_require_org_and_scopes(["policies:write"])),
) -> Policy:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        revision = conn.execute(
            "SELECT * FROM policy_revisions WHERE policy_id = ? AND org_id = ? AND version = ?",
            (policy_id, org_id, version),
        ).fetchone()
        if not revision:
            raise HTTPException(status_code=404, detail="Revision not found")
        current = conn.execute(
            "SELECT * FROM policies WHERE id = ? AND org_id = ?",
            (policy_id, org_id),
        ).fetchone()
        current_version = int(row_to_dict(current).get("version") or 1)
        next_version = current_version + 1
        rule_json = row_to_dict(revision)["rule_json"]
        approval_sig = _policy_approval_signature(policy_id, next_version, rule_json, approved_by="rollback")
        conn.execute(
            "UPDATE policies SET rule_json = ?, version = ? WHERE id = ?",
            (rule_json, next_version, policy_id),
        )
        conn.execute(
            "INSERT INTO policy_revisions (id, policy_id, org_id, version, description, rule_json, approved_by, approval_signature, rego_text, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                policy_id,
                org_id,
                next_version,
                f"Rollback to v{version}",
                rule_json,
                "rollback",
                approval_sig,
                row_to_dict(revision).get("rego_text"),
                now_iso(),
            ),
        )
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    return _policy_model_from_row(row_to_dict(row))


@app.post("/policies/{policy_id}/simulate", response_model=PlaygroundDecision)
def simulate_policy(
    policy_id: str,
    payload: PlaygroundRequest,
    version: int | None = None,
    as_of: str | None = None,
    key_row: dict = Depends(_require_org_and_scopes(["policies:read", "resources:read"])),
) -> PlaygroundDecision:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        if version is not None:
            rev = conn.execute(
                "SELECT * FROM policy_revisions WHERE policy_id = ? AND org_id = ? AND version = ?",
                (policy_id, org_id, version),
            ).fetchone()
        elif as_of:
            rev = conn.execute(
                "SELECT * FROM policy_revisions WHERE policy_id = ? AND org_id = ? AND created_at <= ?"
                " ORDER BY created_at DESC LIMIT 1",
                (policy_id, org_id, as_of),
            ).fetchone()
        else:
            rev = conn.execute(
                "SELECT * FROM policy_revisions WHERE policy_id = ? AND org_id = ? ORDER BY version DESC LIMIT 1",
                (policy_id, org_id),
            ).fetchone()
        resource_row = conn.execute(
            "SELECT * FROM resources WHERE id = ? AND org_id = ?",
            (payload.resource_id, org_id),
        ).fetchone()
    if not rev:
        raise HTTPException(status_code=404, detail="Policy revision not found")
    if not resource_row:
        raise HTTPException(status_code=404, detail="Resource not found")
    rule = PolicyRule(**parse_json_field(row_to_dict(rev)["rule_json"]))
    resource_data = row_to_dict(resource_row)
    resource = Resource(
        id=resource_data["id"],
        org_id=resource_data["org_id"],
        name=resource_data["name"],
        type=resource_data["type"],
        attributes=parse_json_field(resource_data["attributes_json"]),
        source_system=resource_data.get("source_system") or "manual",
        external_id=resource_data.get("external_id"),
        ai_metadata=parse_json_field(resource_data.get("ai_metadata_json", "")) or None,
        created_at=resource_data["created_at"],
    )
    decision, rationale, explain = evaluate_policy(rule, payload.principal, payload.action, resource)
    return PlaygroundDecision(
        policy_id=policy_id,
        decision=decision,
        rationale=rationale,
        matched_attributes={**rule.required_attributes, **(explain or {})},
    )


@app.get("/policies/{policy_id}/rego", response_model=OpaPolicyExport)
def export_policy_rego(
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
    rego = _rego_from_rule(PolicyRule(**rule))
    return OpaPolicyExport(
        policy_id=policy_id,
        org_id=org_id,
        rule=rule,
        opa_input=opa_input,
        rego=rego,
    )


@app.post("/policies/import/rego", response_model=Policy)
def import_policy_rego(
    payload: dict,
    key_row: dict = Depends(_require_org_and_scopes(["policies:write"])),
) -> Policy:
    org_id = key_row["org_id"]
    name = payload.get("name")
    rego_text = payload.get("rego")
    if not name or not rego_text:
        raise HTTPException(status_code=400, detail="Missing name or rego")
    rule_json = None
    for line in rego_text.splitlines():
        if line.strip().startswith("#policy-json:"):
            rule_json = line.split(":", 1)[1].strip()
            break
    if not rule_json:
        raise HTTPException(status_code=400, detail="Rego missing #policy-json metadata")
    try:
        rule_dict = json.loads(rule_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid policy-json metadata") from exc
    policy = create_policy(
        PolicyCreate(
            name=name,
            description=payload.get("description"),
            rule=PolicyRule(**rule_dict),
            inherits_from=payload.get("inherits_from"),
        ),
        key_row,
    )
    with get_conn() as conn:
        conn.execute(
            "UPDATE policy_revisions SET rego_text = ? WHERE policy_id = ? AND version = 1",
            (rego_text, policy.id),
        )
    return policy


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
        rego=_rego_from_rule(PolicyRule(**rule)),
    )


@app.post("/policies/generate", response_model=PolicyCreate)
def generate_policy(
    prompt: dict,
    key_row: dict = Depends(_require_org_and_scopes(["policies:write"])),
) -> PolicyCreate:
    _ = key_row
    text = (prompt.get("text") or "").lower()
    llm = generate_policy_from_text(text)
    if llm and "rule" in llm:
        return PolicyCreate(
            name=llm.get("name") or prompt.get("name") or "Generated Policy",
            description=llm.get("description") or prompt.get("description"),
            rule=PolicyRule(**llm["rule"]),
        )
    rule = {
        "allowed_principals": ["*"],
        "allowed_actions": ["*"],
        "resource_types": ["*"],
        "required_attributes": {},
    }
    if "marketing" in text:
        rule["allowed_principals"] = ["marketing"]
    if "data scientist" in text or "data-scientist" in text:
        rule["allowed_principals"] = ["data-scientist"]
    if "gpt-4" in text:
        rule["required_attributes"]["model_type"] = "llm"
        rule["required_attributes"]["model_provider"] = "openai"
    if "sensitive" in text:
        rule["required_attributes"]["sensitivity_level"] = 4
    if "cannot" in text or "deny" in text:
        rule["allowed_actions"] = ["none"]
    name = prompt.get("name") or "Generated Policy"
    return PolicyCreate(name=name, description=prompt.get("description"), rule=PolicyRule(**rule))


@app.post("/resources", response_model=Resource)
def create_resource(
    payload: ResourceCreate,
    key_row: dict = Depends(_require_org_and_scopes(["resources:write"])),
) -> Resource:
    org_id = key_row["org_id"]
    resource_id = str(uuid.uuid4())
    created_at = now_iso()
    ai_metadata = payload.ai_metadata.model_dump() if payload.ai_metadata else {}
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO resources (id, org_id, name, type, attributes_json, source_system, external_id, ai_metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                resource_id,
                org_id,
                payload.name,
                payload.type,
                dump_json_field(payload.attributes),
                payload.source_system,
                payload.external_id,
                dump_json_field(ai_metadata),
                created_at,
            ),
        )
    return Resource(id=resource_id, org_id=org_id, created_at=created_at, **payload.model_dump())


@app.post("/v1/resources", response_model=Resource)
def v1_create_resource(
    payload: ResourceCreate,
    key_row: dict = Depends(_require_org_and_scopes(["resources:write"])),
) -> Resource:
    return create_resource(payload, key_row)


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
                ai_metadata=parse_json_field(data.get("ai_metadata_json", "")) or None,
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
        ai_metadata=parse_json_field(data.get("ai_metadata_json", "")) or None,
        created_at=data["created_at"],
    )


@app.post("/evaluations", response_model=Evaluation)
def evaluate(
    payload: EvaluationRequest,
    key_row: dict = Depends(_require_org_and_scopes(["evaluations:write"])),
) -> Evaluation:
    org_id = key_row["org_id"]
    _rate_limit(org_id)
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

    policy_rule = _resolve_policy_rule(org_id, policy_data)
    resource = Resource(
        id=resource_data["id"],
        org_id=resource_data["org_id"],
        name=resource_data["name"],
        type=resource_data["type"],
        attributes=parse_json_field(resource_data["attributes_json"]),
        source_system=resource_data.get("source_system") or "manual",
        external_id=resource_data.get("external_id"),
        ai_metadata=parse_json_field(resource_data.get("ai_metadata_json", "")) or None,
        created_at=resource_data["created_at"],
    )

    decision, rationale, explain = evaluate_policy(policy_rule, payload.principal, payload.action, resource)

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
            INSERT INTO evaluations (id, org_id, policy_id, principal, action, resource_id, decision, rationale, explain_json, created_at, prev_hash, record_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                dump_json_field(explain),
                created_at,
                prev_hash,
                record_hash,
            ),
        )
        conn.execute(
            "INSERT INTO decision_logs (id, org_id, payload_json, created_at) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), org_id, dump_json_field({**payload_hash, "explain": explain}), created_at),
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
        rule_snapshot=policy_rule.model_dump(),
        created_at=created_at,
        prev_hash=prev_hash,
        record_hash=record_hash,
        explain=explain,
    )


@app.post("/v1/evaluations", response_model=Evaluation)
def v1_evaluate(
    payload: EvaluationRequest,
    key_row: dict = Depends(_require_org_and_scopes(["evaluations:write"])),
) -> Evaluation:
    return evaluate(payload, key_row)


@app.post("/enforce", response_model=EnforcementDecision)
def enforce(
    payload: EnforcementRequest,
    key_row: dict = Depends(_require_org_and_scopes(["evaluations:write", "policies:read", "resources:read"])),
) -> EnforcementDecision:
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
    if not policy_row or not resource_row:
        raise HTTPException(status_code=404, detail="Policy or resource not found")
    policy_rule = _resolve_policy_rule(org_id, row_to_dict(policy_row))
    resource_data = row_to_dict(resource_row)
    resource = Resource(
        id=resource_data["id"],
        org_id=resource_data["org_id"],
        name=resource_data["name"],
        type=resource_data["type"],
        attributes=parse_json_field(resource_data["attributes_json"]),
        source_system=resource_data.get("source_system") or "manual",
        external_id=resource_data.get("external_id"),
        ai_metadata=parse_json_field(resource_data.get("ai_metadata_json", "")) or None,
        created_at=resource_data["created_at"],
    )
    decision, rationale, explain = evaluate_policy(policy_rule, payload.principal, payload.action, resource)
    risk_score = _compute_risk_score(resource, payload.action)
    threshold = payload.risk_threshold if payload.risk_threshold is not None else settings.risk_score_threshold
    enforced = False
    if payload.webhook_enforcement:
        with get_conn() as conn:
            webhook_row = conn.execute(
                "SELECT * FROM webhooks WHERE org_id = ? AND enabled = 1 ORDER BY created_at DESC LIMIT 1",
                (org_id,),
            ).fetchone()
        if webhook_row:
            status_code, response_body = _deliver_webhook(
                webhook_row["url"],
                webhook_row["secret"],
                {
                    "principal": payload.principal,
                    "action": payload.action,
                    "resource_id": payload.resource_id,
                    "policy_id": payload.policy_id,
                    "decision": decision,
                    "risk_score": risk_score,
                },
            )
            if status_code and response_body:
                try:
                    response_json = json.loads(response_body)
                    if response_json.get("decision") in {"allow", "deny"}:
                        decision = response_json["decision"]
                        rationale = response_json.get("rationale") or "Webhook enforcement decision"
                        enforced = True
                except json.JSONDecodeError:
                    pass
    if decision == "allow" and risk_score >= threshold:
        decision = "deny"
        rationale = "Denied by risk threshold"
        enforced = True
    return EnforcementDecision(
        decision=decision,
        rationale=rationale,
        risk_score=risk_score,
        enforced=enforced,
        policy_id=payload.policy_id,
        resource_id=payload.resource_id,
        principal=payload.principal,
        action=payload.action,
        explain=explain,
    )


@app.get("/evaluations/{evaluation_id}/replay", response_model=dict)
def replay_evaluation(
    evaluation_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["evaluations:read"])),
) -> dict:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        eval_row = conn.execute(
            "SELECT * FROM evaluations WHERE id = ? AND org_id = ?",
            (evaluation_id, org_id),
        ).fetchone()
        if not eval_row:
            raise HTTPException(status_code=404, detail="Evaluation not found")
        policy_row = conn.execute(
            "SELECT * FROM policies WHERE id = ? AND org_id = ?",
            (eval_row["policy_id"], org_id),
        ).fetchone()
        resource_row = conn.execute(
            "SELECT * FROM resources WHERE id = ? AND org_id = ?",
            (eval_row["resource_id"], org_id),
        ).fetchone()
    if not policy_row or not resource_row:
        raise HTTPException(status_code=404, detail="Policy or resource not found")
    policy_rule = _resolve_policy_rule(org_id, row_to_dict(policy_row))
    resource_data = row_to_dict(resource_row)
    resource = Resource(
        id=resource_data["id"],
        org_id=resource_data["org_id"],
        name=resource_data["name"],
        type=resource_data["type"],
        attributes=parse_json_field(resource_data["attributes_json"]),
        source_system=resource_data.get("source_system") or "manual",
        external_id=resource_data.get("external_id"),
        ai_metadata=parse_json_field(resource_data.get("ai_metadata_json", "")) or None,
        created_at=resource_data["created_at"],
    )
    new_decision, new_rationale, new_explain = evaluate_policy(
        policy_rule,
        eval_row["principal"],
        eval_row["action"],
        resource,
    )
    stored_decision = eval_row["decision"]
    drift = stored_decision != new_decision
    return {
        "evaluation_id": evaluation_id,
        "stored_decision": stored_decision,
        "new_decision": new_decision,
        "stored_rationale": eval_row.get("rationale"),
        "new_rationale": new_rationale,
        "drift": drift,
        "explain": new_explain,
    }


@app.post("/playground/evaluate", response_model=list[PlaygroundDecision])
def playground_evaluate(
    payload: PlaygroundRequest,
    key_row: dict = Depends(_require_org_and_scopes(["policies:read", "resources:read"])),
) -> list[PlaygroundDecision]:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        policy_rows = conn.execute(
            "SELECT * FROM policies WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
        resource_row = conn.execute(
            "SELECT * FROM resources WHERE id = ? AND org_id = ?",
            (payload.resource_id, org_id),
        ).fetchone()
    if not resource_row:
        raise HTTPException(status_code=404, detail="Resource not found")
    resource_data = row_to_dict(resource_row)
    resource = Resource(
        id=resource_data["id"],
        org_id=resource_data["org_id"],
        name=resource_data["name"],
        type=resource_data["type"],
        attributes=parse_json_field(resource_data["attributes_json"]),
        source_system=resource_data.get("source_system") or "manual",
        external_id=resource_data.get("external_id"),
        ai_metadata=parse_json_field(resource_data.get("ai_metadata_json", "")) or None,
        created_at=resource_data["created_at"],
    )
    results: list[PlaygroundDecision] = []
    for row in policy_rows:
        data = row_to_dict(row)
        rule = _resolve_policy_rule(org_id, data)
        decision, rationale, explain = evaluate_policy(rule, payload.principal, payload.action, resource)
        matched = {}
        combined_attributes = dict(resource.attributes)
        if resource.ai_metadata:
            combined_attributes.update(resource.ai_metadata)
        for key, value in rule.required_attributes.items():
            matched[key] = combined_attributes.get(key)
        if explain:
            matched.update(explain)
        results.append(
            PlaygroundDecision(
                policy_id=data["id"],
                decision=decision,
                rationale=rationale,
                matched_attributes=matched,
            )
        )
    return results


@app.get("/evaluations", response_model=list[Evaluation])
def list_evaluations(key_row: dict = Depends(_require_org_and_scopes(["evaluations:read"]))) -> list[Evaluation]:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM evaluations WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    return [_evaluation_from_row(row_to_dict(row)) for row in rows]


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


@app.post("/maintenance/cleanup", response_model=dict)
def maintenance_cleanup(
    key_row: dict = Depends(_require_org_and_scopes(["orgs:write"])),
) -> dict:
    org_id = key_row["org_id"]
    now = datetime.utcnow()
    decision_cutoff = (now - timedelta(days=settings.decision_log_retention_days)).isoformat() + "Z"
    webhook_cutoff = (now - timedelta(days=settings.webhook_delivery_retention_days)).isoformat() + "Z"
    export_cutoff = (now - timedelta(days=settings.retention_days)).isoformat() + "Z"
    with get_conn() as conn:
        decision_deleted = conn.execute(
            "DELETE FROM decision_logs WHERE org_id = ? AND created_at < ?",
            (org_id, decision_cutoff),
        ).rowcount
        webhook_deleted = conn.execute(
            "DELETE FROM webhook_deliveries WHERE webhook_id IN (SELECT id FROM webhooks WHERE org_id = ?) AND created_at < ?",
            (org_id, webhook_cutoff),
        ).rowcount
        export_deleted = conn.execute(
            "DELETE FROM evidence_exports WHERE org_id = ? AND created_at < ?",
            (org_id, export_cutoff),
        ).rowcount
    return {
        "org_id": org_id,
        "decision_logs_deleted": decision_deleted,
        "webhook_deliveries_deleted": webhook_deleted,
        "evidence_exports_deleted": export_deleted,
        "cutoffs": {
            "decision_logs_before": decision_cutoff,
            "webhook_deliveries_before": webhook_cutoff,
            "evidence_exports_before": export_cutoff,
        },
    }


@app.get("/evidence/search", response_model=EvidenceSearchResult)
def evidence_search(
    principal: str | None = None,
    policy_id: str | None = None,
    decision: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 50,
    offset: int = 0,
    key_row: dict = Depends(_require_org_and_scopes(["evidence:read"])),
) -> EvidenceSearchResult:
    org_id = key_row["org_id"]
    _rate_limit(org_id)
    conditions = ["org_id = ?"]
    params: list = [org_id]
    if principal:
        conditions.append("principal = ?")
        params.append(principal)
    if policy_id:
        conditions.append("policy_id = ?")
        params.append(policy_id)
    if decision:
        conditions.append("decision = ?")
        params.append(decision)
    if start:
        conditions.append("created_at >= ?")
        params.append(start)
    if end:
        conditions.append("created_at <= ?")
        params.append(end)
    where = " AND ".join(conditions)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM evaluations WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) as total FROM evaluations WHERE {where}",
            tuple(params),
        ).fetchone()
    total_count = total["total"] if isinstance(total, dict) else total[0]
    return EvidenceSearchResult(
        evaluations=[_evaluation_from_row(row_to_dict(row)) for row in rows],
        total=total_count,
    )


@app.get("/v1/evidence/search", response_model=EvidenceSearchResult)
def v1_evidence_search(
    principal: str | None = None,
    policy_id: str | None = None,
    decision: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 50,
    offset: int = 0,
    key_row: dict = Depends(_require_org_and_scopes(["evidence:read"])),
) -> EvidenceSearchResult:
    return evidence_search(principal, policy_id, decision, start, end, limit, offset, key_row)


@app.get("/evidence/verify", response_model=EvidenceVerifyResult)
def verify_evidence_chain(
    key_row: dict = Depends(_require_org_and_scopes(["evidence:read"])),
) -> EvidenceVerifyResult:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM evaluations WHERE org_id = ? ORDER BY created_at ASC",
            (org_id,),
        ).fetchall()
    prev_hash = None
    for row in rows:
        data = row_to_dict(row)
        payload_hash = {
            "org_id": data["org_id"],
            "policy_id": data["policy_id"],
            "principal": data["principal"],
            "action": data["action"],
            "resource_id": data["resource_id"],
            "decision": data["decision"],
            "rationale": data["rationale"],
            "created_at": data["created_at"],
        }
        expected = _hash_record(payload_hash, prev_hash)
        if data.get("record_hash") != expected:
            result = EvidenceVerifyResult(valid=False, checked_records=len(rows), last_hash=prev_hash)
            with get_conn() as conn:
                conn.execute(
                    "INSERT INTO evidence_verifications (id, org_id, valid, checked_records, last_hash, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), org_id, 0, result.checked_records, result.last_hash, now_iso()),
                )
            return result
        prev_hash = expected
    result = EvidenceVerifyResult(valid=True, checked_records=len(rows), last_hash=prev_hash)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO evidence_verifications (id, org_id, valid, checked_records, last_hash, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), org_id, 1, result.checked_records, result.last_hash, now_iso()),
        )
    return result


@app.post("/evidence/attestations", response_model=EvidenceAttestation)
def create_attestation(
    payload: EvidenceAttestationCreate,
    key_row: dict = Depends(_require_org_and_scopes(["evidence:read"])),
) -> EvidenceAttestation:
    org_id = key_row["org_id"]
    try:
        day = datetime.strptime(payload.date, "%Y-%m-%d")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid date format (YYYY-MM-DD)") from exc
    start_iso = day.isoformat() + "Z"
    end_iso = (day + timedelta(days=1)).isoformat() + "Z"
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT record_hash FROM evaluations WHERE org_id = ? AND created_at >= ? AND created_at < ? ORDER BY created_at ASC",
            (org_id, start_iso, end_iso),
        ).fetchall()
    record_hashes = [row["record_hash"] for row in rows if row["record_hash"]]
    digest_input = "".join(record_hashes)
    digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
    signature = hmac.new(
        settings.evidence_hmac_secret.encode("utf-8"),
        digest.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    attestation_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO evidence_attestations (id, org_id, date, record_count, digest, signature, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (attestation_id, org_id, payload.date, len(record_hashes), digest, signature, created_at),
        )
    return EvidenceAttestation(
        id=attestation_id,
        org_id=org_id,
        date=payload.date,
        record_count=len(record_hashes),
        digest=digest,
        signature=signature,
        created_at=created_at,
    )


@app.get("/evidence/attestations", response_model=list[EvidenceAttestation])
def list_attestations(
    key_row: dict = Depends(_require_org_and_scopes(["evidence:read"])),
) -> list[EvidenceAttestation]:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM evidence_attestations WHERE org_id = ? ORDER BY date DESC",
            (org_id,),
        ).fetchall()
    return [EvidenceAttestation(**row_to_dict(row)) for row in rows]


@app.get("/evidence/attestations/{date}", response_model=EvidenceAttestation)
def get_attestation(
    date: str,
    key_row: dict = Depends(_require_org_and_scopes(["evidence:read"])),
) -> EvidenceAttestation:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM evidence_attestations WHERE org_id = ? AND date = ?",
            (org_id, date),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Attestation not found")
    return EvidenceAttestation(**row_to_dict(row))


@app.get("/evidence/export", response_model=EvidenceExport)
def export_evidence(
    format: str = "json",
    principal: str | None = None,
    policy_id: str | None = None,
    decision: str | None = None,
    start: str | None = None,
    end: str | None = None,
    key_row: dict = Depends(_require_org_and_scopes(["evidence:read"])),
):
    org_id = key_row["org_id"]
    _rate_limit(org_id)
    conditions = ["org_id = ?"]
    params: list = [org_id]
    if principal:
        conditions.append("principal = ?")
        params.append(principal)
    if policy_id:
        conditions.append("policy_id = ?")
        params.append(policy_id)
    if decision:
        conditions.append("decision = ?")
        params.append(decision)
    if start:
        conditions.append("created_at >= ?")
        params.append(start)
    if end:
        conditions.append("created_at <= ?")
        params.append(end)
    where = " AND ".join(conditions)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM evaluations WHERE {where} ORDER BY created_at DESC",
            tuple(params),
        ).fetchall()
    evaluations = [_evaluation_from_row(row_to_dict(row)) for row in rows]
    exported_at = now_iso()
    export_id = str(uuid.uuid4())

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
        content_hash = _hash_content(csv_data)
        content_bytes = len(csv_data.encode("utf-8"))
        _append_to_vault(csv_data, export_id)
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO evidence_exports (id, org_id, format, content_hash, signature, content_bytes, record_count, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (export_id, org_id, "csv", content_hash, signature, content_bytes, len(evaluations), exported_at),
            )
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"X-Evidence-Signature": signature, "X-Evidence-Export-Id": export_id},
        )

    json_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = hmac.new(
        settings.evidence_hmac_secret.encode("utf-8"),
        json_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    content_hash = _hash_content(json_payload)
    content_bytes = len(json_payload.encode("utf-8"))
    _append_to_vault(json_payload, export_id)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO evidence_exports (id, org_id, format, content_hash, signature, content_bytes, record_count, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (export_id, org_id, "json", content_hash, signature, content_bytes, len(evaluations), exported_at),
        )

    return EvidenceExport(
        export_id=export_id,
        org_id=org_id,
        exported_at=exported_at,
        format="json",
        signature=signature,
        evaluations=evaluations,
    )


@app.get("/v1/evidence/export", response_model=EvidenceExport)
def v1_export_evidence(
    format: str = "json",
    principal: str | None = None,
    policy_id: str | None = None,
    decision: str | None = None,
    start: str | None = None,
    end: str | None = None,
    key_row: dict = Depends(_require_org_and_scopes(["evidence:read"])),
):
    return export_evidence(format, principal, policy_id, decision, start, end, key_row)


@app.get("/connectors")
def list_connector_metadata(key_row: dict = Depends(_require_org_and_scopes(["connectors:read"]))) -> list[dict]:
    _ = key_row
    return [meta.__dict__ for meta in list_connectors()]


@app.post("/webhooks", response_model=Webhook)
def create_webhook(
    payload: WebhookCreate,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:write"])),
) -> Webhook:
    org_id = key_row["org_id"]
    webhook_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO webhooks (id, org_id, url, secret, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (webhook_id, org_id, payload.url, payload.secret, 1 if payload.enabled else 0, created_at),
        )
    return Webhook(
        id=webhook_id,
        org_id=org_id,
        url=payload.url,
        secret=payload.secret,
        enabled=payload.enabled,
        created_at=created_at,
    )


@app.get("/webhooks", response_model=list[Webhook])
def list_webhooks(key_row: dict = Depends(_require_org_and_scopes(["orgs:read"]))) -> list[Webhook]:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM webhooks WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    return [
        Webhook(
            id=row["id"],
            org_id=row["org_id"],
            url=row["url"],
            secret=row["secret"],
            enabled=bool(row["enabled"]),
            created_at=row["created_at"],
        )
        for row in rows
    ]


@app.post("/webhooks/{webhook_id}/rotate-secret", response_model=Webhook)
def rotate_webhook_secret(
    webhook_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:write"])),
) -> Webhook:
    org_id = key_row["org_id"]
    new_secret = secrets.token_urlsafe(24)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM webhooks WHERE id = ? AND org_id = ?",
            (webhook_id, org_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Webhook not found")
        conn.execute(
            "UPDATE webhooks SET secret = ? WHERE id = ?",
            (new_secret, webhook_id),
        )
    data = row_to_dict(row)
    return Webhook(
        id=data["id"],
        org_id=data["org_id"],
        url=data["url"],
        secret=new_secret,
        enabled=bool(data["enabled"]),
        created_at=data["created_at"],
    )


@app.post("/webhooks/{webhook_id}/test", response_model=WebhookDelivery)
def test_webhook(
    webhook_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:write"])),
) -> WebhookDelivery:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        webhook_row = conn.execute(
            "SELECT * FROM webhooks WHERE id = ? AND org_id = ?",
            (webhook_id, org_id),
        ).fetchone()
        log_row = conn.execute(
            "SELECT * FROM decision_logs WHERE org_id = ? ORDER BY created_at DESC LIMIT 1",
            (org_id,),
        ).fetchone()
    if not webhook_row:
        raise HTTPException(status_code=404, detail="Webhook not found")
    payload = parse_json_field(log_row["payload_json"]) if log_row else {"message": "no logs"}
    status_code, response_body = _deliver_webhook(
        webhook_row["url"], webhook_row["secret"], payload
    )
    delivery_id = str(uuid.uuid4())
    created_at = now_iso()
    success = 1 if status_code and status_code < 300 else 0
    attempts = 1
    next_attempt_at = None if success else (datetime.utcnow() + timedelta(seconds=2)).isoformat() + "Z"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO webhook_deliveries (id, webhook_id, status_code, response_body, attempts, next_attempt_at, success, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (delivery_id, webhook_id, status_code, response_body, attempts, next_attempt_at, success, created_at),
        )
    return WebhookDelivery(
        id=delivery_id,
        webhook_id=webhook_id,
        status_code=status_code,
        response_body=response_body,
        attempts=attempts,
        next_attempt_at=next_attempt_at,
        success=bool(success),
        created_at=created_at,
    )


@app.get("/webhooks/{webhook_id}/deliveries", response_model=list[WebhookDelivery])
def list_webhook_deliveries(
    webhook_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:read"])),
) -> list[WebhookDelivery]:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        wh = conn.execute(
            "SELECT * FROM webhooks WHERE id = ? AND org_id = ?",
            (webhook_id, org_id),
        ).fetchone()
        if not wh:
            raise HTTPException(status_code=404, detail="Webhook not found")
        rows = conn.execute(
            "SELECT * FROM webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC",
            (webhook_id,),
        ).fetchall()
    return [WebhookDelivery(**row_to_dict(row)) for row in rows]


@app.post("/webhooks/{webhook_id}/retry", response_model=WebhookDelivery)
def retry_webhook(
    webhook_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:write"])),
) -> WebhookDelivery:
    org_id = key_row["org_id"]
    with get_conn() as conn:
        webhook_row = conn.execute(
            "SELECT * FROM webhooks WHERE id = ? AND org_id = ?",
            (webhook_id, org_id),
        ).fetchone()
        log_row = conn.execute(
            "SELECT * FROM decision_logs WHERE org_id = ? ORDER BY created_at DESC LIMIT 1",
            (org_id,),
        ).fetchone()
    if not webhook_row:
        raise HTTPException(status_code=404, detail="Webhook not found")
    payload = parse_json_field(log_row["payload_json"]) if log_row else {"message": "no logs"}
    status_code, response_body = _deliver_webhook(
        webhook_row["url"], webhook_row["secret"], payload
    )
    delivery_id = str(uuid.uuid4())
    created_at = now_iso()
    with get_conn() as conn:
        last = conn.execute(
            "SELECT attempts FROM webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 1",
            (webhook_id,),
        ).fetchone()
    attempts = (last["attempts"] if last else 0) + 1
    success = 1 if status_code and status_code < 300 else 0
    backoff = 2 ** min(attempts, 6)
    next_attempt_at = None if success else (datetime.utcnow() + timedelta(seconds=backoff)).isoformat() + "Z"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO webhook_deliveries (id, webhook_id, status_code, response_body, attempts, next_attempt_at, success, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (delivery_id, webhook_id, status_code, response_body, attempts, next_attempt_at, success, created_at),
        )
    return WebhookDelivery(
        id=delivery_id,
        webhook_id=webhook_id,
        status_code=status_code,
        response_body=response_body,
        attempts=attempts,
        next_attempt_at=next_attempt_at,
        success=bool(success),
        created_at=created_at,
    )


@app.get("/decision-logs/export", response_model=DecisionLogExport)
def export_decision_logs(
    format: str = "json",
    key_row: dict = Depends(_require_org_and_scopes(["evidence:read"])),
):
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM decision_logs WHERE org_id = ? ORDER BY created_at DESC LIMIT 1000",
            (org_id,),
        ).fetchall()
    exported_at = now_iso()
    if format == "csv":
        serialized = io.StringIO()
        writer = csv.DictWriter(serialized, fieldnames=["id", "org_id", "payload_json", "created_at"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row_to_dict(row))
        return Response(content=serialized.getvalue(), media_type="text/csv")
    return DecisionLogExport(org_id=org_id, exported_at=exported_at, total=len(rows))


@app.get("/audit/export")
def export_audit_log(
    format: str = "csv",
    key_row: dict = Depends(_require_org_and_scopes(["evidence:read"])),
):
    org_id = key_row["org_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM evaluations WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    serialized = io.StringIO()
    writer = csv.DictWriter(serialized, fieldnames=list(Evaluation.model_fields.keys()))
    writer.writeheader()
    for row in rows:
        writer.writerow(row_to_dict(row))
    csv_data = serialized.getvalue()
    checksum = hashlib.sha256(csv_data.encode("utf-8")).hexdigest()
    return Response(content=csv_data, media_type="text/csv", headers={"X-Audit-Checksum": checksum})


@app.get("/decision-logs/stream")
def stream_decision_logs(
    key_row: dict = Depends(_require_org_and_scopes(["evidence:read"])),
):
    org_id = key_row["org_id"]

    def generator():
        last_sent = None
        for _ in range(5):
            with get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM decision_logs WHERE org_id = ? ORDER BY created_at DESC LIMIT 1",
                    (org_id,),
                ).fetchone()
            if row:
                payload = row_to_dict(row)
                if payload.get("id") != last_sent:
                    last_sent = payload.get("id")
                    yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(1)

    from fastapi.responses import StreamingResponse
    return StreamingResponse(generator(), media_type="text/event-stream")


@app.get("/orgs/{org_id}/usage", response_model=UsageSummary)
def org_usage(
    org_id: str,
    period: str | None = None,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:read"])),
) -> UsageSummary:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if period is None:
        period = datetime.utcnow().strftime("%Y-%m")
    try:
        period_start = datetime.strptime(period + "-01", "%Y-%m-%d")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid period format, use YYYY-MM") from exc
    if period_start.month == 12:
        period_end = datetime(period_start.year + 1, 1, 1)
    else:
        period_end = datetime(period_start.year, period_start.month + 1, 1)
    start_iso = period_start.isoformat() + "Z"
    end_iso = period_end.isoformat() + "Z"

    with get_conn() as conn:
        eval_count_row = conn.execute(
            "SELECT COUNT(*) as total FROM evaluations WHERE org_id = ? AND created_at >= ? AND created_at < ?",
            (org_id, start_iso, end_iso),
        ).fetchone()
        export_rows = conn.execute(
            "SELECT SUM(content_bytes) as total_bytes FROM evidence_exports WHERE org_id = ? AND created_at >= ? AND created_at < ?",
            (org_id, start_iso, end_iso),
        ).fetchone()
        api_key_rows = conn.execute(
            "SELECT COUNT(*) as total FROM api_keys WHERE org_id = ? AND revoked_at IS NULL",
            (org_id,),
        ).fetchone()
        policy_rows = conn.execute(
            "SELECT COUNT(*) as total FROM policies WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        resource_rows = conn.execute(
            "SELECT COUNT(*) as total FROM resources WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        webhook_rows = conn.execute(
            "SELECT COUNT(*) as total FROM webhooks WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        user_rows = conn.execute(
            "SELECT COUNT(*) as total FROM org_memberships WHERE org_id = ?",
            (org_id,),
        ).fetchone()
    total_evaluations = eval_count_row["total"] if isinstance(eval_count_row, dict) else eval_count_row[0]
    total_bytes = export_rows["total_bytes"] if isinstance(export_rows, dict) else export_rows[0]
    total_bytes = total_bytes or 0
    total_mb = round(total_bytes / (1024 * 1024), 2)
    active_api_keys = api_key_rows["total"] if isinstance(api_key_rows, dict) else api_key_rows[0]
    total_policies = policy_rows["total"] if isinstance(policy_rows, dict) else policy_rows[0]
    total_resources = resource_rows["total"] if isinstance(resource_rows, dict) else resource_rows[0]
    total_webhooks = webhook_rows["total"] if isinstance(webhook_rows, dict) else webhook_rows[0]
    total_users = user_rows["total"] if isinstance(user_rows, dict) else user_rows[0]

    return UsageSummary(
        org_id=org_id,
        period=period,
        total_evaluations=total_evaluations,
        total_evidence_stored_mb=total_mb,
        active_api_keys=active_api_keys,
        total_policies=total_policies,
        total_resources=total_resources,
        total_webhooks=total_webhooks,
        total_users=total_users,
    )


@app.get("/orgs/{org_id}/export", response_model=OrgExport)
def export_org(
    org_id: str,
    key_row: dict = Depends(_require_org_and_scopes(["orgs:read"])),
) -> OrgExport:
    if key_row["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    with get_conn() as conn:
        org_row = conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
        if not org_row:
            raise HTTPException(status_code=404, detail="Org not found")
        user_rows = conn.execute(
            "SELECT u.* FROM users u JOIN org_memberships m ON u.id = m.user_id WHERE m.org_id = ?",
            (org_id,),
        ).fetchall()
        membership_rows = conn.execute(
            "SELECT * FROM org_memberships WHERE org_id = ?",
            (org_id,),
        ).fetchall()
        team_rows = conn.execute(
            "SELECT * FROM teams WHERE org_id = ?",
            (org_id,),
        ).fetchall()
        role_rows = conn.execute(
            "SELECT * FROM roles WHERE org_id = ?",
            (org_id,),
        ).fetchall()
        team_membership_rows = conn.execute(
            "SELECT * FROM team_memberships WHERE org_id = ?",
            (org_id,),
        ).fetchall()
        policy_rows = conn.execute(
            "SELECT * FROM policies WHERE org_id = ?",
            (org_id,),
        ).fetchall()
        resource_rows = conn.execute(
            "SELECT * FROM resources WHERE org_id = ?",
            (org_id,),
        ).fetchall()
        api_key_rows = conn.execute(
            "SELECT * FROM api_keys WHERE org_id = ?",
            (org_id,),
        ).fetchall()
        webhook_rows = conn.execute(
            "SELECT * FROM webhooks WHERE org_id = ?",
            (org_id,),
        ).fetchall()
    org = Org(**row_to_dict(org_row))
    users = [User(**row_to_dict(row)) for row in user_rows]
    memberships = [Membership(**row_to_dict(row)) for row in membership_rows]
    teams = [Team(**row_to_dict(row)) for row in team_rows]
    roles = [
        Role(
            id=row["id"],
            org_id=row["org_id"],
            name=row["name"],
            permissions=parse_json_field(row["permissions_json"]),
            created_at=row["created_at"],
        )
        for row in role_rows
    ]
    team_memberships = [TeamMembership(**row_to_dict(row)) for row in team_membership_rows]
    policies = [
        Policy(
            id=row["id"],
            org_id=row["org_id"],
            name=row["name"],
            description=row["description"],
            rule=PolicyRule(**parse_json_field(row["rule_json"])),
            created_at=row["created_at"],
        )
        for row in policy_rows
    ]
    resources = [
        Resource(
            id=row["id"],
            org_id=row["org_id"],
            name=row["name"],
            type=row["type"],
            attributes=parse_json_field(row["attributes_json"]),
            source_system=row.get("source_system") or "manual",
            external_id=row.get("external_id"),
            ai_metadata=parse_json_field(row.get("ai_metadata_json", "")) or None,
            created_at=row["created_at"],
        )
        for row in resource_rows
    ]
    api_keys = [
        ApiKey(
            id=row["id"],
            org_id=row["org_id"],
            name=row["name"],
            scopes=parse_json_field(row["scopes_json"]),
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            revoked_at=row["revoked_at"],
        )
        for row in api_key_rows
    ]
    webhooks = [
        Webhook(
            id=row["id"],
            org_id=row["org_id"],
            url=row["url"],
            secret=row["secret"],
            enabled=bool(row["enabled"]),
            created_at=row["created_at"],
        )
        for row in webhook_rows
    ]
    return OrgExport(
        org=org,
        users=users,
        memberships=memberships,
        teams=teams,
        roles=roles,
        team_memberships=team_memberships,
        policies=policies,
        resources=resources,
        api_keys=api_keys,
        webhooks=webhooks,
        created_at=now_iso(),
    )


@app.get("/trust/last-checks", response_model=list[TrustCheck])
def trust_last_checks() -> list[TrustCheck]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT valid, checked_records, created_at FROM evidence_verifications ORDER BY created_at DESC LIMIT 10"
        ).fetchall()
    return [
        TrustCheck(
            created_at=row["created_at"],
            valid=bool(row["valid"]),
            checked_records=row["checked_records"],
        )
        for row in rows
    ]


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


@app.get("/trust-badge.js", response_class=Response)
def trust_badge_script() -> Response:
    script = """
(() => {
  async function load() {
    const res = await fetch('/trust/last-checks');
    const data = res.ok ? await res.json() : [];
    const latest = data[0];
    const el = document.getElementById('ug-trust-badge');
    if (!el) return;
    const status = latest && latest.valid ? 'Verified' : 'Unknown';
    el.style.cssText = 'display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;background:#ecfeff;border:1px solid #a5f3fc;font-size:12px;color:#0f172a;';
    el.textContent = `System Integrity: ${status}`;
  }
  load();
})();
"""
    return Response(content=script, media_type="application/javascript")
