from fastapi.testclient import TestClient

from src.app import app


client = TestClient(app)


def _create_org_and_key(scopes=None):
    org_resp = client.post("/orgs", json={"name": "Acme"})
    assert org_resp.status_code == 200
    org_id = org_resp.json()["id"]

    key_payload = {"name": "test"}
    if scopes is not None:
        key_payload["scopes"] = scopes

    key_resp = client.post(f"/orgs/{org_id}/keys", json=key_payload)
    assert key_resp.status_code == 200
    api_key = key_resp.json()["api_key"]
    key_id = key_resp.json()["id"]
    return org_id, api_key, key_id


def test_policy_resource_evaluation_flow():
    org_id, api_key, _ = _create_org_and_key()
    headers = {"X-API-Key": api_key}

    policy_resp = client.post(
        "/policies",
        headers=headers,
        json={
            "name": "Allow finance read",
            "description": "Allow finance user to read payroll resources",
            "rule": {
                "allowed_principals": ["finance-user"],
                "allowed_actions": ["read"],
                "resource_types": ["payroll"],
                "required_attributes": {"sensitivity": "high"},
            },
        },
    )
    assert policy_resp.status_code == 200
    policy_id = policy_resp.json()["id"]

    resource_resp = client.post(
        "/resources",
        headers=headers,
        json={
            "name": "Payroll DB",
            "type": "payroll",
            "attributes": {"sensitivity": "high"},
            "source_system": "snowflake",
            "external_id": "table-abc",
            "ai_metadata": {
                "model_type": "llm",
                "model_provider": "openai",
                "sensitivity_level": 4,
                "is_governed": True,
            },
        },
    )
    assert resource_resp.status_code == 200
    resource_id = resource_resp.json()["id"]

    evaluation_resp = client.post(
        "/evaluations",
        headers=headers,
        json={
            "policy_id": policy_id,
            "principal": "finance-user",
            "action": "read",
            "resource_id": resource_id,
        },
    )
    assert evaluation_resp.status_code == 200
    assert evaluation_resp.json()["decision"] == "allow"
    assert evaluation_resp.json()["record_hash"]

    evidence_resp = client.get("/evidence/export", headers=headers)
    assert evidence_resp.status_code == 200
    assert evidence_resp.json()["org_id"] == org_id
    assert evidence_resp.json()["export_id"]

    verify_resp = client.get("/evidence/verify", headers=headers)
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True


def test_evidence_csv_export_signature_header():
    _, api_key, _ = _create_org_and_key()
    headers = {"X-API-Key": api_key}

    response = client.get("/evidence/export?format=csv", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("X-Evidence-Signature")
    assert response.headers.get("X-Evidence-Export-Id")
    assert "text/csv" in response.headers.get("content-type", "")


def test_key_rotation_and_revocation():
    org_id, api_key, key_id = _create_org_and_key(scopes=["orgs:read", "orgs:write"])
    headers = {"X-API-Key": api_key}

    rotate_resp = client.post(f"/orgs/{org_id}/keys/{key_id}/rotate", headers=headers)
    assert rotate_resp.status_code == 200
    new_key = rotate_resp.json()["api_key"]
    assert new_key

    list_resp = client.get(f"/orgs/{org_id}/keys", headers={"X-API-Key": new_key})
    assert list_resp.status_code == 200

    revoke_resp = client.post(f"/orgs/{org_id}/keys/{key_id}/revoke", headers={"X-API-Key": new_key})
    assert revoke_resp.status_code == 200

    list_after_revoke = client.get(f"/orgs/{org_id}/keys", headers={"X-API-Key": new_key})
    assert list_after_revoke.status_code == 401


def test_retention_enforcement():
    _, api_key, _ = _create_org_and_key(scopes=["evidence:write", "evidence:read", "policies:write", "resources:write", "evaluations:write"])
    headers = {"X-API-Key": api_key}

    policy_resp = client.post(
        "/policies",
        headers=headers,
        json={
            "name": "Allow all",
            "rule": {
                "allowed_principals": ["*"],
                "allowed_actions": ["*"],
                "resource_types": ["*"],
                "required_attributes": {},
            },
        },
    )
    resource_resp = client.post(
        "/resources",
        headers=headers,
        json={
            "name": "Test",
            "type": "db",
            "attributes": {},
            "source_system": "manual",
        },
    )
    evaluation_resp = client.post(
        "/evaluations",
        headers=headers,
        json={
            "policy_id": policy_resp.json()["id"],
            "principal": "p",
            "action": "a",
            "resource_id": resource_resp.json()["id"],
        },
    )
    assert evaluation_resp.status_code == 200

    retain_resp = client.post("/evidence/retain", headers=headers)
    assert retain_resp.status_code == 200


def test_opa_export():
    _, api_key, _ = _create_org_and_key(scopes=["policies:read", "policies:write"])
    headers = {"X-API-Key": api_key}

    policy_resp = client.post(
        "/policies",
        headers=headers,
        json={
            "name": "Allow read",
            "rule": {
                "allowed_principals": ["user"],
                "allowed_actions": ["read"],
                "resource_types": ["file"],
                "required_attributes": {},
            },
        },
    )
    policy_id = policy_resp.json()["id"]

    export_resp = client.get(f"/policies/{policy_id}/opa", headers=headers)
    assert export_resp.status_code == 200
    assert export_resp.json()["policy_id"] == policy_id


def test_scim_user_flow():
    _, api_key, _ = _create_org_and_key(scopes=["scim:read", "scim:write"])
    headers = {"X-API-Key": api_key}

    create_resp = client.post(
        "/scim/Users",
        headers=headers,
        json={
            "userName": "alice@example.com",
            "name": {"formatted": "Alice Example"},
            "emails": [{"value": "alice@example.com", "primary": True}],
            "active": True,
        },
    )
    assert create_resp.status_code == 200
    user_id = create_resp.json()["id"]

    list_resp = client.get("/scim/Users", headers=headers)
    assert list_resp.status_code == 200
    assert list_resp.json()["totalResults"] >= 1

    get_resp = client.get(f"/scim/Users/{user_id}", headers=headers)
    assert get_resp.status_code == 200

    delete_resp = client.delete(f"/scim/Users/{user_id}", headers=headers)
    assert delete_resp.status_code == 200


def test_sso_initiate_flows():
    org_id, api_key, _ = _create_org_and_key(scopes=["sso:read", "sso:write"])
    headers = {"X-API-Key": api_key}

    saml_resp = client.post(
        f"/orgs/{org_id}/sso",
        headers=headers,
        json={"provider": "saml", "metadata": {"sso_url": "https://idp.example.com/sso"}},
    )
    assert saml_resp.status_code == 200

    oidc_resp = client.post(
        f"/orgs/{org_id}/sso",
        headers=headers,
        json={"provider": "oidc", "metadata": {"authorize_url": "https://idp.example.com/authorize", "client_id": "client"}},
    )
    assert oidc_resp.status_code == 200

    saml_init = client.post(
        "/sso/saml/initiate",
        headers=headers,
        json={"org_id": org_id, "relay_state": "xyz"},
    )
    assert saml_init.status_code == 200
    assert saml_init.json()["sso_url"].startswith("https://")

    oidc_init = client.post(
        "/sso/oidc/initiate",
        headers=headers,
        json={"org_id": org_id, "redirect_uri": "https://app.example.com/callback", "state": "abc"},
    )
    assert oidc_init.status_code == 200
    assert "authorize" in oidc_init.json()["authorization_url"]


def test_rbac_team_role_membership_flow():
    org_id, api_key, _ = _create_org_and_key(scopes=["rbac:read", "rbac:write"])
    headers = {"X-API-Key": api_key}

    user_resp = client.post(
        "/users",
        json={"email": "rbac@example.com", "name": "RBAC User"},
    )
    assert user_resp.status_code == 200
    user_id = user_resp.json()["id"]

    team_resp = client.post(
        f"/orgs/{org_id}/teams",
        headers=headers,
        json={"name": "Security", "description": "Security team"},
    )
    assert team_resp.status_code == 200
    team_id = team_resp.json()["id"]

    role_resp = client.post(
        f"/orgs/{org_id}/roles",
        headers=headers,
        json={"name": "Admin", "permissions": ["policies:write", "evidence:read"]},
    )
    assert role_resp.status_code == 200
    role_id = role_resp.json()["id"]

    membership_resp = client.post(
        f"/orgs/{org_id}/team-memberships",
        headers=headers,
        json={"user_id": user_id, "team_id": team_id, "role_id": role_id},
    )
    assert membership_resp.status_code == 200

    list_roles = client.get(f"/orgs/{org_id}/roles", headers=headers)
    assert list_roles.status_code == 200
    assert len(list_roles.json()) >= 1

    list_teams = client.get(f"/orgs/{org_id}/teams", headers=headers)
    assert list_teams.status_code == 200
    assert len(list_teams.json()) >= 1

    list_memberships = client.get(f"/orgs/{org_id}/team-memberships", headers=headers)
    assert list_memberships.status_code == 200
    assert len(list_memberships.json()) >= 1


def test_usage_endpoint():
    org_id, api_key, _ = _create_org_and_key(scopes=["orgs:read", "policies:write", "resources:write", "evaluations:write", "evidence:read"])
    headers = {"X-API-Key": api_key}

    policy_resp = client.post(
        "/policies",
        headers=headers,
        json={
            "name": "Allow all",
            "rule": {
                "allowed_principals": ["*"],
                "allowed_actions": ["*"],
                "resource_types": ["*"],
                "required_attributes": {},
            },
        },
    )
    resource_resp = client.post(
        "/resources",
        headers=headers,
        json={
            "name": "Usage Test",
            "type": "db",
            "attributes": {},
        },
    )
    client.post(
        "/evaluations",
        headers=headers,
        json={
            "policy_id": policy_resp.json()["id"],
            "principal": "p",
            "action": "a",
            "resource_id": resource_resp.json()["id"],
        },
    )
    client.get("/evidence/export", headers=headers)

    usage = client.get(f"/orgs/{org_id}/usage", headers=headers)
    assert usage.status_code == 200
    assert usage.json()["total_evaluations"] >= 1


def test_evidence_search():
    _, api_key, _ = _create_org_and_key(scopes=["evidence:read"])
    headers = {"X-API-Key": api_key}

    search = client.get("/evidence/search", headers=headers)
    assert search.status_code == 200
    assert "evaluations" in search.json()


def test_generate_policy():
    _, api_key, _ = _create_org_and_key(scopes=["policies:write"])
    headers = {"X-API-Key": api_key}
    resp = client.post("/policies/generate", headers=headers, json={"text": "Marketing cannot use GPT-4 with sensitive data"})
    assert resp.status_code == 200
    assert resp.json()["rule"]["required_attributes"].get("model_provider") in ["openai", None]


def test_webhook_create_and_test():
    _, api_key, _ = _create_org_and_key(scopes=["orgs:write"])
    headers = {"X-API-Key": api_key}
    wh = client.post("/webhooks", headers=headers, json={"url": "https://example.com/webhook", "enabled": True})
    assert wh.status_code == 200
    wh_id = wh.json()["id"]
    test = client.post(f"/webhooks/{wh_id}/test", headers=headers)
    assert test.status_code == 200
    retry = client.post(f"/webhooks/{wh_id}/retry", headers=headers)
    assert retry.status_code == 200
