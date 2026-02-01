from fastapi.testclient import TestClient

from src.app import app


client = TestClient(app)


def _create_org_and_key():
    org_resp = client.post("/orgs", json={"name": "Acme"})
    assert org_resp.status_code == 200
    org_id = org_resp.json()["id"]

    key_resp = client.post(f"/orgs/{org_id}/keys", json={"name": "test"})
    assert key_resp.status_code == 200
    api_key = key_resp.json()["api_key"]
    return org_id, api_key


def test_policy_resource_evaluation_flow():
    org_id, api_key = _create_org_and_key()
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

    evidence_resp = client.get("/evidence/export", headers=headers)
    assert evidence_resp.status_code == 200
    assert evidence_resp.json()["org_id"] == org_id


def test_evidence_csv_export_signature_header():
    _, api_key = _create_org_and_key()
    headers = {"X-API-Key": api_key}

    response = client.get("/evidence/export?format=csv", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("X-Evidence-Signature")
    assert "text/csv" in response.headers.get("content-type", "")
