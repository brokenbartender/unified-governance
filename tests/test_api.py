from fastapi.testclient import TestClient

from src.app import app


client = TestClient(app)


def test_policy_resource_evaluation_flow():
    policy_resp = client.post(
        "/policies",
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
        json={
            "policy_id": policy_id,
            "principal": "finance-user",
            "action": "read",
            "resource_id": resource_id,
        },
    )
    assert evaluation_resp.status_code == 200
    assert evaluation_resp.json()["decision"] == "allow"
