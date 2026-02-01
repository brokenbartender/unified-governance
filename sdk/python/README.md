# Python SDK

## Usage
```python
from unified_governance import Client

client = Client("https://unified-governance.onrender.com", "YOUR_API_KEY")

policy = client.create_policy(
    name="Allow read",
    rule={
        "allowed_principals": ["user"],
        "allowed_actions": ["read"],
        "resource_types": ["file"],
        "required_attributes": {},
    },
)
```

## Enforcement Middleware (FastAPI/Starlette)
```python
from unified_governance import Client, EnforcementMiddleware

client = Client("https://unified-governance.onrender.com", "YOUR_API_KEY")

app.add_middleware(
    EnforcementMiddleware,
    client=client,
    policy_id="POLICY_ID",
    resource_id_resolver=lambda req: "RESOURCE_ID",
    principal_resolver=lambda req: "user@example.com",
    action_resolver=lambda req: "read",
)
```
