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
