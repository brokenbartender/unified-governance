# TypeScript SDK

## Usage
```ts
import { Client } from "unified-governance-sdk";

const client = new Client("https://unified-governance.onrender.com", "YOUR_API_KEY");

const policy = await client.createPolicy("Allow read", {
  allowed_principals: ["user"],
  allowed_actions: ["read"],
  resource_types: ["file"],
  required_attributes: {},
});
```

## Enforcement Middleware (Express)
```ts
import { Client, createEnforcementMiddleware } from "unified-governance-sdk";

const client = new Client("https://unified-governance.onrender.com", "YOUR_API_KEY");

app.use(
  createEnforcementMiddleware({
    client,
    policyId: "POLICY_ID",
    resolveResourceId: () => "RESOURCE_ID",
    resolvePrincipal: (req) => req.user?.email ?? "anonymous",
    resolveAction: () => "read",
  })
);
```
