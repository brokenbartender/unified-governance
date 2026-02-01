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
