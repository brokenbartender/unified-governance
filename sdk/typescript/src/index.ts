export type PolicyRule = {
  allowed_principals: string[];
  allowed_actions: string[];
  resource_types: string[];
  required_attributes: Record<string, unknown>;
};

export class Client {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl: string, apiKey: string) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
  }

  private async request(method: string, path: string, body?: unknown) {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        "X-API-Key": this.apiKey,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!res.ok) {
      throw new Error(`Request failed: ${res.status}`);
    }

    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }

  createPolicy(name: string, rule: PolicyRule, description?: string) {
    return this.request("POST", "/policies", { name, rule, description });
  }

  listPolicies() {
    return this.request("GET", "/policies");
  }

  createResource(name: string, type: string, attributes: Record<string, unknown>, sourceSystem = "manual", externalId?: string) {
    return this.request("POST", "/resources", {
      name,
      type,
      attributes,
      source_system: sourceSystem,
      external_id: externalId,
    });
  }

  evaluate(policyId: string, principal: string, action: string, resourceId: string) {
    return this.request("POST", "/evaluations", {
      policy_id: policyId,
      principal,
      action,
      resource_id: resourceId,
    });
  }

  enforce(policyId: string, principal: string, action: string, resourceId: string, riskThreshold?: number) {
    const payload: Record<string, unknown> = {
      policy_id: policyId,
      principal,
      action,
      resource_id: resourceId,
    };
    if (riskThreshold !== undefined) {
      payload.risk_threshold = riskThreshold;
    }
    return this.request("POST", "/enforce", payload);
  }

  exportEvidence() {
    return this.request("GET", "/evidence/export");
  }

  verifyEvidence() {
    return this.request("GET", "/evidence/verify");
  }
}

export function createEnforcementMiddleware(options: {
  client: Client;
  policyId: string;
  resolveResourceId: (req: any) => string;
  resolvePrincipal: (req: any) => string;
  resolveAction: (req: any) => string;
}) {
  return async (req: any, res: any, next: any) => {
    const decision = await options.client.enforce(
      options.policyId,
      options.resolvePrincipal(req),
      options.resolveAction(req),
      options.resolveResourceId(req),
    );
    if (decision && decision.decision === "deny") {
      res.status(403).send("Access denied");
      return;
    }
    next();
  };
}
