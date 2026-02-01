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

  exportEvidence() {
    return this.request("GET", "/evidence/export");
  }

  verifyEvidence() {
    return this.request("GET", "/evidence/verify");
  }
}
