# Control Matrix (SOC 2 / ISO 27001 / NIST AI RMF)

## Scope
This matrix maps current implementation artifacts to common control expectations. It is intended for acquisition diligence and enterprise pre‑sales. It is **not** a certification.

## SOC 2 (Security) – Core Controls
| SOC2 CC | Description | Status | Evidence | Notes |
|---|---|---|---|---|
| CC1.1 | Governance, roles, oversight | Partial | `docs/PRD.md`, `docs/SECURITY_MODEL.md` | Governance docs exist; formal org policies not included |
| CC2.1 | Communication of policies | Partial | `docs/PRD.md`, `docs/COMPLIANCE_ALIGNMENT.md` | Docs only; no training program |
| CC3.1 | Risk assessment | Partial | `docs/COMPLIANCE_ALIGNMENT.md` | No formal risk register |
| CC4.1 | Monitoring controls | Partial | `src/app.py` (evidence logs) | No alerting/monitoring stack |
| CC5.1 | Control activities | Partial | `src/app.py` (scopes, auth), `src/policy_engine.py` | Access control present but no RBAC UI |
| CC6.1 | Logical access | Partial | `src/app.py` (API keys + scopes) | No SSO enforcement yet |
| CC7.1 | System operations | Partial | `docs/DEPLOYMENT.md` | No runbooks |
| CC7.2 | Change management | Partial | `docs/ROADMAP.md` | No formal change mgmt |
| CC7.3 | Incident response | Partial | `docs/SECURITY_MODEL.md` | No IR playbook |
| CC8.1 | Availability | Partial | `docs/DEPLOYMENT.md` | No SLAs |

## ISO 27001:2022 – Sample Control Mapping
| ISO Control | Description | Status | Evidence | Notes |
|---|---|---|---|---|
| A.5.1 | Information security policies | Partial | `docs/SECURITY_MODEL.md` | Policy document exists |
| A.5.23 | Information security for use of cloud services | Partial | `docs/DEPLOYMENT.md` | Guidance, not enforcement |
| A.8.1 | Responsibility for assets | Partial | `src/app.py` (resources) | Resource inventory present |
| A.8.9 | Configuration management | Partial | `docs/DEPLOYMENT.md` | No formal CM process |
| A.8.15 | Logging | Partial | `src/app.py` (evaluations + hash chain) | Logs present, no SIEM |
| A.8.16 | Monitoring activities | Partial | `docs/SECURITY_MODEL.md` | No monitoring pipeline |
| A.8.24 | Use of cryptography | Partial | `src/app.py` (HMAC evidence signatures) | Key rotation policies pending |
| A.8.25 | Secure development life cycle | Partial | `docs/ROADMAP.md` | No SDL policy |

## NIST AI RMF 1.0 – Core Functions
| Function | Subcategory | Status | Evidence | Notes |
|---|---|---|---|---|
| Govern | Risk policy, roles, accountability | Partial | `docs/PRD.md`, `docs/SECURITY_MODEL.md` | Governance documented |
| Map | Context, impact, risk identification | Partial | `docs/COMPLIANCE_ALIGNMENT.md` | No formal risk register |
| Measure | Evaluation + logging | Partial | `src/app.py` (evaluations) | Evidence export implemented |
| Manage | Response + improvement | Partial | `docs/ROADMAP.md` | No incident playbooks |

## Evidence Artifacts
- API auth + scopes: `src/app.py`
- Evidence export + HMAC signatures: `src/app.py`
- Hash chain for evaluation logs: `src/app.py`
- Retention enforcement: `src/app.py`, `src/settings.py`
- SSO/SCIM stubs: `src/app.py`, `docs/IDENTITY.md`
- Deployment guidance: `docs/DEPLOYMENT.md`

## Summary
Current implementation is suitable for enterprise demos and acquisition diligence but does not constitute full compliance. It establishes the foundations expected by buyers and accelerates integration.
