# 5-Minute Demo Script

## Goal
Show a buyer that the product enforces access policy, preserves evidence integrity, and plugs into enterprise identity + connectors.

## Setup (2 min before demo)
- Start API (local or Docker)
- Have API key ready with scopes: policies:write, resources:write, evaluations:write, evidence:read, connectors:read

## Script (5 minutes)

### 0:00-0:30 - Problem + Promise
Say:
"Enterprises lack a single layer to govern data access across vendors and AI tools. This service enforces policy-as-code and produces audit-ready evidence in minutes."

### 0:30-1:30 - Create a Policy
Call `POST /policies` with a rule:
- principal: finance-user
- action: read
- resource type: payroll
Narrate:
"Policies are explicit, portable, and stored as structured rules."

### 1:30-2:30 - Register a Resource
Call `POST /resources` with:
- name: Payroll DB
- type: payroll
- source_system: snowflake
- external_id: table-abc
Narrate:
"Resources carry external IDs so sync stays stable across systems."

### 2:30-3:30 - Evaluate Access + Evidence Chain
Call `POST /evaluations` and point to:
- decision: allow
- record_hash: present
Narrate:
"Every decision is hashed into an integrity chain for evidence."

### 3:30-4:15 - Export Evidence Pack
Call `GET /evidence/export?format=csv`
Point to `X-Evidence-Signature` header.
Narrate:
"You get a business-friendly export with tamper-evident signature."

### 4:15-4:45 - Connectors + Identity
Call `GET /connectors` and show metadata.
Mention SCIM/SSO stubs in `docs/IDENTITY.md`.
Narrate:
"This drops into enterprise identity and data stacks quickly."

### 4:45-5:00 - Close
Say:
"This is a focused, acquisition-ready module: policy enforcement, evidence integrity, and connector-ready architecture."

## Optional Q&A
- Postgres ready (DB_URL)
- API key scopes + rotation
- OPA export for policy portability
