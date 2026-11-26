
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# API Inventory & OpenAPI Parsing

## Tool Binding

- Transport: Burp MCP (primary) / Playwright MCP (fallback).
- Discovery paths (probe in order):
  `/swagger.json`, `/swagger/v1/swagger.json`, `/openapi.json`, `/openapi.yaml`,
  `/v3/api-docs`, `/api-docs`, `/docs`, `/redoc`, `/postman.json`,
  `/.well-known/openapi.json`

## Detection Ladder

### Rung 1 — Spec publicly reachable
GET each path. 200 + JSON/YAML with `openapi` or `swagger` key →
`inventory.spec_exposed` (info).

### Rung 2 — Build endpoint inventory
Parse spec → extract `(method, path, params, auth_required)` tuples.
Write to `evidence_dir/inventory.json`. This becomes input for other classes.

### Rung 3 — Shadow endpoints
For each spec'd path, probe with:
- Verb variations (GET↔POST↔PUT↔PATCH↔DELETE)
- Path suffix variations (`/v1/`, `/v2/`, `/internal/`, `/.json`, `/;x=`)
Endpoints that respond but aren't in the spec → `inventory.shadow_endpoint`.

### Rung 4 — Zombie / deprecated versions
Compare `info.version` in spec to live `Server` / `X-API-Version` header.
Mismatch → `inventory.version_drift`. Probe `/v1` while spec is `/v2` → still
live → `inventory.zombie_version`.

### Rung 5 — Unauthenticated spec'd endpoints
From inventory, filter rows marked `auth_required: true`. Replay without auth.
200 → `inventory.unauth_endpoint` (high if it returns data, medium if only
metadata).

### Rung 6 — Improper inventory management (broader)
Check:
- Old hosts (`api-old.*`, `api-v1.*`, `legacy.*`) via DNS hints in spec `servers:`
- Spec `servers:` pointing to non-prod hosts reachable from prod network
- Postman collections with `{{baseUrl}}` swapped to prod
Any hit → `inventory.improper_management` (medium–high).

## Minimal Proof

- Spec URL + HTTP status + first 500 bytes of body
- For shadow/zombie: one request showing live response ≠ spec
- For unauth: request without auth header + response with data

## Evidence Requirements

- `evidence_dir/inventory.json` (parsed endpoint list)
- `evidence_dir/inventory_<finding>_req.txt` / `_res.txt`
- `evidence_dir/inventory_diff.md` (spec vs. live, tabular)

## Severity

| Finding | Severity |
|---|---|
| Spec exposed (public docs) | info |
| Shadow endpoint (no auth needed) | medium |
| Shadow endpoint (auth, but undocumented) | low |
| Zombie version (deprecated but live) | medium |
| Unauth endpoint returning data | high |
| Improper management (old host reachable) | high |

## Result Contract

```json
{
  "status": "confirmed | tested_clean",
  "class": "inventory.<rung>",
  "endpoint": "<method + path>",
  "spec_ref": "<spec url or 'none'>",
  "evidence": ["..."],
  "severity": "<table>",
  "poc_ref": "poc/inventory-<slug>.md | null"
}
```

## Stop Conditions

- Spec probing triggers WAF → halt, `blocked_by_defense`.
- More than 500 endpoints in spec → paginate; do not brute-force the whole set.
  Sample 20% + all rows marked `deprecated: true`.

## Non-Goals

- Full API fuzzing per endpoint (delegated to injection/business-logic).
- Swagger UI XSS (goes to `offsec-client-side-agent`, class `swagger-ui-xss`).
- Spec-only analysis without live confirmation.
