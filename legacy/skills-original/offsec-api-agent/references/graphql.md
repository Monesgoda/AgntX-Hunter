
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# GraphQL Testing

## Tool Binding

- Transport: Burp MCP (primary) / Playwright MCP (fallback). Never raw curl.
- Primary inputs: base URL, endpoint path, auth header.
- Discovery endpoints to probe (in order):
  `/graphql`, `/graphiql`, `/v1/graphql`, `/api/graphql`, `/query`, `/gql`

## Detection Ladder

### Rung 1 — Introspection enabled
POST `{"query":"{__schema{types{name}}}"}`. Success (200 + `data.__schema`)
= `graphql.introspection_enabled` (info). Failure ≠ clean; continue.

### Rung 2 — Introspection via GET / content-type bypass
Try GET `?query={__schema{...}}`, try `Content-Type: application/x-www-form-urlencoded`,
try `Accept: text/html`. Some servers disable only POST-introspection.

### Rung 3 — Alias-based batching
Send one query with N aliased identical fields:
`{ a1:user(id:1){email} a2:user(id:2){email} ... a1000:user(id:1000){email} }`
Baseline vs. amplified response time → `graphql.alias_batching_dos` if
`t_amplified > 5 × t_baseline` AND server didn't cap.

### Rung 4 — Array batching (JSON list of operations)
POST `[{"query":"..."},{"query":"..."},...]` × 100. If all execute and no
rate-cap → `graphql.array_batching`.

### Rung 5 — Query depth / cost DoS
Recursive fragment or nested `user{friends{friends{...}}}` to depth 20.
If response < 3s and depth accepted → `graphql.depth_dos`.
Cap at depth 20 to avoid crashing prod.

### Rung 6 — Node-IDOR via relay `node(id:)` or `user(id:)`
Iterate IDs ±5 around a known authorized ID. If foreign object returned →
`graphql.node_idor`. **Boundary:** relay-IDOR is scoped here; REST IDOR stays
in `offsec-business-logic-agent/references/idor.md`.

### Rung 7 — Field-level authorization (BFLA analog)
Query a field the current role shouldn't see (e.g. `User.isAdmin`,
`User.passwordHash`, `Order.internalNote`). 200 with data → `graphql.bfla_field`.

### Rung 8 — Unauthenticated mutations
Send a harmless mutation (`mutation{__typename}` and a benign no-op) without
auth header. 200 → `graphql.unauth_mutation_surface`.

## Minimal Proof

For each finding, capture:
1. Raw request (headers + body)
2. Raw response (status + first 2 KB body)
3. One-line impact statement

Never dump full introspection schema to evidence — truncate to 200 lines.

## Evidence Requirements

- `evidence_dir/graphql_<rung>_req.txt`
- `evidence_dir/graphql_<rung>_res.txt`
- `evidence_dir/graphql_timings.json` (baseline vs. amplified, for DoS rungs)

## Severity

| Finding | Severity |
|---|---|
| Introspection enabled | low |
| Alias/array batching (no cap) | medium |
| Depth DoS | high |
| node-IDOR (foreign object) | high |
| BFLA field leak (secrets) | critical |
| Unauthenticated mutation | critical |

## Result Contract

```json
{
  "status": "confirmed | tested_clean",
  "class": "graphql.<rung>",
  "endpoint": "<method + path>",
  "evidence": ["..."],
  "severity": "<table>",
  "poc_ref": "poc/graphql-<slug>.md | null"
}
```

## Stop Conditions

- WAF block page → `blocked_by_defense`, halt class.
- 5xx server errors × 2 consecutive → halt class.
- Response > 30s → halt, log timeout (not a finding).

## Non-Goals

- GraphQL subscription hijacking (out of scope).
- Persisted-query bypass attacks (separate skill, not implemented).
- Federation/stitching-specific bugs.
