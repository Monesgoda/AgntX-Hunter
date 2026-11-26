
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# API Resource Consumption Abuse

## Tool Binding

- Transport: Burp MCP / Playwright MCP.
- Focus: endpoints that accept cost/effort parameters (GraphQL, export, report,
  pagination, batch).

## Detection Ladder

### Rung 1 — GraphQL query cost
Send a query with N aliased fields (N=10, 100, 1000). Measure server time.
If linear scaling (no cost cap) → `resource.graphql_no_cost_cap` (low).

### Rung 2 — GraphQL batch amplification
`[{query},{query},...]` × 100 in one POST. If accepted and processed serially
without 429 → `resource.graphql_batch_amplify` (medium).

### Rung 3 — Deep pagination abuse
`?page=1&per_page=10000` or `?limit=999999`. Response contains > 10× baseline
rows → `resource.pagination_bypass` (medium).

### Rung 4 — Export endpoint abuse
`/export?format=csv&filter=*` on large datasets. Time > 30s → potential
`resource.export_amplification`. Only test with small `filter` to avoid
real DoS, then extrapolate.

### Rung 5 — Rate-limit bypass via API-specific quirks
Test:
- Different HTTP method for same endpoint
- `X-Forwarded-For` spoof (see `host-header-attacks` for header semantics)
- Case variation in path (`/API/v1/...` vs `/api/v1/...`)
- Trailing-dot / semicolon path params
Any bypass of the throttle → `resource.rate_limit_bypass` (high).

## Minimal Proof

- Two requests: baseline (1 unit) and amplified (N units)
- Timing + response sizes in tabular form
- Never trigger full DoS — cap amplification at the minimum that demonstrates
  non-constant scaling.

## Evidence Requirements

- `evidence_dir/resource_timings.json` — `{rung, baseline_ms, amplified_ms, ratio}`
- `evidence_dir/resource_<rung>_req.txt` / `_res.txt`
- For rate-limit bypass: 20 requests spread across 5s, showing no 429.

## Severity

| Finding | Severity |
|---|---|
| No cost cap (linear scaling) | low |
| Batch amplification (medium N) | medium |
| Pagination bypass | medium |
| Export amplification (extrapolated) | medium |
| Rate-limit bypass | high |
| Confirmed full DoS | critical (requires `allow_destructive: true`) |

## Result Contract

```json
{
  "status": "confirmed | tested_clean",
  "class": "resource.<rung>",
  "endpoint": "<method + path>",
  "amplification_ratio": 12.4,
  "evidence": ["..."],
  "severity": "<table>",
  "poc_ref": "poc/resource-<slug>.md | null"
}
```

## Stop Conditions

- Any 5xx from target → immediate halt.
- Response time exceeding 30s → halt, log timeout.
- WAF 429/403 → `blocked_by_defense`, halt.
- Never confirm a critical DoS without `allow_destructive: true` in receipt
  AND target marked `staging` in scope.json.

## Non-Goals

- Login/OTP throttling — stays in `client-api/rate-limiting/SKILL.md`
  (see-also, not duplicated here).
- Distributed DoS simulation.
- Cache poisoning amplified via cache (that's `web-cache-poisoning`).
