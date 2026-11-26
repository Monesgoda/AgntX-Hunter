
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Business Logic Techniques (Race / Price / Workflow / Mass Assignment) — MCP-Native

Model-agnostic procedure. Every action runs through **Burp Suite MCP** (primary) or
**Playwright MCP** (fallback). Object-reference bugs (IDOR/BFLA) live in `idor.md`;
insecure deserialization in `deserialization.md`. Each section below is a **Detection
Ladder**: escalate the Rungs in order and stop at the first demonstrable impact.

---

## 0. Tool Binding (once per task)

| Label | Capability | Preferred server |
|---|---|---|
| `C-HTTP` | Send/replay a request (status, body, timing) | Burp Suite MCP |
| `C-HISTORY` | Replay a captured request by id, modified | Burp Suite MCP |
| `C-PARALLEL` | Send N near-simultaneous requests (single-packet attack) | Burp Suite MCP |
| `C-BROWSER-NAV` | Walk the multi-step flow | Playwright MCP |
| `C-BROWSER-EVAL` | Drive fetch() with explicit per-account session headers (fallback) | Playwright MCP |
| `C-BROWSER-NET` | Capture requests/state changes | Playwright MCP |

**Two-session rule.** Use exactly two test accounts (A attacker, B victim) supplied by the
Main Agent; never mix their cookies in one request. **Precedence.** If Burp MCP exposes no
tools, use Playwright MCP and log `"transport": "playwright-fallback"`; `C-PARALLEL` degrades
to best-effort `fetch()` bursts.

---

## 1. Race Conditions

### Rung 1 — Identify a single-use action
Coupon redeem, balance/points transfer, vote, signup bonus, invite accept, withdrawal.

### Rung 2 — Concurrency
Send N identical state-changing requests with `C-PARALLEL` (single-packet where possible).

### Rung 3 — Confirm double-spend
Resource consumed N times for one entitlement (e.g. balance credited twice), or two winners
for one slot. A single success is not a race; N>1 effects are.

### Rung 4 — TOCTOU
Test check-then-act gaps (stock check → purchase; "is member" → add) by interleaving the
check and the act.

---

## 2. Price / Quantity Manipulation

### Rung 1 — Intercept the state-changing request
Modify the server-facing request, not the cart UI.

### Rung 2 — Mutations
Negative quantity, `price=0`, `price=0.01`, currency switch, discount stacking, integer
overflow, quantity beyond stock.

### Rung 3 — Server-side recalculation check
Compare client-submitted total vs. server-recomputed total; a discounted/zero total that is
honoured is the finding.

---

## 3. Workflow Bypass

### Rung 1 — Skip steps
Submit the final step directly with crafted IDs (POST step 3 without step 2).

### Rung 2 — Replay
Repeat a completed one-time step (re-claim, re-confirm).

### Rung 3 — Parameter pollution on step indicators
`step=3&step=1` / duplicated status fields to force a later state.

---

## 4. Mass Assignment

### Rung 1 — Baseline
Capture the legitimate profile/creation request body.

### Rung 2 — Inject privileged fields
Add `role`, `is_admin`, `is_verified`, `balance`, `tenant_id`, `owner_id`, `created_by`,
parent-object IDs.

### Rung 3 — Detect silent acceptance
Re-read the object after the write; a changed privileged field that survives read-back is
the finding.

---

## 5. Minimal Proof

One of: N>1 effects for a single entitlement (race), a changed price/quantity honoured
(price), a skipped/replayed step reaching a later state (workflow), or a privileged field
persisted after read-back (mass assignment). Minimal impact only — smallest amount, own
test items.

## 6. Evidence Requirements

- `evidence_dir/techniques_<class>_req.txt` / `_res.txt` (all parallel requests for race)
- `evidence_dir/techniques_state_before_after.json` (read-back proof)
- Confirmations repeated at least twice; controls (single request / unmodified body).

## 7. Severity

| Condition | Severity |
|---|---|
| Anomaly without material impact | low |
| Non-financial state anomaly (duplicate flag) | medium |
| Double-spend / price tamper with real value | high |
| Mass assignment → privilege escalation, or race → balance theft | critical |

## 8. Result Contract

```json
{
  "class": "race | price-tamper | workflow-bypass | mass-assignment",
  "transport": "burp | playwright-fallback",
  "confirmed": [{
    "flow": "checkout",
    "endpoint": "POST /api/redeem",
    "technique": "parallelism | negative-qty | step-skip | field-inject",
    "impact": "coupon applied 3x | price set to 0.01 | role set to admin",
    "evidence": {"burp_history_ids": ["..."], "playwright_artifact": "..."},
    "control": "single request / unmodified body",
    "reproduced_twice": true,
    "severity_estimate": "high"
  }],
  "tested_clean": ["flow#step"],
  "blocked": [{"flow": "...", "note": "rate-limited / requires third account"}],
  "delegation_requests": [],
  "status": "complete | partial | blocked"
}
```

## 9. Stop Conditions

- A rate limiter/lock blocks the test accounts → `blocked` (do not brute-force).
- Impact would require real user data or a third account → `escalation_request`, stop.
- Any rung would be destructive/irreversible → stop, confirmed-with-limitations.
- Two consecutive 5xx → halt class.

## 10. Non-Goals

- IDOR / BFLA object-reference bugs → `idor.md`; deserialization → `deserialization.md`.
- DoS-class flooding → `client-api/rate-limiting`.
- Real-user data or bulk enumeration — never.
