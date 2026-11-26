
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# IDOR / Broken Access Control — MCP-Native Methodology

Model-agnostic procedure. Every action is executed through **Burp Suite MCP** or **Playwright MCP**. No shell, no scripts, no CLI tooling, no agent framework of any kind.

---

## 0. Tool Binding (do this once per task)

Bind these capability labels to whichever tools your MCP servers actually expose. Ask the server for its tool list if unsure; never guess a tool name, never fall back to a terminal.

| Label | Capability | Preferred server |
|---|---|---|
| `C-HTTP` | Send a raw/hand-edited HTTP request and return status, headers, body | Burp Suite MCP |
| `C-HISTORY` | Read previously observed proxy traffic; retrieve a request by id to replay verbatim with modified IDs | Burp Suite MCP |
| `C-SCAN` | Passive scanner findings, used only as leads to confirm manually | Burp Suite MCP |
| `C-BROWSER-NAV` | Navigate to a URL and obtain the rendered response/DOM | Playwright MCP |
| `C-BROWSER-EVAL` | Execute JS in page context (fetch with custom headers, cookie/state inspection) | Playwright MCP |
| `C-BROWSER-NET` | Observe requests the browser makes, with headers and bodies | Playwright MCP |
| `C-BROWSER-CONSOLE` | Read console output/errors | Playwright MCP |

**Precedence.** If Burp MCP is unavailable or exposes no tools — it is an SSE bridge to a running Burp instance and stays silent when Burp is closed — run the entire methodology on Playwright MCP: `C-HTTP` becomes `C-BROWSER-EVAL` issuing `fetch()` from page context with explicit `Authorization` / `Cookie` headers per account, and `C-HISTORY` becomes `C-BROWSER-NET`. Log the substitution as `"transport": "playwright-fallback"`.

**Two-session rule.** IDOR testing requires exactly two distinct authenticated identities: attacker `A` and victim `B`, supplied by the Main Agent. `C-BROWSER-EVAL` page context carries one session's cookies; the *other* session must be attached explicitly per request via headers. Never mix the two in one request. As a normal user first, walk the flow once per account and record every object ID each account legitimately owns — those ownership maps are the baselines everything else diffs against.

---

## 1. Triage Before Probing

For each endpoint, record: URL, method, where object references live (path segment / query param / JSON body key / header / cookie / WebSocket message field), reference shape (numeric / UUID / hash / slug), owning account, and the baseline response per account.

Establish **two baselines** via `C-HTTP` (or `C-BROWSER-EVAL` with explicit session headers):

- `A-baseline`: account A requests A's own object → record status, body, length.
- `B-baseline`: account B requests B's own object → record the same.

Every later judgment is a comparison against these two baselines. A response to a cross-account request that matches the *owner's* baseline instead of a denial is the finding.

Enumerate every object reference on the endpoint — path IDs, query params, JSON body IDs, UUIDs, hashes, slugs, filenames, report IDs, invite tokens. Encoded or UUID-shaped references are **not** protection; test them exactly like numeric IDs.

---

## 2. Detection Ladder

Escalate in this order. Stop at the first rung that produces a clear cross-account differential; do not climb for its own sake.

### Rung 1 — Unauthenticated access
Replay an authenticated request with the session header/cookie removed entirely.

| Observation | Meaning |
|---|---|
| Same data as the authenticated baseline | Missing authentication — report as broken auth, not IDOR |
| Redirect to login / 401 / 403 with no data | Authentication enforced — continue to Rung 2 |
| Different error per object existence (404 vs 403) | Oracle — note it, continue to Rung 2 |

### Rung 2 — Horizontal swap (the workhorse)
Account A requests account B's object ID, byte-identical to B's own baseline request except for the session identity:

```
A-baseline: GET /api/orders/101  (A's order) -> 200, A's data
B-baseline: GET /api/orders/207  (B's order) -> 200, B's data
probe:      GET /api/orders/207  with A's session
```

| Observation | Meaning |
|---|---|
| Probe returns B's data (matches B-baseline) | **IDOR confirmed** — record and go to Section 4 |
| Probe returns 403/404 with no data | Enforced here — try Rung 3 variants on the same endpoint |
| Probe returns A's data or an error mentioning A's context | Server ignored the ID — broken, but not cross-account disclosure |

Repeat the probe twice to rule out caching. A single differential is not confirmation.

### Rung 3 — Reference-shape variants
When Rung 2 is denied, the check may be shape-fragile rather than sound. Try each once:

| # | Variant | Shape |
|---|---|---|
| 1 | Numeric swap | `/api/user/123/profile` → `124` (also `123+1`, `0123`, `0124`) |
| 2 | UUID swap | Victim UUID harvested from invites, shared links, exports, or error messages |
| 3 | Indirect IDOR | `POST /api/export?report_id=456` exports another user's report — action endpoints, not just reads |
| 4 | Parameter add | Append `?user_id=<victim>` / `&owner=<victim>` and observe whether the backend honors it |
| 5 | Method swap | Replay as GET, PUT, PATCH, DELETE — authorization is frequently enforced on one method only |
| 6 | Old API version | `/v1/users/123` vs `/v2/users/123` — legacy versions routinely lack the current auth checks |
| 7 | GraphQL node | `{ node(id: "base64(Type:victim-id)") { email phone ssn } }` — node resolution frequently bypasses per-object auth |
| 8 | WebSocket message | Client-supplied `{"action":"get_history","userId":"<victim>"}` — ownership rarely checked on socket frames |

### Rung 4 — Vertical escalation
Replay admin/internal endpoints with the low-privilege session:

```
/api/admin/users  /api/admin/export  /api/admin/delete  /api/admin/reset
```

Apply the sibling rule: if nine sibling routes enforce auth and one does not, the tenth is the bug. A low-priv session reaching any admin data or action is **privilege escalation**, severity one step above the equivalent horizontal read.

### Rung 5 — Broken Function / Object-Property Level Authorization (BFLA / BOPLA)
Function-level and property-level authorization is distinct from object references: the object ID is legitimate, but the **action** or the **field** is not permitted for this role. Probe sibling functions and privileged fields with the low-privilege session:

```
GET   /api/admin/users            (a function the role should not have)
POST  /api/users/me/role          (a field a non-admin should not set)
PATCH /api/orders/101 {status}    (a property a customer should not change)
PATCH /api/users/101 {managerId}  (reassign another user's property)
```

| Observation | Meaning |
|---|---|
| Low-priv session reaches an admin/internal function or data | **BFLA confirmed** — severity one step above the equivalent horizontal read |
| Response returns or accepts a privileged property (`role`, `is_admin`, `tenant_id`, `managerId`, `status`, `balance`) | **BOPLA confirmed** — pair with a read-back to prove the write actually landed |
| Denied with 403/404 | Enforced here — continue to Rung 6 |

Apply the sibling rule: a function-level check that holds on nine routes but not the tenth is the bug. A hidden UI control is not enforcement — confirm the server API.

### Rung 6 — Write-path IDOR
Reads are the common case; writes pay more. For every Rung 2 success on GET, replay the same ID swap on PUT/PATCH/DELETE/POST against the victim's object with a **reversible, minimal, own-test-data-only** mutation (e.g. append a marker string to a display name you own in the victim test account). Read back to confirm the write landed. IDOR + write on another user's data is High; IDOR + admin action or account-takeover path is Critical.

---

## 3. Second-Order and Stored References

Object references frequently execute at **read** time in a different session — exports, audit logs, admin panels, shared dashboards, notification renderers.

1. Create or modify an object as A containing B's reference (shared link, invite, assignment, mention).
2. Trigger the read path — B's listing page, an admin review queue, an export job — via `C-BROWSER-NAV`.
3. Observe via `C-BROWSER-NET` whether A's session (or an admin session) discloses B's data at render time.

If a stored reference fires in an **admin** session, that is privilege escalation, not a duplicate of the input bug — report the escalation path separately.

---

## 4. Minimal Proof and Hard Limits

**One cross-account read is a valid finding. Stop there.**

- Read-only proofs only: one record, one screen, one export row belonging to the *other test account*.
- Never touch real user data — only the two test accounts the Main Agent provided.
- Never modify, delete, or reassign a victim object beyond a reversible marker on your own test data — and only when the Main Agent explicitly authorized write confirmation.
- No mass enumeration: do not walk ID ranges. Two IDs (yours, theirs) prove the missing check; a third ID adds nothing and looks like data harvesting.
- Stop the moment one cross-account differential is captured with baseline, probe, and control.

---

## 5. WAF / Filter Note

IDOR is a missing server-side check, not a blocked payload — there is nothing to encode. If a filter blocks a probe, it blocked the *transport shape* (e.g. a traversal-looking path), not the vulnerability. Re-express the same ID swap through a different reference location (query param instead of path, body key instead of query) once, then report `blocked` if all shapes are filtered. Do not brute-force a filter.

---

## 6. Evidence Requirements

A finding is **confirmed** only when the evidence survives re-derivation:

1. A-baseline and B-baseline captured (each account reading its own object).
2. Cross-account probe captured, payload (the swapped ID) shown verbatim, returning the victim's data.
3. A **control**: same probe with a nonexistent ID returns 404/empty (proves the endpoint actually resolves IDs and is not echoing input).
4. Evidence repeated at least twice.
5. Evidence is human-readable in the report: the victim test account's record returned under the attacker's session.

If Playwright drove the request, capture the network entry via `C-BROWSER-NET` so the report carries a real request. If Burp drove it, cite the proxy history ids for baseline, probe, and control.

Never confirm on scanner output, on a 500 alone, or on a response that merely *mentions* the victim ID without disclosing victim data.

**False-positive guard:** a response that echoes the requested ID back without any stored victim data behind it is reflection, not disclosure. The control in step 3 exists precisely to kill this class.

---

## 7. Severity

| Condition | Severity |
|---|---|
| Cross-account read of non-sensitive metadata (counts, statuses) | Medium |
| Cross-account read of PII, documents, messages, financial records | High |
| Cross-account write (modify another user's data) | High |
| Low-priv session reaches admin endpoint or action | Critical (privilege escalation) |
| IDOR enables account takeover (email change, token read, password reset) | Critical |
| Chatbot/AI assistant reads another user's data via IDOR | High |
| Strict per-object checks hold on every tested shape | Clean — report as tested, not as a finding |

Escalate only on demonstrated impact. "IDs are guessable" is not a severity — data actually reachable across accounts is.

---

## 8. Result Contract

```json
{
  "class": "idor",
  "transport": "burp | playwright-fallback",
  "confirmed": [{
    "endpoint": "GET /api/orders",
    "param": "order_id (query, numeric)",
    "technique": "horizontal-swap | unauthenticated | method-swap | version-swap | graphql-node | websocket | vertical | write-path | second-order",
    "attacker": "account A id",
    "victim": "account B id / object id",
    "baseline_refs": {"a_own": "burp_history_id | playwright_network_ref",
                      "b_own": "burp_history_id | playwright_network_ref"},
    "probe": "GET /api/orders/207 with A's session -> 200, B's data",
    "control": "GET /api/orders/999999 with A's session -> 404",
    "data_exposed": "victim test account's order record (one row)",
    "reproduced_twice": true,
    "severity_estimate": "high"
  }],
  "tested_clean": ["GET /api/profile#id (own-data only under swapped session)"],
  "blocked": [],
  "delegation_requests": [],
  "status": "complete | partial | blocked"
}
```

`data_exposed` and both `baseline_refs` are mandatory on every confirmed entry — they are what justify the severity and kill false positives.

---

## 9. Stop Conditions

Halt immediately and report `blocked` when:

- The endpoint rate-limits, locks, or CAPTCHA-gates the test accounts.
- Ownership checks hold on every rung and variant for the endpoint.
- Scope is unclear for the host or path.
- Further testing would touch real user data or require a third account.
- The only remaining path is mass enumeration.

Halt and hand back when the only remaining path is destructive. Report the finding as confirmed-with-limitations rather than escalating.

---

## 10. Non-Goals

Do not attempt: ID range walking, victim-data modification beyond an authorized reversible marker, privilege persistence, chaining into unrelated accounts, or automated high-volume probing. Every request must be attributable to a single named test between the two provided accounts.
