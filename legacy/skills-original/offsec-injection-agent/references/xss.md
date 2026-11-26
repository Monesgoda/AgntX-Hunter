
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# XSS (Reflected / Stored / DOM) — MCP-Native Methodology

Model-agnostic procedure. Every action runs through **Burp Suite MCP** (primary) or
**Playwright MCP** (fallback). No shell, no scripts, no agent framework.

---

## 0. Tool Binding (once per task)

| Label | Capability | Preferred server |
|---|---|---|
| `C-HTTP` | Send a raw request, return status/headers/body | Burp Suite MCP |
| `C-HISTORY` | Replay a captured request by id, modified | Burp Suite MCP |
| `C-BROWSER-NAV` | Navigate to a URL, obtain rendered DOM | Playwright MCP |
| `C-BROWSER-EVAL` | Execute JS in page context, inspect DOM/sinks | Playwright MCP |
| `C-BROWSER-NET` | Observe requests the browser makes | Playwright MCP |
| `C-BROWSER-CONSOLE` | Read console output/errors (dialog + sink proof) | Playwright MCP |

**Precedence.** If Burp MCP exposes no tools, run the whole methodology on Playwright MCP
(`C-HTTP` → `C-BROWSER-EVAL` `fetch()`; `C-HISTORY` → `C-BROWSER-NET`) and report
`"transport": "playwright-fallback"`. Verification is Playwright-first regardless.

**Marker strategy.** Use a unique marker per injection point (`xss<MARK>7f3a`) to trace the
reflection context and rule out unrelated echoes.

---

## 1. Triage Before Probing

For each candidate parameter, record endpoint, method, location (path/query/body/header/
cookie/fragment), whether it is reflected, and the rendering context. Classify before
injecting: HTML body, attribute, JS string, URL, or CSS.

---

## 2. Detection Ladder

Escalate in order; stop at the first executed proof.

### Rung 1 — Reflection
Inject a benign marker (`m4rk<TOKEN>`, `"`, `'`, `</b>`). A reflected marker the server
echoes is a lead only — record where and in which context.

### Rung 2 — Context classification
Determine the sink context from the reflected marker:
- **HTML body** → `<svg/onload=alert(document.domain)>`
- **Attribute** → `" onmouseover=alert(1) x="`, `" autofocus onfocus=alert(1) x="`
- **JS string** → `';alert(1)//`, `${alert(1)}`
- **URL/href** → `javascript:alert(1)` (needs user interaction — note it)

### Rung 3 — Reflected execution (the workhorse)
Load the crafted URL in `C-BROWSER-NAV` with a dialog handler (`page.on('dialog')`); a
fired dialog or the marker executing in the DOM (`window.__xss_confirmed` hook) = executed.
Repeat to rule out caching.

### Rung 4 — Stored XSS
Submit the payload through the legitimate form (`C-BROWSER-NAV`), then revisit the
rendering page in a **fresh browser context** (`C-BROWSER-NAV` + `C-BROWSER-CONSOLE`) to
confirm persistence and execution.

### Rung 5 — DOM XSS (no server round-trip)
Trace sources (`location.hash`, `location.search`, `window.name`, `postMessage`) into sinks
(`innerHTML`, `document.write`, `eval`, `setTimeout(string)`) via `C-BROWSER-EVAL`. Confirm
sink reachability by executing the flow in-page; do not inject through the server.

### Rung 6 — Filter bypass
Apply the shared ladder (see `infra-protocol/waf-evasion-generic/SKILL.md`): case mixing,
event handlers (`onfocus`, `ontoggle`), `<img src=x onerror=...>`, template literals, HTML
entity encoding in attribute contexts. Try once each, then stop.

---

## 3. Minimal Proof

One executed dialog / marker in DOM / persisted payload. A screenshot via `C-BROWSER-NAV`
is the artifact. `alert(document.domain)` (not a generic `alert(1)`) proves real origin
execution for a stronger claim.

## 4. Evidence Requirements

- `evidence_dir/xss_<context>_req.txt` / `_res.txt`
- `evidence_dir/xss_screenshot*.png` (dialog firing or persisted execution)
- `evidence_dir/xss_dom_trace.json` (for DOM XSS: source → sink)
- Confirmations repeated at least twice (fresh context for stored).

## 5. Severity

| Condition | Severity |
|---|---|
| Reflection with no execution (mirror/escaped) | info–low |
| Non-persistent reflected execution (self-XSS) | medium |
| Reflected/stored execution reachable by a victim | high |
| Stored XSS in an admin/privileged session, or account-takeover path | critical |

## 6. Result Contract

```json
{
  "class": "xss",
  "transport": "burp | playwright-fallback",
  "confirmed": [{
    "type": "reflected | stored | dom",
    "endpoint": "GET /search",
    "param": "q (query, html-context)",
    "payload_used": "\"><svg/onload=alert(document.domain)>",
    "control_payload": "m4rk7f3a",
    "proof": "dialog fired in fresh context / marker executed in DOM",
    "data_exposed": "script execution in the victim origin",
    "reproduced_twice": true,
    "severity_estimate": "high"
  }],
  "tested_clean": ["endpoint#param"],
  "blocked": [{"endpoint": "...", "param": "...", "variants_tried": [1,2,3], "note": "WAF token match"}],
  "delegation_requests": [],
  "status": "complete | partial | blocked"
}
```

## 7. Stop Conditions

- Filter survives the shared ladder → `blocked_by_defense`, halt class.
- DOM-only XSS with no server round-trip that needs a browser → hand to
  `offsec-client-side-agent` as a `delegation_request` and stop.
- Two consecutive 5xx → halt class.
- Scope unclear for the host/path → stop.

## 8. Non-Goals

- Weaponized payload delivery beyond a proof dialog/marker.
- Client-only DOM gadget analysis (prototype pollution, DOM clobbering) →
  `offsec-client-side-agent`.
- SVG-upload / Swagger-UI render XSS → `offsec-client-side-agent`.
- SQLi/NoSQLi/SSTI/command injection → `sqli.md` / `cmd-ssti.md`.
