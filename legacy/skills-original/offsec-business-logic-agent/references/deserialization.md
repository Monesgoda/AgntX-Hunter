
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Insecure Deserialization — MCP-Native Methodology

Model-agnostic procedure. Every action runs through **Burp Suite MCP** (primary) or
**Playwright MCP** (fallback). No shell, no scripts, no agent framework. This reference
covers **server-side insecure deserialization** (object/gadget injection) — the
business-logic consequence of an untrusted serialized object being reconstructed.

---

## 0. Tool Binding (once per task)

| Label | Capability | Preferred server |
|---|---|---|
| `C-HTTP` | Send a raw request/response pair (status, headers, body, timing) | Burp Suite MCP |
| `C-HISTORY` | Replay a captured request by id, modified | Burp Suite MCP |
| `C-SCAN` | Passive scanner leads (Java/PHP/.NET gadget signatures) | Burp Suite MCP |
| `C-BROWSER-EVAL` | Drive requests from page context (fallback) | Playwright MCP |
| `C-BROWSER-NET` | Capture the browser's requests/responses | Playwright MCP |

**Precedence.** If Burp MCP exposes no tools, use Playwright MCP and log
`"transport": "playwright-fallback"`. Serialized-object tampering is easiest in Burp;
without it, this class may be `blocked` rather than improvised.

---

## 1. Triage Before Probing

Find where a client-supplied serialized object is reconstructed:
- **Java**: base64 starting `rO0AB`, `Content-Type: application/x-java-serialized-object`,
  `acesession`/`JSESSIONID` carrying a serialized blob, viewstate-like parameters.
- **PHP**: `O:8:"stdClass":...`, `a:1:{...}`, cookies/params that are PHP-serialized.
- **.NET**: `__VIEWSTATE`, `__EVENTVALIDATION`, BinaryFormatter/`ObjectStateFormatter` blobs.
- **Python**: `pickle` payloads (`\x80\x04...`), `yaml.load` reachable with `!!python/object`.
- **Node**: `node-serialize`/`serialize-to-js` payloads, `JSON.parse` followed by a
  `reviver` or `eval`.

Record endpoint, parameter, format, and the baseline response. Classify by language —
each has a different gadget path.

---

## 2. Detection Ladder

Escalate in order; stop at the first human-readable proof (a benign effect). Do not climb
for its own sake.

### Rung 1 — Format confirmation
Modify a scalar in the serialized blob and resend: does the server accept and reflect the
change (e.g. a username field inside the object)? A clean parse + changed effect confirms
the object is deserialized server-side and untrusted input is honoured.

### Rung 2 — Type / structure tampering
Change an object's class/type to a neighbouring one, drop a field, or nest an unexpected
object. A different error (stack trace, class-name leak) or a behaviour change is a lead,
not yet a finding.

### Rung 3 — Known gadget chain (non-destructive proof)
Use a **benign** gadget to prove influence without harm — a DNS/HTTP callback:
- Java: `URLDNS` gadget — a `HashMap`/`java.net.URL` whose hashCode triggers a DNS lookup
  to a host you control.
- PHP: an object whose `__wakeup`/`__destruct` performs a controlled request.
- .NET: a callback via `ObjectDataProvider`, or type-confusion to a benign method.
Confirm only on an inbound OOB hit carrying the unique token.

### Rung 4 — Read-only impact
Where a chain permits file read or a benign command, capture a single readable value
(e.g. `id` output) — never a destructive command, never persistence.

### Rung 5 — Client-side deserialization
If the serialized object is consumed in the browser (React `serialize-javascript`,
`node-serialize` in an SPA, `webpack` state injection), this overlaps client-side gadget
territory — hand to `offsec-client-side-agent` (prototype-pollution) as a
`delegation_request` and stop climbing here.

---

## 3. Minimal Proof and Hard Limits

**One benign effect is a valid finding. Stop there.**

- Read-only proofs only: a callback hit, a readable file value, an `id` result.
- No destructive payloads, no persistence, no reverse shell, no data modification — ever.
- No full gadget-chain weaponization beyond the benign callback/read.
- Never target real user data; never exfiltrate beyond the minimal proof.

## 4. WAF / Filter Note

Deserialization is a parser-trust bug; if a filter blocks the blob, re-express it once
(encoding, alternate parameter, alternate cookie) then report `blocked`. Do not
brute-force a filter or fuzz gadget on production.

## 5. Evidence Requirements

1. Baseline request/response captured.
2. Tampered request with the modified object shown verbatim.
3. A **control** (valid object, no gadget) that does not fire.
4. Observation repeated at least twice (or a one-shot callback with the unique token).
5. Human-readable proof: a collaborator hit, a readable value, or an `id` output.

Never confirm on scanner output, on a 500 alone, or on an error that merely names a class.

## 6. Severity

| Condition | Severity |
|---|---|
| Format confirmed, no gadget influence | low–medium |
| Non-destructive callback proves deserialization of untrusted object | high |
| Read-only file/command impact | high |
| Deserialization → RCE demonstrated (benign proof only) | critical |
| Client-side sink only | handled in client-side class (delegation) |

## 7. Result Contract

```json
{
  "class": "deserialization",
  "transport": "burp | playwright-fallback",
  "confirmed": [{
    "endpoint": "POST /api/profile",
    "param": "state (base64 java)",
    "format": "java | php | dotnet | python | node",
    "technique": "format-confirm | type-tamper | gadget-callback | read-only",
    "payload_used": "URLDNS gadget to <host>",
    "control_payload": "valid object, no gadget",
    "proof": "collaborator DNS hit / readable value",
    "data_exposed": "callback only | <value>",
    "reproduced_twice": true,
    "severity_estimate": "high"
  }],
  "tested_clean": ["endpoint#param"],
  "blocked": [{"endpoint": "...", "param": "...", "note": "filter/serialization library patched"}],
  "delegation_requests": [],
  "status": "complete | partial | blocked"
}
```

## 8. Stop Conditions

- A filter survives re-expression → `blocked_by_defense`, halt class.
- Any rung would require a destructive/state-changing payload → stop, confirmed-with-limitations.
- The only proof path is full RCE weaponization → stop at the benign callback.
- Two consecutive 5xx → halt class.

## 9. Non-Goals

- Building or delivering a working RCE payload beyond the benign callback.
- Client-side deserialization → `offsec-client-side-agent` (prototype-pollution).
- Mass assignment / over-posting → `offsec-business-logic-agent` SKILL main flow.
- SQLi reached through a deserialized field → `offsec-injection-agent`.
