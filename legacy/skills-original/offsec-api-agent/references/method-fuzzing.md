
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# HTTP Method Tampering / Fuzzing

## Tool Binding

- Transport: Burp MCP / Playwright MCP.
- Input: endpoint inventory from `api-inventory-openapi.md` (or manual list).
- Allowed methods: `GET POST PUT PATCH DELETE HEAD OPTIONS TRACE CONNECT`
  plus common non-standard (`PROPFIND`, `X-HTTP-METHOD-OVERRIDE` header).

## Detection Ladder

### Rung 1 — Method enumeration via OPTIONS
OPTIONS on endpoint → parse `Allow:` header. Compare advertised vs. actually
accepted. Mismatch → `method.allow_mismatch` (info).

### Rung 2 — Verb tampering for auth bypass
Endpoint requires `POST` (auth enforced in POST handler). Send `GET` /
`HEAD` / `PUT`. If 200 with data → `method.tamper_bypass` (high).

### Rung 3 — Method override headers
Send POST with:
- `X-HTTP-Method-Override: GET`
- `X-HTTP-Method: DELETE`
- `X-Method-Override: PUT`
If server honors override while path-level auth differs → `method.override_bypass`.

### Rung 4 — Case / encoding variants
`GET` vs `get` vs `GeT`, `POST` vs `POST\t` (trailing whitespace).
Some proxies normalize; some app servers don't. Divergence → `method.case_mismatch`.

### Rung 5 — Path param pollution
`/api/users/1;admin`, `/api/users/1%00`, `/api/users/1..;/`
Combined with method variation → `method.path_smuggling`. **Boundary:** if the
core bug is path traversal, this belongs to `offsec-path-file-agent`; only
keep it here if the exploit requires method variation.

### Rung 6 — HEAD with body
Some frameworks treat HEAD like GET but return headers only — occasionally
leaking content-length of sensitive resources. Info-level.

## Minimal Proof

- Baseline request with correct method + auth
- Tampered request with same auth (or none) showing different outcome
- Diff table: method × status × body-size

## Evidence Requirements

- `evidence_dir/method_matrix.json` — `{endpoint, method, status, len, auth}`
- `evidence_dir/method_<rung>_req.txt` / `_res.txt`
- One raw pair per confirmed finding.

## Severity

| Finding | Severity |
|---|---|
| Allow mismatch (info only) | info |
| Verb tampering → auth bypass | high |
| Method override bypass | high |
| Case mismatch (no auth impact) | low |
| Path param smuggling (method-dependent) | high |

## Result Contract

```json
{
  "status": "confirmed | tested_clean",
  "class": "method.<rung>",
  "endpoint": "<path>",
  "method_used": "GET",
  "baseline_method": "POST",
  "evidence": ["..."],
  "severity": "<table>",
  "poc_ref": "poc/method-<slug>.md | null"
}
```

## Stop Conditions

- TRACE / CONNECT returning 200 → log as info, don't probe further.
- Any 5xx → halt.
- WAF block → `blocked_by_defense`.

## Non-Goals

- Full endpoint fuzzing (parameter discovery) — that's `offsec-recon-agent`.
- Bypassing WAF via method tricks (that's `waf-evasion-generic`).
- CSRF-via-method-change (that's `csrf-protection` + business-logic).
