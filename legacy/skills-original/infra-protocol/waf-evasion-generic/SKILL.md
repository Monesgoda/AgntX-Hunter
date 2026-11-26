---
name: waf-evasion-generic
description: Audits and guides generic WAF/filter evasion — the ordered bypass ladder applied when a defensive filter blocks an otherwise valid payload, used by the Active injection/api agents instead of duplicating evasion logic in each reference.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Generic WAF / Filter Evasion Audit Procedure

## 1. Audit Scope & Objective
Provide one canonical, ordered evasion ladder for any filter that blocks a validated payload (SQLi, XSS, structural injection, path, etc.), plus the discipline for when evasion is appropriate. The objective is to raise the chance a blocked valid payload reaches the vulnerable context **without** brute-forcing a filter or escalating to DoS. This is a shared reference: the Active agents (`offsec-injection-agent`, `offsec-api-agent`) consume it instead of each re-implementing evasion (see `offsec-injection-agent/references/sqli.md` §7).

## 2. Detection Checklist
### A. Characterize the filter
- Determine what trips it: a token (`SELECT`, `<script>`), a character (`'`, `<>`), a length, a rate, or a fingerprint (IP/UA). Probe a prefix ladder (`S`, `SE`, `SEL`, `SELE`, `SELECT`) to find the exact tripping token.
- Distinguish a WAF block (403/challenge page) from an origin error — only the former is an evasion problem.

### B. Apply the ordered ladder (try once each, in order)
1. Case variation (`SeLeCt`).
2. Inline comment split (`SE/**/LECT`, `UN/**/ION`).
3. Versioned comment (`/*!50000SELECT*/`).
4. Operator substitution (`OR`→`||`, `=`→`LIKE`).
5. Whitespace substitution (`%0a`, `%0b`, `%09`, `/**/`, `+`).
6. Comment terminator change (`-- -`, `#`, `;`).
7. URL encoding / double encoding (`%27`, `%2527`).
8. Case-alternating keyword.
9. Arithmetic truth (`1=1`→`2>1`).
10. Stacked/second-statement form (only if already in scope).
11. Unicode/overlong apostrophe variants (overlong UTF-8 `%c0%a7`, full-width, mixed charset).
12. Parenthesis/type juggling (`1)`, `1))`, JSON type swap).
13. Character-set switching (`Content-Type: ...; charset=ibm037` / UTF-16) to make the parser reinterpret the same bytes.
14. HTTP-level splitting: chunked encoding, `Transfer-Encoding`, or a duplicate parameter, to place the payload past the inspected boundary.

### C. Stop conditions
- Stop at the first variant that reaches the vulnerable context; do not continue the ladder.
- If a variant triggers a different defense (429/CAPTCHA/hard ban), stop and record `blocked_by_defense`.

## 3. False-Positive Guardrails
- Evasion is only meaningful for a payload already shown to be valid (a confirmed detection rung). A bypass that only changes an error page is not a finding.
- A WAF that lets a boolean pair through did not block anything — do not claim an evasion success where the payload already worked.
- Toggle case/comment tricks that are normalized by the origin are not a bypass.
- Boundary: this is the shared ladder; per-class exploitation proof belongs to the consuming agent (`offsec-injection-agent`, `offsec-api-agent`). Cache poisoning and host-header trickery are `web-cache-poisoning` / `host-header-attacks`, not evasion.

## 4. Remediation Guidance
- Prefer server-side input validation and parameterized queries/encoding over blocklists; treat a bypassable WAF as defense-in-depth, not the control.
- Normalize/URL-decode and canonicalize input once, then validate; reject rather than transform.
- Log and alert on evasion attempts; rate-limit and CAPTCHA-gate abusive sources.
