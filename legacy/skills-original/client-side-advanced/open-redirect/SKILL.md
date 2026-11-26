---
name: open-redirect
description: Audits client-side navigation sinks that can send the browser to an attacker-controlled destination from an insufficiently validated redirect parameter.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Open Redirect (Client-Side Navigation) Audit Procedure

## 1. Audit Scope & Objective
Review client-side JavaScript and HTML for navigation sinks that redirect to a destination derived from attacker-influenced input (`?next=`, `?returnUrl=`, hash, `postMessage`) and verify whether the validation can be bypassed. The objective is to determine whether an attacker can steer navigation to an external origin, especially on pre-auth or post-auth callback paths.

## 2. Detection Checklist
### A. Navigation sinks
- Search for `location.assign(`, `location.href =`, `location.replace(`, `window.open(`, `router.push(`/`replace(`, `navigate(`, `redirectTo(`, meta-refresh, `history.pushState` into a later redirect.

### B. Input source
- Confirm the destination is attacker-controlled (query parameter, hash fragment, `postMessage` field, `localStorage`, decoded deep-link).

### C. Validation strength
- Classify the guard: none; blocklist (`startsWith('/')`, `includes(host)`); allow-list prefix without an anchor; strict equality on the full parsed origin.
- Test bypass shapes: `//evil.com`, `https://trusted.com.evil.com`, `/\evil.com`, `\/\/evil`, `?@evil.com` (userinfo), `https://trusted.com@evil.com`, embedded `\t`/`\n`/`\r`, Unicode dot look-alikes (`evil。com`, `evil．com`), and non-`http(s)` schemes (`javascript:`, `data:`) where the sink accepts them.

## 3. False-Positive Guardrails
- A redirect to a relative, same-origin path built from a validated value is not an open redirect — suppress and say why.
- A guard that parses the URL and compares the **full origin** for equality neutralizes string tricks; do not claim a bypass you did not find.
- Fixed internal sidebar/login links and allow-listed destinations are not findings.
- Open redirect alone is typically medium; do not inflate without a chained impact (token leak, CSP bypass).
- Boundary: host-header-driven redirects belong to `host-header-attacks`; a fully server-decided redirect is noted and delegated.

## 4. Remediation Guidance
- Resolve the destination URL and compare the full origin against an exact allow-list; reject anything else.
- Prefer relative, same-origin paths and pass an opaque server-side reference instead of a URL.
- Never trust `//`-prefixed or backslash-normalized values as "relative".
