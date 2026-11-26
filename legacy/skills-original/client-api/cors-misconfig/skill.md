---
name: cors-misconfig
description: Audits Cross-Origin Resource Sharing (CORS) configurations for insecure trust relationships, origin reflection, and credential leakage.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Insecure CORS Audit Procedure

## 1. Audit Scope & Objective
Evaluate how the application constructs its CORS response headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`). The goal is to detect cross-origin trust relationships that let an arbitrary website read **credentialed** (authenticated) responses or otherwise act as the victim's origin.

## 2. Detection Checklist

### A. Origin Reflection
- Look for code reflecting the incoming `Origin` header directly into `Access-Control-Allow-Origin`.

### B. Credentials Handling
- Flag instances where `Access-Control-Allow-Credentials: true` is combined with reflected origins or `null`.

### C. Origin Matching & Parsing Flaws
- Review origin-matching regular expressions for unescaped dots or missing string anchors (e.g., matching `target.com.attacker.com`).
- Check prefix/suffix matching (`startsWith` / `endsWith`) that would accept `eviltarget.com` or `target.com.evil.com`.

## 3. False-Positive Guardrails
- An open origin (`*`) is NOT vulnerable if `Access-Control-Allow-Credentials` is not present and no private/authenticated data is returned.
- A reflected `Origin` is NOT exploitable when the reflected response carries no session-bound or private data readable by the attacker's page.
- `Access-Control-Allow-Credentials: true` alone is not a finding; the trusted origin must be attacker-controllable.

## 4. Remediation Guidance
- Maintain a strict server-side allow-list of fully-qualified trusted origins; never reflect the request `Origin` verbatim and never accept `null`.
- Anchor origin matching at both ends (exact match, or a validated suffix on a dot boundary); avoid unescaped regex and unanchored `startsWith` / `endsWith`.
- Send `Access-Control-Allow-Credentials: true` only for origins on the allow-list, and never combine it with a wildcard `*`.
- Emit `Vary: Origin` when the response varies by origin so shared caches do not serve one tenant's CORS headers to another.