---
name: password-reset-flow
description: Audits password reset flows for token weakness, host-header poisoning of reset links, user enumeration, and missing single-use/expiry enforcement.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Password Reset Flow Audit Procedure

## 1. Audit Scope & Objective
Review the "forgot password" request and reset-completion flow to determine whether reset tokens can be predicted, reused, exfiltrated, or redirected to an attacker, and whether the reset link can be poisoned. The objective is to detect account-takeover vectors in the reset flow.

## 2. Detection Checklist
### A. Token generation and lifecycle
- Is the reset token cryptographically random, long, single-use, and short-lived? Reject sequential/short/predictable tokens.
- Confirm the token is invalidated after use and after a successful reset.
- Confirm a successful reset invalidates **other active sessions** and refresh tokens for the account (or the omission is documented), and that the token is bound to the requesting context (account, and where feasible the browser/UA).

### B. Link construction and host poisoning
- Determine how the base URL in the reset link is built — a static config is safe; a value derived from the request `Host`/`X-Forwarded-Host` enables reset-link poisoning.
- Check whether the reset URL leaks via `Referer` or third-party resources.

### C. Flow weaknesses
- Whether the reset endpoint reveals account existence (see `client-api/rate-limiting` Username Enumeration).
- Whether the reset token is bound to the account and cannot be swapped to another account id.
- Whether an attacker can request unlimited resets (email/SMS flooding → `client-api/rate-limiting`).

## 3. False-Positive Guardrails
- A host-header-driven reset link is a finding only if the injected host actually reaches the delivered email/redirect — reproduce the poison, do not assume it.
- A reset endpoint that always returns a generic response is not user enumeration; do not claim it.
- Rate limiting presence is a control; its absence is owned by `client-api/rate-limiting`.
- **Boundary:** the **general reset logic** (token strength/lifecycle, binding, flow) is this class; exploitation **specifically via the Host header** is `infra-protocol/host-header-attacks` — cross-reference both ways.

## 4. Remediation Guidance
- Generate tokens with a CSPRNG, store only a hash, expire in minutes, and enforce single-use and post-reset invalidation.
- Build reset links from a static, configured base URL; never from request headers.
- Return generic responses, rate-limit reset requests, and bind the token to the account and session.
- On a successful reset, invalidate all other sessions and refresh tokens for the account and revoke the used token so a leaked link cannot be replayed.
