---
name: session-lifecycle
description: Audits session generation, storage, cookie attributes, revocation upon logout, and session fixation vulnerabilities.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Session Lifecycle & Cookie Security Audit Procedure

## 1. Audit Scope & Objective
Ensure user sessions are initialized safely, bound properly to the authenticated state, protected against theft in transit/storage, and reliably revoked.

## 2. Detection Checklist
1. Session Fixation:
   - Verify that a completely new session identifier is issued immediately upon successful authentication.
   - Check if an unauthenticated session token persists post-login.
2. Session Revocation:
   - Inspect the logout handler: verify that session state is destroyed in server-side storage (e.g., Redis, DB), not just cleared in client-side cookies.
   - Check if changing credentials (password, email) terminates all existing active sessions.
3. Cookie Security Attributes:
   - Check session cookies for `HttpOnly` (mitigates script access).
   - Check for `Secure` flag (enforces transmission strictly over HTTPS).
   - Check for `SameSite=Lax` or `SameSite=Strict`.
4. Idle & Absolute Timeouts:
   - Verify server-side enforcement of absolute session expiration and inactivity timeout thresholds.
5. Weak "Remember Me" Cookie:
   - Inspect the persistent-auth ("remember me"/"keep me signed in") token: is it a long-lived session cookie, a static secret, or a reusable token?
   - Check that the token is random, single-use (rotated on each use), revocable server-side, bound to the user agent/device, and invalidated on logout and password change.
   - Flag a "remember me" cookie that is predictable, never rotates, is not revocable, or whose theft grants indefinite access beyond a normal session lifetime.
6. Session Identifier Strength & Scope:
   - Session IDs must come from a CSPRNG with at least 128 bits of entropy (>= 16 random bytes).
   - Prefer the `__Host-` cookie prefix (implies `Secure`, no `Domain`, `Path=/`) or `__Secure-` where a `Domain` is required, to prevent subdomain/scope shadowing.
7. Concurrent Sessions:
   - Check whether the application limits concurrent sessions and lets the user list/revoke them; unbounded parallel sessions widen the theft window.

## 3. False-Positive Guardrails
- Stateless tokens (e.g., JWT) stored in memory or Web Storage are not evaluated as session fixation; evaluate them under token expiration and revocation instead.
- Do not flag lack of `Secure` flags in local development configuration files if production environment flags enforce it.
- A long `Max-Age` on a "remember me" cookie is not by itself a finding — the issue is a token that is predictable, non-rotating, or non-revocable (see `agent-auth-session` `jwt-security` for token-specific flaws).
- Boundary: server-set cookie attributes and lifecycle are this skill; cross-subdomain cookie *tossing* / client-boundary SameSite bypass is `client-side-advanced/cookie-tossing-samesite`.

## 4. Remediation Guidance
- Always regenerate the session ID upon any privilege transition (login, role change).
- Implement a server-side session registry to allow definitive session invalidation upon logout.
- Set session cookie flags: `Secure; HttpOnly; SameSite=Lax`.
- Implement "remember me" as a random, server-stored, single-use, revocable token (rotate on each use, bind to the device) — never as a long-lived copy of the session cookie.
- Generate session IDs from a CSPRNG with >= 128 bits of entropy and name cookies with the `__Host-` prefix (falling back to `__Secure-` when a `Domain` is required).
- Offer session listing/revocation and optionally cap concurrent sessions per account.