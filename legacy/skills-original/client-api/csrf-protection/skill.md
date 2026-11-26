---
name: csrf-protection
description: Audits web endpoints for Cross-Site Request Forgery (CSRF) vulnerabilities, missing anti-CSRF tokens, and insufficient cookie defenses.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# CSRF Defense Audit Procedure

## 1. Audit Scope & Objective
Ensure all state-changing actions cannot be triggered across origins without explicit user intent.

## 2. Detection Checklist
1. Anti-CSRF Token Validation:
   - Identify state-changing operations (`POST`, `PUT`, `DELETE`, `PATCH`).
   - Check if endpoints require a cryptographically unpredictable token (Synchronizer Token Pattern or Double Submit Cookie).
   - Verify that token validation is enforced strictly on the server and cannot be bypassed by removing the token parameter.
2. Cookie SameSite Defense:
   - Check whether authentication cookies use `SameSite=Strict` or `SameSite=Lax`.
   - Identify GET requests that perform state changes (which bypass `SameSite=Lax`).
3. Content-Type Constraints:
   - Determine if API endpoints accept simple content types (`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`) without custom headers.
   - For JSON APIs, check whether the parser tolerates `text/plain` or a missing/loose `Content-Type`, which turns a non-preflighted simple request into a CSRF vector.
4. Method-Override Handling:
   - Check for `_method`, `X-HTTP-Method-Override`, or method tunneling that lets a simple `GET`/`POST` reach a state-changing handler, bypassing the token check attached to the "real" method.
5. Origin / Referer Enforcement:
   - Verify the server validates `Origin` (falling back to `Referer`) against an allow-list for state-changing requests, including when no anti-CSRF token is present.
6. Login & Session-Change CSRF:
   - Check login, logout, email/password change, and MFA enrollment for CSRF (login-CSRF can fixate a session or log the victim into the attacker's account).

## 3. False-Positive Guardrails
- Purely read-only endpoints (e.g., `GET /search`) do not require anti-CSRF tokens.
- APIs utilizing `Authorization: Bearer <token>` in headers (without reliance on ambient browser cookies) are inherently immune to browser-driven CSRF.
- **Boundary:** missing anti-CSRF tokens and SameSite defenses are this class; cross-subdomain cookie *tossing* and client-boundary SameSite bypass are `client-side-advanced/cookie-tossing-samesite`; where CSRF merely triggers an already-broken action, the underlying bug stays with its own class.

## 4. Remediation Guidance
- Require anti-CSRF tokens for all state-changing requests relying on cookie-based authentication.
- Set `SameSite=Lax` or `SameSite=Strict` on session cookies.
- Reject requests using unexpected content types on API endpoints, and validate `Origin`/`Referer` as defense in depth.
- Disable method-override on cookie-authenticated endpoints, and protect login/logout/session-change routes with CSRF tokens.