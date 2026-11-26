---
name: rate-limiting
description: Audits API endpoints and sensitive application functions for lack of request throttling, resource exhaustion vectors, and unconstrained batch operations.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# API Rate Limiting & Resource Exhaustion Audit Procedure

## 1. Audit Scope & Objective
Identify critical endpoints lacking consumption boundaries, leading to brute-force enablement, costly third-party consumption, or Denial of Service (DoS) via resource-intensive processing.

## 2. Detection Checklist
1. High-Impact Sensitive Endpoints:
   - Password reset request triggers (email/SMS flooding).
   - OTP generation and verification routes.
   - User registration and account creation endpoints.
   - External paid API triggers (e.g., LLM inference, credit checks, payment gateway inquiries).
2. Resource-Intensive Processing:
   - Heavy data export endpoints (PDF/CSV generators, complex ZIP archiving).
   - Expensive search queries lacking pagination or with arbitrary `limit` parameters (e.g., `limit=1000000`).
   - Unconstrained file upload size limits in multipart request parsers.
3. Throttling Key Evaluation:
   - Check how rate limits identify clients (e.g., IP-based, token-based, user-ID-based).
   - Verify whether rate limits can be trivially bypassed via client-spoofed headers (e.g., manipulating `X-Forwarded-For` or `Client-IP` when the application trusts unverified proxy headers).
   - Check the limiter's key dimensionality: an IP-only limit is bypassed with IPv6 rotation or a proxy pool, an account-only limit by spraying across many accounts. Confirm the sensitive action is bounded on user **and** source.
4. GraphQL Batching & Query Depth:
   - Check if GraphQL endpoints allow unlimited query depth or batched execution of sensitive mutations in a single HTTP request.
   - Confirm operation/persisted-query limits and query cost analysis, not just requests-per-second, since one request can fan out to thousands of resolvers.
5. Username / Account Enumeration:
   - Compare responses (status code, body text, response length, and timing) for a valid vs. invalid identifier at login, registration, password reset, invite, and MFA-challenge endpoints.
   - Flag endpoints that reveal account existence via distinct error text ("no such user" vs "wrong password"), differing status codes, or a measurable timing delta.
   - Test both the request phase (e.g. reset "if the account exists") and the response phase; also check whether rate limiting is absent, which makes enumeration practical.

## 3. False-Positive Guardrails
- Static asset endpoints (images, public CSS/JS) served from a cache or CDN do not require application-level rate limiting.
- Internal microservice-to-microservice communication over secure private service meshes may deliberately omit public-facing throttling.
- A uniform generic response with the same status/body/timing for any identifier is **not** username enumeration — do not claim it.
- A single differing error string that is actually a validation/format error (not existence-based) is not enumeration.
- Boundary: enumeration found here is reported in this skill; the reset-flow logic itself is `auth-session/password-reset-flow`. Cross-reference, do not duplicate.
- Aggressive account lockout is itself a trade-off: confirm it is not a lockout-to-DoS vector (an attacker can lock a known user out). Report the trade-off, not an invented "no limit" finding.

## 4. Remediation Guidance
- Implement centralized rate limiting (e.g., via Redis token bucket or reverse proxy middleware) on all sensitive and resource-heavy routes.
- Ensure the rate limiter reads client IPs strictly from verified reverse proxy headers (configured with a trusted upstream count).
- Enforce strict maximum bounds on all pagination `limit` parameters and multipart file payload sizes.
- Return one generic response (same status, body, and near-constant timing) for authentication/registration/reset regardless of whether the account exists; add rate limiting to make enumeration impractical.
- Rate-limit on composite keys (account **and** source), return `429` with an accurate `Retry-After`, and prefer progressive backoff or temporary lockout over permanent account lockout.