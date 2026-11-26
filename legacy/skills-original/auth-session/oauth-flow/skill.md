---
name: oauth-flow
description: Audits OAuth 2.0 and OpenID Connect (OIDC) implementations for redirect_uri validation flaws, CSRF on connection flows, token leakage, and insecure grant types.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# OAuth 2.0 & OIDC Security Audit Procedure

## 1. Audit Scope & Objective
Evaluate authorization code and token exchanges against common protocol implementation flaws, broken redirect logic, and missing state validations.

## 2. Detection Checklist
1. Redirect URI Validation:
   - Check if `redirect_uri` is validated via an exact string-matching whitelist on the authorization server.
   - Look for regex weaknesses, path traversal patterns, or open subdomain matching in redirect validation.
2. CSRF on OAuth Flows (`state` parameter):
   - Verify that the `state` parameter is generated cryptographically, uniquely per session, and validated upon callback.
   - Flag flows where `state` is optional, static, predictable, or absent.
3. Authorization Code & Token Leakage:
   - Check for token or authorization code passing in URL query parameters where it might be leaked via `Referer` headers or browser history.
   - Verify that authorization codes are strictly single-use and have a short time-to-live (TTL <= 10 minutes).
4. PKCE Enforcement:
   - In single-page applications (SPAs) or mobile clients, ensure PKCE (RFC 7636) with `S256` is enforced.
   - Reject `code_challenge_method=plain`; a downgraded PKCE offers no protection against interception.
5. OIDC ID Token & `nonce` Validation:
   - Confirm the `nonce` sent in the authorization request is validated in the returned `id_token` and bound to the session.
   - Verify the `id_token` signature and its `iss`, `aud`, `azp`, `exp`, and `iat` are all checked against the expected issuer/client.
6. IdP Mix-Up & Issuer Binding:
   - Check that a single configured issuer identifier is bound to the client and re-checked at the token endpoint; a client willing to talk to an attacker-supplied authorization server enables mix-up attacks.
7. Grant Types & Token Handling:
   - Flag use of the implicit flow and the resource-owner password credentials (ROPC) grant; require authorization code + PKCE.
   - Confirm refresh tokens rotate on every use and that reuse of a rotated refresh token is detected and revokes the token family.

## 3. False-Positive Guardrails
- Do not flag absent `state` parameters if the flow uses OpenID Connect with a cryptographically verified `nonce` linked to the client session.
- Do not flag broad redirect paths if the domain and subdomains are strictly owned and have no open redirectors.
- **Boundary:** the OAuth/OIDC **protocol** flaws (redirect_uri, `state`/`nonce`, PKCE, grant types, token endpoint) are this class; a plain open redirector is `client-side-advanced/open-redirect`; JWT/ID-token verification internals are `auth-session/jwt-security`; SSRF on JWKS/`issuer` fetching is `infra-protocol/ssrf-defense`.

## 4. Remediation Guidance
- Enforce strict exact-match whitelisting for all client redirect URIs.
- Bind the OAuth `state` value to an anti-tamper session cookie before redirecting.
- Require PKCE (`code_challenge_method: S256`) for public clients; reject `plain`.
- Validate the OIDC `nonce` and the full `id_token` claim set (`iss`/`aud`/`azp`/`exp`/`iat`) against the configured client.
- Bind the client to a single issuer and drop the implicit and ROPC grants; rotate refresh tokens and revoke the token family on reuse detection.