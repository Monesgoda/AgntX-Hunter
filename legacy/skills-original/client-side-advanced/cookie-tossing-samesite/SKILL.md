---
name: cookie-tossing-samesite
description: Audits cookie scoping and SameSite reachability for Cookie Tossing across sibling subdomains and client-boundary SameSite bypass.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Cookie Tossing & SameSite Bypass Audit Procedure

## 1. Audit Scope & Objective
Review captured `Set-Cookie` headers, client cookie-writing code, and reachable host names to determine whether an attacker-controlled sibling subdomain can set a `Domain=.<parent>` cookie that shadows or overrides a cookie the application trusts, and whether a `SameSite` cookie can be reached cross-site by a mutable top-level GET or client route. The objective is to determine whether cookie scope or SameSite protection can be defeated at the client boundary.

## 2. Detection Checklist
### A. Cookie scope inventory
- From captures, list each cookie's `name`, `Domain`, `Path`, `SameSite`, `Secure`, `HttpOnly`; flag any `Domain=.<parent>` (parent-scoped, not host-only).
- Note the `__Host-` / `__Secure-` prefixes: `__Host-` cookies must be `Secure`, host-only (no `Domain`) and `Path=/`, so a sibling subdomain **cannot** toss them (the browser rejects a mismatching `Set-Cookie`).
- Check `Path` scoping: a cookie set with a more specific `Path` does not override one with a broader `Path` — both are sent, and servers read the first, so a tosser can win via a broader or duplicate path.

### B. Sibling-subdomain primitive
- Identify an authorized user-content or non-production subdomain under the same registrable domain that could set `.example.com` cookies; if none is reachable, the primitive is blocked.

### C. Client-boundary SameSite reachability
- For `Lax`, find a top-level GET or client-side route that mutates state or performs a sensitive action on load.
- Confirm whether the app reads any cookie client-side (`document.cookie`) to make a trust decision (redirect target, feature flag, `returnUrl`).

## 3. False-Positive Guardrails
- A **host-only** cookie (no `Domain` attribute) or a `__Host-` prefixed cookie cannot be tossed by a sibling subdomain — suppress and say why.
- A sibling subdomain you are not authorized to test is not a usable primitive — record as unproven, do not claim.
- Server-set cookies on the correct host with `Secure; HttpOnly` are normal; the finding is the scope/shadowing, not the cookie's existence.
- Boundary: cookie scoping and client-boundary SameSite are this class; session fixation, server-set attributes, and logout revocation belong to `agent-auth-session` (`session-lifecycle`).

## 4. Remediation Guidance
- Prefer host-only cookies (omit `Domain`) and use the `__Host-` prefix for session cookies.
- Scope security-relevant cookies to the exact host; avoid parent-domain cookies for auth state.
- Set `SameSite=Strict` (or `Lax`) plus `Secure; HttpOnly`, and never perform state changes on GET.
