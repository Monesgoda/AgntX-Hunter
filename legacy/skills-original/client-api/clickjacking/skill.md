---
name: clickjacking
description: Audits UI redressing and framing protections via HTTP response headers and CSP directives.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Clickjacking & Framing Protection Audit Procedure

## 1. Audit Scope & Objective
Verify that application web interfaces containing sensitive actions or forms cannot be rendered inside unauthorized `<iframe>` or `<frame>` elements.

## 2. Detection Checklist
1. Framing Headers:
   - Check HTTP response headers on sensitive web pages for `X-Frame-Options`.
   - Check for valid values: `DENY` or `SAMEORIGIN`.
2. Content Security Policy:
   - Check for the modern replacement: `Content-Security-Policy: frame-ancestors 'none'` or `frame-ancestors 'self'`.
3. Client-Side Framebusters:
   - Look for JavaScript-based frame-busting scripts (e.g., `top.location != self.location`) and verify they are supplemented with standard HTTP headers, as JS framebusters are bypassable.
   - Keep the common bypasses in mind: a `sandbox="allow-scripts"` iframe without `allow-top-navigation` neuters `top.location` writes, and nested iframes plus `onbeforeunload` tricks can defeat naive framebusters.
4. Header Precedence & Coverage:
   - When both are present, `Content-Security-Policy: frame-ancestors` takes precedence over `X-Frame-Options` in modern browsers; a stale `X-Frame-Options` value does not override a permissive `frame-ancestors`.
   - Confirm the control is present on every sensitive route and error page, not only on the main HTML shell.

## 3. False-Positive Guardrails
- API endpoints returning pure JSON/XML payloads do not require framing headers.
- Public, static informational pages with no user state or actions present minimal clickjacking risk.
- **Boundary:** framing and `frame-ancestors` protections are this class; the wider CSP `script-src`/nonce bypass surface is `client-side-advanced/csp-bypass`. Cross-reference, do not duplicate.

## 4. Remediation Guidance
- Configure reverse proxies or application middleware to inject:
  `Content-Security-Policy: frame-ancestors 'self';`
  and
  `X-Frame-Options: SAMEORIGIN`
- Prefer `frame-ancestors` as the authoritative control and keep `X-Frame-Options` only for legacy clients; apply both across all sensitive and error responses.