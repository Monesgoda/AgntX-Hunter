---
name: host-header-attacks
description: Audits application code and reverse proxy architectures for HTTP Host header vulnerabilities, including password reset poisoning, routing and virtual host bypasses, and server-side cache poisoning via injected host/forwarded headers.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# HTTP Host Header Attacks Audit Procedure

## 1. Audit Scope & Objective
Evaluate how the web application and its upstream reverse proxies parse, validate, and utilize the HTTP `Host` header (and associated forwarding headers like `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`). The goal is to detect instances where untrusted host values are reflected into business workflows, email templates, absolute redirects, or caching layers without strict validation.

## 2. Detection Checklist

### A. Password Reset Poisoning
1. Email Link Construction:
   - Inspect password reset generation logic across controllers and services.
   - Verify if the base domain used in tokenized password reset links is dynamically extracted from `request.headers['host']`, `request.get_host()`, or incoming `X-Forwarded-Host` headers rather than a static environment configuration.
2. Template Rendering:
   - Trace whether user-controlled host values pass unescaped into email body generation or transactional notification templates.

### B. Routing, Proxy & Virtual Host Bypasses
1. Internal Virtual Host Access:
   - Identify whether routing logic or ingress controllers expose internal administrative dashboards (e.g., `localhost`, `internal.admin`, `management.local`) based solely on the incoming `Host` header.
2. Inconsistent Proxy Rewriting:
   - Check if edge reverse proxies (Nginx, HAProxy, Envoy) pass the client's `Host` header unaltered to backend origins without sanitizing or overriding it with the trusted upstream domain name.

### C. Dynamic Redirects & Absolute URL Generation
1. Unvalidated Redirect Targets:
   - Search for redirection logic (HTTP 301, 302, 307, 308) that constructs absolute destination URLs dynamically using the incoming `Host` header (e.g., redirecting HTTP to HTTPS or canonicalizing paths).
   - Check if an injected hostname results in an open redirect to an external origin.
2. Asset & Script Link Injection:
   - Check if script tags, stylesheets, or API base URLs rendered in HTML pages use the incoming `Host` header to build absolute URLs (e.g., `<script src="//[Host]/static/app.js">`), potentially enabling script inclusion if cached.

### D. Multiple & Malformed Host Headers
1. Header Duplication & Line Wrapping:
   - Evaluate backend framework behavior when handling duplicate `Host` headers or headers with leading spaces/tabs.
   - Check for discrepancies between frontend load balancers and backend application servers in resolving conflicting host declarations.

## 3. False-Positive Guardrails
- **Static Domain Configuration:** Do NOT report if the application derives base URLs, email links, and absolute redirects strictly from hardcoded constants, environment variables (e.g., `APP_URL`, `SERVER_NAME`), or verified configuration files.
- **Server-Level Binding:** If the web server or proxy enforces a strict whitelist of accepted server names and immediately returns `400 Bad Request` or a default fallback page for unrecognized hostnames, dynamic reflection risks are mitigated.
- **Header Forwarding Without Reflection:** The presence of `X-Forwarded-Host` in proxy passes is not a vulnerability unless backend code explicitly consumes and acts upon it without verification.

## 4. Remediation Guidance
1. Rely on Static Server Configurations:
   - Hardcode or inject the canonical base domain via environment variables (e.g., `process.env.PUBLIC_URL` or `settings.ALLOWED_HOSTS`) for all email generation, password reset tokens, and canonical URLs.
2. Enforce Hostname Whitelisting at Edge & App Layers:
   - Configure web servers (e.g., Nginx `server_name`, Apache `ServerName`) and application frameworks (e.g., Django `ALLOWED_HOSTS`, Express `trust proxy` settings) to strictly drop or reject requests with unrecognized host headers.
3. Ignore or Override Untrusted Forwarding Headers:
   - Strip or overwrite `X-Forwarded-Host`, `X-Forwarded-Server`, and `X-Host` at the outermost reverse proxy unless explicitly originating from a trusted internal tier.

## 5. Boundary
- The **Host-header-specific** reflection of reset links (the base URL taken from `Host` / `X-Forwarded-Host`) is this class; the **general reset logic** (token strength, lifecycle, binding, single-use/expiry) is `auth-session/password-reset-flow` - cross-reference both ways.
- Cache-key mechanics of host-header-driven cache poisoning stay here; generic cache de-synchronization and deception are `infra-protocol/web-cache-poisoning`.
- Header/request-line parsing mismatches (`Content-Length` vs `Transfer-Encoding`, duplicate-header splitting) belong to `http-smuggling`.