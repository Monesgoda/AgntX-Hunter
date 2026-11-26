---
name: ssrf-defense
description: Audits codebases and architectures for Server-Side Request Forgery (SSRF), inspecting outbound HTTP requests, webhook handlers, URL parsers, and cloud metadata access protections.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Server-Side Request Forgery (SSRF) Audit Procedure

## 1. Audit Scope & Objective
Detect application features that accept user-supplied URLs or network identifiers and fetch remote resources server-side without strict network boundary enforcement and schema validation.

## 2. Detection Checklist
1. Outbound Network Sinks:
   - Identify functions making HTTP/socket requests (e.g., Python `requests.get()`, `urllib`, Node.js `axios`, `fetch`, Java `HttpURLConnection`, Go `http.Get`).
   - Trace the origin of the target URL: verify if any component (scheme, host, port, path) is derived directly or indirectly from user input.
2. Scheme & Protocol Validation:
   - Verify that schemes are strictly constrained to `http` and `https`.
   - Flag code accepting arbitrary URI schemes like `file://`, `gopher://`, `dict://`, `ftp://`, or `ldap://`.
3. IP & DNS Resolution Controls:
   - Verify that destination IPs are resolved and validated against a blacklist of private/internal ranges (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, Loopback `127.0.0.0/8`, IPv6 `::1`).
   - Prefer an allow-list of permitted destinations over a block-list: block-lists miss alternative IP encodings (`http://2130706433/`, `http://0177.0.0.1/`, `http://[::ffff:127.0.0.1]/`, `0x7f.0.0.1`) and rarely-reserved ranges.
   - Check for protection against Cloud Metadata endpoints (e.g., `169.254.169.254`).
   - Verify mitigation against DNS Rebinding (TOCTOU): the validated IP must be the one actually connected to (pin the resolved address, or use a controlled resolver), not merely re-checked on the hostname string.
   - For AWS, confirm IMDSv2 (token-required) is enforced over IMDSv1; other clouds' equivalents should require a non-guessable request header.
4. HTTP Redirect Handling:
   - Check if outbound HTTP clients follow redirects automatically.
   - Ensure redirection targets undergo the same IP and protocol validation as the initial request.

## 3. False-Positive Guardrails
- Hardcoded URLs pointing to trusted third-party APIs with no user-controllable path or parameter injection are safe.
- Webhook dispatchers that allow user-defined callback URLs are not vulnerable to external SSRF by design, provided strict internal IP blocking (RFC 1918 + loopback + link-local) is enforced on resolution.
- Boundary: SSRF here is an attacker-supplied **destination URL**; an attacker-supplied **Host header** steering a redirect or absolute URL is `infra-protocol/host-header-attacks`; a JWT `jku`/`jwk` fetch is `auth-session/jwt-security` (destination validation owned here).

## 4. Remediation Guidance
- Resolve the target hostname to an IP address before establishing the connection, and assert that the IP does not belong to private, loopback, multicast, or link-local ranges.
- Disable automatic redirect following on server-side HTTP clients, or re-run IP validation on every redirect hop.
- Configure egress firewall / network-level isolation (e.g., network security groups) to block application servers from reaching internal administrative ports and metadata services.