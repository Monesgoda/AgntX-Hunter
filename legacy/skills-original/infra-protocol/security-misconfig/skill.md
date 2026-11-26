---
name: security-misconfig
description: Audits application and server configurations for debug modes, stack trace disclosure, default credentials, and unprotected administrative panels.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Security Misconfiguration Audit Procedure

## 1. Audit Scope & Objective
Identify exposed system internals, unhardened development interfaces, default accounts, and excessive diagnostic information leakage.

## 2. Detection Checklist
1. Debugging & Verbose Errors:
   - Check frameworks for active debug flags in production settings (e.g., `DEBUG = True`, `display_errors = On`).
   - Look for generic error handlers leaking framework stack traces, SQL queries, or internal IP addresses.
2. Management & Monitoring Interfaces:
   - Search for exposed management endpoints without authentication (e.g., Spring Boot Actuator, Django Admin, Swagger UI in production).
   - Framework-specific leaks to probe: Spring Boot `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`; the Django debug page (`DEBUG=True`) exposing settings and tracebacks; Rails `/rails/info`; and, from any origin, exposed `.git/`, `.env`, `.svn/`, backup SQL dumps, `phpinfo.php`, and directory listing (`Index of /`).
3. Default Credentials:
   - Inspect configuration files and initialization scripts for standard default credentials (e.g., `admin/admin`, `root/root`).
4. HTTP Method Configuration:
   - Check for unneeded HTTP methods enabled globally (e.g., `TRACE`, `TRACK`, `DEBUG`).

## 3. False-Positive Guardrails
- Swagger/OpenAPI documentation intentionally made public on non-sensitive, public API endpoints should not be marked as a vulnerability unless administrative routes are exposed.
- Detailed logging writing to internal log files (not returned to the HTTP response) is acceptable practice.
- Boundary: an exposed datastore/control API (Redis, Docker, Elasticsearch) is `cloud-infra/exposed-services`; a debug mode leaking source, tracebacks, or config is this class. Cross-reference, do not duplicate.

## 4. Remediation Guidance
- Ensure configuration environments strictly disable debug flags (`DEBUG=False`) in staging and production.
- Implement global exception handlers returning generic error messages to clients while logging details internally.
- Disable unused HTTP methods and restrict access to management routes via IP whitelisting or separate internal networks.