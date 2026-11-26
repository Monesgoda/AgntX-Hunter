---
name: exposed-services
description: Audits for unaudited network exposure of datastores and control-plane services such as Redis, MongoDB, Elasticsearch, and the Docker API.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Exposed Services Audit Procedure

## 1. Audit Scope & Objective
Review reachable network services and captured banners to find datastores or control APIs exposed without authentication to untrusted networks (Redis, MongoDB, Elasticsearch, Memcached, etcd, Docker daemon, Kibana, Jenkins). The objective is to determine whether an attacker can read, alter, or control data through an exposed service.

## 2. Detection Checklist
### A. Reachability and banner
- From supplied port/banner data (or passive scan output), flag services answering on their default **and** non-default ports from a non-internal origin (a moved datastore is still exposed).
- Identify version banners (Redis `-ERR`, MongoDB wire hello, Elasticsearch `{"version":{...}}`) and map the exact version to known CVEs.
- Include locally reachable sockets in the review: a Docker/containerd Unix socket (`/var/run/docker.sock`) is a full control plane even with no TCP listener.

### B. Authentication posture
- Redis: `AUTH` required? `CONFIG GET`/`INFO` reachable unauthenticated?
- MongoDB: unauthenticated `listDatabases`/collection reads.
- Elasticsearch: unauthenticated `_cat/indices`, `_search`.
- Docker API: `/version`, `/containers/json` reachable without TLS/auth.
- "Authentication present" is not the end of it: test vendor/default credentials (Redis `redis`, Elasticsearch `elastic:changeme`, MongoDB admin with no auth) — a default password is still an exposure.

### C. Impact confirmation
- Confirm read access to real data or a state-changing capability (carefully, in scope, non-destructive) — do not enumerate beyond minimal proof.

## 3. False-Positive Guardrails
- A service reachable only from a trusted internal network is not "exposed" for the purposes of this finding — confirm the origin of the evidence.
- A banner alone is not an exposure; authentication must be shown absent or bypassable.
- A port that is open but returns a TLS/mTLS handshake failure is not an unauthenticated service.
- Boundary: SSRF-driven internal service reachability is `infra-protocol/ssrf-defense`; direct external exposure is this class.

## 4. Remediation Guidance
- Never expose datastores/control APIs to untrusted networks; bind to private interfaces and firewall egress/ingress.
- Require authentication + TLS (and mTLS for control planes) on every datastore.
- Segment management networks; monitor for new public listeners.
