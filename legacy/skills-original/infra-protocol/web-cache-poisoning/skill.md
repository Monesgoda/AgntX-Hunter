---
name: web-cache-poisoning
description: Audits caching architectures for unkeyed inputs, host header injection in cached responses, and cache de-synchronization. Use when analyzing CDNs, reverse proxies, or caching headers.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Web Cache Poisoning Audit Procedure

## 1. Audit Scope & Objective
Evaluate how the application's caching layer (CDN, reverse proxy, or application cache) decides what to store and what to key on. The goal is to detect cases where a value the attacker controls - an unkeyed header, an unkeyed query parameter, or a normalization difference - is stored in a shared cache and later served to **other users**, poisoning the cached response.

## 2. Detection Checklist
1. Identify Cache Presence:
   - Look for headers: `X-Cache`, `CF-Cache-Status`, `Age`, `Cache-Control`.
2. Inspect Unkeyed Headers:
   - Check if custom headers (e.g., `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`) influence the response body or redirects while being cached.
3. Validate Cache Keys:
   - Verify whether query parameters or request headers that alter output are included in the cache key.

## 3. False-Positive Guardrails
- Ensure the response has a caching directive allowing storage (e.g., `public, max-age > 0`) and is not `no-store` or `private`.
- Ensure changes reflected in the body are persistent across unauthenticated requests.

## 4. Cache Deception
Cache deception (distinct from poisoning) tricks a cache into storing a **victim-authenticated** response under an attacker-chosen URL, which is then served to the attacker.

1. Identify the extension/path trick the origin ignores but the cache keys on: `/account/profile.css`, `/settings/nonexistent.js`, `/api/me/;x`, or a trailing `/` on a sensitive route.
2. Send an authenticated request to the deceptive URL; confirm the origin still returns the sensitive page while the cache stores it (a follow-up unauthenticated request shows `X-Cache: HIT` / `CF-Cache-Status: HIT`).
3. Confirm the follow-up **unauthenticated** request actually receives the victim's data (the impact), not merely a cache hit.

### False-Positive Guardrails
- A cache `MISS`, or a `private`/`no-store` response, is not cache deception - nothing sensitive was stored.
- A cached `200` that returns only public content is not deception; the stored body must contain authenticated/sensitive data.
- Boundary: **poisoning** (injecting into a shared cache via unkeyed input) is the section above; **deception** (storing a victim's response) is this section - same file, different mechanism. Path/extension normalization overlaps with `http-smuggling` / `host-header-attacks`, but the cache-storage decision stays here.

## 5. Remediation Guidance
- **Cache poisoning:** ensure every input that can change a response is part of the cache key (or excluded); strip unknown forwarding headers at the edge. Never let an unkeyed input influence a cached body or redirect.
- **Cache deception:** never cache authenticated responses; set `Cache-Control: private, no-store` (or `Vary` on `Authorization`/cookie) for sensitive routes. Normalize path extensions at the edge and cache on the normalized route, not the raw path.
- Cache only responses whose content is identical for every requester.
