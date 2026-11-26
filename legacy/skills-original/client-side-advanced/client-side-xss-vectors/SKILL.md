---
name: client-side-xss-vectors
description: Audits client-side rendering of attacker-supplied content for XSS through Swagger UI / API-docs fields and through SVG download-and-render (XSS-via-SVG only).
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Client-Side XSS Vectors (Swagger UI & SVG Rendering) Audit Procedure

## 1. Audit Scope & Objective
Review the client-side renderers that turn attacker-supplied content into DOM to find XSS that executes **client-side**: (1) Swagger UI / API-docs rendering of spec fields (`description`, `title`, `externalDocs`, `$ref` URLs), and (2) SVG rendering when the app fetches or inlines an uploaded/remote SVG and its `<script>`/`onload` runs. The objective is to determine whether an attacker-controlled spec field or SVG executes script in the application origin.

## 2. Detection Checklist
### A. Renderer identification
- Identify the Swagger UI version and whether the rendered spec is attacker-influenced (public, per-tenant, or user-supplied spec URL).
- Determine how SVG reaches the DOM: inline (`innerHTML`, `dangerouslySetInnerHTML`, `<object data>`), or served same-origin and navigated to.

### B. Attacker-controlled content
- Swagger: which spec fields flow into HTML without sanitization (`description`, `title`, `externalDocs.url`, `termsOfService`, parameter `name`/`example`); note that `$ref` can point at a remote URL, so a spec can pull in attacker-hosted content.
- SVG: can the attacker set SVG content (upload/remote/template), and is it served `image/svg+xml` without forced download?
- Rendering context matters: `<object>`/`<embed>`/`<iframe>`/direct navigation to a same-origin SVG execute its script, while `<img src=...svg>` does **not** (the SVG renders in a non-scripting context) — confirm the actual tag before claiming execution.
- Swagger UI versions to fingerprint from `package.json`/bundle: older `swagger-ui`/`swagger-ui-dist` releases with unsanitized markdown or DOM-based XSS (`<3.35.x` and the `4.x` markdown-sanitizer fixes) — record the exact version.

### C. Sink and execution conditions
- Locate the `innerHTML`/`dangerouslySetInnerHTML`/markdown-to-HTML sink and the `$ref` resolution.
- Confirm same-origin rendering with script privileges (not `Content-Disposition: attachment`, not a sandboxed origin, not blocked by CSP).

## 3. False-Positive Guardrails
- SVG served with `Content-Disposition: attachment` **and** `X-Content-Type-Options: nosniff`, or from a distinct sandboxed origin, does not execute — suppress and say why.
- A Swagger UI version that sanitizes markdown or sandboxes the spec is not vulnerable; confirm the version and the field's handling.
- A spec rendered only by the attacker's own session (self-served spec) is not a finding; the spec must be host-trusted or other-user-visible.
- An origin CSP without inline script kills the execution — check before claiming.
- Boundary: this class is the client-render XSS only; the upload gate, extension allow-list, and server-side execution belong to `file-upload-audit`, and ordinary server-reflected/stored XSS to `offsec-injection-agent`.

## 4. Remediation Guidance
- Sanitize/escape all spec fields before rendering; disable unsafe markdown or run the spec viewer in a sandboxed origin.
- Do not serve user SVGs same-origin as inline content; force download or serve from a sandboxed, script-disabled domain.
- Add `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff` and a restrictive CSP on any content origin.
