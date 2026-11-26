---
name: file-upload-audit
description: Audits file upload endpoints for unrestricted extensions, MIME-type spoofing, path traversal during storage, and executable file handling.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# File Upload Security Audit Procedure

## 1. Audit Scope & Objective
Ensure server-side file upload workflows enforce strict file validation, isolate stored files from executable web roots, and prevent path manipulation or storage exhaustion.

## 2. Detection Checklist
1. File Extension Validation:
   - Verify whether file extensions are checked against an explicit **whitelist** rather than a blacklist.
   - Inspect extension extraction logic for bypasses: double extensions (e.g., `.php.jpg`), trailing dots/spaces, null byte injection (`%00`), or case variations.
2. File Content & MIME-Type Verification:
   - Check if validation relies solely on client-supplied `Content-Type` headers or file extensions.
   - Ensure the server validates file headers / magic bytes (e.g., using `libmagic` or equivalent binary signature parsers).
   - Test polyglots that satisfy an image signature but carry HTML/SVG script (GIFAR, JPEG+HTML, `image/svg+xml` served inline); server-side image re-encoding (e.g. GIF→PNG) strips embedded payloads and is a mitigating control to look for.
   - `Content-Disposition: inline` (or a missing header) on a user-supplied HTML/SVG file means the browser renders it — check the disposition, not just the content type.
3. Storage Location & Path Traversal:
   - Inspect the file saving routine: verify that the target filename is randomized (e.g., UUIDv4) or sanitized.
   - Check for path traversal risks if the user-supplied filename is concatenated into the storage path (`../`).
   - Verify that the storage directory has execution permissions disabled (e.g., `AllowOverride None`, no script execution engine mounted on the upload directory).
   - Confirm user content is served from a **separate**, cookie-free, script-disabled domain rather than the application origin (a same-origin upload origin enables stored XSS/SVG execution).
4. Compressed File Handling (Zip Slip):
   - If archive files (ZIP, TAR) are decompressed, check whether extraction logic verifies that canonicalized destination paths remain strictly within the target extract directory.
   - **Boundary (mutual cross-reference):** this skill owns only the **upload gate** — whether the archive is accepted at all (extension allow-list, MIME/magic-byte validation, size limits). The **extraction/unpacking traversal logic** itself is owned by `path-file/zip-slip/SKILL.md`. A `.zip` upload path is assessed in both; do not duplicate the traversal analysis here.

## 3. False-Positive Guardrails
- Files stored in external object storage (e.g., AWS S3, Google Cloud Storage, Azure Blob Storage) with auto-generated random keys do not execute on the web server; focus solely on access permissions and bucket misconfigurations.
- Client-side validation in HTML/JS is not a vulnerability itself, provided server-side validation is strictly enforced.

## 4. Remediation Guidance
- Rename uploaded files to a randomly generated identifier (e.g., UUID) and store the original filename only as metadata in the database.
- Store uploaded assets outside the web document root or serve them exclusively through a dedicated static domain or CDN without script execution permissions.
- Validate file signatures (magic bytes) server-side and enforce an allowlist of accepted formats.