---
name: cloud-storage-misconfig
description: Audits S3, GCS, and Azure Blob storage configurations for public read/write access, unauthenticated listing, and over-permissive signed URL policies.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Cloud Storage Misconfiguration Audit Procedure

## 1. Audit Scope & Objective
Review bucket/blob configurations, access policies, and observable access behaviour to determine whether storage intended to be private is publicly listable, readable, or writable, and whether signed URLs or CORS grant excessive access. The objective is to determine whether an attacker can list, read, or modify objects without authorization.

## 2. Detection Checklist
### A. Public access posture
- S3: `s3:GetBucketAcl`, bucket policy `Principal: "*"`, Block Public Access settings, website endpoint enabled.
- GCS: `allUsers` / `allAuthenticatedUsers` IAM bindings, `storage.googleapis.com` listing.
- Azure: container access level (`Container`/`Blob`), SAS token scope/expiry.

### B. Listing and object access
- Attempt anonymous listing (`?list-type=2`, `?prefix=`) and known-key GETs; distinguish "list allowed" vs. "object readable" vs. "denied".
- Check for predictable keys (backups, `config`, `.env`, database dumps).

### C. Write and policy abuse
- Probe anonymous PUT/DELETE (carefully, only when in scope) and overly broad signed-URL CORS (`Access-Control-Allow-Origin: *` with credentials).
- Review IAM/ACL for write grants to unauthenticated principals.
- Confused deputy: a bucket policy granting a service `Principal` (e.g. a logging/monitoring account) without an `aws:SourceArn` / `aws:SourceAccount` condition lets any resource of that service read or write the bucket.
- Signed-URL scope and replay: check the URL's action, key/prefix, and expiry — an over-broad (`s3:*`, prefix-wide) or long-lived URL is a credential. Where object-level ACLs exist, confirm an object ACL cannot re-grant the public access Block Public Access was meant to stop.

## 3. False-Positive Guardrails
- A bucket that intentionally hosts public static assets (a public CDN origin) is not a finding unless it also allows listing or write.
- An object readable by design (public downloads) is not a leak; the finding is unintended exposure or listing/write.
- A single 403/404 on one key does not prove the bucket is private or public — test listing and a second key.
- Boundary: object-key path traversal or upload handling is `path-file/` or `file-upload-audit`; the storage access-control posture is this class.

## 4. Remediation Guidance
- Enable Block Public Access (S3) / uniform bucket-level access (GCS) / disable anonymous container access (Azure) by default.
- Never grant `allUsers`/`allAuthenticatedUsers` or `Principal:"*"` for sensitive data.
- Scope and shorten signed URLs; restrict CORS to trusted origins; monitor for public-access drift.
