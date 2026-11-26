---
name: subdomain-takeover
description: Audits DNS records and CNAME chains for dangling references to de-provisioned cloud resources that could allow an attacker to claim a subdomain.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Subdomain Takeover Audit Procedure

## 1. Audit Scope & Objective
Review DNS records (CNAME, A, MX, TXT), certificate transparency data, and service fingerprints to find a subdomain that points to a third-party resource which no longer exists or is unclaimed, allowing an attacker to register that resource and serve content under the target's name. The objective is to determine whether any in-scope hostname can be taken over by claiming an orphaned cloud resource.

## 2. Detection Checklist
### A. Dangling DNS records
- Identify CNAMEs/A records pointing at services with detectable "unclaimed" states: S3 website endpoints, GitHub Pages, Heroku, Azure `*.cloudapp.azure.com`, Netlify, Vercel, Shopify, Fastly, Zendesk.
- Extend beyond CNAME: **MX** (unclaimed mail provider), **NS** (delegated to a lapsed/retired name server), and **TXT** records that reference a de-provisioned service. A dangling NS delegation can hand over a whole zone subtree.
- Cross-check each CNAME target against the provider's "does not exist / unclaimed" fingerprint, following the chain to its final hop — the "unclaimed" signal is NXDOMAIN/edge-404 at the **end** of the chain, not the first record.

### B. Service fingerprints
- HTTP: provider default 404 pages ("NoSuchBucket", "There isn't a GitHub Pages site here", "No such app"), TLS cert CN/SAN mismatch, connection reset vs. app response.
- DNS: NXDOMAIN on the target host while the CNAME still resolves.

### C. Claimability confirmation
- Confirm whether the resource name is claimable (globally unique name still free) without actually claiming it — rely on the provider's not-existing response.
- Use certificate-transparency logs and passive DNS to discover hostnames that no longer resolve publicly but still exist in DNS — a common source of forgotten dangling records.

## 3. False-Positive Guardrails
- A CNAME to a live, correctly served third-party resource is not a takeover; the target must return the provider's "unclaimed/does not exist" signal.
- A wildcard DNS record that resolves but serves the app is not a dangling reference.
- Do not claim a takeover you did not verify is claimable from the provider's unclaimed response.
- Boundary: passive DNS/CT enumeration is `offsec-recon-agent/references/methodology.md`; the takeover assessment itself is this class.

## 4. Remediation Guidance
- Remove DNS records for de-provisioned resources before removing the resource; monitor for dangling CNAMEs.
- Prefer provider configurations that reserve the name (e.g. keep the S3 bucket) or use non-claimable targets.
- Add automated dangling-DNS detection to CI/monitoring.
