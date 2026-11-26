---
name: supply-chain-deps
description: Audits dependency and supply-chain posture for vulnerable or typosquatted packages, unpinned versions, and insecure artifact provenance.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Supply-Chain & Dependencies Audit Procedure

## 1. Audit Scope & Objective
Review lockfiles, manifests, and build provenance to find known-vulnerable dependencies, typosquatting/lookalike packages, unpinned or floating versions, and unsigned/unverified artifacts. The objective is to determine whether an attacker can introduce or exploit a dependency to compromise the build or product.

## 2. Detection Checklist
### A. Vulnerable and unpinned dependencies
- Known-CVE packages from lockfile against advisory data (OSV / `npm audit` / `pip-audit`) — name the advisory ID and version range; direct vs. transitive.
- Floating ranges (`^`, `*`, `latest`), missing lockfile, or lockfile not enforced in CI.
- Verify the lockfile records `integrity`/`resolved` hashes and that installs run with `--frozen-lockfile`/`npm ci`; a lockfile without integrity hashes can be silently swapped at fetch time.

### B. Namespace and typosquatting
- Lookalike package names, dependency-confusion (internal name resolving to a public registry), scoped-name confusion — confirm the registry scope (`.npmrc`/`pip.conf`) is set so private names cannot resolve publicly.
- Post-install scripts running arbitrary code.

### C. Provenance and integrity
- Unsigned artifacts/images, missing SBOM, images pulled by mutable tag, no digest pinning.
- Registry with weak auth or public push.

## 3. False-Positive Guardrails
- A CVE in a dependency that is not reachable/exploitable in this application's usage is lower severity — state reachability.
- A dev-only dependency with no build/runtime exposure is not automatically a finding.
- A "newer version exists" is not a vulnerability; a demonstrated vulnerable/typosquatted package is.
- Boundary: CI secret/execution posture is `cicd-misconfig`; image/container runtime config is `container-orchestration`; dependency content itself is this class.

## 4. Remediation Guidance
- Pin exact versions with a committed lockfile and enforce it in CI; enable automated dependency updates with review.
- Use scoped/verified registries and code signing (Sigstore/cosign); pin images by digest and generate an SBOM.
- Disable untrusted post-install scripts where feasible; monitor for dependency-confusion.
