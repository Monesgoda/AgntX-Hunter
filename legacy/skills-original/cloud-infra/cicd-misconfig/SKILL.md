---
name: cicd-misconfig
description: Audits CI/CD pipelines and build configurations for secret exposure, untrusted-code execution, and over-permissive runner or deployment credentials.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# CI/CD Misconfiguration Audit Procedure

## 1. Audit Scope & Objective
Review pipeline definitions (GitHub Actions, GitLab CI, Jenkinsfile, CircleCI), build logs, and runner configuration to find secret leakage, execution of untrusted code (pull-request builds with secrets), and over-permissive deployment credentials. The objective is to determine whether an attacker with repository or pipeline influence can exfiltrate secrets or reach production.

## 2. Detection Checklist
### A. Secret handling
- Hardcoded secrets in workflow files, build logs, artifacts, or environment dumps.
- Secrets exposed to pull-request/ fork builds (`pull_request_target`, workflow from forks with secrets).
- Over-broad `GITHUB_TOKEN` permissions (default `write-all`).

### B. Untrusted-code execution
- Workflows that check out and run untrusted PR code with access to secrets or self-hosted runners.
- Script injection via `github.event.*` / PR title/branch names interpolated into `run:` steps.
- Self-hosted runners on public repos (persistence risk).
- `workflow_run` / `pull_request_target` chains that hand a privileged workflow the artifacts of an untrusted one (privilege chaining), including artifact poisoning where a low-trust job uploads an artifact a high-trust job later executes.

### C. Credential and deployment scope
- Deployment credentials (cloud keys, registry tokens) with broad/`*` scope.
- Long-lived static credentials vs. OIDC short-lived federation.
- OIDC trust-policy confusion: a cloud role trusting the CI provider with a subject condition that is too broad — e.g. `repo:org/*` or `pull_request` — so any repository (or any fork PR) can assume it. Verify the cloud trust policy pins the exact repo **and** the protected branch/environment.

## 3. False-Positive Guardrails
- A workflow that runs untrusted code but has **no** secrets or privileged token in scope is low risk — state the missing privilege.
- Secrets masked in logs are not leaked; verify they are unmasked and reachable before claiming.
- A public repo with no deploy secrets is not automatically high severity.
- Boundary: dependency/supply-chain risk is `supply-chain-deps`; pipeline secret/execution posture is this class.

## 4. Remediation Guidance
- Use OIDC federation with short-lived, least-privilege credentials; scope `GITHUB_TOKEN` to `contents: read`.
- Never expose secrets to fork/PR builds; require approval for `pull_request_target`.
- Pin actions to SHAs, avoid `${{ github.event.* }}` in `run:` shell interpolation, and isolate self-hosted runners.
