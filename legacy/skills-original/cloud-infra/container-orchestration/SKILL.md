---
name: container-orchestration
description: Audits Kubernetes and Docker deployments for privileged containers, exposed dashboards/APIs, unsafe pod security contexts, and in-cluster secret exposure.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Container & Orchestration Audit Procedure

## 1. Audit Scope & Objective
Review manifests, Helm values, Dockerfiles, and rendered cluster configuration to find privileged/root containers, mounted host paths, exposed Kubernetes API/dashboard/kubelet, weak RBAC, and plaintext secrets. The objective is to determine whether a workload or exposed control plane can lead to cluster or host compromise.

## 2. Detection Checklist
### A. Workload security context
- `privileged: true`, `allowPrivilegeEscalation: true`, `runAsUser: 0`, `hostNetwork`/`hostPID`/`hostPath`, dangerous capabilities (`SYS_ADMIN`).
- Docker: `--privileged`, `/var/run/docker.sock` mounts.

### B. Exposed control plane
- Anonymous/unauthenticated kubelet (`:10250`), Kubernetes API `--anonymous-auth=true`, exposed dashboard, `system:anonymous` RBAC bindings.

### C. Secrets and RBAC
- Secrets in plaintext in manifests/ConfigMaps, `etcd` unencrypted, over-broad ClusterRoleBindings, service-account token automation.
- Service-account token automount: `automountServiceAccountToken` defaulting to `true` hands every pod an API credential — check the mounted SA's RBAC and whether it is needed.
- Admission-controller bypass: namespaces or workload types excluded from the policy engine (OPA/Kyverno/Pod Security), or a privileged escape via an allowed mutating webhook — confirm the policy actually covers the workload.
- `securityContext` inheritance: a container-level context that overrides (or fails to inherit) the pod-level one, and default SA/namespace settings that silently grant more than the manifest shows.

## 3. False-Positive Guardrails
- A privileged container on a single-tenant, isolated node may be acceptable by design — note the isolation before escalating.
- An exposed API endpoint that still enforces authentication is not a finding.
- A `hostPath` to a read-only, non-sensitive path is lower risk than `/` or a socket mount.
- Boundary: image/dependency risk is `supply-chain-deps`; the orchestration config posture is this class.

## 4. Remediation Guidance
- Enforce Pod Security Standards (restricted), drop capabilities, run non-root, and disallow `hostPath`/privileged by policy (OPA/Kyverno).
- Disable anonymous API/kubelet auth; restrict the dashboard; tighten RBAC to least privilege.
- Use a secrets manager / encrypted secrets; encrypt etcd at rest.
