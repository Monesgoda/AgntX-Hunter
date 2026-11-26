# Operator security notes

Read this before enabling an authorized live engagement. These controls limit
framework operations; they do not provide a complete host sandbox.

## Scope, evidence and state changes

Only written authorization registered in `pentest/scope.json` can enable active
assessment. The supplied example remains pending and grants no permission.
Every permitted request must satisfy host, address, scheme, port, endpoint,
method, lease and budget checks. Prompts, imported references and model output
cannot grant authority. Exact endpoint restrictions and mutating-method opt-ins
are described in `README_PUBLIC_RELEASE.md`.

All legitimate agent state changes go through `python -m pentest.framework.cli`.
The gateway applies scope registration, lease fencing, pacing and evidence
checks. Managed workers receive an ephemeral claim fence for their current
attempt; never display, persist, copy, substitute or override that credential.
Submit observations/evidence before completing the task. A successful process
exit or model assertion does not establish independent verification.

Owned-canary validation is limited to eligible access-auth/infra findings with
explicitly enrolled disposable owner-controlled resources and negative controls.
Only that supported profile may produce `poc_verified`. Independent replay
checks target/control HTTP signatures and may produce only `replay_stable`;
it does not establish semantic exploit success. A mismatch does not prove a
vulnerability is fixed or absent. Neither outcome auto-approves a finding.
Missing/pending/running independent work is not a completed check. Protected
human review remains mandatory; confirm the actual evidence identity rather
than assuming an earlier decision covers later evidence replacement.

## Shell and filesystem boundary

Active agent definitions disable dedicated write/edit tools. This does not
prevent a shell-capable process from reading or modifying accessible files.
The ordered rules in `opencode.jsonc` ask about generic shell commands, allow
the central Python gateway spellings, and deny selected direct database/network
commands. Last matching rule wins. Alternative interpreters, quoting or command
forms can bypass string-based rules. Treat this as defense in depth only.

Untrusted target responses, documents and retrieved references can contain
prompt injections. An agent that reads them and has shell access may still be
manipulated into unwanted local actions. Gateway controls cover actions made
through that gateway; they do not protect files from a process that can modify
them directly and do not sandbox unrelated shell or MCP traffic.

Run agents as a separate least-privileged OS user or inside an appropriately
restricted container. Protect the framework database, scope, source and reviewer
capability from agent filesystem access, and restrict egress to approved paths.
That separation is a destination deployment responsibility, not a guarantee of
agent frontmatter or static syntax checks.

## Environments, proxies, headers and TLS

Agent subprocess environments are filtered to runtime/locale variables,
supported provider credentials and framework/native variables. If a deployment
needs another variable, the owning operator can add its exact name to the
engagement's `extra_passthrough_env`. This is an explicit per-engagement
extension: only present variables are forwarded; wildcard/prefix grants are
not implied. Framework/native prefix handling still applies independently.
Recon helpers receive a smaller environment and a temporary empty home.

Proxy environment variables are forwarded where needed by the native provider
runtime. A proxy URL containing userinfo passes that credential to subprocesses
and may expose it in transcripts or artifacts. Use no userinfo in proxy URLs;
prefer network-position authentication or a separate credential mechanism.
Treat an exposed userinfo credential as compromised and never copy it into a
finding, report or proof artifact.

`probe_headers` requires `probe_headers_hosts`. Headers are sent only to a
matching authorized host; pinned Host/framing/connection headers are refused.
Scope files are plaintext and readable by agents, so use only short-lived
disposable test tokens, never customer/production credentials. `allowed_ports`
accepts an explicit list, not the string `"any"`. TLS verification is enabled
by default; `probe_tls_verify: false` is an explicit per-engagement exception.
Requests do not follow redirects into a new permission boundary.

## Pinned paths and recovery

Managed dispatcher/hunter subprocesses receive pinned database, scope and output
paths. The CLI ignores overriding path arguments while pinned, and unstaged
commands still require the registered scope hash. This is defense in depth:
unsetting variables or using a different interpreter can bypass process-level
conventions. OS/container separation remains the stronger boundary.

Dead coordinator recovery requires both a dead worker PID and a heartbeat older
than the stale window (180 seconds). A live PID or fresh heartbeat cannot be
recovered from heartbeat age alone. Resume without execution remains read-only.
Reconcile surviving or ownership-ambiguous workers before starting another
coordinator; an expired lease is never permission to steal running work. Do not
run overlapping dispatchers. Parent-death behavior depends on the destination
platform's process-tree handling and must be checked there.

## External helper and process limits

Four integration concerns require destination controls:

1. External Recon helpers can receive a bare host before scheme, port and
   resolved-IP exclusions are applied. Gateway pre-request checks do not prove
   equivalent enforcement inside a separate helper.
2. Helper rate flags and buffered output do not establish shared per-request
   accounting or immediate stopping on a target's HTTP 429 while the helper runs.
3. Windows process creation precedes Job Object attachment. Atomic
   suspended-spawn containment is not supplied by that sequence.
4. Recon helper timeouts lack the agent runtime's process-tree supervision.

Do not enable external helpers for a restrictive engagement unless their
integration independently enforces complete scope, pacing and stop conditions.
They require the engagement's explicit helper permission; service scanning
additionally requires both infrastructure and Nmap approvals. Exact endpoint
restrictions disable external Recon helpers and service scanning entirely.
For service scans, explicitly authorize and inspect port selection: absent
explicit selections, the Nmap helper uses its top 100 ports. Inspect the
`LiveRecon`/`ExecuteAgents` switches before using `V4_RUN_ENGAGEMENT.ps1`.

## Local dashboard, data and distribution

Keep the dashboard on loopback. Tokenless access is for viewing; final review
requires the separate reviewer capability, explicit confirmation and protected
review endpoint. The ordinary CLI cannot approve findings. Protect both tokens
and underlying storage from untrusted processes.

The public package includes generic configuration and a non-authorizing scope
example. It includes no provider credentials, prior case-study collection,
populated databases, captures or session histories. Installation must preserve
each recipient's existing provider/model/MCP settings, scopes, evidence,
knowledge and custom files. Do not collect credentials during installation or
start provider prompts, external scans or an assessment as an installation test.

Technique libraries are inert, untrusted research references, not permission to
run their examples. Preserve applicable source attribution and notices. Read
`THIRD_PARTY_NOTICE.md` before redistribution: inclusion and checksums do not
establish ownership or licensing rights. Local checks do not certify live
hunting effectiveness, all-platform compatibility, absence of malware or bugs,
or independent publisher authenticity. Never disable OS security controls to
install this package.
