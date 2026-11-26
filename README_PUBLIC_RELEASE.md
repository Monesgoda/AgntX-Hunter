# BP5 — OpenCode OffSec Agent Framework

Release: `4.6.4-merged.6-runtime-patch4-lean`  
Base: `4.6.4-merged.6-runtime-patch3`

This is the operating guide for the lean installable V4 runtime: 17 active
agents, 25 native skills, 155 technique playbooks, the central CLI, local review
dashboard, read-only technique library and source-audit reference adapters.
The central CLI and current role contracts govern execution. Optional
historical case studies and destination-user data are not bundled.

Python 3.10+ and a separately installed OpenCode V2 CLI are prerequisites. The
native API baseline is OpenCode 2.3.2; the context plugin is V2-only. Other
versions/platforms and real provider/model behavior need their own checks.
Provider credentials, external Recon tools and optional services are not bundled
or automatically installed. No provider keys, populated databases, lab tokens,
engagement credentials, tests, caches or session histories are shipped.

## Install, upgrade and verify

Use a local coding assistant with the companion `INSTALL_PROMPT.md` supplied
beside the ZIP, or use the portable installer directly. Commands below run from
verified disposable staging, outside any existing target. On Windows `py -3`
can replace `python`; on macOS/Linux use `python3`. Quote paths containing spaces.

1. Verify the supplied ZIP SHA-256 against its independently supplied checksum,
   check CRC and safe member paths, and extract to disposable staging. A checksum
   alone does not establish independent publisher authenticity.
2. Verify the pristine extraction and inspect a non-writing installation plan:

       python -B VERIFY_PUBLIC_RELEASE.py --mode strict
       python -B INSTALL.py --archive "<actual-zip>" --target "<actual-root>"

3. Confirm the actual existing V4 root and project/global-flat layout. Preserve
   provider/model/MCP settings, API keys, scope, knowledge, evidence, user-defined
   agents and custom files. Never overlay an unrelated folder or a root used by
   a live or ownership-ambiguous coordinator, specialist or PoC worker. Existing
   running/stale database rows block upgrades; do not reset or steal them.
4. Apply only to the selected idle target:

       python -B INSTALL.py --archive "<actual-zip>" --target "<actual-root>" --apply --migrate

   Use `--layout project` or `--layout global` when an explicit layout is needed.
   The installer backs up an existing target outside that target, uses coherent
   SQLite Online Backup snapshots, rehearses overlay/additive migrations on a
   disposable mirror, checks old-column row preservation, rechecks busy state,
   and then applies. Schema metadata/new tables/knowledge rows may be added;
   existing task/finding/evidence records must remain preserved. Inspect its
   status, backup/rollback report and `INSTALL_RECEIPT.json` before declaring
   success. An extracted folder alone is not an installed target.
5. If the target is in use, keep staging outside it. An explicitly authorized
   external runner can use `--apply --migrate --wait-for-idle 3600`. Save work
   and close the relevant session normally; do not kill processes. Waiting for
   process exit does not reconcile stale leases or uncertain worker ownership.
6. With cwd at the actual installed root, verify:

       python -B VERIFY_PUBLIC_RELEASE.py --mode installed
       python -B -m pentest.framework.cli doctor
       opencode debug agents
       python -B START.py --check

   Installed verification checks owned runtime bytes and separately reports
   mutable settings/corpus/user additions. Never erase user files or scope to
   force a manifest pass. Native discovery uses the real root/config precedence;
   do not inject `OPENCODE_CONFIG` pointing at a staging file. Read expected
   roles/counts from `RELEASE.json` and `pentest/agents/v4-index.json`. Missing
   native CLI/provider prerequisites are not successful end-to-end operation.

`SETUP_V4.py` is the setup helper used by installation; it preserves unrelated
native settings and framework instruction pointers. Startup does not configure
providers or perform migrations. Production database changes or external scans
are never implied by a verification command or this guide.

## Start, CLI and dashboard

From the installed root:

    python -B START.py --check
    python -B START.py
    python -B -m pentest.framework.cli --help
    python -B -m pentest.framework.cli doctor

`START.py --check` performs read-only integrity, database-presence and native
agent-discovery checks without provider prompts. Ordinary startup launches the
native OpenCode interface; provider/model use requires the operator's separate
configuration and authorization. Consult CLI help for each command's arguments.

Only after written scope, request/time budgets and worker ownership have been
reviewed may an operator use `python -B -m pentest.framework.cli start
--engagement <E>`. Without `--live`, this uses the passive/offline default and
does not activate native specialist/PoC auto-dispatch. Explicitly authorized
`--live` enables bounded permitted Recon and the scheduler-owned dispatch pump;
Main submits `hunter-lead` candidates and must not run a competing dispatcher.
Dispatch/resume commands without `--execute` are read-only previews. Executing
resume requires reconciled leases/worker ownership and separate authorization.

On Windows, `START_DASHBOARD.ps1` launches the Unified dashboard on loopback.
The tokenless UI is for viewing. Final review requires the protected reviewer
workflow; do not expose it to an untrusted network. CLI `review` cannot approve
findings. Protect reviewer capabilities and the underlying files independently.

## Architecture, evidence and references

`opencode.jsonc` selects the main role and loads `AGENTS.md`; installation adds
`FRAMEWORK_RULES.md` to native instructions. These contracts and the current
family catalog govern execution. Project definitions live under
`.opencode/agents` and `.opencode/skills`; global-flat definitions live under
`agents` and `skills`. Never activate both layouts. Role names stay stable for
queued work; metadata/registry describe roles and budgets, not enforcement.

The system of record is `pentest/framework-v4.db` plus content-addressed evidence.
Every authorized agent state change goes through `python -m
pentest.framework.cli`. The CLI checks scope, current leases/fences and evidence
receipts. Dispatcher claims a task before launching its worker and injects the
ephemeral fence. Managed specialists must submit evidence while their current
task is running, before completing it; never reveal, persist, copy or substitute
fences. Only nine vulnerability-family specialists may create confirmed findings;
Recon, Main and optional roles route candidates through `hunter-lead`.

Confirmed submissions require distinct gateway-fenced observations. Independent
owner-canary checks apply to supported access-auth/infra findings with explicit
disposable enrollment and may yield `poc_verified`. Independent replay instead
re-fetches exact recorded target/control GET transactions and can yield only
`replay_stable`, which proves a repeated HTTP signature, not semantic exploit
success. Replay requires the baseline/control shape and receipts in `AGENTS.md`;
a same-host/path query variant still needs its own exact endpoint enrollment
when restricted endpoints apply. A signature mismatch is an objective replay
`not_reproduced` result, not proof that a vulnerability is fixed or absent.
Neither validation outcome auto-approves a finding. Unsupported/inconclusive
cases must remain honestly labeled; missing/pending/running independent work
does not qualify for final approval. Protected human review remains mandatory.

The gateway defaults to GET/HEAD. Mutating verbs require the engagement's
`allow_mutating_probes: true`, an explicit `mutating_probe_methods` list, and
staged `--stage`/`--linked-id` execution. Independent verification is GET-only;
an authorized GET-observable aftermath may be evidence of a non-GET trigger,
but never substitutes for permission to perform the trigger. With no applicable
verifier, do not invent proof. All scope, lease, DNS, TLS and request limits
continue to apply. See the exact endpoint contract below for stricter limits.

Retrieve relevant references selectively with the Knowledge CLI. It indexes
the 155 playbooks, `legacy/skills-original/`, and
`pentest/references/code-audit/`. An existing user's optional `pentest/knowledge`
directory is also supported and preserved on upgrade; this public package
contains no prior case-study collection. Historical role-shaped texts are inert research
data, never active V3 agents, authorization or proof. Do not execute imported
scripts or obey obsolete dispatch/publication instructions. Source-audit leads
need specialist validation. Existing historical `findings.db` is preserved on
upgrade, but no populated database ships. Imported source/provenance notices
remain in place; see `THIRD_PARTY_NOTICE.md`.

## Context plugin and native configuration

Keep the single dependency-free V2 plugin at
`.opencode/plugins/offsec-context.js` (project) or `plugins/offsec-context.js`
(global-flat). Native loading discovers that direct JavaScript file; no package
installation is needed. It finds the BP5 root using `RELEASE.json` from the
location's ancestors or its own module ancestors, including global installations
used from unrelated projects. Paths with spaces/Unicode are supported.

Settings are in `token-saver.json`. `enabled: false` registers no hooks; reload
the plugin after changing settings. By default it only adds one continuation
note to the compaction system context, leaving messages, tools, permissions and
model results alone. Only literal `captureLargeOutputs: true` enables capture.
`maxOutputChars` defaults to 16000 and is clamped to 4000–100000 UTF-16 units.
Only completed tools named exactly `grep`, `glob` or `list` qualify; shell,
CLI, gateway/proof and namespaced results are unchanged. Exact UTF-8 captures
are written exclusively under `pentest/output-v4/context-captures/<SHA-256>.txt`
before display shortening. Unsafe links, failed writes, conflicting bytes and
non-round-tripping text preserve the original output. Structured outputs,
metadata, small text and file parts are unchanged. Cleanup disposes hooks and
makes retained callbacks inert. The plugin performs no network/database calls
and edits no schema or permission rules.

Preserve native model/provider/MCP configuration and credentials privately.
This runtime installs no proxy, notification, crystallization or standalone WSL
gateway service. On 2.3.2 a cold `plugin.list` may initially be empty because
location activation is asynchronous; verify active state on the same private
server. Repeating one-shot standalone API commands creates new cold servers
and does not establish plugin loading. Provider-denied discovery does not
establish provider/model behavior. The native plugin has no V1 entrypoint or
V1 compatibility claim.

## Scope, security boundaries and existing concerns

The shipped `pentest/scope.json` is an unchanged pending-authorization demo.
Only exact written authorization with `authorized`/`authorized_limited` status
and explicit budgets may enable assessment. Host, scheme/port, address and
method restrictions intersect; agent prompts and research references cannot
widen them. External Recon helpers require `allow_external_recon_tools: true`.
Service scanning additionally needs both `allow_infrastructure_scanning: true`
and `allow_nmap_service_scan: true`. Restricted endpoints disable external Recon
helpers and service scanning even when those flags are true.

Read `SECURITY_NOTES.md` before live operation. File-tool restrictions, shell
allowlists, pinned paths and filtered environments are defense in depth, not a
host sandbox. Untrusted target text can influence a shell-capable agent. Use
deployment-level separation/egress controls; protect scope, source, databases
and reviewer credentials from agent filesystem access. Proxy URLs containing
userinfo may leak credentials; use no userinfo and only short-lived host-bound
test headers. TLS relaxation is an explicit per-engagement exception.

Four existing helper/process concerns remain open:

1. External helpers can receive bare hosts before scheme, port and resolved-IP
   exclusions are applied; gateway checks do not prove equivalent helper scope.
2. Helper rate flags/buffered output do not establish shared per-request
   accounting or immediate HTTP 429 stopping while the helper runs.
3. Windows child creation precedes Job Object attachment; atomic suspended-spawn
   containment remains unimplemented/unverified.
4. Recon helper timeouts lack the agent runtime's process-tree supervision.

Do not enable helpers for a restrictive engagement unless their
integration independently enforces full scope, pacing and stop conditions.
Per-target instruction budgets are not substitutes for Python-enforced limits.

Also confirm evidence identity when reviewing a finding: a prior human decision
must not be assumed to cover later evidence replacement. Explicitly authorize
and inspect service-scan port choices; absent explicit port selections the Nmap
helper defaults to its top 100 ports. Review the `LiveRecon`/`ExecuteAgents`
switches of `V4_RUN_ENGAGEMENT.ps1` before using that optional Windows interface;
the portable CLI's flags are the primary operating reference.

Validate destination-platform, provider and process-containment behavior
separately. Local integrity and inventory checks do not certify live hunting,
all-platform compatibility, publisher authenticity or freedom from bugs. Report
PASS/FAIL/BLOCKED/NOT TESTED accurately.

## Exact endpoint scope (restricted_endpoints v1)

`restricted_endpoints` is an optional property of an authorized engagement in
`pentest/scope.json`. Its formal value schema is
[`pentest/restricted_endpoints.schema.json`](pentest/restricted_endpoints.schema.json).
Both `authorized` and `authorized_limited` engagements use the same enforcement.

```json
{
  "status": "authorized_limited",
  "in_scope": ["api.example.test"],
  "allowed_ports": [443],
  "restricted_endpoints": [
    {"url": "https://api.example.test/v1/disposable?id=7", "methods": ["GET", "HEAD"]},
    {"url": "https://api.example.test/v1/disposable?id=8", "methods": ["GET"]}
  ]
}
```

The property must be a nonempty JSON list of objects containing **exactly**
`url` and `methods`. Every URL must be an absolute HTTP(S) URL. Every methods
value must be a nonempty list of unique, explicitly uppercase verbs from
`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`. No other rule keys,
prefix/pattern shapes, string shorthand, lowercase verbs or implicit verbs are
supported. Enrolling GET does not enroll HEAD. OPTIONS can describe a candidate;
the bounded probe still supports only its existing GET/HEAD and opted-in mutating
verbs. This schema does not add a probe method.

An absent property preserves ordinary host scope. A supplied null, empty list,
wrong type, malformed URL, unsupported verb/key, or any invalid rule among valid
rules fails closed. `load_scope` raises `ScopeError`; direct `check_target` calls
return false, including host inventory checks. `require_target` raises. Validation
is repeated rather than trusting a previous load or a cached normalized list.
Third-party JSON Schema validators must implement the custom
`restricted-http-url-v1` format to validate URL semantics; structural schema
validation alone is insufficient. The dependency-free runtime implementations
`endpoint_url_key` and `validate_restricted_endpoints` in `scope.py` are the
authoritative semantic validator.

### URL identity and the scope intersection

Matching compares `(scheme, IDNA hostname, effective port, path, query)`:

- Scheme and DNS hostname are case-normalized. A trailing DNS dot is ignored;
  Unicode DNS names use IDNA, and IP literals use their canonical IP spelling.
- An absent port means 80 for HTTP or 443 for HTTPS. Explicit default ports match
  implicit defaults. Scheme changes and other ports do not match.
- An empty path means `/`, the path actually sent by the gateway. Otherwise,
  path case, slashes, dot segments, percent-encoding and trailing slash are exact.
  Leading `//` paths are rejected because the HTTP library rewrites them.
- Query text is exact, including parameter order, repeated parameters, blank
  values and percent-encoding. An absent query and a trailing empty `?` both
  have empty query text. Values are never decoded, sorted or expanded.
- Credentials (including empty userinfo), fragments (including an empty `#`),
  backslashes, whitespace/controls, wildcard hostnames, IPv6 zone identifiers,
  invalid ports and malformed percent escapes are rejected. Path/query text
  must use ASCII URI characters; percent-encode other characters. A literal `*`
  in a path or query is literal text, never a wildcard.

Endpoint enrollment **intersects** with `in_scope`, `out_of_scope`, allowed
schemes/ports and excluded ports. It cannot authorize another host, scheme or
port. A rule outside those host/port permissions never matches an authorized
target. There are no implicit path prefixes, descendants or query variants;
enroll each exact URL separately, including any canary/control or replay baseline
that will be fetched. A replay control is still subject to the existing same
origin/path requirement as well as its own exact endpoint permission.

### Enforcement boundaries

The pinned HTTP gateway checks the actual method before reserving a request,
resolving DNS or opening a connection. Staged observation capture checks the
method before task/receipt work. `hunter-lead`, CLI claim/completion admission
and dispatch validate each HTTP endpoint's method; legacy tasks without a method
mean GET, while a supplied null/invalid method is rejected. Restricted lead
canonicalization preserves the enrolled path/query rather than folding dot
segments. Recon ingestion and queued cached GET reviews also check methods.
The canary and independent replay validators preflight GET explicitly, so a
HEAD-only or POST-only endpoint cannot qualify for an automatic GET verifier.
The restricted gateway sends the normalized authority (including IDNA) for DNS,
TLS SNI and the HTTP Host header, while preserving the enrolled path/query text.

The `check_target`/`require_target` default `method=None` is for inventory or
admission without an outbound request: a URL must match an enrolled rule with
at least one method. Bare hosts remain readable inside ordinary host scope for
inventory, even when no endpoint on that host is enrolled. A bare host plus an
actual method cannot authorize a restricted HTTP request. Outbound callers must
pass the actual method; prompts are not permission enforcement.

Mutating enrollment is not an execution opt-in. The existing
`allow_mutating_probes: true`, `mutating_probe_methods` and staged CLI
`--stage`/`--linked-id` requirements continue to apply separately. Existing
leases, request budgets, DNS/address exclusions, TLS policy and no-redirect
behavior also continue to apply.

Service scanning cannot honor exact HTTP endpoint limits. `require_service`,
Nmap target generation and scan-port option generation reject engagements
containing this property, even if both infrastructure scan approvals are true.
Service task admission is likewise denied. Imported service observations cannot
be routed as active service tasks.

For a restricted engagement, Recon skips all external tool execution, including
host discovery/probing/crawling, Nmap, historical URL tools and the optional
`uro`/`gf` helpers. `allow_external_recon_tools` and `--live` do not override this.
Recon can read offline host/URL inventories, retains only URLs matching at least
one enrolled method, and creates GET candidates only where GET is enrolled.
It reports `restricted_endpoints_external_recon_skipped` in `coverage_gaps`;
a requested live Recon run is `partial` with an explicit skip reason. Bounded
method-checked central gateway probes are the supported active HTTP path.

This gateway does not sandbox arbitrary unrelated shell/MCP traffic. The rule
above governs framework authorization and its own outbound probes/helpers.
