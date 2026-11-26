---
name: lfi-rfi
description: Audits file inclusion sinks for Local and Remote File Inclusion allowing source disclosure, code execution, or inclusion of attacker-controlled content.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# LFI / RFI Audit Procedure

## 1. Audit Scope & Objective
Review code where a user-controlled value selects an included/required file (PHP `include`/`require`, template engines, plugin loaders, `import()`), to determine whether an attacker can include local sensitive files (LFI) or remote attacker-hosted code (RFI), or chain to code execution (log poisoning, wrapper abuse). The objective is to determine whether inclusion can be steered to attacker-chosen content.

## 2. Detection Checklist
### A. Inclusion sinks
- Find dynamic includes: `include($_GET...)`, `require $x`, template `render(user)`, dynamic `import(userPath)`, `spl_autoload` with user path.

### B. LFI confirmation and wrappers
- Traverse to known files (`/etc/passwd`, `win.ini`, app config, `.env`); on PHP test `php://filter/convert.base64-encode/resource=`, `php://input`, `data://`, `expect://`, and `/proc/self/environ` / access-log poisoning.
- For `php://filter`, chain multiple filters to defeat a naive word filter (e.g. `convert.iconv.../convert.base64-encode/resource=`) — the chain also gives source disclosure without code execution.

### C. RFI and reachability
- Check `allow_url_include`/`allow_url_fopen` (PHP) or equivalent; test inclusion of an attacker-hosted URL (only if the OOB host is authorized).

## 3. False-Positive Guardrails
- An include of a value constrained to a hardcoded allow-list/map is not LFI/RFI.
- A disclosed error that merely names a missing include is not inclusion — you must include content you control or read a file you should not.
- RFI requires the runtime to allow remote includes; absent that, RFI is not demonstrated.
- Boundary: reading arbitrary files via a path join is `path-file/path-traversal`; inclusion-driven execution is this class; templating injection is `offsec-injection-agent` (SSTI).

## 4. Remediation Guidance
- Never let user input select an included file; use a static map from key to file.
- Disable `allow_url_include`/`allow_url_fopen`; restrict include paths to a non-user-writable directory.
- Apply the same canonical-path confinement as path traversal; disable risky PHP wrappers.
