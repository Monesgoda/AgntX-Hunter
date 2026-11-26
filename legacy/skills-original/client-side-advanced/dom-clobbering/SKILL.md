---
name: dom-clobbering
description: Audits client-side code and DOM sinks for DOM Clobbering, where attacker-injected HTML id/name attributes shadow globals or object properties trusted by surrounding script.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# DOM Clobbering Audit Procedure

## 1. Audit Scope & Objective
Review client-side JavaScript, HTML templates, and captured DOM sinks to find code that dereferences an implicit global (`window.x` / `document.x`) or an object property that an attacker could shadow by injecting an element with a matching `id` or `name`. The objective is to determine whether injected markup can redirect a trusted reference into an attacker-controlled value that reaches a dangerous sink.

## 2. Detection Checklist
### A. Clobberable global dereferences
- Search for reads of implicit globals: `window.foo`, `document.foo`, a bare `foo` where `id="foo"` may exist, `document.getElementById(x)`, `x.src`, `x.href`, `form.action`, `x.innerHTML`.
- Flag code that treats `document.forms`/`elements` members as configuration.
- Check two-level lookups: `window.a.b` can be satisfied by `<a id=a><b id=b>` or by named form elements (`document.forms[0].x`, `form.elements.x`), where a single element alone would not.

### B. DOM injection points
- Find where attacker-controlled HTML can introduce `id`/`name` attributes: rich-text/markdown rendering, `innerHTML`, `document.write`, URL-fragment rendering, stored comments.
- Confirm whether the sanitizer preserves `id`/`name`.

### C. Clobber-to-sink chain
- Match a clobberable reference to an injection point whose clobbered value reaches `script.src`, `location`, `innerHTML`, `eval`, or `setAttribute('src')`.
- Record the exact element to inject and the sink reached.

## 3. False-Positive Guardrails
- Both a clobberable dereference **and** a reachable `id`/`name` injection point are required; one alone is informational, not a finding.
- A sanitizer (DOMPurify, Trusted Types) that strips `id`/`name` neutralizes the primitive — suppress and state why.
- A global that is explicitly reassigned by script before use, or read via a scoped variable, is not clobberable.
- Boundary: DOM-only clobber with no server round-trip is this class; server-reflected XSS belongs to `offsec-injection-agent/references/xss.md`.

## 4. Remediation Guidance
- Read elements explicitly with `document.getElementById`/`querySelector` instead of relying on named globals.
- Sanitize or strip `id`/`name` from user-supplied HTML before rendering.
- Freeze or re-declare trusted configuration objects in a scope that markup cannot shadow.
