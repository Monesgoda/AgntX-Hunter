---
name: prototype-pollution
description: Audits client-side code for Prototype Pollution, where untrusted input merged into Object.prototype influences a gadget that reaches a dangerous sink.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Prototype Pollution Audit Procedure

## 1. Audit Scope & Objective
Review client-side JavaScript to find recursive merge/extend/clone functions that copy untrusted input (URL fragment, `postMessage` body, remote JSON, storage) into an object without filtering `__proto__`, `constructor`, or `prototype`, and to find a downstream gadget that reads the resulting polluted property and reaches a sink. The objective is to determine whether an attacker can influence an in-page gadget through prototype pollution.

## 2. Detection Checklist
### A. Client-side merge sinks
- Search for `deepMerge(`, `merge(`, `extend(`, `Object.assign` inside a loop, `$.extend(true, ...)`, and any recursive key-copy routine. Named library sinks: `lodash.merge` / `_.set`, `jQuery.extend(true, ...)`, `deepmerge`, `hoek.applyToDefaults`, AngularJS `merge`.
- Confirm whether `__proto__`, `constructor`, **and** `constructor.prototype` keys are filtered (the last reaches the prototype via `obj.constructor.prototype`), and whether the target is `Object.create(null)`.
- Check `JSON.parse` reviver functions and path-based setters (`set(obj, path, value)`) that honor a `__proto__`/`constructor.prototype` segment in the path.

### B. Attacker-controlled sources
- Confirm the merge input is attacker-influenced: URL hash/query parsed client-side, a `postMessage` payload, remote JSON config, or `localStorage`/`window.name`.

### C. Gadget reaching a sink
- Look for code reading a property that, when polluted, flows into `innerHTML`, `script.src`, `fetch(cfg.url)`, a navigation, a truthiness branch, or a sanitizer configuration object.

## 3. False-Positive Guardrails
- `Object.assign({}, userInput)` does **not** pollute `Object.prototype` — it copies own enumerable properties only; a `__proto__` key there does not reach the prototype chain. Suppress and say why.
- A merge of two trusted static objects, or a source that is not attacker-controllable, is not a finding.
- Pollution that never reaches a gadget is informational, not high severity.
- `Object.create(null)` targets, a frozen `Object.prototype`, or strict key sanitation neutralizes the primitive — suppress.
- Boundary: client-side gadget pollution is this class; a `__proto__` body reaching a server-side merge belongs to `offsec-business-logic-agent`.

## 4. Remediation Guidance
- Reject or strip `__proto__`/`constructor`/`prototype` keys before merging untrusted data.
- Merge into `Object.create(null)` or use `Map` for user-keyed data.
- `Object.freeze(Object.prototype)` at bootstrap as defense-in-depth; avoid trusting inherited properties in gadgets.
