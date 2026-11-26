---
name: postmessage
description: Audits cross-window messaging for missing or weak origin/source checks on message handlers and over-broad targetOrigin on senders.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# postMessage / Cross-Window Messaging Audit Procedure

## 1. Audit Scope & Objective
Review client-side JavaScript and captured frames/embeds to find `message` event handlers that act on `event.data` without validating `event.origin` (or `event.source`), and senders that broadcast with `targetOrigin: '*'` carrying sensitive data. The objective is to determine whether an attacker-controlled frame or opener can drive a privileged action or exfiltrate data through the messaging channel.

## 2. Detection Checklist
### A. Handler origin/source validation
- Enumerate every `addEventListener('message', ...)` / `.onmessage` handler.
- Classify each: no check; weak check (`includes`, prefix, unanchored regex); strict equality on the full origin.
- Inspect whether `event.source` is used as a reply target without verifying it is the expected frame; a reply to an unverified `event.source` hands data to the attacker's window.
- Cover the other cross-context channels too: `MessageChannel`/`MessagePort` and `BroadcastChannel` handlers receive messages with no origin binding at all, so the same data-to-sink and reply-target analysis applies (prove reachability separately).

### B. Data-to-sink flow
- Follow `event.data` into `innerHTML`, `eval`, `location = data.url`, `document.write`, DOM insertion, or a structured action (`{action:'navigate',url}`).

### C. Sender-side exposure and reachability
- Find outbound `postMessage(data, targetOrigin)`; flag `'*'` when `data` carries a token, user object, or URL.
- Confirm an attacker frame/opener is reachable: the app is framable, opens attacker-influenced popups, or `window.name` survives navigation.

## 3. False-Positive Guardrails
- A handler with a **strict** `event.origin === 'https://exact.origin'` equality check is not a finding.
- A handler that only logs or reads a non-security boolean is not a finding on its own.
- `targetOrigin: '*'` is acceptable when the message body is non-sensitive and public by design — suppress and say why.
- postMessage to a same-origin child the attacker cannot host is not exploitable — reachability must be shown.
- Boundary: the client message sink is this class; a server-reflected XSS reached via the message is `offsec-injection-agent`.

## 4. Remediation Guidance
- Validate `event.origin` against an exact allow-list and verify `event.source` before acting.
- Never pass `event.data` into a DOM/script sink without validation; treat messages as untrusted input.
- Set an explicit `targetOrigin` on every outbound `postMessage`; never use `'*'` for sensitive payloads.
