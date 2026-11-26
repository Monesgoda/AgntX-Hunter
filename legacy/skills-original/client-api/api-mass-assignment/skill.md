---
name: api-mass-assignment
description: Audits API endpoints for Mass Assignment / Over-posting vulnerabilities where unvalidated client inputs bind directly into data models.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# API Mass Assignment Audit Procedure

## 1. Audit Scope & Objective
Detect instances where request payloads are automatically bound to internal objects, allowing unauthorized modification of protected fields (e.g., roles, balances, ownership).

## 2. Detection Checklist
1. Model Binding Logic:
   - Look for framework auto-binding patterns (e.g., `user.update(request.body)`, Spring `@ModelAttribute`, Django ModelForm without `fields`, Sequelize `create(req.body)`).
   - Framework-specific sinks: Laravel `$fillable` omissions or `$guarded = []`, Rails `permit!` / gaps in `params.require(...).permit`, Spring `@ModelAttribute` binding an entity directly, Django `fields = '__all__'` / `exclude = []`, and DRF serializers missing `read_only_fields`.
2. Schema & DTO Inspection:
   - Verify if endpoints use Data Transfer Objects (DTOs), form request classes, or explicit input whitelisting.
   - Check if critical fields (e.g., `is_admin`, `role`, `verified`, `tenant_id`, `balance`) can be injected via the request JSON payload.
3. Sensitive Attributes in Update Handlers:
   - Inspect account profile update routes to ensure administrative or permission flags are not exposed to modification.
4. Nested & Relationship Binding:
   - Check whether nested payloads let a client set foreign keys or ownership (`owner_id`, `account_id`, `organization_id`) or append to a relation (`roles[]`, `permissions[]`, `groups[]`).
   - Verify that associations are bound from the authenticated principal, not from client-supplied identifiers.

## 3. False-Positive Guardrails
- Do not flag endpoints if the ORM schema explicitly marks fields as read-only, private, or protected at the model level (e.g., `attr_protected` or `exclude`).
- Do not flag when a strict schema validator (e.g., Zod, Pydantic, Joi) strips unrecognized fields before processing.
- **Boundary:** the *binding* of protected fields is this class; where an over-posted field yields a privilege/ownership change end-to-end, the exploitation narrative belongs to `offsec-business-logic-agent` (IDOR/BFLA). Cross-reference, do not duplicate.

## 4. Remediation Guidance
- Use strict DTOs (Data Transfer Objects) and explicit parameter whitelisting for all incoming payloads.
- Avoid passing raw request dictionaries or objects directly to ORM create/update methods.
- Bind ownership and relationship fields from the authenticated principal only; never from client-supplied foreign keys or arrays.