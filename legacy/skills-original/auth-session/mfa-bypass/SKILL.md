---
name: mfa-bypass
description: Audits multi-factor authentication enrollment and challenge flows for bypass via response manipulation, missing enforcement, and recovery/enrollment weaknesses.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# MFA Bypass Audit Procedure

## 1. Audit Scope & Objective
Review MFA enrollment, challenge, verification, and recovery flows to determine whether an attacker (with the password but not the second factor) can reach an authenticated state without completing MFA. The objective is to detect enforcement gaps, response-manipulation bypasses, and weak recovery paths.

## 2. Detection Checklist
### A. Enforcement coverage
- Confirm every authenticated entry point after login requires MFA completion (API endpoints, alternate login, SSO/OAuth/token endpoints, mobile API).
- Check for endpoints that issue a session/token before MFA verification.

### B. Response/conclusion manipulation
- In client-evaluated or redirect-based MFA, test forcing the "success" state (response tampering, skipping the challenge step, replaying the post-MFA redirect).
- Check whether the MFA result is decided server-side and bound to the session.

### C. Recovery and enrollment
- Weak "trust this device" cookies (predictable, non-expiring, not bound to device/user).
- Recovery codes: guessable, reusable, or accepted without the primary factor.
- Enrollment of a new factor without re-authentication; MFA reset via email/SMS without step-up.

### D. Second-factor verification details
- For TOTP/HOTP, confirm the server rejects a code already accepted for the same time step (RFC 6238 §5.2 replay) and applies only a narrow clock window.
- Confirm the pending-MFA state is a server-side, single-use challenge bound to the authenticated half-session and cannot be reused to complete a different session.
- Confirm enrolling or replacing a factor performs step-up re-authentication rather than trusting the existing half-session.

## 3. False-Positive Guardrails
- A client-side MFA gate hiding the UI while the server still enforces the challenge is not a bypass — confirm the server denies the post-login action without MFA.
- Rate limiting on OTP attempts is a control, not a finding; its absence is `rate-limiting` (see boundary).
- A single successful login after MFA is normal; the finding is reaching auth **without** the second factor.
- Boundary: OTP/lockout throttling belongs to `client-api/rate-limiting`; password-reset-based MFA reset flaws belong to `auth-session/password-reset-flow`.

## 4. Remediation Guidance
- Require MFA server-side on every post-login privileged action and token issuance; bind MFA completion to the server session.
- Make "trust device" cookies unpredictable, scoped, expiring, and device/user-bound.
- Require the primary factor (and step-up) to enroll/reset a factor or use recovery codes; make codes single-use and random.
- Reject TOTP/HOTP codes already accepted within their validity window and keep the acceptance window narrow.
