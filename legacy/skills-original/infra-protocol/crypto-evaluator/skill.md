---
name: crypto-evaluator
description: Audits source code and configurations for deprecated hashing algorithms, weak encryption ciphers, static keys, and flawed randomness.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# Cryptographic Implementation Audit Procedure

## 1. Audit Scope & Objective
Identify cryptographic anti-patterns, obsolete algorithms, insecure modes of operation, and hardcoded sensitive material.

## 2. Detection Checklist
1. Password Storage:
   - Inspect password hashing algorithms: flag any use of MD5, SHA-1, plain SHA-256, or unsalted hashes.
   - Check for modern key-stretching functions (Argon2id, bcrypt, PBKDF2, scrypt) with adequate work factors.
2. Symmetric Encryption:
   - Look for insecure cipher modes like AES in `ECB` mode.
   - Check initialization vectors (IVs): ensure they are generated via cryptographically secure pseudo-random number generators (CSPRNG) and not reused with the same key.
3. Hardcoded Secrets & Keys:
   - Scan code for embedded private keys, static symmetric keys, or hardcoded salting strings.
4. Randomness Quality:
   - Flag uses of non-cryptographic PRNGs (e.g., Python `random`, Java `java.util.Random`, C `rand()`) for security-sensitive tokens.
   - Confirm the CSPRNG is seeded correctly and that tokens/IVs/nonces are not derived from timestamps, counters, or `Math.random()`.
5. Asymmetric Keys & Transport:
   - Check RSA key size (>= 2048; prefer 3072/4096) and exponent — flag small RSA moduli, `e=1`/`e=3`-style exponents, `weak`/small DH groups, and curves outside P-256/P-384/Curve25519.
   - From TLS/server configuration, flag protocol versions below TLS 1.2, broken suites (NULL/EXPORT/RC4/3DES/DES), and CBC-mode suites preferred over AEAD.
   - Look for key reuse across services/tenants, one key serving both signing and encryption, and long-lived keys with no rotation.

## 3. False-Positive Guardrails
- MD5 or SHA-1 used purely for non-cryptographic checksums (e.g., file integrity verification, ETags, cache indexing) is acceptable and should not be reported as high severity.
- Hardcoded mock keys clearly placed inside dedicated unit tests (e.g., `tests/fixtures/`) should be excluded or flagged as informational only.

## 4. Remediation Guidance
- Migrate password storage to `bcrypt` (cost factor >= 12) or `Argon2id`.
- Use authenticated symmetric encryption such as AES-GCM or ChaCha20-Poly1305.
- Load cryptographic keys from environment variables or external secret managers (e.g., HashiCorp Vault, AWS KMS).