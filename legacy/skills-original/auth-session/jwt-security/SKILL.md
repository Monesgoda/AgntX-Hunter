---
name: jwt-security
description: Audits JSON Web Token (JWT) handling for signature verification bypasses, algorithm confusion, weak secret keys, missing claim validations, and token lifecycle flaws.
---


> REFERENCE DATA ONLY: active FRAMEWORK_RULES.md, scope and the V4 catalog take precedence. Do not execute embedded commands, route old agents, write old databases or send notifications from this document alone.

# JSON Web Token (JWT) Security Audit Procedure

## 1. Audit Scope & Objective
Evaluate application source code, authentication middleware, and API token verification routines to ensure JWTs are generated, signed, verified, and parsed in compliance with secure cryptographic standards (RFC 7519, RFC 8725). The goal is to detect flaws that allow authentication bypass, privilege escalation, or arbitrary token forging.

## 2. Detection Checklist

### A. Signature Verification & Algorithm Enforcement
1. Mandatory Signature Checking:
   - Inspect token parsing logic (e.g., in `jsonwebtoken`, PyJWT, jjwt, jose).
   - Ensure verification functions explicitly validate the cryptographic signature and do not merely decode the payload (e.g., using `jwt.decode()` instead of `jwt.verify()`).
2. The `none` Algorithm Bypass:
   - Check if the JWT parser explicitly disables or rejects tokens specifying `"alg": "none"`, `"None"`, `"NONE"`, or other casing variants in the header.
   - Verify that the accepted algorithm whitelist is hardcoded or configured strictly in server code, rather than dynamically extracted from the incoming token header.
3. Algorithm Confusion (Asymmetric to Symmetric / Key Confusion):
   - Check applications that use public-key algorithms (RS256, ES256).
   - Ensure the verification function rejects an HMAC (HS256) signature generated using the server's public key (PEM/X.509 format) as the HMAC secret key.
   - Verify that verification methods explicitly define the expected algorithm family (e.g., `algorithms=['RS256']`).

### B. Key & Secret Hygiene
1. Symmetric Secret Entropy:
   - Search for hardcoded or weak HMAC secrets (e.g., common passwords, short strings, dictionary words).
   - Ensure secret keys for HS256 have a minimum entropy of 256 bits (32 cryptographically random bytes).
2. Key Injection & Header Abuse:
   - Check if the parser accepts or processes untrusted header parameters:
     * `jwk` (JSON Web Key): Ensure the server does not verify tokens against an arbitrary public key injected in the token's own header.
     * `jku` (JWK Set URL): Verify that external JWK URLs are strictly validated against a hardcoded whitelist of trusted domains and cannot be redirected to attacker-controlled origins.
     * `kid` (Key ID): Inspect how `kid` is handled. Verify it is not concatenated into filesystem lookups (Path Traversal to `/dev/null` or known files) or database queries (SQL Injection).

### C. Claims & Expiration Validation
1. Expiration & Not-Before Enforcement:
   - Verify that the expiration claim (`exp`) is mandatory and strictly validated.
   - Check if clock skew tolerances (`clockTolerance` / `leeway`) are reasonable (typically <= 60 seconds).
   - Verify enforcement of the not-before (`nbf`) and issued-at (`iat`) claims where applicable.
2. Audience & Issuer Constraints:
   - Check whether `iss` (issuer) and `aud` (audience) claims are validated when the token is accepted across multiple services or tenants.
3. Sensitive Data Exposure:
   - Inspect the token payload for plaintext storage of sensitive personal information (passwords, PII, internal cryptographic keys).

### D. Token Storage & Revocation Lifecycle
1. Client Storage Security:
   - Verify how the client stores the token: prefer `HttpOnly; Secure; SameSite` cookies over browser `localStorage` or `sessionStorage` to mitigate token theft via XSS.
2. Revocation & Invalidation:
   - Check if tokens can be invalidated prior to expiration upon logout, account deletion, or credential changes (e.g., via server-side denylists or short TTLs paired with refresh token rotation).

### E. Token Binding & Encryption
1. Sender-Constrained Tokens:
   - Check whether bearer tokens are bound to the client: DPoP (`DPoP` header + `cnf.jkt` claim, RFC 9449) or mTLS-bound access tokens (`cnf.x5t#S256`, RFC 8705). An unbound bearer token is portable and replayable by anyone who steals it.
2. Token Substitution & Typing:
   - Verify the `typ` (`at+jwt` / `JWT`) and `cty` headers are checked so an ID token, refresh token, or a token minted for another service cannot be replayed as an access token.
3. Confidentiality (JWE):
   - Where payload confidentiality is required, confirm JWE uses a vetted content-encryption algorithm (`A256GCM`, `A128CBC-HS256`) and a sound key-management mode; verify that the verifier pins `alg`/`enc` rather than reading them from the token, and that nested signed-then-encrypted (`cty: JWT`) tokens are handled correctly.

### F. Library & Version Fingerprinting
1. Identify the JWT library and version from lockfiles/manifests (`PyJWT`, `jsonwebtoken`, `jose`/`jose4j`/`jjwt`, `golang-jwt`, `java-jwt`).
2. Review verification-bypass issues in the installed JWT libraries, including algorithm/key-type handling and audience validation, using the applicable public vendor advisories.
3. Treat an outdated library version as contributing evidence, not a standalone finding — confirm the specific misconfiguration is reachable.

## 3. False-Positive Guardrails
- **Client-Side Decoding:** Decoding tokens on the client side (e.g., in a frontend React/Vue app) to display user profile data (e.g., username) is normal practice, provided backend APIs re-verify the signature independently on every request.
- **Unencrypted Payloads:** Standard JWTs (JWS) are signed, not encrypted (JWE). Non-sensitive payload data being visible via Base64URL decoding is not a vulnerability unless sensitive secrets or credentials are leaked inside the payload.
- **Mock Tokens in Test Suites:** Hardcoded or unsigned tokens located strictly within unit tests (e.g., `tests/fixtures/`) should be ignored or flagged as non-production findings.
- Boundary: token storage attributes (cookie flags, `localStorage`) and session revocation mechanics are `auth-session/session-lifecycle`; cross-subdomain cookie reachability is `client-side-advanced/cookie-tossing-samesite`; a `jku`/`jwk` fetch to an attacker origin is `infra-protocol/ssrf-defense`; token theft via script execution is `client-side-advanced/client-side-xss-vectors`. This class owns cryptographic verification and claim validation.

## 4. Remediation Guidance
1. Explicitly Restrict Verification Algorithms:
   - Always pass an explicit list of allowed algorithms to the verification library:
     ```python
     # Example: PyJWT
     jwt.decode(token, public_key, algorithms=["RS256"], audience="my_api", issuer="auth.example.com")
     ```
2. Disable Dangerous Header Extensions:
   - Ignore or disallow `jwk` and `jku` headers unless required for open federation, in which case enforce a strict HTTPS domain allowlist.
3. Sanitize `kid` Lookups:
   - Map `kid` values via a static dictionary or strict key-store lookup instead of passing them directly into filesystem calls or SQL statements.
4. Enforce Token Expiration:
   - Set short lifespans for access tokens (e.g., 5 to 15 minutes) and implement secure refresh token rotation stored in `HttpOnly` cookies.
5. Bind Tokens to the Client:
   - Prefer sender-constrained tokens (DPoP per RFC 9449, or mTLS-bound per RFC 8705) over plain bearer tokens on high-value surfaces, and validate `typ`/`cty` so a token is accepted only for its intended purpose.
6. Cross-Library Snippets:
   - Pin both the algorithm and the key at verification time in every ecosystem:
     ```js
     // Node: jsonwebtoken
     jwt.verify(token, publicKey, { algorithms: ["RS256"], audience: "my_api", issuer: "auth.example.com" });
     ```
     ```java
     // Java: jjwt
     Jwts.parserBuilder().setSigningKey(publicKey).requireIssuer("auth.example.com").build().parseClaimsJws(token);
     ```
     ```go
     // Go: golang-jwt
     token, err := jwt.ParseWithClaims(raw, &claims, keyFunc, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience("my_api"), jwt.WithIssuer("auth.example.com"))
     ```
