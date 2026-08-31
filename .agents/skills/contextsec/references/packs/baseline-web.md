# Baseline web pack

Apply to browser-facing or HTTP applications. Combine with `api-inbound` for API routes and `auth-session` when identities exist.

| ID | Invariant | Minimum verification evidence |
|---|---|---|
| `WEB-OUT-001` | Untrusted data is encoded for its output context; unsafe HTML/URL/script construction is narrowly isolated and reviewed. | Framework-specific test or code path showing contextual encoding. |
| `WEB-CSRF-001` | Cookie-authenticated state changes resist cross-site request forgery. | Cross-origin negative test or framework configuration assertion. |
| `WEB-HEADER-001` | Transport and browser security headers match the deployment, including CSP where rendered content warrants it. | Response-header integration test in the deployed mode. |
| `WEB-COOKIE-001` | Sensitive cookies use secure attributes and the narrowest viable scope and lifetime. | Response/config inspection covering `Secure`, `HttpOnly`, `SameSite`, domain, path, and expiry. |
| `WEB-CACHE-001` | Authenticated or sensitive responses are not stored in shared/public caches. | Response-header test for a representative sensitive route. |
| `WEB-ADMIN-001` | Administrative surfaces are authenticated, authorized, non-enumerable where practical, and not enabled by accidental defaults. | Unauthorized and wrong-role tests against the real server route. |

Do not infer that a framework's default is active in production. Verify the effective configuration.

Standards navigation: OWASP ASVS 5.0 and OWASP Web Security Testing Guide. Mappings are guidance only.
