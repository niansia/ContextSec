# Inbound API pack

Apply to endpoints that accept requests across a trust boundary, including REST, GraphQL, gRPC, webhooks, and internal service APIs.

| ID | Invariant | Minimum verification evidence |
|---|---|---|
| `API-OBJ-001` | Object access is authorized for the current principal and scope on every operation. | Wrong-owner object test. |
| `API-FUNC-001` | Functions and administrative actions enforce server-side role/capability authorization. | Wrong-role function test. |
| `API-PROP-001` | Writable and readable properties are allowlisted; mass assignment and excessive data exposure are prevented. | Extra-field write and response-minimization tests. |
| `API-SCHEMA-001` | Boundary schemas reject malformed, ambiguous, oversized, or unexpected input before business logic. | Invalid type/shape/size tests. |
| `API-BUDGET-001` | Expensive resources and sensitive workflows have bounded rate, concurrency, pagination, query depth, and cost as appropriate. | Limit-exceeded behavior test. |
| `API-TOKEN-001` | Authentication tokens are validated for issuer, audience, signature, expiry, type, and required scope. | Wrong-audience/scope/token-type tests. |
| `API-INV-001` | Deployed API versions and routes are inventoried; obsolete or debug endpoints are not accidentally exposed. | Runtime route/inventory comparison. |

For webhooks carrying provider state, also use the signature, freshness, and idempotency controls from the relevant domain pack.

Standards navigation: OWASP API Security Top 10 2023 and OWASP ASVS 5.0. Mappings are guidance only.
