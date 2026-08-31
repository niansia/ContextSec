# Multi-tenant pack

Core invariant:

> A principal may access a tenant-owned resource only when the principal's server-established tenant scope includes that resource's tenant, except for an explicitly authorized and audited cross-tenant capability.

| ID | Invariant | Minimum verification evidence |
|---|---|---|
| `TEN-CTX-001` | Tenant context comes from authenticated server-side scope, never solely from a client-supplied tenant/resource identifier. | Tenant substitution negative test. |
| `TEN-DB-001` | Every tenant-owned database read/write, including joins, aggregates, batch operations, and raw queries, is scoped. | Cross-tenant tests plus query/policy inspection. |
| `TEN-CACHE-001` | Cache keys and invalidation include tenant scope; shared caches cannot return another tenant's object. | Same-key cross-tenant test. |
| `TEN-STORE-001` | Object keys, presigned operations, and downloads bind tenant ownership and authorization. | Cross-tenant presign/download negative test. |
| `TEN-ASYNC-001` | Queues, scheduled jobs, exports, and event handlers preserve and revalidate tenant scope. | Cross-tenant job/event mutation test. |
| `TEN-SEARCH-001` | Search, analytics, and vector retrieval apply tenant filters before ranking/aggregation and cannot be overridden by user input. | Missing-filter and filter-tampering tests. |
| `TEN-ADMIN-001` | Support/admin cross-tenant access is explicit, least-privileged, step-up protected where warranted, and records actor, tenant, reason, and action. | Unauthorized support-role and missing-reason tests plus audit assertion. |

## High-value mutation

Remove one tenant predicate or row-level policy from a known-good path. The relevant cross-tenant negative test must fail. If it does not, the evidence is insufficient.

Standards navigation: OWASP ASVS 5.0 access-control requirements and applicable cloud tenant-isolation guidance. Mappings are guidance only.
