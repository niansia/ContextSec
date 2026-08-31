# Third-party SaaS and OAuth

Activate for connected apps, delegated OAuth grants, tenant-wide integrations, sync/export connectors, or vendor access to customer data.

| Control | Invariant | Required verification |
|---|---|---|
| `SAAS-INV-001` | Connected apps, grants, owners, tenants, scopes, and data access are inventoried and reconcilable. | Runtime grant-to-owner inventory reconciliation. |
| `SAAS-SCOPE-001` | Delegated scopes are minimal; tenant-wide consent and dangerous optional scopes are explicit. | Scope downgrade, consent, and unexpected-scope tests. |
| `SAAS-TOKEN-001` | Access and refresh tokens are encrypted, tenant-bound, short-lived where possible, and absent from logs and URLs. | Storage, refresh, tenant substitution, and logging tests. |
| `SAAS-REVOKE-001` | Disconnect, user removal, scope change, and incident response revoke grants and cached access. | Revocation, stale-token, and refresh-after-disconnect tests. |
| `SAAS-BLAST-001` | Connected-app or vendor compromise has bounded tenant, principal, field, operation, and time blast radius. | Trust graph and provider-compromise isolation exercise. |
| `SAAS-EXPORT-001` | Bulk third-party reads and exports are authorized, limited, attributable, and anomaly-detected. | Bulk export, cross-tenant, rate, and alert tests. |

OAuth protocol correctness is necessary but insufficient: include downstream vendor trust, data fan-out, revocation latency, and support access in the review.
