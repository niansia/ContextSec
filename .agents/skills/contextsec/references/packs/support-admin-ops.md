# Support and Administrative Operations

Activate for support consoles, customer impersonation, cross-tenant operations, customer export, privileged diagnostics, or production operational access.

| Control | Invariant | Required verification |
|---|---|---|
| `ADMIN-JIT-001` | Privileged support access is approved just in time, least-privileged, and time-bounded. | Elevation approval, expiry, and post-expiry denial tests. |
| `ADMIN-REASON-001` | Sensitive access requires a valid case-linked reason before data is revealed or changed. | Missing, unrelated, invalid, and closed-case tests. |
| `ADMIN-BULK-001` | Bulk reads, searches, exports, and mutations have strict volume and velocity limits. | Bulk-limit and scripted-enumeration tests. |
| `ADMIN-MASK-001` | Interfaces return the minimum fields and mask sensitive values until an authorized reveal action. | Role-based projection, masking, and reveal tests. |
| `ADMIN-DUAL-001` | Irreversible or broad-impact operations require an independent authorized approver. | Self-approval, reused approval, and stale approval tests. |
| `ADMIN-IMPERSONATE-001` | Impersonation is explicit, short-lived, visibly marked, constrained, attributable, and non-transferable. | Privilege, expiry, session-fixation, and prohibited-action tests. |
| `ADMIN-EXPORT-001` | Customer exports are scoped, approved, encrypted, expiring, and attributable. | Wrong-tenant, expiry, download, and volume tests. |
| `ADMIN-AUDIT-001` | Access records actor, customer, case, reason, fields, action, and outcome in tamper-resistant audit. | Success, denial, completeness, and audit-integrity assertions. |
| `ADMIN-SESSION-001` | Admin sessions use stronger assurance, controlled devices, short lifetime, and rapid revocation. | Weak-assurance, stale, revoked, and device-policy tests. |
| `ADMIN-ANOMALY-001` | Unusual customer access, export, and privilege patterns trigger investigation and containment. | Detection-rule, alert-delivery, and triage-route tests. |
| `ADMIN-ARTIFACT-001` | Attachments and diagnostic artifacts are sanitized, access-controlled, and retention-bounded. | Active-content, wrong-user, direct-link, and expiry tests. |

Support urgency is not an authorization model. Emergency access still needs bounded authority, attribution, review, and expiry.
