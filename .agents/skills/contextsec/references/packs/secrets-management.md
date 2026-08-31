# Secrets Management

Activate when the product or platform stores, serves, rotates, exports, or administers credentials—not merely because an application reads its own environment variables.

| Control | Invariant | Required verification |
|---|---|---|
| `SECRET-STORE-001` | Secret values are encrypted with separated key authority and never persist in plaintext. | Storage, envelope-encryption, backup, and plaintext-negative inspection. |
| `SECRET-READ-001` | Every value read is explicitly authorized and returns only the requested secret, version, and fields. | Wrong-principal, wrong-scope, and list-versus-value tests. |
| `SECRET-BULK-001` | Bulk read, export, backup, and migration cannot bypass per-secret authority, volume limits, or anomaly controls. | Bulk authorization, rate, volume, and alert tests. |
| `SECRET-SCOPE-001` | Secret identity binds tenant, environment, workload, and purpose; client labels are never the authority. | Cross-tenant, environment, and workload substitution tests. |
| `SECRET-ROTATE-001` | Rotation supports bounded overlap, revocation, dependency update, and safe rollback without disclosing values. | Rotation, overlap-window, failure, and rollback tests. |
| `SECRET-CASCADE-001` | Compromise of one secret, provider, or operator cannot silently unlock unrelated credentials or control planes. | Authority graph review and lateral-use negative tests. |
| `SECRET-DETECT-001` | Exposure and anomalous read signals trigger containment, revocation, and rotation workflows. | Canary exposure and alert-pipeline test without live value disclosure. |
| `SECRET-AUDIT-001` | Reads and administration record actor, workload, scope, reason, version, and outcome without logging values. | Read, denial, export, and rotation audit assertions. |

Do not report or hash short matched secret values. Evidence may name a redacted path, configuration key, provider resource type, or reproducible test result.
