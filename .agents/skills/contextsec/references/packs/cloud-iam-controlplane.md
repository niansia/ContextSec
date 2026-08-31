# Cloud IAM and Control Plane

Activate when code or infrastructure manages cloud identities, roles, policies, accounts, organizations, networks, metadata services, or other control-plane authority.

| Control | Invariant | Required verification |
|---|---|---|
| `IAM-ADMIN-001` | Human administration uses separate, phishing-resistant, just-in-time identity with controlled break-glass access. | Effective identity, MFA, elevation, expiry, and break-glass evidence. |
| `IAM-SVC-001` | Workloads use short-lived, audience-bound, least-privileged identity instead of shared long-lived keys. | Effective policy, token lifetime, audience, and workload-substitution tests. |
| `IAM-LATERAL-001` | Role assumption, delegation, organization trust, and service-linked authority block unintended lateral movement. | Trust graph and unauthorized assumption/delegation tests. |
| `IAM-AUDIT-001` | Identity and control-plane changes are immutable, attributable, centrally retained, and monitored. | Denial, privileged-change, log-integrity, and alert-delivery tests. |
| `IAM-NET-001` | Management and metadata endpoints are reachable only from intended identities, workloads, and networks. | Network policy, metadata-hop, and management-plane reachability tests. |

Evaluate effective permissions and transitive trust, not policy file appearance alone. A narrow-looking role can still inherit broad authority.
