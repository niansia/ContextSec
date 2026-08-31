# High-impact Transactions

Activate for payouts, bank or wallet changes, domain transfers, credential resets, API-key creation, role escalation, destructive operations, or other irreversible/high-blast-radius actions.

| Control | Invariant | Required verification |
|---|---|---|
| `HIT-INTENT-001` | Authorization binds actor intent to the exact action, target, amount, recipient, and consequences. | Target, amount, recipient, and action substitution tests. |
| `HIT-STATE-001` | Sensitive parameters derive from fresh trusted server state, not client summaries or stale approvals. | Client-field and stale-state tampering tests. |
| `HIT-STEPUP-001` | Execution requires fresh, phishing-resistant authentication proportionate to risk. | Stale-session and weak-factor rejection tests. |
| `HIT-CONFIRM-001` | Confirmation is independent, specific, understandable, and cannot be silently rewritten after approval. | Confirmation-content and channel-confusion tests. |
| `HIT-RECIPIENT-001` | New or changed recipients receive additional validation and visible risk treatment. | Recipient substitution and recent-change tests. |
| `HIT-LIMIT-001` | Per-action, actor, tenant, recipient, time, and value limits cap cumulative and concurrent blast radius. | Threshold, cumulative, parallel, and boundary tests. |
| `HIT-COOL-001` | Risky changes use a cancellable delay when immediate execution is unnecessary. | Cooldown, cancellation, notification, and bypass tests. |
| `HIT-DUAL-001` | Broad or exceptional transactions require an independent approver. | Self-approval, reused approval, and collusion-boundary tests. |
| `HIT-AUDIT-001` | Attempt, approval, execution, cancellation, and outcome are tamper-resistant and attributable. | Lifecycle audit and integrity assertions. |
| `HIT-REPLAY-001` | Requests and approvals are single-use, expiry-bound, concurrency-safe, and idempotent. | Duplicate, delayed, parallel, and approval-replay tests. |

Do not treat a UI confirmation dialog as proof. Verify server-side intent binding, fresh state, authorization, and replay behavior.
