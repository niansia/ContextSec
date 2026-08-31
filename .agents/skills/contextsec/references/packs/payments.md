# Payments pack

Apply to checkout, billing, subscription, refunds, payouts, marketplaces, wallets, or any flow that changes monetary value or paid entitlement.

| ID | Invariant | Minimum verification evidence |
|---|---|---|
| `PAY-SCOPE-001` | Cardholder data scope is explicit. PAN/CVV handling is `unknown` until evidence shows hosted/tokenized collection or direct handling; CVV is never retained. | Data-flow/config inspection and client/server boundary review. |
| `PAY-PRICE-001` | The server derives amount, currency, product, discount, recipient, and entitlement from trusted server-side state. | Client amount/currency/product tampering test. |
| `PAY-STATE-001` | Success redirects and client callbacks never grant paid state; only a verified provider API response or authenticated event can do so. | Fake-success redirect and forged client callback tests. |
| `PAY-WEBHOOK-001` | Webhooks verify the provider signature over the unmodified body and enforce timestamp tolerance where supported. | Invalid signature, mutated body, and stale event tests. |
| `PAY-IDEMP-001` | Duplicate, replayed, delayed, and out-of-order events or requests cannot double-charge or corrupt entitlement. | Duplicate-event and idempotency regression tests. |
| `PAY-PRIV-001` | Refund, payout, destination, pricing, and restricted-key operations use server-side authorization, step-up controls, limits, and audit where impact warrants it. | Wrong-role, wrong-owner, stale-session, and limit tests. |
| `PAY-SECRET-001` | Secret/restricted provider credentials remain server-only, least-privileged, and absent from logs and public bundles. | Build artifact/config/log inspection without exposing values. |

## Composition checks

- With `multi-tenant`, every payment object and event must be re-bound to the server-resolved tenant before state changes.
- With `privacy-pii`, minimize billing metadata and exclude it from routine logs, analytics, and model prompts.
- With marketplace/payout flows, treat recipient manipulation and privileged payout changes as distinct high-impact controls.

Standards navigation: PCI DSS 4.0.1, OWASP ASVS 5.0, and the provider implementation guide selected by the project. This pack cannot certify PCI compliance.
