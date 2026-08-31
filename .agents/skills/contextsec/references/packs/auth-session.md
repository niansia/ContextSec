# Authentication and session pack

Apply when the product authenticates people or services, maintains sessions, uses JWTs, or integrates OAuth/OIDC.

| ID | Invariant | Minimum verification evidence |
|---|---|---|
| `AUTH-LOGIN-001` | Authentication failure does not reveal whether an account exists and is protected against automated guessing. | Enumeration and rate-control negative tests. |
| `AUTH-SESSION-001` | Session identifiers rotate at authentication and privilege changes, expire, revoke, and are never accepted from unsafe locations. | Fixation, logout/revocation, and expiry tests. |
| `AUTH-RECOVERY-001` | Recovery tokens are random, single-use, short-lived, bound to an intended account/action, and do not reveal account existence. | Replay, expiry, and account-confusion tests. |
| `AUTH-OAUTH-001` | OAuth/OIDC validates exact redirect intent, state/nonce, issuer, audience, signature, expiry, and PKCE where applicable. | Tampered state/nonce/issuer/audience and redirect mismatch tests. |
| `AUTH-TOKEN-001` | API tokens use the least scope and are validated by the intended resource server; token type confusion is rejected. | Wrong audience/scope/token-type negative tests. |
| `AUTH-STEPUP-001` | High-impact actions such as payout, recovery, credential change, or cross-tenant administration require recent or stronger authentication where warranted. | Stale/low-assurance session rejection test. |

Do not equate the presence of an authentication library with correct configuration. Missing identity evidence in a tenant or account-bound flow is a gap.

Standards navigation: OWASP ASVS 5.0 V2/V3, OWASP Authentication and Session Management Cheat Sheets, and RFC 9700. Mappings are guidance only.
