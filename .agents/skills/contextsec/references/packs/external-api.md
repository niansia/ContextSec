# External API pack

Apply when the product sends requests or data to a third party, accepts user-influenced destinations, or depends on provider responses.

| ID | Invariant | Minimum verification evidence |
|---|---|---|
| `EXT-DEST-001` | Destinations are server-controlled or constrained by an allowlist/resolver that resists SSRF, redirects, rebinding, and alternate address forms. | Loopback/private/link-local/redirect negative tests where URLs are influenced. |
| `EXT-SECRET-001` | Provider credentials use the least scope, remain server-side, are rotated through an intended mechanism, and are never forwarded from users. | Config and outbound-header inspection without printing values. |
| `EXT-TIME-001` | Connections, reads, retries, concurrency, and response sizes are bounded; retries are safe for the operation. | Timeout/retry/oversize and partial-failure tests. |
| `EXT-SCHEMA-001` | Provider responses are treated as untrusted and validated before affecting state, rendering, queries, or tool calls. | Malformed/unexpected response test. |
| `EXT-EGRESS-001` | Outbound payloads contain only intended data and do not leak credentials, debug context, or unnecessary PII. | Payload/log inspection on success and failure paths. |
| `EXT-FAIL-001` | Provider outage, duplicate response, and partial success cannot silently corrupt local state or bypass authorization. | Controlled outage and replay/idempotency tests. |
| `EXT-TLS-001` | TLS verification is enabled and insecure overrides are absent from production paths. | Effective client configuration inspection. |

Do not trust a provider because it is well known. The trust boundary is the response and data flow, not the vendor's reputation.

Standards navigation: OWASP API Security Top 10 2023 unsafe-consumption guidance and OWASP SSRF Prevention guidance. Mappings are guidance only.
