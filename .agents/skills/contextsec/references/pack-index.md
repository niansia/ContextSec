# ContextSec pack router

Use this file after profiling. Load the foundation pack plus only the required and candidate context packs. This is the human-readable index; `catalog.json` is the single machine-readable source for pack order, claims, dependencies, and control policy.

| Pack | Activate on repository or declared evidence | Reference | Dependency notes |
|---|---|---|---|
| `foundation` | Every software repository | [packs/foundation.md](packs/foundation.md) | None |
| `baseline-web` | Web framework, public HTTP surface, browser client, or server-rendered application | [packs/baseline-web.md](packs/baseline-web.md) | None |
| `auth-session` | Login, session, JWT, OAuth/OIDC, password reset, API authentication, or user roles | [packs/auth-session.md](packs/auth-session.md) | None |
| `payments` | Payment provider SDK, checkout/billing/subscription/refund/payout flow, or movement of monetary value | [packs/payments.md](packs/payments.md) | Also apply `external-api`; apply `auth-session` to account-bound or privileged money flows |
| `privacy-pii` | Personal identifiers, user documents, telemetry tied to people, regulated data, or PII sent to a processor | [packs/privacy-pii.md](packs/privacy-pii.md) | Add to any pack that handles identified or identifiable people |
| `multi-tenant` | Tenant, organization, workspace, account boundary, shared infrastructure, or support cross-tenant access | [packs/multi-tenant.md](packs/multi-tenant.md) | Also apply `auth-session`; missing identity evidence is a gap, not non-applicability |
| `api-inbound` | REST, GraphQL, gRPC, webhook, or public/internal service endpoint | [packs/api-inbound.md](packs/api-inbound.md) | Also apply `baseline-web` for HTTP surfaces |
| `external-api` | Outbound provider SDK, user-controlled URL fetch, webhook callback, or third-party data transfer | [packs/external-api.md](packs/external-api.md) | Add `privacy-pii` when personal data can leave the trust boundary |
| `file-upload` | Multipart input, object upload, presigned upload, document/media processing, or user-controlled archive | [packs/file-upload.md](packs/file-upload.md) | Add `privacy-pii` for user documents or identifying metadata |
| `ai-rag-agent` | LLM provider, RAG/vector search, model serving, tools/MCP, agent memory, or autonomous action | [packs/ai-rag-agent.md](packs/ai-rag-agent.md) | Also apply `external-api`; compose with PII, tenancy, and high-impact evidence |
| `secrets-management` | Product/platform secret storage, read, export, rotation, or administration | [packs/secrets-management.md](packs/secrets-management.md) | Distinct from an ordinary app reading its own environment variables |
| `cloud-iam-controlplane` | Cloud identities, roles, policies, accounts, organizations, networks, or metadata/control planes | [packs/cloud-iam-controlplane.md](packs/cloud-iam-controlplane.md) | Also apply `secrets-management` to control-plane credentials and rotation |
| `cicd-supply-chain` | CI workflows, build automation, package publication, deployment identity, or artifact provenance | [packs/cicd-supply-chain.md](packs/cicd-supply-chain.md) | Compose with cloud IAM when builds obtain deployment authority |
| `third-party-saas-oauth` | Connected apps, delegated OAuth grants, tenant-wide integrations, sync, or export | [packs/third-party-saas-oauth.md](packs/third-party-saas-oauth.md) | Also apply `auth-session` and `external-api`; compose with PII |
| `support-admin-ops` | Support console, impersonation, cross-tenant operation, export, or privileged diagnostics | [packs/support-admin-ops.md](packs/support-admin-ops.md) | Also apply `auth-session` and `api-inbound`; compose with tenancy |
| `high-impact-transactions` | Payout, recipient change, domain transfer, credential reset, role escalation, or destructive action | [packs/high-impact-transactions.md](packs/high-impact-transactions.md) | Also apply `auth-session`; compose with AI when a model can propose actions |

## Routing rules

1. Direct SDK/config/schema/route evidence outranks names, comments, and prose.
2. Documentation and examples alone may create a candidate only when the user explicitly includes them in scope; they never create a required pack.
3. Pack dependencies express security invariants, not proof that the dependent implementation exists.
4. A missing expected pack dependency is an evidence gap to investigate.
5. A single feature can activate multiple packs. Compose their controls and deduplicate by invariant; do not drop the stricter requirement.
6. For a diff, compare the previous and current profile and route newly affected packs before reviewing the code change.
7. Emit a composition as a candidate when all of its packs are active. Promote it to required only when its named flow/intersection capability or a deterministic finding proves the contexts actually meet.

## Control decision vocabulary

Record applicability as `required`, `candidate`, `not_applicable`, or `unknown`. Record verification independently as `verified`, `failed`, `unknown`, or `waived`. A control may be `not_applicable` only when its required sub-capability is concretely not observed under complete supported coverage. Silence never becomes `verified`.
