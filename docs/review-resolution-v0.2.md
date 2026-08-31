# v0.2 review resolution

> Historical record. The stricter applicability and integrity corrections are
> documented in [v0.2.1 review resolution](review-resolution-v0.2.1.md).

This document maps the two long-form reviews supplied for the v0.1 archive to implemented, partial, or deferred work. “Implemented” means code plus a regression or contract test, not README wording alone.

| Review item | Status | v0.2 evidence |
|---|---|---|
| Position as the product-security decision layer, not a larger OWASP checklist | Implemented | README first screen, competitive positioning, skill description, CLI `explain` |
| Preserve executable `${...}` inside template literals | Implemented | framed lexical adapter and positive/negative twin tests |
| Bind evidence to content without emitting matched secrets | Implemented | stable evidence/location IDs, whole-file digest, content-bound fingerprint, subject revision |
| Invalidate evidence when routing/control semantics change | Implemented | decision-model digest covers pack/control and composition catalogs and is included in subject revision |
| Remove dependency drift between code and pack docs | Implemented | profiler loads dependencies only from `references/catalog.json` |
| Machine-readable control metadata | Implemented | 16 packs and 116 controls with invariant, severity, blocking policy, and verification requirement |
| Cross-context composition engine | Implemented | nine rules in `references/compositions/catalog.json`, activated in the ledger |
| Control Evaluation Ledger | Implemented | every active control gets applicability, status, evidence, verification, reason, and waiver |
| Strict release gate | Implemented | `PASS/WARN/BLOCK/WAIVED`; unknown blocking controls and partial traversal block |
| Reject stale supplied evidence | Implemented | evidence root must match the current subject revision; regression proves replay rejection |
| Secrets Plane | Implemented at routing/control level | eight controls, detectors, fixture, benchmark, Zeabur incident map |
| Cloud IAM / control plane | Implemented at routing/control level | five controls, Terraform/dependency detectors, fixture, benchmark, CI+IAM composition |
| CI/CD supply chain | Implemented plus two checks | eight controls, workflow detector, immutable-action and declared-permission checks |
| Third-party SaaS / OAuth | Implemented at routing/control level | six controls, detector, fixture, benchmark, SaaS+PII composition, Drift incident map |
| Support / admin operations | Implemented at routing/control level | eleven controls, detector, fixture, benchmark, admin+tenant composition, Coinbase incident map |
| High-impact transactions | Implemented at routing/control level | ten controls, detector, payout fixture, AI+transaction composition |
| Relationship/sharing data fan-out | Implemented as a control | `PII-FANOUT-001` |
| Incident → failure pattern → control → regression corpus | Initial implementation | five first-party/official maps; confirmed facts are separate from ContextSec inferences |
| Benchmark metrics rather than scenario count only | Implemented for authored corpus | precision, recall, exact state/confidence, false-required activation, per-case mismatch output |
| Split checker coverage dimensions | Implemented | traversal, language support, checker support, and match enumeration |
| Check candidate packs to help resolve ambiguity | Implemented conservatively | narrow checkers receive required + candidate packs; findings do not silently upgrade applicability |
| One CLI surface | Implemented core commands | `profile`, `check`, `explain`, `gate`, `benchmark` |
| Clean release archives | Implemented | deterministic allowlist packager; `.git` and tool caches excluded; reproducibility verified |
| Full AST/framework fact graph | Deferred | lexical adapters remain explicit and bounded; add adapters only with held-out twins |
| Component-scoped monorepo and cross-service flow graph | Deferred | planned for v0.4 |
| `diff` and `init` CLI commands | Deferred | profile identity and catalog are ready, but impact propagation is not yet proven |
| Signed commit/CI attestation | Deferred | subject is content/model bound but not cryptographically signed by CI |
| Mutation kill-rate gate for all critical controls | Deferred | incident mutations are specified; automated mutation harness is v0.3 work |
| Broad language and checker coverage | Deferred | current coverage remains intentionally partial and is exposed in output |

## Residual product risk

The largest remaining gap is no longer “more control prose.” It is executable verification depth. v0.3 should prioritize one mutation-backed checker per new high-impact plane, beginning with secret bulk access, CI/OIDC trust, support bulk export, and transaction intent/replay. Public claims should continue to say “decision layer” and “research preview” until held-out multi-repository and multi-agent benchmarks exist.
