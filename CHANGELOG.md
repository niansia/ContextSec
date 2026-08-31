# Changelog

## 0.3.2 — Evidence identity hardening

- Anchored POSIX repository traversal to directory descriptors, added Windows reparse/final-handle containment checks, and routed untrusted JSON artifacts through one bounded, duplicate-key-rejecting reader.
- Split display-path privacy from canonical path identity, expanded observation and finding IDs to full SHA-256 width, added explicit artifact privacy metadata, and made semantic validators recompute evidence identities.
- Added evidence families and correlation groups so dependency/import signals from the same SDK do not become independent high-confidence proof.
- Bound routing, detector, checker, catalog, composition, and support-matrix digests separately across Profile, Checks, Ledger, `doctor`, and external predictions.
- Made unsupported requirements indirection an explicit partial-coverage gap and added identity/forgery/indirection regression contracts.
- Made `benchmark --suite all` include the adversarial suite and added public CLI contracts for version, doctor, external review, and holdout evaluation.
- Replaced owner-level Action trust with an exact action allowlist and expanded CI audit coverage across expression-tainted environment variables, `github.ref_name`, and dynamic shell-code sinks.
- Narrowed static release provenance to `unknown` until runtime and added local plus re-downloaded draft checksum/attestation verification.
- Factored the complete 12-way matrix, evidence/dogfood, official Agent Skills validator, and four pinned real-repository lanes into one reusable proof required by PR, main, and tag release paths.
- Added tag-to-main ancestry validation, a permanent Research Preview release preamble, and a publish step that runs only after draft assets verify.
- Added external review license/sampling/expertise/adjudicator provenance, raw confusion/prevalence output, undefined degenerate κ, public evaluation Schemas, and a separate `evaluate-holdout` accuracy evaluator without fabricating labels.
- Added a JSON Schema for the machine-readable support matrix and documented deterministic path pseudonymization rather than secrecy.

## 0.3.1 — Boundary and release provenance hardening

- Updated the non-executed composite example from Next.js 15.0.0 to 15.5.21 through Dependabot PR #7.
- Replaced check-then-read repository access with descriptor reads that compare pre-open and opened identities, reject symlink/reparse replacements, and detect metadata changes through the read.
- Replaced the hand-written PEP 621, Poetry, and Pipfile TOML subset with Python 3.11 `tomllib`; malformed production TOML now makes traversal partial.
- Added heuristic, hashed, and opaque path-privacy modes and narrowed the artifact privacy claim to distinguish source-content non-disclosure from filename handling.
- Added canonical tool/schema version files, `contextsec --version`, `contextsec doctor`, and a machine-readable support matrix used by profiler and checker constants.
- Moved every JSON Schema `$id` from the unregistered `contextsec.dev` namespace to immutable `v0.3.1` source URLs and advanced artifact schemas to 0.3.1.
- Added six generated 500 KiB adversarial performance/non-disclosure cases and removed an avoidable Python f-string substring path that amplified runtime.
- Scoped the CI/CD OIDC capability detector to deployment or package-publication use, so provenance-only attestations do not trigger deployment controls.
- Hash-pinned the Agent Skills validator's complete PyPI build/runtime closure while retaining the upstream full-commit source pin.
- Added a tag-only draft-first release workflow that verifies version identity, rebuilds twice, compares bytes, publishes SHA256SUMS, creates artifact attestations, and only then publishes the release.
- Added subject-bound CI policy evidence, real core-engine self-profiling, an external two-reviewer label protocol with Cohen's κ, `CITATION.cff`, and a Contributor Covenant-based Code of Conduct.

## 0.3.0 — Benchmark and mutation proof

- Added a 40-case fully labeled profile corpus with 24 development and 16 frozen maintainer-authored evaluation cases, per-pack confusion counts, macro/micro F1, safety-critical recall, capability annotations, and false-required activation counts.
- Added ten baseline/mutant pairs covering every published deterministic checker shape; all mutations must change the expected finding state and control binding.
- Added a mandatory positive/negative contract for every text and dependency detector so boundary and false-positive behavior is regression tested.
- Fixed no-argument `auth()` recognition, added Clerk/Auth0/WorkOS/Better Auth/Lucia dependency evidence, and expanded conservative tenant-key aliases including `orgId`, `org_id`, `accountId`, `teamId`, and `companyId`.
- Added key-name-only `.env` profiling and a blocking checker for secret-bearing `NEXT_PUBLIC_`, `VITE_`, and `REACT_APP_` variables without serializing or hashing secret values.
- Expanded tenant checks across supported Prisma CRUD calls, enumerate every supported match, and emit an explicit `unknown` finding for raw SQL that needs semantic review.
- Added machine-readable supported/partial/unsupported stack coverage and bound it across Profile, Checks, Ledger, and gate evaluation; this intentionally advances artifact schemas from `0.2.1` to `0.3.0`.
- Added mainstream Node ecosystem evidence for authentication, ORM, queue, observability, Supabase, and Taiwan payment integrations while keeping technology-only dependencies from activating risk packs on their own.
- Excluded non-workflow `.github` governance files from production evidence so issue forms and dependency configuration cannot pollute self-profiling.
- Added four manually reviewed public-repository cases pinned to immutable commits with license/provenance metadata and a local-checkout runner that verifies `HEAD` without cloning or executing target code.
- Added conservative Python production-manifest evidence for PEP 621, Poetry, requirements, and Pipfile while excluding optional/dev and test/example manifests.
- Added Python FastAPI/Django/Flask, PII model, tenant model, and authentication evidence; promoted supported generic HTTP routes to direct high-confidence API evidence.
- Narrowed the RAG sub-capability detector after a real Stripe samples case exposed false `retrieve` matches.
- Added path-safe temporary benchmark materialization, explicit metric claim boundaries, and separate benchmark methodology/real-repository documentation.
- Expanded CI to Ubuntu, macOS, and Windows across Python 3.11–3.14, smoke-tested the documented public CLI on every combination, retained dogfood and reproducible archive checks, and pinned the official Agent Skills reference validator to a full commit.
- Added an editable, dependency-free SVG decision flow and copyable Windows, macOS, and Linux quick-start instructions.
- Unified the documented agent path around `contextsec.py`, declared Python 3.11+ and three-OS compatibility, and added schema validation subcommands to the public dispatcher.

## 0.2.1 — Applicability correctness and integrity hardening

- Replaced universal comment masking with language-aware lexical policies; JavaScript decrement/private fields, Python f-string expressions, and MySQL hash comments retain their intended semantics.
- Unified `scope_hash` as `subject_revision`, profiled once per evaluation, and reject mismatched Profile/Checks artifacts or mid-evaluation source changes through a shared source-inventory digest.
- Added evidence-backed sub-capabilities and per-control `applies_when` conditions.
- Split ledger applicability from verification so irrelevant controls cannot create false blockers.
- Changed compositions from pack-co-occurrence activation to candidate-by-default, required-on-explicit-intersection semantics; unrelated same-file keywords cannot prove a flow.
- Added strict catalog, profile, check, and ledger semantic validation, including exact object shapes, catalog-bound rows, recomputed summaries/gates, and non-boolean `blocking` rejection.
- Made computed required applicability monotonic against supplied evidence and added active/expired/partial waiver lifecycle regressions.
- Bound finding evidence to the current subject revision and reject decision-model mutation between profiling and ledger evaluation.
- Prevented upload findings from matching inert template-literal prose.
- Added a bounded JavaScript object-property scanner for equivalent public ACL syntax and a tenant-derived upload-key composition checker.
- Made finding identity/digest relationships self-consistent and require artifact decision-model digests to match the live model.
- Bound waiver ledgers to an explicit evaluation date and require release-date revalidation to prevent expired-artifact replay.
- Rejected `verified`/`failed` ledger states without evidence references or consistent evaluation sources.
- Added repository-aware `explain --repo` output.
- Expanded the regression benchmark with control applicability, composition applicability, and gate annotations.
- Standardized stored ZIP entries, platform/version metadata, permissions, timestamps, and LF checkout policy for byte-identical cross-platform packaging inputs.
- Corrected the Zeabur incident map from delegated SaaS/OAuth to ordinary external API exposure.

## 0.2.0 — Decision layer

- Repositioned ContextSec around the question “which security controls does this product actually need?”
- Added one machine-readable catalog with 16 product-risk packs and 116 controls.
- Added six risk planes: secrets management, cloud IAM/control plane, CI/CD supply chain, third-party SaaS/OAuth, support/admin operations, and high-impact transactions.
- Added nine cross-context composition controls.
- Added a Control Evaluation Ledger and strict `PASS`, `WARN`, `BLOCK`, and expiry-bound `WAIVED` gate.
- Split stable evidence/location identity from content digest, content-bound fingerprint, subject revision, and decision-model digest.
- Fixed executable expressions inside JavaScript/TypeScript template literals while preserving literal decoy suppression.
- Added narrow CI action-pin and token-permission checks.
- Added a five-case official/first-party incident-to-control corpus.
- Expanded the annotated routing benchmark to 13 scenarios and 65 decisions.
- Added a deterministic, allowlisted source release packager.

## 0.1.0 — Applicability proof

- Added the canonical Agent Skill, offline repository profiler, explainable router, ten initial packs, five narrow control checks, semantic validators, composite demo, and adversarial fixtures.
