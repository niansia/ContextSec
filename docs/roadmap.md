# Roadmap and release gates

"Perfect" is not a measurable stopping condition for a security project. ContextSec uses red-team failures, regression fixtures, and explicit release gates.

## v0.1 - Applicability proof

Delivered scope:

- one canonical `contextsec` Agent Skill;
- offline, read-only deterministic profiler/router;
- versioned observations, claims, contradictions, and routing explanations;
- Node.js/Next.js/Prisma-focused detectors;
- ten progressively disclosed packs including the universal foundation;
- semantic profile validation plus five narrow deterministic cross-context checks with versioned finding evidence;
- composite SaaS, negative-control, decoy, provider-without-SDK, limit, redaction, and contradiction tests.

Release gate:

- all supported high-confidence inferred claims have evidence provenance;
- repeated runs over the same scope are byte-for-byte canonical after JSON normalization;
- malicious documentation and dev dependencies cannot alter routing;
- secret/PII source text is absent from evidence output;
- no network, target execution, or implicit write;
- no unresolved P0/P1 finding from two independent review rounds;
- Agent Skill validator and repository tests pass.

## v0.2 - Decision-layer proof

Delivered scope:

- 16-plane machine-readable pack/control catalog with 116 controls;
- content-bound evidence identity, location, digest, fingerprint, and subject revision;
- nine machine-readable cross-context composition controls;
- Control Evaluation Ledger with strict `PASS`, `WARN`, `BLOCK`, and owner/expiry-bound `WAIVED` semantics;
- CLI dispatcher for `profile`, `check`, `explain`, `gate`, and `benchmark`;
- separate checker traversal, language, support, and enumeration coverage;
- five official/first-party incident-to-control maps;
- 13 scenarios and 65 annotated routing decisions, including template-expression positive/negative twins.

Release gate:

- every catalog and pack control ID is unique and synchronized;
- every incident map references real controls, packs, and a runnable fixture;
- content changes invalidate fingerprint and subject revision while stable evidence/location identity remains comparable;
- a required blocking `unknown` produces `BLOCK`;
- all repository tests and benchmark annotations pass.

## v0.2.1 - Applicability correctness and integrity hardening

Delivered scope:

- language-aware JavaScript/TypeScript, Python, SQL, Terraform, YAML, JSON, and generic lexical policies;
- one-profile evaluation plus strict Profile ↔ Checks subject binding;
- per-control `applies_when` sub-capabilities and independent applicability/verification dimensions;
- flow-aware composition promotion instead of pack-co-occurrence promotion;
- catalog/composition JSON Schemas and semantic validation, including exact boolean types;
- repository-aware `explain --repo` output;
- benchmark annotations for controls, compositions, and gate outcomes;
- cross-platform-stable ZIP metadata.

Release gate:

- the static Next.js negative control is `WARN`, not falsely `BLOCK`;
- JavaScript decrement and private-field adversarial twins retain downstream detections;
- stale or mismatched Profile/Checks artifacts are rejected;
- every authored pack, control, composition, and gate annotation passes;
- two independently generated source archives are byte-identical.

## v0.3 - Verification proof

Delivered scope:

- production dependency evidence for PEP 621, Poetry, requirements, and Pipfile manifests without treating optional/dev dependencies as product facts;
- high-confidence FastAPI/Django/Flask framework evidence plus supported Python PII and tenant model shapes;
- 40 fully labeled profile cases split into 24 development and 16 frozen maintainer-authored evaluation cases;
- required/candidate pack metrics, macro/micro F1, safety-critical recall, capability annotations, and absolute false-required counts;
- ten single-edit mutation pairs covering every published deterministic checker shape;
- four public repositories pinned to immutable commits, license/provenance metadata, and an opt-in local runner that verifies `HEAD`;
- Windows, macOS, and Linux × Python 3.11–3.14 CI, public CLI smoke tests, dogfood artifacts, deterministic packaging, and the official Agent Skills reference validator pinned to a commit.

Release gate:

- profile macro F1 >= 0.90 on the authored corpus (currently 1.00);
- safety-critical trigger recall 100% (currently 100%);
- false required-pack activation count 0;
- published-checker mutation kill rate 100% (currently 10/10);
- all four pinned real-repository expectations reproduce, while partial coverage remains partial;
- stale-evidence replay rejection remains covered by the ledger regression suite.

The evaluation split is frozen but not independently labeled. v0.3 therefore remains a research preview and does not claim ecosystem accuracy.

## v0.3.1 - Boundary and provenance hardening

Delivered scope:

- descriptor-based race-resistant repository reads with explicit unsafe-file coverage;
- Python 3.11 `tomllib` parsing for PEP 621, Poetry, and Pipfile production dependencies;
- heuristic, hashed, and opaque artifact path privacy;
- machine-readable support matrix plus `--version` and `doctor` diagnostics;
- adversarial 500 KiB performance/non-disclosure cases and an optimized f-string lexical path;
- hash-pinned Agent Skills validator dependency closure;
- byte-identical release, SHA256SUMS, artifact attestation, and draft-then-publish automation;
- independently reviewable external-label protocol with raw agreement and Cohen's κ;
- Contributor Covenant-based conduct policy and citation metadata.

Release gate:

- every blocking self-routed CI control has subject-bound policy evidence;
- self-profile covers both the repository surface and the core skill directory;
- the adversarial suite passes its generous supported-runner ceiling and non-disclosure properties;
- release archives are byte-identical and every external Action is commit-pinned;
- future release assets are protected by repository release immutability.

## v0.3.2 - Evidence identity hardening

Delivered scope:

- root-anchored, link-rejecting repository traversal and one bounded strict JSON boundary for untrusted artifacts;
- separate display paths and full canonical path identities, full-length observation/finding IDs, and symmetric validator recomputation;
- correlation-aware medium-confidence aggregation and explicit `artifact_options.path_privacy` metadata;
- separate routing, detector, checker, catalog, composition, and support-matrix digests;
- unsupported requirements indirection becomes partial coverage instead of a silent negative;
- `benchmark --suite all` now includes adversarial cases;
- one reusable full security proof for PR, main, and tag release paths, plus tag-to-main ancestry and draft-asset verification;
- exact Action allowlisting and conservative CI audit evidence, including expression-to-environment flows and dynamic shell sinks;
- external-review license/sampling/reviewer provenance, undefined degenerate κ, and separate `evaluate-holdout` accuracy reporting;
- public support-matrix and external-evaluation JSON Schemas.

Release gate:

- tag publication waits for the same 12-way test matrix, evidence/dogfood lane, official Agent Skills validator, and four pinned real repositories used by normal CI;
- static configuration cannot claim a particular release's provenance verified; that claim is established only when the tag run verifies local and re-downloaded draft assets;
- every non-local Action is both commit-pinned and exactly allowlisted;
- the tag commit must be an ancestor of `main` before build or publication.

## v0.3.3 - Release attestation verifier compatibility

Delivered scope:

- checksum-pinned GitHub CLI 2.98.0 for immutable-release predicate v0.2 verification;
- a bounded ten-minute wait for GitHub's asynchronously available release attestation;
- fail-closed release completion if the attestation never verifies;
- artifact schemas remain at 0.3.2 because their semantics did not change.

Release gate:

- the verifier archive must match its fixed SHA-256 before extraction;
- the pinned verifier version must be active before any release mutation;
- release, tag, commit, and asset digests must verify against the GitHub-issued release attestation.

## v0.4 - Trust closure and component evidence

Delivered scope:

- independent canonical tool, detector, checker, and schema versions plus dependency-aware semantic model digests;
- Profile source provenance bound to a canonical Git origin, full commit, and clean worktree;
- component-scoped monorepo Profiles with non-overlapping roots, acyclic dependencies, and explicit evidence-referenced cross-component flows;
- a stricter external-label contract excluding every ContextSec contributor, requiring distinct reviewer organizations, frozen pre-output labels, conflict disclosure, retained disagreements, and independent adjudication;
- support class derived from each frozen commit-bound Profile rather than supplied by the label manifest;
- attestation verification for label and prediction artifacts, with unsigned results restricted to `development-only` and never headline-eligible;
- exact automated-versus-evidence-required classification for all 116 catalog controls and nine compositions;
- CI audit of digest-pinned containers and exact effective job-level token permissions;
- pre-build Immutable Releases verification, release-environment approval, exact tag-to-`main` equality, and attested release evidence binding the complete proof, model identities, coverage, and archive.

Release gate:

- all local contracts, benchmarks, CI policy audits, and deterministic package checks pass;
- no release build begins unless Immutable Releases is already enabled;
- the tagged commit equals current reviewed `main`, not merely an ancestor;
- release evidence and every published asset verify locally and after draft re-download before publication;
- independent ecosystem accuracy remains unclaimed until qualified third parties contribute attested labels and predictions under the frozen protocol.

## v0.4.1 - Promotion-readiness boundary fixes

Delivered scope:

- pre- and post-scan Git provenance equality for repository and aggregate component profiling;
- privacy-transformed embedded component models whose canonical roots remain bound only through full path identities;
- detector/checker semantic identities that include final repository orchestration;
- indentation-aware job container/service image auditing without treating action `with.image` inputs as containers;
- regression coverage for all four review cases and a first-run README path before the deep evidence reference.

Artifact schemas remain at 0.4.0 because these changes strengthen collection, display privacy, model identity, and CI audit parsing without changing artifact field shapes.

## Next evidence milestone

- collect externally labeled repositories from the frozen sampling protocol without maintainer participation;
- compare no-skill, generic-security, and ContextSec-assisted baselines across multiple coding agents;
- expand framework adapters and mutation-backed checker coverage without duplicating canonical controls;
- publish real “Routed by ContextSec, found and verified by the agent/tool” cases.

## Deliberately deferred

- automatic high-risk fixes for authorization, payments, deletion, cryptography, and schema migrations;
- aggregate 0-100 risk scores;
- compliance certification or universal legal overlays;
- a custom SAST/SCA engine;
- dashboard, hosted service, or GitHub App before the local decision layer is proven.
