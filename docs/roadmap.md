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
- 36 fully labeled profile cases split into 20 development and 16 frozen maintainer-authored evaluation cases;
- required/candidate pack metrics, macro/micro F1, safety-critical recall, capability annotations, and absolute false-required counts;
- eight single-edit mutation pairs covering every published deterministic checker shape;
- four public repositories pinned to immutable commits, license/provenance metadata, and an opt-in local runner that verifies `HEAD`;
- 2 OS × Python 3.11–3.14 CI, dogfood artifacts, deterministic packaging, and the official Agent Skills reference validator pinned to a commit.

Release gate:

- profile macro F1 >= 0.90 on the authored corpus (currently 1.00);
- safety-critical trigger recall 100% (currently 100%);
- false required-pack activation count 0;
- published-checker mutation kill rate 100% (currently 8/8);
- all four pinned real-repository expectations reproduce, while partial coverage remains partial;
- stale-evidence replay rejection remains covered by the ledger regression suite.

The evaluation split is frozen but not independently labeled. v0.3 therefore remains a research preview and does not claim ecosystem accuracy.

## v0.4 - Ecosystem proof

- externally labeled repositories from a declared sampling frame, with reviewer disagreements retained;
- component-scoped monorepo profiles and cross-component flows;
- framework adapters without duplicating canonical controls;
- comparison against no-skill and generic-security baselines across multiple coding agents;
- signed/pinned pack provenance and permission manifests;
- contributor certification through held-out scenarios;
- public benchmark methodology and real "Routed by ContextSec, found and verified by the agent/tool" cases.

## Deliberately deferred

- automatic high-risk fixes for authorization, payments, deletion, cryptography, and schema migrations;
- aggregate 0-100 risk scores;
- compliance certification or universal legal overlays;
- a custom SAST/SCA engine;
- dashboard, hosted service, or GitHub App before the local decision layer is proven.
