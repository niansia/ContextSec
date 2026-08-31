# ContextSec

[![CI](https://github.com/niansia/ContextSec/actions/workflows/ci.yml/badge.svg)](https://github.com/niansia/ContextSec/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/niansia/ContextSec?display_name=tag&sort=semver)](https://github.com/niansia/ContextSec/releases)
[![License](https://img.shields.io/github/license/niansia/ContextSec)](LICENSE)
![Research Preview](https://img.shields.io/badge/status-research%20preview-6f42c1)

## The product-security decision layer for AI coding agents

> **Your coding agent knows security rules. ContextSec tells it which ones your product actually needs.**

ContextSec turns bounded repository evidence into a reproducible answer to one question:

> **What security controls does this product need right now—and what evidence would prove them?**

It is not another OWASP checklist and not another general vulnerability scanner. It profiles what the product appears to do from bounded evidence, classifies product-risk packs and controls as required, candidate, inactive, or unknown, derives stricter controls where proven contexts intersect, and produces a Control Evaluation Ledger instead of treating silence as safety.

```text
Generic security skill

"Check this Next.js app."
        ↓
OWASP / generic checks


ContextSec

"What is this Next.js app actually doing?"
        ↓
B2B SaaS
+ PII
+ Stripe
+ file upload
+ OpenAI
+ multi-tenant
+ customer support admin
        ↓
classify control applicability
+ derive cross-context invariants
        ↓
generate / review / test
        ↓
Control Ledger + evidence + release gate
```

**Status:** research preview `v0.4.0`. Local-first, read-only profiling, no source upload, no target-code execution, and no third-party runtime dependency.

**Versioning:** Tool, detector, checker, and artifact-schema versions are independent and each has one canonical file. Their semantic model digests bind the behavior and dependencies that affect each artifact while ignoring comments and formatting.

## The decision pipeline

![ContextSec decision flow: product evidence becomes a bounded profile, applicable controls, and an evidence-backed release gate.](docs/assets/contextsec-decision-flow.svg)

The diagram is a dependency-free, editable [SVG source](docs/assets/contextsec-decision-flow.svg); every label and shape remains reviewable in Git.

The profiler preserves four distinctions generic security prompts usually blur:

- **Applicability is not vulnerability detection.** A pack can apply even when no bug is found.
- **No finding is not verification.** Unchecked controls remain `unknown` in the ledger.
- **Inference confidence is not impact.** Weak evidence for a context and critical impact of a broken control are separate fields.
- **Pack co-occurrence is not a data flow.** AI + PII or payment + tenancy starts as a candidate composition; direct intersection evidence makes the derived invariant required.

## 90-second demo

The included fixture is an intentionally incomplete Next.js invoice SaaS with Stripe, PII, tenancy, S3 uploads, and OpenAI:

```bash
python .agents/skills/contextsec/scripts/contextsec.py profile \
  --repo examples/composite-saas \
  --format markdown

python .agents/skills/contextsec/scripts/contextsec.py check \
  --repo examples/composite-saas

python .agents/skills/contextsec/scripts/contextsec.py gate \
  --repo examples/composite-saas
```

The current deterministic result is intentionally uncomfortable:

```text
required      foundation · baseline-web · auth-session · payments · privacy-pii
              multi-tenant · api-inbound · external-api · file-upload · ai-rag-agent

required      AI+PII · AI+tenant · API+tenant intersections
candidates    payment+tenant · upload+tenant intersections

checks        5 failed · 1 unknown · 0 verified
ledger        every applicable control represented; unchecked controls stay unknown
gate          BLOCK
```

The same framework does not select everything for every repository:

| Scope | Required packs |
|---|---|
| `examples/next-static` | `foundation`, `baseline-web` |
| `tests/fixtures/secret-plane` | `foundation`, `secrets-management` |
| `tests/fixtures/cicd-supply` | `foundation`, `cicd-supply-chain` |
| `examples/composite-saas` | the ten directly applicable/dependency-routed original product packs |

Explain a decision without reading every pack:

```bash
python .agents/skills/contextsec/scripts/contextsec.py explain payments
python .agents/skills/contextsec/scripts/contextsec.py explain COMP-AI-TEN-001
python .agents/skills/contextsec/scripts/contextsec.py explain payments --repo examples/composite-saas
```

## What is machine-verifiable now

### Security Profile

The profiler emits versioned observations, claims, routing, contradictions, and coverage. Evidence includes:

- `evidence_id`: stable identity for detector + location;
- `location_id`: stable identity for repository-relative location;
- `path_identity`: full canonical identity derived from the raw repository-relative path, independent of its display policy;
- `content_digest`: whole-file integrity digest;
- `fingerprint`: evidence identity bound to the content digest;
- `subject_revision`: the bounded repository scope plus active routing model evaluated by this run;
- `source_inventory_digest`: the exact supported production file inventory shared by profiler and checker, used to reject mid-evaluation source changes.
- `source_provenance`: a canonical Git origin, full commit, and clean/dirty worktree state; only all-three verified can bind a Profile to a frozen external case.

These hashes are integrity identifiers, not secrecy mechanisms. ContextSec never emits matched source lines or source-content values. Repository-relative filenames use bounded heuristic redaction by default and may themselves contain personal data; use `--path-privacy hashed` or `--path-privacy opaque` when filenames are sensitive. Those modes are deterministic pseudonymization, not secrecy: low-entropy filenames can still be guessed by hashing candidate paths. The selected policy is explicit in `artifact_options.path_privacy` and never changes canonical path identity.

### Pack and control catalog

[The machine-readable catalog](.agents/skills/contextsec/references/catalog.json) is the single source for pack order, claims, dependencies, per-control `applies_when` conditions, 16 risk packs, and 116 controls. Its [JSON Schema](.agents/skills/contextsec/references/catalog.schema.json) and semantic validator reject malformed fields—including string values masquerading as booleans. Human-readable pack files add implementation and verification guidance.

The [machine-readable support matrix](.agents/skills/contextsec/references/support-matrix.json) and its [JSON Schema](.agents/skills/contextsec/references/support-matrix.schema.json) define profiler/checker manifests, suffixes, framework families, coverage semantics, and the ten published deterministic checker families. `contextsec doctor` reports that complete contract plus the separate routing, detector, checker, catalog, composition, and support-matrix digests.

### Composition engine

[Nine composition rules](.agents/skills/contextsec/references/compositions/catalog.json) become candidates when contexts coexist and become required only when an intersection capability or deterministic flow finding is present, including:

- payment + multi-tenant;
- AI + PII and AI + multi-tenant;
- upload + multi-tenant and API + multi-tenant;
- support/admin + multi-tenant;
- SaaS OAuth + PII;
- CI/CD + cloud IAM;
- AI + high-impact transactions.

### Monorepo component model

A monorepo is not treated as one blended application. `profile-components` consumes an explicit component model, rejects duplicate or overlapping roots, unknown dependencies, dependency cycles, and flows with unknown endpoints, then emits one independently source-bound Profile per component plus declared cross-component flows. The aggregate artifact binds the component manifest digest and each component Profile digest.

```bash
python .agents/skills/contextsec/scripts/contextsec.py profile-components \
  --repo . \
  --components component-model.json \
  --output component-profile.json

python .agents/skills/contextsec/scripts/contextsec.py validate-component-profile \
  component-profile.json
```

Cross-component flow declarations require named capabilities and evidence references; they do not silently convert component co-location into a proven data flow.

### Control Evaluation Ledger and release gate

Every active control receives:

```text
evaluation_date · control_id · applicability · verification · severity · blocking
evidence_refs · required_verification · reason · waiver
```

`applicability` is one of `required`, `candidate`, `not_applicable`, or `unknown`.
`verification` is independently one of `verified`, `failed`, `unknown`, or
`waived`. This prevents “not relevant here” from being confused with “security
tested and passed.”

The gate semantics are strict:

- `PASS`: all blocking required controls are verified;
- `WARN`: only non-blocking or candidate gaps remain;
- `BLOCK`: a blocking control failed, is unknown, traversal is partial, or profiler stack support is partial/unsupported;
- `WAIVED`: every blocker has a named owner, reason, compensating control, and unexpired waiver evaluated against an explicit date. Consumers must run `contextsec.py validate-ledger <ledger> --as-of <release-date>` so an old waiver artifact cannot be replayed.

## Product-risk packs

| Plane | Pack | Representative decisions |
|---|---|---|
| Universal | `foundation` | trust boundaries, server authority, secrets, dependency trust, fail-safe evidence |
| Application | `baseline-web` | browser output, CSRF, cookies, caching, admin surface |
| Identity | `auth-session` | sessions, OAuth/OIDC, recovery, tokens, step-up |
| Money | `payments` | trusted price/state, webhook authenticity, replay, payout authority |
| Data | `privacy-pii` | inventory, minimization, access, processors, lifecycle, data fan-out |
| Isolation | `multi-tenant` | DB, cache, object, async, search, and support tenant boundaries |
| Inbound | `api-inbound` | object/function/property authority, schemas, budgets, token intent |
| Outbound | `external-api` | destination trust, egress, provider failure, response trust, TLS |
| Content | `file-upload` | type, name, size, storage, parser isolation, download, scanner failure |
| AI | `ai-rag-agent` | indirect injection, RAG ACL, tools, memory, output trust, autonomy |
| Secrets plane | `secrets-management` | value read, bulk export, scope, rotation, cascade, detection, audit |
| Cloud authority | `cloud-iam-controlplane` | human admin, workload identity, lateral trust, audit, management network |
| Delivery | `cicd-supply-chain` | immutable actions, token permissions, fork isolation, OIDC, provenance |
| Connected SaaS | `third-party-saas-oauth` | grant inventory, scope, token lifecycle, vendor blast radius, export |
| Operations | `support-admin-ops` | JIT access, case reason, masking, bulk limits, impersonation, audit |
| Irreversible action | `high-impact-transactions` | intent binding, fresh state, recipient, step-up, limits, dual control, replay |

This is the strategic boundary: OWASP and specialist tools explain security rules and find classes of flaws. ContextSec decides which product-risk invariants must be active, composes them, and tracks whether the required evidence exists.

## Install as an agent skill

The canonical skill is [.agents/skills/contextsec](.agents/skills/contextsec).

- Agent Skills-compatible tools can load `SKILL.md` directly.
- Keep it repository-local at `.agents/skills/contextsec`.
- Copy the same folder to `.claude/skills/contextsec` for Claude Code.
- Copy it to `$HOME/.agents/skills/contextsec` for a user-level Codex installation.

Use natural requests:

```text
Use $contextsec to derive security requirements for this PRD.
Use $contextsec while implementing this subscription webhook.
Use $contextsec to review this diff for newly activated product risks.
Use $contextsec to evaluate release evidence and return the Control Ledger and gate.
```

The skill is the orchestration layer; `catalog.json`, composition rules, schemas, profiler, checks, and tests remain shared artifacts rather than platform-specific prompt copies.

### Cross-platform quick start

ContextSec has a zero-dependency Python runtime. CI runs the full test suite and public benchmark CLI on Windows, macOS, and Ubuntu with Python 3.11–3.14.

```bash
python .agents/skills/contextsec/scripts/contextsec.py --version
python .agents/skills/contextsec/scripts/contextsec.py doctor
```

#### Windows — PowerShell

```powershell
git clone https://github.com/niansia/ContextSec.git
Set-Location ContextSec
python -m unittest discover -s tests
python .agents\skills\contextsec\scripts\contextsec.py benchmark --suite all
```

Optional user-level Codex installation, using the [official Codex user-skill location](https://developers.openai.com/codex/skills#where-codex-loads-local-skills):

```powershell
$destination = Join-Path $env:USERPROFILE ".agents\skills\contextsec"
New-Item -ItemType Directory -Force -Path $destination | Out-Null
Copy-Item -Recurse -Force ".agents\skills\contextsec\*" $destination
```

#### macOS — Terminal

```bash
git clone https://github.com/niansia/ContextSec.git
cd ContextSec
python3 -m unittest discover -s tests
python3 .agents/skills/contextsec/scripts/contextsec.py benchmark --suite all
```

Optional user-level Codex installation:

```bash
mkdir -p ~/.agents/skills/contextsec
cp -R .agents/skills/contextsec/. ~/.agents/skills/contextsec/
```

#### Linux — shell

```bash
git clone https://github.com/niansia/ContextSec.git
cd ContextSec
python3 -m unittest discover -s tests
python3 .agents/skills/contextsec/scripts/contextsec.py benchmark --suite all
```

Optional user-level Codex installation:

```bash
mkdir -p ~/.agents/skills/contextsec
cp -R .agents/skills/contextsec/. ~/.agents/skills/contextsec/
```

For repository-local use in another project, copy the canonical folder to that repository's `.agents/skills/contextsec`; Claude Code users can use `.claude/skills/contextsec` instead. Keep one canonical copy rather than maintaining platform-specific prompt forks.

## Benchmark and incident corpus

Run every offline benchmark suite:

```bash
python .agents/skills/contextsec/scripts/contextsec.py benchmark --suite all
```

v0.4 keeps evidence classes separate:

| Suite | Scope | Current result | What it does **not** prove |
|---|---:|---:|---|
| Authored regression | 13 scenarios / 80 annotations | 80/80 | ecosystem accuracy |
| Profile evaluation | 40 cases: 24 development + 16 frozen evaluation | macro F1 1.00; safety trigger recall 1.00; 0 false required activations | independent or representative accuracy |
| Mutation verification | 10 single-edit pairs covering all 10 published checker shapes | 10/10 killed | coverage of all 116 controls or application tests |
| Pinned real repositories | 4 exact public commits | 4/4 expected profiles reproduced | a statistically representative sample |
| Adversarial performance | 6 generated pathological files at 500 KiB each | bounded runtime, offset preservation, non-disclosure, fail-closed malformed TOML | universal CPU bounds on every machine |

The profile labels are maintainer-authored, including the frozen evaluation split. The real-repository suite requires existing local checkouts, verifies `HEAD`, and never clones or executes target code. The [independent evaluation protocol](docs/external-evaluation-protocol.md) excludes all ContextSec contributors, requires reviewers from distinct organizations, freezes labels before tool output, discloses conflicts, and retains disagreements. `support_class` is derived from each commit-bound Profile rather than trusted from a manifest. `evaluate-holdout` is headline-eligible only when signer-constrained GitHub attestations verify both artifacts and trusted timestamps prove labels predate predictions; unsigned runs require an explicit development flag and are marked `development-only`. See the [benchmark method](docs/benchmark-methodology.md) and [real-repository cases](docs/real-repo-cases.md).

Exact verification coverage is public and deliberately non-inflated:

```bash
python .agents/skills/contextsec/scripts/contextsec.py verification-coverage
```

Every one of the 116 catalog controls and nine composition controls is classified as either `automated` or `evidence-required`. `automated` means a supported deterministic checker or repository-policy audit exists; it never means that a control passed for a particular repository.

The [incident corpus](incidents) stores confirmed facts separately from ContextSec inferences and maps each case to trust boundaries, controls, and a proposed regression mutation. It currently includes Zeabur's ongoing 2026 investigation, tj-actions, Coinbase support insiders, Salesloft Drift OAuth abuse, and an NPM→GitHub OIDC→AWS control-plane pivot.

## Safety properties

- Parses bounded local text; never imports, builds, tests, or executes target code.
- Never uses the network during profiling, checks, benchmark, or ledger evaluation.
- Ignores repository symlinks and common dependency/generated directories. POSIX traversal is anchored to an opened root descriptor and walks link-rejecting directory descriptors; Windows rejects reparse parents and verifies final handle containment beneath the opened root. Files are identity-checked before and after bounded reads; concurrent replacement or mutation becomes partial coverage.
- Documentation, examples, fixtures, tests, non-workflow GitHub governance files, and development-only dependencies cannot create production claims.
- Uses language-aware lexical policies so JavaScript `n--` and `#private`, Python f-string replacement fields, PostgreSQL hash operators, and MySQL no-space subtraction remain executable while supported comment forms are masked.
- Separates template-literal prose from executable `${...}` expressions.
- Reports `partial` traversal coverage for read, byte, encoding, or manifest gaps, and separately reports supported, partial, or unsupported stack coverage.
- Parses `.env`-family files as key names only: values are discarded before hashing, evidence generation, or artifact output.
- Supports `heuristic`, `hashed`, and `opaque` path-privacy modes across Profile, Checks, and Ledger artifacts and records the mode in artifact metadata.
- Reports checker traversal, language support, checker support, and match enumeration separately.
- Reads owner declarations only when explicitly supplied; declarations cannot erase contradictory code evidence.
- Does not modify target source or configuration. Runtime bytecode writes are disabled; artifacts are written only to an explicitly supplied output path.
- Never calls an applicability decision a penetration test or compliance certification.

## Validate locally

```bash
python -m unittest discover -s tests -v
python -m compileall -q .agents/skills/contextsec/scripts tests
python .agents/skills/contextsec/scripts/contextsec.py validate-catalog
python .agents/skills/contextsec/scripts/contextsec.py benchmark --suite all
python .agents/skills/contextsec/scripts/audit_ci.py --repo .
python .agents/skills/contextsec/scripts/contextsec.py verification-coverage
python .agents/skills/contextsec/scripts/contextsec.py explain secrets-management --repo .
```

## Honest limitations

- Detectors are strongest for Node.js, Python dependency manifests, Next.js, FastAPI, Django, Prisma, Terraform, and common CI workflow shapes. Other stacks may need manual evidence or future adapters.
- The lexical adapters are deterministic but are not full language parsers. Every detector needs positive/negative twins, and ambiguous evidence remains candidate or unknown.
- Race-resistant descriptor reads reject observed replacement and in-place mutation, but ContextSec does not create an operating-system-wide atomic filesystem snapshot.
- The built-in control checks remain narrow. The exact 125-row verification-coverage artifact distinguishes automated methods from evidence-required controls; neither classification proves a repository passed.
- A verified source provenance binds a clean checkout to its Git commit and canonical origin, but it is not by itself a signature and cannot prove skipped input safe.
- Release evidence supplied by an owner still needs trustworthy test/configuration provenance. The ledger records the assertion; it cannot magically establish its truth.
- Static CI audit evidence deliberately leaves release provenance `unknown`; a specific tag run must build, attest, publish a draft, re-download it, and verify its checksums and attestations before publication.
- Standards mappings are navigation aids. ContextSec does not certify PCI DSS, GDPR, HIPAA, SOC 2, or any other compliance state.
- No claim of global novelty is made. The testable product claim is evidence-backed product-risk routing, composition, and control evaluation for coding agents.

## Roadmap

1. **v0.2–v0.3 — deterministic decision proof:** applicability correctness, evidence identity, mutation coverage, reproducible packages, complete CI proof, and fail-closed release attestation verification.
2. **v0.4 — trust-closure contracts:** independent tool/detector/checker versions, semantic model digests, clean commit-bound Profiles, explicit monorepo components, strict external-review independence, attestation-gated holdouts, exact verification coverage, and exact-main immutable release evidence.
3. **Next — collect external ground truth:** qualified third parties must populate the already-frozen protocol; comparative agent studies and broader checker/framework coverage remain future evidence, not current claims.

Read [architecture](docs/architecture.md), [competitive positioning](docs/competitive-positioning.md), [v0.2.1 review resolution](docs/review-resolution-v0.2.1.md), and [release roadmap](docs/roadmap.md) before proposing a large feature.

## Contributing and security

Contributions are welcome, especially small detector twins, framework adapters, incident-to-regression maps, and mutation-backed controls. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue. Research users can cite the project with [`CITATION.cff`](CITATION.cff).

Apache-2.0 licensed. Control wording is original; external standards and incident sources are used for navigation and evidence, not copied as a checklist.
