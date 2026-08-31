<p align="center">
  <img src="docs/assets/contextsec-hero.svg" width="100%" alt="ContextSec — know what security controls apply and prove what passed. Research preview v0.4.1." />
</p>

<p align="center">
  <a href="README.md"><strong>English</strong></a> ·
  <a href="docs/i18n/README.zh-TW.md">繁體中文</a> ·
  <a href="docs/i18n/README.zh-CN.md">简体中文</a> ·
  <a href="docs/i18n/README.ja.md">日本語</a>
</p>

<p align="center">
  <a href="https://github.com/niansia/ContextSec/actions/workflows/ci.yml"><img alt="CI status" src="https://github.com/niansia/ContextSec/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="https://github.com/niansia/ContextSec/releases/tag/v0.4.1"><img alt="Release v0.4.1" src="https://img.shields.io/badge/release-v0.4.1-d95d39" /></a>
  <a href="LICENSE"><img alt="Apache-2.0 license" src="https://img.shields.io/github/license/niansia/ContextSec" /></a>
  <img alt="Python 3.11 through 3.14" src="https://img.shields.io/badge/python-3.11–3.14-2563eb" />
  <img alt="Research preview" src="https://img.shields.io/badge/status-research%20preview-7048b8" />
</p>

## Security controls that match the product—not a generic checklist

**Your coding agent knows security rules. ContextSec tells it which ones this product actually needs, then keeps missing proof visible.**

ContextSec reads bounded repository evidence, identifies product contexts such as payments, PII, tenancy, AI, uploads, CI/CD, cloud authority, and support access, then produces applicable controls and an evidence-backed release gate. It does not upload source, execute target code, or turn “no finding” into “verified.”

| Decide | Compose | Prove |
|---|---|---|
| Route only the product-risk packs supported by evidence. | Derive stricter invariants when proven contexts intersect. | Record every applicable control as `verified`, `failed`, `unknown`, or `waived`. |

ContextSec is an applicability and evidence layer—not a penetration test, general vulnerability scanner, or compliance certification.

## Try it in 60 seconds

Requirements: Git and Python 3.11–3.14. The runtime has zero third-party dependencies. The included fixture is an intentionally incomplete Next.js invoice SaaS, so the expected gate result is `BLOCK`.

### Windows — PowerShell

```powershell
git clone https://github.com/niansia/ContextSec.git
Set-Location ContextSec
python --version  # must report Python 3.11–3.14
python .agents/skills/contextsec/scripts/contextsec.py doctor
python .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

### macOS — Terminal

```bash
git clone https://github.com/niansia/ContextSec.git
cd ContextSec
python3 --version  # must report Python 3.11–3.14
python3 .agents/skills/contextsec/scripts/contextsec.py doctor
python3 .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python3 .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python3 .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

### Linux — shell

```bash
git clone https://github.com/niansia/ContextSec.git
cd ContextSec
python3 --version  # must report Python 3.11–3.14
python3 .agents/skills/contextsec/scripts/contextsec.py doctor
python3 .agents/skills/contextsec/scripts/contextsec.py profile --repo examples/composite-saas --format markdown
python3 .agents/skills/contextsec/scripts/contextsec.py check --repo examples/composite-saas
python3 .agents/skills/contextsec/scripts/contextsec.py gate --repo examples/composite-saas
```

Expected summary:

```text
required      foundation · baseline-web · auth-session · payments · privacy-pii
              multi-tenant · api-inbound · external-api · file-upload · ai-rag-agent
intersections AI+PII · AI+tenant · API+tenant required
checks        5 failed · 1 unknown · 0 verified
gate          BLOCK — unchecked required controls remain visible
```

The final command deliberately exits with status `1` because the fixture's release gate is blocked. The same engine routes only `foundation` and `baseline-web` for the included static Next.js example. It does not select every pack for every repository.

Ready to try your own code? Keep this checkout open and replace `examples/composite-saas` with the absolute path to your repository; start with `profile`, review the evidence, then run `check` and `gate`.

## What v0.4.1 means

This is not a v0.1-shaped prototype with a newer badge. The current immutable release contains:

| Area | Shipped and continuously checked |
|---|---|
| Decision model | 16 product-risk packs, 116 catalog controls, and 9 cross-context composition controls |
| Verification model | Exact 125-row coverage inventory; 21 rows have a deterministic checker or repository-policy audit |
| Deterministic checks | 10 published checker families with positive, negative, mutation, and adversarial regressions |
| Platform proof | Windows, macOS, and Ubuntu × Python 3.11–3.14 |
| Repository evidence | 40 frozen profile cases plus 4 commit-pinned public-repository cases |
| Release integrity | Exact-reviewed-main tags, byte-identical archives, three signed assets, draft re-download verification, and immutable Releases |

The research-preview label remains because independent ecosystem accuracy has not yet been established. That boundary is deliberate; it does not mean the release or its engineering controls are provisional.

## Use it as an agent skill

The canonical skill is [.agents/skills/contextsec](.agents/skills/contextsec). Agent Skills-compatible tools can load its `SKILL.md` directly. Keep it repository-local for the clearest provenance, or install the same folder at user scope.

### Windows — optional user-level Codex installation

```powershell
$destination = Join-Path $env:USERPROFILE ".agents\skills\contextsec"
New-Item -ItemType Directory -Force -Path $destination | Out-Null
Copy-Item -Recurse -Force ".agents\skills\contextsec\*" $destination
```

### macOS and Linux — optional user-level Codex installation

```bash
mkdir -p ~/.agents/skills/contextsec
cp -R .agents/skills/contextsec/. ~/.agents/skills/contextsec/
```

Claude Code users can copy the canonical folder to `.claude/skills/contextsec`. Then ask naturally:

```text
Use $contextsec to derive security requirements for this PRD.
Use $contextsec while implementing this subscription webhook.
Use $contextsec to review this diff for newly activated product risks.
Use $contextsec to evaluate release evidence and return the Control Ledger and gate.
```

## The decision pipeline

![ContextSec decision flow: product evidence becomes a bounded profile, applicable controls, and an evidence-backed release gate.](docs/assets/contextsec-decision-flow.svg)

The profiler keeps four distinctions generic security prompts often blur:

- **Applicability is not vulnerability detection.** A pack can apply even when no bug is found.
- **No finding is not verification.** Unchecked controls remain `unknown` in the ledger.
- **Inference confidence is not impact.** Weak evidence for a context and critical impact of a broken control are separate fields.
- **Pack co-occurrence is not a data flow.** Direct intersection evidence is required before a composition becomes required.

Both diagrams are dependency-free, editable SVG sources whose labels and shapes remain reviewable in Git.

Command notation below uses `python` for brevity. Use `python3` on macOS or Linux, as shown in the copyable quick starts above.

## What is machine-verifiable now

### Security Profile

The profiler emits versioned observations, claims, routing, contradictions, and coverage. Evidence includes:

- `evidence_id`: stable identity for detector + location;
- `location_id`: stable identity for repository-relative location;
- `path_identity`: full canonical identity derived from the raw repository-relative path, independent of its display policy;
- `content_digest`: whole-file integrity digest;
- `fingerprint`: evidence identity bound to the content digest;
- `subject_revision`: the bounded repository scope plus active routing model evaluated by this run;
- `source_inventory_digest`: the exact supported production file inventory shared by profiler and checker, used to reject mid-evaluation source changes;
- `source_provenance`: a canonical Git origin, full commit, and clean/dirty worktree state; identical pre- and post-scan snapshots are required before all-three verified can bind a Profile to a frozen external case.

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

A monorepo is not treated as one blended application. `profile-components` consumes an explicit component model, rejects duplicate or overlapping roots, unknown dependencies, dependency cycles, and flows with unknown endpoints, then emits one independently source-bound Profile per component plus declared cross-component flows. The aggregate artifact binds canonical component roots through full path identities and each component Profile digest, while every displayed root obeys `artifact_options.path_privacy`.

```bash
python .agents/skills/contextsec/scripts/contextsec.py profile-components --repo . --components component-model.json --output component-profile.json
python .agents/skills/contextsec/scripts/contextsec.py validate-component-profile component-profile.json
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

## Benchmark and incident corpus

Run every offline benchmark suite:

```bash
python .agents/skills/contextsec/scripts/contextsec.py benchmark --suite all
```

v0.4.1 keeps evidence classes separate:

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
- Race-resistant descriptor reads reject observed replacement and in-place mutation, and Git provenance must match before and after traversal, but ContextSec does not create an operating-system-wide atomic filesystem snapshot.
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

Start with the [documentation map](docs/README.md), then read [architecture](docs/architecture.md), [competitive positioning](docs/competitive-positioning.md), and the [release roadmap](docs/roadmap.md) before proposing a large feature. Historical review resolutions remain available for auditability.

## Contributing and security

Contributions are welcome, especially small detector twins, framework adapters, incident-to-regression maps, and mutation-backed controls. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue. Research users can cite the project with [`CITATION.cff`](CITATION.cff).

Apache-2.0 licensed. Control wording is original; external standards and incident sources are used for navigation and evidence, not copied as a checklist.
