# Architecture

ContextSec is an applicability layer for product security decisions. It is not a SAST engine, compliance assessor, or autonomous remediation service.

## Data flow

```text
bounded repository files
        |
        v
clean Git source identity ---- deterministic observations ---- caller-supplied declarations
        |                                  |
        +--------------+-------------------+
                       v
              versioned claims
      present | absent | unknown | contradicted
                       |
                       v
              explainable routing
       required | candidate | inactive | unknown
                       |
                       v
       catalog dependencies + sub-capabilities
                       |
                       v
      per-control applicability + flow intersections
                       |
                       v
      checks + supplied verification evidence
                       |
                       v
              Control Evaluation Ledger
                       |
                       v
            PASS | WARN | BLOCK | WAIVED
```

For the published support matrix, a separate deterministic checker consumes the profile and emits narrow `failed` or `unknown` control evidence. The ledger then enumerates every applicable catalog control. It never treats an unreported pattern as `verified`.

Tool, detector, checker, and artifact-schema versions advance independently. Dependency-aware semantic digests bind the executable symbols and data contracts that affect each model while ignoring comments and formatting, so harmless source edits do not invalidate evidence and behavior changes cannot hide behind an unchanged marketing version.

## Source and component identity

A single-repository Profile records a canonical Git origin, full commit, and worktree state. `verified` means all three are available and the worktree is clean; `dirty` and `unavailable` remain explicit. This is local source provenance, not a cryptographic signature.

For monorepos, an explicit component model declares non-overlapping repository-relative roots, component kinds, acyclic dependencies, and evidence-referenced cross-component flows. ContextSec profiles each component root independently while binding every child Profile to the repository's common Git identity. The aggregate component artifact binds the model digest and child Profile digests. Co-location never proves a cross-component flow.

## Trust classes

1. **Deterministic observation:** produced by a versioned detector over a bounded production file. It can support an inferred claim.
2. **Caller declaration:** supplied explicitly through the invocation or `--context`. It can add applicability, but cannot suppress contradictory repository evidence.
3. **Repository prose:** comments, README, PRD, issue text, and generated reports. It is untrusted data and never controls deterministic routing.
4. **Semantic interpretation:** an agent may use it to identify a candidate or a question. It cannot independently verify or disable a high-impact control.

## Observation contract

Each observation contains:

- a full stable observation and `evidence_id` derived from detector, canonical path identity, locator, and detector-model digest;
- a kind, target claim, pack, production scope, confidence, evidence family, and correlation group;
- detector ID and version;
- a display-policy repository-relative path, separate full `path_identity`, and locator;
- a stable `location_id`, whole-file `content_digest`, content-bound `fingerprint`, and profile `subject_revision`.

The full IDs support comparison; the digest/fingerprint detect source change. Hashes are integrity identifiers, not secrecy. The artifact does not contain matched source text, source-content values, environment contents, or absolute local paths. `.env`-family files are reduced to key names before content hashing or observation generation; values never become evidence material. Repository-relative filenames use bounded heuristic redaction by default, so filenames can still carry personal data. `hashed` and `opaque` remove direct text but remain guessable deterministic pseudonyms for low-entropy paths. `artifact_options.path_privacy` declares the policy, while canonical path identity remains independent of display.

## Claim semantics

- `present`: production evidence or a direct caller declaration says the context applies.
- `absent`: only an explicit declaration can currently establish absence.
- `unknown`: the bounded scan did not establish presence or absence.
- `contradicted`: a declaration conflicts with observed production evidence.

Inference confidence describes the evidence behind a claim. Medium signals become high only across distinct evidence families, correlation groups, and source locations; a dependency plus an import of the same SDK stays correlated. Confidence is never a risk or assurance score.

## Routing semantics

- `required`: a universal foundation, a direct declaration, high-confidence evidence (including evidence that contradicts a negative declaration), or a dependency of another required pack.
- `candidate`: partial evidence, a medium-confidence contradiction, or a dependency of another candidate.
- `inactive`: explicit absence without contradictory production evidence.
- `unknown`: no reliable applicability or absence evidence.

Dependencies create security work; they do not prove an implementation exists. `references/catalog.json` is the only machine-readable source for dependency routing.

## Composition semantics

When every pack in a composition is active, the derived control is emitted as a `candidate`. It becomes `required` only when the named `intersection_capability` is observed or a deterministic finding proves the flow. A PII-bearing product that sends only public documentation to an LLM therefore does not automatically require the AI+PII control. Composition controls express cross-boundary invariants that are stricter than concatenating two pack checklists.

## Ledger semantics

Each active-pack control and active composition becomes exactly one ledger row. `applicability` (`required`, `candidate`, `not_applicable`, `unknown`) and `verification` (`verified`, `failed`, `unknown`, `waived`) are independent dimensions. Catalog `applies_when` rules use detected sub-capabilities to avoid irrelevant blockers. Findings force applicability to `required`; a `failed` deterministic finding cannot be overridden by a supplied `verified` assertion. `verified` and `failed` require evidence references. Waivers require owner, reason, compensating control, expiry, and an explicit deterministic `as-of` date. The ledger records that date, while validation of any waiver-bearing artifact requires the intended release date as an external input to prevent replay.

The profiler runs once per repository evaluation. Its `subject_revision`, repository label, source provenance, optional component identity, artifact options, traversal coverage, stack support, and active packs must match the checker artifact before the ledger accepts it. Routing, detector, checker, catalog, composition, and support-matrix digests are bound separately. Profile and finding IDs, location IDs, evidence IDs, and fingerprints are recomputed for internal consistency.

## Verification coverage and signed evaluation

The coverage registry enumerates every catalog control and composition as `automated` or `evidence-required`, with named automated methods. It reports method availability only. Per-repository verification still comes from bound checker/policy findings or supplied evidence and defaults to `unknown`.

External review labels never supply support class; it is derived from each matching Profile. A holdout result is publishable only after the label and prediction files pass signer-workflow-constrained online artifact-attestation verification and trusted timestamps prove labels predate predictions. Explicitly allowed unsigned runs remain development-only. Release evidence uses the same fail-closed pattern: exact `main` commit, full CI proof, immutable-release precondition, model identities, coverage digest, and archive digest are emitted together and covered by source-commit- and signer-constrained attestations before publication.

## Deterministic-core invariants

- No target import, code execution, package script, build, migration, scanner, or test.
- No network access.
- No following of repository symlinks. Every selected input is opened by descriptor, its opened identity must equal the pre-open `lstat` identity, and descriptor metadata must remain stable through the read; observed replacement or mutation fails closed as partial coverage.
- Bounded file count, single-file bytes, and total bytes.
- Production dependency scope is distinct from development dependencies.
- Lexical comment/string policy is selected by language; JavaScript does not inherit SQL `--` or Python/YAML `#` comments.
- Documentation, tests, fixtures, examples, dependencies, and generated output do not drive production claims.
- Stable ordering and no implicit timestamps, so the same byte-identical scope and explicit inputs yield the same profile or ledger.
- Errors and limits become explicit limitations or non-zero process exits, never a pass.
- Coverage has separate dimensions: unreadable, invalid, binary, or bounded-out production input makes traversal `partial`; the detected stack is independently `supported`, `partial`, or `unsupported`. Any non-supported dimension prevents a release pass.

ContextSec does not claim to create an operating-system-wide atomic filesystem snapshot. The descriptor checks close the check-then-read symlink/reparse race and detect ordinary in-place mutation, but a repository under active adversarial local mutation should still be evaluated from an isolated, immutable checkout.

## Why packs are not the moat

The pack Markdown is replaceable guidance. The defensible assets are the versioned claim/evidence model, machine-readable product-risk catalog, deterministic fact graph, explainable applicability traces, composition invariants, Control Ledger, incident-to-regression maps, and adversarial benchmark. New packs must reuse these contracts rather than add another independent checklist.
