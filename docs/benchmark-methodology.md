# Benchmark methodology

## Claim boundary

ContextSec v0.4 reports four quantitative result families and one case-study family. They are never pooled into one headline score.

1. **Authored regression:** exact expectations for known detector, applicability, composition, and gate behavior.
2. **Profile evaluation:** fully labeled synthetic repositories, including a frozen evaluation split that was still authored by the maintainer.
3. **Mutation verification:** paired source/configuration variants that remove one supported security property.
4. **Pinned real repositories:** manually reviewed public projects at exact commits.
5. **Adversarial performance:** generated pathological files at the published single-file bound, evaluated for generous runtime ceilings, offset preservation, non-disclosure, and fail-closed malformed input.

The first three prove repeatability within a published support matrix. The fourth tests scale, noisy layouts, and provenance. None is an independently sampled ecosystem benchmark.

## Profile metrics

Every profile case labels its complete set of required and candidate packs. Required-pack classification is evaluated over all 16 packs per case.

- **Micro precision/recall/F1:** aggregate binary required/not-required decisions.
- **Macro F1 with positive support:** mean F1 only over packs with at least one expected positive, so unused all-negative packs do not inflate the result.
- **Exact set accuracy:** repositories whose entire required set matches.
- **Safety-critical trigger recall:** recall over explicitly named critical packs.
- **False required activation count:** absolute number of unexpected mandatory packs; candidates are reported separately.
- **Capability annotation accuracy:** exact state over the small explicitly annotated sub-capability subset.

The regression gates are macro F1 ≥ 0.90, safety-critical recall 1.00, zero false required activations, and capability annotation accuracy 1.00. Current perfect fixture results are regression facts about this corpus, not evidence that unseen repositories will be perfect.

## Mutation protocol

Each mutation pair contains the minimum production files needed to activate one supported checker. The baseline and mutant differ by one relevant edit. A mutation is killed only if:

1. the target checker emits no finding on the baseline;
2. the mutant emits exactly one target finding;
3. the finding has the expected `failed` or `unknown` state; and
4. the finding binds the expected catalog control IDs.

The ten published mutations cover tenant predicates, tenant raw-query abstention, broad PII logging, whole-object AI egress, client-public secret namespaces, public upload ACLs, tenant-derived object keys, webhook idempotency evidence, immutable Action references, and explicit workflow permissions. A 100% score means 10/10 supported mutation shapes changed as expected. It does not mean 116/116 controls have checkers.

`contextsec verification-coverage` enumerates all 116 controls and nine compositions. Every row is `automated` only when a named deterministic checker or repository-policy audit exists; otherwise it is `evidence-required`. This inventory is a method-coverage statement, never a repository pass result.

## Adversarial performance protocol

`benchmarks/adversarial-performance/cases.json` generates six 500 KiB inputs: an unterminated JavaScript string, nested template expressions, SQL comment/operator boundaries, Python f-string boundaries, regex near matches, and malformed multiline TOML. CI uses a deliberately generous per-case ceiling instead of a microbenchmark. Each case must also preserve mask length, omit its seed value from masks and artifacts, and turn malformed manifests into partial coverage rather than a clean result. The ceiling is a regression guard on supported runners, not a universal CPU-time guarantee.

## Leakage and provenance

Inline fixture paths are validated before materialization and cannot be absolute or contain traversal. Fixtures are written only to an operating-system temporary directory. The benchmark never imports or executes their code.

Real-repository labels, URLs, licenses, and full commit IDs live in `benchmarks/real-repos.json`. The runner requires pre-existing local checkouts and verifies `HEAD`; there is no automatic clone path. Subject revisions bind the actual bounded file inventory evaluated in that run. v0.4 Profiles additionally record canonical Git origin, full commit, and worktree cleanliness. A frozen holdout accepts only `verified` provenance matching its exact case URL and commit.

## Next validity step

The next meaningful accuracy claim requires labels from non-contributors at distinct organizations, a declared sampling frame, frozen pre-output labels, conflict disclosure, independent adjudication, and disagreements retained rather than silently reconciled. [`external-evaluation-protocol.md`](external-evaluation-protocol.md) freezes those rules. The evaluator derives support class from commit-bound Profiles and reports raw agreement plus Cohen's κ overall, per pack, and per framework. A result is headline-eligible only when both artifacts have signer-constrained GitHub attestations and the trusted label timestamp predates the prediction timestamp. Until completed third-party evidence exists, ContextSec remains a research preview.
