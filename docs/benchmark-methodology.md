# Benchmark methodology

## Claim boundary

ContextSec v0.3 reports three quantitative result families and one case-study family. They are never pooled into one headline score.

1. **Authored regression:** exact expectations for known detector, applicability, composition, and gate behavior.
2. **Profile evaluation:** fully labeled synthetic repositories, including a frozen evaluation split that was still authored by the maintainer.
3. **Mutation verification:** paired source/configuration variants that remove one supported security property.
4. **Pinned real repositories:** manually reviewed public projects at exact commits.

The first three prove repeatability within a published support matrix. The fourth tests scale, noisy layouts, and provenance. None is an independently sampled ecosystem benchmark.

## Profile metrics

Every profile case labels its complete set of required and candidate packs. Required-pack classification is evaluated over all 16 packs per case.

- **Micro precision/recall/F1:** aggregate binary required/not-required decisions.
- **Macro F1 with positive support:** mean F1 only over packs with at least one expected positive, so unused all-negative packs do not inflate the result.
- **Exact set accuracy:** repositories whose entire required set matches.
- **Safety-critical trigger recall:** recall over explicitly named critical packs.
- **False required activation count:** absolute number of unexpected mandatory packs; candidates are reported separately.
- **Capability annotation accuracy:** exact state over the small explicitly annotated sub-capability subset.

The v0.3 gates are macro F1 ≥ 0.90, safety-critical recall 1.00, zero false required activations, and capability annotation accuracy 1.00. Current perfect fixture results are regression facts about this corpus, not evidence that unseen repositories will be perfect.

## Mutation protocol

Each mutation pair contains the minimum production files needed to activate one supported checker. The baseline and mutant differ by one relevant edit. A mutation is killed only if:

1. the target checker emits no finding on the baseline;
2. the mutant emits exactly one target finding;
3. the finding has the expected `failed` or `unknown` state; and
4. the finding binds the expected catalog control IDs.

The ten v0.3 mutations cover tenant predicates, tenant raw-query abstention, broad PII logging, whole-object AI egress, client-public secret namespaces, public upload ACLs, tenant-derived object keys, webhook idempotency evidence, immutable Action references, and explicit workflow permissions. A 100% score means 10/10 supported shapes changed as expected. It does not mean 116/116 controls have checkers.

## Leakage and provenance

Inline fixture paths are validated before materialization and cannot be absolute or contain traversal. Fixtures are written only to an operating-system temporary directory. The benchmark never imports or executes their code.

Real-repository labels, URLs, licenses, and full commit IDs live in `benchmarks/real-repos.json`. The runner requires pre-existing local checkouts and verifies `HEAD`; there is no automatic clone path. Subject revisions bind the actual bounded file inventory evaluated in that run.

## Next validity step

The next meaningful accuracy claim requires labels from reviewers who did not implement the detector, a declared sampling frame, disagreements retained rather than silently reconciled, and results reported separately by framework and pack support. Until then, v0.3 remains a research preview.
