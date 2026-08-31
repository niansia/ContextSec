# Independent external evaluation protocol

This protocol freezes the v0.4 evidence rules before external labels are collected. It prevents a maintainer-authored regression set from being presented as an independent holdout.

## Required sequence

1. Declare the repository population, selection method, inclusion and exclusion criteria, and freeze date.
2. Freeze every repository at a full 40-character commit, record its SPDX license and HTTPS license evidence, selection rank/reason, and freeze date before profiling.
3. Assign two reviewers who are not ContextSec contributors and come from distinct organizations. Record organization, expertise, an empty-or-explicit conflict disclosure, and the time labels were frozen. Reviewers label every pack independently before seeing ContextSec output.
4. Preserve `annotator_a` and `annotator_b` verbatim. Store consensus separately with an adjudication reason and a named adjudicator who is neither reviewer, is from neither reviewer's organization, is not a ContextSec contributor, and has disclosed conflicts; never overwrite raw disagreement.
5. Do not label a case `supported`, `partial`, or `unsupported` in the review manifest. The evaluator derives support class from the frozen Profile's traversal and language support so the party supplying labels cannot choose the headline denominator.
6. Report raw confusion counts, label prevalence, agreement, and Cohen's κ overall, per pack, and per framework. Degenerate single-category κ is `null`, not perfect agreement. Do not pool unsupported cases into supported-stack accuracy claims.
7. Only after labels are frozen, run the pinned ContextSec version and compare its output with consensus in a separate result artifact.

The machine template is [`benchmarks/external-review-template.json`](../benchmarks/external-review-template.json). A completed manifest must change `status` to `complete`, add at least one fully labeled case, retain the declared review policy unchanged, and pass:

```bash
python .agents/skills/contextsec/scripts/contextsec.py external-review completed-external-review.json
```

After review and consensus are frozen, create a separate prediction artifact containing the exact Profile for each case plus independent tool, detector, checker, and schema versions; the tool commit; and routing, detector, checker, catalog, composition, and support-matrix digests. Every Profile must report verified source provenance whose canonical repository and full commit exactly match the frozen case.

For a publishable result, attest the labels and predictions independently and verify both online while evaluating:

```bash
python .agents/skills/contextsec/scripts/contextsec.py evaluate-holdout \
  completed-external-review.json \
  completed-holdout-predictions.json \
  --labels-attestation-repo owner/labels-repository \
  --predictions-attestation-repo owner/predictions-repository \
  --labels-signer-workflow https://github.com/owner/labels-repository/.github/workflows/attest.yml \
  --predictions-signer-workflow https://github.com/owner/predictions-repository/.github/workflows/attest.yml
```

Both signer-workflow identities are mandatory for a publishable result, so a different workflow in the same repository cannot silently become the evidence issuer. The verified transparency-log timestamp for the frozen label artifact must also predate the prediction artifact's verified timestamp. A local unsigned analysis is available only with `--allow-unsigned-development`; its result is `development-only` and `headline_eligible` is false.

The accuracy report includes required and candidate precision/recall/F1, false-required count, exact label/required/candidate set accuracy, safety-critical required recall, per-pack results, per-framework results, and separately derived supported/partial/unsupported aggregates. Only an attestation-verified result's `supported_aggregate` is eligible for a supported-stack accuracy claim.

ContextSec ships the protocol and evaluator, not fabricated external labels. Until qualified third parties contribute completed cases, the project must continue to describe its existing labels as maintainer-authored regression evidence.
