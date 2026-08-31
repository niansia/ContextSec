# Independent external evaluation protocol

This protocol freezes the v0.4 evidence rules before external labels are collected. It prevents a maintainer-authored regression set from being presented as an independent holdout.

## Required sequence

1. Declare the repository population, selection method, inclusion and exclusion criteria, and freeze date.
2. Freeze every repository at a full 40-character commit before profiling.
3. Assign two reviewers who did not implement ContextSec detectors. Reviewers label every pack independently and before seeing ContextSec output.
4. Preserve `annotator_a` and `annotator_b` verbatim. Store consensus separately with an adjudication reason; never overwrite raw disagreement.
5. Classify each case as supported, partial, or unsupported before reporting results.
6. Report raw agreement and Cohen's κ overall, per pack, and per framework. Do not pool unsupported cases into supported-stack accuracy claims.
7. Only after labels are frozen, run the pinned ContextSec version and compare its output with consensus in a separate result artifact.

The machine template is [`benchmarks/external-review-template.json`](../benchmarks/external-review-template.json). A completed manifest must change `status` to `complete`, add at least one fully labeled case, retain the declared review policy unchanged, and pass:

```bash
python .agents/skills/contextsec/scripts/contextsec.py external-review completed-external-review.json
```

ContextSec ships the protocol and evaluator, not fabricated external labels. Until qualified third parties contribute completed cases, the project must continue to describe its existing labels as maintainer-authored regression evidence.
