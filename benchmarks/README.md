# ContextSec benchmarks

ContextSec keeps five evidence classes separate so a regression pass cannot be presented as general accuracy.

| Manifest | Purpose | Network or target execution |
|---|---|---|
| `scenarios.json` | 13 repository regression scenarios with 80 explicit pack, control, composition, and gate annotations | none |
| `profile-cases.json` | 40 inline repositories split into 24 development and 16 frozen evaluation cases | none |
| `mutations.json` | 10 baseline/mutant pairs, one for every published deterministic checker shape | none |
| `real-repos.json` | 4 public repositories pinned to full commit IDs and manually reviewed labels | no automatic network; target code is never executed |
| `adversarial-performance/cases.json` | 6 generated pathological 500 KiB inputs with runtime, offset, disclosure, and fail-closed assertions | none |

Run the offline suites:

```bash
python .agents/skills/contextsec/scripts/contextsec.py benchmark --suite all
```

Run one suite:

```bash
python .agents/skills/contextsec/scripts/contextsec.py benchmark --suite regression
python .agents/skills/contextsec/scripts/contextsec.py benchmark --suite profile
python .agents/skills/contextsec/scripts/contextsec.py benchmark --suite mutation
python .agents/skills/contextsec/scripts/contextsec.py benchmark --suite adversarial
```

The real-repository suite accepts a directory whose immediate children match each manifest `directory`. It verifies each checkout's `HEAD` before profiling:

```bash
python .agents/skills/contextsec/scripts/contextsec.py benchmark \
  --suite real-repo \
  --workspace /path/to/pinned-checkouts
```

The runner does not clone repositories. Fetching the public sources is an explicit preparation step outside ContextSec's no-network profiler boundary.

## Metric interpretation

The profile suite reports micro precision/recall/F1, macro F1 over packs with positive support, exact required/candidate set accuracy, safety-critical trigger recall, capability annotation accuracy, and the absolute count of false required activations. Unannotated required-pack states are treated as negatives in this fully labeled synthetic corpus.

The mutation score counts a mutation as killed only when the target finding is absent in the baseline, appears exactly once in the mutant with its expected status, and binds the expected control IDs. It covers ten checker shapes, not 116 controls.

The frozen evaluation cases were authored by the maintainer and are not an independent holdout. The four real repositories are case studies, not a representative sample. Results must retain those qualifications when quoted.

The v0.4 external-label template is `external-review-template.json`. It intentionally contains no cases. A valid completed artifact requires two non-implementer reviewers, raw labels for every pack, separate consensus and adjudication, a frozen sampling frame, and full commit IDs; `scripts/contextsec.py external-review` reports agreement without erasing disagreement.
