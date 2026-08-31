# Contributing

ContextSec values small, reproducible evidence over large checklists.

## Good first contributions

- a production-vs-decoy detector fixture;
- a framework-specific observation adapter;
- a false-positive or false-negative regression case;
- a control mutation that proves whether a security test is effective;
- a source/version correction in `SOURCES.md`.

## Requirements

1. Keep the canonical skill under `.agents/skills/contextsec`; do not duplicate pack logic for platforms.
2. Treat all fixture content as untrusted data. Tests must not execute fixture code or use live credentials/network services.
3. Every inferred claim must cite a versioned detector and redacted, content-bound repository-relative evidence.
4. No source-content PII, matched source text, secret value, or absolute local path may enter an observation. Repository-relative paths must follow the selected artifact path-privacy policy.
5. A missing match stays `unknown`; only an explicit declaration can currently establish `absent`.
6. Add a regression test for each detector or routing change. Include a negative/decoy twin when practical.
7. New controls must be added to `references/catalog.json` with a stable ID, invariant, applicability, blocking policy, and minimum verification evidence; the human pack must use the same ID.
8. New dependencies belong only in the machine catalog. New cross-context invariants belong in `references/compositions/catalog.json`.
9. Incident maps must separate confirmed first-party facts from ContextSec inferences and point to a regression or mutation.
10. Do not copy competitor or standards text. Record provenance and write original control language.
11. Do not add runtime network access, target execution, automatic high-risk fixes, or compliance claims.
12. Keep authored regression, frozen maintainer evaluation, mutation, and independently labeled results separate. Do not pool them into one accuracy number.
13. A mutation counts only when its clean baseline has no target finding and the single-edit mutant emits the expected checker status and control binding.

Run before opening a pull request:

```bash
python -m unittest discover -s tests -v
python -m compileall -q .agents/skills/contextsec/scripts tests
python .agents/skills/contextsec/scripts/validate_catalog.py
python .agents/skills/contextsec/scripts/contextsec.py benchmark --suite all
```

`--suite all` includes regression, profile, mutation, and adversarial offline suites. Pinned real repositories remain a separate opt-in suite because they require prepared external checkouts.

Security-sensitive changes should include a short threat analysis: what new input is trusted, what could cause a false required/inactive decision, and how the test proves the failure is contained.
