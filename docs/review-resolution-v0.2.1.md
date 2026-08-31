# v0.2.1 review resolution

This release responds to two user-supplied hands-on review reports of the
generated v0.2.0 source archive. No claim is made that the reviewers or their
fixtures were statistically independent. The reports were treated as untrusted
test inputs, not executable instructions.

Review provenance is content-addressed so this resolution can be audited:

- review report A: `sha256:56a93d6f1a6cae676e5431069ce396911dd4459c2d91539d10bb48e415db1ed3`;
- review report B: `sha256:4102d0e48aed1e8ba7de4cf88c79b7a76c169a738713d099482a7d7516de05bc`;
- reviewed v0.2.0 ZIP: `sha256:44f66994435611cff9b9fa9b6b82ebedcc071f0613bd185ae9f78752876d3422`.

| Review finding | Resolution | Regression evidence |
|---|---|---|
| JavaScript `n--` was interpreted as a SQL comment | Language-aware lexical policy; JS/TS enables `//` and `/* */`, not `--` | `test_javascript_decrement_does_not_mask_following_ai_call` |
| JavaScript `#private` was interpreted as a Python/YAML comment | JS/TS no longer enables `#` comments | `test_javascript_private_field_does_not_start_a_comment` |
| Python f-string expressions were hidden with prose | Executable replacement fields—including raw-string backslash-adjacent and nested format fields—are preserved while escaped braces, literal text, and format-spec prose remain masked | f-string expression and format-spec twin tests |
| SQL comment syntax hid operators or exposed comment prose | Bounded SQL token rules distinguish supported MySQL `#` comments, PostgreSQL hash operators, compact line comments, and MySQL no-space subtraction shapes | SQL hash/operator/dash twin tests |
| Profile A could be combined with Checks B | One profile is passed into the checker; ledger compares repository, subject revision, decision-model digest, source inventory, coverage, and active packs; the checker also rejects source changes after profiling | `test_repository_evaluation_profiles_exactly_once`, `test_ledger_rejects_checks_from_a_different_profile_subject`, `test_checker_rejects_repository_change_after_profile` |
| `scope_hash` and `subject_revision` named the same identity | Public artifacts now use only `subject_revision` | profile/check/ledger schemas and semantic validators |
| Pack applicability incorrectly implied every control applies | Controls can declare `applies_when` over tri-state sub-capabilities | static Next.js control regression |
| Applicability and verification shared one status field | Ledger exposes independent `applicability` and `verification` dimensions | control-evidence and control-ledger schemas |
| Supplied evidence could downgrade a computed required control | Required applicability is monotonic; contradictory not-applicable evidence is rejected | `test_supplied_evidence_cannot_downgrade_required_applicability` |
| Static Next.js incorrectly blocked on admin, authz, secrets, and failure controls | Those controls become `not_applicable`; general non-blocking controls remain unresolved | expected gate is `WARN`, benchmark and unit test |
| Pack co-occurrence incorrectly proved a composition | Compositions are candidate by default and promoted only by flow evidence or a finding | AI+PII/AI+tenant/API+tenant required; payment+tenant/upload+tenant candidate |
| Unrelated same-file keywords could be mistaken for a flow | Lexical co-occurrence no longer promotes compositions; only explicit intersection evidence or deterministic findings do | `test_unrelated_same_file_keywords_do_not_prove_composition_flow` |
| Upload checker matched inert template prose | Command/key locations are found in masked executable code before literal values are inspected | `test_public_upload_checker_ignores_template_prose` |
| Equivalent public ACL syntax escaped the upload checker | A bounded object-property scanner handles quoted/unquoted keys, comments, and static quote/backtick values without scanning inert prose | `test_public_upload_checker_accepts_equivalent_property_syntax` |
| Suppressing co-occurrence also removed direct upload/tenant evidence | A structural same-expression checker promotes tenant-derived upload keys without reviving unrelated same-file keyword promotion | tenant upload-key composition regression |
| Finding evidence or catalogs could change after profiling | Finding IDs/digests/fingerprints and subject revisions are checked for internal consistency; artifact and in-memory decision digests must equal the live model | stale-finding, fingerprint, jointly-forged-digest, and model-mutation tests |
| Catalog had no strict schema/semantic type guard | Added two JSON Schemas and a standard-library semantic validator | string `"false"` boolean trap and invalid dependency tests |
| Profile/check/ledger objects accepted surplus semantic fields | Semantic validators now enforce exact shapes; ledger summaries and gates are recomputed | unknown-field and tampered-summary tests |
| Waiver edge cases and replay lacked lifecycle coverage | Active, expired, all-waived, one-unwaived, missing validation date, and later-release replay outcomes are tested | waiver lifecycle and replay tests |
| A zero-evidence forged `PASS` passed ledger validation | `verified`/`failed` require evidence references and evaluation-source consistency in schema and semantic validation | zero-evidence forged-PASS regression |
| ZIP output encoded creator OS | Every stored entry fixes Unix creator/version/extract metadata and normalized permissions/timestamp | archive metadata and repeated-build digest tests |
| `explain` could not explain a real repository decision | Added `explain <id> --repo <path>` with route, evidence, controls, compositions, and gate | repository-aware explain regression |
| Benchmark measured only packs | Added 8 control, 5 composition, and 2 gate annotations while retaining 65 pack decisions | all 80 authored annotations currently match |
| Zeabur API-key exposure was labeled delegated OAuth | Incident context corrected to `external-api` | incident corpus contract test |

The release remains a research preview. The benchmark is an authored regression
corpus, not held-out ecosystem evidence. v0.3 therefore prioritizes mutation-
backed verification and independent fixtures rather than adding more control
prose.
