import importlib.util
import copy
import contextlib
import io
import json
import re
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = ROOT / ".agents" / "skills" / "contextsec"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PROFILER = load_module("contract_profiler", SKILL_ROOT / "scripts" / "profile_repo.py")
VALIDATOR = load_module(
    "contract_validator", SKILL_ROOT / "scripts" / "validate_profile.py"
)
CHECKER = load_module("contract_checker", SKILL_ROOT / "scripts" / "check_controls.py")
CHECK_VALIDATOR = load_module(
    "contract_check_validator", SKILL_ROOT / "scripts" / "validate_checks.py"
)
LEDGER_VALIDATOR = load_module(
    "contract_ledger_validator", SKILL_ROOT / "scripts" / "validate_ledger.py"
)
LEDGER = load_module("contract_ledger", SKILL_ROOT / "scripts" / "control_ledger.py")
PACKAGER = load_module(
    "contract_packager", SKILL_ROOT / "scripts" / "package_release.py"
)
CATALOG_VALIDATOR = load_module(
    "contract_catalog_validator", SKILL_ROOT / "scripts" / "validate_catalog.py"
)
CONTEXTSEC = load_module(
    "contract_dispatcher", SKILL_ROOT / "scripts" / "contextsec.py"
)


class SkillContractTests(unittest.TestCase):
    def test_skill_frontmatter_is_discriminating_and_finished(self):
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(skill.startswith("---\nname: contextsec\n"))
        self.assertIn("use for", skill.split("---", 2)[1].lower())
        self.assertIn("compatibility: Requires Python 3.11+", skill)
        self.assertNotRegex(
            skill,
            r"<python> scripts/(?:profile_repo|check_controls|control_ledger|validate_[a-z_]+)\.py",
        )
        self.assertNotIn("TODO", skill)
        self.assertLess(len(skill.splitlines()), 500)

    def test_public_dispatcher_validates_catalogs(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = CONTEXTSEC.main(["validate-catalog"])
        self.assertEqual(0, status)
        self.assertIn("semantically valid", output.getvalue())

    def test_profile_schema_is_valid_json(self):
        schema = json.loads(
            (SKILL_ROOT / "references" / "security-profile.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            PROFILER.SCHEMA_VERSION,
            schema["properties"]["schema_version"]["const"],
        )
        checks_schema = json.loads(
            (SKILL_ROOT / "references" / "control-checks.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            PROFILER.SCHEMA_VERSION,
            checks_schema["properties"]["schema_version"]["const"],
        )
        ledger_schema = json.loads(
            (SKILL_ROOT / "references" / "control-ledger.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            PROFILER.SCHEMA_VERSION,
            ledger_schema["properties"]["schema_version"]["const"],
        )

    def test_generated_profiles_pass_semantic_validation(self):
        for relative in ("examples/composite-saas", "tests/fixtures/static-site"):
            profile = PROFILER.profile_repository(ROOT / relative)
            self.assertEqual([], VALIDATOR.validate(profile), relative)

    def test_semantic_validators_reject_unknown_root_fields(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "next-static")
        profile["unexpected"] = True
        self.assertTrue(any("unexpected" in item for item in VALIDATOR.validate(profile)))
        checks = CHECKER.check_repository(ROOT / "examples" / "next-static")
        checks["unexpected"] = True
        self.assertTrue(
            any("unexpected" in item for item in CHECK_VALIDATOR.validate(checks))
        )

    def test_semantic_validator_rejects_inconsistent_summary(self):
        profile = PROFILER.profile_repository(ROOT / "tests/fixtures/static-site")
        profile["required_packs"] = []
        errors = VALIDATOR.validate(profile)
        self.assertTrue(
            any("required_packs does not match routing" in item for item in errors)
        )

    def test_semantic_validator_rejects_invalid_states_duplicates_and_evidence(self):
        profile = PROFILER.profile_repository(ROOT / "tests/fixtures/static-site")
        profile["routing"][0]["state"] = "banana"
        profile["required_packs"].append("baseline-web")
        web_claim = next(
            item for item in profile["claims"] if item["pack"] == "baseline-web"
        )
        web_claim["evidence_refs"] = []
        errors = VALIDATOR.validate(profile)
        self.assertTrue(any("invalid state" in item for item in errors))
        self.assertIn("required_packs contains duplicates", errors)
        self.assertTrue(any("observed state lacks evidence" in item for item in errors))

    def test_semantic_validator_rejects_suppressed_high_evidence(self):
        profile = PROFILER.profile_repository(ROOT / "tests/fixtures/provider-no-sdk")
        payment_route = next(
            item for item in profile["routing"] if item["pack"] == "payments"
        )
        payment_route["state"] = "inactive"
        profile["required_packs"].remove("payments")
        errors = VALIDATOR.validate(profile)
        self.assertIn("routing states do not match claim-derived routing", errors)

    def test_composite_control_checks_are_reproducible(self):
        first = CHECKER.check_repository(ROOT / "examples/composite-saas")
        second = CHECKER.check_repository(ROOT / "examples/composite-saas")
        self.assertEqual(first, second)
        checker_ids = [item["checker"]["id"] for item in first["findings"]]
        self.assertEqual(
            {
                "AI-PII-EGRESS-001",
                "PAYMENT-IDEMPOTENCY-001",
                "PII-LOG-001",
                "TENANT-QUERY-001",
                "UPLOAD-PUBLIC-001",
            },
            set(checker_ids),
        )
        self.assertEqual(6, len(first["findings"]))
        self.assertEqual(5, first["finding_summary"]["failed_findings"])
        self.assertEqual(1, first["finding_summary"]["unknown_findings"])
        self.assertEqual(
            len(first["findings"]), len({item["id"] for item in first["findings"]})
        )
        self.assertEqual([], CHECK_VALIDATOR.validate(first))

    def test_check_validator_rejects_inconsistent_counts(self):
        result = CHECKER.check_repository(ROOT / "examples/composite-saas")
        result["finding_summary"]["failed_findings"] = 0
        self.assertIn(
            "finding_summary does not match findings", CHECK_VALIDATOR.validate(result)
        )

    def test_check_validator_rejects_invalid_finding_fields(self):
        result = CHECKER.check_repository(ROOT / "examples/composite-saas")
        result["findings"][0]["severity"] = "banana"
        result["findings"][0]["method"] = ""
        result["findings"][0]["evidence"]["fingerprint"] = "not-a-hash"
        errors = CHECK_VALIDATOR.validate(result)
        self.assertTrue(any("invalid severity" in item for item in errors))
        self.assertTrue(any("method must be non-empty" in item for item in errors))
        self.assertTrue(any("invalid evidence values" in item for item in errors))

    def test_ledger_blocks_unknown_required_controls_and_activates_compositions(self):
        profile = PROFILER.profile_repository(ROOT / "examples/composite-saas")
        checks = CHECKER.check_repository(ROOT / "examples/composite-saas")
        result = LEDGER.build_ledger(profile, checks)
        self.assertEqual("BLOCK", result["gate"]["status"])
        self.assertIn("COMP-AI-TEN-001", result["active_compositions"])
        self.assertGreater(result["summary"]["blocking_unresolved"], 0)
        payment_price = next(
            item for item in result["ledger"] if item["control_id"] == "PAY-PRICE-001"
        )
        self.assertEqual("unknown", payment_price["verification"])
        self.assertTrue(payment_price["blocking"])
        self.assertEqual([], LEDGER_VALIDATOR.validate(result))

    def test_ledger_validator_rejects_tampered_summary_and_extra_fields(self):
        result = LEDGER.evaluate_repository(ROOT / "examples" / "next-static")
        result["summary"]["total"] = 0
        result["unexpected"] = True
        errors = LEDGER_VALIDATOR.validate(result)
        self.assertTrue(any("ledger root" in item for item in errors))
        self.assertIn("summary total does not match ledger", errors)

    def test_ledger_validator_abstains_on_hostile_field_types(self):
        result = LEDGER.evaluate_repository(ROOT / "examples" / "next-static")
        result["active_compositions"] = [{"not": "hashable"}]
        result["ledger"][0]["evidence_refs"] = [{"not": "hashable"}]
        result["gate"]["blocking_controls"] = {"not": "an array"}
        errors = LEDGER_VALIDATOR.validate(result)
        self.assertTrue(any("active_compositions" in item for item in errors))
        self.assertTrue(any("evidence_refs" in item for item in errors))
        self.assertIn("gate control arrays are invalid", errors)

    def test_ledger_validator_rejects_zero_evidence_forged_pass(self):
        result = LEDGER.evaluate_repository(ROOT / "examples" / "next-static")
        for row in result["ledger"]:
            if row["applicability"] != "not_applicable":
                row["verification"] = "verified"
                row["evidence_refs"] = []
                row["evaluation_sources"] = ["applicability", "supplied-evidence"]
        result["summary"]["verification"] = {
            state: sum(row["verification"] == state for row in result["ledger"])
            for state in sorted(LEDGER.VERIFICATION_STATES)
        }
        result["summary"]["blocking_unresolved"] = 0
        result["summary"]["blocking_waived"] = 0
        result["gate"] = {
            "status": "PASS",
            "reason": "Forged pass.",
            "blocking_controls": [],
            "waived_controls": [],
        }
        errors = LEDGER_VALIDATOR.validate(result)
        self.assertTrue(any("lacks evidence" in item for item in errors))

    def test_ledger_can_pass_complete_bound_evidence_and_reject_stale_replay(self):
        profile = PROFILER.profile_repository(ROOT / "tests/fixtures/static-site")
        checks = CHECKER.check_repository(ROOT / "tests/fixtures/static-site")
        initial = LEDGER.build_ledger(profile, checks)
        evidence = {
            "schema_version": PROFILER.SCHEMA_VERSION,
            "subject_revision": profile["subject"]["subject_revision"],
            "controls": [
                {
                    "control_id": item["control_id"],
                    "applicability": item["applicability"],
                    "verification": (
                        "unknown"
                        if item["applicability"] == "not_applicable"
                        else "verified"
                    ),
                    "reason": "Fixture verification evidence passed.",
                    "evidence_refs": ["test:" + item["control_id"]],
                }
                for item in initial["ledger"]
            ],
            "waivers": [],
        }
        evaluated = LEDGER.build_ledger(profile, checks, evidence)
        self.assertEqual("PASS", evaluated["gate"]["status"])
        stale = {
            **profile,
            "subject": {
                **profile["subject"],
                "subject_revision": "sha256:" + ("0" * 64),
            },
        }
        with self.assertRaisesRegex(ValueError, "subject_revision"):
            LEDGER.build_ledger(stale, checks, evidence)

    def test_ledger_rejects_checks_from_a_different_profile_subject(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "next-static")
        other_profile = PROFILER.profile_repository(
            ROOT / "examples" / "composite-saas"
        )
        other_checks = CHECKER.check_repository(
            ROOT / "examples" / "composite-saas", profile=other_profile
        )
        with self.assertRaisesRegex(ValueError, "repository|subject_revision"):
            LEDGER.build_ledger(profile, other_checks)

    def test_repository_evaluation_profiles_exactly_once(self):
        profiler = LEDGER.profile_repo.profile_repository
        with mock.patch.object(
            LEDGER.profile_repo, "profile_repository", wraps=profiler
        ) as patched:
            LEDGER.evaluate_repository(ROOT / "examples" / "next-static")
        self.assertEqual(1, patched.call_count)

    def test_checker_rejects_repository_change_after_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            source = repository / "route.ts"
            source.write_text("export const GET = () => 1;\n", encoding="utf-8")
            profile = PROFILER.profile_repository(repository)
            source.write_text("export const POST = () => 2;\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "changed after profiling"):
                CHECKER.check_repository(repository, profile=profile)

    def test_static_next_controls_are_not_falsely_blocking(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "next-static")
        checks = CHECKER.check_repository(
            ROOT / "examples" / "next-static", profile=profile
        )
        result = LEDGER.build_ledger(profile, checks)
        controls = {item["control_id"]: item for item in result["ledger"]}
        for control_id in (
            "FND-SECRET-001",
            "FND-AUTHZ-001",
            "FND-ERROR-001",
            "WEB-ADMIN-001",
        ):
            self.assertEqual("not_applicable", controls[control_id]["applicability"])
            self.assertFalse(controls[control_id]["blocking"])
        self.assertEqual("required", controls["WEB-HEADER-001"]["applicability"])
        self.assertEqual("WARN", result["gate"]["status"])

    def test_compositions_require_intersection_evidence_not_pack_cooccurrence(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "composite-saas")
        checks = CHECKER.check_repository(
            ROOT / "examples" / "composite-saas", profile=profile
        )
        result = LEDGER.build_ledger(profile, checks)
        controls = {item["control_id"]: item for item in result["ledger"]}
        self.assertEqual("required", controls["COMP-AI-PII-001"]["applicability"])
        self.assertEqual("required", controls["COMP-AI-TEN-001"]["applicability"])
        self.assertEqual("required", controls["COMP-API-TEN-001"]["applicability"])
        self.assertEqual("candidate", controls["COMP-PAY-TEN-001"]["applicability"])
        self.assertEqual("candidate", controls["COMP-UPL-TEN-001"]["applicability"])

    def test_unrelated_same_file_keywords_do_not_prove_composition_flow(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "package.json").write_text(
                json.dumps({"dependencies": {"stripe": "1.0.0"}}), encoding="utf-8"
            )
            (repository / "schema.prisma").write_text(
                "model Tenant { id String @id }\nmodel Invoice { id String @id tenantId String }\n",
                encoding="utf-8",
            )
            (repository / "app.ts").write_text(
                "const tenantId = metrics.tenantId;\nstripe.paymentIntents.retrieve(globalPaymentId);\n",
                encoding="utf-8",
            )
            profile = PROFILER.profile_repository(repository)
            checks = CHECKER.check_repository(repository, profile=profile)
            result = LEDGER.build_ledger(profile, checks)
        control = next(
            item
            for item in result["ledger"]
            if item["control_id"] == "COMP-PAY-TEN-001"
        )
        self.assertEqual("candidate", control["applicability"])
        self.assertFalse(control["blocking"])

    def test_failed_finding_overrides_supplied_pass(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "composite-saas")
        checks = CHECKER.check_repository(
            ROOT / "examples" / "composite-saas", profile=profile
        )
        evidence = {
            "schema_version": PROFILER.SCHEMA_VERSION,
            "subject_revision": profile["subject"]["subject_revision"],
            "controls": [
                {
                    "control_id": "TEN-DB-001",
                    "applicability": "required",
                    "verification": "verified",
                    "reason": "Untrusted contradictory assertion.",
                    "evidence_refs": ["external:test"],
                }
            ],
            "waivers": [],
        }
        result = LEDGER.build_ledger(profile, checks, evidence)
        control = next(
            item for item in result["ledger"] if item["control_id"] == "TEN-DB-001"
        )
        self.assertEqual("required", control["applicability"])
        self.assertEqual("failed", control["verification"])
        self.assertTrue(control["blocking"])

    def test_supplied_evidence_cannot_downgrade_required_applicability(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "composite-saas")
        checks = CHECKER.check_repository(
            ROOT / "examples" / "composite-saas", profile=profile
        )
        evidence = {
            "schema_version": PROFILER.SCHEMA_VERSION,
            "subject_revision": profile["subject"]["subject_revision"],
            "controls": [
                {
                    "control_id": "PAY-PRICE-001",
                    "applicability": "not_applicable",
                    "verification": "unknown",
                    "reason": "Attempted downgrade.",
                    "evidence_refs": ["external:test"],
                }
            ],
            "waivers": [],
        }
        with self.assertRaisesRegex(ValueError, "cannot downgrade required"):
            LEDGER.build_ledger(profile, checks, evidence)

    def test_not_applicable_evidence_cannot_claim_verified(self):
        with self.assertRaisesRegex(ValueError, "cannot claim control verification"):
            LEDGER.evidence_index(
                {
                    "controls": [
                        {
                            "control_id": "WEB-ADMIN-001",
                            "applicability": "not_applicable",
                            "verification": "verified",
                            "reason": "Contradictory dimensions.",
                            "evidence_refs": ["external:test"],
                        }
                    ]
                }
            )

    def test_supplied_evidence_rejects_unknown_fields(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "next-static")
        checks = CHECKER.check_repository(
            ROOT / "examples" / "next-static", profile=profile
        )
        evidence = {
            "schema_version": PROFILER.SCHEMA_VERSION,
            "subject_revision": profile["subject"]["subject_revision"],
            "controls": [],
            "waivers": [],
            "unexpected": True,
        }
        with self.assertRaisesRegex(ValueError, "unexpected or missing"):
            LEDGER.build_ledger(profile, checks, evidence)

    def test_waiver_lifecycle_and_gate_semantics(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "composite-saas")
        checks = CHECKER.check_repository(
            ROOT / "examples" / "composite-saas", profile=profile
        )
        initial = LEDGER.build_ledger(profile, checks)
        blocker_ids = [
            item["control_id"]
            for item in initial["ledger"]
            if item["blocking"] and item["verification"] in {"failed", "unknown"}
        ]
        waivers = [
            {
                "control_id": control_id,
                "owner": "security-owner",
                "reason": "Time-bounded fixture exception.",
                "compensating_control": "Release monitoring and manual approval.",
                "expires": "2026-12-31",
            }
            for control_id in blocker_ids
        ]
        evidence = {
            "schema_version": PROFILER.SCHEMA_VERSION,
            "subject_revision": profile["subject"]["subject_revision"],
            "controls": [],
            "waivers": waivers,
        }

        waived = LEDGER.build_ledger(
            profile, checks, evidence, LEDGER.date.fromisoformat("2026-08-31")
        )
        self.assertEqual("WAIVED", waived["gate"]["status"])
        self.assertEqual(sorted(blocker_ids), sorted(waived["gate"]["waived_controls"]))
        self.assertEqual(
            [],
            LEDGER_VALIDATOR.validate(
                waived, LEDGER.date.fromisoformat("2026-08-31")
            ),
        )

        expired = LEDGER.build_ledger(
            profile, checks, evidence, LEDGER.date.fromisoformat("2027-01-01")
        )
        self.assertEqual("BLOCK", expired["gate"]["status"])
        self.assertEqual([], expired["gate"]["waived_controls"])

        one_unwaived = {**evidence, "waivers": waivers[:-1]}
        partial = LEDGER.build_ledger(
            profile, checks, one_unwaived, LEDGER.date.fromisoformat("2026-08-31")
        )
        self.assertEqual("BLOCK", partial["gate"]["status"])
        self.assertEqual(1, len(partial["gate"]["blocking_controls"]))

    def test_old_waived_ledger_cannot_be_replayed_for_a_later_release(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "composite-saas")
        checks = CHECKER.check_repository(
            ROOT / "examples" / "composite-saas", profile=profile
        )
        initial = LEDGER.build_ledger(profile, checks)
        evidence = {
            "schema_version": PROFILER.SCHEMA_VERSION,
            "subject_revision": profile["subject"]["subject_revision"],
            "controls": [],
            "waivers": [
                {
                    "control_id": item["control_id"],
                    "owner": "security-owner",
                    "reason": "Historical fixture exception.",
                    "compensating_control": "Historical manual release approval.",
                    "expires": "2020-12-31",
                }
                for item in initial["ledger"]
                if item["blocking"]
                and item["verification"] in {"failed", "unknown"}
            ],
        }
        old = LEDGER.build_ledger(
            profile, checks, evidence, LEDGER.date.fromisoformat("2019-01-01")
        )
        self.assertEqual("WAIVED", old["gate"]["status"])
        self.assertTrue(LEDGER_VALIDATOR.validate(old))
        replay_errors = LEDGER_VALIDATOR.validate(
            old, LEDGER.date.fromisoformat("2026-08-31")
        )
        self.assertTrue(any("expected release date" in item for item in replay_errors))
        self.assertTrue(any("validity is stale" in item for item in replay_errors))

    def test_ledger_rejects_stale_finding_evidence_revision(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "composite-saas")
        checks = CHECKER.check_repository(
            ROOT / "examples" / "composite-saas", profile=profile
        )
        checks["findings"][0]["evidence"]["subject_revision"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(ValueError, "semantic validation"):
            LEDGER.build_ledger(profile, checks)

    def test_ledger_rejects_inconsistent_finding_fingerprint(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "composite-saas")
        checks = CHECKER.check_repository(
            ROOT / "examples" / "composite-saas", profile=profile
        )
        checks["findings"][0]["evidence"]["content_digest"] = "sha256:" + ("0" * 64)
        errors = CHECK_VALIDATOR.validate(checks)
        self.assertTrue(any("fingerprint is inconsistent" in item for item in errors))
        with self.assertRaisesRegex(ValueError, "semantic validation"):
            LEDGER.build_ledger(profile, checks)

    def test_decision_model_mutation_after_profile_is_rejected(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "composite-saas")
        checks = CHECKER.check_repository(
            ROOT / "examples" / "composite-saas", profile=profile
        )
        mutated = copy.deepcopy(LEDGER.profile_repo.COMPOSITION_CATALOG)
        mutated["rules"][0]["blocking"] = False
        with mock.patch.object(LEDGER.profile_repo, "COMPOSITION_CATALOG", mutated):
            with self.assertRaisesRegex(ValueError, "Decision model changed"):
                LEDGER.build_ledger(profile, checks)

    def test_jointly_forged_artifact_model_digest_is_rejected(self):
        profile = PROFILER.profile_repository(ROOT / "examples" / "next-static")
        checks = CHECKER.check_repository(
            ROOT / "examples" / "next-static", profile=profile
        )
        forged = "sha256:" + ("0" * 64)
        profile["subject"]["decision_model_digest"] = forged
        checks["subject"]["decision_model_digest"] = forged
        with self.assertRaisesRegex(ValueError, "live model"):
            LEDGER.build_ledger(profile, checks)

    def test_explain_repo_includes_route_controls_and_gate(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = CONTEXTSEC.explain(
                "baseline-web", ROOT / "examples" / "next-static"
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(0, status)
        self.assertEqual("required", payload["repository_evaluation"]["route"]["state"])
        self.assertIn("controls", payload["repository_evaluation"])
        self.assertEqual("WARN", payload["repository_evaluation"]["gate"]["status"])

    def test_control_checkers_reject_clean_coincidental_shapes(self):
        schema = b"""
model Invoice { id String @id organizationId String billingAddress String }
model Country { id String @id name String }
"""
        source = b"""
const user = await prisma.country.findUnique({ where: { id: countryId } });
console.log(user);
const snapshot = JSON.stringify(user);
openai.responses.create({ input: "safe" });
const defaultAcl = "public-read";
new PutObjectCommand({ Bucket: bucket, Key: key });
"""
        sources = [
            ("prisma/schema.prisma", schema.decode(), schema),
            ("src/route.ts", source.decode(), source),
        ]
        active = [
            "multi-tenant",
            "api-inbound",
            "privacy-pii",
            "ai-rag-agent",
            "external-api",
            "file-upload",
        ]
        self.assertEqual([], CHECKER.check_tenant_queries(sources, active))
        self.assertEqual([], CHECKER.check_pii_logging(sources, active))
        self.assertEqual([], CHECKER.check_ai_egress(sources, active))
        self.assertEqual([], CHECKER.check_public_upload(sources, active))

    def test_public_upload_checker_ignores_template_prose(self):
        source = b'const docs = `new PutObjectCommand({ ACL: "public-read" })`;\n'
        findings = CHECKER.check_public_upload(
            [("src/docs.ts", source.decode(), source)], ["file-upload"]
        )
        self.assertEqual([], findings)

    def test_public_upload_checker_accepts_equivalent_property_syntax(self):
        variants = (
            'new PutObjectCommand({"ACL":"public-read"});',
            'new PutObjectCommand({ACL: /* reviewed */ "public-read"});',
            'new PutObjectCommand({ACL:`public-read`});',
            'new PutObjectCommand({ACL:"public\\x2dread"});',
            'new PutObjectCommand({ACL:"public\\u002dread"});',
            'new PutObjectCommand({["ACL"]:"public-read"});',
            'new PutObjectCommand({ACL:("public-read")});',
            'new PutObjectCommand({ACL:"public\\u{2d}read"});',
            'new PutObjectCommand({ACL:"public-read" as const});',
            'new PutObjectCommand({ACL:("public-read" as const)});',
            'new PutObjectCommand({[("ACL")]:"public-read"});',
        )
        for source_text in variants:
            with self.subTest(source_text=source_text):
                source = source_text.encode("utf-8")
                findings = CHECKER.check_public_upload(
                    [("src/upload.ts", source_text, source)], ["file-upload"]
                )
                self.assertEqual(1, len(findings))
                self.assertEqual("UPLOAD-PUBLIC-001", findings[0]["checker"]["id"])

    def test_tenant_identity_in_upload_key_requires_composition(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "package.json").write_text(
                json.dumps(
                    {"dependencies": {"@aws-sdk/client-s3": "1.0.0"}}
                ),
                encoding="utf-8",
            )
            (repository / "schema.prisma").write_text(
                "model Tenant { id String @id }\nmodel Upload { id String @id tenantId String }\n",
                encoding="utf-8",
            )
            (repository / "upload.ts").write_text(
                "const form = await request.formData();\n"
                "new PutObjectCommand({Key:`${tenantId}/upload.bin`,Body:file});\n",
                encoding="utf-8",
            )
            profile = PROFILER.profile_repository(repository)
            checks = CHECKER.check_repository(repository, profile=profile)
            result = LEDGER.build_ledger(profile, checks)
        checker_ids = {item["checker"]["id"] for item in checks["findings"]}
        self.assertIn("UPLOAD-TENANT-FLOW-001", checker_ids)
        control = next(
            item
            for item in result["ledger"]
            if item["control_id"] == "COMP-UPL-TEN-001"
        )
        self.assertEqual("required", control["applicability"])
        self.assertTrue(control["blocking"])

    def test_upload_tenant_flow_distinguishes_member_use_from_property_name(self):
        active = ["file-upload", "multi-tenant"]
        positive_text = (
            'new PutObjectCommand({Key:`${ctx["tenantId"]}/upload.bin`,Body:file});'
        )
        positive_raw = positive_text.encode("utf-8")
        positive = CHECKER.check_upload_tenant_binding(
            [("src/upload.ts", positive_text, positive_raw)], active
        )
        decoy_text = (
            'new PutObjectCommand({Key:JSON.stringify({tenantId:"constant"}),Body:file});'
        )
        decoy_raw = decoy_text.encode("utf-8")
        decoy = CHECKER.check_upload_tenant_binding(
            [("src/upload.ts", decoy_text, decoy_raw)], active
        )
        computed_key_text = (
            'new PutObjectCommand({Key:JSON.stringify({["tenantId"]:"constant"}),Body:file});'
        )
        computed_key_raw = computed_key_text.encode("utf-8")
        computed_key = CHECKER.check_upload_tenant_binding(
            [("src/upload.ts", computed_key_text, computed_key_raw)], active
        )
        array_text = (
            'new PutObjectCommand({Key:["tenantId"].join("/"),Body:file});'
        )
        array_raw = array_text.encode("utf-8")
        array_literal = CHECKER.check_upload_tenant_binding(
            [("src/upload.ts", array_text, array_raw)], active
        )
        self.assertEqual(1, len(positive))
        self.assertEqual([], decoy)
        self.assertEqual([], computed_key)
        self.assertEqual([], array_literal)

    def test_pii_checks_abstain_on_explicit_projection(self):
        schema = b"model User { id String @id email String }"
        source = b"""
const user = await prisma.user.findUnique({ where: { id }, select: { id: true } });
console.log(user);
openai.responses.create({ input: JSON.stringify(user) });
"""
        sources = [
            ("prisma/schema.prisma", schema.decode(), schema),
            ("src/route.ts", source.decode(), source),
        ]
        active = ["privacy-pii", "ai-rag-agent", "external-api"]
        self.assertEqual([], CHECKER.check_pii_logging(sources, active))
        self.assertEqual([], CHECKER.check_ai_egress(sources, active))

    def test_tenant_checker_enumerates_crud_and_abstains_on_raw_sql(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "package.json").write_text(
                '{"dependencies":{"next":"15"}}\n', encoding="utf-8"
            )
            schema = repository / "prisma" / "schema.prisma"
            schema.parent.mkdir()
            schema.write_text(
                "model Organization { id String @id orders Order[] }\n"
                "model Order { id String @id orgId String organization Organization @relation(fields:[orgId], references:[id]) }\n",
                encoding="utf-8",
            )
            route = repository / "app" / "api" / "orders" / "route.ts"
            route.parent.mkdir(parents=True)
            route.write_text(
                "export async function GET() {\n"
                " const a = await prisma.order.findUnique({ where: { id: one } });\n"
                " const b = await prisma.order.findFirst({ where: { id: two } });\n"
                " const c = await prisma.order.findMany({ where: { id: three } });\n"
                " const d = await prisma.order.update({ where: { id: four }, data: { status } });\n"
                " const e = await prisma.order.delete({ where: { id: five } });\n"
                " const f = await prisma.order.upsert({ where: { id: six }, update: { status }, create: { id: six, orgId } });\n"
                " const g = await prisma.$queryRawUnsafe(query);\n"
                " return Response.json([a,b,c,d,e,f,g]);\n"
                "}\n",
                encoding="utf-8",
            )
            profile = PROFILER.profile_repository(repository)
            checks = CHECKER.check_repository(repository, profile=profile)
        tenant_findings = [
            item
            for item in checks["findings"]
            if item["checker"]["id"] == "TENANT-QUERY-001"
        ]
        raw_findings = [
            item
            for item in checks["findings"]
            if item["checker"]["id"] == "TENANT-RAW-QUERY-001"
        ]
        self.assertEqual(6, len(tenant_findings))
        self.assertEqual(1, len(raw_findings))
        self.assertEqual("unknown", raw_findings[0]["status"])
        self.assertEqual([], CHECK_VALIDATOR.validate(checks))

    def test_client_public_secret_checker_uses_names_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "package.json").write_text(
                '{"dependencies":{"next":"15"}}\n', encoding="utf-8"
            )
            (repository / ".env.local").write_text(
                "NEXT_PUBLIC_STRIPE_SECRET_KEY=VALUE_MUST_NOT_APPEAR\n",
                encoding="utf-8",
            )
            source = repository / "src"
            source.mkdir()
            (source / "client.ts").write_text(
                "const one = process.env.NEXT_PUBLIC_WEBHOOK_SECRET;\n"
                "const two = import.meta.env.VITE_SERVICE_ROLE_SECRET;\n"
                "const three = process.env.REACT_APP_ACCESS_TOKEN;\n"
                "const safe = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;\n"
                '// process.env.NEXT_PUBLIC_COMMENT_SECRET\n'
                'const prose = "process.env.NEXT_PUBLIC_STRING_SECRET";\n',
                encoding="utf-8",
            )
            profile = PROFILER.profile_repository(repository)
            checks = CHECKER.check_repository(repository, profile=profile)
        findings = [
            item
            for item in checks["findings"]
            if item["checker"]["id"] == "CLIENT-PUBLIC-SECRET-001"
        ]
        self.assertEqual(4, len(findings))
        self.assertNotIn("VALUE_MUST_NOT_APPEAR", json.dumps(checks, sort_keys=True))
        self.assertEqual([], CHECK_VALIDATOR.validate(checks))

    def test_checker_reports_unsupported_language_separately(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "go.mod").write_text(
                "module example.invalid/contextsec\n\ngo 1.24\n", encoding="utf-8"
            )
            (repository / "main.go").write_text(
                "package main\nfunc main() {}\n", encoding="utf-8"
            )
            profile = PROFILER.profile_repository(repository)
            checks = CHECKER.check_repository(repository, profile=profile)
            ledger = LEDGER.build_ledger(profile, checks)
        self.assertEqual("unsupported", profile["coverage"]["language_support"])
        self.assertEqual(
            "unsupported", checks["subject"]["checker_coverage"]["language_support"]
        )
        self.assertEqual("BLOCK", ledger["gate"]["status"])

    def test_event_id_logging_is_not_idempotency_evidence(self):
        source = b"""
const event = stripe.webhooks.constructEvent(body, signature, secret);
console.log(event.id);
"""
        findings = CHECKER.check_payment_idempotency(
            [("src/webhook.ts", source.decode(), source)], ["payments"]
        )
        self.assertEqual(1, len(findings))
        self.assertEqual("unknown", findings[0]["status"])

    def test_control_checker_total_byte_limit_is_partial(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "route.ts").write_text("const value = 1;", encoding="utf-8")
            sources, coverage, checker_hash = CHECKER.load_sources(
                repository, max_total_bytes=1
            )
        self.assertEqual([], sources)
        self.assertEqual("partial", coverage["status"])
        self.assertRegex(checker_hash, r"^sha256:[a-f0-9]{64}$")

    def test_cicd_checks_flag_mutable_action_and_implicit_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            workflow = repository / ".github" / "workflows"
            workflow.mkdir(parents=True)
            (workflow / "ci.yml").write_text(
                "name: ci\non: push\njobs:\n  test:\n    steps:\n      - uses: vendor/action@v1\n",
                encoding="utf-8",
            )
            result = CHECKER.check_repository(repository)
        checker_ids = {item["checker"]["id"] for item in result["findings"]}
        self.assertEqual(
            {"CICD-ACTION-PIN-001", "CICD-PERMISSIONS-001"}, checker_ids
        )
        self.assertEqual([], CHECK_VALIDATOR.validate(result))

    def test_openai_metadata_uses_skill_name(self):
        metadata = (SKILL_ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn('display_name: "ContextSec"', metadata)
        self.assertIn("$contextsec", metadata)

    def test_pack_index_references_existing_files(self):
        index = (SKILL_ROOT / "references" / "pack-index.md").read_text(
            encoding="utf-8"
        )
        links = re.findall(r"\((packs/[a-z0-9-]+\.md)\)", index)
        self.assertEqual(16, len(links))
        for link in links:
            self.assertTrue((SKILL_ROOT / "references" / link).is_file(), link)

    def test_control_ids_are_unique(self):
        seen = set()
        for path in sorted((SKILL_ROOT / "references" / "packs").glob("*.md")):
            for control_id in re.findall(
                r"`([A-Z]+(?:-[A-Z]+)+-\d{3})`", path.read_text(encoding="utf-8")
            ):
                self.assertNotIn(control_id, seen, control_id)
                seen.add(control_id)
        catalog = json.loads(
            (SKILL_ROOT / "references" / "catalog.json").read_text(encoding="utf-8")
        )
        catalog_ids = {
            control["id"]
            for pack in catalog["packs"]
            for control in pack["controls"]
        }
        self.assertEqual(catalog_ids, seen)
        self.assertGreaterEqual(len(seen), 100)

    def test_catalog_semantics_reject_string_boolean_and_bad_composition(self):
        catalog = json.loads(
            (SKILL_ROOT / "references" / "catalog.json").read_text(encoding="utf-8")
        )
        compositions = json.loads(
            (SKILL_ROOT / "references" / "compositions" / "catalog.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            [], CATALOG_VALIDATOR.validate_catalogs(catalog, compositions, SKILL_ROOT)
        )
        bad_catalog = copy.deepcopy(catalog)
        bad_catalog["packs"][0]["controls"][0]["blocking"] = "false"
        errors = CATALOG_VALIDATOR.validate_catalogs(
            bad_catalog, compositions, SKILL_ROOT
        )
        self.assertTrue(any("JSON boolean" in item for item in errors))
        bad_compositions = copy.deepcopy(compositions)
        bad_compositions["rules"][0]["requires"].append("does-not-exist")
        errors = CATALOG_VALIDATOR.validate_catalogs(
            catalog, bad_compositions, SKILL_ROOT
        )
        self.assertTrue(any("requires is invalid" in item for item in errors))
        bad_catalog = copy.deepcopy(catalog)
        conditional = next(
            control
            for pack in bad_catalog["packs"]
            for control in pack["controls"]
            if "applies_when" in control
        )
        conditional["applies_when"] = {"all": ["missing.capability"]}
        errors = CATALOG_VALIDATOR.validate_catalogs(
            bad_catalog, compositions, SKILL_ROOT
        )
        self.assertTrue(any("unknown capability" in item for item in errors))

    def test_incident_corpus_references_real_controls_packs_and_fixtures(self):
        incident_schema = json.loads(
            (ROOT / "incidents" / "schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual("0.1.0", incident_schema["properties"]["schema_version"]["const"])
        catalog = json.loads(
            (SKILL_ROOT / "references" / "catalog.json").read_text(encoding="utf-8")
        )
        pack_ids = {pack["id"] for pack in catalog["packs"]}
        control_ids = {
            control["id"]
            for pack in catalog["packs"]
            for control in pack["controls"]
        }
        compositions = json.loads(
            (
                SKILL_ROOT
                / "references"
                / "compositions"
                / "catalog.json"
            ).read_text(encoding="utf-8")
        )
        control_ids.update(rule["id"] for rule in compositions["rules"])
        incidents = sorted((ROOT / "incidents").glob("20*/*.json"))
        self.assertGreaterEqual(len(incidents), 5)
        for path in incidents:
            incident = json.loads(path.read_text(encoding="utf-8"))
            self.assertLessEqual(set(incident["contexts"]), pack_ids, path.name)
            self.assertLessEqual(set(incident["controls"]), control_ids, path.name)
            fixture = ROOT / incident["regression"]["fixture"]
            self.assertTrue(fixture.exists(), path.name)
            profile = PROFILER.profile_repository(fixture)
            self.assertLessEqual(
                set(incident["regression"]["expected_routes"]),
                set(profile["required_packs"]),
                path.name,
            )

    def test_release_allowlist_excludes_repository_and_tool_caches(self):
        paths = [path.as_posix() for path in PACKAGER.release_files(ROOT)]
        self.assertIn("README.md", paths)
        self.assertIn(".agents/skills/contextsec/SKILL.md", paths)
        self.assertIn(".github/CODEOWNERS", paths)
        forbidden = ("/.git/", "__pycache__", ".pytest_cache", ".ruff_cache")
        self.assertFalse(any(any(item in "/" + path for item in forbidden) for path in paths))

    def test_release_zip_uses_platform_independent_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "contextsec.zip"
            PACKAGER.build_archive(archive_path, ROOT)
            with zipfile.ZipFile(archive_path) as archive:
                infos = archive.infolist()
        self.assertTrue(infos)
        self.assertTrue(all(info.create_system == 3 for info in infos))
        self.assertTrue(all(info.create_version == 20 for info in infos))
        self.assertTrue(all(info.extract_version == 20 for info in infos))
        self.assertTrue(all(info.compress_type == zipfile.ZIP_STORED for info in infos))

    def test_release_zip_is_byte_for_byte_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.zip"
            second = Path(temporary) / "second.zip"
            PACKAGER.build_archive(first, ROOT)
            PACKAGER.build_archive(second, ROOT)
            self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == "__main__":
    unittest.main()
