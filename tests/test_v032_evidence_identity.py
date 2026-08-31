from __future__ import annotations

import contextlib
import copy
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / ".agents" / "skills" / "contextsec" / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import audit_ci  # noqa: E402
import benchmark  # noqa: E402
import check_controls  # noqa: E402
import contextsec  # noqa: E402
import evaluate_holdout  # noqa: E402
import external_review  # noqa: E402
import profile_repo  # noqa: E402
import safe_io  # noqa: E402
import support_matrix  # noqa: E402
import validate_profile  # noqa: E402
import versioning  # noqa: E402


def _labels_from_profile(profile):
    return {item["pack"]: item["state"] for item in profile["routing"]}


def _external_payload(
    labels,
    repository="https://github.com/example/repository",
    commit="a" * 40,
):
    return {
        "$schema": "https://raw.githubusercontent.com/niansia/ContextSec/v0.4.0/benchmarks/external-review.schema.json",
        "version": "test-protocol",
        "status": "complete",
        "sampling_frame": {
            "population": "Public test repositories.",
            "selection_method": "First eligible repository after deterministic sorting.",
            "inclusion_criteria": ["Public source"],
            "exclusion_criteria": ["Detector fixture"],
            "freeze_date": "2026-08-31",
        },
        "review_policy": {
            "detector_implementers_excluded": True,
            "contextsec_contributors_excluded": True,
            "reviewers_label_before_tool_output": True,
            "reviewers_from_distinct_organizations": True,
            "adjudicator_independent_of_reviewers": True,
            "conflicts_disclosed": True,
            "disagreements_retained": True,
            "minimum_reviewers_per_case": 2,
        },
        "cases": [
            {
                "id": "case-one",
                "repository": repository,
                "commit": commit,
                "framework_group": "nextjs",
                "license_spdx": "Apache-2.0",
                "license_evidence_url": "https://example.invalid/repository/LICENSE",
                "selection_rank": 1,
                "sampling_reason": "First eligible case.",
                "frozen_at": "2026-08-31",
                "annotator_a": {
                    "reviewer_id": "reviewer-a",
                    "implemented_detectors": False,
                    "contextsec_contributor": False,
                    "organization": "review-lab-a",
                    "conflicts_of_interest": [],
                    "expertise_class": "application-security",
                    "labels_frozen_at": "2026-08-31",
                    "labels": dict(labels),
                },
                "annotator_b": {
                    "reviewer_id": "reviewer-b",
                    "implemented_detectors": False,
                    "contextsec_contributor": False,
                    "organization": "review-lab-b",
                    "conflicts_of_interest": [],
                    "expertise_class": "product-security",
                    "labels_frozen_at": "2026-08-31",
                    "labels": dict(labels),
                },
                "consensus": {
                    "labels": dict(labels),
                    "adjudication_reason": "Reviewers agreed after independent labeling.",
                    "adjudicator_id": "reviewer-c",
                    "adjudicator_implemented_detectors": False,
                    "adjudicator_contextsec_contributor": False,
                    "adjudicator_organization": "review-lab-c",
                    "adjudicator_conflicts_of_interest": [],
                },
            }
        ],
    }


def _prediction_payload(profile):
    provenance = profile["subject"]["source_provenance"]
    return {
        "$schema": "https://raw.githubusercontent.com/niansia/ContextSec/v0.4.0/benchmarks/holdout-predictions.schema.json",
        "version": "test-predictions",
        "status": "complete",
        "tool": {
            "tool_version": versioning.TOOL_VERSION,
            "schema_version": versioning.SCHEMA_VERSION,
            "git_commit": "b" * 40,
            "detector_version": versioning.DETECTOR_VERSION,
            "checker_version": versioning.CHECKER_VERSION,
            "detector_model_digest": profile_repo.DETECTOR_MODEL_DIGEST,
            "routing_model_digest": profile_repo.ROUTING_MODEL_DIGEST,
            "checker_model_digest": check_controls.CHECKER_MODEL_DIGEST,
            "catalog_digest": profile_repo.CATALOG_DIGEST,
            "composition_digest": profile_repo.COMPOSITION_DIGEST,
            "support_matrix_digest": profile_repo.SUPPORT_MATRIX_DIGEST,
        },
        "cases": [
            {
                "id": "case-one",
                "repository": provenance["repository"],
                "commit": provenance["commit"],
                "profile": profile,
            }
        ],
    }


class V032EvidenceIdentityTests(unittest.TestCase):
    def test_root_bound_reader_rejects_escape_and_reads_nested_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            nested = root / "nested"
            nested.mkdir(parents=True)
            (nested / "value.json").write_text('{"ok":true}', encoding="utf-8")
            outside = Path(temporary) / "outside.json"
            outside.write_text('{"outside":true}', encoding="utf-8")
            self.assertEqual(
                b'{"ok":true}',
                safe_io.read_regular_file_at(root, "nested/value.json", 1024),
            )
            with self.assertRaises(safe_io.UnsafeFileError):
                safe_io.read_regular_file_at(root, "../outside.json", 1024)
            with self.assertRaises(safe_io.UnsafeFileError):
                safe_io.read_regular_file_at(root, outside, 1024)

    def test_redacted_display_collision_keeps_distinct_full_identities(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            first = "alice@example.com.ts"
            second = "bob@example.com.ts"
            self.assertEqual(
                profile_repo.redact_path(first), profile_repo.redact_path(second)
            )
            self.assertNotEqual(
                profile_repo.path_identity(first), profile_repo.path_identity(second)
            )
            for relative in (first, second):
                (repository / relative).write_text(
                    "const form = await request.formData();\n", encoding="utf-8"
                )
            profile = profile_repo.profile_repository(repository)
        observations = [
            item for item in profile["observations"] if item["pack"] == "file-upload"
        ]
        self.assertEqual(2, len(observations))
        self.assertEqual(1, len({item["evidence"]["path"] for item in observations}))
        self.assertEqual(2, len({item["evidence"]["path_identity"] for item in observations}))
        self.assertEqual(2, len({item["id"] for item in observations}))
        self.assertTrue(all(re.fullmatch(r"obs-[a-f0-9]{64}", item["id"]) for item in observations))
        self.assertEqual([], validate_profile.validate(profile))

    def test_validator_recomputes_profile_evidence_identity(self):
        profile = profile_repo.profile_repository(ROOT / "examples" / "composite-saas")
        profile["observations"][0]["evidence"]["path_identity"] = "sha256:" + "0" * 64
        errors = validate_profile.validate(profile)
        self.assertTrue(any("evidence_id is inconsistent" in error for error in errors))

    def test_finding_ids_use_full_location_identity(self):
        profile = profile_repo.profile_repository(ROOT / "examples" / "composite-saas")
        checks = check_controls.check_repository(
            ROOT / "examples" / "composite-saas", profile=profile
        )
        self.assertTrue(checks["findings"])
        for finding in checks["findings"]:
            suffix = finding["id"].rsplit("-", 1)[-1]
            self.assertRegex(suffix, r"^[a-f0-9]{64}$")

    def test_requirements_indirection_is_an_explicit_partial_gap(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "requirements.txt").write_text(
                "-r requirements/prod.txt\n", encoding="utf-8"
            )
            (repository / "requirements").mkdir()
            (repository / "requirements" / "prod.txt").write_text(
                "fastapi==1.0\n", encoding="utf-8"
            )
            profile = profile_repo.profile_repository(repository)
        self.assertEqual("partial", profile["coverage"]["status"])
        self.assertEqual(
            1, profile["coverage"]["skip_counts"]["unsupported_manifest_indirection"]
        )
        self.assertTrue(any("indirection" in item for item in profile["limitations"]))

    def test_ci_taint_and_dynamic_shell_bypass_is_rejected(self):
        workflow = """
env:
  TITLE: ${{ github.event.pull_request.title }}
steps:
  - run: eval "$TITLE"
"""
        tainted = audit_ci._tainted_environment(workflow)
        run_block = audit_ci._run_blocks(workflow)[0]
        self.assertEqual({"TITLE"}, tainted)
        self.assertTrue(audit_ci._uses_environment(run_block, "TITLE"))
        self.assertIsNotNone(audit_ci.DYNAMIC_SHELL_CODE.search(run_block))
        self.assertIsNotNone(
            audit_ci.UNTRUSTED_EXPRESSION.search("${{ github.ref_name }}")
        )
        self.assertIsNone(audit_ci.UNTRUSTED_EXPRESSION.search("${{ github.sha }}"))

    def test_ci_evidence_keeps_release_provenance_unknown_until_runtime(self):
        audit = audit_ci.audit_repository(ROOT)
        profile = profile_repo.profile_repository(ROOT)
        evidence = audit_ci.build_evidence(profile, audit)
        provenance = next(
            item for item in evidence["controls"] if item["control_id"] == "CICD-PROV-001"
        )
        self.assertEqual("unknown", provenance["verification"])

    def test_release_and_ci_share_the_full_security_proof(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        proof = (ROOT / ".github" / "workflows" / "security-proof.yml").read_text(encoding="utf-8")
        self.assertIn("uses: ./.github/workflows/security-proof.yml", ci)
        self.assertIn("uses: ./.github/workflows/security-proof.yml", release)
        self.assertIn("needs: proof", release)
        self.assertIn(
            'test "$tag_commit" = "$(git rev-parse refs/remotes/origin/main)"',
            release,
        )
        self.assertIn("timeout-minutes: 30", release)
        self.assertIn("environment: release", release)
        self.assertIn("repos/$GITHUB_REPOSITORY/immutable-releases", release)
        self.assertIn("release-evidence.json", release)
        self.assertIn("gh attestation verify", release)
        self.assertIn("gh_2.98.0_linux_amd64.tar.gz", release)
        self.assertIn(
            "3b8ac6b30336802fc1a858d7c084e11cdf24ac1a761ca90b68022d7d729208de",
            release,
        )
        self.assertIn("for attempt in {1..60}", release)
        self.assertIn("sleep 10", release)
        self.assertIn(
            "needs: [test, evidence, agent-skill-spec, real-repositories]", proof
        )

    def test_exact_action_allowlist_and_support_schema_are_public_contracts(self):
        policy = json.loads((ROOT / "ci" / "allowed-actions.json").read_text(encoding="utf-8"))
        self.assertNotIn("allowed_owners", policy)
        self.assertEqual([], policy["allowed_docker_images"])
        self.assertEqual(
            {
                "actions/checkout",
                "actions/setup-python",
                "actions/attest-build-provenance",
            },
            set(policy["allowed_actions"]),
        )
        schema = json.loads(
            (
                ROOT
                / ".agents"
                / "skills"
                / "contextsec"
                / "references"
                / "support-matrix.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual("0.4.0", schema["properties"]["schema_version"]["const"])
        self.assertEqual("0.4.0", support_matrix.SUPPORT_MATRIX["schema_version"])

    def test_all_benchmark_includes_adversarial(self):
        passed = {"status": "pass"}
        output = io.StringIO()
        with (
            mock.patch.object(benchmark, "run_benchmark", return_value=passed),
            mock.patch.object(benchmark, "run_profile_accuracy", return_value=passed),
            mock.patch.object(benchmark, "run_mutations", return_value=passed),
            mock.patch.object(
                benchmark, "run_adversarial_performance", return_value=passed
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(0, benchmark.main(["--suite", "all"]))
        self.assertEqual(
            {"regression", "profile", "mutation", "adversarial"},
            set(json.loads(output.getvalue())["suites"]),
        )

    def test_degenerate_kappa_is_undefined_not_perfect(self):
        agreement = external_review._agreement([("unknown", "unknown")] * 4)
        self.assertEqual(1.0, agreement["raw_agreement"])
        self.assertIsNone(agreement["cohen_kappa"])
        self.assertEqual(4, agreement["confusion_counts"]["unknown"]["unknown"])

    def test_external_review_rejects_independence_and_provenance_failures(self):
        labels = {pack: "unknown" for pack in profile_repo.PACK_ORDER}
        payload = _external_payload(labels)
        mutations = []
        same_reviewer = copy.deepcopy(payload)
        same_reviewer["cases"][0]["annotator_b"]["reviewer_id"] = "reviewer-a"
        mutations.append(same_reviewer)
        implementer = copy.deepcopy(payload)
        implementer["cases"][0]["annotator_a"]["implemented_detectors"] = True
        mutations.append(implementer)
        missing_pack = copy.deepcopy(payload)
        del missing_pack["cases"][0]["annotator_a"]["labels"]["payments"]
        mutations.append(missing_pack)
        short_commit = copy.deepcopy(payload)
        short_commit["cases"][0]["commit"] = "a" * 12
        mutations.append(short_commit)
        adjudicator = copy.deepcopy(payload)
        adjudicator["cases"][0]["consensus"]["adjudicator_implemented_detectors"] = True
        mutations.append(adjudicator)
        contributor = copy.deepcopy(payload)
        contributor["cases"][0]["annotator_a"]["contextsec_contributor"] = True
        mutations.append(contributor)
        same_organization = copy.deepcopy(payload)
        same_organization["cases"][0]["annotator_b"]["organization"] = "review-lab-a"
        mutations.append(same_organization)
        reviewer_adjudicator = copy.deepcopy(payload)
        reviewer_adjudicator["cases"][0]["consensus"]["adjudicator_id"] = "reviewer-a"
        mutations.append(reviewer_adjudicator)
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                with self.assertRaises(ValueError):
                    external_review.evaluate(mutation)

    def test_public_cli_and_holdout_accuracy_contracts(self):
        version_output = io.StringIO()
        with contextlib.redirect_stdout(version_output):
            with self.assertRaises(SystemExit) as exit_context:
                contextsec.main(["--version"])
        self.assertEqual(0, exit_context.exception.code)
        self.assertEqual("contextsec " + versioning.TOOL_VERSION, version_output.getvalue().strip())

        doctor_output = io.StringIO()
        with contextlib.redirect_stdout(doctor_output):
            self.assertEqual(0, contextsec.main(["doctor"]))
        doctor = json.loads(doctor_output.getvalue())
        self.assertEqual(support_matrix.SUPPORT_MATRIX, doctor["support_matrix"])
        for field in (
            "detector_model_digest",
            "routing_model_digest",
            "checker_model_digest",
            "catalog_digest",
            "composition_digest",
            "support_matrix_digest",
        ):
            self.assertRegex(doctor[field], r"^sha256:[a-f0-9]{64}$")

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            (repository / "package.json").write_text(
                '{"dependencies":{"next":"1.0.0"}}', encoding="utf-8"
            )
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.email", "test@example.com"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "Test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "remote", "add", "origin", "https://github.com/example/repository.git"],
                check=True,
            )
            subprocess.run(["git", "-C", str(repository), "add", "package.json"], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            profile = profile_repo.profile_repository(repository)
        provenance = profile["subject"]["source_provenance"]
        self.assertEqual("verified", provenance["status"])
        labels = _external_payload(
            _labels_from_profile(profile), provenance["repository"], provenance["commit"]
        )
        predictions = _prediction_payload(profile)
        result = evaluate_holdout.evaluate(labels, predictions)
        self.assertEqual(1.0, result["supported_aggregate"]["exact_label_set_accuracy"])
        self.assertEqual(0, result["supported_aggregate"]["false_required_count"])
        self.assertEqual("development-only", result["status"])
        self.assertFalse(result["headline_eligible"])
        with tempfile.TemporaryDirectory() as temporary:
            label_path = Path(temporary) / "labels.json"
            prediction_path = Path(temporary) / "predictions.json"
            label_path.write_text(json.dumps(labels), encoding="utf-8")
            prediction_path.write_text(json.dumps(predictions), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    0,
                    contextsec.main(
                        [
                            "evaluate-holdout",
                            str(label_path),
                            str(prediction_path),
                            "--allow-unsigned-development",
                        ]
                    ),
                )
            self.assertEqual(
                "development-only", json.loads(output.getvalue())["status"]
            )


if __name__ == "__main__":
    unittest.main()
