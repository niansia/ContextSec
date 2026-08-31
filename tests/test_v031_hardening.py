from __future__ import annotations

import contextlib
import io
import json
import os
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
import external_review  # noqa: E402
import package_release  # noqa: E402
import profile_repo  # noqa: E402
import safe_io  # noqa: E402
import support_matrix  # noqa: E402
import validate_checks  # noqa: E402
import validate_profile  # noqa: E402
import versioning  # noqa: E402


class V032HardeningTests(unittest.TestCase):
    def test_version_sources_drive_cli_schema_and_packager(self):
        self.assertEqual("0.3.2", versioning.TOOL_VERSION)
        self.assertEqual("0.3.2", versioning.SCHEMA_VERSION)
        self.assertEqual(versioning.TOOL_VERSION, profile_repo.DETECTOR_VERSION)
        self.assertEqual(versioning.TOOL_VERSION, check_controls.CHECKER_VERSION)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, contextsec.doctor())
        doctor = json.loads(output.getvalue())
        self.assertEqual(versioning.TOOL_VERSION, doctor["tool_version"])
        self.assertTrue(doctor["python_supported"])
        self.assertEqual(
            "contextsec-v0.3.2.zip", package_release.DEFAULT_OUTPUT.name
        )
        self.assertIn('version: "0.3.2"', (ROOT / ".agents" / "skills" / "contextsec" / "SKILL.md").read_text(encoding="utf-8"))
        self.assertIn("version: 0.3.2", (ROOT / "CITATION.cff").read_text(encoding="utf-8"))
        schema_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / ".agents" / "skills" / "contextsec" / "references").rglob("*.schema.json")
        )
        self.assertNotIn("contextsec.dev", schema_text)
        self.assertIn("/v0.3.2/", schema_text)

    def test_external_review_is_available_through_public_dispatcher(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            result = contextsec.main(
                [
                    "external-review",
                    str(ROOT / "benchmarks" / "external-review-template.json"),
                ]
            )
        self.assertEqual(2, result)
        self.assertIn("must be marked complete", output.getvalue())

    def test_support_constants_are_derived_from_machine_contract(self):
        matrix = support_matrix.SUPPORT_MATRIX
        self.assertEqual(
            set(matrix["profile"]["supported_manifests"]),
            profile_repo.PROFILE_SUPPORTED_MANIFESTS,
        )
        self.assertEqual(
            set(matrix["checker"]["supported_suffixes"]),
            check_controls.CHECKER_SUPPORTED_SUFFIXES,
        )
        self.assertEqual(10, len(matrix["checker"]["control_shapes"]))

    def test_tomllib_handles_multiline_quoted_and_inline_table_manifests(self):
        pyproject = """
[project]
dependencies = [
  "fastapi>=0.115",
]
[project.optional-dependencies]
dev = ["openai>=2"]
[tool.poetry.dependencies]
python = ">=3.11"
"django" = { version = "5.2", extras = ["argon2"] }
"""
        self.assertEqual(
            ["fastapi>=0.115", "django"],
            profile_repo.python_dependency_specs("pyproject.toml", pyproject),
        )
        pipfile = """
[packages]
"Flask" = {version = "==3.1.2", extras = ["async"]}
[dev-packages]
openai = "*"
"""
        self.assertEqual(
            ["Flask"], profile_repo.python_dependency_specs("Pipfile", pipfile)
        )

    def test_invalid_toml_is_partial_and_never_a_clean_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pyproject.toml").write_text(
                '[project]\ndependencies = ["fastapi"\n', encoding="utf-8"
            )
            profile = profile_repo.profile_repository(root)
        self.assertEqual("partial", profile["coverage"]["status"])
        self.assertEqual(1, profile["coverage"]["skip_counts"]["invalid_manifest"])
        self.assertEqual([], validate_profile.validate(profile))

    def test_path_privacy_modes_remove_sensitive_repository_paths(self):
        sensitive = "customers/王小明_0912345678/route.ts"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / Path(sensitive)
            target.parent.mkdir(parents=True)
            target.write_text(
                "await openai.responses.create({input: publicDocument});\n",
                encoding="utf-8",
            )
            for mode in ("hashed", "opaque"):
                profile = profile_repo.profile_repository(root, path_privacy=mode)
                checks = check_controls.check_repository(root, profile=profile)
                serialized = json.dumps(
                    {"profile": profile, "checks": checks}, ensure_ascii=False
                )
                self.assertNotIn("王小明", serialized)
                self.assertNotIn("0912345678", serialized)
                self.assertEqual([], validate_profile.validate(profile))
                self.assertEqual([], validate_checks.validate(checks))

    def test_descriptor_identity_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.txt"
            path.write_text("bounded", encoding="utf-8")
            actual = os.lstat(path)
            values = list(actual)
            values[1] = int(actual.st_ino) + 1
            forged = os.stat_result(values)
            with mock.patch.object(safe_io.os, "lstat", return_value=forged):
                with self.assertRaisesRegex(safe_io.UnsafeFileError, "identity changed"):
                    safe_io.read_regular_file(path)

    def test_ci_expression_audit_is_limited_to_run_blocks(self):
        workflow = """
jobs:
  test:
    if: ${{ matrix.enabled }}
    steps:
      - name: safe
        env:
          TOKEN: ${{ github.token }}
        run: echo "$TOKEN"
"""
        self.assertFalse(
            any(
                audit_ci.UNTRUSTED_EXPRESSION.search(block)
                for block in audit_ci._run_blocks(workflow)
            )
        )
        dangerous = "run: echo '${{ github.event.pull_request.title }}'\n"
        self.assertTrue(
            any(
                audit_ci.UNTRUSTED_EXPRESSION.search(block)
                for block in audit_ci._run_blocks(dangerous)
            )
        )

    def test_small_adversarial_manifest_exercises_properties(self):
        manifest = {
            "version": "test",
            "method": "bounded unit case",
            "max_seconds_per_case": 12.0,
            "cases": [
                {
                    "id": "unit-fstring",
                    "recipe": "python-fstrings",
                    "path": "input.py",
                    "bytes": 20000,
                    "expected_coverage": "complete",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            result = benchmark.run_adversarial_performance(path)
        self.assertEqual("pass", result["status"])
        self.assertTrue(all(result["results"][0]["properties"].values()))

    def test_external_review_preserves_disagreement_and_reports_kappa(self):
        labels = {pack: "unknown" for pack in profile_repo.PACK_ORDER}
        disagreeing = dict(labels)
        disagreeing["payments"] = "required"
        payload = {
            "$schema": "https://raw.githubusercontent.com/niansia/ContextSec/v0.3.2/benchmarks/external-review.schema.json",
            "version": "test",
            "status": "complete",
            "sampling_frame": {
                "population": "Public repositories in a predeclared list.",
                "selection_method": "First two after deterministic sorting.",
                "inclusion_criteria": ["Public source"],
                "exclusion_criteria": ["Detector fixture"],
                "freeze_date": "2026-08-31",
            },
            "review_policy": {
                "detector_implementers_excluded": True,
                "reviewers_label_before_tool_output": True,
                "disagreements_retained": True,
                "minimum_reviewers_per_case": 2,
            },
            "cases": [
                {
                    "id": "case-one",
                    "repository": "https://example.invalid/one",
                    "commit": "1" * 40,
                    "framework_group": "python",
                    "support_class": "supported",
                    "license_spdx": "MIT",
                    "license_evidence_url": "https://example.invalid/one/LICENSE",
                    "selection_rank": 1,
                    "sampling_reason": "First eligible case.",
                    "frozen_at": "2026-08-31",
                    "annotator_a": {"reviewer_id": "a", "implemented_detectors": False, "expertise_class": "application-security", "labels": labels},
                    "annotator_b": {"reviewer_id": "b", "implemented_detectors": False, "expertise_class": "product-security", "labels": labels},
                    "consensus": {"labels": labels, "adjudication_reason": "Reviewers agreed.", "adjudicator_id": "c", "adjudicator_implemented_detectors": False},
                },
                {
                    "id": "case-two",
                    "repository": "https://example.invalid/two",
                    "commit": "2" * 40,
                    "framework_group": "node",
                    "support_class": "supported",
                    "license_spdx": "Apache-2.0",
                    "license_evidence_url": "https://example.invalid/two/LICENSE",
                    "selection_rank": 2,
                    "sampling_reason": "Second eligible case.",
                    "frozen_at": "2026-08-31",
                    "annotator_a": {"reviewer_id": "a", "implemented_detectors": False, "expertise_class": "application-security", "labels": labels},
                    "annotator_b": {"reviewer_id": "b", "implemented_detectors": False, "expertise_class": "product-security", "labels": disagreeing},
                    "consensus": {"labels": disagreeing, "adjudication_reason": "Payment evidence was accepted after review.", "adjudicator_id": "c", "adjudicator_implemented_detectors": False},
                },
            ],
        }
        result = external_review.evaluate(payload)
        self.assertEqual(1, result["raw_disagreement_count"])
        self.assertLess(result["agreement"]["raw_agreement"], 1.0)
        self.assertEqual(["payments"], result["cases"][1]["disagreement_packs"])


if __name__ == "__main__":
    unittest.main()
