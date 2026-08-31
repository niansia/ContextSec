from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / ".agents" / "skills" / "contextsec" / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    assert specification.loader is not None
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


PROFILE = load_module("v03_profile", SCRIPT_DIR / "profile_repo.py")
BENCHMARK = load_module("v03_benchmark", SCRIPT_DIR / "benchmark.py")
CHECKS = load_module("v03_checks", SCRIPT_DIR / "check_controls.py")


class V03BenchmarkTests(unittest.TestCase):
    def profile_files(self, files):
        with BENCHMARK.materialized_case("unit-profile", files) as root:
            return PROFILE.profile_repository(root)

    def test_python_requirement_manifest_is_production_evidence(self):
        profile = self.profile_files({"requirements.txt": "fastapi>=0.115\n"})
        self.assertIn("baseline-web", profile["required_packs"])
        self.assertEqual("complete", profile["coverage"]["status"])

    def test_optional_python_dependency_does_not_route_production(self):
        profile = self.profile_files(
            {
                "pyproject.toml": (
                    "[project]\nname='library'\ndependencies=[]\n"
                    "[project.optional-dependencies]\ndev=['openai>=2']\n"
                )
            }
        )
        self.assertEqual(["foundation"], profile["required_packs"])
        self.assertEqual([], profile["candidate_packs"])

    def test_python_models_route_pii_and_tenancy(self):
        profile = self.profile_files(
            {
                "models.py": (
                    "class Customer(SQLModel):\n"
                    "    email: str\n"
                    "    organization_id: str\n"
                )
            }
        )
        self.assertIn("privacy-pii", profile["required_packs"])
        self.assertIn("multi-tenant", profile["required_packs"])
        self.assertIn("auth-session", profile["required_packs"])

    def test_payment_retrieval_name_is_not_rag(self):
        profile = self.profile_files(
            {"src/payment.ts": "const value = retrievePayment(paymentId);\n"}
        )
        capabilities = {item["key"]: item["state"] for item in profile["capabilities"]}
        self.assertNotEqual("present", capabilities["ai.rag"])
        self.assertNotIn("ai-rag-agent", profile["required_packs"])

    def test_profile_benchmark_has_frozen_splits_and_meets_gates(self):
        result = BENCHMARK.run_profile_accuracy()
        self.assertEqual("pass", result["status"])
        self.assertEqual(36, result["case_count"])
        self.assertEqual(20, result["splits"]["development"]["case_count"])
        self.assertEqual(16, result["splits"]["evaluation"]["case_count"])
        self.assertEqual(1.0, result["metrics"]["macro_f1_positive_support"])
        self.assertEqual(0, result["metrics"]["false_required_activation_count"])
        self.assertTrue(all(item["status"] == "pass" for item in result["results"]))

    def test_mutation_suite_kills_every_published_checker_shape(self):
        result = BENCHMARK.run_mutations()
        self.assertEqual("pass", result["status"])
        self.assertEqual(8, result["eligible_mutations"])
        self.assertEqual(8, result["killed_mutations"])
        self.assertEqual(1.0, result["mutation_kill_rate"])
        self.assertEqual(8, len(result["by_checker"]))

    def test_mutation_claim_is_scoped_to_published_checkers(self):
        manifest = json.loads(
            (ROOT / "benchmarks" / "mutations.json").read_text(encoding="utf-8")
        )
        self.assertIn("not all 116", manifest["method"])
        self.assertIn("checker shapes", manifest["method"])

    def test_materialized_case_rejects_path_escape(self):
        with self.assertRaises(ValueError):
            with BENCHMARK.materialized_case("escape", {"../outside.py": "x = 1\n"}):
                pass
        with self.assertRaises(ValueError):
            with BENCHMARK.materialized_case("escape", {"C:/outside.py": "x = 1\n"}):
                pass

    def test_real_repo_manifest_is_commit_pinned_and_non_vendored(self):
        manifest = json.loads(
            (ROOT / "benchmarks" / "real-repos.json").read_text(encoding="utf-8")
        )
        self.assertEqual(4, len(manifest["repositories"]))
        self.assertTrue(
            all(len(item["commit"]) == 40 for item in manifest["repositories"])
        )
        self.assertIn("never clones", manifest["method"])
        self.assertFalse((ROOT / "benchmarks" / "real-repos").exists())

    def test_v03_detector_and_checker_versions_are_evidence_bound(self):
        profile = self.profile_files(
            {"src/upload.ts": "new PutObjectCommand({Bucket, Key, Body});\n"}
        )
        self.assertTrue(
            all(
                item["detector"]["version"] == "0.3.0"
                for item in profile["observations"]
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "upload.ts").write_text(
                "new PutObjectCommand({Bucket, Key, Body});\n", encoding="utf-8"
            )
            current_profile = PROFILE.profile_repository(root)
            checks = CHECKS.check_repository(root, profile=current_profile)
        self.assertEqual("0.3.0", checks["subject"]["checker_version"])


if __name__ == "__main__":
    unittest.main()
