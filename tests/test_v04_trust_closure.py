from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / ".agents" / "skills" / "contextsec" / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import audit_ci  # noqa: E402
import attestation_verifier  # noqa: E402
import component_profile  # noqa: E402
import evaluate_holdout  # noqa: E402
import model_digest  # noqa: E402
import profile_repo  # noqa: E402
import release_evidence  # noqa: E402
import verification_coverage  # noqa: E402


def _git_repository(path: Path, remote: str = "https://github.com/example/monorepo.git") -> str:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(path), "config", "user.name", "Test"], check=True
    )
    subprocess.run(
        ["git", "-C", str(path), "remote", "add", "origin", remote], check=True
    )
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(path), "commit", "-q", "-m", "fixture"], check=True
    )
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


class V04TrustClosureTests(unittest.TestCase):
    def test_holdout_trust_requires_labels_to_be_attested_before_predictions(self):
        trust = {
            "labels": {"status": "verified", "verified_at": "2026-08-31T01:00:00+00:00"},
            "predictions": {"status": "verified", "verified_at": "2026-08-31T02:00:00+00:00"},
        }
        self.assertTrue(evaluate_holdout._trusted_evidence(trust))
        reversed_trust = json.loads(json.dumps(trust))
        reversed_trust["labels"]["verified_at"] = "2026-08-31T03:00:00+00:00"
        self.assertFalse(evaluate_holdout._trusted_evidence(reversed_trust))
        naive = json.loads(json.dumps(trust))
        naive["labels"]["verified_at"] = "2026-08-31T01:00:00"
        self.assertFalse(evaluate_holdout._trusted_evidence(naive))

    def test_attestation_verifier_requires_digest_bound_signer_and_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "labels.json"
            artifact.write_text("{}", encoding="utf-8")
            digest = __import__("hashlib").sha256(artifact.read_bytes()).hexdigest()
            verified = [{
                "verificationResult": {
                    "statement": {"subject": [{"digest": {"sha256": digest}}]},
                    "signature": {"certificate": {
                        "subjectAlternativeName": "https://github.com/example/labels/.github/workflows/attest.yml@refs/heads/main",
                        "sourceRepositoryDigest": "a" * 40,
                    }},
                    "verifiedTimestamps": [{
                        "timestamp": "2026-08-31T01:00:00+00:00",
                        "type": "Tlog",
                        "uri": "https://rekor.sigstore.dev",
                    }],
                }
            }]
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps(verified).encode(), stderr=b""
            )
            with mock.patch("attestation_verifier.subprocess.run", return_value=completed) as run:
                result = attestation_verifier.verify(
                    artifact,
                    "example/labels",
                    signer_workflow="https://github.com/example/labels/.github/workflows/attest.yml",
                )
            self.assertEqual("verified", result["status"])
            self.assertEqual("2026-08-31T01:00:00+00:00", result["verified_at"])
            self.assertIn(
                "github.com/example/labels/.github/workflows/attest.yml",
                run.call_args.args[0],
            )
            self.assertNotIn(
                "https://github.com/example/labels/.github/workflows/attest.yml",
                run.call_args.args[0],
            )
    def test_semantic_model_digest_ignores_comments_but_tracks_behavior_and_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.py"
            comments = Path(temporary) / "comments.py"
            behavior = Path(temporary) / "behavior.py"
            first.write_text("VALUE = 1\ndef decide(x):\n    return x + VALUE\n", encoding="utf-8")
            comments.write_text("# prose only\nVALUE=1\n\ndef decide(x):\n    return x + VALUE  # same\n", encoding="utf-8")
            behavior.write_text("VALUE = 2\ndef decide(x):\n    return x + VALUE\n", encoding="utf-8")
            kwargs = {"symbols": ("VALUE", "decide"), "dependencies": {"safe_io": "sha256:" + "1" * 64}}
            baseline = model_digest.semantic_model_digest(path=first, **kwargs)
            self.assertEqual(baseline, model_digest.semantic_model_digest(path=comments, **kwargs))
            self.assertNotEqual(baseline, model_digest.semantic_model_digest(path=behavior, **kwargs))
            changed_dependency = model_digest.semantic_model_digest(
                path=first,
                symbols=("VALUE", "decide"),
                dependencies={"safe_io": "sha256:" + "2" * 64},
            )
            self.assertNotEqual(baseline, changed_dependency)

    def test_profile_git_provenance_requires_a_clean_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            source = repository / "package.json"
            source.write_text('{"dependencies":{"next":"1.0.0"}}', encoding="utf-8")
            commit = _git_repository(repository, "https://github.com/example/provenance.git")
            clean = profile_repo.profile_repository(repository)
            self.assertEqual(
                {
                    "status": "verified",
                    "vcs": "git",
                    "repository": "https://github.com/example/provenance",
                    "commit": commit,
                    "worktree": "clean",
                },
                clean["subject"]["source_provenance"],
            )
            source.write_text('{"dependencies":{"next":"2.0.0"}}', encoding="utf-8")
            dirty = profile_repo.profile_repository(repository)
            self.assertEqual("dirty", dirty["subject"]["source_provenance"]["status"])
            self.assertNotEqual(
                clean["subject"]["subject_revision"], dirty["subject"]["subject_revision"]
            )

    def test_profile_git_provenance_supports_linked_worktrees(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            worktree = Path(temporary) / "worktree"
            repository.mkdir()
            (repository / "package.json").write_text(
                '{"dependencies":{"next":"1.0.0"}}', encoding="utf-8"
            )
            commit = _git_repository(
                repository, "git@github.com:example/worktree-provenance.git"
            )
            subprocess.run(
                ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(worktree), "HEAD"],
                check=True,
            )
            profile = profile_repo.profile_repository(worktree)
            self.assertEqual("verified", profile["subject"]["source_provenance"]["status"])
            self.assertEqual(commit, profile["subject"]["source_provenance"]["commit"])
            self.assertEqual(
                "https://github.com/example/worktree-provenance",
                profile["subject"]["source_provenance"]["repository"],
            )

    def test_component_profile_binds_non_overlapping_components_and_flows(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "monorepo"
            (repository / "apps" / "web").mkdir(parents=True)
            (repository / "services" / "api").mkdir(parents=True)
            (repository / "apps" / "web" / "package.json").write_text(
                '{"dependencies":{"next":"1.0.0"}}', encoding="utf-8"
            )
            (repository / "services" / "api" / "requirements.txt").write_text(
                "fastapi==1.0\n", encoding="utf-8"
            )
            manifest = {
                "$schema": component_profile.MODEL_SCHEMA_URL,
                "schema_version": "0.4.0",
                "components": [
                    {"id": "web", "root": "apps/web", "kind": "application", "depends_on": ["api"]},
                    {"id": "api", "root": "services/api", "kind": "service", "depends_on": []},
                ],
                "flows": [
                    {"id": "web_to_api", "from": "web", "to": "api", "capabilities": ["http.request"], "evidence_refs": ["architecture:public-api"]}
                ],
            }
            (repository / "contextsec.components.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            _git_repository(repository)
            before = subprocess.run(
                ["git", "-C", str(repository), "status", "--porcelain=v1", "--untracked-files=all"],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout
            self.assertEqual("", before)
            result = component_profile.build(
                repository, Path("contextsec.components.json")
            )
            self.assertEqual([], component_profile.validate(result))
            self.assertEqual({"api", "web"}, {item["id"] for item in result["components"]})
            self.assertTrue(
                all(
                    item["profile"]["subject"]["source_provenance"]["status"] == "verified"
                    for item in result["components"]
                ),
                {
                    "provenance": [
                    item["profile"]["subject"]["source_provenance"]
                    for item in result["components"]
                    ],
                    "git_status": subprocess.run(
                        ["git", "-C", str(repository), "status", "--porcelain=v1", "--untracked-files=all"],
                        check=True,
                        stdout=subprocess.PIPE,
                        text=True,
                    ).stdout,
                },
            )
            tampered = json.loads(json.dumps(result))
            tampered["components"][0]["profile_artifact_digest"] = "sha256:" + "0" * 64
            self.assertTrue(component_profile.validate(tampered))
            forged_model = json.loads(json.dumps(result))
            forged_model["component_model"]["components"][0]["depends_on"] = ["missing"]
            forged_model["subject"]["component_model_digest"] = profile_repo.canonical_digest(
                forged_model["component_model"]
            )
            self.assertTrue(component_profile.validate(forged_model))
            overlapping = json.loads(json.dumps(manifest))
            overlapping["components"][1]["root"] = "apps/web/nested"
            (repository / "overlap.json").write_text(json.dumps(overlapping), encoding="utf-8")
            with self.assertRaises(ValueError):
                component_profile.load_model(repository, Path("overlap.json"))

    def test_ci_parser_audits_docker_digests_and_effective_job_permissions(self):
        workflow = """permissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n  publish:\n    permissions:\n      contents: write\n      id-token: write\n"""
        top, jobs = audit_ci._effective_job_permissions(workflow)
        self.assertEqual({"contents": "read"}, top)
        self.assertEqual({"contents": "read"}, jobs["test"])
        self.assertEqual(
            {"contents": "write", "id-token": "write"}, jobs["publish"]
        )
        self.assertIsNone(audit_ci.IMMUTABLE_DOCKER.fullmatch("docker://alpine:latest"))
        self.assertIsNotNone(
            audit_ci.IMMUTABLE_DOCKER.fullmatch(
                "docker://alpine@sha256:" + "a" * 64
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            copy = Path(temporary) / "repo"
            shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            ci_path = copy / ".github" / "workflows" / "ci.yml"
            ci_path.write_text(
                ci_path.read_text(encoding="utf-8").replace(
                    "      contents: read", "      contents: write"
                ),
                encoding="utf-8",
            )
            audit = audit_ci.audit_repository(copy)
            self.assertEqual("fail", audit["status"])
            self.assertTrue(any("effective job permissions" in item for item in audit["issues"]))
            permission_path = copy / "ci" / "workflow-permissions.json"
            permissions = json.loads(permission_path.read_text(encoding="utf-8"))
            permissions["workflows"][".github/workflows/missing.yml"] = {
                "test": {"contents": "read"}
            }
            permission_path.write_text(json.dumps(permissions), encoding="utf-8")
            audit = audit_ci.audit_repository(copy)
            self.assertTrue(any("workflow inventory is not exact" in item for item in audit["issues"]))

    def test_verification_coverage_is_complete_and_non_inflated(self):
        result = verification_coverage.build()
        expected = sum(
            len(pack["controls"]) for pack in profile_repo.PACK_CATALOG["packs"]
        ) + len(profile_repo.COMPOSITION_CATALOG["rules"])
        self.assertEqual(expected, result["summary"]["total"])
        self.assertLess(result["summary"]["automated"], expected)
        self.assertEqual(
            expected,
            result["summary"]["automated"]
            + result["summary"]["evidence_required"],
        )
        self.assertEqual(expected, len({item["id"] for item in result["items"]}))

    def test_release_evidence_binds_exact_main_models_coverage_and_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "contextsec-v0.4.0.zip"
            archive.write_bytes(b"deterministic archive")
            commit = "a" * 40
            payload = release_evidence.build(
                archive,
                tag="v0.4.0",
                source_commit=commit,
                main_commit=commit,
                workflow_run="https://github.com/example/repository/actions/runs/1/attempts/1",
                proof_result="success",
                immutable_releases_enabled=True,
            )
            self.assertEqual([], release_evidence.validate(payload))
            self.assertEqual(
                release_evidence.file_digest(archive), payload["artifact"]["sha256"]
            )
            tampered = json.loads(json.dumps(payload))
            tampered["verification_coverage"]["summary"]["automated"] += 1
            self.assertTrue(release_evidence.validate(tampered))
            with self.assertRaises(ValueError):
                release_evidence.build(
                    archive,
                    tag="v0.4.0",
                    source_commit=commit,
                    main_commit="b" * 40,
                    workflow_run="https://github.com/example/repository/actions/runs/1/attempts/1",
                    proof_result="success",
                    immutable_releases_enabled=True,
                )


if __name__ == "__main__":
    unittest.main()
