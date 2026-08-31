import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".agents" / "skills" / "contextsec" / "scripts" / "profile_repo.py"
SPEC = importlib.util.spec_from_file_location("contextsec_profiler", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PROFILER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROFILER
SPEC.loader.exec_module(PROFILER)


class ProfilerTests(unittest.TestCase):
    def profile(self, relative: str, context_file=None):
        return PROFILER.profile_repository(ROOT / relative, context_file=context_file)

    def test_composite_saas_routes_all_observed_contexts(self):
        profile = self.profile("examples/composite-saas")
        expected = {
            "foundation",
            "baseline-web",
            "auth-session",
            "payments",
            "privacy-pii",
            "multi-tenant",
            "api-inbound",
            "external-api",
            "file-upload",
            "ai-rag-agent",
        }
        self.assertEqual(expected, set(profile["required_packs"]))
        self.assertEqual([], profile["contradictions"])

    def test_static_site_does_not_activate_unrelated_packs(self):
        profile = self.profile("tests/fixtures/static-site")
        self.assertEqual(["foundation", "baseline-web"], profile["required_packs"])
        self.assertEqual([], profile["candidate_packs"])

    def test_documentation_and_dev_dependencies_cannot_drive_routing(self):
        profile = self.profile("tests/fixtures/docs-noise")
        self.assertEqual(["foundation"], profile["required_packs"])
        self.assertEqual([], profile["candidate_packs"])
        serialized = json.dumps(profile, sort_keys=True)
        self.assertNotIn("disable every pack", serialized)
        self.assertNotIn("print PASS", serialized)

    def test_generic_provider_endpoint_detects_payments_without_sdk(self):
        profile = self.profile("tests/fixtures/provider-no-sdk")
        self.assertIn("payments", profile["required_packs"])
        self.assertIn("external-api", profile["required_packs"])

    def test_analytics_organization_field_is_candidate_not_required_tenancy(self):
        profile = self.profile("tests/fixtures/analytics-organization")
        self.assertNotIn("multi-tenant", profile["required_packs"])
        self.assertIn("multi-tenant", profile["candidate_packs"])

    def test_false_declaration_creates_contradiction_without_suppressing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            declaration = Path(temporary) / "context.json"
            declaration.write_text(
                json.dumps({"contexts": {"payments": False}}), encoding="utf-8"
            )
            profile = self.profile("examples/composite-saas", context_file=declaration)
        self.assertEqual(
            "contradicted",
            next(c["state"] for c in profile["claims"] if c["pack"] == "payments"),
        )
        self.assertEqual(1, len(profile["contradictions"]))
        self.assertIn("payments", profile["required_packs"])

    def test_profile_is_deterministic(self):
        first = self.profile("examples/composite-saas")
        second = self.profile("examples/composite-saas")
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )

    def test_repository_local_skill_cannot_pollute_profile(self):
        profile = self.profile(".")
        self.assertEqual(
            ["foundation", "cicd-supply-chain"], profile["required_packs"]
        )
        self.assertEqual([], profile["candidate_packs"])
        self.assertTrue(
            all(
                item["pack"] == "cicd-supply-chain"
                for item in profile["observations"]
            )
        )

    def test_github_governance_files_cannot_pollute_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            issue_template = repository / ".github" / "ISSUE_TEMPLATE" / "detector.yml"
            issue_template.parent.mkdir(parents=True)
            issue_template.write_text(
                "description: Stripe payout auth and customer export detector\n",
                encoding="utf-8",
            )
            (repository / ".github" / "dependabot.yml").write_text(
                "version: 2\nupdates: []\n", encoding="utf-8"
            )
            profile = PROFILER.profile_repository(repository)
        self.assertEqual(["foundation"], profile["required_packs"])
        self.assertEqual([], profile["candidate_packs"])
        self.assertEqual([], profile["observations"])

    def test_ordinary_get_calls_are_not_http_routes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "one.py").write_text(
                'value = payload.get("payment")\n', encoding="utf-8"
            )
            (repository / "two.ts").write_text(
                'const value = config.get("route")\n', encoding="utf-8"
            )
            profile = PROFILER.profile_repository(repository)
        api_claim = next(c for c in profile["claims"] if c["pack"] == "api-inbound")
        self.assertEqual("unknown", api_claim["state"])
        self.assertNotIn("api-inbound", profile["required_packs"])

    def test_repeated_weak_detector_does_not_become_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "one.ts").write_text(
                "const organizationId = input.organizationId\n", encoding="utf-8"
            )
            (repository / "two.ts").write_text(
                "const organizationId = job.organizationId\n", encoding="utf-8"
            )
            profile = PROFILER.profile_repository(repository)
        tenant_claim = next(c for c in profile["claims"] if c["pack"] == "multi-tenant")
        self.assertEqual("medium", tenant_claim["inference_confidence"])
        self.assertIn("multi-tenant", profile["candidate_packs"])
        self.assertNotIn("multi-tenant", profile["required_packs"])

    def test_comments_and_prose_strings_cannot_create_callsite_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "decoy.ts").write_text(
                '// stripe.paymentIntents.create()\nconst note = "openai.responses.create"\n',
                encoding="utf-8",
            )
            profile = PROFILER.profile_repository(repository)
        self.assertEqual(["foundation"], profile["required_packs"])
        self.assertEqual([], profile["observations"])

    def test_template_expression_is_code_but_template_prose_is_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            source = repository / "template.ts"
            source.write_text(
                "const result = `answer: ${await openai.responses.create({ input })}`;\n",
                encoding="utf-8",
            )
            positive = PROFILER.profile_repository(repository)
            source.write_text(
                "const result = `openai.responses.create({ input })`;\n",
                encoding="utf-8",
            )
            negative = PROFILER.profile_repository(repository)
        self.assertIn("ai-rag-agent", positive["required_packs"])
        self.assertIn("external-api", positive["required_packs"])
        self.assertEqual(["foundation"], negative["required_packs"])

    def test_content_bound_evidence_changes_without_changing_stable_ids(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            source = repository / "billing.ts"
            source.write_text(
                "stripe.paymentIntents.create({ amount });\n", encoding="utf-8"
            )
            first = PROFILER.profile_repository(repository)["observations"][0]["evidence"]
            source.write_text(
                "stripe.paymentIntents.create({ amount });\nconst unrelated = 1;\n",
                encoding="utf-8",
            )
            second = PROFILER.profile_repository(repository)["observations"][0]["evidence"]
        self.assertEqual(first["evidence_id"], second["evidence_id"])
        self.assertEqual(first["location_id"], second["location_id"])
        self.assertNotEqual(first["content_digest"], second["content_digest"])
        self.assertNotEqual(first["fingerprint"], second["fingerprint"])
        self.assertNotEqual(first["subject_revision"], second["subject_revision"])

    def test_subject_revision_changes_when_declarations_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            repository.mkdir()
            first_context = Path(temporary) / "first.json"
            second_context = Path(temporary) / "second.json"
            first_context.write_text(
                json.dumps({"contexts": {"payments": True}}), encoding="utf-8"
            )
            second_context.write_text(
                json.dumps({"contexts": {"payments": False}}), encoding="utf-8"
            )
            first = PROFILER.profile_repository(repository, context_file=first_context)
            second = PROFILER.profile_repository(
                repository, context_file=second_context
            )
        self.assertNotEqual(
            first["subject"]["subject_revision"],
            second["subject"]["subject_revision"],
        )

    def test_duplicate_context_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            repository.mkdir()
            declaration = Path(temporary) / "context.json"
            declaration.write_text(
                '{"contexts":{"payments":true,"payments":false}}', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
                PROFILER.profile_repository(repository, context_file=declaration)

    def test_optional_payment_dependency_plus_import_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "package.json").write_text(
                json.dumps({"optionalDependencies": {"stripe": "1.0.0"}}),
                encoding="utf-8",
            )
            (repository / "billing.ts").write_text(
                'import Stripe from "stripe";\nconst client = new Stripe(key);\n',
                encoding="utf-8",
            )
            profile = PROFILER.profile_repository(repository)
        self.assertIn("payments", profile["required_packs"])

    def test_form_data_call_activates_upload_pack(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "upload.ts").write_text(
                "const form = await request.formData();\n", encoding="utf-8"
            )
            profile = PROFILER.profile_repository(repository)
        self.assertIn("file-upload", profile["required_packs"])

    def test_partial_coverage_is_explicit_and_scope_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            source = repository / "large.ts"
            source.write_text("a" * 100, encoding="utf-8")
            first = PROFILER.profile_repository(repository, max_file_bytes=10)
            source.write_text("b" * 101, encoding="utf-8")
            second = PROFILER.profile_repository(repository, max_file_bytes=10)
        self.assertEqual("partial", first["coverage"]["status"])
        self.assertEqual(1, first["coverage"]["skip_counts"]["file_size_limit"])
        self.assertNotEqual(
            first["subject"]["subject_revision"],
            second["subject"]["subject_revision"],
        )

    def test_javascript_decrement_does_not_mask_following_ai_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "agent.ts").write_text(
                "let n = 2; n--; openai.responses.create({ input });\n",
                encoding="utf-8",
            )
            profile = PROFILER.profile_repository(repository)
        self.assertIn("ai-rag-agent", profile["required_packs"])
        self.assertIn("external-api", profile["required_packs"])

    def test_javascript_private_field_does_not_start_a_comment(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "agent.ts").write_text(
                "class Agent { #client = openai; run() { return this.#client.responses.create({ input }); } }\n",
                encoding="utf-8",
            )
            profile = PROFILER.profile_repository(repository)
        self.assertIn("ai-rag-agent", profile["required_packs"])
        self.assertIn("external-api", profile["required_packs"])

    def test_python_and_sql_comment_markers_remain_language_specific(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "decoy.py").write_text(
                "value = 1  # openai.responses.create({ input })\n",
                encoding="utf-8",
            )
            (repository / "decoy.sql").write_text(
                "SELECT 1; -- openai.responses.create({ input })\n",
                encoding="utf-8",
            )
            profile = PROFILER.profile_repository(repository)
        self.assertNotIn("ai-rag-agent", profile["required_packs"])

    def test_python_fstring_expression_is_code_but_escaped_braces_are_prose(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            source = repository / "agent.py"
            source.write_text(
                'result = f"answer: {openai.responses.create(input=user_data)}"\n',
                encoding="utf-8",
            )
            positive = PROFILER.profile_repository(repository)
            source.write_text(
                'result = f"example: {{openai.responses.create(input=user_data)}}"\n',
                encoding="utf-8",
            )
            negative = PROFILER.profile_repository(repository)
        self.assertIn("ai-rag-agent", positive["required_packs"])
        self.assertIn("external-api", positive["required_packs"])
        self.assertNotIn("ai-rag-agent", negative["required_packs"])

    def test_raw_fstring_brace_and_format_spec_are_distinguished(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            source = repository / "agent.py"
            source.write_text(
                'result = rf"\\{openai.responses.create(input=user_data)}"\n',
                encoding="utf-8",
            )
            positive = PROFILER.profile_repository(repository)
            source.write_text(
                'result = f"{value:openai.responses.create}"\n',
                encoding="utf-8",
            )
            format_prose = PROFILER.profile_repository(repository)
            source.write_text(
                'result = f"{value:{openai.responses.create(input=user_data)}}"\n',
                encoding="utf-8",
            )
            nested_positive = PROFILER.profile_repository(repository)
        self.assertIn("ai-rag-agent", positive["required_packs"])
        self.assertNotIn("ai-rag-agent", format_prose["required_packs"])
        self.assertIn("ai-rag-agent", nested_positive["required_packs"])

    def test_mysql_hash_comment_cannot_activate_payment_pack(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "schema.sql").write_text(
                "# cvv is intentionally not stored\nSELECT 1;\n",
                encoding="utf-8",
            )
            profile = PROFILER.profile_repository(repository)
        self.assertNotIn("payments", profile["required_packs"])

    def test_sql_hash_operators_and_dash_boundaries_are_not_comments(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            source = repository / "schema.sql"
            source.write_text(
                "SELECT 1; # cvv is intentionally not stored\n",
                encoding="utf-8",
            )
            mysql_comment = PROFILER.profile_repository(repository)
            source.write_text(
                "SELECT payload #> path, cvv FROM cards;\n",
                encoding="utf-8",
            )
            postgres_operator = PROFILER.profile_repository(repository)
            source.write_text(
                "SELECT 1--cvv FROM cards;\n",
                encoding="utf-8",
            )
            mysql_subtraction = PROFILER.profile_repository(repository)
            source.write_text(
                "SELECT payload #- path, cvv FROM cards;\n",
                encoding="utf-8",
            )
            postgres_delete_operator = PROFILER.profile_repository(repository)
            source.write_text(
                "SELECT flags # mask, cvv FROM cards;\n",
                encoding="utf-8",
            )
            postgres_xor_operator = PROFILER.profile_repository(repository)
            source.write_text(
                "--cvv is intentionally not stored\nSELECT 1;\n",
                encoding="utf-8",
            )
            compact_comment = PROFILER.profile_repository(repository)
            source.write_text(
                "SELECT 1 # cvv not stored\n",
                encoding="utf-8",
            )
            mysql_inline_comment = PROFILER.profile_repository(repository)
            source.write_text(
                "SELECT (flags) # (mask), cvv FROM cards;\n",
                encoding="utf-8",
            )
            parenthesized_xor = PROFILER.profile_repository(repository)
            source.write_text(
                "SELECT 1; --cvv not stored\n",
                encoding="utf-8",
            )
            inline_compact_comment = PROFILER.profile_repository(repository)
        self.assertNotIn("payments", mysql_comment["required_packs"])
        self.assertIn("payments", postgres_operator["required_packs"])
        self.assertIn("payments", mysql_subtraction["required_packs"])
        self.assertIn("payments", postgres_delete_operator["required_packs"])
        self.assertIn("payments", postgres_xor_operator["required_packs"])
        self.assertNotIn("payments", compact_comment["required_packs"])
        self.assertNotIn("payments", mysql_inline_comment["required_packs"])
        self.assertIn("payments", parenthesized_xor["required_packs"])
        self.assertNotIn("payments", inline_compact_comment["required_packs"])

    def test_evidence_never_contains_matched_source_text(self):
        profile = self.profile("examples/composite-saas")
        for observation in profile["observations"]:
            self.assertEqual(
                {
                    "path",
                    "locator",
                    "evidence_id",
                    "location_id",
                    "content_digest",
                    "fingerprint",
                    "subject_revision",
                },
                set(observation["evidence"]),
            )
        serialized = json.dumps(profile, sort_keys=True)
        self.assertNotIn("STRIPE_SECRET_KEY", serialized)
        self.assertNotIn("public-read", serialized)

    def test_explicit_true_declaration_can_add_context_without_fake_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "empty-repo"
            repository.mkdir()
            declaration = Path(temporary) / "context.json"
            declaration.write_text(
                json.dumps({"contexts": {"privacy-pii": True}}), encoding="utf-8"
            )
            profile = PROFILER.profile_repository(repository, context_file=declaration)
        claim = next(c for c in profile["claims"] if c["pack"] == "privacy-pii")
        self.assertEqual("present", claim["state"])
        self.assertEqual("declared", claim["source"])
        self.assertEqual([], claim["evidence_refs"])
        self.assertIn("privacy-pii", profile["required_packs"])

    def test_true_declaration_with_medium_evidence_remains_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            declaration = Path(temporary) / "context.json"
            declaration.write_text(
                json.dumps({"contexts": {"multi-tenant": True}}), encoding="utf-8"
            )
            profile = self.profile(
                "tests/fixtures/analytics-organization", context_file=declaration
            )
        claim = next(c for c in profile["claims"] if c["pack"] == "multi-tenant")
        self.assertEqual("combined", claim["source"])
        self.assertEqual("medium", claim["inference_confidence"])
        self.assertIn("multi-tenant", profile["required_packs"])
        self.assertIn("auth-session", profile["required_packs"])

    def test_symlink_outside_repository_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repo"
            repository.mkdir()
            outside = base / "outside.ts"
            outside.write_text(
                'fetch("https://api.stripe.com/v1/payment_intents")', encoding="utf-8"
            )
            link = repository / "linked.ts"
            try:
                os.symlink(outside, link)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks are unavailable in this environment")
            profile = PROFILER.profile_repository(repository)
        self.assertEqual(["foundation"], profile["required_packs"])
        self.assertEqual([], profile["observations"])

    def test_windows_reparse_attribute_is_treated_as_link_like(self):
        reparse_flag = getattr(PROFILER.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        fake = types.SimpleNamespace(st_file_attributes=reparse_flag)
        self.assertTrue(PROFILER.has_reparse_attribute(fake))

    def test_oversized_source_is_skipped_not_partially_trusted(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            repository.mkdir()
            (repository / "billing.ts").write_text(
                'fetch("https://api.stripe.com/v1/payment_intents")' + ("x" * 1000),
                encoding="utf-8",
            )
            profile = PROFILER.profile_repository(repository, max_file_bytes=64)
        self.assertEqual(["foundation"], profile["required_packs"])
        self.assertEqual(1, profile["subject"]["files_skipped"])

    def test_max_files_bounds_oversized_candidates(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            for index in range(8):
                (repository / f"large-{index}.ts").write_text(
                    "x" * 100, encoding="utf-8"
                )
            profile = PROFILER.profile_repository(
                repository, max_files=2, max_file_bytes=10
            )
        self.assertEqual(2, profile["subject"]["files_skipped"])
        self.assertTrue(
            any("File limit reached" in item for item in profile["limitations"])
        )

    def test_utf16_source_is_profiled(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "billing.ts").write_text(
                'fetch("https://api.stripe.com/v1/payment_intents")',
                encoding="utf-16",
            )
            profile = PROFILER.profile_repository(repository)
        self.assertIn("payments", profile["required_packs"])

    def test_unrelated_pan_and_messages_methods_do_not_activate_packs(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "camera.ts").write_text(
                "camera.pan(4); mailer.messages.create(payload);\n", encoding="utf-8"
            )
            profile = PROFILER.profile_repository(repository)
        self.assertEqual(["foundation"], profile["required_packs"])
        self.assertEqual([], profile["candidate_packs"])

    def test_markdown_escapes_repository_controlled_labels(self):
        profile = self.profile("examples/composite-saas")
        profile["subject"]["repository"] = "bad`name\n# injected"
        profile["observations"][0]["evidence"]["path"] = "bad`path\n# injected"
        rendered = PROFILER.render_markdown(profile)
        self.assertIn("bad%60name\\n# injected", rendered)
        self.assertIn("bad%60path\\n# injected", rendered)
        self.assertNotIn("bad`name\n# injected", rendered)

    def test_sensitive_path_segments_are_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "alice@example.com.ts").write_text(
                'fetch("https://api.stripe.com/v1/payment_intents")', encoding="utf-8"
            )
            profile = PROFILER.profile_repository(repository)
        serialized = json.dumps(profile, sort_keys=True)
        self.assertNotIn("alice@example.com", serialized)
        self.assertIn("[redacted-email]", serialized)

    def test_atomic_output_does_not_modify_hardlink_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            # macOS exposes its system temporary directory through /var, which is
            # itself a symlink to /private/var. Canonicalize that trusted test
            # fixture root so this test isolates hardlink replacement behavior.
            base = Path(temporary).resolve(strict=True)
            original = base / "outside.txt"
            output = base / "profile.json"
            original.write_text("keep", encoding="utf-8")
            try:
                os.link(original, output)
            except OSError:
                self.skipTest("Hardlinks are unavailable in this environment")
            PROFILER.write_output_atomic(output, "replacement")
            self.assertEqual("keep", original.read_text(encoding="utf-8"))
            self.assertEqual("replacement", output.read_text(encoding="utf-8"))

    def test_atomic_output_refuses_symlink_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve(strict=True)
            real_directory = base / "real"
            linked_directory = base / "linked"
            real_directory.mkdir()
            try:
                os.symlink(real_directory, linked_directory, target_is_directory=True)
            except OSError:
                self.skipTest("Symlinks are unavailable in this environment")
            with self.assertRaisesRegex(ValueError, "symlink or reparse point"):
                PROFILER.write_output_atomic(linked_directory / "profile.json", "data")

    def test_deep_invalid_manifest_abstains_without_crashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "package.json").write_text(
                "[" * 2000 + "]" * 2000, encoding="utf-8"
            )
            profile = PROFILER.profile_repository(repository)
        self.assertEqual(["foundation"], profile["required_packs"])
        self.assertTrue(
            any("could not be parsed" in item for item in profile["limitations"])
        )

    def test_auth_no_argument_and_clerk_dependency_form_a_required_route(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "package.json").write_text(
                json.dumps(
                    {"dependencies": {"next": "15", "@clerk/nextjs": "6"}}
                ),
                encoding="utf-8",
            )
            (repository / "route.ts").write_text(
                "const { orgId } = await auth();\n", encoding="utf-8"
            )
            positive = PROFILER.profile_repository(repository)
            (repository / "route.ts").write_text(
                'const example = "await auth()";\n', encoding="utf-8"
            )
            negative = PROFILER.profile_repository(repository)
        positive_routes = {item["pack"]: item["state"] for item in positive["routing"]}
        negative_routes = {item["pack"]: item["state"] for item in negative["routing"]}
        self.assertEqual("required", positive_routes["auth-session"])
        self.assertEqual("candidate", positive_routes["multi-tenant"])
        self.assertEqual("candidate", negative_routes["auth-session"])

    def test_org_alias_routes_tenancy_but_bare_account_alias_does_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            source = repository / "model.ts"
            source.write_text(
                'const orgId = row.orgId; const dbName = "org_id";\n',
                encoding="utf-8",
            )
            positive = PROFILER.profile_repository(repository)
            source.write_text("const accountId = user.accountId;\n", encoding="utf-8")
            negative = PROFILER.profile_repository(repository)
        self.assertIn("multi-tenant", positive["candidate_packs"])
        self.assertNotIn("multi-tenant", negative["candidate_packs"])

    def test_public_env_values_are_never_evidence_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "package.json").write_text(
                '{"dependencies":{"next":"15"}}\n', encoding="utf-8"
            )
            dotenv = repository / ".env.local"
            dotenv.write_text(
                "NEXT_PUBLIC_STRIPE_SECRET_KEY=FIRST_PRIVATE_VALUE\n",
                encoding="utf-8",
            )
            first = PROFILER.profile_repository(repository)
            dotenv.write_text(
                "NEXT_PUBLIC_STRIPE_SECRET_KEY=SECOND_DIFFERENT_PRIVATE_VALUE\n",
                encoding="utf-8",
            )
            second = PROFILER.profile_repository(repository)
        serialized = json.dumps(second, sort_keys=True)
        self.assertNotIn("SECOND_DIFFERENT_PRIVATE_VALUE", serialized)
        self.assertEqual(
            first["subject"]["subject_revision"],
            second["subject"]["subject_revision"],
        )
        self.assertIn(
            "client-public-secret-env-key",
            {item["detector"]["id"] for item in second["observations"]},
        )

    def test_stack_support_is_separate_from_traversal_completeness(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "go.mod").write_text(
                "module example.invalid/contextsec\n\ngo 1.24\n", encoding="utf-8"
            )
            (repository / "main.go").write_text(
                "package main\nfunc main() {}\n", encoding="utf-8"
            )
            unsupported = PROFILER.profile_repository(repository)
            (repository / "package.json").write_text(
                '{"dependencies":{"next":"15"}}\n', encoding="utf-8"
            )
            mixed = PROFILER.profile_repository(repository)
        self.assertEqual("complete", unsupported["coverage"]["status"])
        self.assertEqual("unsupported", unsupported["coverage"]["language_support"])
        self.assertEqual("partial", mixed["coverage"]["language_support"])

    def test_taiwan_payment_provider_endpoints_route_payments(self):
        for endpoint in (
            "https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5",
            "https://ccore.newebpay.com/MPG/mpg_gateway",
            "https://sandbox.tappaysdk.com/tpc/payment/pay-by-prime",
        ):
            with self.subTest(endpoint=endpoint), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary)
                (repository / "billing.ts").write_text(
                    'fetch("' + endpoint + '");\n', encoding="utf-8"
                )
                profile = PROFILER.profile_repository(repository)
            self.assertIn("payments", profile["required_packs"])

    def test_benchmark_manifest_matches_profiles(self):
        benchmark = json.loads(
            (ROOT / "benchmarks" / "scenarios.json").read_text(encoding="utf-8")
        )
        for scenario in benchmark["automated"]:
            profile = self.profile(scenario["fixture"])
            routing = {item["pack"]: item["state"] for item in profile["routing"]}
            confidence = {
                item["pack"]: item["inference_confidence"] for item in profile["claims"]
            }
            for pack, expected in scenario["expected"].items():
                self.assertEqual(
                    expected["routed_state"], routing[pack], scenario["id"]
                )
                if pack != "foundation":
                    self.assertEqual(
                        expected["direct_evidence_state"],
                        confidence[pack],
                        scenario["id"],
                    )


if __name__ == "__main__":
    unittest.main()
