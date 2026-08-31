import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / ".agents" / "skills" / "contextsec" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import profile_repo as PROFILER  # noqa: E402


TEXT_CASES = {
    "next-api-route": ("app/api/orders/route.ts", "export async function GET() {}"),
    "generic-http-route": ("src/server.ts", "app.get(path, handler);"),
    "authentication-code": ("src/auth.ts", "const session = await auth();"),
    "payment-callsite": ("src/pay.ts", "stripe.paymentIntents.create(input);"),
    "payment-sdk-import": ("src/pay.ts", 'import Stripe from "stripe";'),
    "payment-provider-endpoint": (
        "src/pay.ts",
        'fetch("https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5");',
    ),
    "payment-webhook-callsite": (
        "src/hook.ts",
        "stripe.webhooks.constructEvent(body, sig, secret);",
    ),
    "raw-card-data-field": ("src/card.ts", "const cardNumber = input.cardNumber;"),
    "prisma-pii-field": ("prisma/schema.prisma", "model User {\n email String\n}"),
    "python-pii-model": (
        "src/models.py",
        "class User(SQLModel):\n    email: str\n",
    ),
    "source-pii-shape": ("src/user.ts", "const email = user.email; const phone = user.phone;"),
    "tenant-schema-field": ("prisma/schema.prisma", "model Order {\n orgId String\n}"),
    "prisma-tenant-model": (
        "prisma/schema.prisma",
        "model Org {\n id String @id\n}\nmodel User {\n orgId String\n}\n",
    ),
    "python-tenant-model": (
        "src/models.py",
        "class User(SQLModel):\n    org_id: str\n",
    ),
    "tenant-code-field": ("src/tenant.ts", "const orgId = session.orgId;"),
    "tenant-contextual-alias": (
        "src/account.ts",
        "const accountId = membership.accountId; const tenantRole = membership.role;",
    ),
    "outbound-http-call": ("src/http.ts", "fetch(target);"),
    "file-upload-callsite": ("src/upload.ts", "const form = await request.formData();"),
    "ai-callsite": ("src/ai.ts", "openai.responses.create(input);"),
    "ai-provider-callsite": ("src/ai.ts", "openai.responses.create(input);"),
    "secret-plane-callsite": ("src/secrets.ts", "new SecretsManagerClient(config);"),
    "secret-plane-schema": (
        "prisma/schema.prisma",
        "model Secret {\n id String @id\n encryptedValue String\n}\n",
    ),
    "cloud-iam-infrastructure": ("infra/main.tf", 'resource "aws_iam_role" "app" {}'),
    "cicd-workflow": (".github/workflows/ci.yml", "jobs:\n  test:\n    steps: []\n"),
    "saas-oauth-callsite": ("src/slack.ts", "const slackOauthScopes = scopes;"),
    "support-admin-surface": (
        "app/api/admin/impersonate/route.ts",
        "startSupportSession(userId);",
    ),
    "high-impact-transaction": ("src/payout.ts", "payouts.create(input);"),
    "feature-web-admin-surface": (
        "app/api/admin/route.ts",
        "const admin = requireAdmin();",
    ),
    "feature-web-cookie-auth": ("src/session.ts", "const jar = cookies();"),
    "feature-web-state-change": ("app/api/order/route.ts", "export async function POST() {}"),
    "feature-web-sensitive-response": (
        "src/response.ts",
        "return NextResponse.json({ email });",
    ),
    "feature-server-actions": ("src/action.ts", "return prisma.user.findMany();"),
    "feature-secrets-used": ("src/config.ts", "process.env.OPENAI_API_KEY;"),
    "client-public-secret-reference": (
        "src/client.ts",
        "process.env.NEXT_PUBLIC_WEBHOOK_SECRET;",
    ),
    "client-public-secret-env-key": (
        ".env.local",
        "NEXT_PUBLIC_STRIPE_SECRET_KEY=\n",
    ),
    "feature-failure-prone-processing": ("src/parser.ts", "JSON.parse(payload);"),
    "feature-auth-password-login": ("src/login.ts", "login({ password });"),
    "feature-auth-recovery": ("src/recovery.ts", "resetPassword(recoveryToken);"),
    "feature-auth-oauth": ("src/oauth.ts", "const flow = authorizationCode;"),
    "feature-auth-api-token": ("src/token.ts", "const authorization = bearerToken;"),
    "feature-payment-subscription": ("src/sub.ts", "subscriptions.create(input);"),
    "feature-payment-webhook": ("src/hook.ts", "webhooks.constructEvent(body, sig, secret);"),
    "feature-payment-refund": ("src/refund.ts", "refunds.create(input);"),
    "feature-payment-payout": ("src/payout.ts", "payouts.create(input);"),
    "feature-ai-rag": ("src/rag.ts", "similaritySearch(query);"),
    "feature-user-controlled-destination": ("src/proxy.ts", "fetch(req.url);"),
    "feature-ai-tools": ("src/tools.ts", "const request = { tool_calls };"),
    "feature-ai-memory": ("src/memory.ts", "saveMemory(message);"),
    "feature-ai-autonomous-action": ("src/agent.ts", "executeToolLoop(task);"),
    "feature-cicd-package-publish": (".github/workflows/release.yml", "run: npm publish\n"),
    "feature-cicd-cloud-deploy": (".github/workflows/deploy.yml", "run: terraform apply\n"),
    "feature-cicd-untrusted-pr": (".github/workflows/pr.yml", "pull_request:\n"),
    "feature-cicd-oidc": (
        ".github/workflows/deploy.yml",
        "id-token: write\nrun: terraform apply\n",
    ),
    "feature-support-impersonation": ("src/support.ts", "impersonate(userId);"),
    "feature-support-bulk-access": ("src/export.ts", "exportAllCustomers();"),
    "feature-high-impact-transaction": ("src/admin.ts", "deleteTenant(tenantId);"),
}

TARGETED_NEGATIVES = {
    "authentication-code": ("src/auth.ts", 'const example = "await auth()";'),
    "payment-provider-endpoint": ("src/pay.ts", 'fetch("https://api.stripe.example");'),
    "payment-sdk-import": ("src/pay.ts", 'const example = "from stripe import Stripe";'),
    "source-pii-shape": ("src/user.ts", "const email = user.email;"),
    "tenant-code-field": ("src/tenant.ts", "const organizationName = input.name;"),
    "tenant-contextual-alias": ("src/account.ts", "const accountId = user.accountId;"),
    "client-public-secret-reference": (
        "src/client.ts",
        "process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;",
    ),
    "client-public-secret-env-key": (
        ".env.local",
        "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=\n",
    ),
    "feature-web-sensitive-response": ("src/response.ts", "return NextResponse.json({ ok: true });"),
    "feature-auth-password-login": ("src/login.ts", "login({ passkey });"),
    "feature-user-controlled-destination": ("src/proxy.ts", 'fetch("https://example.com");'),
    "feature-cicd-oidc": (
        ".github/workflows/release.yml",
        "id-token: write\nuses: actions/attest-build-provenance@0123456789012345678901234567890123456789\n",
    ),
}


class DetectorContractTests(unittest.TestCase):
    def detector_ids(self, path: str, text: str):
        return {
            item["detector"]["id"]
            for item in PROFILER.inspect_text(path, text, "production")
        }

    def test_every_text_detector_has_a_positive_and_negative_contract(self):
        detector_ids = {item.detector_id for item in PROFILER.TEXT_DETECTORS}
        self.assertEqual(detector_ids, set(TEXT_CASES))
        for detector_id, (path, positive) in TEXT_CASES.items():
            with self.subTest(detector=detector_id, polarity="positive"):
                self.assertIn(detector_id, self.detector_ids(path, positive))
            negative_path, negative = TARGETED_NEGATIVES.get(
                detector_id, (path, "const harmlessValue = 1;\n")
            )
            with self.subTest(detector=detector_id, polarity="negative"):
                self.assertNotIn(
                    detector_id, self.detector_ids(negative_path, negative)
                )

    def test_every_dependency_detector_has_production_and_dev_twins(self):
        for dependency, expected in PROFILER.NODE_DEPENDENCY_DETECTORS.items():
            with self.subTest(runtime="node", dependency=dependency):
                production = PROFILER.inspect_package_json(
                    "package.json",
                    json.dumps({"dependencies": {dependency: "1"}}),
                    "production",
                )
                development = PROFILER.inspect_package_json(
                    "package.json",
                    json.dumps({"devDependencies": {dependency: "1"}}),
                    "production",
                )
                self.assertTrue(
                    any(item["detector"]["id"] == expected[0] for item in production)
                )
                self.assertEqual([], development)
        for dependency, expected in PROFILER.PYTHON_DEPENDENCY_DETECTORS.items():
            with self.subTest(runtime="python", dependency=dependency):
                production = PROFILER.inspect_python_manifest(
                    "requirements.txt", dependency + "\n", "production"
                )
                non_production = PROFILER.inspect_python_manifest(
                    "requirements.txt", dependency + "\n", "test"
                )
                self.assertTrue(
                    any(item["detector"]["id"] == expected[0] for item in production)
                )
                self.assertEqual([], non_production)


if __name__ == "__main__":
    unittest.main()
