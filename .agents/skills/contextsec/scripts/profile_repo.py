#!/usr/bin/env python3
"""Build a deterministic, read-only ContextSec security profile.

The profiler never imports or executes target code, follows repository symlinks,
uses the network, or emits matched source text. It is intentionally conservative:
not finding evidence produces an ``unknown`` claim, never ``absent``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

SCHEMA_VERSION = "0.2.1"
DETECTOR_VERSION = "0.3.0"
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_FILE_BYTES = 512 * 1024
DEFAULT_MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_CONTEXT_BYTES = 64 * 1024

CATALOG_PATH = Path(__file__).resolve().parents[1] / "references" / "catalog.json"
COMPOSITION_CATALOG_PATH = (
    Path(__file__).resolve().parents[1] / "references" / "compositions" / "catalog.json"
)


def load_pack_catalog(path: Path = CATALOG_PATH) -> Dict[str, Any]:
    """Load the sole machine-readable source for pack order and dependencies."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise RuntimeError("Unable to load ContextSec pack catalog: " + str(exc)) from exc
    packs = payload.get("packs") if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("ContextSec pack catalog has an incompatible schema.")
    capabilities = payload.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or len(capabilities) != len(set(capabilities))
        or not all(
            isinstance(item, str)
            and re.fullmatch(r"[a-z][a-z0-9_.-]+", item)
            for item in capabilities
        )
    ):
        raise RuntimeError("ContextSec pack catalog has invalid capabilities.")
    if not isinstance(packs, list) or not packs:
        raise RuntimeError("ContextSec pack catalog must contain a non-empty packs array.")
    identifiers = [item.get("id") for item in packs if isinstance(item, dict)]
    if len(identifiers) != len(packs) or len(identifiers) != len(set(identifiers)):
        raise RuntimeError("ContextSec pack catalog contains invalid or duplicate pack ids.")
    if identifiers[0] != "foundation":
        raise RuntimeError("ContextSec pack catalog must start with foundation.")
    known = set(identifiers)
    control_ids = set()
    for item in packs:
        dependencies = item.get("dependencies")
        if not isinstance(dependencies, list) or not set(dependencies) <= known:
            raise RuntimeError("ContextSec pack catalog has an invalid dependency.")
        controls = item.get("controls")
        if not isinstance(controls, list) or not controls:
            raise RuntimeError("ContextSec pack catalog has an invalid controls array.")
        for control in controls:
            if not isinstance(control, dict) or not isinstance(control.get("id"), str):
                raise RuntimeError("ContextSec pack catalog has an invalid control.")
            if control["id"] in control_ids:
                raise RuntimeError("ContextSec pack catalog has duplicate control ids.")
            control_ids.add(control["id"])
            if type(control.get("blocking")) is not bool:
                raise RuntimeError(
                    "ContextSec control blocking fields must be JSON booleans."
                )
    return payload


PACK_CATALOG = load_pack_catalog()
try:
    COMPOSITION_CATALOG = json.loads(
        COMPOSITION_CATALOG_PATH.read_text(encoding="utf-8")
    )
except (OSError, ValueError, RecursionError) as exc:
    raise RuntimeError(
        "Unable to load ContextSec composition catalog: " + str(exc)
    ) from exc
if COMPOSITION_CATALOG.get("schema_version") != SCHEMA_VERSION or not isinstance(
    COMPOSITION_CATALOG.get("rules"), list
):
    raise RuntimeError("ContextSec composition catalog has an incompatible schema.")
for composition in COMPOSITION_CATALOG["rules"]:
    if not isinstance(composition, dict) or type(composition.get("blocking")) is not bool:
        raise RuntimeError("ContextSec composition blocking fields must be JSON booleans.")
def decision_model_digest() -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                {"packs": PACK_CATALOG, "compositions": COMPOSITION_CATALOG},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )


DECISION_MODEL_DIGEST = decision_model_digest()
PACK_ORDER = tuple(item["id"] for item in PACK_CATALOG["packs"])
PACK_CLAIMS = {
    item["id"]: item["claim"]
    for item in PACK_CATALOG["packs"]
    if item["id"] != "foundation"
}
PACK_DEPENDENCIES = {
    item["id"]: tuple(item["dependencies"])
    for item in PACK_CATALOG["packs"]
    if item["dependencies"]
}

EXCLUDED_DIRS = {
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".nuxt",
    ".turbo",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "target",
    "out",
    "tmp",
    "temp",
    "__pycache__",
}

DOCUMENTATION_DIRS = {"doc", "docs", "documentation", "incidents"}
TEST_DIRS = {
    "test",
    "tests",
    "fixtures",
    "fixture",
    "mocks",
    "mock",
    "examples",
    "example",
    "benchmarks",
}
DOCUMENTATION_SUFFIXES = {".md", ".mdx", ".rst", ".txt", ".adoc"}
SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".dart",
    ".env.example",
    ".go",
    ".graphql",
    ".gql",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".php",
    ".prisma",
    ".proto",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sql",
    ".swift",
    ".tf",
    ".toml",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}

MANIFEST_NAMES = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "requirements.in",
    "Pipfile",
    "Gemfile",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
}

NODE_DEPENDENCY_DETECTORS: Mapping[str, Tuple[str, str, str, str]] = {
    "next": ("node-web-framework", "baseline-web", "capabilities.web", "high"),
    "express": ("node-web-framework", "baseline-web", "capabilities.web", "high"),
    "fastify": ("node-web-framework", "baseline-web", "capabilities.web", "high"),
    "astro": ("node-web-framework", "baseline-web", "capabilities.web", "high"),
    "@nestjs/core": ("node-web-framework", "baseline-web", "capabilities.web", "high"),
    "@auth/core": (
        "node-auth-library",
        "auth-session",
        "identity.authentication",
        "medium",
    ),
    "next-auth": (
        "node-auth-library",
        "auth-session",
        "identity.authentication",
        "medium",
    ),
    "passport": (
        "node-auth-library",
        "auth-session",
        "identity.authentication",
        "medium",
    ),
    "jsonwebtoken": (
        "node-auth-library",
        "auth-session",
        "identity.authentication",
        "medium",
    ),
    "jose": ("node-auth-library", "auth-session", "identity.authentication", "medium"),
    "stripe": ("node-payment-sdk", "payments", "capabilities.payments", "medium"),
    "@adyen/api-library": (
        "node-payment-sdk",
        "payments",
        "capabilities.payments",
        "medium",
    ),
    "braintree": ("node-payment-sdk", "payments", "capabilities.payments", "medium"),
    "paypal-rest-sdk": (
        "node-payment-sdk",
        "payments",
        "capabilities.payments",
        "medium",
    ),
    "graphql": (
        "node-api-library",
        "api-inbound",
        "capabilities.api_inbound",
        "medium",
    ),
    "@apollo/server": (
        "node-api-library",
        "api-inbound",
        "capabilities.api_inbound",
        "high",
    ),
    "axios": (
        "node-http-client",
        "external-api",
        "integrations.external_api",
        "medium",
    ),
    "got": ("node-http-client", "external-api", "integrations.external_api", "medium"),
    "multer": (
        "node-upload-library",
        "file-upload",
        "capabilities.file_upload",
        "medium",
    ),
    "formidable": (
        "node-upload-library",
        "file-upload",
        "capabilities.file_upload",
        "medium",
    ),
    "uploadthing": (
        "node-upload-library",
        "file-upload",
        "capabilities.file_upload",
        "medium",
    ),
    "@aws-sdk/client-s3": (
        "node-object-storage",
        "file-upload",
        "capabilities.file_upload",
        "medium",
    ),
    "openai": ("node-ai-sdk", "ai-rag-agent", "capabilities.ai_rag_agent", "medium"),
    "@anthropic-ai/sdk": (
        "node-ai-sdk",
        "ai-rag-agent",
        "capabilities.ai_rag_agent",
        "medium",
    ),
    "langchain": ("node-ai-sdk", "ai-rag-agent", "capabilities.ai_rag_agent", "medium"),
    "@langchain/core": (
        "node-ai-sdk",
        "ai-rag-agent",
        "capabilities.ai_rag_agent",
        "medium",
    ),
    "@aws-sdk/client-secrets-manager": (
        "node-secret-manager",
        "secrets-management",
        "authority.secrets_plane",
        "medium",
    ),
    "node-vault": (
        "node-secret-manager",
        "secrets-management",
        "authority.secrets_plane",
        "medium",
    ),
    "@aws-sdk/client-iam": (
        "node-cloud-iam",
        "cloud-iam-controlplane",
        "authority.cloud_control_plane",
        "medium",
    ),
    "@slack/oauth": (
        "node-saas-oauth",
        "third-party-saas-oauth",
        "integrations.saas_oauth",
        "medium",
    ),
    "simple-oauth2": (
        "node-saas-oauth",
        "third-party-saas-oauth",
        "integrations.saas_oauth",
        "medium",
    ),
}

PYTHON_DEPENDENCY_DETECTORS: Mapping[str, Tuple[str, str, str, str]] = {
    "fastapi": ("python-web-framework", "baseline-web", "capabilities.web", "high"),
    "django": ("python-web-framework", "baseline-web", "capabilities.web", "high"),
    "flask": ("python-web-framework", "baseline-web", "capabilities.web", "high"),
    "litestar": ("python-web-framework", "baseline-web", "capabilities.web", "high"),
    "sanic": ("python-web-framework", "baseline-web", "capabilities.web", "high"),
    "authlib": ("python-auth-library", "auth-session", "identity.authentication", "medium"),
    "django-allauth": ("python-auth-library", "auth-session", "identity.authentication", "medium"),
    "pyjwt": ("python-auth-library", "auth-session", "identity.authentication", "medium"),
    "python-jose": ("python-auth-library", "auth-session", "identity.authentication", "medium"),
    "stripe": ("python-payment-sdk", "payments", "capabilities.payments", "medium"),
    "adyen": ("python-payment-sdk", "payments", "capabilities.payments", "medium"),
    "braintree": ("python-payment-sdk", "payments", "capabilities.payments", "medium"),
    "paypalrestsdk": ("python-payment-sdk", "payments", "capabilities.payments", "medium"),
    "requests": ("python-http-client", "external-api", "integrations.external_api", "medium"),
    "httpx": ("python-http-client", "external-api", "integrations.external_api", "medium"),
    "aiohttp": ("python-http-client", "external-api", "integrations.external_api", "medium"),
    "python-multipart": ("python-upload-library", "file-upload", "capabilities.file_upload", "medium"),
    "openai": ("python-ai-sdk", "ai-rag-agent", "capabilities.ai_rag_agent", "medium"),
    "anthropic": ("python-ai-sdk", "ai-rag-agent", "capabilities.ai_rag_agent", "medium"),
    "langchain": ("python-ai-sdk", "ai-rag-agent", "capabilities.ai_rag_agent", "medium"),
    "llama-index": ("python-ai-sdk", "ai-rag-agent", "capabilities.ai_rag_agent", "medium"),
    "hvac": ("python-secret-manager", "secrets-management", "authority.secrets_plane", "medium"),
}


@dataclass(frozen=True)
class TextDetector:
    detector_id: str
    pack: str
    claim: str
    kind: str
    confidence: str
    patterns: Tuple[str, ...]
    minimum_distinct: int = 1
    required_suffixes: Tuple[str, ...] = ()
    excluded_suffixes: Tuple[str, ...] = ()
    path_pattern: str = ""


@dataclass
class WalkStats:
    entries_seen: int = 0
    entry_limit_reached: bool = False


TEXT_DETECTORS = (
    TextDetector(
        "next-api-route",
        "api-inbound",
        "capabilities.api_inbound",
        "route",
        "high",
        (r"\b(GET|POST|PUT|PATCH|DELETE)\s*(?:=|\()", r"NextRequest|NextResponse"),
        path_pattern=r"(^|/)(app|pages)/api/",
    ),
    TextDetector(
        "generic-http-route",
        "api-inbound",
        "capabilities.api_inbound",
        "route",
        "high",
        (
            r"\b(app|router|server|fastify)\.(get|post|put|patch|delete)\s*\(",
            r"@(app|router)\.(get|post|put|patch|delete)\b",
        ),
    ),
    TextDetector(
        "authentication-code",
        "auth-session",
        "identity.authentication",
        "identity",
        "medium",
        (
            r"\b(signIn|signOut|getServerSession|auth\(|authenticate|login|verifyToken|jwt\.verify|oauth|oidc)\b",
        ),
    ),
    TextDetector(
        "payment-callsite",
        "payments",
        "capabilities.payments",
        "value-transfer",
        "high",
        (
            r"\bstripe\.(checkout|paymentIntents|subscriptions|refunds|payouts)\b",
            r"\b(checkout\.sessions|paymentIntents)\.create\b",
        ),
    ),
    TextDetector(
        "payment-sdk-import",
        "payments",
        "capabilities.payments",
        "import",
        "medium",
        (
            r"(?:\bfrom\s*|\brequire\s*\(\s*)[\"'](?:stripe|@adyen/api-library|braintree|paypal-rest-sdk)[\"']",
            r"\b(import\s+stripe|from\s+stripe\s+import)\b",
        ),
    ),
    TextDetector(
        "payment-provider-endpoint",
        "payments",
        "capabilities.payments",
        "value-transfer",
        "high",
        (
            r"\b(api\.stripe\.com|api-m\.paypal\.com|checkoutshopper[^/]*\.adyen\.com|payments\.braintree-api\.com)\b",
        ),
    ),
    TextDetector(
        "payment-webhook-callsite",
        "payments",
        "capabilities.payments",
        "webhook",
        "high",
        (r"\bwebhooks\.constructEvent(?:Async)?\b",),
    ),
    TextDetector(
        "raw-card-data-field",
        "payments",
        "capabilities.payments",
        "payment-data",
        "high",
        (r"\b(cardNumber|card_number|primaryAccountNumber|cvv|cvc)\b",),
    ),
    TextDetector(
        "prisma-pii-field",
        "privacy-pii",
        "data.pii",
        "schema-field",
        "high",
        (
            r"(?im)^\s*(email|phone|fullName|firstName|lastName|address|billingAddress|dateOfBirth|nationalId|ssn)\s+",
        ),
        required_suffixes=(".prisma",),
    ),
    TextDetector(
        "python-pii-model",
        "privacy-pii",
        "data.pii",
        "schema-field",
        "high",
        (
            r"(?m)^\s*class\s+\w+\s*\([^\n)]*(?:SQLModel|BaseModel|models\.Model)[^\n)]*\)\s*:",
            r"(?m)^\s*(?:email|phone|full_name|first_name|last_name|address|billing_address|date_of_birth|national_id|ssn)\s*(?::|=)",
        ),
        minimum_distinct=2,
        required_suffixes=(".py",),
    ),
    TextDetector(
        "source-pii-shape",
        "privacy-pii",
        "data.pii",
        "data-shape",
        "medium",
        (
            r"\bemail\b",
            r"\b(phone|address|dateOfBirth|nationalId|ssn|billingAddress)\b",
        ),
        minimum_distinct=2,
        excluded_suffixes=(".prisma",),
    ),
    TextDetector(
        "tenant-schema-field",
        "multi-tenant",
        "architecture.multi_tenant",
        "schema-field",
        "medium",
        (
            r"\b(tenantId|tenant_id|organizationId|organization_id|workspaceId|workspace_id)\b",
        ),
        required_suffixes=(".prisma", ".sql", ".graphql", ".gql"),
    ),
    TextDetector(
        "prisma-tenant-model",
        "multi-tenant",
        "architecture.multi_tenant",
        "tenant-boundary",
        "high",
        (
            r"\bmodel\s+(Organization|Tenant|Workspace)\b",
            r"\b(tenantId|organizationId|workspaceId)\b",
        ),
        minimum_distinct=2,
        required_suffixes=(".prisma",),
    ),
    TextDetector(
        "python-tenant-model",
        "multi-tenant",
        "architecture.multi_tenant",
        "tenant-boundary",
        "high",
        (
            r"(?m)^\s*class\s+\w+\s*\([^\n)]*(?:SQLModel|BaseModel|models\.Model)[^\n)]*\)\s*:",
            r"(?m)^\s*(?:tenant_id|organization_id|workspace_id)\s*(?::|=)",
        ),
        minimum_distinct=2,
        required_suffixes=(".py",),
    ),
    TextDetector(
        "tenant-code-field",
        "multi-tenant",
        "architecture.multi_tenant",
        "tenant-boundary",
        "medium",
        (
            r"\b(tenantId|tenant_id|organizationId|organization_id|workspaceId|workspace_id)\b",
        ),
        excluded_suffixes=(".prisma", ".sql", ".graphql", ".gql"),
    ),
    TextDetector(
        "outbound-http-call",
        "external-api",
        "integrations.external_api",
        "outbound-call",
        "medium",
        (
            r"\b(fetch|axios\.(get|post|put|patch|delete)|requests\.(get|post|put|patch|delete)|httpx\.(get|post|put|patch|delete))\s*\(",
        ),
    ),
    TextDetector(
        "file-upload-callsite",
        "file-upload",
        "capabilities.file_upload",
        "upload",
        "high",
        (
            r"(?:\bformData\s*\(|multipart/form-data|\bPutObjectCommand\b|\bcreatePresignedPost\b|\bpresign(?:ed)?Url\b)",
        ),
    ),
    TextDetector(
        "ai-callsite",
        "ai-rag-agent",
        "capabilities.ai_rag_agent",
        "model-call",
        "high",
        (
            r"\b(chat\.completions\.create|responses\.create|openai\.responses\.create|anthropic\.messages\.create|vectorStore|similaritySearch|tool_calls|mcpServers)\b",
        ),
    ),
    TextDetector(
        "ai-provider-callsite",
        "external-api",
        "integrations.external_api",
        "outbound-call",
        "high",
        (
            r"\b(openai\.(chat\.completions|responses)|anthropic\.messages|client\.(chat\.completions|responses|messages))\.create\b",
        ),
    ),
    TextDetector(
        "secret-plane-callsite",
        "secrets-management",
        "authority.secrets_plane",
        "secret-control-plane",
        "high",
        (
            r"\b(SecretsManagerClient|GetSecretValueCommand|BatchGetSecretValueCommand|VaultClient)\b",
        ),
    ),
    TextDetector(
        "secret-plane-schema",
        "secrets-management",
        "authority.secrets_plane",
        "secret-control-plane",
        "high",
        (
            r"\bmodel\s+(Secret|Credential|ApiCredential)\b",
            r"\b(encryptedValue|ciphertext|kmsKeyId|secretVersion)\b",
        ),
        minimum_distinct=2,
        required_suffixes=(".prisma",),
    ),
    TextDetector(
        "cloud-iam-infrastructure",
        "cloud-iam-controlplane",
        "authority.cloud_control_plane",
        "cloud-control-plane",
        "high",
        (
            r"\b(resource|data)\s+[\"']?(aws_iam_|google_(project|organization)_iam_|azurerm_role_assignment)",
            r"\b(iam:PassRole|sts:AssumeRole|roles/iam\.)\b",
        ),
        required_suffixes=(".tf", ".yaml", ".yml", ".json"),
    ),
    TextDetector(
        "cicd-workflow",
        "cicd-supply-chain",
        "delivery.cicd_supply_chain",
        "delivery-pipeline",
        "high",
        (r"(?m)^\s*(jobs|stages|steps|uses)\s*:",),
        required_suffixes=(".yaml", ".yml"),
        path_pattern=r"(^|/)(\.github/workflows|\.gitlab|\.circleci|\.buildkite)/",
    ),
    TextDetector(
        "saas-oauth-callsite",
        "third-party-saas-oauth",
        "integrations.saas_oauth",
        "delegated-integration",
        "high",
        (
            r"\b(slack|salesforce|hubspot|google|microsoft|github).{0,80}\b(oauth|scopes?|refresh_token|access_token)\b",
            r"\b(oauth|scopes?|refresh_token|access_token)\b.{0,80}\b(slack|salesforce|hubspot|google|microsoft|github)\b",
        ),
    ),
    TextDetector(
        "support-admin-surface",
        "support-admin-ops",
        "operations.support_admin",
        "privileged-operations",
        "high",
        (
            r"\b(impersonate|startSupportSession|supportSession|customerExport|exportAllCustomers|adminOverride|breakGlass)\b",
        ),
        path_pattern=r"(^|/)(admin|support|ops)(/|[-_.])|(^|/)(app|pages)/api/(admin|support|ops)/",
    ),
    TextDetector(
        "high-impact-transaction",
        "high-impact-transactions",
        "authority.high_impact_transactions",
        "irreversible-action",
        "high",
        (
            r"\b(payouts?\.create|refunds?\.create|bankAccount|walletAddress|transferDomain|rotateApiKey|resetMfa|grantAdmin|deleteAccount|deleteTenant)\b",
        ),
    ),
    TextDetector(
        "feature-web-admin-surface",
        "baseline-web",
        "web.admin_surface",
        "feature",
        "high",
        (r"\b(admin|support|ops|impersonate|breakGlass)\b",),
        path_pattern=r"(^|/)(admin|support|ops)(/|[-_.])|(^|/)(app|pages)/api/(admin|support|ops)/",
    ),
    TextDetector(
        "feature-web-cookie-auth",
        "auth-session",
        "web.cookie_auth",
        "feature",
        "high",
        (r"\b(cookies?\s*\(|setCookie|sessionToken|getServerSession)\b",),
    ),
    TextDetector(
        "feature-web-state-change",
        "api-inbound",
        "web.state_change",
        "feature",
        "high",
        (r"\b(POST|PUT|PATCH|DELETE)\s*(?:=|\()",),
        path_pattern=r"(^|/)(app|pages)/api/",
    ),
    TextDetector(
        "feature-web-sensitive-response",
        "baseline-web",
        "web.sensitive_response",
        "feature",
        "medium",
        (r"\b(NextResponse\.json|res\.json)\s*\(", r"\b(email|tenantId|billingAddress|token)\b"),
        minimum_distinct=2,
    ),
    TextDetector(
        "feature-server-actions",
        "foundation",
        "authority.server_actions",
        "feature",
        "high",
        (r"\b(prisma\.|NextRequest|NextResponse|app\.(?:get|post|put|patch|delete)\s*\()",),
    ),
    TextDetector(
        "feature-secrets-used",
        "foundation",
        "authority.secrets_used",
        "feature",
        "high",
        (r"\b(process\.env|os\.environ|getenv)\b.{0,80}(secret|token|password|api[_-]?key|private[_-]?key)",),
    ),
    TextDetector(
        "feature-failure-prone-processing",
        "foundation",
        "runtime.failure_prone_processing",
        "feature",
        "medium",
        (r"\b(JSON\.parse|fetch\s*\(|parse\s*\(|scan\w*\s*\(|constructEvent)\b",),
    ),
    TextDetector(
        "feature-auth-password-login",
        "auth-session",
        "auth.password_login",
        "feature",
        "high",
        (r"\b(signIn|login|authenticate)\b.{0,120}\b(password|credential)\b",),
    ),
    TextDetector(
        "feature-auth-recovery",
        "auth-session",
        "auth.recovery",
        "feature",
        "high",
        (r"\b(forgotPassword|resetPassword|recoveryToken|passwordReset)\b",),
    ),
    TextDetector(
        "feature-auth-oauth",
        "auth-session",
        "auth.oauth",
        "feature",
        "high",
        (r"\b(oauth|oidc|authorizationCode|refresh_token|pkce)\b",),
    ),
    TextDetector(
        "feature-auth-api-token",
        "auth-session",
        "auth.api_token",
        "feature",
        "high",
        (r"\b(authorization|bearer|api[_-]?token|jwt\.verify)\b",),
    ),
    TextDetector(
        "feature-payment-subscription",
        "payments",
        "payment.subscription",
        "feature",
        "high",
        (r"\bsubscriptions?\.(?:create|update|cancel)|checkout\.sessions\.create\b",),
    ),
    TextDetector(
        "feature-payment-webhook",
        "payments",
        "payment.webhook",
        "feature",
        "high",
        (r"\bwebhooks\.constructEvent(?:Async)?\b",),
    ),
    TextDetector(
        "feature-payment-refund",
        "payments",
        "payment.refund",
        "feature",
        "high",
        (r"\brefunds?\.create\b",),
    ),
    TextDetector(
        "feature-payment-payout",
        "payments",
        "payment.payout",
        "feature",
        "high",
        (r"\bpayouts?\.create\b",),
    ),
    TextDetector(
        "feature-ai-rag",
        "ai-rag-agent",
        "ai.rag",
        "feature",
        "high",
        (
            r"\b(vectorStore|similaritySearch|retrieval(?:Chain|Pipeline|Context|Query|Result|Augmented)|embeddings?)\b",
        ),
    ),
    TextDetector(
        "feature-user-controlled-destination",
        "external-api",
        "external.user_controlled_destination",
        "feature",
        "high",
        (r"\b(fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*(?:req(?:uest)?|input|params|query|url|target|destination)\b",),
    ),
    TextDetector(
        "feature-ai-tools",
        "ai-rag-agent",
        "ai.tools",
        "feature",
        "high",
        (r"\b(tool_calls|tools\s*:|mcpServers|function_call)\b",),
    ),
    TextDetector(
        "feature-ai-memory",
        "ai-rag-agent",
        "ai.memory",
        "feature",
        "high",
        (r"\b(conversationMemory|chatMemory|memoryStore|saveMemory)\b",),
    ),
    TextDetector(
        "feature-ai-autonomous-action",
        "ai-rag-agent",
        "ai.autonomous_action",
        "feature",
        "high",
        (r"\b(auto(?:nomous)?Agent|executeToolLoop|runUntilComplete)\b",),
    ),
    TextDetector(
        "feature-cicd-package-publish",
        "cicd-supply-chain",
        "cicd.package_publish",
        "feature",
        "high",
        (r"\b(npm publish|twine upload|cargo publish|docker push)\b",),
        required_suffixes=(".yaml", ".yml"),
    ),
    TextDetector(
        "feature-cicd-cloud-deploy",
        "cicd-supply-chain",
        "cicd.cloud_deploy",
        "feature",
        "high",
        (r"\b(terraform apply|kubectl apply|aws |gcloud |az )\b",),
        required_suffixes=(".yaml", ".yml"),
    ),
    TextDetector(
        "feature-cicd-untrusted-pr",
        "cicd-supply-chain",
        "cicd.untrusted_pr",
        "feature",
        "high",
        (r"\b(pull_request_target|pull_request)\s*:",),
        required_suffixes=(".yaml", ".yml"),
    ),
    TextDetector(
        "feature-cicd-oidc",
        "cicd-supply-chain",
        "cicd.oidc",
        "feature",
        "high",
        (r"\bid-token\s*:\s*write\b",),
        required_suffixes=(".yaml", ".yml"),
    ),
    TextDetector(
        "feature-support-impersonation",
        "support-admin-ops",
        "support.impersonation",
        "feature",
        "high",
        (r"\b(impersonate|startSupportSession|supportSession)\b",),
    ),
    TextDetector(
        "feature-support-bulk-access",
        "support-admin-ops",
        "support.bulk_access",
        "feature",
        "high",
        (r"\b(exportAllCustomers|customerExport|bulk(?:Read|Search|Export))\b",),
    ),
    TextDetector(
        "feature-high-impact-transaction",
        "high-impact-transactions",
        "high_impact.transaction",
        "feature",
        "high",
        (r"\b(payouts?\.create|refunds?\.create|transferDomain|rotateApiKey|resetMfa|grantAdmin|deleteAccount|deleteTenant)\b",),
    ),
)

KNOWN_CAPABILITIES = tuple(PACK_CATALOG["capabilities"])
DETECTOR_CAPABILITIES = {
    detector.claim
    for detector in TEXT_DETECTORS
    if detector.claim not in set(PACK_CLAIMS.values())
}
if not DETECTOR_CAPABILITIES <= set(KNOWN_CAPABILITIES):
    raise RuntimeError("A detector references an undeclared ContextSec capability.")

CAPABILITY_CONTEXT_PACKS = {
    "web.admin_surface": {"support-admin-ops"},
    "web.cookie_auth": {"auth-session"},
    "web.state_change": {"api-inbound"},
    "web.sensitive_response": {"privacy-pii"},
    "authority.server_actions": {
        "payments",
        "multi-tenant",
        "api-inbound",
        "external-api",
        "file-upload",
        "ai-rag-agent",
        "secrets-management",
        "cloud-iam-controlplane",
        "support-admin-ops",
        "high-impact-transactions",
    },
    "authority.secrets_used": {
        "payments",
        "external-api",
        "ai-rag-agent",
        "secrets-management",
        "cloud-iam-controlplane",
        "cicd-supply-chain",
        "third-party-saas-oauth",
    },
    "runtime.failure_prone_processing": {
        "payments",
        "api-inbound",
        "external-api",
        "file-upload",
        "ai-rag-agent",
        "cicd-supply-chain",
    },
    "auth.api_token": {"auth-session", "api-inbound"},
    "auth.oauth": {"auth-session", "third-party-saas-oauth"},
    "auth.password_login": {"auth-session"},
    "auth.recovery": {"auth-session"},
    "external.user_controlled_destination": {"external-api"},
    "high_impact.transaction": {"high-impact-transactions"},
    "payment.payout": {"payments"},
    "payment.refund": {"payments"},
    "payment.subscription": {"payments"},
    "payment.webhook": {"payments"},
    "ai.autonomous_action": {"ai-rag-agent"},
    "ai.memory": {"ai-rag-agent"},
    "ai.rag": {"ai-rag-agent"},
    "ai.tools": {"ai-rag-agent"},
    "cicd.cloud_deploy": {"cicd-supply-chain"},
    "cicd.oidc": {"cicd-supply-chain"},
    "cicd.package_publish": {"cicd-supply-chain"},
    "cicd.untrusted_pr": {"cicd-supply-chain"},
    "support.bulk_access": {"support-admin-ops"},
    "support.impersonation": {"support-admin-ops"},
    "flow.ai_to_high_impact": {"ai-rag-agent", "high-impact-transactions"},
    "flow.api_to_tenant": {"api-inbound", "multi-tenant"},
    "flow.cicd_to_cloud": {"cicd-supply-chain", "cloud-iam-controlplane"},
    "flow.payment_to_tenant": {"payments", "multi-tenant"},
    "flow.pii_to_ai": {"privacy-pii", "ai-rag-agent"},
    "flow.pii_to_saas": {"privacy-pii", "third-party-saas-oauth"},
    "flow.support_to_tenant": {"support-admin-ops", "multi-tenant"},
    "flow.tenant_to_ai": {"multi-tenant", "ai-rag-agent"},
    "flow.upload_to_tenant": {"file-upload", "multi-tenant"},
}
if set(CAPABILITY_CONTEXT_PACKS) != set(KNOWN_CAPABILITIES):
    raise RuntimeError("Every ContextSec capability needs a context coverage policy.")


def sha256_text(value: str) -> str:
    return (
        "sha256:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    )


def redact_path(value: str) -> str:
    redacted = re.sub(
        r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",
        "[redacted-email]",
        value,
    )
    redacted = re.sub(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", "[redacted-id]", redacted)
    redacted = re.sub(
        r"(?<![A-Za-z0-9])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9])",
        "[redacted-token]",
        redacted,
    )
    return "".join(char if char >= " " else "?" for char in redacted)


def reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def strict_json_loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=reject_duplicate_keys)


def classify_scope(relative: Path) -> str:
    lowered = {part.lower() for part in relative.parts[:-1]}
    if lowered & DOCUMENTATION_DIRS:
        return "documentation"
    if lowered & TEST_DIRS or re.search(
        r"(^|[._-])(test|spec)([._-]|$)", relative.name.lower()
    ):
        return "test"
    if relative.name in MANIFEST_NAMES:
        return "production"
    if relative.suffix.lower() in DOCUMENTATION_SUFFIXES:
        return "documentation"
    return "production"


def is_supported_file(path: Path) -> bool:
    if path.name in MANIFEST_NAMES:
        return True
    name_lower = path.name.lower()
    if name_lower.endswith(".env.example"):
        return True
    return path.suffix.lower() in SOURCE_SUFFIXES


def has_reparse_attribute(stat_result: Any) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def is_link_like(path: Path) -> bool:
    try:
        return path.is_symlink() or has_reparse_attribute(os.lstat(str(path)))
    except OSError:
        return True


def line_number(text: str, match_start: int) -> int:
    return text.count("\n", 0, match_start) + 1


def make_observation(
    relative: str,
    locator: str,
    content_digest: str,
    detector_id: str,
    pack: str,
    claim: str,
    kind: str,
    confidence: str,
    scope: str,
) -> Dict[str, Any]:
    evidence_id = sha256_text(
        "evidence\x1f" + "\x1f".join((relative, locator, detector_id, DETECTOR_VERSION))
    )
    location_id = sha256_text("location\x1f" + "\x1f".join((relative, locator)))
    fingerprint = sha256_text(
        "fingerprint\x1f" + "\x1f".join((evidence_id, content_digest))
    )
    observation_id = "obs-" + evidence_id.removeprefix("sha256:")[:12]
    return {
        "id": observation_id,
        "kind": kind,
        "pack": pack,
        "claim": claim,
        "scope": scope,
        "confidence": confidence,
        "detector": {"id": detector_id, "version": DETECTOR_VERSION},
        "evidence": {
            "path": redact_path(relative),
            "locator": locator,
            "evidence_id": evidence_id,
            "location_id": location_id,
            "content_digest": content_digest,
            "fingerprint": fingerprint,
            "subject_revision": "pending",
        },
    }


def inspect_package_json(relative: str, text: str, scope: str) -> List[Dict[str, Any]]:
    if scope != "production" or Path(relative).name != "package.json":
        return []
    try:
        payload = strict_json_loads(text)
    except (ValueError, TypeError, RecursionError):
        return []
    if not isinstance(payload, dict):
        return []
    observations: List[Dict[str, Any]] = []
    for section in ("dependencies", "optionalDependencies"):
        dependencies = payload.get(section, {})
        if not isinstance(dependencies, dict):
            continue
        for dependency in sorted(dependencies):
            detector = NODE_DEPENDENCY_DETECTORS.get(dependency.lower())
            if detector is None:
                continue
            detector_id, pack, claim, confidence = detector
            observations.append(
                make_observation(
                    relative,
                    section + "." + dependency,
                    sha256_text(text),
                    detector_id,
                    pack,
                    claim,
                    "dependency",
                    confidence,
                    scope,
                )
            )
    return observations


def _strip_manifest_comment(line: str) -> str:
    """Remove an unquoted manifest comment without evaluating the manifest."""

    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in {"'", '"'}:
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
            continue
        if char == "#" and not quote:
            return line[:index]
    return line


def _dependency_name(specification: str) -> Optional[str]:
    candidate = specification.strip()
    if not candidate or candidate.startswith(("-", ".", "/")):
        return None
    match = re.match(r"[A-Za-z0-9][A-Za-z0-9_.-]*", candidate)
    if match is None:
        return None
    return re.sub(r"[-_.]+", "-", match.group(0)).lower()


def _quoted_values(text: str) -> List[str]:
    return [
        match.group("value")
        for match in re.finditer(
            r"(?P<quote>['\"])(?P<value>(?:\\.|(?!\1).)*)\1", text
        )
    ]


def python_dependency_specs(relative: str, text: str) -> List[str]:
    """Extract production Python requirements from a conservative manifest subset."""

    name = Path(relative).name.lower()
    if name in {"requirements.txt", "requirements.in"}:
        return [
            cleaned.strip()
            for line in text.splitlines()
            if (cleaned := _strip_manifest_comment(line)).strip()
            and not cleaned.lstrip().startswith(("-r", "--requirement", "-e"))
        ]

    if name == "pipfile":
        section = ""
        specs: List[str] = []
        for raw_line in text.splitlines():
            line = _strip_manifest_comment(raw_line).strip()
            header = re.fullmatch(r"\[([^]]+)\]", line)
            if header:
                section = header.group(1).strip().lower()
                continue
            if section != "packages" or "=" not in line:
                continue
            package = line.split("=", 1)[0].strip().strip("'\"")
            if package:
                specs.append(package)
        return specs

    if name != "pyproject.toml":
        return []

    section = ""
    collecting_project_dependencies = False
    dependency_buffer: List[str] = []
    specs = []
    for raw_line in text.splitlines():
        line = _strip_manifest_comment(raw_line).strip()
        header = re.fullmatch(r"\[([^]]+)\]", line)
        if header:
            section = header.group(1).strip().lower()
            collecting_project_dependencies = False
            continue
        if section == "project" and re.match(r"^dependencies\s*=", line):
            collecting_project_dependencies = True
            dependency_buffer.append(line.split("=", 1)[1])
            if "]" in line.split("=", 1)[1]:
                collecting_project_dependencies = False
            continue
        if collecting_project_dependencies:
            dependency_buffer.append(line)
            if "]" in line:
                collecting_project_dependencies = False
            continue
        if section == "tool.poetry.dependencies" and "=" in line:
            package = line.split("=", 1)[0].strip().strip("'\"")
            if package.lower() != "python" and package:
                specs.append(package)

    specs.extend(_quoted_values("\n".join(dependency_buffer)))
    return specs


def inspect_python_manifest(
    relative: str, text: str, scope: str
) -> List[Dict[str, Any]]:
    if scope != "production":
        return []
    observations: List[Dict[str, Any]] = []
    for specification in python_dependency_specs(relative, text):
        dependency = _dependency_name(specification)
        if dependency is None:
            continue
        detector = PYTHON_DEPENDENCY_DETECTORS.get(dependency)
        if detector is None:
            continue
        detector_id, pack, claim, confidence = detector
        observations.append(
            make_observation(
                relative,
                "dependencies." + dependency,
                sha256_text(text),
                detector_id,
                pack,
                claim,
                "dependency",
                confidence,
                scope,
            )
        )
    return observations


def inspect_text(relative: str, text: str, scope: str) -> List[Dict[str, Any]]:
    if scope != "production":
        return []
    observations: List[Dict[str, Any]] = []
    normalized_path = relative.replace("\\", "/")
    suffix = Path(relative).suffix.lower()
    language = language_for_path(relative)
    code_text = mask_comments_and_strings(text, language=language)
    comments_removed = mask_comments_and_strings(
        text, keep_strings=True, language=language
    )
    for detector in TEXT_DETECTORS:
        if detector.required_suffixes and suffix not in detector.required_suffixes:
            continue
        if detector.excluded_suffixes and suffix in detector.excluded_suffixes:
            continue
        if detector.path_pattern and not re.search(
            detector.path_pattern, normalized_path, re.IGNORECASE
        ):
            continue
        searchable = (
            comments_removed
            if detector.detector_id
            in {
                "payment-provider-endpoint",
                "payment-sdk-import",
                "cloud-iam-infrastructure",
            }
            else code_text
        )
        matches: List[re.Match[str]] = []
        for pattern in detector.patterns:
            match = re.search(pattern, searchable, re.IGNORECASE | re.MULTILINE)
            if match is not None:
                matches.append(match)
        if len(matches) < detector.minimum_distinct:
            continue
        first = min(matches, key=lambda item: item.start())
        line = line_number(text, first.start())
        observations.append(
            make_observation(
                relative,
                "line:" + str(line),
                sha256_text(text),
                detector.detector_id,
                detector.pack,
                detector.claim,
                detector.kind,
                detector.confidence,
                scope,
            )
        )
    return observations


def language_for_path(path: str) -> str:
    """Return the bounded lexical policy used for a supported source path."""

    suffix = Path(path).suffix.lower()
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".vue"}:
        return "javascript"
    if suffix == ".py":
        return "python"
    if suffix == ".sql":
        return "sql"
    if suffix in {".tf", ".hcl"}:
        return "terraform"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix == ".json":
        return "json"
    return "generic"


def sql_dash_starts_comment(text: str, index: int) -> bool:
    after_pair = text[index + 2] if index + 2 < len(text) else ""
    line_prefix = text[text.rfind("\n", 0, index) + 1 : index].rstrip()
    return bool(
        not line_prefix
        or line_prefix.endswith(";")
        or not after_pair
        or after_pair.isspace()
        or ord(after_pair) < 32
    )


def sql_hash_starts_comment(text: str, index: int) -> bool:
    following = text[index + 1] if index + 1 < len(text) else ""
    if following in {">", "-"}:
        return False
    line_start = text.rfind("\n", 0, index) + 1
    line_end = text.find("\n", index + 1)
    line_end = len(text) if line_end < 0 else line_end
    prefix = text[line_start:index].rstrip()
    if not prefix or prefix.endswith(";"):
        return True
    suffix = text[index + 1 : line_end].lstrip()
    if not suffix:
        return True
    lhs = prefix[-1]
    rhs = suffix[0]
    if lhs not in ")]_" and not lhs.isalnum():
        return True
    if rhs not in "([_" and not rhs.isalnum():
        return True
    if suffix.startswith("("):
        depth = 0
        closing = -1
        for offset, char in enumerate(suffix):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    closing = offset
                    break
        tail = suffix[closing + 1 :].lstrip() if closing >= 0 else ""
    else:
        atom = re.match(r"[A-Za-z0-9_$]+", suffix)
        tail = suffix[atom.end() :].lstrip() if atom else suffix
    operator_tail = re.compile(
        r"^(?:[,);+*/%<>=|&^]|::|\b(?:AS|FROM|WHERE|GROUP|ORDER|LIMIT|OFFSET|RETURNING|AND|OR)\b)",
        re.IGNORECASE,
    )
    if operator_tail.search(tail):
        return False
    if not tail and not prefix[-1].isdigit():
        return False
    return True


def mask_comments_and_strings(
    text: str, keep_strings: bool = False, language: str = "generic"
) -> str:
    """Mask comments/literals with a language-aware bounded lexical policy.

    It is deliberately smaller than a parser, preserves offsets, and keeps
    executable JavaScript ``${...}`` expressions. Comment markers are enabled only
    for languages in which they are valid so ``n--`` and ``#private`` remain code.
    """

    policies = {
        "javascript": {"slash_line", "slash_block", "template"},
        "python": {"hash", "python_triple"},
        "sql": {"dash_line", "slash_block", "sql_hash", "sql_quote"},
        "terraform": {"hash", "slash_line", "slash_block"},
        "yaml": {"hash"},
        "json": set(),
        "generic": {"slash_line", "slash_block", "template"},
    }
    policy = policies.get(language, policies["generic"])

    output = list(text)
    length = len(text)
    index = 0
    frames: List[Dict[str, Any]] = [{"kind": "code", "template_expr": False}]

    def mask(position: int) -> None:
        if text[position] not in {"\r", "\n"}:
            output[position] = " "

    while index < length:
        frame = frames[-1]
        kind = frame["kind"]
        char = text[index]
        following = text[index + 1] if index + 1 < length else ""

        if kind == "code":
            if frame.get("template_expr"):
                if frame.get("python_fexpr"):
                    if char == "(":
                        frame["paren_depth"] += 1
                    elif char == ")" and frame["paren_depth"]:
                        frame["paren_depth"] -= 1
                    elif char == "[":
                        frame["bracket_depth"] += 1
                    elif char == "]" and frame["bracket_depth"]:
                        frame["bracket_depth"] -= 1
                    at_field_level = (
                        frame["brace_depth"] == 1
                        and frame["paren_depth"] == 0
                        and frame["bracket_depth"] == 0
                    )
                    if at_field_level and char == ":":
                        if not keep_strings:
                            mask(index)
                        frame["kind"] = "f-format"
                        index += 1
                        continue
                    if at_field_level and char == "!" and following != "=":
                        if not keep_strings:
                            mask(index)
                        frame["kind"] = "f-conversion"
                        index += 1
                        continue
                if char == "{":
                    frame["brace_depth"] += 1
                    index += 1
                    continue
                if char == "}":
                    frame["brace_depth"] -= 1
                    if frame["brace_depth"] == 0:
                        if not keep_strings:
                            mask(index)
                        frames.pop()
                    index += 1
                    continue
            if "slash_line" in policy and char == "/" and following == "/":
                mask(index)
                mask(index + 1)
                frames.append({"kind": "line-comment"})
                index += 2
                continue
            if "slash_block" in policy and char == "/" and following == "*":
                mask(index)
                mask(index + 1)
                frames.append({"kind": "block-comment"})
                index += 2
                continue
            if (
                "dash_line" in policy
                and char == "-"
                and following == "-"
                and sql_dash_starts_comment(text, index)
            ):
                mask(index)
                mask(index + 1)
                frames.append({"kind": "line-comment"})
                index += 2
                continue
            if (
                ("hash" in policy and char == "#")
                or (
                    "sql_hash" in policy
                    and char == "#"
                    and sql_hash_starts_comment(text, index)
                )
            ):
                mask(index)
                frames.append({"kind": "line-comment"})
                index += 1
                continue
            if language == "python" and (index == 0 or not re.match(r"[A-Za-z0-9_]", text[index - 1])):
                prefix_match = re.match(
                    r"(?i:(?:f|fr|rf))(?P<quote>'''|\"\"\"|'|\")",
                    text[index:],
                )
                if prefix_match is not None:
                    token = prefix_match.group(0)
                    quote = prefix_match.group("quote")
                    if not keep_strings:
                        for offset in range(len(token)):
                            mask(index + offset)
                    frames.append({"kind": "fstring", "quote": quote})
                    index += len(token)
                    continue
            if (
                "python_triple" in policy
                and char in {"'", '"'}
                and text[index : index + 3] == char * 3
            ):
                if not keep_strings:
                    for offset in range(3):
                        mask(index + offset)
                frames.append({"kind": "string", "quote": char, "triple": True})
                index += 3
                continue
            if char in {"'", '"'}:
                if not keep_strings:
                    mask(index)
                frames.append(
                    {
                        "kind": "string",
                        "quote": char,
                        "triple": False,
                        "sql_quote": "sql_quote" in policy,
                    }
                )
                index += 1
                continue
            if "template" in policy and char == "`":
                if not keep_strings:
                    mask(index)
                frames.append({"kind": "template"})
                index += 1
                continue
            index += 1
            continue

        if kind == "line-comment":
            if char == "\n":
                frames.pop()
            else:
                mask(index)
            index += 1
            continue

        if kind == "block-comment":
            if char == "*" and following == "/":
                mask(index)
                mask(index + 1)
                frames.pop()
                index += 2
            else:
                mask(index)
                index += 1
            continue

        if kind == "string":
            if frame.get("triple") and text[index : index + 3] == frame["quote"] * 3:
                if not keep_strings:
                    for offset in range(3):
                        mask(index + offset)
                frames.pop()
                index += 3
                continue
            if (
                frame.get("sql_quote")
                and char == frame["quote"]
                and following == frame["quote"]
            ):
                if not keep_strings:
                    mask(index)
                    mask(index + 1)
                index += 2
                continue
            if char == "\\":
                if not keep_strings:
                    mask(index)
                    if index + 1 < length:
                        mask(index + 1)
                index += 2
                continue
            if not keep_strings:
                mask(index)
            index += 1
            if char == frame["quote"]:
                frames.pop()
            continue

        if kind == "template":
            if char == "\\":
                if not keep_strings:
                    mask(index)
                    if index + 1 < length:
                        mask(index + 1)
                index += 2
                continue
            if char == "`":
                if not keep_strings:
                    mask(index)
                frames.pop()
                index += 1
                continue
            if char == "$" and following == "{":
                if not keep_strings:
                    mask(index)
                    mask(index + 1)
                frames.append(
                    {"kind": "code", "template_expr": True, "brace_depth": 1}
                )
                index += 2
                continue
            if not keep_strings:
                mask(index)
            index += 1
            continue

        if kind == "fstring":
            quote = frame["quote"]
            if text[index : index + len(quote)] == quote:
                if not keep_strings:
                    for offset in range(len(quote)):
                        mask(index + offset)
                frames.pop()
                index += len(quote)
                continue
            if char == "\\":
                if not keep_strings:
                    mask(index)
                    if index + 1 < length and following != "{":
                        mask(index + 1)
                index += 1 if following == "{" else 2
                continue
            if char == "{" and following == "{":
                if not keep_strings:
                    mask(index)
                    mask(index + 1)
                index += 2
                continue
            if char == "}" and following == "}":
                if not keep_strings:
                    mask(index)
                    mask(index + 1)
                index += 2
                continue
            if char == "{":
                if not keep_strings:
                    mask(index)
                frames.append(
                    {
                        "kind": "code",
                        "template_expr": True,
                        "python_fexpr": True,
                        "brace_depth": 1,
                        "paren_depth": 0,
                        "bracket_depth": 0,
                    }
                )
                index += 1
                continue
            if not keep_strings:
                mask(index)
            index += 1
            continue

        if kind == "f-format":
            if char == "{" and following == "{":
                if not keep_strings:
                    mask(index)
                    mask(index + 1)
                index += 2
                continue
            if char == "}" and following == "}":
                if not keep_strings:
                    mask(index)
                    mask(index + 1)
                index += 2
                continue
            if char == "{":
                if not keep_strings:
                    mask(index)
                frames.append(
                    {
                        "kind": "code",
                        "template_expr": True,
                        "python_fexpr": True,
                        "brace_depth": 1,
                        "paren_depth": 0,
                        "bracket_depth": 0,
                    }
                )
                index += 1
                continue
            if char == "}":
                if not keep_strings:
                    mask(index)
                frames.pop()
                index += 1
                continue
            if not keep_strings:
                mask(index)
            index += 1
            continue

        if kind == "f-conversion":
            if not keep_strings:
                mask(index)
            if char == ":":
                frame["kind"] = "f-format"
            elif char == "}":
                frames.pop()
            index += 1
            continue

    return "".join(output)


def iter_repository_files(
    root: Path, stats: Optional[WalkStats] = None, max_entries: int = 200_000
) -> Iterable[Path]:
    stats = stats or WalkStats()
    for current, directories, filenames in os.walk(
        str(root), topdown=True, followlinks=False
    ):
        current_path = Path(current)
        kept_directories = []
        for name in sorted(directories):
            stats.entries_seen += 1
            if stats.entries_seen > max_entries:
                stats.entry_limit_reached = True
                directories[:] = []
                return
            candidate = current_path / name
            if name.lower() in EXCLUDED_DIRS or is_link_like(candidate):
                continue
            kept_directories.append(name)
        directories[:] = kept_directories
        for name in sorted(filenames):
            stats.entries_seen += 1
            if stats.entries_seen > max_entries:
                stats.entry_limit_reached = True
                directories[:] = []
                return
            candidate = current_path / name
            if is_link_like(candidate) or not is_supported_file(candidate):
                continue
            yield candidate


def load_declarations(path: Optional[Path]) -> Dict[str, bool]:
    if path is None:
        return {}
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_CONTEXT_BYTES:
            raise ValueError("Context declaration exceeds the 64 KiB input limit.")
        payload = strict_json_loads(raw.decode("utf-8-sig"))
    except (OSError, ValueError, RecursionError) as exc:
        raise ValueError(
            "Unable to read context declaration JSON: " + str(exc)
        ) from exc
    contexts = payload.get("contexts")
    if not isinstance(contexts, dict):
        raise ValueError("Context declaration must contain an object named 'contexts'.")
    allowed = set(PACK_CLAIMS)
    unknown = sorted(set(contexts) - allowed)
    if unknown:
        raise ValueError("Unknown declared context(s): " + ", ".join(unknown))
    declarations: Dict[str, bool] = {}
    for pack, value in contexts.items():
        if not isinstance(value, bool):
            raise ValueError("Declared context '" + pack + "' must be true or false.")
        declarations[pack] = value
    return declarations


def confidence_for(observations: Sequence[Mapping[str, Any]]) -> str:
    levels = [item["confidence"] for item in observations]
    if "high" in levels:
        return "high"
    independent_detectors = {item["detector"]["id"] for item in observations}
    independent_kinds = {item["kind"] for item in observations}
    if len(independent_detectors) >= 2 and len(independent_kinds) >= 2:
        return "high"
    if "medium" in levels:
        return "medium"
    return "low"


def build_capabilities(
    observations: Sequence[Mapping[str, Any]],
    coverage_status: str,
    routing: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Build tri-state sub-capabilities used by control applicability rules."""

    result: List[Dict[str, Any]] = []
    active_packs = {
        str(item["pack"])
        for item in routing
        if item["state"] in {"required", "candidate"}
    }
    for key in KNOWN_CAPABILITIES:
        supporting = [
            item
            for item in observations
            if item["claim"] == key and item["scope"] == "production"
        ]
        if supporting:
            state = "present"
            reason = "Supported production evidence established this sub-capability."
        elif coverage_status == "complete" and not (
            CAPABILITY_CONTEXT_PACKS[key] & active_packs
        ):
            state = "not_observed"
            reason = (
                "No prerequisite product context or supported production evidence "
                "for this sub-capability was observed."
            )
        else:
            state = "unknown"
            reason = (
                "A prerequisite context is active or coverage is partial; pattern "
                "non-observation is not enough to establish absence."
            )
        result.append(
            {
                "key": key,
                "state": state,
                "evidence_refs": sorted(item["id"] for item in supporting),
                "reason": reason,
            }
        )
    return result


def build_claims(
    observations: Sequence[Mapping[str, Any]], declarations: Mapping[str, bool]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    claims: List[Dict[str, Any]] = []
    contradictions: List[Dict[str, str]] = []
    for pack in PACK_ORDER:
        if pack == "foundation":
            continue
        key = PACK_CLAIMS[pack]
        supporting = [
            item
            for item in observations
            if item["claim"] == key and item["scope"] == "production"
        ]
        declared = declarations.get(pack)
        observed = bool(supporting)
        if declared is False and observed:
            state = "contradicted"
            source = "combined"
            contradictions.append(
                {
                    "claim": key,
                    "declared": "absent",
                    "observed": "present",
                    "message": "Owner declaration conflicts with production repository evidence; evidence was not suppressed.",
                }
            )
        elif declared is True:
            state = "present"
            source = "combined" if observed else "declared"
        elif declared is False:
            state = "absent"
            source = "declared"
        elif observed:
            state = "present"
            source = "inferred"
        else:
            state = "unknown"
            source = "inferred"
        claims.append(
            {
                "key": key,
                "pack": pack,
                "state": state,
                "source": source,
                "inference_confidence": confidence_for(supporting)
                if supporting
                else "none",
                "evidence_refs": sorted(item["id"] for item in supporting),
            }
        )
    return claims, contradictions


def build_routing(claims: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    states: Dict[str, str] = {"foundation": "required"}
    reasons: Dict[str, List[str]] = {
        "foundation": ["Universal foundation for every software repository."]
    }
    for claim in claims:
        pack = str(claim["pack"])
        state = str(claim["state"])
        confidence = str(claim["inference_confidence"])
        if state == "present" and (
            claim["source"] in {"declared", "combined"} or confidence == "high"
        ):
            states[pack] = "required"
            reasons[pack] = [
                "Applicable context is present with direct declaration or high-confidence evidence."
            ]
        elif state == "contradicted" and confidence == "high":
            states[pack] = "required"
            reasons[pack] = [
                "Applicable context is present with direct declaration or high-confidence evidence."
            ]
        elif state == "present":
            states[pack] = "candidate"
            reasons[pack] = [
                "Context evidence is present but needs confirmation before mandatory routing."
            ]
        elif state == "contradicted":
            states[pack] = "candidate"
            reasons[pack] = [
                "Declared context conflicts with partial repository evidence; investigate before disposition."
            ]
        elif state == "absent":
            states[pack] = "inactive"
            reasons[pack] = [
                "An explicit declaration marks this context absent; repository evidence did not contradict it."
            ]
        else:
            states[pack] = "unknown"
            reasons[pack] = [
                "No reliable production evidence established applicability or absence."
            ]

    changed = True
    while changed:
        changed = False
        for pack, dependencies in PACK_DEPENDENCIES.items():
            parent_state = states.get(pack, "unknown")
            if parent_state not in {"required", "candidate"}:
                continue
            for dependency in dependencies:
                desired = "required" if parent_state == "required" else "candidate"
                current = states.get(dependency, "unknown")
                rank = {"unknown": 0, "inactive": 0, "candidate": 1, "required": 2}
                if rank[current] < rank[desired]:
                    states[dependency] = desired
                    reasons[dependency] = [
                        desired.capitalize() + " dependency of " + pack + "."
                    ]
                    changed = True

    routing: List[Dict[str, Any]] = []
    for pack in PACK_ORDER:
        routing.append(
            {
                "pack": pack,
                "state": states.get(pack, "unknown"),
                "reasons": reasons.get(pack, ["No routing decision was available."]),
                "dependencies": list(PACK_DEPENDENCIES.get(pack, ())),
            }
        )
    return routing


def profile_repository(
    root: Path,
    context_file: Optional[Path] = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> Dict[str, Any]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Repository root is not a directory: " + str(root))
    declarations = load_declarations(context_file)
    observations: List[Dict[str, Any]] = []
    file_hashes: List[str] = []
    files_considered = 0
    files_scanned = 0
    files_skipped = 0
    bytes_scanned = 0
    skip_counts: Dict[str, int] = {
        "non_production_scope": 0,
        "file_size_limit": 0,
        "total_byte_limit": 0,
        "stat_error": 0,
        "read_error": 0,
        "binary": 0,
        "invalid_encoding": 0,
        "invalid_manifest": 0,
    }
    partial = False
    walk_stats = WalkStats()
    max_entries = max(1_000, max_files * 20)
    limitations = [
        "Static evidence only: absence of a detector match remains unknown.",
        "v0.3 detectors are strongest for Node.js, Python manifests, Next.js, FastAPI, Django, Prisma, Terraform, and common CI workflow shapes; other stacks may need manual profiling.",
        "Documentation, tests, fixtures, generated output, dependencies, and symlinks do not drive routing.",
        "No target code, build, test, scanner, network call, or compliance assessment was executed.",
    ]

    for path in iter_repository_files(root, walk_stats, max_entries):
        relative_path = path.relative_to(root)
        scope = classify_scope(relative_path)
        if scope != "production":
            files_skipped += 1
            skip_counts["non_production_scope"] += 1
            continue
        if files_considered >= max_files:
            partial = True
            limitations.append(
                "File limit reached; remaining supported production files were not scanned."
            )
            break
        files_considered += 1
        relative = relative_path.as_posix()
        try:
            size = path.stat().st_size
        except OSError:
            files_skipped += 1
            partial = True
            skip_counts["stat_error"] += 1
            file_hashes.append(relative + "\x1funreadable")
            continue
        if size > max_file_bytes or bytes_scanned + size > max_total_bytes:
            files_skipped += 1
            partial = True
            file_hashes.append(relative + "\x1fskipped-size=" + str(size))
            if bytes_scanned + size > max_total_bytes:
                skip_counts["total_byte_limit"] += 1
                limitations.append(
                    "Total byte limit reached; remaining files were not scanned."
                )
                break
            skip_counts["file_size_limit"] += 1
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            files_skipped += 1
            partial = True
            skip_counts["read_error"] += 1
            file_hashes.append(relative + "\x1funreadable")
            continue
        try:
            if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                text = raw.decode("utf-16")
            elif raw.startswith(b"\xef\xbb\xbf"):
                text = raw.decode("utf-8-sig")
            elif b"\x00" in raw[:4096]:
                raise ValueError("binary")
            else:
                text = raw.decode("utf-8")
        except UnicodeDecodeError:
            files_skipped += 1
            partial = True
            skip_counts["invalid_encoding"] += 1
            file_hashes.append(
                relative + "\x1finvalid-encoding=" + hashlib.sha256(raw).hexdigest()
            )
            continue
        except ValueError:
            files_skipped += 1
            partial = True
            skip_counts["binary"] += 1
            file_hashes.append(
                relative + "\x1fbinary=" + hashlib.sha256(raw).hexdigest()
            )
            continue
        content_hash = hashlib.sha256(raw).hexdigest()
        file_hashes.append(relative + "\x1f" + content_hash)
        files_scanned += 1
        bytes_scanned += len(raw)
        observations.extend(inspect_package_json(relative, text, scope))
        observations.extend(inspect_python_manifest(relative, text, scope))
        if Path(relative).name == "package.json":
            try:
                manifest = strict_json_loads(text)
                if not isinstance(manifest, dict):
                    raise ValueError("package.json root must be an object")
            except (ValueError, TypeError, RecursionError):
                partial = True
                skip_counts["invalid_manifest"] += 1
                limitations.append(
                    "At least one production package.json could not be parsed; dependency evidence may be incomplete."
                )
        observations.extend(inspect_text(relative, text, scope))

    if walk_stats.entry_limit_reached:
        partial = True
        limitations.append(
            "Repository entry limit reached; remaining directories and files were not inspected."
        )

    unique = {item["id"]: item for item in observations}
    observations = [unique[key] for key in sorted(unique)]
    claims, contradictions = build_claims(observations, declarations)
    routing = build_routing(claims)
    coverage_status = "partial" if partial else "complete"
    capabilities = build_capabilities(observations, coverage_status, routing)
    required_packs = [item["pack"] for item in routing if item["state"] == "required"]
    candidate_packs = [item["pack"] for item in routing if item["state"] == "candidate"]
    scope_material = [
        "schema=" + SCHEMA_VERSION,
        "detector=" + DETECTOR_VERSION,
        "decision-model=" + DECISION_MODEL_DIGEST,
        "declarations="
        + json.dumps(declarations, sort_keys=True, separators=(",", ":")),
        "limits="
        + json.dumps(
            {
                "max_entries": max_entries,
                "max_files": max_files,
                "max_file_bytes": max_file_bytes,
                "max_total_bytes": max_total_bytes,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        "coverage="
        + json.dumps(
            {"partial": partial, "skip_counts": skip_counts},
            sort_keys=True,
            separators=(",", ":"),
        ),
        *sorted(file_hashes),
    ]
    subject_revision = sha256_text("\n".join(scope_material))
    source_inventory_digest = sha256_text("\n".join(sorted(file_hashes)))
    for observation in observations:
        observation["evidence"]["subject_revision"] = subject_revision
    return {
        "schema_version": SCHEMA_VERSION,
        "subject": {
            "repository": redact_path(root.name),
            "subject_revision": subject_revision,
            "source_inventory_digest": source_inventory_digest,
            "decision_model_digest": DECISION_MODEL_DIGEST,
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "bytes_scanned": bytes_scanned,
        },
        "coverage": {
            "status": coverage_status,
            "entries_seen": walk_stats.entries_seen,
            "production_files_considered": files_considered,
            "skip_counts": skip_counts,
            "limits": {
                "max_entries": max_entries,
                "max_files": max_files,
                "max_file_bytes": max_file_bytes,
                "max_total_bytes": max_total_bytes,
            },
        },
        "observations": observations,
        "claims": claims,
        "capabilities": capabilities,
        "routing": routing,
        "required_packs": required_packs,
        "candidate_packs": candidate_packs,
        "contradictions": contradictions,
        "limitations": list(dict.fromkeys(limitations)),
    }


def render_markdown(profile: Mapping[str, Any]) -> str:
    subject = profile["subject"]
    coverage = profile["coverage"]
    lines = [
        "# ContextSec Security Profile",
        "",
        "- Repository: `" + markdown_safe(str(subject["repository"])) + "`",
        "- Subject revision: `" + str(subject["subject_revision"]) + "`",
        "- Detector version: `" + DETECTOR_VERSION + "`",
        "- Coverage: `" + str(coverage["status"]) + "`",
        "- Scanned: "
        + str(subject["files_scanned"])
        + " files / "
        + str(subject["bytes_scanned"])
        + " bytes",
        "- Skipped: " + str(subject["files_skipped"]) + " files",
        "",
        "## Routing",
        "",
        "| Pack | State | Reason |",
        "|---|---|---|",
    ]
    for item in profile["routing"]:
        lines.append(
            "| `"
            + item["pack"]
            + "` | "
            + item["state"]
            + " | "
            + " ".join(item["reasons"])
            + " |"
        )
    lines.extend(
        [
            "",
            "## Claims",
            "",
            "| Claim | State | Source | Confidence | Evidence |",
            "|---|---|---|---|---|",
        ]
    )
    for claim in profile["claims"]:
        refs = ", ".join("`" + ref + "`" for ref in claim["evidence_refs"]) or "-"
        lines.append(
            "| `"
            + claim["key"]
            + "` | "
            + claim["state"]
            + " | "
            + claim["source"]
            + " | "
            + claim["inference_confidence"]
            + " | "
            + refs
            + " |"
        )
    relevant_capabilities = [
        item for item in profile["capabilities"] if item["state"] != "not_observed"
    ]
    lines.extend(["", "## Sub-capabilities", ""])
    if not relevant_capabilities:
        lines.append("No supported sub-capability evidence was observed.")
    else:
        lines.extend(["| Capability | State | Evidence |", "|---|---|---|"])
        for capability in relevant_capabilities:
            refs = ", ".join(
                "`" + ref + "`" for ref in capability["evidence_refs"]
            ) or "-"
            lines.append(
                "| `"
                + capability["key"]
                + "` | "
                + capability["state"]
                + " | "
                + refs
                + " |"
            )
    lines.extend(["", "## Evidence (redacted)", ""])
    if not profile["observations"]:
        lines.append("No production observations matched the v0.3 detectors.")
    else:
        for item in profile["observations"]:
            evidence = item["evidence"]
            lines.append(
                "- `"
                + item["id"]
                + "` "
                + item["detector"]["id"]
                + " ("
                + item["confidence"]
                + ") at `"
                + markdown_safe(evidence["path"])
                + ":"
                + markdown_safe(evidence["locator"])
                + "`; content `"
                + evidence["content_digest"]
                + "`; fingerprint `"
                + evidence["fingerprint"]
                + "`"
            )
    if profile["contradictions"]:
        lines.extend(["", "## Contradictions", ""])
        for item in profile["contradictions"]:
            lines.append("- `" + item["claim"] + "`: " + item["message"])
    lines.extend(["", "## Limitations", ""])
    lines.extend("- " + item for item in profile["limitations"])
    return "\n".join(lines) + "\n"


def markdown_safe(value: str) -> str:
    """Keep repository-controlled labels inside one Markdown code span."""

    return (
        value.replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("`", "%60")
        .replace("|", "\\|")
    )


def write_output_atomic(path: Path, rendered: str) -> None:
    """Replace an output path atomically so symlinks/hardlinks are not followed."""

    destination = path.absolute()
    for parent in (destination.parent, *destination.parents):
        if parent.exists() and is_link_like(parent):
            raise ValueError("Output path traverses a symlink or reparse point.")
    destination.parent.mkdir(parents=False, exist_ok=True)
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".contextsec-",
            suffix=".tmp",
            dir=str(destination.parent),
            delete=False,
        ) as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
            temporary_name = handle.name
        os.replace(temporary_name, destination)
    finally:
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a deterministic ContextSec repository profile."
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Repository root to inspect (default: current directory).",
    )
    parser.add_argument(
        "--context",
        help="Optional caller-supplied JSON declaration with a 'contexts' boolean map.",
    )
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument(
        "--output",
        help="Explicit output file. Without this option, output is written to stdout only.",
    )
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.max_files < 1 or args.max_file_bytes < 1 or args.max_total_bytes < 1:
        print("error: scan limits must be positive integers", file=sys.stderr)
        return 2
    try:
        profile = profile_repository(
            Path(args.repo),
            Path(args.context).resolve(strict=True) if args.context else None,
            args.max_files,
            args.max_file_bytes,
            args.max_total_bytes,
        )
        rendered = (
            json.dumps(profile, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
            if args.format == "json"
            else render_markdown(profile)
        )
        if args.output:
            write_output_atomic(Path(args.output), rendered)
        else:
            sys.stdout.write(rendered)
        return 0
    except (OSError, ValueError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
