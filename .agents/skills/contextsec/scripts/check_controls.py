#!/usr/bin/env python3
"""Run narrow, deterministic cross-context checks for the v0.4 support matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import profile_repo  # noqa: E402
import model_digest  # noqa: E402
import safe_io  # noqa: E402
import support_matrix  # noqa: E402
import versioning  # noqa: E402

CHECKER_VERSION = versioning.CHECKER_VERSION


def checker_model_digest() -> str:
    """Digest normalized checker behavior, orchestration, and live dependencies."""

    return model_digest.semantic_model_digest(
        path=Path(__file__),
        symbols=(
            "CHECKER_SUPPORTED_SUFFIXES",
            "CHECKER_UNSUPPORTED_SUFFIXES",
            "CHECKER_PIPELINE",
            "checker_stack_family",
            "digest",
            "location",
            "finding",
            "load_sources",
            "prisma_models_with_fields",
            "check_tenant_queries",
            "check_tenant_raw_queries",
            "check_pii_logging",
            "check_ai_egress",
            "_skip_js_trivia",
            "_js_static_string",
            "_js_object_properties",
            "_js_static_expression",
            "_tenant_identity_use",
            "check_client_public_secrets",
            "check_public_upload",
            "check_upload_tenant_binding",
            "check_payment_idempotency",
            "check_cicd_action_pins",
            "check_cicd_declared_permissions",
        ),
        dependencies={
            "detector_model_digest": profile_repo.DETECTOR_MODEL_DIGEST,
            "safe_io": model_digest.semantic_module_digest(Path(safe_io.__file__)),
            "support_matrix": profile_repo.SUPPORT_MATRIX_DIGEST,
        },
    )

CHECKER_SUPPORTED_SUFFIXES = support_matrix.values("checker", "supported_suffixes")
CHECKER_UNSUPPORTED_SUFFIXES = support_matrix.values(
    "checker", "unsupported_suffixes"
)


def checker_stack_family(relative: Path) -> str:
    if relative.name == "package.json" or profile_repo.is_environment_file(relative):
        return "supported"
    suffix = relative.suffix.lower()
    normalized = relative.as_posix().lower()
    if suffix in {".yaml", ".yml"} and normalized.startswith(".github/workflows/"):
        return "supported"
    if suffix in CHECKER_SUPPORTED_SUFFIXES:
        return "supported"
    if relative.name in profile_repo.PROFILE_UNSUPPORTED_MANIFESTS:
        return "unsupported"
    if suffix in CHECKER_UNSUPPORTED_SUFFIXES:
        return "unsupported"
    return "neutral"


def digest(material: bytes) -> str:
    return "sha256:" + hashlib.sha256(material).hexdigest()


def location(
    relative: str,
    text: str,
    start: int,
    checker_id: str,
    raw: bytes,
    path_privacy: str = "heuristic",
) -> Dict[str, str]:
    locator = "line:" + str(profile_repo.line_number(text, start))
    safe_path = profile_repo.redact_path(relative, path_privacy)
    canonical_path = profile_repo.path_identity(relative)
    evidence_id = digest(
        "\x1f".join(
            ("evidence", canonical_path, locator, checker_id, CHECKER_MODEL_DIGEST)
        ).encode("utf-8")
    )
    content_digest = digest(raw)
    return {
        "path": safe_path,
        "path_identity": canonical_path,
        "locator": locator,
        "evidence_id": evidence_id,
        "location_id": digest(
            "\x1f".join(("location", canonical_path, locator)).encode("utf-8")
        ),
        "content_digest": content_digest,
        "fingerprint": digest(
            "\x1f".join(("fingerprint", evidence_id, content_digest)).encode("utf-8")
        ),
        "subject_revision": "pending",
    }


def finding(
    checker_id: str,
    control_ids: Sequence[str],
    status: str,
    severity: str,
    title: str,
    impact: str,
    attack_path: str,
    evidence: Mapping[str, str],
    method: str,
) -> Dict[str, Any]:
    stable_suffix = str(evidence["location_id"]).removeprefix("sha256:")
    return {
        "id": "finding-" + checker_id.lower() + "-" + stable_suffix,
        "checker": {"id": checker_id, "version": CHECKER_VERSION},
        "control_ids": list(control_ids),
        "status": status,
        "severity": severity,
        "title": title,
        "impact": impact,
        "attack_path": attack_path,
        "evidence": dict(evidence),
        "method": method,
    }


def load_sources(
    root: Path,
    max_files: int = profile_repo.DEFAULT_MAX_FILES,
    max_file_bytes: int = profile_repo.DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = profile_repo.DEFAULT_MAX_TOTAL_BYTES,
) -> Tuple[List[Tuple[str, str, bytes]], Dict[str, Any], str]:
    sources: List[Tuple[str, str, bytes]] = []
    stats = profile_repo.WalkStats()
    bytes_scanned = 0
    files_considered = 0
    partial = False
    supported_stack_seen = False
    unsupported_stack_seen = False
    scope_material = [
        "checker=" + CHECKER_VERSION,
        "limits="
        + json.dumps(
            {
                "max_entries": max(1_000, max_files * 20),
                "max_files": max_files,
                "max_file_bytes": max_file_bytes,
                "max_total_bytes": max_total_bytes,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
    ]
    for path in profile_repo.iter_repository_files(
        root, stats, max(1_000, max_files * 20)
    ):
        relative_path = path.relative_to(root)
        if profile_repo.classify_scope(relative_path) != "production":
            continue
        if files_considered >= max_files:
            partial = True
            break
        files_considered += 1
        relative = relative_path.as_posix()
        stack_family = checker_stack_family(relative_path)
        supported_stack_seen = supported_stack_seen or stack_family == "supported"
        unsupported_stack_seen = unsupported_stack_seen or stack_family == "unsupported"
        remaining_total = max_total_bytes - bytes_scanned
        if remaining_total < 1:
            partial = True
            break
        try:
            raw = safe_io.read_regular_file_at(
                root, relative_path, min(max_file_bytes, remaining_total)
            )
        except safe_io.FileSizeLimitError as exc:
            partial = True
            scope_material.append(relative + "\x1fskipped-size=" + str(exc.size))
            if remaining_total <= max_file_bytes:
                break
            continue
        except safe_io.UnsafeFileError:
            partial = True
            scope_material.append(relative + "\x1funsafe-file")
            continue
        except OSError:
            partial = True
            scope_material.append(relative + "\x1funreadable")
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
            partial = True
            scope_material.append(
                relative + "\x1finvalid-encoding=" + hashlib.sha256(raw).hexdigest()
            )
            continue
        except ValueError:
            partial = True
            scope_material.append(
                relative + "\x1fbinary=" + hashlib.sha256(raw).hexdigest()
            )
            continue
        evidence_text = (
            profile_repo.sanitize_environment_text(text)
            if profile_repo.is_environment_file(path)
            else text
        )
        evidence_raw = (
            evidence_text.encode("utf-8")
            if profile_repo.is_environment_file(path)
            else raw
        )
        sources.append((relative, evidence_text, evidence_raw))
        bytes_scanned += len(raw)
        scope_material.append(
            relative + "\x1f" + hashlib.sha256(evidence_raw).hexdigest()
        )
    if stats.entry_limit_reached:
        partial = True
    checker_hash = (
        "sha256:"
        + hashlib.sha256("\n".join(sorted(scope_material)).encode("utf-8")).hexdigest()
    )
    coverage = {
        "status": "partial" if partial else "complete",
        "language_support": (
            "partial"
            if supported_stack_seen and unsupported_stack_seen
            else "supported"
            if supported_stack_seen
            else "unsupported"
        ),
        "entries_seen": stats.entries_seen,
        "production_files_considered": files_considered,
        "files_loaded": len(sources),
        "bytes_loaded": bytes_scanned,
        "source_inventory_digest": profile_repo.sha256_text(
            "\n".join(sorted(scope_material[2:]))
        ),
    }
    return sources, coverage, checker_hash


def prisma_models_with_fields(
    sources: Sequence[Tuple[str, str, bytes]], field_pattern: str
) -> set:
    models = set()
    model_pattern = re.compile(r"\bmodel\s+(\w+)\s*\{(?P<body>.*?)\}", re.DOTALL)
    for relative, text, _raw in sources:
        if not relative.lower().endswith(".prisma"):
            continue
        for model_match in model_pattern.finditer(text):
            if re.search(field_pattern, model_match.group("body"), re.IGNORECASE):
                models.add(model_match.group(1).lower())
    return models


def check_tenant_queries(
    sources: Sequence[Tuple[str, str, bytes]],
    active: Sequence[str],
    path_privacy: str = "heuristic",
) -> List[Dict[str, Any]]:
    if not {"multi-tenant", "api-inbound"} <= set(active):
        return []
    tenant_models = prisma_models_with_fields(
        sources, rf"\b(?:{profile_repo.TENANT_PREDICATE_PATTERN})\b"
    )
    if not tenant_models:
        return []
    results = []
    pattern = re.compile(
        r"prisma\.(?P<model>\w+)\.(?P<operation>findUnique|findFirst|findMany|update|updateMany|delete|deleteMany|upsert)\s*\(\s*\{(?P<body>.{0,3000}?)\}\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    for relative, text, raw in sources:
        code = profile_repo.mask_comments_and_strings(
            text, language=profile_repo.language_for_path(relative)
        )
        for match in pattern.finditer(code):
            if match.group("model").lower() not in tenant_models:
                continue
            body = match.group("body")
            where_match = re.search(
                r"\bwhere\s*:\s*\{(?P<where>.{0,1200}?)\}",
                body,
                re.IGNORECASE | re.DOTALL,
            )
            where = where_match.group("where") if where_match else ""
            if not re.search(
                rf"\b(?:{profile_repo.TENANT_PREDICATE_PATTERN})\b",
                where,
                re.IGNORECASE,
            ):
                results.append(
                    finding(
                        "TENANT-QUERY-001",
                        (
                            "TEN-DB-001",
                            "API-OBJ-001",
                            "PII-ACCESS-001",
                            "COMP-API-TEN-001",
                        ),
                        "failed",
                        "critical",
                        "Tenant-owned record query lacks a tenant predicate",
                        "A caller-controlled object identifier can cross the tenant boundary.",
                        "Inbound identifier -> database lookup by object id only -> tenant-owned record response or processing.",
                        location(
                            relative, text, match.start(), "TENANT-QUERY-001", raw,
                            path_privacy,
                        ),
                        "Supported inline Prisma "
                        + match.group("operation")
                        + " operation contained no recognized tenant predicate.",
                    )
                )
    return results


def check_tenant_raw_queries(
    sources: Sequence[Tuple[str, str, bytes]],
    active: Sequence[str],
    path_privacy: str = "heuristic",
) -> List[Dict[str, Any]]:
    if not {"multi-tenant", "api-inbound"} <= set(active):
        return []
    results: List[Dict[str, Any]] = []
    pattern = re.compile(
        r"\bprisma\.\$(?:queryRaw|queryRawUnsafe|executeRaw|executeRawUnsafe)\b",
        re.IGNORECASE,
    )
    for relative, text, raw in sources:
        code = profile_repo.mask_comments_and_strings(
            text, language=profile_repo.language_for_path(relative)
        )
        for match in pattern.finditer(code):
            results.append(
                finding(
                    "TENANT-RAW-QUERY-001",
                    ("TEN-DB-001", "API-OBJ-001"),
                    "unknown",
                    "high",
                    "Raw Prisma query requires explicit tenant-scope verification",
                    "A raw query can bypass ORM-level tenant predicates and cross the tenant boundary.",
                    "Inbound request -> raw SQL execution -> tenant-owned rows without a mechanically verified scope.",
                    location(relative, text, match.start(), "TENANT-RAW-QUERY-001", raw, path_privacy),
                    "ContextSec found a supported Prisma raw-query call but does not parse SQL deeply enough to verify its tenant predicate.",
                )
            )
    return results


def check_pii_logging(
    sources: Sequence[Tuple[str, str, bytes]],
    active: Sequence[str],
    path_privacy: str = "heuristic",
) -> List[Dict[str, Any]]:
    if "privacy-pii" not in active:
        return []
    pii_models = prisma_models_with_fields(
        sources,
        r"\b(email|phone|fullName|firstName|lastName|address|billingAddress|dateOfBirth|nationalId|ssn)\b",
    )
    if not pii_models:
        return []
    assignment = re.compile(
        r"const\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*await\s+prisma\.(?P<model>\w+)\.find(?:Unique|First)\s*\((?P<query>.{0,2000}?)\)\s*;",
        re.IGNORECASE | re.DOTALL,
    )
    for relative, text, raw in sources:
        code = profile_repo.mask_comments_and_strings(
            text, language=profile_repo.language_for_path(relative)
        )
        for source_match in assignment.finditer(code):
            if source_match.group("model").lower() not in pii_models:
                continue
            if re.search(r"\b(select|omit)\s*:", source_match.group("query")):
                continue
            name = re.escape(source_match.group("name"))
            sink = re.search(
                r"console\.(?:log|info|debug|warn)\s*\([^)]*\b" + name + r"\b",
                code,
                re.IGNORECASE,
            )
            if sink:
                return [
                    finding(
                        "PII-LOG-001",
                        ("PII-LOG-001", "FND-LOG-001"),
                        "failed",
                        "high",
                        "Sensitive database object is written to an application log",
                        "Logs can retain and redistribute fields beyond their intended access and retention boundary.",
                        "PII-bearing Prisma result -> broad console logging sink.",
                        location(relative, text, sink.start(), "PII-LOG-001", raw, path_privacy),
                        "A supported Prisma model with PII fields flowed by variable identity to a same-file console logging sink.",
                    )
                ]
    return []


def check_ai_egress(
    sources: Sequence[Tuple[str, str, bytes]],
    active: Sequence[str],
    path_privacy: str = "heuristic",
) -> List[Dict[str, Any]]:
    if not {"privacy-pii", "ai-rag-agent", "external-api"} <= set(active):
        return []
    pii_models = prisma_models_with_fields(
        sources,
        r"\b(email|phone|fullName|firstName|lastName|address|billingAddress|dateOfBirth|nationalId|ssn)\b",
    )
    if not pii_models:
        return []
    tenant_models = prisma_models_with_fields(
        sources, r"\b(tenantId|organizationId|workspaceId)\b"
    )
    assignment = re.compile(
        r"const\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*await\s+prisma\.(?P<model>\w+)\.find(?:Unique|First)\s*\((?P<query>.{0,2000}?)\)\s*;",
        re.IGNORECASE | re.DOTALL,
    )
    call = re.compile(
        r"\b(?:responses|chat\.completions)\.create\s*\(\s*\{(?P<body>.{0,3000}?)\}\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    for relative, text, raw in sources:
        code = profile_repo.mask_comments_and_strings(
            text, language=profile_repo.language_for_path(relative)
        )
        assignments = [
            match
            for match in assignment.finditer(code)
            if match.group("model").lower() in pii_models
            and not re.search(r"\b(select|omit)\s*:", match.group("query"))
        ]
        for call_match in call.finditer(code):
            body = call_match.group("body")
            for source_match in assignments:
                name = re.escape(source_match.group("name"))
                sink = re.search(
                    r"\b(?:input|messages)\s*:\s*JSON\.stringify\s*\(\s*"
                    + name
                    + r"\s*\)",
                    body,
                    re.IGNORECASE,
                )
                if sink:
                    offset = call_match.start("body") + sink.start()
                    control_ids = [
                        "PII-PROC-001",
                        "EXT-EGRESS-001",
                        "AIR-DATA-001",
                        "COMP-AI-PII-001",
                    ]
                    if source_match.group("model").lower() in tenant_models:
                        control_ids.append("COMP-AI-TEN-001")
                    return [
                        finding(
                            "AI-PII-EGRESS-001",
                            tuple(control_ids),
                            "failed",
                            "critical",
                            "Unprojected database object is sent to an AI provider",
                            "Tenant and personal data can leave the application without field minimization or an explicit egress boundary.",
                            "PII-bearing Prisma result -> full-object serialization in model request input.",
                            location(relative, text, offset, "AI-PII-EGRESS-001", raw, path_privacy),
                            "A supported Prisma model with PII fields flowed by variable identity into the input/messages field of a same-file model call.",
                        )
                    ]
    return []


def _skip_js_trivia(text: str, index: int) -> int:
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            if newline < 0:
                return len(text)
            index = newline + 1
            continue
        if text.startswith("/*", index):
            closing = text.find("*/", index + 2)
            if closing < 0:
                return len(text)
            index = closing + 2
            continue
        break
    return index


def _js_static_string(text: str, index: int) -> Tuple[Optional[str], int]:
    if index >= len(text) or text[index] not in {"'", '"', "`"}:
        return None, index
    quote = text[index]
    cursor = index + 1
    value: List[str] = []
    static = True
    while cursor < len(text):
        char = text[cursor]
        if char == "\\":
            escape = text[cursor + 1] if cursor + 1 < len(text) else ""
            if escape == "x" and re.fullmatch(
                r"[0-9a-fA-F]{2}", text[cursor + 2 : cursor + 4]
            ):
                value.append(chr(int(text[cursor + 2 : cursor + 4], 16)))
                cursor += 4
            elif escape == "u" and re.match(
                r"\{[0-9a-fA-F]{1,6}\}", text[cursor + 2 :]
            ) is not None:
                closing = text.find("}", cursor + 3, cursor + 10)
                codepoint = int(text[cursor + 3 : closing], 16)
                if codepoint > 0x10FFFF:
                    return None, len(text)
                value.append(chr(codepoint))
                cursor = closing + 1
            elif escape == "u" and re.fullmatch(
                r"[0-9a-fA-F]{4}", text[cursor + 2 : cursor + 6]
            ):
                value.append(chr(int(text[cursor + 2 : cursor + 6], 16)))
                cursor += 6
            else:
                if escape:
                    value.append(escape)
                cursor += 2
            continue
        if quote == "`" and text.startswith("${", cursor):
            static = False
        if char == quote:
            return ("".join(value) if static else None), cursor + 1
        value.append(char)
        cursor += 1
    return None, len(text)


def _js_object_properties(body: str) -> List[Tuple[str, int, int]]:
    """Return bounded top-level object property value spans."""

    properties: List[Tuple[str, int, int]] = []
    cursor = 0
    while cursor < len(body):
        cursor = _skip_js_trivia(body, cursor)
        while cursor < len(body) and body[cursor] == ",":
            cursor = _skip_js_trivia(body, cursor + 1)
        if cursor >= len(body):
            break
        if body[cursor] == "[":
            computed_start = _skip_js_trivia(body, cursor + 1)
            computed_end = body.find("]", computed_start)
            if computed_end >= 0:
                name = _js_static_expression(body, computed_start, computed_end)
                key_end = computed_end + 1
            else:
                name = None
                key_end = cursor
        elif body[cursor] in {"'", '"', "`"}:
            name, key_end = _js_static_string(body, cursor)
        else:
            match = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", body[cursor:])
            name = match.group(0) if match else None
            key_end = cursor + len(name) if name else cursor
        separator = _skip_js_trivia(body, key_end)
        if not name or separator >= len(body) or body[separator] != ":":
            next_comma = body.find(",", max(cursor + 1, separator))
            cursor = len(body) if next_comma < 0 else next_comma + 1
            continue
        value_start = _skip_js_trivia(body, separator + 1)
        value_end = value_start
        depths = {"(": 0, "[": 0, "{": 0}
        closing_for = {")": "(", "]": "[", "}": "{"}
        while value_end < len(body):
            char = body[value_end]
            if body.startswith("//", value_end) or body.startswith("/*", value_end):
                value_end = _skip_js_trivia(body, value_end)
                continue
            if char in {"'", '"', "`"}:
                _, value_end = _js_static_string(body, value_end)
                continue
            if char in depths:
                depths[char] += 1
            elif char in closing_for and depths[closing_for[char]]:
                depths[closing_for[char]] -= 1
            elif char == "," and not any(depths.values()):
                break
            value_end += 1
        properties.append((name, value_start, value_end))
        cursor = value_end + 1
    return properties


def _js_static_expression(text: str, start: int, end: int) -> Optional[str]:
    start = _skip_js_trivia(text, start)
    while True:
        segment = text[start:end]
        assertion = re.search(
            r"\s+(?:as\s+const|satisfies\s+[A-Za-z_$][A-Za-z0-9_.$<>\[\]| &]*)\s*$",
            segment,
            re.IGNORECASE,
        )
        if assertion is not None:
            end = start + assertion.start()
        while end > start and text[end - 1].isspace():
            end -= 1
        if start >= end or text[start] != "(":
            break
        cursor = start + 1
        depth = 1
        closing = -1
        while cursor < end:
            if text[cursor] in {"'", '"', "`"}:
                _, cursor = _js_static_string(text, cursor)
                continue
            if text.startswith("//", cursor) or text.startswith("/*", cursor):
                cursor = _skip_js_trivia(text, cursor)
                continue
            if text[cursor] == "(":
                depth += 1
            elif text[cursor] == ")":
                depth -= 1
                if depth == 0:
                    closing = cursor
                    break
            cursor += 1
        if closing < 0 or _skip_js_trivia(text, closing + 1) != end:
            break
        start = _skip_js_trivia(text, start + 1)
        end = closing
    value, value_end = _js_static_string(text, start)
    trailing = text[_skip_js_trivia(text, value_end) : end]
    if value is None or trailing.strip():
        return None
    return value


def _tenant_identity_use(expression: str) -> Optional[int]:
    tenant_name = re.compile(
        rf"\b(?:{profile_repo.TENANT_PREDICATE_PATTERN})\b",
        re.IGNORECASE,
    )
    executable = profile_repo.mask_comments_and_strings(
        expression, language="javascript"
    )
    for match in tenant_name.finditer(executable):
        after = match.end()
        while after < len(executable) and executable[after].isspace():
            after += 1
        if after < len(executable) and executable[after] == ":":
            continue
        return match.start()
    for bracket in re.finditer(r"\[", executable):
        previous = bracket.start() - 1
        while previous >= 0 and executable[previous].isspace():
            previous -= 1
        if previous < 0 or not (
            executable[previous].isalnum()
            or executable[previous] in {"_", "$", ")", "]", "."}
        ):
            continue
        value_start = _skip_js_trivia(expression, bracket.end())
        value, value_end = _js_static_string(expression, value_start)
        value_end = _skip_js_trivia(expression, value_end)
        if (
            value is not None
            and tenant_name.fullmatch(value)
            and value_end < len(expression)
            and expression[value_end] == "]"
        ):
            return value_start
    return None


def check_client_public_secrets(
    sources: Sequence[Tuple[str, str, bytes]],
    active: Sequence[str],
    path_privacy: str = "heuristic",
) -> List[Dict[str, Any]]:
    del active
    code_pattern = re.compile(
        r"\b(?:process\.env\.(?:NEXT_PUBLIC_|REACT_APP_)|import\.meta\.env\.VITE_)"
        r"[A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE_KEY|ACCESS_TOKEN|REFRESH_TOKEN|"
        r"SERVICE_ROLE|SIGNING_KEY|WEBHOOK_SECRET)[A-Z0-9_]*\b",
        re.IGNORECASE,
    )
    env_pattern = re.compile(
        r"(?m)^\s*(?:export\s+)?(?:NEXT_PUBLIC_|VITE_|REACT_APP_)"
        r"[A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE_KEY|ACCESS_TOKEN|REFRESH_TOKEN|"
        r"SERVICE_ROLE|SIGNING_KEY|WEBHOOK_SECRET)[A-Z0-9_]*\s*=",
        re.IGNORECASE,
    )
    results: List[Dict[str, Any]] = []
    for relative, text, raw in sources:
        if profile_repo.is_environment_file(Path(relative)):
            matches = env_pattern.finditer(text)
        else:
            executable = profile_repo.mask_comments_and_strings(
                text, language=profile_repo.language_for_path(relative)
            )
            matches = code_pattern.finditer(executable)
        for match in matches:
            results.append(
                finding(
                    "CLIENT-PUBLIC-SECRET-001",
                    ("FND-SECRET-001",),
                    "failed",
                    "critical",
                    "Secret-bearing environment name is exposed to client code",
                    "A build-time public namespace can embed the corresponding credential in browser-delivered assets.",
                    "Server credential -> public framework environment namespace -> client bundle or browser runtime.",
                    location(relative, text, match.start(), "CLIENT-PUBLIC-SECRET-001", raw, path_privacy),
                    "The key name, not its value, matched a supported Next.js, Vite, or Create React App public namespace and an unambiguously secret-bearing token.",
                )
            )
    return results


def check_public_upload(
    sources: Sequence[Tuple[str, str, bytes]],
    active: Sequence[str],
    path_privacy: str = "heuristic",
) -> List[Dict[str, Any]]:
    if "file-upload" not in active:
        return []
    command = re.compile(
        r"\bnew\s+PutObjectCommand\s*\(\s*\{(?P<body>.{0,3000}?)\}\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    for relative, text, raw in sources:
        code = profile_repo.mask_comments_and_strings(
            text,
            language=profile_repo.language_for_path(relative),
        )
        for command_match in command.finditer(code):
            body_start = command_match.start("body")
            raw_body = text[body_start : command_match.end("body")]
            for name, value_start, value_end in _js_object_properties(raw_body):
                value = _js_static_expression(raw_body, value_start, value_end)
                if name.lower() != "acl" or value is None or value.lower() != "public-read":
                    continue
                offset = body_start + value_start
                return [
                    finding(
                        "UPLOAD-PUBLIC-001",
                        ("UPL-STORE-001",),
                        "failed",
                        "critical",
                        "Uploaded object is explicitly made public",
                        "An anonymous or weakly authorized upload can become attacker-controlled public content.",
                        "Inbound multipart file -> object storage write -> public-read ACL.",
                        location(relative, text, offset, "UPLOAD-PUBLIC-001", raw, path_privacy),
                        "The object passed to a supported S3 PutObjectCommand contained an explicit public-read ACL.",
                    )
                ]
    return []


def check_upload_tenant_binding(
    sources: Sequence[Tuple[str, str, bytes]],
    active: Sequence[str],
    path_privacy: str = "heuristic",
) -> List[Dict[str, Any]]:
    if not {"file-upload", "multi-tenant"} <= set(active):
        return []
    command = re.compile(
        r"\bnew\s+PutObjectCommand\s*\(\s*\{(?P<body>.{0,3000}?)\}\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    for relative, text, raw in sources:
        code = profile_repo.mask_comments_and_strings(
            text, language=profile_repo.language_for_path(relative)
        )
        for command_match in command.finditer(code):
            body_start = command_match.start("body")
            raw_body = text[body_start : command_match.end("body")]
            for name, value_start, value_end in _js_object_properties(raw_body):
                if name.lower() != "key":
                    continue
                raw_value = raw_body[value_start:value_end]
                identity_offset = _tenant_identity_use(raw_value)
                if identity_offset is None:
                    continue
                offset = body_start + value_start + identity_offset
                return [
                    finding(
                        "UPLOAD-TENANT-FLOW-001",
                        ("COMP-UPL-TEN-001",),
                        "unknown",
                        "critical",
                        "Tenant identity flows into an upload object key",
                        "The upload and tenant contexts intersect and require tenant-bound storage verification.",
                        "Authenticated tenant identity -> object key construction -> tenant-scoped upload storage.",
                        location(
                            relative,
                            text,
                            offset,
                            "UPLOAD-TENANT-FLOW-001",
                            raw,
                            path_privacy,
                        ),
                        "A supported PutObjectCommand Key property contained a tenant identity inside the same bounded expression.",
                    )
                ]
    return []


def check_payment_idempotency(
    sources: Sequence[Tuple[str, str, bytes]],
    active: Sequence[str],
    path_privacy: str = "heuristic",
) -> List[Dict[str, Any]]:
    if "payments" not in active:
        return []
    webhook = re.compile(r"\bwebhooks\.constructEvent(?:Async)?\b", re.IGNORECASE)
    dedupe = re.compile(
        r"\b(idempoten|dedup|processedEvent|processed_event|webhookEvent\.upsert)\b",
        re.IGNORECASE,
    )
    for relative, text, raw in sources:
        code = profile_repo.mask_comments_and_strings(
            text, language=profile_repo.language_for_path(relative)
        )
        match = webhook.search(code)
        if match and not dedupe.search(code):
            return [
                finding(
                    "PAYMENT-IDEMPOTENCY-001",
                    ("PAY-IDEMP-001",),
                    "unknown",
                    "high",
                    "No reproducible webhook idempotency evidence",
                    "A provider retry may repeat fulfillment or state changes if deduplication is absent.",
                    "Repeated signed event -> webhook handler -> potentially repeated business transition.",
                    location(
                        relative, text, match.start(), "PAYMENT-IDEMPOTENCY-001", raw,
                        path_privacy,
                    ),
                    "A verified-provider webhook call was present, but the supported lexical guard set found no event-id ledger or dedupe operation; no mutation test was run.",
                )
            ]
    return []


def check_cicd_action_pins(
    sources: Sequence[Tuple[str, str, bytes]],
    active: Sequence[str],
    path_privacy: str = "heuristic",
) -> List[Dict[str, Any]]:
    if "cicd-supply-chain" not in active:
        return []
    results: List[Dict[str, Any]] = []
    action = re.compile(r"(?m)^\s*-?\s*uses\s*:\s*[\"']?(?P<value>[^\s\"'#]+)")
    immutable = re.compile(r"^[^@]+@[a-f0-9]{40}(?:[a-f0-9]{24})?$", re.IGNORECASE)
    immutable_docker = re.compile(
        r"^docker://[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$", re.IGNORECASE
    )
    for relative, text, raw in sources:
        normalized = relative.replace("\\", "/").lower()
        if "/.github/workflows/" not in "/" + normalized:
            continue
        comments_removed = profile_repo.mask_comments_and_strings(
            text,
            keep_strings=True,
            language=profile_repo.language_for_path(relative),
        )
        for match in action.finditer(comments_removed):
            value = match.group("value")
            if value.startswith("./") or immutable.fullmatch(value):
                continue
            if value.startswith("docker://") and immutable_docker.fullmatch(value):
                continue
            results.append(
                finding(
                    "CICD-ACTION-PIN-001",
                    ("CICD-ACTION-001",),
                    "failed",
                    "critical",
                    "Third-party workflow action is not pinned to an immutable digest",
                    "A mutable tag or branch can be repointed after review and execute with workflow authority.",
                    "Workflow uses reference -> upstream reference changes -> unreviewed code executes in CI.",
                    location(relative, text, match.start("value"), "CICD-ACTION-PIN-001", raw, path_privacy),
                    "A non-local uses reference was not a 40- or 64-character hexadecimal digest.",
                )
            )
    return results


def check_cicd_declared_permissions(
    sources: Sequence[Tuple[str, str, bytes]],
    active: Sequence[str],
    path_privacy: str = "heuristic",
) -> List[Dict[str, Any]]:
    if "cicd-supply-chain" not in active:
        return []
    results: List[Dict[str, Any]] = []
    permissions = re.compile(r"(?m)^permissions\s*:")
    for relative, text, raw in sources:
        normalized = relative.replace("\\", "/").lower()
        if "/.github/workflows/" not in "/" + normalized:
            continue
        comments_removed = profile_repo.mask_comments_and_strings(
            text,
            keep_strings=True,
            language=profile_repo.language_for_path(relative),
        )
        if permissions.search(comments_removed):
            continue
        results.append(
            finding(
                "CICD-PERMISSIONS-001",
                ("CICD-TOKEN-001",),
                "unknown",
                "high",
                "Workflow does not declare a top-level token permission baseline",
                "Repository or organization defaults can grant more workflow authority than the file makes reviewable.",
                "Workflow trigger -> implicit platform token permissions -> build step receives repository authority.",
                location(relative, text, 0, "CICD-PERMISSIONS-001", raw, path_privacy),
                "The workflow contained no unindented top-level permissions mapping; effective platform defaults were not queried.",
            )
        )
    return results


CHECKER_PIPELINE = (
    check_tenant_queries,
    check_tenant_raw_queries,
    check_pii_logging,
    check_ai_egress,
    check_client_public_secrets,
    check_public_upload,
    check_upload_tenant_binding,
    check_payment_idempotency,
    check_cicd_action_pins,
    check_cicd_declared_permissions,
)
CHECKER_MODEL_DIGEST = checker_model_digest()


def check_repository(
    root: Path,
    profile: Optional[Mapping[str, Any]] = None,
    path_privacy: str = "heuristic",
) -> Dict[str, Any]:
    root = root.resolve(strict=True)
    if profile is None:
        profile = profile_repo.profile_repository(root, path_privacy=path_privacy)
    else:
        path_privacy = str(
            profile.get("artifact_options", {}).get("path_privacy", path_privacy)
        )
    if profile.get("schema_version") != profile_repo.SCHEMA_VERSION:
        raise ValueError("Profile schema_version does not match this checker.")
    if profile.get("subject", {}).get("repository") != profile_repo.redact_path(
        root.name, path_privacy
    ):
        raise ValueError("Profile repository does not match the checker repository.")
    if profile.get("subject", {}).get(
        "decision_model_digest"
    ) != profile_repo.DECISION_MODEL_DIGEST:
        raise ValueError("Profile decision model does not match this checker.")
    active = list(dict.fromkeys(profile["required_packs"] + profile["candidate_packs"]))
    sources, checker_coverage, checker_hash = load_sources(root)
    if checker_coverage["source_inventory_digest"] != profile["subject"].get(
        "source_inventory_digest"
    ):
        raise ValueError(
            "Repository changed after profiling; source inventory does not match."
        )
    findings: List[Dict[str, Any]] = []
    for checker in CHECKER_PIPELINE:
        findings.extend(checker(sources, active, path_privacy))
    findings.sort(key=lambda item: item["id"])
    for item in findings:
        item["evidence"]["subject_revision"] = profile["subject"][
            "subject_revision"
        ]
    limitations = [
        "These are narrow deterministic checks, not a general vulnerability scan.",
        "A missing lexical pattern is never treated as verified control evidence.",
        "Only the documented Node.js, Next.js, Prisma, S3, Stripe, OpenAI, GitHub/docker action, and public environment-name shapes are supported in v0.4.",
        "Traversal coverage, language support, checker support, and match enumeration are reported separately; most v0.4 checkers enumerate only their first supported finding per file or repository.",
        "PII flow checks abstain on Prisma select/omit projections rather than assuming the returned shape is sensitive.",
    ]
    if profile["coverage"]["status"] == "partial":
        limitations.append(
            "The underlying applicability profile is partial; findings are incomplete."
        )
    if checker_coverage["status"] == "partial":
        limitations.append(
            "The checker input traversal is partial; deterministic findings are incomplete."
        )
    return {
        "schema_version": profile_repo.SCHEMA_VERSION,
        "artifact_options": {"path_privacy": path_privacy},
        "subject": {
            "repository": profile["subject"]["repository"],
            "subject_revision": profile["subject"]["subject_revision"],
            "decision_model_digest": profile["subject"]["decision_model_digest"],
            "routing_model_digest": profile["subject"]["routing_model_digest"],
            "detector_version": profile["subject"]["detector_version"],
            "detector_model_digest": profile["subject"]["detector_model_digest"],
            "checker_model_digest": CHECKER_MODEL_DIGEST,
            "catalog_digest": profile["subject"]["catalog_digest"],
            "composition_digest": profile["subject"]["composition_digest"],
            "support_matrix_digest": profile["subject"]["support_matrix_digest"],
            "source_inventory_digest": checker_coverage["source_inventory_digest"],
            "checker_version": CHECKER_VERSION,
            "profile_coverage": profile["coverage"]["status"],
            "profile_language_support": profile["coverage"]["language_support"],
            "checker_coverage": {
                "traversal": checker_coverage["status"],
                "language_support": checker_coverage["language_support"],
                "checker_support": support_matrix.SUPPORT_MATRIX["coverage_semantics"]["checker_support"],
                "match_enumeration": support_matrix.SUPPORT_MATRIX["coverage_semantics"]["match_enumeration"]
            },
            "checker_input_hash": checker_hash,
        },
        "active_packs": active,
        "findings": findings,
        "finding_summary": {
            "failed_findings": sum(item["status"] == "failed" for item in findings),
            "unknown_findings": sum(item["status"] == "unknown" for item in findings),
            "verified_findings": 0,
            "total_findings": len(findings),
        },
        "limitations": limitations,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run ContextSec deterministic control checks."
    )
    parser.add_argument("--repo", default=".")
    parser.add_argument("--output")
    parser.add_argument(
        "--path-privacy",
        choices=profile_repo.PATH_PRIVACY_MODES,
        default="heuristic",
    )
    args = parser.parse_args(argv)
    try:
        result = check_repository(Path(args.repo), path_privacy=args.path_privacy)
        rendered = (
            json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        )
        if args.output:
            profile_repo.write_output_atomic(Path(args.output), rendered)
        else:
            sys.stdout.write(rendered)
        return 0
    except (OSError, ValueError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
