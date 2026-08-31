"""Stable semantic digests for detector and checker behavior.

The digest input is normalized Python AST, not source bytes. This keeps comments,
formatting, CLI help, and rendering changes out of the model identity while making
the exact behavior symbols and supporting modules explicit and reviewable.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


def canonical_digest(value: Any) -> str:
    material = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _assigned_names(node: ast.AST) -> set[str]:
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return {
            target.id
            for target in targets
            if isinstance(target, ast.Name)
        }
    return set()


def semantic_symbols(path: Path, names: Iterable[str]) -> Mapping[str, str]:
    """Return normalized AST for an exact, fail-closed symbol allowlist."""

    requested = set(names)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    found: dict[str, str] = {}
    for node in tree.body:
        node_names: set[str] = set()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            node_names.add(node.name)
        node_names.update(_assigned_names(node))
        selected = node_names & requested
        if not selected:
            continue
        normalized = ast.dump(node, annotate_fields=True, include_attributes=False)
        for name in selected:
            if name in found:
                raise RuntimeError("Duplicate semantic model symbol: " + name)
            found[name] = normalized
    missing = sorted(requested - set(found))
    if missing:
        raise RuntimeError("Missing semantic model symbols: " + ", ".join(missing))
    return {name: found[name] for name in sorted(found)}


def semantic_module_digest(path: Path) -> str:
    """Digest all executable module semantics while ignoring source formatting."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    return canonical_digest(ast.dump(tree, annotate_fields=True, include_attributes=False))


def semantic_model_digest(
    *,
    path: Path,
    symbols: Iterable[str],
    dependencies: Mapping[str, str],
) -> str:
    return canonical_digest(
        {
            "symbols": semantic_symbols(path, symbols),
            "dependencies": dict(sorted(dependencies.items())),
        }
    )
