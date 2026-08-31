"""Explicit online verification for signed GitHub artifact attestations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(
    path: Path,
    repository: str,
    *,
    signer_workflow: Optional[str] = None,
    gh_executable: str = "gh",
) -> Dict[str, Any]:
    """Verify with gh without a shell and return only digest-bound signer facts."""

    path = path.resolve(strict=True)
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise ValueError("Attestation repository must be OWNER/REPO.")
    command = [
        gh_executable,
        "attestation",
        "verify",
        str(path),
        "--repo",
        repository,
        "--format",
        "json",
    ]
    if signer_workflow is not None:
        if re.fullmatch(
            r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:\.github/workflows/)?[A-Za-z0-9_./-]+\.ya?ml",
            signer_workflow,
        ) is None:
            raise ValueError("Signer workflow must be a canonical GitHub URL.")
        command.extend(["--signer-workflow", signer_workflow.removeprefix("https://")])
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "GH_TOKEN", "GH_HOST"}
    }
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Unable to verify GitHub attestation.") from exc
    if result.returncode != 0:
        raise ValueError("GitHub attestation verification failed.")
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("GitHub attestation verification returned invalid JSON.") from exc
    records = payload if isinstance(payload, list) else [payload]
    expected = _sha256(path)
    for record in records:
        if not isinstance(record, dict):
            continue
        verification = record.get("verificationResult")
        if not isinstance(verification, dict):
            continue
        statement = verification.get("statement")
        signature = verification.get("signature")
        if not isinstance(statement, dict) or not isinstance(signature, dict):
            continue
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or not any(
            isinstance(subject, dict)
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == expected
            for subject in subjects
        ):
            continue
        certificate = signature.get("certificate")
        if not isinstance(certificate, dict):
            continue
        verified_times = []
        timestamps = verification.get("verifiedTimestamps")
        if isinstance(timestamps, list):
            for timestamp in timestamps:
                if not isinstance(timestamp, dict):
                    continue
                try:
                    verified_times.append(
                        datetime.fromisoformat(
                            str(timestamp.get("timestamp", "")).replace("Z", "+00:00")
                        )
                    )
                except ValueError:
                    continue
        signer = certificate.get("subjectAlternativeName")
        source_commit = certificate.get("sourceRepositoryDigest") or certificate.get(
            "githubWorkflowSHA"
        )
        if (
            not isinstance(signer, str)
            or not signer.startswith("https://github.com/")
            or re.fullmatch(r"[a-f0-9]{40}", str(source_commit)) is None
            or not verified_times
        ):
            continue
        return {
            "status": "verified",
            "repository": repository,
            "sha256": expected,
            "signer": signer,
            "source_commit": source_commit,
            "verified_at": min(verified_times).isoformat(),
        }
    raise ValueError("Verified attestation did not bind the requested file digest.")
