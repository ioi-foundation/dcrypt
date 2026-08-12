#!/usr/bin/env python3
"""Canonical process-isolated entry point for the blocked reference scaffold."""

from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

from common import (
    PROTOCOL_VERSION,
    ValidationError,
    canonical_bytes,
    load_canonical_bytes,
    sha256_bytes,
    validate_request,
)


ROOT = Path(__file__).resolve().parent
WORKER = ROOT / "worker.py"
# Deliberately empty. Adding an independently reviewed dossier requires a
# reviewed source change, not a self-attested JSON status flip.
APPROVED_BACKEND_DOSSIER_SHA256: frozenset[str] = frozenset()
PINNED_PROTOCOL_CONTRACT_SHA256: frozenset[str] = frozenset()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--request",
        type=Path,
        required=True,
        help="canonical request JSON (use '-' for stdin)",
    )
    return result


def read_request(path: Path) -> bytes:
    if str(path) == "-":
        raw = sys.stdin.buffer.read(65537)
    else:
        raw = path.read_bytes()
    if len(raw) > 65536:
        raise ValidationError("request: exceeds 65536-byte limit")
    return raw


def sanitized_environment(tmp: str) -> dict[str, str]:
    return {
        "HOME": tmp,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "PYTHONHASHSEED": "0",
        "TMPDIR": tmp,
    }


def validate_worker_response(
    response_raw: bytes,
    *,
    request: dict[str, object],
    request_raw: bytes,
    challenge: str,
) -> dict[str, object]:
    response = load_canonical_bytes(response_raw, label="worker response")
    expected = {
        "accepted_evidence_count",
        "accepted_fixture_count",
        "challenge",
        "error",
        "execution_id",
        "protocol_version",
        "release_status",
        "request_id",
        "request_sha256",
        "status",
    }
    if not isinstance(response, dict) or set(response) != expected:
        raise ValidationError("worker response: closed member set mismatch")
    if response["challenge"] != challenge:
        raise ValidationError("worker response: challenge mismatch (possible output reuse)")
    if response["request_sha256"] != sha256_bytes(request_raw):
        raise ValidationError("worker response: request digest mismatch")
    if response["request_id"] != request["request_id"]:
        raise ValidationError("worker response: request_id mismatch")
    if response["protocol_version"] != PROTOCOL_VERSION:
        raise ValidationError("worker response: protocol version mismatch")
    if (
        type(response["accepted_fixture_count"]) is not int
        or response["accepted_fixture_count"] != 0
        or type(response["accepted_evidence_count"]) is not int
        or response["accepted_evidence_count"] != 0
    ):
        raise ValidationError("worker response: forbidden evidence promotion")
    if response["release_status"] != "release-blocked" or response["status"] != "refused":
        raise ValidationError("worker response: scaffold may only refuse")
    error = response["error"]
    if (
        not isinstance(error, dict)
        or set(error) != {"code", "detail"}
        or not isinstance(error["code"], str)
        or not error["code"]
        or not isinstance(error["detail"], str)
        or not error["detail"]
    ):
        raise ValidationError("worker response: invalid error object")
    for key in ("challenge", "execution_id", "request_sha256"):
        value = response[key]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValidationError(f"worker response: invalid {key}")
    return response


def invoke_worker(request: dict[str, object], raw: bytes) -> subprocess.CompletedProcess[bytes]:
    challenge = secrets.token_hex(32)
    envelope = {
        "challenge": challenge,
        "operation": request["operation"],
        "parent_pid": os.getpid(),
        "request_id": request["request_id"],
        "request_sha256": sha256_bytes(raw),
        "suite_id": request["suite_id"],
    }
    with tempfile.TemporaryDirectory(prefix="dcrypt-clean-room-ref-") as tmp:
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(WORKER)],
            input=canonical_bytes(envelope),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=tmp,
            env=sanitized_environment(tmp),
            check=False,
            timeout=15,
        )
    validate_worker_response(
        completed.stdout,
        request=request,
        request_raw=raw,
        challenge=challenge,
    )
    sys.stdout.buffer.write(completed.stdout)
    return completed


def main() -> int:
    args = parser().parse_args()
    try:
        raw = read_request(args.request)
        request = validate_request(load_canonical_bytes(raw, label="request"))
        completed = invoke_worker(request, raw)
    except (OSError, subprocess.SubprocessError, ValidationError) as exc:
        print(f"clean-room scaffold refusal: {exc}", file=sys.stderr)
        return 3
    if completed.stderr:
        print("clean-room scaffold refusal: worker emitted stderr", file=sys.stderr)
        return 3
    # No worker response can be release-unblocking evidence in scaffold v1.
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
