#!/usr/bin/env python3
"""Shared, non-cryptographic validation helpers for the blocked scaffold."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


PROTOCOL_VERSION = "dcrypt-clean-room-ipc/1"
SCAFFOLD_STATUS = "scaffold-only"
RELEASE_STATUS = "release-blocked"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SUITE_ID = re.compile(r"^[A-Z0-9][A-Z0-9+._/-]{0,127}$")
OPERATIONS = frozenset(
    {"status", "generate-fixture", "verify-fixture", "accept-fixture"}
)
CRYPTO_OPERATIONS = OPERATIONS - {"status"}


class ValidationError(ValueError):
    """Raised when bytes are not the one accepted canonical representation."""


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def canonical_bytes(value: Any) -> bytes:
    """Return the scaffold's canonical UTF-8 JSON form, including final LF."""
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def load_canonical_bytes(raw: bytes, *, label: str) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValidationError(f"{label}: UTF-8 BOM is forbidden")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{label}: only canonical ASCII JSON is accepted") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValidationError(f"{label}: forbidden numeric constant {token}")
            ),
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValidationError(f"{label}: malformed JSON") from exc
    if canonical_bytes(value) != raw:
        raise ValidationError(f"{label}: noncanonical JSON encoding")
    return value


def load_canonical_file(path: Path) -> Any:
    return load_canonical_bytes(path.read_bytes(), label=path.name)


def exact_keys(value: Any, expected: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label}: expected object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValidationError(f"{label}: closed member set mismatch; missing={missing} extra={extra}")
    return value


def validate_request(value: Any) -> dict[str, Any]:
    request = exact_keys(
        value,
        {"operation", "payload", "protocol_version", "request_id", "suite_id"},
        label="request",
    )
    if request["protocol_version"] != PROTOCOL_VERSION:
        raise ValidationError("request: unsupported protocol_version")
    if not isinstance(request["request_id"], str) or not REQUEST_ID.fullmatch(
        request["request_id"]
    ):
        raise ValidationError("request: invalid request_id")
    if request["operation"] not in OPERATIONS:
        raise ValidationError("request: unsupported operation")
    if request["operation"] == "status":
        if request["suite_id"] is not None or request["payload"] != {}:
            raise ValidationError("request: status requires null suite_id and empty payload")
    else:
        if not isinstance(request["suite_id"], str) or not SUITE_ID.fullmatch(
            request["suite_id"]
        ):
            raise ValidationError("request: cryptographic operation requires suite_id")
        payload = exact_keys(
            request["payload"],
            {"direction", "input_sha256"},
            label="request.payload",
        )
        if payload["direction"] not in {
            "reference-to-dcrypt",
            "dcrypt-to-reference",
        }:
            raise ValidationError("request.payload: invalid direction")
        if not isinstance(payload["input_sha256"], str) or not HEX_64.fullmatch(
            payload["input_sha256"]
        ):
            raise ValidationError("request.payload: invalid input_sha256")
    return request


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
