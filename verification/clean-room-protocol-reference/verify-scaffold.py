#!/usr/bin/env python3
"""Fail-closed verifier for the non-cryptographic clean-room scaffold."""

from __future__ import annotations

import ast
import datetime as dt
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from common import (
    ValidationError,
    load_canonical_bytes,
    load_canonical_file,
    sha256_file,
    validate_request,
)


ROOT = Path(__file__).resolve().parent
PROTOCOL_CONTRACT = (
    ROOT.parent.parent
    / "assurance"
    / "interoperability"
    / "protocol-specs"
    / "current-behavior.json"
)
JSON_FILES = {
    "backend-provenance.schema.json",
    "backend-slot.json",
    "execution-record.schema.json",
    "execution-records.json",
    "fixture.schema.json",
    "fixtures.json",
    "request.schema.json",
    "response.schema.json",
    "status.request.json",
    "suite-registry.schema.json",
    "suite-registry.json",
}
EXPECTED_FILES = JSON_FILES | {
    "ARTIFACTS.sha256",
    "README.md",
    "common.py",
    "runner.py",
    "scaffold-selftest.py",
    "verify-scaffold.py",
    "worker.py",
}
# Filled with reviewed exact bytes. The verifier itself is instead bound by
# ARTIFACTS.sha256 and the repository evidence subject.
PINNED_ARTIFACT_SHA256: dict[str, str] = {
    "README.md": "82d33e3839da1ddc9d51036ab2a6896d647672680fa193fe967152604ac22119",
    "backend-provenance.schema.json": "dc4a6de8d29680c652b4361bcc4511d46f23e3796bf508afeea54c2358068a14",
    "backend-slot.json": "ae5efd6c92e8c4ba3f065dba489a31017fb8b63bb4eb241e857f00c890e13565",
    "common.py": "46b89e7a7096d8e230107be4e4f79b82adbe7dcecd75e3275fbabd9b37dc0d0e",
    "execution-record.schema.json": "8628ecdd2007a3a72cd142378b1110fdaeb22b1f42ebe930f81c026f55476bc1",
    "execution-records.json": "e8d7baef309e81de33de5cea59cb0e8a57656e2a9d14e6d04955b1f1e7a9e627",
    "fixture.schema.json": "348262b8593fdfbc6726d21020c63f71e86b0effd10b613275d9fbc52f4fbd37",
    "fixtures.json": "62b207d056585b54e461c58c8c0a3b886733bb8f6a7ae09df3895f3b5721833c",
    "request.schema.json": "b75779d046fc06cbd1cec1366d55504ff651bf5848fd524d2e178f8f4a8cfcee",
    "response.schema.json": "4d108d84bf2484d8d8705b251624ce842d2e7b37fade71dc5daf52048263028f",
    "runner.py": "0a010a9d7270ce1440fec7310665a3bb65edacf90ac74a0e7950eb526b05b528",
    "scaffold-selftest.py": "15e4c2010ea0bad042062303aaf16a118dbe1bc0de36be375ce403e4aa011498",
    "status.request.json": "69bbc2c502591a1ebde6111d05ccd964319961f624f1084153b882020aea31af",
    "suite-registry.json": "dfba58b6321bef09ff662ba898a85ca9cca3d25be9bb8ff0e94e9a39f7aa02e2",
    "suite-registry.schema.json": "a9c8aec169c0a29c2e6e37dc11724ad18934a0cc83c0a23d9a3dbc629e0ce751",
    "worker.py": "42910cc9f6a5755aa661c1ea27b5b19f78cdd2d80da105cf6c1941e4e5968391",
}
EXPECTED_SUITES = {
    "ECIES-P224-HKDF-SHA256-CHACHA20POLY1305": ("ecies", 57, None, None, 91),
    "ECIES-P256-HKDF-SHA256-CHACHA20POLY1305": ("ecies", 65, None, None, 99),
    "ECIES-P384-HKDF-SHA384-AES256GCM": ("ecies", 97, None, None, 131),
    "ECIES-P521-HKDF-SHA512-AES256GCM": ("ecies", 133, None, None, 167),
    "ECDH-K256+ML-KEM-512": ("hybrid-kem", 33, 833, 801, None),
    "ECDH-P256+ML-KEM-512": ("hybrid-kem", 33, 833, 801, None),
    "ECDH-P256+ML-KEM-768": ("hybrid-kem", 33, 1217, 1121, None),
    "ECDH-P384+ML-KEM-1024": ("hybrid-kem", 49, 1617, 1617, None),
    "ECDH-P521+ML-KEM-1024": ("hybrid-kem", 67, 1635, 1635, None),
    "ECDSA-P384+ML-DSA-65": ("hybrid-signature", 97, 2106, None, None),
}


def die(message: str) -> None:
    raise ValidationError(message)


def verify_filesystem() -> None:
    actual: set[str] = set()
    for entry in os.scandir(ROOT):
        mode = os.lstat(entry.path).st_mode
        if stat.S_ISLNK(mode):
            die(f"symlink forbidden: {entry.name}")
        if not stat.S_ISREG(mode):
            die(f"non-regular artifact forbidden: {entry.name}")
        actual.add(entry.name)
    if actual != EXPECTED_FILES:
        die(
            f"artifact set mismatch; missing={sorted(EXPECTED_FILES-actual)} "
            f"extra={sorted(actual-EXPECTED_FILES)}"
        )


def verify_manifest() -> None:
    lines = (ROOT / "ARTIFACTS.sha256").read_text(encoding="ascii").splitlines()
    seen: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if not match:
            die("ARTIFACTS.sha256 is noncanonical")
        digest, name = match.groups()
        if name in seen or name == "ARTIFACTS.sha256":
            die("ARTIFACTS.sha256 has duplicate or self entry")
        seen[name] = digest
    expected = EXPECTED_FILES - {"ARTIFACTS.sha256"}
    if set(seen) != expected:
        die("ARTIFACTS.sha256 completeness mismatch")
    for name, digest in seen.items():
        if sha256_file(ROOT / name) != digest:
            die(f"artifact digest mismatch: {name}")
    for name, digest in PINNED_ARTIFACT_SHA256.items():
        if sha256_file(ROOT / name) != digest:
            die(f"reviewed digest mismatch: {name}")


def verify_schema_closure(schema: Any, *, path: str) -> None:
    if isinstance(schema, dict):
        declares_object = "properties" in schema
        if declares_object and schema.get("additionalProperties") is not False:
            die(f"open object schema: {path}")
        for key, value in schema.items():
            verify_schema_closure(value, path=f"{path}/{key}")
    elif isinstance(schema, list):
        for index, value in enumerate(schema):
            verify_schema_closure(value, path=f"{path}/{index}")


def parse_utc(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"invalid UTC timestamp: {value}") from exc
    if parsed.tzinfo != dt.timezone.utc or not value.endswith("Z"):
        die(f"timestamp must be UTC Z form: {value}")
    return parsed


def verify_registry(registry: dict[str, Any]) -> None:
    expected_keys = {
        "contract_binding",
        "evidence_effect",
        "expires_at_utc",
        "format_version",
        "owner",
        "release_status",
        "review_deadline_utc",
        "reviewer",
        "status",
        "suites",
    }
    if set(registry) != expected_keys:
        die("suite registry is not closed")
    binding = registry["contract_binding"]
    if binding != {
        "artifact_id": "dcrypt-package-b-current-wire-behavior-1",
        "normative_path": "assurance/interoperability/protocol-specs/current-behavior.json",
        "sha256": None,
        "status": "pending-final-seal",
    }:
        die("protocol contract must remain explicitly pending until final seal")
    expected_effect = {
        "accepted_evidence_count": 0,
        "accepted_fixture_count": 0,
        "counts_as_interoperability_evidence": False,
        "counts_as_release_unblocking_evidence": False,
    }
    if json.dumps(registry["evidence_effect"], sort_keys=True) != json.dumps(
        expected_effect, sort_keys=True
    ):
        die("suite registry attempted evidence promotion")
    if registry["format_version"] != 1 or registry["status"] != "scaffold-only":
        die("suite registry is not scaffold-only")
    if registry["release_status"] != "release-blocked":
        die("suite registry is not release-blocked")
    if registry["owner"] == registry["reviewer"]:
        die("suite registry owner and reviewer must differ")
    if parse_utc(registry["review_deadline_utc"]) >= parse_utc(registry["expires_at_utc"]):
        die("suite registry review deadline must precede expiry")
    suites = registry["suites"]
    if not isinstance(suites, list) or len(suites) != len(EXPECTED_SUITES):
        die("suite registry inventory mismatch")
    observed: dict[str, tuple[Any, ...]] = {}
    for suite in suites:
        if set(suite) != {
            "byte_order",
            "dimensions",
            "family",
            "status",
            "suite_id",
            "version_id",
        }:
            die("suite entry is not closed")
        if suite["byte_order"] != "big-endian-explicit-lengths":
            die("suite byte order changed")
        if suite["status"] != "unreviewed-contract-copy":
            die("suite entry attempted promotion")
        dimensions = suite["dimensions"]
        if set(dimensions) != {
            "ciphertext_bytes",
            "ciphertext_overhead_bytes",
            "framing_formula",
            "nonce_bytes",
            "point_bytes",
            "public_key_bytes",
            "secret_key_bytes",
            "signature_bytes",
            "tag_bytes",
        }:
            die("suite dimensions are not closed")
        observed[suite["suite_id"]] = (
            suite["family"],
            dimensions["point_bytes"],
            dimensions["public_key_bytes"],
            dimensions["ciphertext_bytes"],
            dimensions["ciphertext_overhead_bytes"],
        )
    if observed != EXPECTED_SUITES:
        die("suite IDs or framing dimensions changed")


def verify_empty_state(name: str, value: dict[str, Any], collection: str) -> None:
    expected = {
        "accepted_evidence_count": 0,
        "accepted_fixture_count": 0,
        "format_version": 1,
        collection: [],
        "release_status": "release-blocked",
        "status": "scaffold-only",
    }
    if json.dumps(value, sort_keys=True) != json.dumps(expected, sort_keys=True):
        die(f"{name} must contain zero accepted fixtures/evidence")


def verify_backend_slot(slot: dict[str, Any]) -> None:
    if set(slot) != {
        "approvals",
        "backend",
        "dossier_id",
        "expires_at_utc",
        "format_version",
        "owner",
        "review_deadline_utc",
        "reviewer",
        "status",
    }:
        die("backend slot is not closed")
    if (
        slot["status"] != "not-installed"
        or slot["backend"] is not None
        or slot["approvals"] != []
    ):
        die("no clean-room backend is approved or installed")
    if slot["owner"] == slot["reviewer"]:
        die("backend owner and reviewer must differ")
    if parse_utc(slot["review_deadline_utc"]) >= parse_utc(slot["expires_at_utc"]):
        die("backend review deadline must precede expiry")


def verify_python_boundaries() -> None:
    for name in ("common.py", "runner.py", "verify-scaffold.py", "worker.py"):
        tree = ast.parse((ROOT / name).read_text(encoding="utf-8"), filename=name)
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            for module in modules:
                if module == "dcrypt" or module.startswith("dcrypt."):
                    die(f"forbidden implementation import in {name}")
    runner_text = (ROOT / "runner.py").read_text(encoding="utf-8")
    if "APPROVED_BACKEND_DOSSIER_SHA256: frozenset[str] = frozenset()" not in runner_text:
        die("backend digest allowlist is not provably empty")
    if "PINNED_PROTOCOL_CONTRACT_SHA256: frozenset[str] = frozenset()" not in runner_text:
        die("protocol contract digest allowlist is not provably empty")
    forbidden = ("../crates/", "path =", "Cargo.toml", "git+file:")
    for name in ("backend-slot.json", "fixtures.json", "execution-records.json"):
        raw = (ROOT / name).read_text(encoding="ascii")
        if any(token in raw for token in forbidden):
            die(f"local implementation source/path dependency in {name}")


def verify_runtime_probe(request_raw: bytes) -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "runner.py"), "--request", str(ROOT / "status.request.json")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ROOT,
        check=False,
        timeout=20,
    )
    if completed.returncode != 3 or completed.stderr:
        die("status runner did not fail closed with exit 3")
    response = load_canonical_bytes(completed.stdout, label="status response")
    if response.get("error", {}).get("code") != "scaffold-only":
        die("status runner did not report scaffold-only")
    if response.get("request_sha256") != __import__("hashlib").sha256(request_raw).hexdigest():
        die("status runner did not bind exact request bytes")


def main() -> int:
    try:
        verify_filesystem()
        data = {name: load_canonical_file(ROOT / name) for name in JSON_FILES}
        for name in sorted(name for name in JSON_FILES if name.endswith("schema.json")):
            verify_schema_closure(data[name], path=name)
        request_raw = (ROOT / "status.request.json").read_bytes()
        validate_request(data["status.request.json"])
        verify_registry(data["suite-registry.json"])
        verify_backend_slot(data["backend-slot.json"])
        verify_empty_state("fixtures.json", data["fixtures.json"], "fixtures")
        verify_empty_state(
            "execution-records.json", data["execution-records.json"], "records"
        )
        verify_python_boundaries()
        verify_manifest()
        verify_runtime_probe(request_raw)
    except (OSError, subprocess.SubprocessError, ValidationError) as exc:
        print(f"clean-room scaffold verification failed: {exc}", file=sys.stderr)
        return 1
    print(
        "clean-room scaffold verified: suites=10 accepted_fixtures=0 "
        "accepted_evidence=0 status=scaffold-only release=blocked contract=pending"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
