#!/usr/bin/env python3
"""Fail-closed verifier for the non-cryptographic clean-room scaffold."""

from __future__ import annotations

import ast
import copy
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
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
PROTOCOL_RELATIVE_PATH = PurePosixPath(
    "assurance/interoperability/protocol-specs/current-behavior.json"
)
EXPECTED_REVIEWED_SOURCE_COMMIT = "f00be3676dd01643c46a51b2c56be01159ee4796"
EXPECTED_REVIEWED_SOURCE_TREE = "8bc8826d8b0340557c25c526db54a35601ad0924"
EXPECTED_REVIEWED_SOURCE_BLOB_OID = "df50ccdcab03e3e5a8e3f734391268ef18180221"
EXPECTED_REVIEWED_SOURCE_SHA256 = (
    "07c79d695b906a0cd7a7be4f10f473c0414438390f3d0bdc18c2e9017d6b6035"
)
EXPECTED_PROTOCOL_SEMANTIC_PROJECTION_SHA256 = (
    "37b0ecf19b57cf4c526af6bcfbbbf51a3f6bfe034dd19e50a0040fd8742c8eff"
)
SUBJECT_ROOT_FILES = [
    "Cargo.lock",
    "Cargo.toml",
    "CONSTANT_TIME_POLICY.md",
    "README.md",
    "SECURITY.md",
    "deny.toml",
    "implementation-boundary.toml",
]
SUBJECT_ABSENT_BUILD_INPUTS = [
    ".cargo/config",
    ".cargo/config.toml",
    "build.rs",
    "rust-toolchain",
    "rust-toolchain.toml",
]
SUBJECT_INCLUDE_POLICY = "production-and-evidence-v1"
SUBJECT_EXCLUDED_FILES = {
    ".gitignore",
    "tools/bench-processor/Cargo.lock",
    "tools/cargo_snapshot.sh",
    "tools/codebase_snapshot.sh",
    "tools/codebase_snapshot2.sh",
    "tools/tree.sh",
}
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
    "README.md": "4d0e62b022c32223d1d54be28abc363d574ffb73bc4305ff605a789ceb473460",
    "backend-provenance.schema.json": "dc4a6de8d29680c652b4361bcc4511d46f23e3796bf508afeea54c2358068a14",
    "backend-slot.json": "ae5efd6c92e8c4ba3f065dba489a31017fb8b63bb4eb241e857f00c890e13565",
    "common.py": "46b89e7a7096d8e230107be4e4f79b82adbe7dcecd75e3275fbabd9b37dc0d0e",
    "execution-record.schema.json": "8628ecdd2007a3a72cd142378b1110fdaeb22b1f42ebe930f81c026f55476bc1",
    "execution-records.json": "e8d7baef309e81de33de5cea59cb0e8a57656e2a9d14e6d04955b1f1e7a9e627",
    "fixture.schema.json": "348262b8593fdfbc6726d21020c63f71e86b0effd10b613275d9fbc52f4fbd37",
    "fixtures.json": "62b207d056585b54e461c58c8c0a3b886733bb8f6a7ae09df3895f3b5721833c",
    "request.schema.json": "b75779d046fc06cbd1cec1366d55504ff651bf5848fd524d2e178f8f4a8cfcee",
    "response.schema.json": "4d108d84bf2484d8d8705b251624ce842d2e7b37fade71dc5daf52048263028f",
    "runner.py": "9a63e400590ccccf26dbceb7c53c5af9ef0d8af5af00f98ae50653139379d213",
    "scaffold-selftest.py": "f56fa3c0516f360e0e7f824e5ac4b53e330bb2629f1ebe5497ef6184ddc2983c",
    "status.request.json": "69bbc2c502591a1ebde6111d05ccd964319961f624f1084153b882020aea31af",
    "suite-registry.json": "ec5c76171eae490d23e57ba520c09882868ea4d76c7169da7bb6c4b0298f032a",
    "suite-registry.schema.json": "93d29fb38433b059ab636ab3eae6e66c880021c44c11870fea36a922ad835f13",
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
        metadata = os.lstat(entry.path)
        mode = metadata.st_mode
        if stat.S_ISLNK(mode):
            die(f"symlink forbidden: {entry.name}")
        if not stat.S_ISREG(mode):
            die(f"non-regular artifact forbidden: {entry.name}")
        if metadata.st_nlink != 1:
            die(f"hardlinked artifact forbidden: {entry.name}")
        if mode & 0o111:
            die(f"executable artifact forbidden: {entry.name}")
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
        "final_subject_rebind_status": "verified-at-runtime-not-asserted",
        "normative_path": PROTOCOL_RELATIVE_PATH.as_posix(),
        "reviewed_source_blob_oid": EXPECTED_REVIEWED_SOURCE_BLOB_OID,
        "reviewed_source_commit": EXPECTED_REVIEWED_SOURCE_COMMIT,
        "reviewed_source_sha256": EXPECTED_REVIEWED_SOURCE_SHA256,
        "reviewed_source_tree": EXPECTED_REVIEWED_SOURCE_TREE,
        "semantic_projection_sha256": EXPECTED_PROTOCOL_SEMANTIC_PROJECTION_SHA256,
        "source_package_review_status": "independently-reviewed-go",
        "status": "immutable-source-package-reviewed",
        "working_copy_policy": "interim-or-reviewed-final-subject-rebind",
    }:
        die("immutable protocol source binding changed")
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
        if suite["status"] != "reviewed-source-contract-copy-no-evidence":
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


def run_git(repo_root: Path, arguments: list[str], *, binary: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=not binary,
        timeout=20,
    )


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            die(f"protocol contract has duplicate JSON member: {key}")
        value[key] = item
    return value


def protocol_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        text_value = raw.decode("utf-8")
        value = json.loads(text_value, object_pairs_hook=reject_duplicate_members)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label} is not valid canonical UTF-8 JSON") from exc
    if not isinstance(value, dict):
        die(f"{label} root is not an object")
    canonical = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if raw != canonical:
        die(f"{label} is not canonical sorted-key JSON")
    return value


def protocol_semantic_projection(contract: dict[str, Any]) -> bytes:
    normalized = copy.deepcopy(contract)
    rows = normalized.get("source_bindings")
    if not isinstance(rows, list):
        die("protocol contract source_bindings is not an array")
    normalized["subject_binding"] = {"allowlisted": "subject-binding"}
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"path", "role", "sha256"}:
            die(f"protocol source binding {index} is malformed")
        path_value = row.get("path")
        if not isinstance(path_value, str) or path_value in seen:
            die(f"protocol source binding {index} has invalid or duplicate path")
        seen.add(path_value)
        row["sha256"] = "0" * 64
    return (
        json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def immutable_reviewed_contract(repo_root: Path) -> dict[str, Any]:
    commit = run_git(repo_root, ["rev-parse", f"{EXPECTED_REVIEWED_SOURCE_COMMIT}^{{commit}}"])
    if commit.returncode != 0 or commit.stdout.strip() != EXPECTED_REVIEWED_SOURCE_COMMIT:
        die("immutable reviewed protocol source commit is missing or changed")
    tree = run_git(repo_root, ["rev-parse", f"{EXPECTED_REVIEWED_SOURCE_COMMIT}^{{tree}}"])
    if tree.returncode != 0 or tree.stdout.strip() != EXPECTED_REVIEWED_SOURCE_TREE:
        die("immutable reviewed protocol source tree is missing or changed")
    listing = run_git(
        repo_root,
        [
            "ls-tree",
            "-z",
            "--full-tree",
            EXPECTED_REVIEWED_SOURCE_COMMIT,
            "--",
            PROTOCOL_RELATIVE_PATH.as_posix(),
        ],
        binary=True,
    )
    records = [record for record in listing.stdout.split(b"\0") if record]
    if listing.returncode != 0 or len(records) != 1:
        die("immutable reviewed protocol source path is missing")
    expected_record = (
        f"100644 blob {EXPECTED_REVIEWED_SOURCE_BLOB_OID}\t"
        f"{PROTOCOL_RELATIVE_PATH.as_posix()}"
    ).encode("utf-8")
    if records[0] != expected_record:
        die("immutable reviewed protocol source blob identity changed")
    blob = run_git(
        repo_root,
        ["cat-file", "blob", EXPECTED_REVIEWED_SOURCE_BLOB_OID],
        binary=True,
    )
    if blob.returncode != 0:
        die("immutable reviewed protocol source blob is missing")
    if hashlib.sha256(blob.stdout).hexdigest() != EXPECTED_REVIEWED_SOURCE_SHA256:
        die("immutable reviewed protocol source bytes changed")
    contract = protocol_json(blob.stdout, label="immutable reviewed protocol source")
    projection = hashlib.sha256(protocol_semantic_projection(contract)).hexdigest()
    if projection != EXPECTED_PROTOCOL_SEMANTIC_PROJECTION_SHA256:
        die("immutable reviewed protocol semantic projection changed")
    return contract


def validate_relative_path(path_value: str, *, label: str) -> None:
    pure = PurePosixPath(path_value)
    if (
        not path_value
        or pure.is_absolute()
        or ".." in pure.parts
        or "." in pure.parts
        or str(pure) != path_value
        or "\\" in path_value
    ):
        die(f"unsafe or noncanonical {label} path: {path_value}")


def ensure_regular_path(path: Path, repo_root: Path, *, label: str) -> None:
    try:
        relative = path.relative_to(repo_root)
    except ValueError:
        die(f"{label} escapes repository root")
    current = repo_root
    for component in relative.parts:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ValidationError(f"{label} is missing: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            die(f"{label} contains a symlink")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        die(f"{label} must be a single-link regular file")


def subject_path_included(path_value: str) -> bool:
    normalized = path_value[2:] if path_value.startswith("./") else path_value
    if normalized in SUBJECT_EXCLUDED_FILES:
        return False
    return normalized != "assurance" and not normalized.startswith("assurance/")


def git_tree_entries(repo_root: Path, commit: str) -> dict[str, tuple[str, str]]:
    result = run_git(repo_root, ["ls-tree", "-r", "-z", "--full-tree", commit, "--", "."], binary=True)
    if result.returncode != 0:
        die("final protocol subject commit tree cannot be enumerated")
    entries: dict[str, tuple[str, str]] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ")
            path_value = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            die("final protocol subject commit has malformed tree entry")
        if kind != "blob" or mode not in {"100644", "100755"}:
            die(f"final protocol subject has non-regular entry: {path_value}")
        validate_relative_path(path_value, label="subject")
        if subject_path_included(path_value):
            entries[path_value] = (mode, object_id)
    return entries


def git_blob_sha256s(repo_root: Path, object_ids: list[str]) -> dict[str, str]:
    identifiers = sorted(set(object_ids))
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=repo_root,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        die("cannot open final protocol subject blob pipes")
    result: dict[str, str] = {}
    for expected in identifiers:
        process.stdin.write((expected + "\n").encode("ascii"))
        process.stdin.flush()
        header = process.stdout.readline()
        parts = header[:-1].decode("ascii", "replace").split(" ")
        if len(parts) != 3 or parts[0] != expected or parts[1] != "blob":
            die("unexpected final protocol subject blob header")
        try:
            remaining = int(parts[2])
        except ValueError:
            die("invalid final protocol subject blob size")
        digest = hashlib.sha256()
        while remaining:
            block = process.stdout.read(min(1024 * 1024, remaining))
            if not block:
                die("truncated final protocol subject blob")
            digest.update(block)
            remaining -= len(block)
        if process.stdout.read(1) != b"\n":
            die("invalid final protocol subject blob delimiter")
        result[expected] = digest.hexdigest()
    process.stdin.close()
    if process.stdout.read(1) != b"":
        die("trailing final protocol subject blob output")
    stderr = process.stderr.read()
    if process.wait() != 0:
        die("cannot read final protocol subject blobs: " + stderr.decode("utf-8", "replace"))
    return result


def verify_current_subject(
    repo_root: Path,
    declared: dict[str, tuple[str, str]],
    *,
    bound_commit: str,
) -> None:
    declared_paths = set(declared)
    staged = run_git(
        repo_root,
        ["ls-files", "--stage", "-z", "--", "."],
        binary=True,
    )
    if staged.returncode != 0:
        die("protocol subject index cannot be enumerated")
    index: dict[str, tuple[str, str]] = {}
    for record in staged.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split(" ")
            path_value = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            die("protocol subject index has a malformed entry")
        if not subject_path_included(path_value):
            continue
        validate_relative_path(path_value, label="index subject")
        if stage != "0":
            die(f"protocol subject index has an unmerged entry: {path_value}")
        if path_value in index:
            die(f"protocol subject index has a duplicate entry: {path_value}")
        if mode not in {"100644", "100755"}:
            die(f"protocol subject index has a non-regular mode: {path_value}")
        if re.fullmatch(r"[0-9a-f]{40}", object_id) is None or object_id == "0" * 40:
            die(f"protocol subject index has an invalid or intent-to-add object: {path_value}")
        index[path_value] = (mode, object_id)
    if set(index) != declared_paths:
        die(
            "protocol subject index path set differs from the bound Git subject: "
            f"new={sorted(set(index) - declared_paths)} "
            f"removed={sorted(declared_paths - set(index))}"
        )

    flags = run_git(
        repo_root,
        ["ls-files", "-v", "-z", "--cached", "--", "."],
        binary=True,
    )
    if flags.returncode != 0:
        die("protocol subject index flags cannot be enumerated")
    flag_by_path: dict[str, str] = {}
    for record in flags.stdout.split(b"\0"):
        if not record:
            continue
        try:
            flag_bytes, raw_path = record.split(b" ", 1)
            flag = flag_bytes.decode("ascii")
            path_value = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            die("protocol subject index has malformed cache flags")
        if not subject_path_included(path_value):
            continue
        validate_relative_path(path_value, label="flagged index subject")
        if len(flag) != 1 or path_value in flag_by_path:
            die("protocol subject index has malformed or duplicate cache flags")
        flag_by_path[path_value] = flag
    if set(flag_by_path) != declared_paths:
        die("protocol subject index flag inventory differs from its stage inventory")
    for path_value, flag in flag_by_path.items():
        # `git ls-files -v` reports an ordinary stage-0 entry as H, skip-worktree
        # as S, and uses lower-case for assume-unchanged. No hidden cache state is
        # accepted for a release subject.
        if flag != "H":
            die(f"protocol subject index has a forbidden cache flag {flag}: {path_value}")

    staged_delta = run_git(
        repo_root,
        ["diff", "--cached", "--name-only", "-z", bound_commit, "--", "."],
        binary=True,
    )
    if staged_delta.returncode != 0:
        die("protocol subject staged semantic state cannot be compared")
    try:
        staged_delta_paths = sorted(
            raw.decode("utf-8")
            for raw in staged_delta.stdout.split(b"\0")
            if raw and subject_path_included(raw.decode("utf-8"))
        )
    except UnicodeDecodeError:
        die("protocol subject staged semantic state has a non-UTF-8 path")
    if staged_delta_paths:
        die(
            "protocol subject index has staged semantic drift: "
            f"{staged_delta_paths}"
        )

    index_digests = git_blob_sha256s(
        repo_root, [object_id for _mode, object_id in index.values()]
    )
    for path_value, (expected_digest, expected_mode) in declared.items():
        index_mode, object_id = index[path_value]
        if index_mode != expected_mode or index_digests.get(object_id) != expected_digest:
            die(f"protocol subject index differs from the bound Git subject: {path_value}")

    listing = run_git(
        repo_root,
        ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "."],
        binary=True,
    )
    if listing.returncode != 0:
        die("current protocol subject paths cannot be enumerated")
    try:
        current = {
            raw.decode("utf-8")
            for raw in listing.stdout.split(b"\0")
            if raw and subject_path_included(raw.decode("utf-8"))
        }
    except UnicodeDecodeError:
        die("current protocol subject has a non-UTF-8 path")
    if current != declared_paths:
        die(
            "current protocol subject path set differs from the bound Git subject: "
            f"new={sorted(current - declared_paths)} "
            f"removed={sorted(declared_paths - current)}"
        )
    for path_value, (expected_digest, expected_mode) in declared.items():
        path = repo_root / path_value
        ensure_regular_path(path, repo_root, label=f"current protocol subject {path_value}")
        if sha256_file(path) != expected_digest:
            die(f"current protocol subject digest mismatch: {path_value}")
        executable = bool(path.lstat().st_mode & 0o111)
        if executable != (expected_mode == "100755"):
            die(f"current protocol subject mode mismatch: {path_value}")


def verify_final_subject_binding(
    contract: dict[str, Any], repo_root: Path
) -> dict[str, str]:
    binding = contract.get("subject_binding")
    expected_keys = {
        "binding_stage",
        "curated_operations_path",
        "curated_operations_sha256",
        "final_rebind_required",
        "manifest_file_count",
        "manifest_include_policy",
        "source_commit",
        "source_tree",
        "subject_manifest_path",
        "subject_manifest_sha256",
    }
    if not isinstance(binding, dict) or set(binding) != expected_keys:
        die("protocol subject binding shape changed")
    if (
        binding["binding_stage"] != "final-subject-candidate-review-required"
        or binding["final_rebind_required"] is not False
        or binding["curated_operations_path"] != "assurance/curated-operations.toml"
        or binding["subject_manifest_path"] != "assurance/subject-manifest.json"
        or binding["manifest_include_policy"] != SUBJECT_INCLUDE_POLICY
        or type(binding["manifest_file_count"]) is not int
        or binding["manifest_file_count"] < 1
    ):
        die("protocol final subject binding is not a reviewed rebind shape")
    for key, length in (
        ("source_commit", 40),
        ("source_tree", 40),
        ("curated_operations_sha256", 64),
        ("subject_manifest_sha256", 64),
    ):
        value = binding[key]
        if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None:
            die(f"protocol final subject binding has invalid {key}")
    resolved = run_git(repo_root, ["rev-parse", f"{binding['source_commit']}^{{tree}}"])
    if resolved.returncode != 0 or resolved.stdout.strip() != binding["source_tree"]:
        die("protocol final subject commit/tree binding is invalid")
    manifest_path = repo_root / binding["subject_manifest_path"]
    curated_path = repo_root / binding["curated_operations_path"]
    ensure_regular_path(manifest_path, repo_root, label="protocol subject manifest")
    ensure_regular_path(curated_path, repo_root, label="protocol curated operations")
    if sha256_file(manifest_path) != binding["subject_manifest_sha256"]:
        die("protocol final subject manifest digest mismatch")
    if sha256_file(curated_path) != binding["curated_operations_sha256"]:
        die("protocol final curated operations digest mismatch")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_members)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("protocol final subject manifest is invalid JSON") from exc
    expected_root_keys = [
        "schema_version",
        "source_commit",
        "source_tree",
        "roots",
        "root_files",
        "absent_build_inputs",
        "include_policy",
        "files",
    ]
    if not isinstance(manifest, dict) or list(manifest) != expected_root_keys:
        die("protocol final subject manifest shape changed")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("source_commit") != binding["source_commit"]
        or manifest.get("source_tree") != binding["source_tree"]
        or manifest.get("roots") != ["."]
        or manifest.get("root_files") != SUBJECT_ROOT_FILES
        or manifest.get("absent_build_inputs") != SUBJECT_ABSENT_BUILD_INPUTS
        or manifest.get("include_policy") != SUBJECT_INCLUDE_POLICY
    ):
        die("protocol final subject manifest provenance or scope changed")
    canonical_manifest = (
        json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=False) + "\n"
    ).encode("utf-8")
    if manifest_path.read_bytes() != canonical_manifest:
        die("protocol final subject manifest is noncanonical")
    committed = git_tree_entries(repo_root, binding["source_commit"])
    bound_absent_inputs = sorted(set(SUBJECT_ABSENT_BUILD_INPUTS) & set(committed))
    if bound_absent_inputs:
        die(
            "protocol final subject contains declared-absent build inputs: "
            f"{bound_absent_inputs}"
        )
    current_absent_inputs = [
        path_value
        for path_value in SUBJECT_ABSENT_BUILD_INPUTS
        if os.path.lexists(repo_root / path_value)
    ]
    if current_absent_inputs:
        die(
            "current protocol subject contains declared-absent build inputs: "
            f"{current_absent_inputs}"
        )
    rows = manifest.get("files")
    if not isinstance(rows, list) or len(rows) != binding["manifest_file_count"]:
        die("protocol final subject manifest row count changed")
    declared: dict[str, tuple[str, str]] = {}
    ordered: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or list(row) != ["path", "sha256", "git_mode"]:
            die(f"protocol final subject manifest row {index} shape changed")
        path_value, digest, mode = row.get("path"), row.get("sha256"), row.get("git_mode")
        if not isinstance(path_value, str):
            die(f"protocol final subject manifest row {index} path invalid")
        validate_relative_path(path_value, label="subject manifest")
        if (
            not subject_path_included(path_value)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or mode not in {"100644", "100755"}
            or path_value in declared
        ):
            die(f"protocol final subject manifest row {index} invalid")
        declared[path_value] = (digest, mode)
        ordered.append(path_value)
    if ordered != sorted(ordered) or set(declared) != set(committed):
        die("protocol final subject manifest does not enumerate the exact Git subject")
    blob_digests = git_blob_sha256s(
        repo_root, [object_id for _mode, object_id in committed.values()]
    )
    digests: dict[str, str] = {}
    for path_value, (digest, mode) in declared.items():
        commit_mode, object_id = committed[path_value]
        if mode != commit_mode or blob_digests.get(object_id) != digest:
            die(f"protocol final subject manifest differs from Git blob: {path_value}")
        digests[path_value] = digest
    verify_current_subject(
        repo_root,
        declared,
        bound_commit=binding["source_commit"],
    )
    return digests


def verify_protocol_contract(registry: dict[str, Any], repo_root: Path) -> str:
    reviewed = immutable_reviewed_contract(repo_root)
    protocol_path = repo_root / PROTOCOL_RELATIVE_PATH
    ensure_regular_path(protocol_path, repo_root, label="working protocol contract")
    current = protocol_json(protocol_path.read_bytes(), label="working protocol contract")
    projection = hashlib.sha256(protocol_semantic_projection(current)).hexdigest()
    if projection != EXPECTED_PROTOCOL_SEMANTIC_PROJECTION_SHA256:
        die("working protocol semantic projection differs from reviewed source")
    binding = registry["contract_binding"]
    if binding["semantic_projection_sha256"] != projection:
        die("suite registry semantic projection binding changed")
    if current.get("artifact_id") != binding["artifact_id"] or current.get("format_version") != 1:
        die("working protocol contract identity changed")
    subject = current.get("subject_binding")
    stage = subject.get("binding_stage") if isinstance(subject, dict) else None
    if stage == "interim-rebind-required":
        if subject != reviewed.get("subject_binding"):
            die("working interim protocol subject binding differs from reviewed source")
        if current.get("source_bindings") != reviewed.get("source_bindings"):
            die("working interim protocol source bindings differ from reviewed source")
        return "interim"
    if stage != "final-subject-candidate-review-required":
        die("working protocol subject binding stage is not allowlisted")
    subject_rows = verify_final_subject_binding(current, repo_root)
    reviewed_rows = reviewed.get("source_bindings")
    current_rows = current.get("source_bindings")
    if not isinstance(reviewed_rows, list) or not isinstance(current_rows, list) or len(reviewed_rows) != len(current_rows):
        die("working final protocol source binding inventory changed")
    for index, (old, new) in enumerate(zip(reviewed_rows, current_rows)):
        if old.get("path") != new.get("path") or old.get("role") != new.get("role"):
            die(f"working final protocol source identity or role changed at {index}")
        if new.get("sha256") != subject_rows.get(new.get("path")):
            die(f"working final protocol source digest is not final-subject-bound at {index}")
    return "final"


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
    expected_source_pin = (
        'REVIEWED_PROTOCOL_SOURCE_SHA256 = (\n'
        '    "07c79d695b906a0cd7a7be4f10f473c0414438390f3d0bdc18c2e9017d6b6035"\n'
        ")"
    )
    expected_projection_pin = (
        'REVIEWED_PROTOCOL_SEMANTIC_PROJECTION_SHA256 = (\n'
        '    "37b0ecf19b57cf4c526af6bcfbbbf51a3f6bfe034dd19e50a0040fd8742c8eff"\n'
        ")"
    )
    if expected_source_pin not in runner_text or expected_projection_pin not in runner_text:
        die("runner immutable protocol input pins changed")
    if "APPROVED_REFERENCE_SOURCE_SHA256: frozenset[str] = frozenset()" not in runner_text:
        die("reference source digest allowlist is not provably empty")
    if "APPROVED_BACKEND_DOSSIER_SHA256: frozenset[str] = frozenset()" not in runner_text:
        die("backend digest allowlist is not provably empty")
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
    stage = "unverified"
    try:
        repo_root = ROOT.parents[1]
        verify_filesystem()
        data = {name: load_canonical_file(ROOT / name) for name in JSON_FILES}
        for name in sorted(name for name in JSON_FILES if name.endswith("schema.json")):
            verify_schema_closure(data[name], path=name)
        request_raw = (ROOT / "status.request.json").read_bytes()
        validate_request(data["status.request.json"])
        verify_registry(data["suite-registry.json"])
        verify_backend_slot(data["backend-slot.json"])
        stage = verify_protocol_contract(data["suite-registry.json"], repo_root)
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
        "accepted_evidence=0 status=scaffold-only release=blocked "
        f"contract=immutable-reviewed-source working_binding={stage}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
