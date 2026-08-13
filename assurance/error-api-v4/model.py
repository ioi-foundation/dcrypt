#!/usr/bin/env python3
"""Normative, fail-closed Package E error-API migration model."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
import unicodedata
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True

FRAMEWORK = Path(__file__).resolve().parent
REPO = FRAMEWORK.parent.parent
INVENTORY = FRAMEWORK / "reviewed-inventory.toml"

A_D_COMMIT = "39fed53adc1fa256812f6157396cd75a62b8fc8d"
A_D_TREE = "0ab8a595efbff7fb857e8573e3f138ad4a8d9cb1"
S_E_COMMIT = "219ee68040fa48ae1973ba5a16ccf7f32f73657a"
S_E_TREE = "4390012075501659de01e21b24432967b5aa0c23"
R_E_COMMIT = "276b78f9b3c2aed91d2548ab9add721c434ded06"
R_E_TREE = "c47c98062c43463818bb61bd3eed75ebaf189e1d"
R_E_SUBJECT_MANIFEST_SHA256 = (
    "d48d134daa383fb12c03e45aebe3bcf16f40e2c6930e17f209e0af95f1133eb4"
)
REVIEWED_INVENTORY_SHA256 = (
    "5d2ae3900fd3517f3fb6b36d2c4fb7970e984bc8a27e919a7b99562ff601b071"
)

REMOVED_CURATED_IDS_SHA256 = (
    "207c942fb87a247fae08f45a3a84f86b6f3b3a62937ed0d627f5b76f9344461a"
)
REMOVED_ATOMIC_IDS_SHA256 = (
    "abe5e401904633e0cbfbcf1d0800400bd179086811bb087dd07f617f81737e17"
)
REMOVED_PUBLIC_IDENTITIES_SHA256 = (
    "32fcd564f80ffb7ea0638a556f237de4ad591d2e85ae942d203c505be97ccf3a"
)
REMOVED_PUBLIC_RECORDS_SHA256 = (
    "70970b905e0e61232d4abc8b4c1a522dd350a556e7a1002e9efb1f902a1c77b8"
)
POST_CURATED_IDS_SHA256 = (
    "37a8d4b0eab59494c31f99cc6241974c6a04bc59c7bdef4e0e961947f1b5f264"
)
POST_EXPANDED_CURATED_IDS_SHA256 = (
    "4e7087153cbb40dcb331138b3ea999fe196533a0437cc77efa1af1754eb34af3"
)
POST_ALL_ATOMIC_IDS_SHA256 = (
    "ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff"
)
POST_PUBLIC_IDENTITIES_SHA256 = (
    "f8570cbda3504733e9545172fa4c01e6c9b32879f5cdb7e139c87452de71caba"
)
A_D_ALL_PUBLIC_IDENTITIES_SHA256 = (
    "da0b8f46f99e2f07deddef80f22fe419174522477d4a2c653af851e2bad1c4f4"
)
RETAINED_OTHER_TRANSITIONAL_SHA256 = (
    "7e9f22ac2cf35b4e325d4589971e4a78b7544186b97e1950693d1cd4a28592a6"
)
RETAINED_TOMBSTONES_SHA256 = (
    "e4e57254f0733f5bec758bdaf5f8e2b401ede1bed7b0d132d1ed90418ece7559"
)

BASELINE_FILE_HASHES = {
    "assurance/atomic-operations.toml":
        "1177eea6ff7fb48b8e3b7fc49f83da47d50949b724711331f4faf25311b56c3c",
    "assurance/curated-operations.toml":
        "5e2b8cf7de029ff79bda08c0709d6c14b58b2ee655ef44966ef0a0a876ab21f4",
    "assurance/public-api-snapshot.json":
        "9b0cadc30f7dd922e127b04251015136330d9883b6ee00e7ebcca32140595540",
    "assurance/subject-manifest.json":
        "12a8ddb037816e802640e921a7012e28a638943dba38eceed6f3ef0cf5465d5b",
}

EXPECTED_COUNTS = {
    "baseline-curated-source-rows": 314,
    "baseline-expanded-curated-rows": 666,
    "baseline-unreviewed-gaps": 8_632,
    "baseline-total-atomic-rows": 9_298,
    "baseline-public-identities": 19_021,
    "baseline-transitional-public-identities": 254,
    "post-curated-source-rows": 283,
    "post-expanded-curated-rows": 566,
    "post-canonical-expanded-rows": 283,
    "post-alias-expanded-rows": 283,
    "post-unreviewed-gaps": 8_632,
    "post-total-atomic-rows": 9_198,
    "post-public-identities": 18_891,
    "post-production-rust-sources": 255,
    "post-critical-fuzz-rows": 372,
    "post-explicit-fuzz-blockers": 8_826,
    "post-release-blocked-rows": 9_198,
    "retained-other-transitional-public-identities": 124,
    "removed-curated-source-rows": 31,
    "removed-expanded-atomic-rows": 100,
    "removed-public-identities": 130,
    "interop-curated-operation-rows": 552,
    "interop-operation-atoms": 6_184,
    "interop-curated-metadata-rows": 14,
    "interop-metadata-atoms": 56,
    "interop-generated-matrix-rows": 6_240,
    "interop-blockers": 14_816,
    "ledger-blockers": 9_198,
}

ROLE_CAPS = {
    "downstream-migration-candidate": {
        "files": 16, "per_file": 16_777_216, "total": 67_108_864,
    },
    "external-review-candidate": {
        "files": 32, "per_file": 16_777_216, "total": 67_108_864,
    },
}

PUBLIC_IDENTITY_FIELDS = ("package", "path", "unit", "kind", "canonical")
PUBLIC_RECORD_FIELDS = (*PUBLIC_IDENTITY_FIELDS, "classification", "operation_refs")
TOMBSTONE_PATHS = (
    "dcrypt::api::error::registry",
    "dcrypt::api::error::traits",
    "dcrypt_api::error::registry",
    "dcrypt_api::error::traits",
)
REMOVED_SOURCE_TOKENS = (
    "ConstantTimeResult",
    "ERROR_REGISTRY",
    "ErrorRegistry",
    "ErrorRegistryExt",
    "ResultExt",
    "SecureErrorHandling",
    "SymmetricResultExt",
    "ct_is_err",
    "ct_is_ok",
    "ct_map",
    "map_io_err",
    "map_primitive_err",
    "secure_unwrap",
    "unwrap_or_record_with",
    "wrap_err",
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class PackageEError(RuntimeError):
    """A reviewed Package E invariant failed closed."""


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def canonical_set_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _reject_float(_value: str) -> float:
    raise ValueError("JSON floats are forbidden")


def _reject_constant(_value: str) -> None:
    raise ValueError("nonfinite JSON values are forbidden")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _assert_nfc(value: Any, *, label: str) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise PackageEError(f"{label} contains a non-NFC string")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_nfc(item, label=f"{label}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _assert_nfc(key, label=f"{label} key")
            _assert_nfc(item, label=f"{label}.{key}")


def parse_json_strict(
    raw: bytes, *, label: str, require_canonical: bool = False
) -> Any:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise PackageEError(f"{label} is not strict JSON: {error}") from error
    _assert_nfc(value, label=label)
    if require_canonical and canonical_json(value) != raw:
        raise PackageEError(f"{label} is not canonical JSON")
    return value


def parse_toml_strict(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise PackageEError(f"{label} is not strict TOML: {error}") from error
    if not isinstance(value, dict):
        raise PackageEError(f"{label} root is not a table")
    _assert_nfc(value, label=label)
    return value


def read_regular_once(
    path: Path, *, label: str, maximum: int = 1 << 30
) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as error:
        raise PackageEError(f"cannot stat {label}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_mode & 0o7000
        or stat.S_IMODE(before.st_mode) & 0o002
        or before.st_size < 0
        or before.st_size > maximum
    ):
        raise PackageEError(f"{label} is not a bounded safe single-link regular file")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        identity = (
            before.st_dev, before.st_ino, before.st_uid, before.st_gid,
            before.st_mode, before.st_nlink, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        )
        observed = (
            opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid,
            opened.st_mode, opened.st_nlink, opened.st_size,
            opened.st_mtime_ns, opened.st_ctime_ns,
        )
        if observed != identity:
            raise PackageEError(f"{label} changed before descriptor read")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                raise PackageEError(f"{label} was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) != b"":
            raise PackageEError(f"{label} grew during descriptor read")
        after = os.fstat(descriptor)
        final = (
            after.st_dev, after.st_ino, after.st_uid, after.st_gid,
            after.st_mode, after.st_nlink, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        )
        if final != identity:
            raise PackageEError(f"{label} changed during descriptor read")
        return b"".join(chunks), before
    except OSError as error:
        raise PackageEError(f"cannot read {label}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _safe_relative(value: str, *, label: str) -> str:
    pure = PurePosixPath(value)
    if (
        not isinstance(value, str)
        or not value
        or pure.is_absolute()
        or pure.as_posix() != value
        or "." in pure.parts
        or ".." in pure.parts
        or "\\" in value
        or ".git" in pure.parts
    ):
        raise PackageEError(f"{label} is not a canonical relative path")
    return value


def safe_relative_path(value: str, *, label: str) -> str:
    return _safe_relative(value, label=label)


def _git_blob(commit: str, path: str) -> bytes:
    if HEX40.fullmatch(commit) is None:
        raise PackageEError("baseline commit identity is malformed")
    _safe_relative(path, label="baseline Git path")
    result = subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=REPO,
        capture_output=True,
        timeout=30,
        env={
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "TZ": "UTC",
        },
    )
    if result.returncode != 0:
        raise PackageEError(f"cannot read reviewed baseline Git blob {path}")
    return result.stdout


def _git_text(arguments: list[str]) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=30,
        env={
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "TZ": "UTC",
        },
    )
    if result.returncode != 0:
        raise PackageEError("cannot inspect reviewed Git topology")
    return result.stdout.strip()


def public_identity(record: dict[str, Any]) -> list[str]:
    if not isinstance(record, dict):
        raise PackageEError("public API record is not an object")
    values: list[str] = []
    for field in PUBLIC_IDENTITY_FIELDS:
        value = record.get(field)
        if not isinstance(value, str) or not value:
            raise PackageEError(f"public API record lacks exact {field}")
        values.append(value)
    return values


def _public_record(record: dict[str, Any]) -> dict[str, Any]:
    identity = public_identity(record)
    classification = record.get("classification")
    operation_refs = record.get("operation_refs")
    if (
        not isinstance(classification, str)
        or not classification
        or not isinstance(operation_refs, list)
        or any(not isinstance(value, str) or not value for value in operation_refs)
        or operation_refs != sorted(set(operation_refs))
    ):
        raise PackageEError("public API classification/reference record differs")
    return {
        **dict(zip(PUBLIC_IDENTITY_FIELDS, identity, strict=True)),
        "classification": classification,
        "operation_refs": operation_refs,
    }


def _sorted_identities(records: list[dict[str, Any]]) -> list[list[str]]:
    identities = sorted(public_identity(record) for record in records)
    if len(identities) != len({tuple(value) for value in identities}):
        raise PackageEError("public API identity closure contains duplicates")
    return identities


def _sorted_public_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = [_public_record(record) for record in records]
    selected.sort(key=lambda row: tuple(str(row[field]) for field in PUBLIC_IDENTITY_FIELDS))
    if len(selected) != len({tuple(row[field] for field in PUBLIC_IDENTITY_FIELDS) for row in selected}):
        raise PackageEError("public API record closure contains duplicates")
    return selected


def load_reviewed_inventory() -> tuple[dict[str, Any], bytes]:
    raw, _metadata = read_regular_once(
        INVENTORY, label="Package E reviewed inventory", maximum=1 << 20
    )
    if sha256_bytes(raw) != REVIEWED_INVENTORY_SHA256:
        raise PackageEError("reviewed inventory differs from the model-pinned authority")
    inventory = parse_toml_strict(raw, label="Package E reviewed inventory")
    expected_keys = {
        "a-d-all-public-identities-sha256", "a-d-atomic-file-sha256",
        "a-d-commit", "a-d-curated-file-sha256", "a-d-public-snapshot-file-sha256",
        "a-d-subject-manifest-sha256", "a-d-tree", "atomic-ids", "content-policy",
        "counts", "curated-ids", "migration-fixture", "migration-guide",
        "post-all-atomic-ids-sha256", "post-curated-ids-sha256",
        "post-expanded-curated-ids-sha256", "post-public-identities-sha256",
        "promotion-eligible", "publish-eligible", "r-e-commit",
        "r-e-subject-manifest-sha256", "r-e-tree", "release-exit-code",
        "release-gate", "removed-atomic-ids-sha256", "removed-curated",
        "removed-curated-ids-sha256", "removed-public-identities",
        "removed-public-identities-sha256", "removed-public-records",
        "removed-public-records-sha256", "replacements",
        "retained-other-transitional-sha256", "retained-tombstones",
        "retained-tombstones-sha256", "s-e-commit", "s-e-tree", "schema-version",
        "status", "target-major", "version-preparation-authorized", "workspace-version",
    }
    if set(inventory) != expected_keys:
        raise PackageEError("reviewed inventory root closure differs")
    return inventory, raw


def load_public_snapshot(path: Path | None = None) -> tuple[dict[str, Any], bytes]:
    target = path or REPO / "assurance/public-api-snapshot.json"
    raw, _metadata = read_regular_once(target, label="public API snapshot")
    document = parse_json_strict(raw, label="public API snapshot")
    if not isinstance(document, dict) or not isinstance(document.get("entries"), list):
        raise PackageEError("public API snapshot root closure differs")
    return document, raw


def load_atomic_inventory(path: Path | None = None) -> tuple[dict[str, Any], bytes]:
    target = path or REPO / "assurance/atomic-operations.toml"
    raw, _metadata = read_regular_once(target, label="atomic operation inventory")
    document = parse_toml_strict(raw, label="atomic operation inventory")
    if (
        document.get("schema-version") != 2
        or not isinstance(document.get("operation"), list)
        or not isinstance(document.get("unreviewed-gap"), list)
    ):
        raise PackageEError("atomic operation inventory root closure differs")
    return document, raw


def _load_curated_inventory(path: Path | None = None) -> tuple[dict[str, Any], bytes]:
    target = path or REPO / "assurance/curated-operations.toml"
    raw, _metadata = read_regular_once(target, label="curated operation inventory")
    document = parse_toml_strict(raw, label="curated operation inventory")
    if document.get("schema-version") != 2 or not isinstance(document.get("operation"), list):
        raise PackageEError("curated operation inventory root closure differs")
    return document, raw


@lru_cache(maxsize=1)
def _baseline_documents() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    for path, digest in BASELINE_FILE_HASHES.items():
        if sha256_bytes(_git_blob(A_D_COMMIT, path)) != digest:
            raise PackageEError(f"reviewed A_D baseline blob differs: {path}")
    curated = parse_toml_strict(
        _git_blob(A_D_COMMIT, "assurance/curated-operations.toml"),
        label="A_D curated inventory",
    )
    atomic = parse_toml_strict(
        _git_blob(A_D_COMMIT, "assurance/atomic-operations.toml"),
        label="A_D atomic inventory",
    )
    snapshot = parse_json_strict(
        _git_blob(A_D_COMMIT, "assurance/public-api-snapshot.json"),
        label="A_D public API snapshot",
        require_canonical=False,
    )
    return curated, atomic, snapshot


def _row_ids(rows: Any, *, label: str) -> list[str]:
    if not isinstance(rows, list):
        raise PackageEError(f"{label} is not a list")
    result: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
            raise PackageEError(f"{label} contains a row without an exact ID")
        result.append(row["id"])
    if result != sorted(result) or len(result) != len(set(result)):
        raise PackageEError(f"{label} ID order/closure differs")
    return result


def validate_baseline_bindings(inventory: dict[str, Any] | None = None) -> None:
    inventory = inventory or load_reviewed_inventory()[0]
    if (
        inventory["schema-version"] != 1
        or inventory["content-policy"] != "dcrypt-package-e-reviewed-error-api-removal-v1"
        or inventory["a-d-commit"] != A_D_COMMIT
        or inventory["a-d-tree"] != A_D_TREE
        or inventory["s-e-commit"] != S_E_COMMIT
        or inventory["s-e-tree"] != S_E_TREE
        or inventory["r-e-commit"] != R_E_COMMIT
        or inventory["r-e-tree"] != R_E_TREE
        or inventory["r-e-subject-manifest-sha256"] != R_E_SUBJECT_MANIFEST_SHA256
        or inventory["counts"] != EXPECTED_COUNTS
    ):
        raise PackageEError("reviewed baseline/topology/count bindings differ")
    if _git_text(["rev-parse", f"{A_D_COMMIT}^{{tree}}"]) != A_D_TREE:
        raise PackageEError("A_D tree binding differs")
    _baseline_documents()


def validate_exact_removed_curated_ids(
    inventory: dict[str, Any] | None = None,
) -> list[str]:
    inventory = inventory or load_reviewed_inventory()[0]
    reviewed = inventory["curated-ids"]
    if (
        not isinstance(reviewed, list)
        or reviewed != sorted(set(reviewed))
        or len(reviewed) != 31
        or sha256_bytes(canonical_set_json(reviewed)) != REMOVED_CURATED_IDS_SHA256
        or inventory["removed-curated-ids-sha256"] != REMOVED_CURATED_IDS_SHA256
    ):
        raise PackageEError("exact removed curated-ID authority differs")
    categories = inventory["removed-curated"]
    if (
        not isinstance(categories, list)
        or [row.get("id") for row in categories] != reviewed
        or any(set(row) != {"id", "replacement-category"} for row in categories)
        or any(not isinstance(row["replacement-category"], str) or not row["replacement-category"] for row in categories)
    ):
        raise PackageEError("per-ID replacement-category closure differs")
    baseline_curated, _baseline_atomic, _baseline_snapshot = _baseline_documents()
    baseline_ids = _row_ids(baseline_curated.get("operation"), label="A_D curated rows")
    if len(baseline_ids) != 314 or not set(reviewed).issubset(baseline_ids):
        raise PackageEError("reviewed removed curated IDs do not bind A_D exactly")
    return reviewed


def validate_exact_atomic_delta(
    inventory: dict[str, Any] | None = None,
    document: dict[str, Any] | None = None,
) -> dict[str, int]:
    inventory = inventory or load_reviewed_inventory()[0]
    document = document or load_atomic_inventory()[0]
    removed = inventory["atomic-ids"]
    if (
        not isinstance(removed, list)
        or removed != sorted(set(removed))
        or len(removed) != 100
        or sha256_bytes(canonical_set_json(removed)) != REMOVED_ATOMIC_IDS_SHA256
        or inventory["removed-atomic-ids-sha256"] != REMOVED_ATOMIC_IDS_SHA256
    ):
        raise PackageEError("exact removed atomic-ID authority differs")
    operations = _row_ids(document["operation"], label="post-removal curated atomic rows")
    gaps = _row_ids(document["unreviewed-gap"], label="post-removal gap rows")
    all_ids = sorted((*operations, *gaps))
    if (
        len(operations) != 566
        or len(gaps) != 8_632
        or len(all_ids) != 9_198
        or len(set(all_ids)) != 9_198
        or set(removed) & set(all_ids)
        or sha256_bytes(canonical_set_json(operations)) != POST_EXPANDED_CURATED_IDS_SHA256
        or sha256_bytes(canonical_set_json(all_ids)) != POST_ALL_ATOMIC_IDS_SHA256
    ):
        raise PackageEError("post-removal atomic inventory closure differs")
    _baseline_curated, baseline_atomic, _baseline_snapshot = _baseline_documents()
    baseline_operations = _row_ids(
        baseline_atomic.get("operation"), label="A_D curated atomic rows"
    )
    baseline_gaps = _row_ids(baseline_atomic.get("unreviewed-gap"), label="A_D gap rows")
    if (
        len(baseline_operations) != 666
        or baseline_gaps != gaps
        or set(baseline_operations) != set(operations) | set(removed)
    ):
        raise PackageEError("atomic removal is partial or surplus relative to A_D")
    return {"expanded_curated": len(operations), "gaps": len(gaps), "total": len(all_ids)}


def validate_exact_public_delta(
    inventory: dict[str, Any] | None = None,
    snapshot: dict[str, Any] | None = None,
) -> dict[str, int]:
    inventory = inventory or load_reviewed_inventory()[0]
    snapshot = snapshot or load_public_snapshot()[0]
    reviewed_identities = inventory["removed-public-identities"]
    reviewed_records = inventory["removed-public-records"]
    normalized_reviewed_records: list[dict[str, Any]] = []
    if isinstance(reviewed_records, list):
        for row in reviewed_records:
            if not isinstance(row, dict) or set(row) != {
                *PUBLIC_IDENTITY_FIELDS,
                "classification",
                "operation-refs",
            }:
                raise PackageEError("reviewed removed public record closure differs")
            normalized_reviewed_records.append(
                {
                    **{field: row[field] for field in PUBLIC_IDENTITY_FIELDS},
                    "classification": row["classification"],
                    "operation_refs": row["operation-refs"],
                }
            )
    if (
        not isinstance(reviewed_identities, list)
        or reviewed_identities != sorted(reviewed_identities)
        or len(reviewed_identities) != 130
        or len({tuple(value) for value in reviewed_identities}) != 130
        or sha256_bytes(canonical_set_json(reviewed_identities))
        != REMOVED_PUBLIC_IDENTITIES_SHA256
        or not isinstance(reviewed_records, list)
        or len(reviewed_records) != 130
        or sha256_bytes(canonical_set_json(normalized_reviewed_records))
        != REMOVED_PUBLIC_RECORDS_SHA256
    ):
        raise PackageEError("reviewed removed public API authority differs")
    _baseline_curated, _baseline_atomic, baseline_snapshot = _baseline_documents()
    baseline_entries = baseline_snapshot.get("entries")
    post_entries = snapshot.get("entries")
    if not isinstance(baseline_entries, list) or not isinstance(post_entries, list):
        raise PackageEError("public API entry closure differs")
    baseline_identities = _sorted_identities(baseline_entries)
    post_identities = _sorted_identities(post_entries)
    if (
        len(baseline_identities) != 19_021
        or len(post_identities) != 18_891
        or sha256_bytes(canonical_set_json(baseline_identities))
        != A_D_ALL_PUBLIC_IDENTITIES_SHA256
        or sha256_bytes(canonical_set_json(post_identities)) != POST_PUBLIC_IDENTITIES_SHA256
        or set(map(tuple, baseline_identities))
        != set(map(tuple, post_identities)) | set(map(tuple, reviewed_identities))
        or set(map(tuple, post_identities)) & set(map(tuple, reviewed_identities))
    ):
        raise PackageEError("public API removal is partial or surplus relative to A_D")
    removed_set = set(map(tuple, reviewed_identities))
    actual_removed = [
        record for record in baseline_entries if tuple(public_identity(record)) in removed_set
    ]
    if _sorted_public_records(actual_removed) != normalized_reviewed_records:
        raise PackageEError("removed public classifications/operation references differ")
    distribution: dict[str, int] = {}
    for identity in reviewed_identities:
        distribution[identity[0]] = distribution.get(identity[0], 0) + 1
    if distribution != {
        "dcrypt": 65,
        "dcrypt-algorithms": 12,
        "dcrypt-api": 30,
        "dcrypt-kem": 6,
        "dcrypt-symmetric": 17,
    }:
        raise PackageEError("removed public package distribution differs")
    return distribution


def validate_retained_transitional_set(
    inventory: dict[str, Any] | None = None,
    snapshot: dict[str, Any] | None = None,
) -> list[list[str]]:
    inventory = inventory or load_reviewed_inventory()[0]
    snapshot = snapshot or load_public_snapshot()[0]
    retained = sorted(
        public_identity(record)
        for record in snapshot["entries"]
        if record.get("classification") == "transitional-legacy"
    )
    if (
        len(retained) != 124
        or sha256_bytes(canonical_set_json(retained)) != RETAINED_OTHER_TRANSITIONAL_SHA256
        or inventory["retained-other-transitional-sha256"]
        != RETAINED_OTHER_TRANSITIONAL_SHA256
    ):
        raise PackageEError("unrelated transitional public identity set differs")
    return retained


def validate_tombstones(
    inventory: dict[str, Any] | None = None,
    snapshot: dict[str, Any] | None = None,
) -> list[list[str]]:
    inventory = inventory or load_reviewed_inventory()[0]
    snapshot = snapshot or load_public_snapshot()[0]
    if inventory["retained-tombstones"] != list(TOMBSTONE_PATHS):
        raise PackageEError("reviewed tombstone path closure differs")
    rows = [record for record in snapshot["entries"] if record.get("path") in TOMBSTONE_PATHS]
    identities = _sorted_identities(rows)
    if (
        len(rows) != 4
        or {row.get("path") for row in rows} != set(TOMBSTONE_PATHS)
        or any(row.get("kind") != "module" or row.get("operation_refs") != [] for row in rows)
        or sha256_bytes(canonical_set_json(identities)) != RETAINED_TOMBSTONES_SHA256
    ):
        raise PackageEError("metadata-only module tombstones differ")
    return identities


def validate_source_absence() -> int:
    manifest_raw, _metadata = read_regular_once(
        REPO / "assurance/subject-manifest.json", label="R_E subject manifest"
    )
    if sha256_bytes(manifest_raw) != R_E_SUBJECT_MANIFEST_SHA256:
        raise PackageEError("R_E non-assurance subject manifest binding differs")
    manifest = parse_json_strict(
        manifest_raw, label="R_E subject manifest"
    )
    if (
        manifest.get("source_commit") != R_E_COMMIT
        or manifest.get("source_tree") != R_E_TREE
        or not isinstance(manifest.get("files"), list)
    ):
        raise PackageEError("R_E non-assurance subject manifest identity differs")
    paths = sorted(
        row["path"]
        for row in manifest["files"]
        if isinstance(row, dict)
        and isinstance(row.get("path"), str)
        and row["path"].endswith(".rs")
        and (
            row["path"].startswith("src/")
            or (row["path"].startswith("crates/") and "/src/" in row["path"])
        )
    )
    if len(paths) != 255 or len(paths) != len(set(paths)):
        raise PackageEError("production Rust source path closure differs")
    for relative in paths:
        raw, _metadata = read_regular_once(REPO / relative, label=f"production source {relative}")
        try:
            source = raw.decode("utf-8")
        except UnicodeError as error:
            raise PackageEError(f"production source is not UTF-8: {relative}") from error
        for token in REMOVED_SOURCE_TOKENS:
            if re.search(
                rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])",
                source,
            ):
                raise PackageEError(f"removed legacy token remains in production source: {relative}")
    return len(paths)


def _require_fragments(path: Path, fragments: tuple[str, ...], *, label: str) -> str:
    raw, metadata = read_regular_once(path, label=label, maximum=1 << 20)
    if stat.S_IMODE(metadata.st_mode) not in {0o600, 0o640, 0o644, 0o660, 0o664}:
        raise PackageEError(f"{label} does not map unambiguously to Git mode 100644")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise PackageEError(f"{label} is not UTF-8") from error
    for fragment in fragments:
        if fragment not in text:
            raise PackageEError(f"{label} omits required migration contract: {fragment}")
    return text


def validate_migration_contract(inventory: dict[str, Any] | None = None) -> None:
    inventory = inventory or load_reviewed_inventory()[0]
    if (
        inventory["migration-guide"] != "docs/migration/V4-ERROR-API.md"
        or inventory["migration-fixture"] != "tests/tests/error_api_v4_migration.rs"
    ):
        raise PackageEError("migration guide/fixture path binding differs")
    guide = _require_fragments(
        REPO / inventory["migration-guide"],
        (
            "caller-owned state", "Result::is_ok()", "Result::is_err()",
            "map_or_else", "map_err(dcrypt_symmetric::error::from_io_error)",
            "map_err(dcrypt_symmetric::error::from_primitive_error)",
            "documented empty tombstones", "does not change package versions",
        ),
        label="v4 migration guide",
    )
    fixture = _require_fragments(
        REPO / inventory["migration-fixture"],
        (
            "downstream_replacements_compile_and_legacy_surface_fails_closed",
            "--offline", "--locked", "DOWNSTREAM_CHECK_TIMEOUT",
            "map_err(from_io_error)", "map_err(from_primitive_error)",
            "legacy downstream fixture unexpectedly compiled successfully",
            "ErrorRegistry", "ConstantTimeResult", "SymmetricResultExt",
        ),
        label="v4 downstream migration fixture",
    )
    if "publish crates" not in guide or "CARGO_NET_OFFLINE" not in fixture:
        raise PackageEError("migration non-promotion/offline contract differs")
    control_raw, _metadata = read_regular_once(
        FRAMEWORK / "fixtures/control.json", label="Package E synthetic control"
    )
    control = parse_json_strict(control_raw, label="Package E synthetic control", require_canonical=True)
    if (
        not isinstance(control, dict)
        or control.get("status") != "synthetic-not-evidence"
        or control.get("content_policy") != "dcrypt-package-e-synthetic-structural-control-v1"
        or control.get("schema_version") != 1
        or set(map(tuple, control["before"]["public_identities"]))
        - set(map(tuple, control["after"]["public_identities"]))
        != set(map(tuple, control["removed_public_identities"]))
        or not set(map(tuple, control["retained_tombstones"])).issubset(
            set(map(tuple, control["after"]["public_identities"]))
        )
    ):
        raise PackageEError("synthetic exact-removal control differs")


def validate_version_and_release_hold(
    inventory: dict[str, Any] | None = None,
    document: dict[str, Any] | None = None,
) -> None:
    inventory = inventory or load_reviewed_inventory()[0]
    cargo_raw, _metadata = read_regular_once(REPO / "Cargo.toml", label="workspace manifest")
    cargo = parse_toml_strict(cargo_raw, label="workspace manifest")
    version = cargo.get("workspace", {}).get("package", {}).get("version")
    if (
        version != "3.0.0"
        or inventory["workspace-version"] != "3.0.0"
        or inventory["target-major"] != 4
        or inventory["status"] != "HOLD"
        or inventory["release-gate"] != "HOLD"
        or inventory["release-exit-code"] != 3
        or inventory["version-preparation-authorized"] is not False
        or inventory["publish-eligible"] is not False
        or inventory["promotion-eligible"] is not False
    ):
        raise PackageEError("version preparation/publication must remain unauthorized and HOLD")
    if document is not None and document.get("release_state") != {
        "promotion_eligible": False,
        "publish_eligible": False,
        "release_gate": "HOLD",
        "release_gate_exit_code": 3,
        "version_preparation_authorized": False,
    }:
        raise PackageEError("generated release state differs from unconditional HOLD")


def _file_binding(path: str) -> dict[str, Any]:
    raw, metadata = read_regular_once(REPO / path, label=f"Package E input {path}")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in {0o600, 0o640, 0o644, 0o660, 0o664}:
        raise PackageEError(f"Package E input does not map to Git mode 100644: {path}")
    return {"git_mode": "100644", "path": path, "sha256": sha256_bytes(raw), "size": len(raw)}


def build_package_document() -> dict[str, Any]:
    inventory, inventory_raw = load_reviewed_inventory()
    validate_baseline_bindings(inventory)
    removed_curated = validate_exact_removed_curated_ids(inventory)
    curated, curated_raw = _load_curated_inventory()
    post_curated = _row_ids(curated["operation"], label="post-removal curated source rows")
    if (
        len(post_curated) != 283
        or sha256_bytes(canonical_set_json(post_curated)) != POST_CURATED_IDS_SHA256
        or set(post_curated) & set(removed_curated)
    ):
        raise PackageEError("post-removal curated source closure differs")
    atomic, atomic_raw = load_atomic_inventory()
    atomic_counts = validate_exact_atomic_delta(inventory, atomic)
    snapshot, snapshot_raw = load_public_snapshot()
    public_distribution = validate_exact_public_delta(inventory, snapshot)
    retained_transitional = validate_retained_transitional_set(inventory, snapshot)
    tombstones = validate_tombstones(inventory, snapshot)
    source_count = validate_source_absence()
    validate_migration_contract(inventory)
    validate_version_and_release_hold(inventory)
    subject_raw, _metadata = read_regular_once(
        REPO / "assurance/subject-manifest.json", label="R_E subject manifest"
    )
    document = {
        "artifact_role": "package-e-error-api-v4-migration",
        "content_policy": "dcrypt-package-e-local-breaking-removal-v1",
        "counts": {
            "curated_source_rows": len(post_curated),
            "expanded_curated_atomic_rows": atomic_counts["expanded_curated"],
            "production_rust_sources": source_count,
            "public_identities": len(snapshot["entries"]),
            "release_blocked_rows": EXPECTED_COUNTS["post-release-blocked-rows"],
            "retained_other_transitional_public_identities": len(retained_transitional),
            "unreviewed_gap_rows": atomic_counts["gaps"],
        },
        "input_bindings": [
            {"git_mode": "100644", "path": "assurance/curated-operations.toml", "sha256": sha256_bytes(curated_raw), "size": len(curated_raw)},
            {"git_mode": "100644", "path": "assurance/atomic-operations.toml", "sha256": sha256_bytes(atomic_raw), "size": len(atomic_raw)},
            {"git_mode": "100644", "path": "assurance/public-api-snapshot.json", "sha256": sha256_bytes(snapshot_raw), "size": len(snapshot_raw)},
            {"git_mode": "100644", "path": "assurance/subject-manifest.json", "sha256": sha256_bytes(subject_raw), "size": len(subject_raw)},
            _file_binding(inventory["migration-guide"]),
            _file_binding(inventory["migration-fixture"]),
        ],
        "migration": {
            "guide": inventory["migration-guide"],
            "replacement_categories": inventory["replacements"],
            "test_fixture": inventory["migration-fixture"],
        },
        "promotion_effect": "none",
        "public_removal": {
            "package_distribution": public_distribution,
            "removed_atomic_ids": len(inventory["atomic-ids"]),
            "removed_atomic_ids_sha256": REMOVED_ATOMIC_IDS_SHA256,
            "removed_curated_ids": len(inventory["curated-ids"]),
            "removed_curated_ids_sha256": REMOVED_CURATED_IDS_SHA256,
            "removed_public_identities": len(inventory["removed-public-identities"]),
            "removed_public_identities_sha256": REMOVED_PUBLIC_IDENTITIES_SHA256,
        },
        "release_state": {
            "promotion_eligible": False,
            "publish_eligible": False,
            "release_gate": "HOLD",
            "release_gate_exit_code": 3,
            "version_preparation_authorized": False,
        },
        "reviewed_inventory_sha256": sha256_bytes(inventory_raw),
        "schema_version": 1,
        "semantic_bindings": {
            "post_all_atomic_ids_sha256": POST_ALL_ATOMIC_IDS_SHA256,
            "post_curated_ids_sha256": POST_CURATED_IDS_SHA256,
            "post_expanded_curated_ids_sha256": POST_EXPANDED_CURATED_IDS_SHA256,
            "post_public_identities_sha256": POST_PUBLIC_IDENTITIES_SHA256,
            "retained_other_transitional_sha256": RETAINED_OTHER_TRANSITIONAL_SHA256,
            "retained_tombstones": tombstones,
            "retained_tombstones_sha256": RETAINED_TOMBSTONES_SHA256,
        },
        "status": "local-breaking-removal-complete",
        "subject_binding": {
            "a_d_commit": A_D_COMMIT,
            "a_d_tree": A_D_TREE,
            "r_e_commit": R_E_COMMIT,
            "r_e_subject_manifest_sha256": R_E_SUBJECT_MANIFEST_SHA256,
            "r_e_tree": R_E_TREE,
            "s_e_commit": S_E_COMMIT,
            "s_e_tree": S_E_TREE,
        },
        "target_major": 4,
        "workspace_version": "3.0.0",
    }
    validate_package_document(document)
    return document


ROLE_POLICIES = {
    "local-removal-proof": "dcrypt-package-e-local-removal-proof-v1",
    "downstream-migration-candidate":
        "dcrypt-package-e-downstream-migration-candidate-v1",
    "external-review-candidate": "dcrypt-package-e-external-review-candidate-v1",
    "acceptance": "dcrypt-package-e-disabled-acceptance-v1",
}
ROLE_STATUSES = {
    "local-removal-proof": "generated-structural-only",
    "downstream-migration-candidate": "collected-unreviewed",
    "external-review-candidate": "collected-unreviewed",
    "acceptance": "acceptance-disabled",
}
CAPTURE_ADMISSIBLE_ROLES = {
    "downstream-migration-candidate", "external-review-candidate"
}


def _closed_object(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(required if required is not None else properties),
        "type": "object",
    }


def _digest_schema() -> dict[str, Any]:
    return {"pattern": "^[0-9a-f]{64}$", "type": "string"}


def _artifact_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "path": {
                "maxLength": 512,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9._+/-]+$",
                "type": "string",
            },
            "sha256": _digest_schema(),
            "size": {"maximum": 67_108_864, "minimum": 0, "type": "integer"},
        }
    )


def _subject_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "r_commit": {"const": R_E_COMMIT},
            "r_tree": {"const": R_E_TREE},
            "subject_manifest_sha256": {"const": R_E_SUBJECT_MANIFEST_SHA256},
        }
    )


def _role_data_schema(role: str) -> dict[str, Any]:
    if role == "local-removal-proof":
        return _closed_object(
            {
                "evidence_effect": {"const": "structural-only"},
                "generated": {"const": True},
                "post_public_identities": {"const": 18_891},
                "post_total_atomic_rows": {"const": 9_198},
                "removed_atomic_ids": {"const": 100},
                "removed_curated_ids": {"const": 31},
                "removed_public_identities": {"const": 130},
            }
        )
    if role == "downstream-migration-candidate":
        return _closed_object(
            {
                "compile_succeeded": {"type": "boolean"},
                "fixture": {"const": "tests/tests/error_api_v4_migration.rs"},
                "legacy_compile_failed": {"type": "boolean"},
                "stderr_sha256": _digest_schema(),
                "stdout_sha256": _digest_schema(),
                "toolchain_sha256": _digest_schema(),
            }
        )
    if role == "external-review-candidate":
        return _closed_object(
            {
                "accepted": {"const": False},
                "independent": {"type": "boolean"},
                "report_sha256": _digest_schema(),
                "reviewer_identity_sha256": _digest_schema(),
                "signature_sha256": _digest_schema(),
            }
        )
    if role == "acceptance":
        return _closed_object(
            {
                "accepted": {"const": False},
                "decision": {"const": "disabled"},
                "reason": {"minLength": 1, "maxLength": 1024, "type": "string"},
            }
        )
    raise PackageEError(f"unknown Package E evidence role: {role}")


def _role_schema(role: str) -> dict[str, Any]:
    return _closed_object(
        {
            "artifact_role": {"const": role},
            "artifacts": {
                "items": _artifact_schema(),
                "maxItems": 64,
                "minItems": 1,
                "type": "array",
            },
            "content_policy": {"const": ROLE_POLICIES[role]},
            "promotion_eligible": {"const": False},
            "raw_artifact_set_sha256": _digest_schema(),
            "role_data": _role_data_schema(role),
            "schema_version": {"const": 1},
            "status": {"const": ROLE_STATUSES[role]},
            "subject_binding": _subject_schema(),
            "trusted": {"const": False},
        }
    )


def build_schema() -> dict[str, Any]:
    """Build the closed, role-disjoint candidate schema.

    Acceptance is schema-defined so an attempted acceptance has a stable shape,
    but v1 semantic validation and capture reject that role unconditionally.
    No role admits trusted or promotion-eligible state.
    """

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "oneOf": [_role_schema(role) for role in ROLE_POLICIES],
        "title": "dcrypt Package E nonpromotable migration candidate roles",
    }


def artifact_set_sha256(artifacts: list[dict[str, Any]]) -> str:
    return sha256_bytes(canonical_set_json(artifacts))


def _schema_scalar(value: Any, schema: dict[str, Any], *, label: str) -> None:
    if "const" in schema and value != schema["const"]:
        raise PackageEError(f"{label} differs from its role constant")
    kind = schema.get("type")
    if kind == "string":
        if not isinstance(value, str):
            raise PackageEError(f"{label} is not a string")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1 << 30):
            raise PackageEError(f"{label} length differs")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise PackageEError(f"{label} pattern differs")
    elif kind == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise PackageEError(f"{label} is not an integer")
        if value < schema.get("minimum", -(1 << 63)) or value > schema.get("maximum", 1 << 63):
            raise PackageEError(f"{label} integer bound differs")
    elif kind == "boolean" and not isinstance(value, bool):
        raise PackageEError(f"{label} is not a boolean")


def _validate_closed_schema(value: Any, schema: dict[str, Any], *, label: str) -> None:
    if schema.get("type") == "object":
        if not isinstance(value, dict):
            raise PackageEError(f"{label} is not an object")
        properties = schema["properties"]
        if set(value) != set(schema["required"]) or set(value) - set(properties):
            raise PackageEError(f"{label} object closure differs")
        for key, item in value.items():
            _validate_closed_schema(item, properties[key], label=f"{label}.{key}")
        return
    if schema.get("type") == "array":
        if not isinstance(value, list):
            raise PackageEError(f"{label} is not an array")
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1 << 30):
            raise PackageEError(f"{label} array bound differs")
        for index, item in enumerate(value):
            _validate_closed_schema(item, schema["items"], label=f"{label}[{index}]")
        return
    _schema_scalar(value, schema, label=label)


def validate_schema_value(value: Any) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("artifact_role"), str):
        raise PackageEError("candidate lacks an exact artifact role")
    role = value["artifact_role"]
    if role not in ROLE_POLICIES:
        raise PackageEError("candidate artifact role is unknown")
    _validate_closed_schema(value, _role_schema(role), label="candidate")
    artifacts = value["artifacts"]
    paths = [row["path"] for row in artifacts]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise PackageEError("candidate artifact paths are not sorted and unique")
    for path in paths:
        _safe_relative(path, label="candidate artifact path")
    if value["raw_artifact_set_sha256"] != artifact_set_sha256(artifacts):
        raise PackageEError("candidate artifact-set digest differs")
    return role


def validate_evidence_candidate(value: Any, *, capture: bool = False) -> str:
    role = validate_schema_value(value)
    if role == "acceptance":
        raise PackageEError("Package E v1 acceptance is disabled")
    if capture and role not in CAPTURE_ADMISSIBLE_ROLES:
        raise PackageEError(f"Package E role is not capture-admissible: {role}")
    if value["trusted"] is not False or value["promotion_eligible"] is not False:
        raise PackageEError("Package E candidates never imply trust or promotion")
    return role


def build_local_removal_proof() -> dict[str, Any]:
    artifacts = [
        {
            "path": "package-e.json",
            "sha256": sha256_bytes(canonical_json(build_package_document())),
            "size": len(canonical_json(build_package_document())),
        }
    ]
    value = {
        "artifact_role": "local-removal-proof",
        "artifacts": artifacts,
        "content_policy": ROLE_POLICIES["local-removal-proof"],
        "promotion_eligible": False,
        "raw_artifact_set_sha256": artifact_set_sha256(artifacts),
        "role_data": {
            "evidence_effect": "structural-only",
            "generated": True,
            "post_public_identities": 18_891,
            "post_total_atomic_rows": 9_198,
            "removed_atomic_ids": 100,
            "removed_curated_ids": 31,
            "removed_public_identities": 130,
        },
        "schema_version": 1,
        "status": ROLE_STATUSES["local-removal-proof"],
        "subject_binding": {
            "r_commit": R_E_COMMIT,
            "r_tree": R_E_TREE,
            "subject_manifest_sha256": R_E_SUBJECT_MANIFEST_SHA256,
        },
        "trusted": False,
    }
    validate_evidence_candidate(value)
    return value


def validate_package_document(document: Any) -> None:
    if not isinstance(document, dict):
        raise PackageEError("Package E generated document is not an object")
    if (
        document.get("schema_version") != 1
        or document.get("content_policy") != "dcrypt-package-e-local-breaking-removal-v1"
        or document.get("status") != "local-breaking-removal-complete"
        or document.get("workspace_version") != "3.0.0"
        or document.get("target_major") != 4
        or document.get("promotion_effect") != "none"
        or document.get("reviewed_inventory_sha256") != REVIEWED_INVENTORY_SHA256
        or set(document) != {
            "artifact_role", "content_policy", "counts", "input_bindings", "migration",
            "promotion_effect", "public_removal", "release_state",
            "reviewed_inventory_sha256", "schema_version", "semantic_bindings", "status",
            "subject_binding", "target_major", "workspace_version",
        }
    ):
        raise PackageEError("Package E generated document identity/closure differs")
    validate_version_and_release_hold(document=document)


def artifact_source_files() -> tuple[str, ...]:
    return (
        "README.md",
        "capture.py",
        "fixtures/control.json",
        "generate.py",
        "model.py",
        "rebind-final-subject.py",
        "reviewed-inventory.toml",
        "selftest.py",
        "verify.py",
    )
