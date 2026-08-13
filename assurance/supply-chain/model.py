#!/usr/bin/env python3
"""Normative fail-closed Package F supply-chain foundation model."""

from __future__ import annotations

import datetime as dt
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

A_E_COMMIT = "86a907154c1f8211a1775c1da8186b71a704536f"
A_E_TREE = "d9bd9b791038fc92c4581468708e9cf39cd6234f"
S_F_COMMIT = "ac91913afee3b91c823a1448e6200de26fdd1c8a"
S_F_TREE = "6952979606c28f739fca1aeb9bb14b1ca042d09d"
R_F_COMMIT = "889cb8c4dc13a78679dc8a7677916484a9966f65"
R_F_TREE = "0d44b68b186913de68844d09b7e498bcda14d109"

# Final post-cascade values are deliberately literal trust anchors. They are
# replaced only after the core cascade is frozen and independently reproduced.
R_F_SUBJECT_MANIFEST_SHA256 = "95902d2ff4a2f99808ba5d404fbce3175b787b93fdc1538cb55ad350e69505c7"
R_F_ATOMIC_OPERATIONS_SHA256 = "8e745ab16086aa50e265ad79189375270c5906df8545f540d96426bc348ca11a"
R_F_PUBLIC_API_SNAPSHOT_SHA256 = "5fa59a0218c2be98ef653d85da35c616c75b1499cb376f2b12c99eb6813e553d"
REVIEWED_INVENTORY_SHA256 = "6786b8d5e312ab6ebe736db57289dfb552bae6b956fedec81a78232eaf7b77ca"

S_F_PATHS = tuple(sorted((
    ".github/workflows/security-validation.yml",
    "tools/bench-processor/Cargo.lock",
    "tools/bench-processor/Cargo.toml",
    "tools/release-dcrypt.sh",
    "tools/verify-publish-ready.sh",
    "tools/verify-remote-release-ready.py",
)))
R_F_PATHS = tuple(sorted((
    "verification/oracle-provisioning/bundle_lib.py",
    "verification/oracle-provisioning/manifest.json",
    "verification/oracle-provisioning/subject-inputs.json",
)))
TRACKED_CARGO_MANIFESTS = (
    "Cargo.toml", "crates/algorithms/Cargo.toml", "crates/api/Cargo.toml",
    "crates/common/Cargo.toml", "crates/hybrid/Cargo.toml", "crates/internal/Cargo.toml",
    "crates/kem/Cargo.toml", "crates/params/Cargo.toml", "crates/pke/Cargo.toml",
    "crates/sign/Cargo.toml", "crates/symmetric/Cargo.toml", "crates/utils/Cargo.toml",
    "fuzz/Cargo.toml", "migration/legacy-xchacha20poly1305/Cargo.toml",
    "tests/Cargo.toml", "tools/bench-processor/Cargo.toml", "verification/Cargo.toml",
)

EXPECTED_COUNTS = {
    "tracked-cargo-manifests": 17,
    "workspace-classifications": 5,
    "tracked-lockfiles": 5,
    "lock-package-occurrences": 342,
    "unique-lock-identities": 255,
    "unique-registry-lock-identities": 238,
    "unique-local-lock-identities": 17,
    "publishable-packages": 12,
    "internal-publish-edges": 42,
    "external-direct-dependency-occurrences": 5,
    "external-direct-dependency-identities": 2,
    "sbom-slots": 5,
    "candidate-crate-archive-slots": 12,
    "registry-crate-archive-slots": 12,
    "dependency-exceptions": 1,
    "artifact-subjects": 18,
    "producer-classes": 2,
    "producer-subject-obligations": 36,
    "required-byte-comparisons": 18,
    "accepted-sboms": 0,
    "accepted-signatures": 0,
    "accepted-attestations": 0,
    "accepted-independent-rebuilds": 0,
    "verified-container-images": 0,
    "verified-runner-images": 0,
    "verified-toolchain-distributions": 0,
    "completed-producer-subjects": 0,
    "completed-byte-comparisons": 0,
    "release-blocked-atomic-rows": 9_198,
}

LOCK_PATHS = (
    ("production", "Cargo.lock"),
    ("verification", "verification/Cargo.lock"),
    ("fuzz", "fuzz/Cargo.lock"),
    ("migration", "migration/legacy-xchacha20poly1305/Cargo.lock"),
    ("bench", "tools/bench-processor/Cargo.lock"),
)
SBOM_IDS = tuple(row[0] for row in LOCK_PATHS)
PUBLISH_ORDER = (
    "dcrypt-internal", "dcrypt-params", "dcrypt-api", "dcrypt-common",
    "dcrypt-algorithms", "dcrypt-symmetric", "dcrypt-kem", "dcrypt-sign",
    "dcrypt-pke", "dcrypt-utils", "dcrypt-hybrid", "dcrypt",
)
ARTIFACT_SUBJECTS = tuple(
    [(f"sbom-{item}", "sbom") for item in SBOM_IDS]
    + [(f"crate-{item}", "crate-archive") for item in PUBLISH_ORDER]
    + [("canonical-source-archive", "source-archive")]
)
ARTIFACT_SUBJECT_SET_SHA256 = "41cae985d2507f82ec0a90a4242cf814536474fa643b21078b60ae2b0186d099"
ROLE_CAPS = {
    "first-party-build-candidate": {"files": 64, "per_file": 67_108_864, "total": 536_870_912},
    "signature-transparency-candidate": {
        "files": 32, "per_file": 16_777_216, "total": 67_108_864,
    },
    "independent-rebuild-candidate": {
        "files": 64, "per_file": 67_108_864, "total": 536_870_912,
    },
}
ROLE_POLICIES = {
    "local-foundation-proof": "dcrypt-package-f-local-foundation-proof-v1",
    "first-party-build-candidate": "dcrypt-package-f-first-party-build-candidate-v1",
    "signature-transparency-candidate":
        "dcrypt-package-f-signature-transparency-candidate-v1",
    "independent-rebuild-candidate":
        "dcrypt-package-f-independent-rebuild-candidate-v1",
    "acceptance": "dcrypt-package-f-disabled-acceptance-v1",
}
ROLE_STATUSES = {
    "local-foundation-proof": "generated-structural-only",
    "first-party-build-candidate": "collected-unreviewed",
    "signature-transparency-candidate": "collected-unverified",
    "independent-rebuild-candidate": "collected-unreviewed",
    "acceptance": "acceptance-disabled",
}
CAPTURE_ADMISSIBLE_ROLES = set(ROLE_CAPS)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
INVENTORY_KEYS = {
    "a-e-commit", "a-e-tree", "accepted-attestations",
    "accepted-independent-rebuilds", "accepted-sboms", "accepted-signatures",
    "antecedent", "artifact-subject", "artifact-subject-set-sha256",
    "artifact-subjects", "bench-workspace-classification", "blocked-slot",
    "candidate-crate-archive-slots", "completed-byte-comparisons",
    "completed-producer-subjects", "content-policy", "dependency-exception",
    "dependency-exceptions", "internal-publish-edges",
    "external-direct-dependency-occurrences", "external-direct-dependency-identities",
    "external-direct-dependency-rows-sha256",
    "lock-occurrence-rows-sha256", "lock-package-occurrences",
    "lock-unique-full-rows-sha256", "lock-unique-identities-sha256",
    "producer-class", "producer-classes", "producer-subject-obligations",
    "promotion-eligible", "publish-eligible", "publish-order-rows-sha256",
    "publish-package", "publishable-packages", "r-f-atomic-operations-sha256",
    "r-f-commit", "r-f-public-api-snapshot-sha256",
    "r-f-subject-manifest-files", "r-f-subject-manifest-sha256",
    "r-f-subject-manifest-size", "r-f-tree", "rebind-input",
    "registry-crate-archive-slots", "release-blocked-atomic-rows",
    "release-exit-code", "release-gate", "required-byte-comparisons",
    "s-f-commit", "s-f-tree", "sbom-slot", "sbom-slots", "schema-version",
    "source-prerequisite", "status", "supply-chain-blocker",
    "toolchain-selector", "tracked-cargo-manifests", "tracked-lockfiles",
    "unique-local-lock-identities", "unique-lock-identities",
    "unique-registry-lock-identities", "verified-container-images",
    "verified-runner-images", "verified-toolchain-distributions",
    "version-preparation-authorized", "workspace-classifications",
    "workspace-lock", "workspace-version",
}


class PackageFError(RuntimeError):
    """A reviewed Package F invariant failed closed."""


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def compact_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_float(_value: str) -> float:
    raise ValueError("JSON floats are forbidden")


def _reject_constant(_value: str) -> None:
    raise ValueError("nonfinite JSON values are forbidden")


def _assert_nfc(value: Any, *, label: str) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise PackageFError(f"{label} contains a non-NFC string")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_nfc(item, label=f"{label}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _assert_nfc(key, label=f"{label} key")
            _assert_nfc(item, label=f"{label}.{key}")


def parse_json_strict(raw: bytes, *, label: str, require_canonical: bool = False) -> Any:
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_float=_reject_float, parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise PackageFError(f"{label} is not strict JSON: {error}") from error
    _assert_nfc(value, label=label)
    if require_canonical and canonical_json(value) != raw:
        raise PackageFError(f"{label} is not canonical JSON")
    return value


def parse_toml_strict(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise PackageFError(f"{label} is not strict TOML: {error}") from error
    _assert_nfc(value, label=label)
    return value


def read_regular_once(path: Path, *, label: str, maximum: int = 64 << 20) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as error:
        raise PackageFError(f"cannot stat {label}") from error
    if (
        not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1 or before.st_size < 0 or before.st_size > maximum
        or before.st_mode & 0o7000 or stat.S_IMODE(before.st_mode) & 0o002
    ):
        raise PackageFError(f"{label} is not a bounded regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        identity = (
            before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode,
            before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns,
        )
        observed = (
            opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid, opened.st_mode,
            opened.st_nlink, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns,
        )
        if observed != identity or not stat.S_ISREG(opened.st_mode):
            raise PackageFError(f"{label} changed before read")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                raise PackageFError(f"{label} truncated during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise PackageFError(f"{label} grew during read")
        after = os.fstat(descriptor)
        if (
            after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode,
            after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        ) != identity:
            raise PackageFError(f"{label} changed during read")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def safe_relative_path(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1024:
        raise PackageFError(f"{label} is not a bounded path")
    path = PurePosixPath(value)
    if (
        path.is_absolute() or value != path.as_posix() or "//" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(len(part.encode("utf-8")) > 255 for part in path.parts)
    ):
        raise PackageFError(f"{label} is not canonical relative POSIX")
    return value


def _git(arguments: list[str], *, binary: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", *arguments], cwd=REPO, capture_output=True, text=not binary, timeout=90,
        env={
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0", "LANG": "C",
            "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC",
        },
    )


def _git_blob(commit: str, path: str) -> tuple[str, bytes]:
    entry = _git(["ls-tree", "-z", "--full-tree", commit, "--", path], binary=True)
    records = [item for item in entry.stdout.split(b"\0") if item] if entry.returncode == 0 else []
    if len(records) != 1:
        raise PackageFError(f"required committed blob differs: {path}")
    metadata, encoded = records[0].split(b"\t", 1)
    mode, kind, object_id = metadata.decode("ascii").split(" ")
    if encoded.decode("utf-8") != path or kind != "blob" or mode not in {"100644", "100755"}:
        raise PackageFError(f"committed path type/mode differs: {path}")
    blob = _git(["cat-file", "blob", object_id], binary=True)
    if blob.returncode != 0:
        raise PackageFError(f"cannot read committed blob: {path}")
    return mode, blob.stdout


def _resolve(commit: str, suffix: str = "commit") -> str:
    result = _git(["rev-parse", "--verify", f"{commit}^{{{suffix}}}"])
    value = result.stdout.strip() if result.returncode == 0 else ""
    if HEX40.fullmatch(value) is None:
        raise PackageFError("cannot resolve exact Git subject")
    return value


def _parents(commit: str) -> list[str]:
    result = _git(["rev-list", "--parents", "-n", "1", commit])
    rows = result.stdout.strip().split() if result.returncode == 0 else []
    if not rows or rows[0] != commit:
        raise PackageFError("cannot resolve exact Git parents")
    return rows[1:]


def _diff_paths(parent: str, child: str) -> list[str]:
    result = _git([
        "diff-tree", "--no-commit-id", "--name-only", "-r", "--no-renames", "-z",
        parent, child,
    ], binary=True)
    if result.returncode != 0:
        raise PackageFError("cannot inspect exact Git path delta")
    try:
        return sorted(item.decode("utf-8") for item in result.stdout.split(b"\0") if item)
    except UnicodeError as error:
        raise PackageFError("Git path delta is not UTF-8") from error


def validate_topology() -> None:
    if (
        _resolve(A_E_COMMIT, "tree") != A_E_TREE
        or _resolve(S_F_COMMIT, "tree") != S_F_TREE
        or _resolve(R_F_COMMIT, "tree") != R_F_TREE
        or _parents(S_F_COMMIT) != [A_E_COMMIT]
        or _parents(R_F_COMMIT) != [S_F_COMMIT]
        or _diff_paths(A_E_COMMIT, S_F_COMMIT) != list(S_F_PATHS)
        or _diff_paths(S_F_COMMIT, R_F_COMMIT) != list(R_F_PATHS)
    ):
        raise PackageFError("A_E -> S_F -> R_F topology/path closure differs")


@lru_cache(maxsize=1)
def load_reviewed_inventory() -> tuple[dict[str, Any], bytes]:
    raw, _metadata = read_regular_once(INVENTORY, label="Package F reviewed inventory", maximum=2 << 20)
    if REVIEWED_INVENTORY_SHA256 != "0" * 64 and sha256_bytes(raw) != REVIEWED_INVENTORY_SHA256:
        raise PackageFError("Package F reviewed inventory digest differs")
    value = parse_toml_strict(raw, label="Package F reviewed inventory")
    return value, raw


def _lock_rows(raw: bytes, *, label: str) -> list[list[Any]]:
    lock = parse_toml_strict(raw, label=label)
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise PackageFError(f"{label} lacks package rows")
    rows: list[list[Any]] = []
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str) or not isinstance(package.get("version"), str):
            raise PackageFError(f"{label} package row differs")
        source = package.get("source", "local")
        checksum = package.get("checksum")
        if not isinstance(source, str) or (checksum is not None and not isinstance(checksum, str)):
            raise PackageFError(f"{label} identity row differs")
        rows.append([package["name"], package["version"], source, checksum])
    return sorted(rows)


def _row_digest(rows: list[list[Any]]) -> str:
    return sha256_bytes(compact_json(rows))


def validate_locks(inventory: dict[str, Any]) -> dict[str, Any]:
    expected_rows = inventory.get("workspace-lock")
    if not isinstance(expected_rows, list) or len(expected_rows) != 5:
        raise PackageFError("workspace lock inventory closure differs")
    observed_all: list[list[Any]] = []
    counts: list[dict[str, Any]] = []
    for expected, (workspace, path) in zip(expected_rows, LOCK_PATHS, strict=True):
        raw, _metadata = read_regular_once(REPO / path, label=f"Package F {workspace} lock", maximum=4 << 20)
        rows = _lock_rows(raw, label=f"Package F {workspace} lock")
        registry = sum(row[2] != "local" for row in rows)
        local = len(rows) - registry
        if expected != {
            "id": workspace, "path": path, "package-occurrences": len(rows),
            "registry-occurrences": registry, "local-occurrences": local,
            "identity-rows-sha256": _row_digest(rows),
        }:
            raise PackageFError(f"Package F {workspace} lock binding differs")
        observed_all.extend(rows)
        counts.append({"id": workspace, "packages": len(rows), "registry": registry, "local": local})
    if _row_digest(sorted(observed_all)) != inventory["lock-occurrence-rows-sha256"]:
        raise PackageFError("all-lock occurrence digest differs")
    unique_full = sorted({tuple(row) for row in observed_all})
    unique_identity = sorted({tuple(row[:3]) for row in observed_all})
    registry_identities = sum(row[2] != "local" for row in unique_identity)
    local_identities = len(unique_identity) - registry_identities
    if (
        _row_digest([list(row) for row in unique_full]) != inventory["lock-unique-full-rows-sha256"]
        or _row_digest([list(row) for row in unique_identity]) != inventory["lock-unique-identities-sha256"]
        or len(unique_identity) != EXPECTED_COUNTS["unique-lock-identities"]
        or registry_identities != EXPECTED_COUNTS["unique-registry-lock-identities"]
        or local_identities != EXPECTED_COUNTS["unique-local-lock-identities"]
    ):
        raise PackageFError("unique lock identity closure differs")
    return {"workspaces": counts, "occurrences": len(observed_all), "unique_identities": len(unique_identity)}


def _package_id(package: dict[str, Any]) -> str:
    return f"{package['name']}@{package['version']}"


def utc_current_date() -> dt.date:
    """Return the current date using an explicit UTC clock."""
    return dt.datetime.now(dt.timezone.utc).date()


def validate_exception_dates(
    reviewed: Any,
    valid: Any,
    *,
    observed_date: dt.date | None = None,
) -> None:
    observed = utc_current_date() if observed_date is None else observed_date
    if (
        not isinstance(reviewed, dt.date) or isinstance(reviewed, dt.datetime)
        or not isinstance(valid, dt.date) or isinstance(valid, dt.datetime)
        or not isinstance(observed, dt.date) or isinstance(observed, dt.datetime)
        or reviewed != dt.date(2026, 8, 13) or valid != dt.date(2026, 9, 10)
        or valid < reviewed or (valid - reviewed).days > 90
        or observed >= valid
    ):
        raise PackageFError("dependency exception reviewed/expiry window differs")


def validate_dependency_exception(inventory: dict[str, Any]) -> dict[str, Any]:
    records = inventory.get("dependency-exception")
    if not isinstance(records, list) or len(records) != 1:
        raise PackageFError("dependency exception closure differs")
    record = records[0]
    expected_keys = {
        "advisory-id", "owner", "reviewed-at", "valid-through", "deny-file",
        "deny-occurrences", "workspace-lock", "direct-manifest", "direct-package",
        "direct-requirement", "affected-package", "lock-path", "reason", "reviewer",
        "dependency-kind", "published-production-reachable", "deny-file-sha256",
        "deny-reason", "node",
    }
    if set(record) != expected_keys or record["advisory-id"] != "RUSTSEC-2026-0173":
        raise PackageFError("dependency exception row closure differs")
    reviewed, valid = record["reviewed-at"], record["valid-through"]
    validate_exception_dates(reviewed, valid)
    if (
        record["owner"] != "dcrypt dependency security"
        or record["reviewer"] != "dcrypt supply-chain assurance"
        or record["reason"] != (
            "Build-time transitive dependency of the pinned, excluded, non-published "
            "ML-DSA verification oracle; no compatible oracle update is currently reviewed."
        )
        or record["deny-reason"] != (
            "proc-macro-error2 is a build-time transitive dependency of the pinned libcrux "
            "ML-DSA test oracle in the excluded, non-published verification workspace; no "
            "compatible oracle update exists yet"
        )
        or record["dependency-kind"] != "dev"
        or record["published-production-reachable"] is not False
        or record["deny-file"] != "deny.toml" or record["deny-occurrences"] != 1
        or record["workspace-lock"] != "verification/Cargo.lock"
        or record["direct-manifest"] != "verification/Cargo.toml"
        or record["direct-package"] != "libcrux-ml-dsa@0.0.10"
        or record["direct-requirement"] != "=0.0.10"
    ):
        raise PackageFError("dependency exception ownership/expiry differs")
    deny_raw, _metadata = read_regular_once(REPO / record["deny-file"], label="deny policy")
    if sha256_bytes(deny_raw) != record["deny-file-sha256"]:
        raise PackageFError("dependency exception deny digest differs")
    deny = parse_toml_strict(deny_raw, label="deny policy")
    ignored = deny.get("advisories", {}).get("ignore", [])
    hits = [row for row in ignored if isinstance(row, dict) and row.get("id") == record["advisory-id"]]
    if (
        len(hits) != record["deny-occurrences"] or len(ignored) != 1
        or hits[0].get("reason") != record["deny-reason"]
    ):
        raise PackageFError("dependency exception is not bijective with deny policy")
    manifest_raw, _metadata = read_regular_once(REPO / record["direct-manifest"], label="verification manifest")
    manifest = parse_toml_strict(manifest_raw, label="verification manifest")
    direct_name, direct_version = record["direct-package"].split("@", 1)
    dependency = manifest.get("dev-dependencies", {}).get(direct_name)
    if not isinstance(dependency, dict) or dependency.get("version") != record["direct-requirement"] or direct_version != record["direct-requirement"].removeprefix("="):
        raise PackageFError("dependency exception direct root differs")
    lock_raw, _metadata = read_regular_once(REPO / record["workspace-lock"], label="exception lock")
    lock = parse_toml_strict(lock_raw, label="exception lock")
    packages = lock.get("package", [])
    by_id = {_package_id(row): row for row in packages}
    if len(by_id) != len(packages) or record["lock-path"] != [
        "libcrux-ml-dsa@0.0.10", "hax-lib@0.3.7", "hax-lib-macros@0.3.7",
        "proc-macro-error2@2.0.1",
    ]:
        raise PackageFError("dependency exception lock path differs")
    nodes = record["node"]
    if not isinstance(nodes, list) or len(nodes) != 4 or [row.get("package") for row in nodes] != record["lock-path"]:
        raise PackageFError("dependency exception node closure differs")
    for node in nodes:
        package = by_id.get(node["package"])
        if (
            set(node) != {"package", "source", "checksum"} or package is None
            or package.get("source") != node["source"] or package.get("checksum") != node["checksum"]
        ):
            raise PackageFError("dependency exception node binding differs")
    for parent, child in zip(record["lock-path"], record["lock-path"][1:]):
        parent_row = by_id.get(parent)
        child_name = child.rsplit("@", 1)[0]
        if not parent_row or child_name not in {
            item.split(" ", 1)[0] for item in parent_row.get("dependencies", [])
        }:
            raise PackageFError("dependency exception lock graph differs")
    if record["affected-package"] != record["lock-path"][-1]:
        raise PackageFError("dependency exception affected package differs")
    chain_ids = set(record["lock-path"])
    for workspace, path in LOCK_PATHS:
        other_raw, _metadata = read_regular_once(REPO / path, label=f"exception confinement {workspace}")
        other_rows = _lock_rows(other_raw, label=f"exception confinement {workspace}")
        observed_ids = {f"{row[0]}@{row[1]}" for row in other_rows}
        intersection = chain_ids & observed_ids
        if workspace == "verification":
            if intersection != chain_ids:
                raise PackageFError("dependency exception chain is incomplete in verification")
        elif intersection:
            raise PackageFError("dependency exception chain reaches a non-verification lock")
    return {
        "advisory_id": record["advisory-id"], "owner": record["owner"],
        "valid_through": record["valid-through"].isoformat(),
        "direct_package": record["direct-package"], "lock_path": record["lock-path"],
    }


def validate_publish_order(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    rows = inventory.get("publish-package")
    if not isinstance(rows, list) or len(rows) != 12 or tuple(row.get("name") for row in rows) != PUBLISH_ORDER:
        raise PackageFError("publish order closure differs")
    root_raw, _root_metadata = read_regular_once(
        REPO / "Cargo.toml", label="root workspace manifest"
    )
    root_manifest = parse_toml_strict(root_raw, label="root workspace manifest")
    if root_manifest.get("workspace", {}).get("package", {}).get("version") != "3.0.0":
        raise PackageFError("root workspace version differs from 3.0.0 HOLD baseline")
    manifest_by_package = {
        row["name"]: row["manifest"]
        for row in rows
        if isinstance(row, dict)
        and isinstance(row.get("name"), str)
        and isinstance(row.get("manifest"), str)
    }
    if set(manifest_by_package) != set(PUBLISH_ORDER):
        raise PackageFError("publish manifest mapping differs")
    normalized: list[dict[str, Any]] = []
    external_rows: list[list[str]] = []
    for index, row in enumerate(rows, 1):
        if set(row) != {"order", "name", "manifest", "internal-dependencies"} or row["order"] != index:
            raise PackageFError("publish package row closure differs")
        manifest_raw, _metadata = read_regular_once(REPO / row["manifest"], label=f"publish manifest {row['name']}")
        manifest = parse_toml_strict(manifest_raw, label=f"publish manifest {row['name']}")
        package = manifest.get("package", {})
        if (
            package.get("name") != row["name"]
            or package.get("publish", True) is not True
            or not _same_json_value(package.get("version"), {"workspace": True})
        ):
            raise PackageFError("publish manifest name/effective publish flag differs")
        dependencies: list[str] = []
        for section in ("dependencies", "build-dependencies"):
            for key, value in manifest.get(section, {}).items():
                name = value.get("package", key) if isinstance(value, dict) else key
                if name in PUBLISH_ORDER:
                    if (
                        not isinstance(value, dict)
                        or value.get("version") != "=3.0.0"
                        or not isinstance(value.get("path"), str)
                    ):
                        raise PackageFError(
                            "internal dependency version/path binding differs"
                        )
                    manifest_parent = PurePosixPath(row["manifest"]).parent
                    resolved = PurePosixPath(os.path.normpath(str(
                        manifest_parent / value["path"] / "Cargo.toml"
                    )))
                    if (
                        resolved.is_absolute()
                        or ".." in resolved.parts
                        or str(resolved) != manifest_by_package[name]
                    ):
                        raise PackageFError(
                            "internal dependency manifest path differs"
                        )
                    dependencies.append(name)
                else:
                    version = value.get("version") if isinstance(value, dict) else value
                    if not isinstance(version, str):
                        raise PackageFError("external direct dependency requirement differs")
                    external_rows.append([row["name"], section, name, version])
        observed = sorted(set(dependencies), key=PUBLISH_ORDER.index)
        if (
            len(dependencies) != len(observed)
            or row["internal-dependencies"] != observed
            or any(PUBLISH_ORDER.index(dep) >= index - 1 for dep in observed)
        ):
            raise PackageFError("publish graph/order differs")
        normalized.append({
            "order": index, "name": row["name"], "manifest": row["manifest"],
            "internal_dependencies": observed,
        })
    if sum(len(row["internal_dependencies"]) for row in normalized) != 42:
        raise PackageFError("internal publish edge count differs")
    digest_rows = [[
        row["order"], row["name"], row["manifest"], row["internal_dependencies"]
    ] for row in normalized]
    if sha256_bytes(compact_json(digest_rows)) != inventory["publish-order-rows-sha256"]:
        raise PackageFError("publish order semantic digest differs")
    external_rows.sort()
    if (
        len(external_rows) != inventory["external-direct-dependency-occurrences"]
        or len({row[2] for row in external_rows}) != inventory["external-direct-dependency-identities"]
        or sha256_bytes(compact_json(external_rows)) != inventory["external-direct-dependency-rows-sha256"]
        or [(row[2], row[3]) for row in external_rows].count(("base64", "=0.22.1")) != 3
        or [(row[2], row[3]) for row in external_rows].count(("hex", "=0.4.3")) != 2
    ):
        raise PackageFError("published external direct dependency closure differs")
    return normalized


def validate_tracked_manifest_closure(
    live_tracked_paths: tuple[str, ...] | None = None,
) -> None:
    result = _git(["ls-tree", "-r", "--name-only", "-z", R_F_COMMIT], binary=True)
    if result.returncode != 0:
        raise PackageFError("cannot inspect committed Cargo manifest closure")
    paths = tuple(sorted(
        item.decode("utf-8") for item in result.stdout.split(b"\0")
        if item and (item == b"Cargo.toml" or item.endswith(b"/Cargo.toml"))
    ))
    if paths != TRACKED_CARGO_MANIFESTS:
        raise PackageFError("tracked Cargo manifest closure differs")
    if live_tracked_paths is None:
        live = _git(["ls-files", "-z", "--", "."], binary=True)
        if live.returncode != 0:
            raise PackageFError("cannot inspect current tracked path closure")
        try:
            live_tracked_paths = tuple(sorted(
                item.decode("utf-8") for item in live.stdout.split(b"\0") if item
            ))
        except UnicodeError as error:
            raise PackageFError("current tracked path closure is not UTF-8") from error
    if len(live_tracked_paths) != len(set(live_tracked_paths)):
        raise PackageFError("current tracked path closure contains duplicates")
    live_manifests = tuple(sorted(
        path for path in live_tracked_paths
        if path == "Cargo.toml" or path.endswith("/Cargo.toml")
    ))
    live_locks = tuple(sorted(
        path for path in live_tracked_paths
        if path == "Cargo.lock" or path.endswith("/Cargo.lock")
    ))
    if (
        live_manifests != TRACKED_CARGO_MANIFESTS
        or live_locks != tuple(sorted(path for _workspace, path in LOCK_PATHS))
    ):
        raise PackageFError("current tracked Cargo manifest/lock closure differs")


def validate_workspace_classifications(
    documents: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Join the five reviewed workspace classes to live manifests and policy."""
    paths = (
        "Cargo.toml", "implementation-boundary.toml",
        "verification/Cargo.toml", "fuzz/Cargo.toml",
        "migration/legacy-xchacha20poly1305/Cargo.toml",
        "tools/bench-processor/Cargo.toml",
    )
    if documents is None:
        documents = {}
        for path in paths:
            raw, _metadata = read_regular_once(
                REPO / path, label=f"workspace classification {path}"
            )
            documents[path] = parse_toml_strict(
                raw, label=f"workspace classification {path}"
            )
    if set(documents) != set(paths):
        raise PackageFError("workspace classification document closure differs")
    root = documents["Cargo.toml"]
    boundary = documents["implementation-boundary.toml"]
    members = root.get("workspace", {}).get("members")
    excluded = root.get("workspace", {}).get("exclude")
    expected_members = [
        "crates/api", "crates/common", "crates/internal", "crates/params",
        "crates/algorithms", "crates/symmetric", "crates/kem", "crates/sign",
        "crates/hybrid", "crates/pke", "crates/utils", "tests",
    ]
    expected_excluded = [
        "fuzz", "verification", "migration/legacy-xchacha20poly1305",
    ]
    if (
        members != expected_members or excluded != expected_excluded
        or boundary.get("schema-version") != 2
        or boundary.get("published-packages") != list(PUBLISH_ORDER)
        or boundary.get("verification-workspace") != "verification"
        or boundary.get("fuzz-workspace") != "fuzz"
        or boundary.get("owned-excluded-workspaces") != [{
            "path": "migration/legacy-xchacha20poly1305",
            "allowed-external-normal-build-packages": [
                "base64@0.22.1", "hex@0.4.3",
            ],
        }]
    ):
        raise PackageFError("implementation-boundary workspace classification differs")
    primary_names = [root.get("package", {}).get("name")]
    tests_package: dict[str, Any] | None = None
    for member in expected_members:
        manifest_path = f"{member}/Cargo.toml"
        if manifest_path not in TRACKED_CARGO_MANIFESTS:
            raise PackageFError("primary workspace member manifest is unreviewed")
        raw, _metadata = read_regular_once(
            REPO / manifest_path, label=f"primary workspace member {member}"
        )
        manifest = parse_toml_strict(raw, label=f"primary workspace member {member}")
        primary_names.append(manifest.get("package", {}).get("name"))
        if member == "tests":
            tests_package = manifest.get("package", {})
    if (
        {name for name in primary_names if name in PUBLISH_ORDER} != set(PUBLISH_ORDER)
        or primary_names.count("dcrypt-tests") != 1
        or len(primary_names) != 13
        or not isinstance(tests_package, dict)
        or tests_package.get("name") != "dcrypt-tests"
        or tests_package.get("publish") is not False
        or not _same_json_value(
            tests_package.get("version"), {"workspace": True}
        )
    ):
        raise PackageFError("primary workspace package classification differs")
    expected_auxiliary = {
        "verification/Cargo.toml": (
            "dcrypt-verification", "verification", {"members": ["."], "resolver": "2"},
        ),
        "fuzz/Cargo.toml": ("dcrypt-fuzz", "fuzz", None),
        "migration/legacy-xchacha20poly1305/Cargo.toml": (
            "dcrypt-legacy-xchacha20poly1305-migration", "migration/legacy-xchacha20poly1305",
            {"members": ["."], "resolver": "2"},
        ),
        "tools/bench-processor/Cargo.toml": ("bench-processor", None, {}),
    }
    for path, (name, excluded_path, expected_workspace) in expected_auxiliary.items():
        document = documents[path]
        package = document.get("package", {})
        if (
            package.get("name") != name or package.get("publish") is not False
            or not _same_json_value(document.get("workspace"), expected_workspace)
            or (excluded_path is not None) != (excluded_path in expected_excluded)
        ):
            raise PackageFError(f"auxiliary workspace classification differs: {path}")
    if len(expected_auxiliary) + 1 != EXPECTED_COUNTS["workspace-classifications"]:
        raise PackageFError("workspace classification count differs")


def _validate_inventory_root(inventory: dict[str, Any]) -> None:
    if set(inventory) != INVENTORY_KEYS:
        raise PackageFError("reviewed inventory top-level closure differs")
    for key, expected in EXPECTED_COUNTS.items():
        if inventory.get(key) != expected:
            raise PackageFError(f"reviewed count differs: {key}")
    if (
        inventory.get("schema-version") != 1
        or inventory.get("content-policy") != "dcrypt-package-f-reviewed-supply-chain-foundation-v1"
        or inventory.get("status") != "HOLD" or inventory.get("release-gate") != "HOLD"
        or inventory.get("release-exit-code") != 3
        or inventory.get("workspace-version") != "3.0.0"
        or any(inventory.get(key) is not False for key in (
            "version-preparation-authorized", "publish-eligible", "promotion-eligible"
        ))
        or inventory.get("a-e-commit") != A_E_COMMIT or inventory.get("a-e-tree") != A_E_TREE
        or inventory.get("s-f-commit") != S_F_COMMIT or inventory.get("s-f-tree") != S_F_TREE
        or inventory.get("r-f-commit") != R_F_COMMIT or inventory.get("r-f-tree") != R_F_TREE
        or inventory.get("r-f-subject-manifest-sha256") != R_F_SUBJECT_MANIFEST_SHA256
        or inventory.get("r-f-subject-manifest-files") != 1511
        or inventory.get("r-f-subject-manifest-size") != 296233
        or inventory.get("r-f-atomic-operations-sha256") != R_F_ATOMIC_OPERATIONS_SHA256
        or inventory.get("r-f-public-api-snapshot-sha256") != R_F_PUBLIC_API_SNAPSHOT_SHA256
    ):
        raise PackageFError("reviewed inventory identity/HOLD differs")


def _validate_committed_inputs(inventory: dict[str, Any]) -> None:
    for key, commit, expected_paths in (
        ("source-prerequisite", S_F_COMMIT, S_F_PATHS),
        ("rebind-input", R_F_COMMIT, R_F_PATHS),
    ):
        rows = inventory.get(key)
        if not isinstance(rows, list) or tuple(sorted(row.get("path", "") for row in rows)) != expected_paths:
            raise PackageFError(f"{key} path closure differs")
        for row in rows:
            if set(row) != {"path", "git-mode", "size", "sha256"}:
                raise PackageFError(f"{key} row closure differs")
            mode, raw = _git_blob(commit, row["path"])
            if (mode, len(raw), sha256_bytes(raw)) != (row["git-mode"], row["size"], row["sha256"]):
                raise PackageFError(f"{key} committed binding differs: {row['path']}")


def validate_s_f_semantics() -> None:
    """Independently enforce the committed S_F policy, not only its blob hashes."""
    workflow = _git_blob(S_F_COMMIT, ".github/workflows/security-validation.yml")[1].decode("utf-8")
    publish = _git_blob(S_F_COMMIT, "tools/verify-publish-ready.sh")[1].decode("utf-8")
    release = _git_blob(S_F_COMMIT, "tools/release-dcrypt.sh")[1].decode("utf-8")
    remote = _git_blob(S_F_COMMIT, "tools/verify-remote-release-ready.py")[1].decode("utf-8")
    if (
        workflow.count("          toolchain: 1.93.1\n") != 7
        or re.search(r"(?m)^\s*toolchain:\s*stable\s*$", workflow) is not None
        or workflow.count("      DCRYPT_ASSEMBLY_TOOLCHAIN: 1.93.1\n") != 1
    ):
        raise PackageFError("committed S_F workflow selector closure differs")
    workflow_f = (
        "python3 -B assurance/supply-chain/generate.py --check",
        "python3 -B assurance/supply-chain/verify.py --ci",
        "python3 -B assurance/supply-chain/selftest.py",
        "python3 -B assurance/supply-chain/verify.py --release",
        'test "$supply_chain_release_rc" -eq 3',
    )
    publish_f = (
        'assurance/supply-chain/generate.py" --check',
        'assurance/supply-chain/verify.py" --ci',
        "assurance/supply-chain/selftest.py",
        'assurance/supply-chain/verify.py" --release',
        '[[ "$supply_chain_release_rc" -eq 3 ]]',
        "Package F release HOLD remains explicit and release-blocking",
    )
    bench_ci = (
        "cargo fmt --manifest-path tools/bench-processor/Cargo.toml -- --check",
        "--manifest-path tools/bench-processor/Cargo.toml",
        "cargo audit --file tools/bench-processor/Cargo.lock",
        "cargo deny --manifest-path tools/bench-processor/Cargo.toml",
    )
    bench_local = (
        'tools/bench-processor/Cargo.toml" -- --check',
        'tools/bench-processor/Cargo.toml"',
        'tools/bench-processor/Cargo.lock"',
    )
    if (
        any(workflow.count(fragment) != 1 for fragment in workflow_f)
        or any(publish.count(fragment) != 1 for fragment in publish_f)
        or any(fragment not in workflow for fragment in bench_ci)
        or any(fragment not in release for fragment in bench_local)
        or "Package F publish HOLD rc 3 differs" not in remote
        or "Package F publish HOLD propagation differs" not in remote
    ):
        raise PackageFError("committed S_F Package F/HOLD/bench wiring differs")
    bench = parse_toml_strict(
        _git_blob(S_F_COMMIT, "tools/bench-processor/Cargo.toml")[1],
        label="committed S_F bench manifest",
    )
    if bench.get("package") != {
        "name": "bench-processor", "version": "0.1.0", "edition": "2021", "publish": False,
    } or set(bench) != {"package", "workspace", "dependencies"} or bench.get("workspace") != {}:
        raise PackageFError("committed S_F bench package classification differs")
    if bench.get("dependencies") != {
        "serde": {"version": "=1.0.228", "features": ["derive"]},
        "serde_json": "=1.0.145", "regex": "=1.12.2",
        "clap": {"version": "=4.5.53", "features": ["derive"]},
        "walkdir": "=2.5.0",
    }:
        raise PackageFError("committed S_F bench direct-pin closure differs")


def validate_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    _validate_inventory_root(inventory)
    validate_topology()
    validate_tracked_manifest_closure()
    validate_workspace_classifications()
    _validate_committed_inputs(inventory)
    validate_s_f_semantics()
    locks = validate_locks(inventory)
    dependency_exception = validate_dependency_exception(inventory)
    publish_order = validate_publish_order(inventory)
    sboms = inventory.get("sbom-slot")
    expected_sboms = [
        {"id": item, "workspace-lock": item, "format": "CycloneDX", "spec-version": "1.6",
         "status": "blocked", "accepted": False}
        for item in SBOM_IDS
    ]
    if not isinstance(sboms, list) or sboms != expected_sboms:
        raise PackageFError("SBOM slot closure differs")
    subjects = inventory.get("artifact-subject")
    producers = inventory.get("producer-class")
    expected_subject_rows = [
        {"id": f"sbom-{item}", "class": "sbom", "workspace": item, "status": "blocked"}
        for item in SBOM_IDS
    ] + [
        {"id": f"crate-{item}", "class": "candidate-crate-archive", "package": item, "status": "blocked"}
        for item in PUBLISH_ORDER
    ] + [{"id": "canonical-source-archive", "class": "source-archive", "status": "blocked"}]
    if (
        not isinstance(subjects, list) or subjects != expected_subject_rows
        or sha256_bytes(compact_json(sorted([list(row) for row in ARTIFACT_SUBJECTS])))
        != ARTIFACT_SUBJECT_SET_SHA256
        or inventory.get("artifact-subject-set-sha256") != ARTIFACT_SUBJECT_SET_SHA256
        or not isinstance(producers, list) or producers != [
            {"id": "first-party", "required-subjects": 18, "completed-subjects": 0, "accepted": False},
            {"id": "administratively-independent", "required-subjects": 18, "completed-subjects": 0, "accepted": False},
        ]
    ):
        raise PackageFError("artifact subject/producer obligation closure differs")
    bench = inventory.get("bench-workspace-classification")
    if bench != {
        "path": "tools/bench-processor",
        "classification": "auxiliary-workspace-not-in-audit-command-graph",
        "publish": False, "lock-required": True, "status": "classified",
        "zero-unsafe-claim": False, "exact-local-toolchain-execution-claim": False,
    }:
        raise PackageFError("bench auxiliary classification differs")
    toolchains = inventory.get("toolchain-selector")
    if not isinstance(toolchains, list) or toolchains != [{
        "id": "stable-release", "selector": "1.93.1",
        "rustc-commit": "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf",
        "rustdoc-commit": "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf",
        "cargo-commit": "083ac5135f967fd9dc906ab057a2315861c7a80d",
        "llvm": "21.1.8", "host": "x86_64-unknown-linux-gnu",
        "targets": [
            "aarch64-unknown-linux-gnu", "thumbv7em-none-eabihf",
            "wasm32-unknown-unknown", "x86_64-unknown-linux-gnu",
        ],
        "availability": "metadata-only-blocked",
        "limitation": "toolchain-distribution-bundle-unavailable",
        "distribution-status": "blocked",
    }]:
        raise PackageFError("stable toolchain selector/nonclaim differs")
    blockers = inventory.get("supply-chain-blocker")
    expected_blockers = [
        {"id": "dependency-provision-bundle-unavailable", "owner": "dcrypt release engineering", "status": "blocked"},
        {"id": "action-source-archives-unavailable", "owner": "dcrypt CI security", "status": "blocked"},
        {"id": "rustsec-database-unbound", "owner": "dcrypt dependency security", "status": "blocked"},
        {"id": "toolchain-distribution-bundle-unavailable", "owner": "dcrypt release engineering", "status": "blocked"},
        {"id": "ambient-local-cargo-invocation-not-byte-bound", "owner": "dcrypt release engineering", "status": "blocked"},
    ]
    if not isinstance(blockers, list) or blockers != expected_blockers:
        raise PackageFError("supply-chain blocker closure differs")
    antecedents = inventory.get("antecedent")
    if not isinstance(antecedents, list) or len(antecedents) != 2:
        raise PackageFError("antecedent closure differs")
    expected_antecedents = {
        "dcrypt-v3.0.0-audit-candidate-003": {
            "path": "assurance/audit/freezes/dcrypt-v3.0.0-audit-candidate-003/freeze.json",
            "sha256": "fbf38be9f0bfa11fb077968685ce2d9279411d110a9f4b0b43ebd012803bd49a",
            "classification": "historical-immutable-gap-evidence-only", "accepted": False,
        },
        "audit-provisioning-lock": {
            "path": "assurance/audit/provisioning-lock.toml",
            "sha256": "3733ed23be2f93e6a756162bde9a841ab4a165037ccc1c0a22d3e23bd5030177",
            "classification": "reviewed-selector-commit-input-operational-distribution-blocked",
            "accepted": False,
        },
    }
    if [row.get("id") for row in antecedents] != [
        "dcrypt-v3.0.0-audit-candidate-003", "audit-provisioning-lock"
    ]:
        raise PackageFError("antecedent identity/order closure differs")
    for row in antecedents:
        identity = row.get("id")
        if identity not in expected_antecedents or row != {"id": identity, **expected_antecedents[identity]}:
            raise PackageFError("antecedent row differs")
        mode, raw = _git_blob(R_F_COMMIT, row["path"])
        if mode != "100644" or sha256_bytes(raw) != row["sha256"]:
            raise PackageFError("committed antecedent binding differs")
    provisioning = parse_toml_strict(
        _git_blob(R_F_COMMIT, "assurance/audit/provisioning-lock.toml")[1],
        label="committed provisioning lock",
    )
    stable = [row for row in provisioning.get("toolchain", []) if row.get("id") == "release-stable-reviewed"]
    inventory_stable = {
        key: value for key, value in toolchains[0].items()
        if key not in {"distribution-status", "selector", "id"}
    }
    inventory_stable["id"] = "release-stable-reviewed"
    inventory_stable["requested"] = toolchains[0]["selector"]
    if len(stable) != 1 or inventory_stable != stable[0] or toolchains[0]["selector"] != stable[0]["requested"]:
        raise PackageFError("reviewed stable toolchain metadata differs from provisioning lock")
    blocked = inventory.get("blocked-slot")
    expected_blocked = [
        ("candidate-crate-archives", "crate-archives", 12, "dcrypt release engineering"),
        ("registry-crate-archives", "registry-archives", 12, "dcrypt release engineering"),
        ("canonical-source-archive", "source-archive", 1, "dcrypt release engineering"),
        ("signed-attestations", "signature-attestation", 18, "dcrypt supply-chain assurance"),
        ("independent-offline-rebuild", "independent-offline-rebuild", 18, "independent assurance reviewer"),
        ("immutable-build-environment", "container-image", 0, "dcrypt release engineering"),
        ("hosted-runner-identity", "runner-image", 0, "dcrypt CI security"),
        ("toolchain-distribution", "toolchain-distribution", 0, "dcrypt release engineering"),
    ]
    if not isinstance(blocked, list) or blocked != [
        {"id": identity, "role": role, "expected-members": members, "owner": owner,
         "status": "blocked", "accepted": False}
        for identity, role, members, owner in expected_blocked
    ]:
        raise PackageFError("typed blocked-slot closure differs")
    return {"locks": locks, "dependency_exception": dependency_exception, "publish_order": publish_order}


def _file_binding(path: str) -> dict[str, Any]:
    raw, metadata = read_regular_once(REPO / path, label=f"Package F input {path}")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o111:
        raise PackageFError(f"Package F input unexpectedly maps to executable Git mode: {path}")
    return {
        "git_mode": "100644", "path": path,
        "sha256": sha256_bytes(raw), "size": len(raw),
    }


def validate_core_inputs() -> list[dict[str, Any]]:
    specifications = (
        ("assurance/subject-manifest.json", R_F_SUBJECT_MANIFEST_SHA256),
        ("assurance/atomic-operations.toml", R_F_ATOMIC_OPERATIONS_SHA256),
        ("assurance/public-api-snapshot.json", R_F_PUBLIC_API_SNAPSHOT_SHA256),
    )
    bindings: list[dict[str, Any]] = []
    documents: dict[str, Any] = {}
    raw_sizes: dict[str, int] = {}
    for path, digest in specifications:
        raw, metadata = read_regular_once(REPO / path, label=f"Package F core {path}", maximum=64 << 20)
        if sha256_bytes(raw) != digest or stat.S_IMODE(metadata.st_mode) & 0o111:
            raise PackageFError(f"Package F core digest differs: {path}")
        documents[path] = (
            parse_toml_strict(raw, label=path) if path.endswith(".toml")
            else parse_json_strict(raw, label=path, require_canonical=False)
        )
        raw_sizes[path] = len(raw)
        bindings.append({"git_mode": "100644", "path": path, "sha256": digest, "size": len(raw)})
    subject = documents["assurance/subject-manifest.json"]
    if (
        not isinstance(subject, dict) or set(subject) != {
            "absent_build_inputs", "files", "include_policy", "root_files", "roots",
            "schema_version", "source_commit", "source_tree",
        } or subject.get("schema_version") != 1
        or subject.get("source_commit") != R_F_COMMIT or subject.get("source_tree") != R_F_TREE
        or subject.get("include_policy") != "production-and-evidence-v1"
        or subject.get("roots") != ["."]
        or subject.get("root_files") != [
            "Cargo.lock", "Cargo.toml", "CONSTANT_TIME_POLICY.md", "README.md",
            "SECURITY.md", "deny.toml", "implementation-boundary.toml",
        ]
        or subject.get("absent_build_inputs") != [
            ".cargo/config", ".cargo/config.toml", "build.rs", "rust-toolchain",
            "rust-toolchain.toml",
        ]
        or not isinstance(subject.get("files"), list) or len(subject["files"]) != 1511
        or raw_sizes["assurance/subject-manifest.json"] != 296233
        or [row.get("path") for row in subject["files"]] != sorted(row.get("path") for row in subject["files"])
        or len({row.get("path") for row in subject["files"] if isinstance(row, dict)}) != 1511
        or any(
            not isinstance(row, dict) or set(row) != {"git_mode", "path", "sha256"}
            or row["git_mode"] not in {"100644", "100755"}
            or HEX64.fullmatch(row["sha256"] or "") is None
            for row in subject["files"]
        )
    ):
        raise PackageFError("R_F subject manifest identity/count closure differs")
    for row in subject["files"]:
        safe_relative_path(row["path"], label="R_F subject manifest path")
    atomic = documents["assurance/atomic-operations.toml"]
    if (
        set(atomic) != {"schema-version", "operation", "unreviewed-gap-defaults", "unreviewed-gap"}
        or atomic.get("schema-version") != 2 or len(atomic.get("operation", [])) != 566
        or len(atomic.get("unreviewed-gap", [])) != 8632
        or len(atomic.get("operation", [])) + len(atomic.get("unreviewed-gap", [])) != 9198
    ):
        raise PackageFError("atomic operation row closure differs")
    public = documents["assurance/public-api-snapshot.json"]
    if (
        set(public) != {
            "boundary_policy_sha256", "cargo_commit", "entries", "profiles", "rustc_commit",
            "rustdoc_commit", "rustdoc_format_version", "rustdoc_toolchain", "schema_version",
            "source_commit", "source_tree",
        }
        or public.get("schema_version") != 2 or public.get("source_commit") != R_F_COMMIT
        or public.get("source_tree") != R_F_TREE or len(public.get("entries", [])) != 18891
    ):
        raise PackageFError("public API snapshot identity/count closure differs")
    return bindings


def build_package_document() -> dict[str, Any]:
    inventory, inventory_raw = load_reviewed_inventory()
    semantics = validate_inventory(inventory)
    inputs = [
        *validate_core_inputs(),
        _file_binding("deny.toml"),
        _file_binding("verification/Cargo.toml"),
        *[_file_binding(path) for _workspace, path in LOCK_PATHS],
    ]
    document = {
        "artifact_role": "package-f-supply-chain-foundation",
        "content_policy": "dcrypt-package-f-local-foundation-v1",
        "counts": {key.replace("-", "_"): value for key, value in EXPECTED_COUNTS.items()},
        "dependency_exception": semantics["dependency_exception"],
        "evidence_state": {
            "accepted": False, "captured_candidates": 0,
            "independent_rebuilds_accepted": 0, "signatures_accepted": 0,
            "sboms_accepted": 0, "trusted": False,
        },
        "input_bindings": sorted(inputs, key=lambda row: row["path"]),
        "lock_graph": semantics["locks"],
        "promotion_effect": "none",
        "publish_order": semantics["publish_order"],
        "release_state": {
            "promotion_eligible": False, "publish_eligible": False,
            "release_gate": "HOLD", "release_gate_exit_code": 3,
            "version_preparation_authorized": False,
        },
        "reviewed_inventory_sha256": sha256_bytes(inventory_raw),
        "schema_version": 1,
        "status": "local-foundation-complete-operational-evidence-absent",
        "subject_binding": {
            "a_e_commit": A_E_COMMIT, "a_e_tree": A_E_TREE,
            "r_f_commit": R_F_COMMIT, "r_f_tree": R_F_TREE,
            "r_f_subject_manifest_sha256": R_F_SUBJECT_MANIFEST_SHA256,
            "s_f_commit": S_F_COMMIT, "s_f_tree": S_F_TREE,
        },
        "workspace_version": "3.0.0",
    }
    return document


def _closed_object(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "additionalProperties": False, "properties": properties,
        "required": sorted(required if required is not None else properties), "type": "object",
    }


def _digest_schema() -> dict[str, Any]:
    return {"pattern": "^[0-9a-f]{64}$", "type": "string"}


def _artifact_schema(
    subject_id: str | None = None,
    artifact_class: str | None = None,
    *,
    maximum_size: int = 67_108_864,
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "artifact_class": {"enum": [
            "sbom", "signature-envelope", "attestation", "certificate-chain",
            "trust-root", "transparency-proof", "source-archive", "crate-archive",
            "build-manifest", "rebuild-report",
        ]} if artifact_class is None else {"const": artifact_class},
        "file_mode": {"const": "0600"},
        "path": {
            "maxLength": 512,
            "minLength": 1,
            "pattern": "^(?!(?:.*?/)?(?:\\.|\\.\\.)(?:/|$))[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*$",
            "type": "string",
        },
        "sha256": _digest_schema(),
        "size": {"maximum": maximum_size, "minimum": 1, "type": "integer"},
        "subject_id": ({"maxLength": 128, "minLength": 1, "pattern": "^[A-Za-z0-9._+@/-]+$", "type": "string"}
                       if subject_id is None else {"const": subject_id}),
    }
    return _closed_object(properties)


def _role_artifact_specs(role: str) -> tuple[tuple[str, str], ...]:
    if role == "local-foundation-proof":
        return (("package-f-local-foundation", "build-manifest"),)
    if role == "first-party-build-candidate":
        return tuple(sorted(ARTIFACT_SUBJECTS))
    if role == "signature-transparency-candidate":
        return (
            ("attestation", "attestation"), ("certificate-chain", "certificate-chain"),
            ("signature-envelope", "signature-envelope"),
            ("transparency-proof", "transparency-proof"), ("trust-root", "trust-root"),
        )
    if role == "independent-rebuild-candidate":
        return tuple(sorted((
            *ARTIFACT_SUBJECTS,
            ("independent-build-manifest", "build-manifest"),
            ("rebuild-comparison-report", "rebuild-report"),
        )))
    if role == "acceptance":
        return (("attestation", "attestation"),)
    raise PackageFError(f"unknown role artifact closure: {role}")


def _subject_schema() -> dict[str, Any]:
    return _closed_object({
        "r_commit": {"const": R_F_COMMIT}, "r_tree": {"const": R_F_TREE},
        "subject_manifest_sha256": {"const": R_F_SUBJECT_MANIFEST_SHA256},
    })


def _role_data_schema(role: str) -> dict[str, Any]:
    if role == "local-foundation-proof":
        return _closed_object({
            "evidence_effect": {"const": "structural-only"}, "generated": {"const": True},
            "lock_occurrences": {"const": 342}, "publishable_packages": {"const": 12},
            "release_blocked_atomic_rows": {"const": 9198}, "sbom_slots": {"const": 5},
        })
    if role == "first-party-build-candidate":
        return _closed_object({
            "accepted_subjects": {"const": 0}, "artifact_subject_count": {"const": 18},
            "cache_policy": {"const": "cold-bound-provisioning-only"},
            "crate_archive_count": {"const": 12}, "producer_class": {"const": "first-party"},
            "environment_sha256": _digest_schema(), "invocation_sha256": _digest_schema(),
            "materials_sha256": _digest_schema(), "network_policy": {"const": "offline"},
            "producer_identity_sha256": _digest_schema(),
            "artifact_subject_set_sha256": {"const": ARTIFACT_SUBJECT_SET_SHA256},
            "command_target_profile_sha256": _digest_schema(),
            "dsse_envelope_sha256": _digest_schema(),
            "in_toto_statement_sha256": _digest_schema(),
            "in_toto_statement_type": {"const": "https://in-toto.io/Statement/v1"},
            "slsa_predicate_sha256": _digest_schema(),
            "slsa_predicate_type": {"const": "https://slsa.dev/provenance/v1"},
            "source_and_lock_input_set_sha256": _digest_schema(),
            "sbom_count": {"const": 5}, "sbom_format": {"const": "CycloneDX"},
            "sbom_spec_version": {"const": "1.6"}, "source_archive_count": {"const": 1},
            "toolchain_distribution_verified": {"const": False},
            "toolchain_bundle_sha256": _digest_schema(),
            "workspace_ids": {"const": list(SBOM_IDS)},
        })
    if role == "signature-transparency-candidate":
        return _closed_object({
            "accepted_attestations": {"const": 0}, "cryptographic_verification_completed": {"const": False},
            "dsse_payload_type": {"const": "application/vnd.in-toto+json"},
            "envelope_sha256": _digest_schema(), "identity_verified": {"const": False},
            "first_party_artifact_set_sha256": _digest_schema(),
            "in_toto_statement_type": {"const": "https://in-toto.io/Statement/v1"},
            "signed_subject_set_sha256": {"const": ARTIFACT_SUBJECT_SET_SHA256},
            "slsa_predicate_type": {"const": "https://slsa.dev/provenance/v1"},
            "signature_count": {"const": 18},
            "signer_identity_sha256": _digest_schema(), "subject_count": {"const": 18},
            "timestamp_binding_sha256": _digest_schema(), "transparency_verified": {"const": False},
            "trust_root_sha256": _digest_schema(), "trust_root_verified": {"const": False},
        })
    if role == "independent-rebuild-candidate":
        return _closed_object({
            "accepted_rebuilds": {"const": 0}, "administrative_independence_claimed": {"const": True},
            "administrative_independence_verified": {"const": False}, "artifact_subject_count": {"const": 18},
            "byte_comparison_report_sha256": _digest_schema(), "cache_policy": {"const": "cold-bound-provisioning-only"},
            "artifact_subject_set_sha256": {"const": ARTIFACT_SUBJECT_SET_SHA256},
            "command_target_profile_sha256": _digest_schema(),
            "environment_sha256": _digest_schema(), "first_party_artifact_set_sha256": _digest_schema(),
            "invocation_sha256": _digest_schema(),
            "materials_sha256": _digest_schema(),
            "matching_subjects": {"minimum": 0, "maximum": 18, "type": "integer"},
            "mismatching_subjects": {"minimum": 0, "maximum": 18, "type": "integer"},
            "network_policy": {"const": "offline"}, "producer_identity_sha256": _digest_schema(),
            "replayer_identity_sha256": _digest_schema(), "toolchain_bundle_sha256": _digest_schema(),
            "source_and_lock_input_set_sha256": _digest_schema(),
        })
    if role == "acceptance":
        return _closed_object({
            "accepted": {"const": False}, "decision": {"const": "disabled"},
            "reason": {"minLength": 1, "maxLength": 1024, "type": "string"},
        })
    raise PackageFError(f"unknown Package F role: {role}")


def _role_schema(role: str) -> dict[str, Any]:
    specs = _role_artifact_specs(role)
    maximum_size = ROLE_CAPS.get(role, {"per_file": 67_108_864})["per_file"]
    return _closed_object({
        "artifact_role": {"const": role},
        "artifacts": {
            "allOf": [
                {
                    "contains": _artifact_schema(
                        subject, kind, maximum_size=maximum_size
                    ),
                    "maxContains": 1,
                    "minContains": 1,
                }
                for subject, kind in specs
            ],
            "items": _artifact_schema(maximum_size=maximum_size),
            "maxItems": len(specs), "minItems": len(specs), "type": "array",
        },
        "content_policy": {"const": ROLE_POLICIES[role]}, "promotion_eligible": {"const": False},
        "raw_artifact_set_sha256": _digest_schema(), "role_data": _role_data_schema(role),
        "schema_version": {"const": 1}, "status": {"const": ROLE_STATUSES[role]},
        "subject_binding": _subject_schema(), "trusted": {"const": False},
    })


def build_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "oneOf": [_role_schema(role) for role in ROLE_POLICIES],
        "title": "dcrypt Package F nonpromotable supply-chain candidate roles",
    }


def artifact_set_sha256(artifacts: list[dict[str, Any]]) -> str:
    return sha256_bytes(compact_json(artifacts))


def _same_json_value(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _same_json_value(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same_json_value(a, b) for a, b in zip(left, right, strict=True)
        )
    return bool(left == right)


def _schema_scalar(value: Any, schema: dict[str, Any], *, label: str) -> None:
    if "const" in schema and not _same_json_value(value, schema["const"]):
        raise PackageFError(f"{label} differs from role constant")
    if "enum" in schema and not any(
        _same_json_value(value, option) for option in schema["enum"]
    ):
        raise PackageFError(f"{label} differs from role enum")
    kind = schema.get("type")
    if kind == "string":
        if not isinstance(value, str) or len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1 << 30):
            raise PackageFError(f"{label} string differs")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise PackageFError(f"{label} pattern differs")
    elif kind == "integer":
        if not isinstance(value, int) or isinstance(value, bool) or value < schema.get("minimum", -(1 << 63)) or value > schema.get("maximum", 1 << 63):
            raise PackageFError(f"{label} integer differs")
    elif kind == "boolean" and not isinstance(value, bool):
        raise PackageFError(f"{label} boolean differs")


def _validate_closed_schema(value: Any, schema: dict[str, Any], *, label: str) -> None:
    if schema.get("type") == "object":
        if not isinstance(value, dict) or set(value) != set(schema["required"]):
            raise PackageFError(f"{label} object closure differs")
        for key, item in value.items():
            _validate_closed_schema(item, schema["properties"][key], label=f"{label}.{key}")
        return
    if schema.get("type") == "array":
        if not isinstance(value, list) or len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1 << 30):
            raise PackageFError(f"{label} array differs")
        if "const" in schema:
            if not _same_json_value(value, schema["const"]):
                raise PackageFError(f"{label} array constant differs")
            return
        for index, item in enumerate(value):
            _validate_closed_schema(item, schema["items"], label=f"{label}[{index}]")
        for index, condition in enumerate(schema.get("allOf", [])):
            contains = condition["contains"]
            matches = 0
            for item in value:
                try:
                    _validate_closed_schema(item, contains, label=f"{label} contains")
                except PackageFError:
                    continue
                matches += 1
            if not condition["minContains"] <= matches <= condition["maxContains"]:
                raise PackageFError(f"{label} exact role artifact mapping {index} differs")
        return
    _schema_scalar(value, schema, label=label)


def validate_schema_value(value: Any) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("artifact_role"), str):
        raise PackageFError("candidate lacks an exact role")
    role = value["artifact_role"]
    if role not in ROLE_POLICIES:
        raise PackageFError("candidate role is unknown")
    _validate_closed_schema(value, _role_schema(role), label="candidate")
    artifacts = value["artifacts"]
    paths = [row["path"] for row in artifacts]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise PackageFError("candidate artifact paths are not sorted and unique")
    for path in paths:
        safe_relative_path(path, label="candidate artifact path")
    if value["raw_artifact_set_sha256"] != artifact_set_sha256(artifacts):
        raise PackageFError("candidate artifact-set digest differs")
    subject_classes = [(row["subject_id"], row["artifact_class"]) for row in artifacts]
    if role == "first-party-build-candidate" and sorted(subject_classes) != sorted(ARTIFACT_SUBJECTS):
        raise PackageFError("first-party artifact subject closure differs")
    if role == "independent-rebuild-candidate" and sorted(subject_classes) != sorted((
        *ARTIFACT_SUBJECTS,
        ("independent-build-manifest", "build-manifest"),
        ("rebuild-comparison-report", "rebuild-report"),
    )):
        raise PackageFError("independent rebuild artifact closure differs")
    if role == "signature-transparency-candidate" and sorted(subject_classes) != sorted((
        ("attestation", "attestation"),
        ("certificate-chain", "certificate-chain"),
        ("signature-envelope", "signature-envelope"),
        ("transparency-proof", "transparency-proof"),
        ("trust-root", "trust-root"),
    )):
        raise PackageFError("signature/transparency artifact closure differs")
    by_subject = {row["subject_id"]: row for row in artifacts}
    if role == "signature-transparency-candidate" and (
        value["role_data"]["envelope_sha256"] != by_subject["signature-envelope"]["sha256"]
        or value["role_data"]["trust_root_sha256"] != by_subject["trust-root"]["sha256"]
    ):
        raise PackageFError("signature named artifact digest join differs")
    if role == "independent-rebuild-candidate" and (
        value["role_data"]["byte_comparison_report_sha256"]
        != by_subject["rebuild-comparison-report"]["sha256"]
    ):
        raise PackageFError("rebuild comparison artifact digest join differs")
    return role


def validate_control_fixture(value: Any | None = None) -> dict[str, Any]:
    """Validate the deliberately non-evidentiary parser/path control index."""
    if value is None:
        raw, _metadata = read_regular_once(
            FRAMEWORK / "fixtures/control.json",
            label="Package F parser-smoke fixture",
            maximum=64 << 10,
        )
        value = parse_json_strict(
            raw, label="Package F parser-smoke fixture", require_canonical=True
        )
    expected = {
        "content_policy": "dcrypt-package-f-parser-smoke-control-v1",
        "controls": [
            "artifact-mode", "double-slash", "duplicate-json-key",
            "empty-artifact", "float", "non-nfc", "noncanonical-order",
            "traversal",
        ],
        "evidence_effect": "none",
        "purpose": "parser-and-path-negative-control-index",
        "schema_version": 1,
        "status": "synthetic-not-evidence",
        "trusted": False,
    }
    if not _same_json_value(value, expected):
        raise PackageFError("Package F parser-smoke fixture closure differs")
    return expected


def validate_evidence_candidate(value: Any, *, capture: bool = False) -> str:
    role = validate_schema_value(value)
    if role == "acceptance":
        raise PackageFError("Package F v1 acceptance is disabled")
    if capture and role not in CAPTURE_ADMISSIBLE_ROLES:
        raise PackageFError(f"Package F role is not capture-admissible: {role}")
    if value["trusted"] is not False or value["promotion_eligible"] is not False:
        raise PackageFError("Package F candidates never imply trust or promotion")
    if role == "independent-rebuild-candidate":
        data = value["role_data"]
        if data["matching_subjects"] + data["mismatching_subjects"] != 18:
            raise PackageFError("rebuild comparison totals differ")
        if data["producer_identity_sha256"] == data["replayer_identity_sha256"]:
            raise PackageFError("rebuild producer/replayer identities are not separated")
    return role


def build_local_foundation_proof() -> dict[str, Any]:
    package_raw = canonical_json(build_package_document())
    artifacts = [{
        "artifact_class": "build-manifest", "file_mode": "0600", "path": "package-f.json",
        "sha256": sha256_bytes(package_raw), "size": len(package_raw),
        "subject_id": "package-f-local-foundation",
    }]
    value = {
        "artifact_role": "local-foundation-proof", "artifacts": artifacts,
        "content_policy": ROLE_POLICIES["local-foundation-proof"],
        "promotion_eligible": False, "raw_artifact_set_sha256": artifact_set_sha256(artifacts),
        "role_data": {
            "evidence_effect": "structural-only", "generated": True,
            "lock_occurrences": 342, "publishable_packages": 12,
            "release_blocked_atomic_rows": 9198, "sbom_slots": 5,
        },
        "schema_version": 1, "status": ROLE_STATUSES["local-foundation-proof"],
        "subject_binding": {
            "r_commit": R_F_COMMIT, "r_tree": R_F_TREE,
            "subject_manifest_sha256": R_F_SUBJECT_MANIFEST_SHA256,
        },
        "trusted": False,
    }
    validate_evidence_candidate(value)
    return value


def validate_package_document(document: Any) -> None:
    expected_keys = {
        "artifact_role", "content_policy", "counts", "dependency_exception",
        "evidence_state", "input_bindings", "lock_graph", "promotion_effect",
        "publish_order", "release_state", "reviewed_inventory_sha256", "schema_version",
        "status", "subject_binding", "workspace_version",
    }
    if (
        not isinstance(document, dict) or set(document) != expected_keys
        or document.get("schema_version") != 1
        or document.get("artifact_role") != "package-f-supply-chain-foundation"
        or document.get("content_policy") != "dcrypt-package-f-local-foundation-v1"
        or document.get("status") != "local-foundation-complete-operational-evidence-absent"
        or document.get("promotion_effect") != "none" or document.get("workspace_version") != "3.0.0"
        or document.get("reviewed_inventory_sha256") != sha256_bytes(load_reviewed_inventory()[1])
        or document.get("release_state") != {
            "promotion_eligible": False, "publish_eligible": False,
            "release_gate": "HOLD", "release_gate_exit_code": 3,
            "version_preparation_authorized": False,
        }
        or document.get("evidence_state") != {
            "accepted": False, "captured_candidates": 0,
            "independent_rebuilds_accepted": 0, "signatures_accepted": 0,
            "sboms_accepted": 0, "trusted": False,
        }
        or not isinstance(document.get("input_bindings"), list)
        or len(document["input_bindings"]) != 10
        or any(row.get("git_mode") != "100644" for row in document["input_bindings"])
    ):
        raise PackageFError("Package F document identity/closure differs")
    if not _same_json_value(document, build_package_document()):
        raise PackageFError("Package F document nested reviewed semantics differ")


def artifact_source_files() -> tuple[str, ...]:
    return (
        "README.md", "capture.py", "fixtures/control.json", "generate.py", "model.py",
        "rebind-final-subject.py", "reviewed-inventory.toml", "selftest.py", "verify.py",
    )
