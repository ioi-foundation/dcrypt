#!/usr/bin/env python3
"""Normative, fail-closed Package D side-channel assurance model."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import sys
import tomllib
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True

FRAMEWORK = Path(__file__).resolve().parent
REPO = FRAMEWORK.parent.parent
INVENTORY = FRAMEWORK / "reviewed-inventory.toml"
SUBJECT_COMMIT = "276b78f9b3c2aed91d2548ab9add721c434ded06"
SUBJECT_TREE = "c47c98062c43463818bb61bd3eed75ebaf189e1d"
SUBJECT_MANIFEST_SHA256 = "d48d134daa383fb12c03e45aebe3bcf16f40e2c6930e17f209e0af95f1133eb4"
ATOMIC_SHA256 = "8e745ab16086aa50e265ad79189375270c5906df8545f540d96426bc348ca11a"
PUBLIC_SNAPSHOT_SHA256 = "0a7c7d6585b6612f35e9dd5622018ca3c87c5fb51f8fa0e4652904d651c6215f"
REVIEWED_INVENTORY_SHA256 = "22c9992bebfdb5d83f2b818fa2d9576f524bf34c3334c4c51b3d8c85a7c51097"
EXPECTED_ROW_IDS_SHA256 = "ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff"
EXPECTED_SOURCE_ROWS_SHA256 = "e35cb1924e6f4480a557651db3fdebec3b9d1518d42160a8e7895c000f21f2f5"
EXPECTED_SOURCE_PATHS_SHA256 = "5aae5258561c750a920b36be67c2652f28ea1c8536ad7527f73967633a62b804"
EXPECTED_SOURCE_ROOTS_SHA256 = "3bdf8ea3f968c18983d73ef3d4523e915e4b1c3fa4f7d8949e73d07b97ec298f"
EXPECTED_TIMING_NAMES_SHA256 = "99d4d109b29625053fb1ca96b37d9391d229642c26e4df1ead105b6f8a501bb5"
EXPECTED_ROWS = 9_198
EXPECTED_CURATED = 566
EXPECTED_GAPS = 8_632
EXPECTED_SOURCES = 255
EXPECTED_PUBLIC_API_UNITS = 18_891
EXPECTED_TIMING_CASES = 29
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_PATH = re.compile(r"[A-Za-z0-9._+:/-]+\Z")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?\Z")
ALLOWED_CAPTURE_STATUSES = (
    "collected-unreviewed",
    "collection-failed",
    "finding",
    "inconclusive",
    "leak-detected",
)
CAPTURE_ROLES = (
    "acceptance",
    "compiler-inventory",
    "dedicated-timing",
    "external-attestation",
    "local-control",
    "physical",
    "platform-runtime",
    "secret-taint",
)
ROLE_CAPS = {
    "acceptance": {"files": 16, "per_file": 16_777_216, "total": 67_108_864},
    "compiler-inventory": {"files": 128, "per_file": 67_108_864, "total": 536_870_912},
    "dedicated-timing": {"files": 128, "per_file": 67_108_864, "total": 536_870_912},
    "external-attestation": {"files": 32, "per_file": 16_777_216, "total": 67_108_864},
    "local-control": {"files": 32, "per_file": 16_777_216, "total": 67_108_864},
    "physical": {"files": 128, "per_file": 67_108_864, "total": 536_870_912},
    "platform-runtime": {"files": 128, "per_file": 67_108_864, "total": 536_870_912},
    "secret-taint": {"files": 128, "per_file": 67_108_864, "total": 536_870_912},
}
DEDICATED_TIMING_CONTRACTS = (
    {
        "class_definition": "fixed-secret-versus-random-secret-with-equal-public-metadata",
        "dedicated_host": True,
        "multiple_test_policy": "holm-familywise-predeclared",
        "negative_control_required": True,
        "observation_type": "raw-integer",
        "positive_control_required": True,
        "profile_id": "linux-aarch64-fixed-vs-random-v1",
        "randomized_balanced_labels": True,
        "setup_outside_measurement": True,
        "stopping_policy": "fixed-preregistered-sample-count-no-optional-stopping",
        "target_triple": "aarch64-unknown-linux-gnu",
    },
    {
        "class_definition": "fixed-secret-versus-random-secret-with-equal-public-metadata",
        "dedicated_host": True,
        "multiple_test_policy": "holm-familywise-predeclared",
        "negative_control_required": True,
        "observation_type": "raw-integer",
        "positive_control_required": True,
        "profile_id": "linux-x86_64-fixed-vs-random-v1",
        "randomized_balanced_labels": True,
        "setup_outside_measurement": True,
        "stopping_policy": "fixed-preregistered-sample-count-no-optional-stopping",
        "target_triple": "x86_64-unknown-linux-gnu",
    },
)
ROLE_PROFILE_CONTRACTS: dict[str, dict[str, dict[str, Any]]] = {
    "compiler-inventory": {
        "legacy-compiler-inventory-v1": {
            "accepted_for_transitive_closure": False,
            "binary_identity_required": True,
            "compiler_identity_required": True,
            "profile_id": "legacy-compiler-inventory-v1",
            "unresolved_edges_block": True,
        },
    },
    "dedicated-timing": {
        row["profile_id"]: dict(row) for row in DEDICATED_TIMING_CONTRACTS
    },
    "external-attestation": {
        "unreviewed-external-attestation-v1": {
            "independent_signature_required": True,
            "profile_id": "unreviewed-external-attestation-v1",
            "trust_or_acceptance_implied": False,
        },
    },
    "local-control": {
        "repository-statistical-control-v1": {
            "dedicated_side_channel_evidence": False,
            "evidence_class": "repository-statistical-control",
            "profile_id": "repository-statistical-control-v1",
            "promotion_eligible": False,
        },
    },
    "platform-runtime": {
        "unprovisioned-platform-runtime-v1": {
            "physical_erasure_claimed": False,
            "platform_identity_required": True,
            "profile_id": "unprovisioned-platform-runtime-v1",
            "representative_only": True,
        },
    },
    "secret-taint": {
        "secret-dependent-address-v1": {
            "negative_control_required": True,
            "observed_property": "load-store-and-indirect-target-address",
            "positive_control_required": True,
            "profile_id": "secret-dependent-address-v1",
            "taint_kind": "address",
        },
        "secret-dependent-branch-v1": {
            "negative_control_required": True,
            "observed_property": "conditional-control-flow",
            "positive_control_required": True,
            "profile_id": "secret-dependent-branch-v1",
            "taint_kind": "branch",
        },
    },
}
ROLE_PROFILES = {
    role: tuple(sorted(contracts)) for role, contracts in ROLE_PROFILE_CONTRACTS.items()
}
COMMON_ARTIFACT_FIELDS = {
    "binding/binary.bin": "binary_sha256",
    "binding/build.json": "build_sha256",
    "binding/compiler.bin": "compiler_sha256",
    "binding/environment.json": "environment_sha256",
    "binding/tool-argv.json": "tool_argv_sha256",
    "binding/tool.bin": "tool_sha256",
}
ROLE_ARTIFACT_FIELDS: dict[str, dict[str, str]] = {
    "acceptance": {
        "evidence-bundle.json": "evidence_bundle_sha256",
        "reviewer-identity.json": "reviewer_identity_sha256",
        "trust-root.json": "trust_root_sha256",
    },
    "compiler-inventory": {
        "call-graph.json": "call_graph_sha256",
        "compiler-identity.json": "compiler_identity_sha256",
        "emission-set.bin": "emission_set_sha256",
        "flags.json": "flags_sha256",
    },
    "dedicated-timing": {
        "class-definition.json": "class_definition_sha256",
        "host-identity.json": "host_identity_sha256",
        "microcode.bin": "cpu_microcode_sha256",
        "negative-control.json": "negative_control_sha256",
        "positive-control.json": "positive_control_sha256",
        "raw-samples.bin": "raw_samples_sha256",
        "statistics-config.json": "statistics_config_sha256",
        "statistics-result.json": "statistics_result_sha256",
    },
    "external-attestation": {
        "attestation.json": "attestation_sha256",
        "reviewer-identity.json": "reviewer_identity_sha256",
        "signature.bin": "signature_sha256",
        "signer-identity.json": "independent_signer_sha256",
        "target-artifact.bin": "target_artifact_sha256",
    },
    "local-control": {
        "host-identity.json": "host_identity_sha256",
        "stderr.log": "stderr_sha256",
        "stdout.log": "stdout_sha256",
    },
    "physical": {
        "acquisition-config.json": "acquisition_config_sha256",
        "analysis-config.json": "analysis_config_sha256",
        "device-identity.json": "device_identity_sha256",
        "firmware.bin": "firmware_sha256",
        "fixture-identity.json": "fixture_identity_sha256",
        "negative-control.bin": "negative_control_sha256",
        "operator-identity.json": "operator_identity_sha256",
        "positive-control.bin": "positive_control_sha256",
        "probe-identity.json": "probe_identity_sha256",
        "raw-traces.bin": "raw_traces_sha256",
        "reviewer-identity.json": "reviewer_identity_sha256",
        "trigger-config.json": "trigger_config_sha256",
    },
    "platform-runtime": {
        "hardware-identity.json": "hardware_identity_sha256",
        "lifecycle-cases.json": "lifecycle_cases_sha256",
        "limits.json": "limits_sha256",
        "negative-control.json": "negative_control_sha256",
        "os-identity.json": "os_identity_sha256",
        "positive-control.json": "positive_control_sha256",
        "runtime-identity.json": "runtime_identity_sha256",
        "runtime-trace.bin": "runtime_trace_sha256",
    },
    "secret-taint": {
        "allowlist.json": "allowlist_sha256",
        "negative-control.json": "negative_control_sha256",
        "positive-control.json": "positive_control_sha256",
        "tool-config.json": "tool_config_sha256",
        "trace.bin": "trace_sha256",
    },
}


class PackageDError(RuntimeError):
    """A reviewed Package D invariant failed closed."""


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def canonical_set_json(value: Any) -> bytes:
    """Canonical compact form used by reviewed set-identity digest anchors."""

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


def profile_sha256(role: str, profile_id: str) -> str:
    contracts = ROLE_PROFILE_CONTRACTS.get(role, {})
    if profile_id not in contracts:
        raise PackageDError("profile is not a code-pinned reviewed capture profile")
    return sha256_bytes(canonical_set_json({
        "artifact_role": role,
        "contract": contracts[profile_id],
        "schema_version": 1,
    }))


def artifact_set_sha256(artifacts: list[dict[str, Any]]) -> str:
    return sha256_bytes(canonical_set_json(artifacts))


def _reject_float(_value: str) -> None:
    raise ValueError("JSON floating point values are forbidden")


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
            raise PackageDError(f"{label} contains a non-NFC string")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_nfc(item, label=f"{label}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _assert_nfc(key, label=f"{label} key")
            _assert_nfc(item, label=f"{label}.{key}")


def parse_json(raw: bytes, *, label: str, require_canonical: bool = False) -> Any:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise PackageDError(f"{label} is not strict JSON: {error}") from error
    _assert_nfc(value, label=label)
    if require_canonical and raw != canonical_json(value):
        raise PackageDError(f"{label} is not canonical JSON")
    return value


def safe_relative_path(value: str, *, label: str) -> str:
    pure = PurePosixPath(value)
    if (
        not isinstance(value, str)
        or not value
        or pure.is_absolute()
        or pure.as_posix() != value
        or "." in pure.parts
        or ".." in pure.parts
        or "\\" in value
        or SAFE_PATH.fullmatch(value) is None
    ):
        raise PackageDError(f"{label} is not a canonical relative path")
    return value


def read_regular(path: Path, *, label: str, maximum: int = 1 << 30) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as error:
        raise PackageDError(f"cannot stat {label}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_mode & 0o7000
        or stat.S_IMODE(before.st_mode) & 0o002
        or before.st_size > maximum
    ):
        raise PackageDError(f"{label} is not a bounded safe single-link regular file")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_gid,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_uid,
            opened.st_gid,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != identity:
            raise PackageDError(f"{label} changed before descriptor read")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                raise PackageDError(f"{label} was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) != b"":
            raise PackageDError(f"{label} grew during descriptor read")
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_gid,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != identity:
            raise PackageDError(f"{label} changed during descriptor read")
        return b"".join(chunks), before
    except OSError as error:
        raise PackageDError(f"cannot read {label}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _git_intent(metadata: os.stat_result) -> str:
    mode = stat.S_IMODE(metadata.st_mode)
    if mode in {0o600, 0o640, 0o644, 0o660, 0o664}:
        return "100644"
    if mode in {0o700, 0o750, 0o755, 0o770, 0o775}:
        return "100755"
    raise PackageDError(f"unsafe or ambiguous filesystem mode {mode:04o}")


def load_inventory() -> tuple[dict[str, Any], bytes]:
    raw, _metadata = read_regular(INVENTORY, label="reviewed inventory", maximum=1 << 20)
    digest = sha256_bytes(raw)
    if REVIEWED_INVENTORY_SHA256 == "UNSTABLE" or digest != REVIEWED_INVENTORY_SHA256:
        raise PackageDError("reviewed inventory differs from the code-pinned semantic authority")
    try:
        inventory = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise PackageDError(f"reviewed inventory is malformed: {error}") from error
    expected_keys = {
        "atomic-operations-sha256",
        "atomic-row-ids-sha256",
        "bls-compiler-cell",
        "bls-compiler-profiles",
        "compiler-targets",
        "content-policy",
        "dedicated-timing-contract",
        "dedicated-timing-profile-ids",
        "expected-atomic-rows",
        "expected-curated-rows",
        "expected-production-rust-sources",
        "expected-public-api-units",
        "expected-unreviewed-gap-rows",
        "ghash-compiler-cell",
        "input",
        "lifecycle-categories",
        "local-timing-cases",
        "physical-kinds",
        "physical-required-metadata",
        "production-source-policy",
        "production-source-paths-sha256",
        "production-source-roots-sha256",
        "production-source-rows-sha256",
        "public-api-snapshot-sha256",
        "release-blockers",
        "schema-version",
        "secret-taint-kinds",
        "status",
        "subject-commit",
        "subject-manifest-sha256",
        "subject-tree",
    }
    if set(inventory) != expected_keys:
        raise PackageDError("reviewed inventory root closure differs")
    if (
        inventory["schema-version"] != 1
        or inventory["content-policy"] != "dcrypt-package-d-reviewed-inventory-v1"
        or inventory["status"] != "HOLD"
        or inventory["subject-commit"] != SUBJECT_COMMIT
        or inventory["subject-tree"] != SUBJECT_TREE
        or inventory["subject-manifest-sha256"] != SUBJECT_MANIFEST_SHA256
        or inventory["atomic-operations-sha256"] != ATOMIC_SHA256
        or inventory["public-api-snapshot-sha256"] != PUBLIC_SNAPSHOT_SHA256
        or inventory["expected-atomic-rows"] != EXPECTED_ROWS
        or inventory["expected-curated-rows"] != EXPECTED_CURATED
        or inventory["expected-unreviewed-gap-rows"] != EXPECTED_GAPS
        or inventory["expected-production-rust-sources"] != EXPECTED_SOURCES
        or inventory["expected-public-api-units"] != EXPECTED_PUBLIC_API_UNITS
        or inventory["atomic-row-ids-sha256"] != EXPECTED_ROW_IDS_SHA256
        or inventory["production-source-paths-sha256"] != EXPECTED_SOURCE_PATHS_SHA256
        or inventory["production-source-rows-sha256"] != EXPECTED_SOURCE_ROWS_SHA256
        or inventory["production-source-roots-sha256"] != EXPECTED_SOURCE_ROOTS_SHA256
    ):
        raise PackageDError("reviewed inventory identity/count pins differ")
    expected_dedicated = [
        {
            key.replace("_", "-"): value
            for key, value in contract.items()
        }
        for contract in DEDICATED_TIMING_CONTRACTS
    ]
    if (
        inventory["dedicated-timing-profile-ids"]
        != [row["profile_id"] for row in DEDICATED_TIMING_CONTRACTS]
        or inventory["dedicated-timing-contract"] != expected_dedicated
    ):
        raise PackageDError("reviewed dedicated timing contract differs")
    return inventory, raw


def build_input_bindings(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    records = inventory["input"]
    if not isinstance(records, list) or len(records) != 13:
        raise PackageDError("reviewed input closure differs")
    result: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict) or set(record) != {"git-mode", "path", "sha256"}:
            raise PackageDError("reviewed input row closure differs")
        path = safe_relative_path(record["path"], label="reviewed input")
        if record["git-mode"] not in {"100644", "100755"} or HEX64.fullmatch(record["sha256"] or "") is None:
            raise PackageDError(f"reviewed input identity differs: {path}")
        raw, metadata = read_regular(REPO / path, label=f"reviewed input {path}")
        if _git_intent(metadata) != record["git-mode"] or sha256_bytes(raw) != record["sha256"]:
            raise PackageDError(f"reviewed input bytes/mode differ: {path}")
        if path == "assurance/public-api-snapshot.json":
            public = parse_json(raw, label="public API snapshot")
            if (
                not isinstance(public, dict)
                or public.get("source_commit") != SUBJECT_COMMIT
                or public.get("source_tree") != SUBJECT_TREE
                or not isinstance(public.get("entries"), list)
                or len(public["entries"]) != EXPECTED_PUBLIC_API_UNITS
            ):
                raise PackageDError("public API snapshot binding/count differs")
        result.append(
            {
                "git_mode": record["git-mode"],
                "path": path,
                "sha256": record["sha256"],
                "size": len(raw),
            }
        )
    result.sort(key=lambda row: row["path"])
    if len({row["path"] for row in result}) != 13:
        raise PackageDError("reviewed inputs contain duplicate paths")
    return result


def build_atomic_rows() -> tuple[list[dict[str, Any]], str]:
    raw, _metadata = read_regular(REPO / "assurance/atomic-operations.toml", label="atomic operations")
    if sha256_bytes(raw) != ATOMIC_SHA256:
        raise PackageDError("atomic operations bytes differ")
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise PackageDError(f"atomic operations are malformed: {error}") from error
    if set(document) != {"schema-version", "operation", "unreviewed-gap-defaults", "unreviewed-gap"} or document["schema-version"] != 2:
        raise PackageDError("atomic operations root closure differs")
    operations = document["operation"]
    gaps = document["unreviewed-gap"]
    if len(operations) != EXPECTED_CURATED or len(gaps) != EXPECTED_GAPS:
        raise PackageDError("atomic operation source counts differ")
    rows: list[dict[str, Any]] = []
    ids: list[str] = []
    blockers = [
        "acceptance-and-promotion-disabled",
        "dedicated-fixed-vs-random-unprovisioned",
        "external-audit-unaccepted",
        "physical-profile-unselected",
        "platform-runtime-unaccepted",
        "secret-taint-unprovisioned",
        "transitive-compiler-closure-incomplete",
        "transitive-secret-flow-incomplete",
    ]
    for source_kind, row_kind, records in (
        ("curated-operation", "operation", operations),
        ("unreviewed-gap", "gap", gaps),
    ):
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("id"), str) or not record["id"]:
                raise PackageDError("atomic source record lacks an exact id")
            row_id = record["id"]
            ids.append(row_id)
            rows.append(
                {
                    "blockers": blockers,
                    "promotion_eligible": False,
                    "release_status": "blocked",
                    "row_id": row_id,
                    "row_kind": row_kind,
                    "source_kind": source_kind,
                    "source_record_sha256": sha256_bytes(canonical_json(record)),
                    "trace_status": "blocked-untraced",
                }
            )
    rows.sort(key=lambda row: row["row_id"])
    if len(rows) != EXPECTED_ROWS or len(set(ids)) != EXPECTED_ROWS:
        raise PackageDError("atomic row identity closure differs")
    ids_digest = sha256_bytes(canonical_set_json(sorted(ids)))
    if ids_digest != EXPECTED_ROW_IDS_SHA256:
        raise PackageDError("atomic row ID-set digest differs")
    return rows, ids_digest


def build_source_rows() -> tuple[list[dict[str, Any]], str, str]:
    raw, _metadata = read_regular(REPO / "assurance/subject-manifest.json", label="subject manifest")
    if sha256_bytes(raw) != SUBJECT_MANIFEST_SHA256:
        raise PackageDError("subject manifest digest differs")
    manifest = parse_json(raw, label="subject manifest")
    if (
        not isinstance(manifest, dict)
        or manifest.get("source_commit") != SUBJECT_COMMIT
        or manifest.get("source_tree") != SUBJECT_TREE
        or not isinstance(manifest.get("files"), list)
    ):
        raise PackageDError("subject manifest identity differs")
    selected: list[dict[str, Any]] = []
    binding_rows: list[dict[str, str]] = []
    paths: list[str] = []
    roots: set[str] = set()
    for source in manifest["files"]:
        if not isinstance(source, dict) or set(source) != {"git_mode", "path", "sha256"}:
            raise PackageDError("subject manifest row closure differs")
        path = source["path"]
        include = path == "src/lib.rs" or (
            path.startswith("crates/") and "/src/" in path and path.endswith(".rs")
        )
        if not include:
            continue
        safe_relative_path(path, label="production source")
        if source["git_mode"] != "100644" or HEX64.fullmatch(source["sha256"] or "") is None:
            raise PackageDError(f"production source manifest row differs: {path}")
        source_raw, metadata = read_regular(REPO / path, label=f"production source {path}")
        if _git_intent(metadata) != "100644" or sha256_bytes(source_raw) != source["sha256"]:
            raise PackageDError(f"production source bytes/mode differ: {path}")
        binding_rows.append({"git_mode": "100644", "path": path, "sha256": source["sha256"]})
        paths.append(path)
        roots.add("src" if path == "src/lib.rs" else "/".join(path.split("/")[:3]))
        selected.append(
            {
                "address_trace_runs": 0,
                "branch_trace_runs": 0,
                "git_mode": "100644",
                "path": path,
                "promotion_eligible": False,
                "sha256": source["sha256"],
                "trace_status": "blocked-untraced",
                "transitive_closure_complete": False,
            }
        )
    selected.sort(key=lambda row: row["path"])
    binding_rows.sort(key=lambda row: row["path"])
    paths.sort()
    if len(selected) != EXPECTED_SOURCES or len(set(paths)) != EXPECTED_SOURCES:
        raise PackageDError("production Rust source closure differs")
    source_digest = sha256_bytes(canonical_set_json(binding_rows))
    path_digest = sha256_bytes(canonical_set_json(paths))
    roots_digest = sha256_bytes(canonical_set_json(sorted(roots)))
    if source_digest != EXPECTED_SOURCE_ROWS_SHA256 or path_digest != EXPECTED_SOURCE_PATHS_SHA256 or roots_digest != EXPECTED_SOURCE_ROOTS_SHA256:
        raise PackageDError("production source-set digest differs")
    return selected, source_digest, path_digest


def build_timing_controls(inventory: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    names = inventory["local-timing-cases"]
    if not isinstance(names, list) or len(names) != EXPECTED_TIMING_CASES or len(set(names)) != len(names):
        raise PackageDError("local timing case closure differs")
    digest = sha256_bytes(canonical_set_json(names))
    if digest != EXPECTED_TIMING_NAMES_SHA256:
        raise PackageDError("local timing case order digest differs")
    raw, _metadata = read_regular(REPO / "tests/tests/constant_time/mod.rs", label="timing registry")
    text = raw.decode("utf-8", errors="strict")
    match = re.search(
        r"const BLOCKING_CASE_NAMES: \[&str; EXPECTED_BLOCKING_CASES\] = \[(.*?)\n\];",
        text,
        re.DOTALL,
    )
    if match is None or re.findall(r'^\s*"([^"]+)",\s*$', match.group(1), re.MULTILINE) != names:
        raise PackageDError("timing source registry differs from reviewed names")
    return [
        {
            "case_id": f"local-{index + 1:02d}",
            "dedicated_host": False,
            "dudect": False,
            "evidence_class": "repository-statistical-control",
            "fixed_vs_random": False,
            "name": name,
            "promotion_eligible": False,
        }
        for index, name in enumerate(names)
    ], digest


def build_compiler_controls(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    targets = inventory["compiler-targets"]
    if targets != sorted(targets) or len(targets) != 4:
        raise PackageDError("compiler target closure differs")
    bls = inventory["bls-compiler-cell"]
    ghash = inventory["ghash-compiler-cell"]
    if len(bls) != 8 or len(ghash) != 4:
        raise PackageDError("legacy compiler control count differs")
    rows: list[dict[str, Any]] = []
    for cell in bls:
        if set(cell) != {"emission-sha256", "profile", "promotion-eligible", "target", "transitive-closure", "version"} or HEX64.fullmatch(cell["emission-sha256"] or "") is None or cell["promotion-eligible"] is not False or cell["transitive-closure"] is not False:
            raise PackageDError("BLS compiler cell closure differs")
        rows.append(
            {
                "accepted_for_transitive_closure": False,
                "compiler_identity": cell["version"],
                "compiler_profile": cell["profile"],
                "control_id": f"bls-{cell['profile']}-{cell['target']}",
                "emission_sha256": cell["emission-sha256"],
                "kind": "legacy-bls-whole-emission-regression",
                "promotion_eligible": False,
                "status": "legacy-regression-only",
                "target": cell["target"],
            }
        )
    for cell in ghash:
        if set(cell) != {"promotion-eligible", "shape", "target", "transitive-closure"} or cell["promotion-eligible"] is not False or cell["transitive-closure"] is not False:
            raise PackageDError("GHASH compiler cell closure differs")
        rows.append(
            {
                "accepted_for_transitive_closure": False,
                "compiler_identity": None,
                "compiler_profile": None,
                "control_id": f"ghash-shape-{cell['target']}",
                "emission_sha256": None,
                "kind": "legacy-ghash-shape-regression",
                "promotion_eligible": False,
                "shape": cell["shape"],
                "status": "shape-only-compiler-unpinned",
                "target": cell["target"],
            }
        )
    rows.sort(key=lambda row: row["control_id"])
    if len({row["control_id"] for row in rows}) != 12:
        raise PackageDError("compiler control IDs are not unique")
    return rows


def build_dedicated_timing_profiles() -> list[dict[str, Any]]:
    return [
        {
            **contract,
            "class_balance": "balanced-fixed-versus-random-secret",
            "decision_rule": "preregistered-familywise-fail-closed",
            "host_identity": None,
            "promotion_eligible": False,
            "raw_samples_sha256": None,
            "run_count": 0,
            "status": "unprovisioned",
            "tool_identity": None,
        }
        for contract in DEDICATED_TIMING_CONTRACTS
    ]


def build_taint_profiles(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    if inventory["secret-taint-kinds"] != ["address", "branch"]:
        raise PackageDError("secret-taint kind closure differs")
    return [
        {
            "kind": kind,
            "negative_control": f"public_{kind}",
            "positive_control": f"secret_{kind}",
            "promotion_eligible": False,
            "run_count": 0,
            "status": "unprovisioned",
            "tool_identity": None,
        }
        for kind in inventory["secret-taint-kinds"]
    ]


def build_capture_contract() -> dict[str, Any]:
    profiles = [
        {
            "artifact_role": role,
            "contract": contract,
            "profile_id": profile_id,
            "profile_sha256": profile_sha256(role, profile_id),
        }
        for role, contracts in sorted(ROLE_PROFILE_CONTRACTS.items())
        for profile_id, contract in sorted(contracts.items())
    ]
    return {
        "accepted_roles": [role for role in CAPTURE_ROLES if role not in {"acceptance", "physical"}],
        "acceptance_enabled": False,
        "destination_policy": "new-private-outside-repository",
        "physical_capture_enabled": False,
        "profile_contracts": profiles,
        "promotion_enabled": False,
        "role_caps": ROLE_CAPS,
        "source_policy": "private-closed-bundle-outside-repository",
    }


def build_package_document() -> dict[str, Any]:
    inventory, inventory_raw = load_inventory()
    inputs = build_input_bindings(inventory)
    atomic_rows, row_ids_digest = build_atomic_rows()
    sources, source_digest, source_path_digest = build_source_rows()
    timing, timing_digest = build_timing_controls(inventory)
    compiler = build_compiler_controls(inventory)
    blockers = inventory["release-blockers"]
    if blockers != sorted(blockers) or len(blockers) != 8:
        raise PackageDError("release blocker closure differs")
    dedicated_profiles = build_dedicated_timing_profiles()
    taint_profiles = build_taint_profiles(inventory)
    document = {
        "artifact_role": "package-d-baseline",
        "atomic_inventory": {
            "row_ids_sha256": row_ids_digest,
            "rows": atomic_rows,
        },
        "capture_contract": build_capture_contract(),
        "compiler_controls": compiler,
        "content_policy": "dcrypt-package-d-side-channel-foundation-v1",
        "counts": {
            "acceptance_records": 0,
            "accepted_evidence_records": 0,
            "accepted_external_attestations": 0,
            "accepted_physical_evidence_records": 0,
            "accepted_physical_profiles": 0,
            "accepted_platform_runtime_records": 0,
            "compiler_controls": 12,
            "curated_rows": EXPECTED_CURATED,
            "dedicated_timing_runs": 0,
            "local_timing_controls": EXPECTED_TIMING_CASES,
            "production_source_files": EXPECTED_SOURCES,
            "public_api_units": EXPECTED_PUBLIC_API_UNITS,
            "promoted_records": 0,
            "promotion_eligible_records": 0,
            "release_blocked_rows": EXPECTED_ROWS,
            "secret_taint_runs": 0,
            "total_atomic_rows": EXPECTED_ROWS,
            "transitive_compiler_closures": 0,
            "transitive_secret_flow_closures": 0,
            "unreviewed_gap_rows": EXPECTED_GAPS,
        },
        "dedicated_timing_profiles": dedicated_profiles,
        "evidence_policy": {
            "external_attestation_status": "unaccepted",
            "local_controls_are_operational_evidence": False,
            "operational_evidence_store": None,
            "roles_are_orthogonal": True,
        },
        "input_bindings": inputs,
        "lifecycle_policy": {
            "categories": inventory["lifecycle-categories"],
            "complete_transitive_inventories": 0,
            "physical_erasure_claimed": False,
            "platform_runtime_accepted": False,
            "status": "blocked-untraced",
        },
        "local_timing_controls": timing,
        "physical_policy": {
            "active_profiles": [],
            "kinds": inventory["physical-kinds"],
            "required_metadata": inventory["physical-required-metadata"],
            "status": "blocked-no-justified-product-profile",
        },
        "promotion_eligible": False,
        "release_blockers": blockers,
        "release_gate": {"exit_code": 3, "status": "HOLD"},
        "reviewed_inventory_sha256": sha256_bytes(inventory_raw),
        "schema_version": 1,
        "source_inventory": {
            "files": sources,
            "paths_sha256": source_path_digest,
            "rows_sha256": source_digest,
        },
        "status": "HOLD-structural-foundation-only",
        "subject_binding": {
            "source_commit": SUBJECT_COMMIT,
            "source_tree": SUBJECT_TREE,
            "subject_manifest_sha256": SUBJECT_MANIFEST_SHA256,
        },
        "taint_profiles": taint_profiles,
        "timing_names_sha256": timing_digest,
    }
    validate_package_document(document)
    return document


def validate_package_document(document: dict[str, Any]) -> None:
    expected_keys = {
        "artifact_role", "atomic_inventory", "capture_contract", "compiler_controls",
        "content_policy", "counts", "dedicated_timing_profiles", "evidence_policy",
        "input_bindings", "lifecycle_policy", "local_timing_controls", "physical_policy",
        "promotion_eligible", "release_blockers", "release_gate", "reviewed_inventory_sha256",
        "schema_version", "source_inventory", "status", "subject_binding", "taint_profiles",
        "timing_names_sha256",
    }
    if set(document) != expected_keys:
        raise PackageDError("Package D document root closure differs")
    inventory, inventory_raw = load_inventory()
    expected_rows, row_ids_sha256 = build_atomic_rows()
    expected_sources, source_rows_sha256, source_paths_sha256 = build_source_rows()
    expected_timing, timing_names_sha256 = build_timing_controls(inventory)
    expected_counts = {
        "acceptance_records": 0,
        "accepted_evidence_records": 0,
        "accepted_external_attestations": 0,
        "accepted_physical_evidence_records": 0,
        "accepted_physical_profiles": 0,
        "accepted_platform_runtime_records": 0,
        "compiler_controls": 12,
        "curated_rows": EXPECTED_CURATED,
        "dedicated_timing_runs": 0,
        "local_timing_controls": EXPECTED_TIMING_CASES,
        "production_source_files": EXPECTED_SOURCES,
        "public_api_units": EXPECTED_PUBLIC_API_UNITS,
        "promoted_records": 0,
        "promotion_eligible_records": 0,
        "release_blocked_rows": EXPECTED_ROWS,
        "secret_taint_runs": 0,
        "total_atomic_rows": EXPECTED_ROWS,
        "transitive_compiler_closures": 0,
        "transitive_secret_flow_closures": 0,
        "unreviewed_gap_rows": EXPECTED_GAPS,
    }
    expected_capture = build_capture_contract()
    expected_evidence = {
        "external_attestation_status": "unaccepted",
        "local_controls_are_operational_evidence": False,
        "operational_evidence_store": None,
        "roles_are_orthogonal": True,
    }
    expected_lifecycle = {
        "categories": inventory["lifecycle-categories"],
        "complete_transitive_inventories": 0,
        "physical_erasure_claimed": False,
        "platform_runtime_accepted": False,
        "status": "blocked-untraced",
    }
    expected_physical = {
        "active_profiles": [],
        "kinds": inventory["physical-kinds"],
        "required_metadata": inventory["physical-required-metadata"],
        "status": "blocked-no-justified-product-profile",
    }
    if (
        document["artifact_role"] != "package-d-baseline"
        or document["schema_version"] != 1
        or document["content_policy"] != "dcrypt-package-d-side-channel-foundation-v1"
        or document["status"] != "HOLD-structural-foundation-only"
        or document["promotion_eligible"] is not False
        or document["release_gate"] != {"exit_code": 3, "status": "HOLD"}
        or document["reviewed_inventory_sha256"] != sha256_bytes(inventory_raw)
        or document["subject_binding"] != {
            "source_commit": SUBJECT_COMMIT,
            "source_tree": SUBJECT_TREE,
            "subject_manifest_sha256": SUBJECT_MANIFEST_SHA256,
        }
        or document["counts"] != expected_counts
        or document["release_blockers"] != inventory["release-blockers"]
        or document["input_bindings"] != build_input_bindings(inventory)
        or document["atomic_inventory"] != {
            "row_ids_sha256": row_ids_sha256,
            "rows": expected_rows,
        }
        or document["source_inventory"] != {
            "files": expected_sources,
            "paths_sha256": source_paths_sha256,
            "rows_sha256": source_rows_sha256,
        }
        or document["local_timing_controls"] != expected_timing
        or document["timing_names_sha256"] != timing_names_sha256
        or document["dedicated_timing_profiles"] != build_dedicated_timing_profiles()
        or document["taint_profiles"] != build_taint_profiles(inventory)
        or document["compiler_controls"] != build_compiler_controls(inventory)
        or document["capture_contract"] != expected_capture
        or document["evidence_policy"] != expected_evidence
        or document["lifecycle_policy"] != expected_lifecycle
        or document["physical_policy"] != expected_physical
    ):
        raise PackageDError("Package D document differs from the exact reviewed HOLD projection")


def _binding_schema() -> dict[str, Any]:
    digest = {"pattern": "^[0-9a-f]{64}$", "type": "string"}
    commit = {"pattern": "^[0-9a-f]{40}$", "type": "string"}
    return {
        "additionalProperties": False,
        "properties": {
            "binary_sha256": digest,
            "build_sha256": digest,
            "compiler_sha256": digest,
            "profile_sha256": digest,
            "r_commit": commit,
            "r_tree": commit,
            "source_set_sha256": digest,
            "subject_manifest_sha256": digest,
            "tool_sha256": digest,
        },
        "required": [
            "binary_sha256", "build_sha256", "compiler_sha256", "profile_sha256",
            "r_commit", "r_tree", "source_set_sha256", "subject_manifest_sha256",
            "tool_sha256",
        ],
        "type": "object",
    }


def _artifact_schema() -> dict[str, Any]:
    return {
        "additionalProperties": False,
        "properties": {
            "path": {"maxLength": 256, "minLength": 1, "pattern": "^(?!/)(?!.*(?:^|/)\\.\\.(?:/|$))[A-Za-z0-9._+/-]+$", "type": "string"},
            "sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "size": {"maximum": 67_108_864, "minimum": 0, "type": "integer"},
        },
        "required": ["path", "sha256", "size"],
        "type": "object",
    }


def _role_schema(role: str) -> dict[str, Any]:
    common: dict[str, Any] = {
        "artifact_role": {"const": role, "type": "string"},
        "artifacts": {"items": {"$ref": "#/$defs/artifact"}, "maxItems": 256, "minItems": 1, "type": "array", "uniqueItems": True},
        "binding": {"$ref": "#/$defs/binding"},
        "content_policy": {"const": "dcrypt-package-d-candidate-bundle-v1", "type": "string"},
        "promotion_eligible": {"const": False, "type": "boolean"},
        "profile_id": {"maxLength": 256, "minLength": 1, "type": "string"},
        "environment_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
        "raw_artifact_set_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
        "schema_version": {"const": 1, "type": "integer"},
        "session_id": {"maxLength": 256, "minLength": 1, "pattern": "^[A-Za-z0-9._:+/-]+$", "type": "string"},
        "status": {"enum": list(ALLOWED_CAPTURE_STATUSES), "type": "string"},
        "tool_argv_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
    }
    role_fields: dict[str, dict[str, Any]] = {
        "local-control": {
            "control_id": {"maxLength": 256, "minLength": 1, "type": "string"},
            "execution_count": {"maximum": 10_000_000, "minimum": 1, "type": "integer"},
            "host_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "result_class": {"enum": ["finding", "inconclusive", "informational"], "type": "string"},
            "stderr_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "stdout_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
        },
        "dedicated-timing": {
            "class_balance": {"const": "1", "type": "string"},
            "class_definition_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "cpu_microcode_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "host_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "negative_control_findings": {"maximum": 1_000_000, "minimum": 0, "type": "integer"},
            "negative_control_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "positive_control_detected": {"type": "boolean"},
            "positive_control_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "raw_samples_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "sample_count": {"maximum": 1_000_000_000, "minimum": 1, "type": "integer"},
            "statistics_config_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "statistics_result_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "target_triple": {"maxLength": 256, "minLength": 1, "type": "string"},
        },
        "secret-taint": {
            "address_event_count": {"maximum": 1_000_000_000, "minimum": 0, "type": "integer"},
            "allowlist_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "branch_event_count": {"maximum": 1_000_000_000, "minimum": 0, "type": "integer"},
            "negative_control_findings": {"maximum": 1_000_000, "minimum": 0, "type": "integer"},
            "negative_control_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "positive_control_detected": {"type": "boolean"},
            "positive_control_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "taint_kind": {"enum": ["address", "branch"], "type": "string"},
            "tool_config_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "trace_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "unresolved_event_count": {"maximum": 1_000_000_000, "minimum": 0, "type": "integer"},
        },
        "compiler-inventory": {
            "call_graph_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "compiler_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "emission_count": {"maximum": 1_000_000, "minimum": 1, "type": "integer"},
            "emission_set_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "flags_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "indirect_target_count": {"maximum": 1_000_000, "minimum": 0, "type": "integer"},
            "target_triple": {"maxLength": 256, "minLength": 1, "type": "string"},
            "transitive_closure_complete": {"const": False, "type": "boolean"},
            "unresolved_edge_count": {"maximum": 1_000_000, "minimum": 0, "type": "integer"},
        },
        "platform-runtime": {
            "hardware_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "lifecycle_cases_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "limits_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "lifecycle_event_count": {"maximum": 1_000_000_000, "minimum": 1, "type": "integer"},
            "negative_control_findings": {"maximum": 1_000_000, "minimum": 0, "type": "integer"},
            "negative_control_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "os_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "platform": {"maxLength": 256, "minLength": 1, "type": "string"},
            "positive_control_detected": {"type": "boolean"},
            "positive_control_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "runtime_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "runtime_trace_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
        },
        "physical": {
            "acquisition_config_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "analysis_config_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "device_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "device_profile": {"maxLength": 256, "minLength": 1, "type": "string"},
            "firmware_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "fixture_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "negative_control_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "operator_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "positive_control_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "probe_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "raw_traces_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "reviewer_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "trace_count": {"maximum": 1_000_000_000, "minimum": 1, "type": "integer"},
            "trigger_config_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
        },
        "external-attestation": {
            "attestation_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "independent_signer_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "reviewer_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "signature_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "target_artifact_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
        },
        "acceptance": {
            "acceptance_decision": {"const": "unreviewed-template", "type": "string"},
            "evidence_bundle_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "reviewer_identity_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
            "trust_root_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
        },
    }[role]
    properties = {**common, **role_fields}
    return {
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(properties),
        "type": "object",
    }


def build_evidence_schema() -> dict[str, Any]:
    definitions: dict[str, Any] = {
        "artifact": _artifact_schema(),
        "binding": _binding_schema(),
    }
    for role in CAPTURE_ROLES:
        definitions[role] = _role_schema(role)
    return {
        "$defs": definitions,
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "oneOf": [{"$ref": f"#/$defs/{role}"} for role in CAPTURE_ROLES],
    }


SUPPORTED_SCHEMA_KEYS = {
    "$defs", "$ref", "$schema", "additionalProperties", "const", "enum", "items",
    "maxItems", "maxLength", "maximum", "minItems", "minLength", "minimum", "oneOf",
    "pattern", "properties", "required", "type", "uniqueItems",
}


def validate_schema_value(
    value: Any,
    schema: dict[str, Any],
    *,
    root: dict[str, Any] | None = None,
    label: str = "value",
    seen_refs: tuple[str, ...] = (),
) -> None:
    if not isinstance(schema, dict) or any(key not in SUPPORTED_SCHEMA_KEYS for key in schema):
        raise PackageDError(f"{label} uses an unsupported schema keyword")
    root = schema if root is None else root
    if "$ref" in schema:
        if set(schema) != {"$ref"}:
            raise PackageDError(f"{label} combines $ref with sibling keywords")
        reference = schema["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/$defs/") or "/" in reference[len("#/$defs/"):]:
            raise PackageDError(f"{label} uses an external/unresolved schema reference")
        if reference in seen_refs:
            raise PackageDError(f"{label} uses a recursive schema reference")
        name = reference[len("#/$defs/"):]
        definitions = root.get("$defs")
        if not isinstance(definitions, dict) or name not in definitions:
            raise PackageDError(f"{label} uses an unresolved schema reference")
        validate_schema_value(value, definitions[name], root=root, label=label, seen_refs=(*seen_refs, reference))
        return
    if "oneOf" in schema:
        branches = schema["oneOf"]
        if not isinstance(branches, list) or not branches:
            raise PackageDError(f"{label} has an invalid oneOf")
        matches = 0
        for branch in branches:
            try:
                validate_schema_value(value, branch, root=root, label=label, seen_refs=seen_refs)
                matches += 1
            except PackageDError:
                pass
        if matches != 1:
            raise PackageDError(f"{label} matches {matches} schema branches; expected exactly one")
        return
    expected_type = schema.get("type")
    type_ok = {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
        None: True,
    }.get(expected_type, False)
    if not type_ok:
        raise PackageDError(f"{label} has the wrong schema type")
    if "const" in schema and value != schema["const"]:
        raise PackageDError(f"{label} differs from schema const")
    if "enum" in schema and value not in schema["enum"]:
        raise PackageDError(f"{label} differs from schema enum")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise PackageDError(f"{label} object schema is malformed")
        if schema.get("additionalProperties") is not False or set(value) != set(required) or set(required) != set(properties):
            raise PackageDError(f"{label} object closure differs")
        for key, item in value.items():
            validate_schema_value(item, properties[key], root=root, label=f"{label}.{key}", seen_refs=seen_refs)
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            raise PackageDError(f"{label} array bounds differ")
        if schema.get("uniqueItems") and len({canonical_json(item) for item in value}) != len(value):
            raise PackageDError(f"{label} array contains duplicate values")
        if "items" not in schema:
            raise PackageDError(f"{label} array schema lacks items")
        for index, item in enumerate(value):
            validate_schema_value(item, schema["items"], root=root, label=f"{label}[{index}]", seen_refs=seen_refs)
    elif isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise PackageDError(f"{label} integer bound differs")
    elif isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            raise PackageDError(f"{label} string bound differs")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise PackageDError(f"{label} string pattern differs")


def validate_evidence_candidate(value: Any, schema: dict[str, Any] | None = None) -> None:
    active = build_evidence_schema() if schema is None else schema
    if set(active) != {"$defs", "$schema", "oneOf"} or active.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise PackageDError("evidence schema root closure/version differs")
    validate_schema_value(value, active, root=active, label="candidate")
    if value["promotion_eligible"] is not False or value["status"] not in ALLOWED_CAPTURE_STATUSES:
        raise PackageDError("candidate attempts unsupported promotion/status")
    binding = value["binding"]
    if (
        binding["r_commit"] != SUBJECT_COMMIT
        or binding["r_tree"] != SUBJECT_TREE
        or binding["subject_manifest_sha256"] != SUBJECT_MANIFEST_SHA256
        or binding["source_set_sha256"] != EXPECTED_SOURCE_ROWS_SHA256
    ):
        raise PackageDError("candidate subject binding differs")
    role = value["artifact_role"]
    if role not in ROLE_PROFILES or value["profile_id"] not in ROLE_PROFILES[role]:
        raise PackageDError("candidate profile is not a code-pinned reviewed capture profile")
    if binding["profile_sha256"] != profile_sha256(role, value["profile_id"]):
        raise PackageDError("candidate profile digest differs")
    artifacts = value["artifacts"]
    caps = ROLE_CAPS[role]
    if (
        len(artifacts) > caps["files"]
        or any(artifact["size"] > caps["per_file"] for artifact in artifacts)
        or sum(artifact["size"] for artifact in artifacts) > caps["total"]
        or value["raw_artifact_set_sha256"] != artifact_set_sha256(artifacts)
    ):
        raise PackageDError("candidate role cap or artifact-set identity differs")
    expected_artifacts = {**COMMON_ARTIFACT_FIELDS, **ROLE_ARTIFACT_FIELDS[role]}
    by_path = {artifact["path"]: artifact for artifact in artifacts}
    if set(by_path) != set(expected_artifacts):
        raise PackageDError("candidate role artifact closure differs")
    for path, field in expected_artifacts.items():
        expected_digest = (
            binding[field]
            if field in {"binary_sha256", "build_sha256", "compiler_sha256", "tool_sha256"}
            else value[field]
        )
        if by_path[path]["sha256"] != expected_digest:
            raise PackageDError("candidate role artifact digest differs")
    contract = ROLE_PROFILE_CONTRACTS[role][value["profile_id"]]
    if role == "dedicated-timing" and (
        value["positive_control_detected"] is not True
        or value["negative_control_findings"] != 0
        or value["class_balance"] != "1"
        or value["target_triple"] != contract["target_triple"]
    ):
        raise PackageDError("dedicated timing controls did not fail closed")
    if role == "secret-taint" and (
        value["positive_control_detected"] is not True
        or value["negative_control_findings"] != 0
        or value["taint_kind"] != contract["taint_kind"]
    ):
        raise PackageDError("secret-taint controls did not fail closed")
    if role == "platform-runtime" and (
        value["positive_control_detected"] is not True
        or value["negative_control_findings"] != 0
    ):
        raise PackageDError("platform-runtime controls did not fail closed")
    artifact_paths = [artifact["path"] for artifact in artifacts]
    if artifact_paths != sorted(artifact_paths) or len(set(artifact_paths)) != len(artifact_paths):
        raise PackageDError("candidate artifact path order/closure differs")
    for path in artifact_paths:
        safe_relative_path(path, label="candidate artifact")
        if ".git" in PurePosixPath(path).parts:
            raise PackageDError("candidate artifact traverses a forbidden .git component")


def artifact_source_files() -> tuple[str, ...]:
    return (
        "README.md",
        "capture.py",
        "fixtures/control.rs",
        "generate.py",
        "model.py",
        "rebind-final-subject.py",
        "reviewed-inventory.toml",
        "selftest.py",
        "verify.py",
    )
