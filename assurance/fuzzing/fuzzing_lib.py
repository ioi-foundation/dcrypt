#!/usr/bin/env python3
"""Normative, standard-library-only Package C fuzz-assurance model.

The code in this module is the reviewed root for the generated policy and
target-registry data.  Generated JSON is deliberately not allowed to redefine
these semantics.  Operational campaign evidence remains blocked until a final
subject binding and independently authenticated campaign records exist.
"""

from __future__ import annotations

import ast
import datetime as dt
import hashlib
import json
import os
import re
import stat
import tempfile
import tomllib
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA_VERSION = 1
STATUS = "STABLE-final-subject-bound"
FRAMEWORK_SUBJECT_COMMIT = "889cb8c4dc13a78679dc8a7677916484a9966f65"
FRAMEWORK_SUBJECT_TREE = "0d44b68b186913de68844d09b7e498bcda14d109"
FRAMEWORK_SUBJECT_MANIFEST_SHA256 = "95902d2ff4a2f99808ba5d404fbce3175b787b93fdc1538cb55ad350e69505c7"
CONTENT_PREFIX = "dcrypt-fuzzing"
FRAMEWORK_DIR = Path(__file__).resolve().parent
REPO_ROOT = FRAMEWORK_DIR.parent.parent

PACKAGE_B_COMMIT = "682947afafdce5bf19339c90bc1a3e768fa15772"
PACKAGE_B_TREE = "7112eb96c4dc92ce24c277d512c286f183b04cf5"
PACKAGE_B_SUBJECT_COMMIT = "ba2685293bf326cef611f33445269071e9fddef1"
PACKAGE_B_SUBJECT_TREE = "869608f3379bf91ebed67308f22117312ddd0e5b"

EXPECTED_CURATED_ROWS = 566
EXPECTED_UNREVIEWED_GAPS = 8_632
EXPECTED_TOTAL_ROWS = 9_198
EXPECTED_CRITICAL_ROWS = 372
EXPECTED_EXPLICIT_BLOCKERS = EXPECTED_TOTAL_ROWS - EXPECTED_CRITICAL_ROWS

PACKAGE_C_CONTROL_INPUTS = {
    ".github/workflows/security-validation.yml": ("6f2fd0a26f633bd6e6f6d9760d7717c42b53e80d971a85ea790e3d4b33cfbeef", "100644"),
    "tools/release-dcrypt.sh": ("c96d7d647dcf8367e84d2ee2f9a62a596bb674f1d6ad1240d2615528e0c5e70d", "100755"),
    "tools/verify-publish-ready.sh": ("d7999f497afe1208eb499bf169f9ca411b285b9651188b9124670cf13d766023", "100755"),
    "tools/verify-remote-release-ready.py": ("c6b0a3e1df1ec1b617f75d07e2f7af689b73e00b53e6903f9f8cdc7cacf96941", "100755"),
}
CONTROL_INPUTS_SHA256 = "4bd01f691f0ff77a786c07152a36a1ca94d85b6912f277486e78c7708d6e7a01"

WEEKLY_CRITICAL_CORE_SECONDS = 72 * 60 * 60
WEEKLY_SECONDARY_CORE_SECONDS = 24 * 60 * 60
RC_CRITICAL_CORE_SECONDS = 24 * 60 * 60
RC_SECONDARY_CORE_SECONDS = 8 * 60 * 60
CRITICAL_FRESHNESS_SECONDS = 24 * 60 * 60
WEEKLY_FRESHNESS_SECONDS = 8 * 24 * 60 * 60
RSS_LIMIT_MB = 2_048
SMOKE_RUNS = 1_000
SMOKE_SEED = 424_242
PARSER_TIMEOUT_SECONDS = 2
EXPENSIVE_CRYPTO_TIMEOUT_SECONDS = 10
HYBRID_SEMANTIC_TIMEOUT_SECONDS = 30
INTEGRATED_ASAN_OPTIONS = "abort_on_error=1:detect_leaks=1:exitcode=86:halt_on_error=1"
INTEGRATED_ASAN_RUNTIME_SHA256 = "963a6c2f6e6925dc483ef93ba3f0d75676f8f1c5ada533e8e0e55eff91d0e41c"
INTEGRATED_ASAN_FUNCTION_SYMBOLS = (
    "__asan_init",
    "__lsan_enable",
    "__lsan_disable",
    "__lsan_do_recoverable_leak_check",
)

# These are replaced once from the canonical in-code projections.  They are
# literal trust anchors so a coherent data-only rewrite cannot promote itself.
EXPECTED_POLICY_SEMANTIC_SHA256 = "92d269f7114417569b5be18399c8e829b7dab2835ffa37f7095345903b945be0"
EXPECTED_REGISTRY_SEMANTIC_SHA256 = "e3fbcb6d7bca241fbe94611b15888c0334f78f16200e21b1b38f3f1013b5e3a2"

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TARGET_ID = re.compile(r"[a-z][a-z0-9_]*\Z")
UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class FuzzingError(RuntimeError):
    """A Package C input violated a fail-closed invariant."""


def _reject_float(value: str) -> None:
    raise FuzzingError(f"floating-point JSON value is forbidden: {value}")


def _reject_constant(value: str) -> None:
    raise FuzzingError(f"non-finite JSON value is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FuzzingError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _require_nfc(value: Any, context: str = "root") -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise FuzzingError(f"non-NFC string at {context}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _require_nfc(item, f"{context}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _require_nfc(key, f"{context}.<key>")
            _require_nfc(item, f"{context}.{key}")


def canonical_json(value: Any) -> bytes:
    _require_nfc(value)
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def parse_json(raw: bytes, *, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FuzzingError(f"{label} is not UTF-8: {error}") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, FuzzingError) as error:
        raise FuzzingError(f"{label} is not strict JSON: {error}") from error
    _require_nfc(value, label)
    if raw != canonical_json(value):
        raise FuzzingError(f"{label} is not canonical sorted-key JSON")
    return value


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate_relative_path(value: str, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise FuzzingError(f"{label} must be a nonempty string")
    if unicodedata.normalize("NFC", value) != value or "\\" in value or "\x00" in value:
        raise FuzzingError(f"unsafe or noncanonical {label}: {value!r}")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise FuzzingError(f"control character in {label}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or "." in pure.parts or ".." in pure.parts or str(pure) != value:
        raise FuzzingError(f"unsafe or noncanonical {label}: {value!r}")
    if len(value.encode("utf-8")) > 4096:
        raise FuzzingError(f"{label} exceeds 4096 bytes")
    if any(len(part.encode("utf-8")) > 255 for part in pure.parts):
        raise FuzzingError(f"{label} component exceeds 255 bytes")
    return pure


def read_regular_file(root: Path, relative: str, *, label: str) -> bytes:
    """Read one single-link file through directory descriptors.

    O_NOFOLLOW is required.  The same final descriptor is hashed/consumed and
    metadata is compared before and after the read, avoiding path reopen races.
    """

    pure = validate_relative_path(relative, label=label)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise FuzzingError("O_NOFOLLOW and O_DIRECTORY are required")
    descriptors: list[int] = []
    try:
        current = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(current)
        for component in pure.parts[:-1]:
            current = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current,
            )
            metadata = os.fstat(current)
            if not stat.S_ISDIR(metadata.st_mode):
                raise FuzzingError(f"{label} ancestor is not a directory")
            descriptors.append(current)
        final = os.open(pure.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current)
        descriptors.append(final)
        before = os.fstat(final)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise FuzzingError(f"{label} must be a single-link regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(final, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(final)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            raise FuzzingError(f"{label} changed while it was read")
        raw = b"".join(chunks)
        if len(raw) != before.st_size:
            raise FuzzingError(f"{label} size changed while it was read")
        return raw
    except OSError as error:
        raise FuzzingError(f"cannot safely read {label}: {error}") from error
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def sha256_regular_file(root: Path, relative: str, *, label: str) -> tuple[str, int]:
    raw = read_regular_file(root, relative, label=label)
    return sha256_bytes(raw), len(raw)


def sha256_regular_file_with_mode(
    root: Path, relative: str, *, label: str
) -> tuple[str, int, int]:
    validate_relative_path(relative, label=label)
    path = root / relative
    before = path.lstat()
    raw = read_regular_file(root, relative, label=label)
    after = path.lstat()
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise FuzzingError(f"{label} changed around its descriptor-safe read")
    return sha256_bytes(raw), len(raw), stat.S_IMODE(before.st_mode)


def canonical_nonexecutable_mode(mode: int, *, label: str) -> str:
    """Normalize checkout umask variance to the Git regular-file mode 100644."""

    if not isinstance(mode, int) or isinstance(mode, bool) or mode < 0 or mode > 0o7777:
        raise FuzzingError(f"{label} mode is invalid")
    if mode & 0o111 or mode & 0o7000 or mode & 0o022 == 0o022:
        raise FuzzingError(f"{label} mode is executable, special, or world-writable")
    if mode not in (0o600, 0o640, 0o644, 0o660, 0o664):
        raise FuzzingError(f"{label} mode is outside reviewed nonexecutable checkout modes")
    return "100644"


def canonical_git_mode(mode: int, expected: str, *, label: str) -> str:
    """Normalize benign checkout umask variance while preserving exec intent."""

    if expected == "100644":
        return canonical_nonexecutable_mode(mode, label=label)
    if expected != "100755" or not isinstance(mode, int) or isinstance(mode, bool):
        raise FuzzingError(f"{label} expected Git mode is unreviewed")
    if mode & 0o7000 or mode & 0o002 or mode & 0o100 == 0:
        raise FuzzingError(f"{label} mode has wrong executable intent, special bits, or world-write")
    if mode not in (0o700, 0o750, 0o755, 0o770, 0o775):
        raise FuzzingError(f"{label} mode is outside reviewed executable checkout modes")
    return "100755"


def validate_control_source_binding_rows(rows: list[dict[str, Any]]) -> None:
    expected_paths = sorted(PACKAGE_C_CONTROL_INPUTS)
    observed_paths = [row.get("path") for row in rows]
    if observed_paths != expected_paths:
        raise FuzzingError("Package C control source binding is missing, surplus, duplicated, or reordered")
    for row in rows:
        expected_digest, expected_mode = PACKAGE_C_CONTROL_INPUTS[row["path"]]
        if row.get("sha256") != expected_digest or row.get("git_mode") != expected_mode:
            raise FuzzingError(f"Package C control source binding differs: {row['path']}")


def list_directory_exact(root: Path, relative: str, expected: Iterable[str], *, label: str) -> list[str]:
    pure = validate_relative_path(relative, label=label)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise FuzzingError("O_NOFOLLOW and O_DIRECTORY are required")
    descriptors: list[int] = []
    try:
        current = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(current)
        for component in pure.parts:
            current = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            descriptors.append(current)
        metadata = os.fstat(current)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_nlink < 2:
            raise FuzzingError(f"{label} must be a real directory")
        entries = sorted(os.listdir(current))
        wanted = sorted(expected)
        if entries != wanted:
            raise FuzzingError(
                f"{label} inventory differs: missing={sorted(set(wanted)-set(entries))} "
                f"surplus={sorted(set(entries)-set(wanted))}"
            )
        for entry in entries:
            validate_relative_path(entry, label=f"{label} member")
        return entries
    except OSError as error:
        raise FuzzingError(f"cannot safely enumerate {label}: {error}") from error
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def exact_keys(value: Any, expected: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FuzzingError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise FuzzingError(
            f"{label} keys differ: missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )
    return value


def validate_code_projection(value: Any, expected: Any, *, label: str) -> None:
    if canonical_json(value) != canonical_json(expected):
        raise FuzzingError(f"{label} differs from its reviewed in-code projection")


def parse_utc(value: str, *, label: str) -> dt.datetime:
    if not isinstance(value, str) or UTC_TIMESTAMP.fullmatch(value) is None:
        raise FuzzingError(f"{label} must use exact YYYY-MM-DDTHH:MM:SSZ form")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise FuzzingError(f"invalid {label}: {error}") from error


def freshness_ok(end: str, as_of: str, limit_seconds: int) -> bool:
    end_time = parse_utc(end, label="campaign end")
    as_of_time = parse_utc(as_of, label="as-of")
    if end_time > as_of_time:
        raise FuzzingError("campaign end is in the future")
    return int((as_of_time - end_time).total_seconds()) <= limit_seconds


def budget_ok(delivered_core_seconds: int, required_core_seconds: int) -> bool:
    for value, label in (
        (delivered_core_seconds, "delivered core-seconds"),
        (required_core_seconds, "required core-seconds"),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise FuzzingError(f"{label} must be a nonnegative integer")
    return delivered_core_seconds >= required_core_seconds


def coverage_regressed(baseline: int, current: int) -> bool:
    for value, label in ((baseline, "baseline"), (current, "current")):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise FuzzingError(f"coverage {label} must be a nonnegative integer")
    if baseline == 0:
        raise FuzzingError("coverage baseline may not be zero")
    # Literal guide rule: greater than 2%, with no floating-point rounding.
    return current < baseline and 100 * (baseline - current) > 2 * baseline


def aggregate_core_seconds(shards: list[dict[str, Any]], *, target_id: str) -> int:
    seen: set[str] = set()
    intervals: list[tuple[dt.datetime, dt.datetime]] = []
    total = 0
    for index, shard in enumerate(shards):
        record = exact_keys(
            shard,
            {"allocated_cores", "cpu_seconds", "end", "shard_id", "start", "target_id"},
            label=f"shard[{index}]",
        )
        if record["target_id"] != target_id:
            raise FuzzingError("campaign shard target mismatch")
        shard_id = record["shard_id"]
        if not isinstance(shard_id, str) or not shard_id or shard_id in seen:
            raise FuzzingError("duplicate or invalid shard ID")
        seen.add(shard_id)
        start = parse_utc(record["start"], label="shard start")
        end = parse_utc(record["end"], label="shard end")
        if end <= start:
            raise FuzzingError("shard end must follow shard start")
        cores = record["allocated_cores"]
        cpu_seconds = record["cpu_seconds"]
        if (
            not isinstance(cores, int)
            or isinstance(cores, bool)
            or cores <= 0
            or not isinstance(cpu_seconds, int)
            or isinstance(cpu_seconds, bool)
            or cpu_seconds < 0
        ):
            raise FuzzingError("invalid shard resource accounting")
        maximum = int((end - start).total_seconds()) * cores
        if cpu_seconds > maximum:
            raise FuzzingError("shard CPU time exceeds its allocation bound")
        for other_start, other_end in intervals:
            if start < other_end and other_start < end:
                raise FuzzingError("overlapping shard intervals may not be double counted")
        intervals.append((start, end))
        total += cpu_seconds
    return total


CRITICAL_ALGORITHMS: dict[str, tuple[str, ...]] = {
    "aes_gcm_semantic": (
        "AES",
        "AES-128-GCM",
        "AES-256-GCM",
        "AES-GCM",
        "GCM<B: BlockCipher>",
    ),
    "bls12_381_semantic": (
        "BLS12-381",
        "BLS12-381 Ethereum consensus signatures",
        "BLS12-381 signatures",
    ),
    "chacha_semantic": (
        "ChaCha20",
        "ChaCha20-Poly1305",
        "Poly1305",
        "XChaCha20-Poly1305",
    ),
    "ecdh_semantic": ("ECDH KEM",),
    "ecdsa_semantic": ("ECDSA",),
    "ecies_semantic": ("dcrypt ECIES",),
    "ed25519_semantic": ("Ed25519",),
    "hybrid_semantic": (
        "ECDH+ML-KEM hybrid KEM",
        "ECDSA+ML-DSA hybrid signature",
    ),
    "ml_dsa_semantic": ("ML-DSA",),
    "ml_kem_semantic": ("ML-KEM",),
}

EXPECTED_TARGET_ROW_COUNTS = {
    "aes_gcm_semantic": 70,
    "bls12_381_semantic": 74,
    "chacha_semantic": 40,
    "ecdh_semantic": 30,
    "ecdsa_semantic": 24,
    "ecies_semantic": 24,
    "ed25519_semantic": 8,
    "hybrid_semantic": 36,
    "ml_dsa_semantic": 42,
    "ml_kem_semantic": 24,
}

ALGORITHM_TARGET: dict[str, str] = {
    algorithm: target
    for target, algorithms in CRITICAL_ALGORITHMS.items()
    for algorithm in algorithms
}

EXISTING_SMOKE_TARGETS: dict[str, tuple[str, int]] = {
    "bls12_381_decoders": ("fuzz/fuzz_targets/bls12_381_decoders.rs", 4 * 1024),
    "hybrid_decoders": ("fuzz/fuzz_targets/hybrid_decoders.rs", 16 * 1024),
    "kem_decoders": ("fuzz/fuzz_targets/kem_decoders.rs", 16 * 1024),
    "legacy_xchacha_migration": ("fuzz/fuzz_targets/legacy_xchacha_migration.rs", 64 * 1024),
    "signature_decoders": ("fuzz/fuzz_targets/signature_decoders.rs", 16 * 1024),
    "stream_frames": ("fuzz/fuzz_targets/stream_frames.rs", 64 * 1024),
    "symmetric_decoders": ("fuzz/fuzz_targets/symmetric_decoders.rs", 64 * 1024),
}

SEMANTIC_TARGET_CAPS: dict[str, int] = {
    "aes_gcm_semantic": 64 * 1024,
    "bls12_381_semantic": 2 * 1024,
    "chacha_semantic": 64 * 1024,
    "ecdh_semantic": 4 * 1024,
    "ecdsa_semantic": 4 * 1024,
    "ecies_semantic": 32 * 1024,
    "ed25519_semantic": 4 * 1024,
    "hybrid_semantic": 4 * 1024,
    "ml_dsa_semantic": 2 * 1024,
    "ml_kem_semantic": 4 * 1024,
}

# Exact reviewed harness bytes. These literal pins are part of the registry
# semantics and must be deliberately updated for every target source change.
TARGET_SOURCE_SHA256: dict[str, str] = {
    "aes_gcm_semantic": "e573701809d926dcebb27c84168d94baea1a82fb8f5f9d09c17f4f27345b290b",
    "bls12_381_decoders": "1002fe75dc820593d556bf1ac71d947657dc2f0ab6be012155734fc321c86832",
    "bls12_381_semantic": "d40bb026b1ceb0baa9f6ff1989115a6d9f5d076d66e2f20c83f065e45eee7c89",
    "chacha_semantic": "fa6accf3adffa4e6e75421c4af6f5b14cbdbba8f1ecee304e6945eb79b99e1fd",
    "ecdh_semantic": "c8eaac26710cdd9b8624f2e0119d648165a02ad94540220e46959e9b0797b140",
    "ecdsa_semantic": "c4920309ee17828337848967621250043b46bf77b4fac8794a122ad8d40c4ba3",
    "ecies_semantic": "c041423b4248441793eb1eaf5dba1d2d15cf6254a55a344795eb40d23da2dc6f",
    "ed25519_semantic": "c7bd719aabc7922edabc8dde20d6746260ff6e95b6e0d7cfde5361b0eb5c4b0d",
    "hybrid_decoders": "abc8f570182e6c0cda0bcbdea64186a4dab1b1acd5c330e16afc3488cb76fa84",
    "hybrid_semantic": "fbb1a98376960176ded7c7ffafa7e8ac43332f997be416cc6db2df64f11c5a52",
    "kem_decoders": "a79cdbac86ea38f57790ccd60506c15fdf22dba87aea96cbfeec59b059d58d74",
    "legacy_xchacha_migration": "138476ed42dcb8e3a0a2b2988cf5fb05656bb16a1f7f12252f1546db39ab08f5",
    "ml_dsa_semantic": "a215fd4ba33021e93ee169f0edf0239b07f07b2d49a98d101f3ef00714ffc759",
    "ml_kem_semantic": "a212a07a492657690da70dd27413002db888e76e6d8874483579186e32c5654c",
    "signature_decoders": "cfde2f46a7bb3bb050e5c6050dabad484b0135590bee871d8bf1cf3d5d4d1d18",
    "stream_frames": "d4a11ccc20a3cdb630626c8c7cbd485c9a511c08edb6cb3edd0f2737ce3383c3",
    "symmetric_decoders": "c09bcf9f328efc4738e2a29dc36b2be1421926545dc11300f4bbd0519cbe6ec4",
}

# These paths are reviewed code, not data-file policy.  The selector emits only
# these exact values after checking the policy/registry literal trust anchors.
SEED_FOR_TARGET: dict[str, str] = {
    "aes_gcm_semantic": "seeds/aes_gcm_semantic",
    "bls12_381_decoders": "seeds/bls12_381_decoders",
    "bls12_381_semantic": "seeds/bls12_381_semantic",
    "chacha_semantic": "seeds/chacha_semantic",
    "ecdh_semantic": "seeds/ecdh_semantic",
    "ecdsa_semantic": "seeds/ecdsa_semantic",
    "ecies_semantic": "seeds/ecies_semantic",
    "ed25519_semantic": "seeds/ed25519_semantic",
    "hybrid_decoders": "seeds/hybrid_decoders",
    "hybrid_semantic": "seeds/hybrid_semantic",
    "kem_decoders": "seeds/kem_decoders",
    "legacy_xchacha_migration": "seeds/legacy_xchacha_migration",
    "ml_dsa_semantic": "seeds/ml_dsa_semantic",
    "ml_kem_semantic": "seeds/ml_kem_semantic",
    "signature_decoders": "seeds/signature_decoders",
    "stream_frames": "seeds/stream_frames",
    "symmetric_decoders": "seeds/symmetric_decoders",
}

REVIEWED_SEED_MEMBERS: dict[str, tuple[str, ...]] = {
    "aes_gcm_semantic": ("aes-128-gcm", "aes-256-gcm"),
    "bls12_381_decoders": ("malformed-zero",),
    "bls12_381_semantic": (
        "augmentation", "basic", "basic-aggregate", "eth2-pop-v4", "proof-of-possession"
    ),
    "chacha_semantic": ("chacha-xchacha-poly1305",),
    "ecdh_semantic": ("k-256", "p-224", "p-256", "p-384", "p-521"),
    "ecdsa_semantic": tuple(
        f"p-{curve}-{state}"
        for curve in ("224", "256", "384", "521")
        for state in (
            "deterministic",
            "key-roundtrip",
            "sign-verify",
            "signature-roundtrip",
            "wrong-message",
            "wrong-signature",
        )
    ),
    "ecies_semantic": ("p-224", "p-256", "p-384", "p-521"),
    "ed25519_semantic": ("deterministic-strict",),
    "hybrid_decoders": ("framing-lengths",),
    "hybrid_semantic": (
        "ecdsa-ml-dsa-65-signature",
        "k256-ml-kem-512",
        "p256-ml-kem-512",
        "p256-ml-kem-768",
        "p384-ml-kem-1024",
        "p521-ml-kem-1024",
    ),
    "kem_decoders": ("canonical-length-expansion",),
    "legacy_xchacha_migration": ("raw-ciphertext", "valid-no-aad", "valid-with-aad"),
    "ml_dsa_semantic": (
        "ml-dsa-44-deterministic",
        "ml-dsa-44-hedged",
        "ml-dsa-65-deterministic",
        "ml-dsa-65-hedged",
        "ml-dsa-87-deterministic",
        "ml-dsa-87-hedged",
    ),
    "ml_kem_semantic": ("ml-kem-1024", "ml-kem-512", "ml-kem-768"),
    "signature_decoders": ("ml-dsa-44-selector", "ml-dsa-65-selector", "ml-dsa-87-selector"),
    "stream_frames": ("aes-gcm-stream", "chacha20-poly1305-stream"),
    "symmetric_decoders": ("malformed-packages",),
}

DICTIONARY_FOR_TARGET: dict[str, str] = {
    "aes_gcm_semantic": "dictionaries/crypto_tokens.dict",
    "bls12_381_decoders": "dictionaries/crypto_tokens.dict",
    "bls12_381_semantic": "dictionaries/crypto_tokens.dict",
    "chacha_semantic": "dictionaries/crypto_tokens.dict",
    "ecdh_semantic": "dictionaries/crypto_tokens.dict",
    "ecdsa_semantic": "dictionaries/crypto_tokens.dict",
    "ecies_semantic": "dictionaries/framing.dict",
    "ed25519_semantic": "dictionaries/crypto_tokens.dict",
    "hybrid_decoders": "dictionaries/framing.dict",
    "hybrid_semantic": "dictionaries/framing.dict",
    "kem_decoders": "dictionaries/crypto_tokens.dict",
    "legacy_xchacha_migration": "dictionaries/crypto_tokens.dict",
    "ml_dsa_semantic": "dictionaries/crypto_tokens.dict",
    "ml_kem_semantic": "dictionaries/crypto_tokens.dict",
    "signature_decoders": "dictionaries/crypto_tokens.dict",
    "stream_frames": "dictionaries/framing.dict",
    "symmetric_decoders": "dictionaries/crypto_tokens.dict",
}

SMOKE_GROUPS: dict[str, tuple[str, ...]] = {
    "hybrid": ("hybrid_decoders", "hybrid_semantic"),
    "kem": ("ecdh_semantic", "ecies_semantic", "kem_decoders", "ml_kem_semantic"),
    "signatures": (
        "bls12_381_decoders",
        "bls12_381_semantic",
        "ecdsa_semantic",
        "ed25519_semantic",
        "ml_dsa_semantic",
        "signature_decoders",
    ),
    "symmetric": (
        "aes_gcm_semantic",
        "chacha_semantic",
        "legacy_xchacha_migration",
        "stream_frames",
        "symmetric_decoders",
    ),
}

HARNESS_LOOP_CONTROL: dict[str, tuple[int, int, tuple[str, ...]]] = {
    "aes_gcm_semantic": (1, 5, ("for boundary in [0usize, 1, 15, 16, 17]",)),
    "bls12_381_decoders": (1, 192, ("for (index, byte) in output.iter_mut().enumerate()",)),
    "bls12_381_semantic": (0, 0, ()),
    "chacha_semantic": (0, 0, ()),
    "ecdh_semantic": (0, 0, ()),
    "ecdsa_semantic": (0, 0, ()),
    "ecies_semantic": (0, 0, ()),
    "ed25519_semantic": (0, 0, ()),
    "hybrid_decoders": (0, 0, ()),
    "hybrid_semantic": (0, 0, ()),
    "kem_decoders": (1, 4_896, ("for (index, byte) in output.iter_mut().enumerate()",)),
    "legacy_xchacha_migration": (0, 0, ()),
    "ml_dsa_semantic": (0, 0, ()),
    "ml_kem_semantic": (0, 0, ()),
    "signature_decoders": (1, 4_896, ("for (index, byte) in output.iter_mut().enumerate()",)),
    "stream_frames": (
        7,
        4_098,
        (
            "for _ in 0..4096",
            "for (index, byte) in seed.iter_mut().enumerate()",
            "for _ in 0..SEMANTIC_READ_MAX",
        ),
    ),
    "symmetric_decoders": (1, 32, ("for (index, byte) in output.iter_mut().enumerate()",)),
}

# Maximum support::seed invocations along one harness path. support::rng calls
# seed exactly once. Each seed performs fixed32 + input-length iterations.
SEMANTIC_SEED_SYNTACTIC_CALLS: dict[str, int] = {
    "aes_gcm_semantic": 4,
    "bls12_381_semantic": 2,
    "chacha_semantic": 5,
    "ecdh_semantic": 2,
    "ecdsa_semantic": 4,
    "ecies_semantic": 3,
    "ed25519_semantic": 1,
    "hybrid_semantic": 3,
    "ml_dsa_semantic": 3,
    "ml_kem_semantic": 2,
}

SEMANTIC_SEED_MAX_DYNAMIC_CALLS: dict[str, int] = {
    **SEMANTIC_SEED_SYNTACTIC_CALLS,
    "bls12_381_semantic": 4,
    "hybrid_semantic": 2,
    "ecdsa_semantic": 1,
}

SOURCE_UNBOUNDED_PRIMITIVES: dict[str, tuple[str, ...]] = {
    "bls12_381_semantic": ("internal scalar/key rejection sampling",),
    "ecdh_semantic": ("EC key generation rejection loop",),
    "ecdsa_semantic": ("EC key generation rejection loop", "RFC6979 signing rejection loop"),
    "ecies_semantic": ("EC key generation rejection loop",),
    "hybrid_semantic": (
        "ECDSA RFC6979 and EC key generation rejection loops",
        "ML-DSA RejBoundedPoly, SampleInBall, and matrix/NTT rejection",
        "ML-KEM sample_ntt",
    ),
    "ml_dsa_semantic": ("ML-DSA RejBoundedPoly, SampleInBall, and matrix/NTT rejection",),
    "ml_kem_semantic": ("ML-KEM sample_ntt",),
}


def build_policy() -> dict[str, Any]:
    return {
        "budgets_core_seconds": {
            "rc_critical": RC_CRITICAL_CORE_SECONDS,
            "rc_secondary": RC_SECONDARY_CORE_SECONDS,
            "weekly_critical": WEEKLY_CRITICAL_CORE_SECONDS,
            "weekly_secondary": WEEKLY_SECONDARY_CORE_SECONDS,
        },
        "canonicalization": {
            "duplicate_keys": "forbidden",
            "encoding": "UTF-8",
            "final_newline": True,
            "floats": "forbidden",
            "key_order": "Unicode code-point ascending",
            "normalization": "NFC",
            "whitespace": "two-space-indent",
        },
        "content_policy": f"{CONTENT_PREFIX}-policy-v1",
        "counts": {
            "critical_family_rows": EXPECTED_CRITICAL_ROWS,
            "explicit_blocker_rows": EXPECTED_EXPLICIT_BLOCKERS,
            "existing_smoke_targets": len(EXISTING_SMOKE_TARGETS),
            "planned_semantic_targets": len(SEMANTIC_TARGET_CAPS),
            "total_atomic_rows": EXPECTED_TOTAL_ROWS,
        },
        "coverage_policy": {
            "baseline_must_be_nonzero": True,
            "comparison_binding": "same-target-toolchain-corpus-profiler-config",
            "edge_and_function_required": True,
            "integer_denominator": 100,
            "regression_numerator": 2,
            "rule": "fail when 100*(baseline-current) > 2*baseline",
            "semantic_state_required": True,
        },
        "differential_evidence_policy": {
            "accepted_differential_evidence": "none",
            "package_b_shared_or_unknown_lineage": "corroborative-only",
            "required_family_blocker": "no-independent-implementation-closure",
        },
        "freshness_seconds": {
            "critical_nightly": CRITICAL_FRESHNESS_SECONDS,
            "weekly": WEEKLY_FRESHNESS_SECONDS,
        },
        "release_gate": {
            "blocked_status": "HOLD",
            "ci_may_pass_structural_controls": True,
            "operational_evidence_promotion_enabled": False,
            "release_exit_code_with_blockers": 3,
            "release_must_fail_with_any_blocker": True,
        },
        "resource_policy": {
            "archive_max_bytes": 64 * 1024 * 1024,
            "crash_bundle_max_bytes": 16 * 1024 * 1024,
            "expensive_crypto_timeout_seconds": EXPENSIVE_CRYPTO_TIMEOUT_SECONDS,
            "hybrid_semantic_timeout_seconds": HYBRID_SEMANTIC_TIMEOUT_SECONDS,
            "ignore_crashes": False,
            "ignore_ooms": False,
            "ignore_timeouts": False,
            "input_cap_must_match_registry_runner_and_harness": True,
            "parser_timeout_seconds": PARSER_TIMEOUT_SECONDS,
            "rss_limit_mb": RSS_LIMIT_MB,
            "timeout_floor_seconds": 1,
            "timeout_formula_multiplier": 10,
        },
        "retention_policy": {
            "attestations_minimum_days": 365,
            "coverage_minimum_days": 365,
            "current_corpus": "indefinite",
            "daily_corpus_days": 30,
            "logs_days": 90,
            "regression_corpus": "indefinite",
            "weekly_corpus_weeks": 52,
        },
        "schema_version": SCHEMA_VERSION,
        "smoke_policy": {
            "counts_as_persistent_campaign": False,
            "integrated_address_sanitizer": {
                "asan_options": INTEGRATED_ASAN_OPTIONS,
                "defined_function_symbols": list(INTEGRATED_ASAN_FUNCTION_SYMBOLS),
                "runtime_sha256": INTEGRATED_ASAN_RUNTIME_SHA256,
            },
            "runs": SMOKE_RUNS,
            "seed": SMOKE_SEED,
        },
        "source_binding": {
            "framework_subject_commit": FRAMEWORK_SUBJECT_COMMIT,
            "framework_subject_manifest_sha256": FRAMEWORK_SUBJECT_MANIFEST_SHA256,
            "framework_subject_tree": FRAMEWORK_SUBJECT_TREE,
            "package_b_assurance_commit": PACKAGE_B_COMMIT,
            "package_b_assurance_tree": PACKAGE_B_TREE,
            "package_b_subject_commit": PACKAGE_B_SUBJECT_COMMIT,
            "package_b_subject_tree": PACKAGE_B_SUBJECT_TREE,
        },
        "status": STATUS,
        "trust_policy": {
            "authoritative_store": "unprovisioned",
            "authoritative_writes_from_forks": False,
            "content_addressed_objects_are_append_only": True,
            "crash_store_is_private_and_separate": True,
            "external_mutation_authorized": False,
            "local_tools_network_policy": "forbidden",
            "promotion_requires_authenticated_writer_and_review": True,
            "signing_identity": "unprovisioned",
            "untrusted_corpus_access": "read-only",
            "untrusted_crash_access": "none",
        },
    }


def _target_record(
    identifier: str,
    source: str,
    cap: int,
    *,
    kind: str,
    algorithms: Iterable[str],
    mapped_rows: int,
    tier: str,
) -> dict[str, Any]:
    critical = tier == "critical"
    unbounded_internal = identifier in SOURCE_UNBOUNDED_PRIMITIVES
    fixed_signing_window = 814 if identifier in {"ml_dsa_semantic", "hybrid_semantic"} else None
    if identifier == "hybrid_semantic":
        timeout_seconds = HYBRID_SEMANTIC_TIMEOUT_SECONDS
    elif critical:
        timeout_seconds = EXPENSIVE_CRYPTO_TIMEOUT_SECONDS
    else:
        timeout_seconds = PARSER_TIMEOUT_SECONDS
    reviewed_semantic_states = list(REVIEWED_SEED_MEMBERS[identifier])
    return {
        "cargo_bin": identifier,
        "family_algorithms": sorted(algorithms),
        "harness_input_cap_bytes": cap,
        "harness_input_cap_status": "required-present",
        "id": identifier,
        "kind": kind,
        "semantic_state_control": (
            {
                "curve_states": 4,
                "max_ec_keygen_calls_per_input": 1,
                "max_rfc6979_sign_calls_per_input": 2,
                "operation_states_per_curve": 6,
                "state_names": [
                    "deterministic",
                    "key-roundtrip",
                    "sign-verify",
                    "signature-roundtrip",
                    "wrong-message",
                    "wrong-signature",
                ],
            }
            if identifier == "ecdsa_semantic"
            else None
        ),
        "mapped_atomic_row_count": mapped_rows,
        "operational_status": (
            "candidate-unaccepted-unprovisioned"
            if kind == "semantic-candidate"
            else "deterministic-smoke-only-not-campaign-evidence"
        ),
        "required_freshness_seconds": (
            CRITICAL_FRESHNESS_SECONDS if critical else WEEKLY_FRESHNESS_SECONDS
        ),
        "required_rc_core_seconds": (
            RC_CRITICAL_CORE_SECONDS if critical else RC_SECONDARY_CORE_SECONDS
        ),
        "required_weekly_core_seconds": (
            WEEKLY_CRITICAL_CORE_SECONDS if critical else WEEKLY_SECONDARY_CORE_SECONDS
        ),
        "reviewed_semantic_states": reviewed_semantic_states,
        "reviewed_semantic_states_sha256": sha256_bytes(canonical_json(reviewed_semantic_states)),
        "resource_limits": {
            "input_max_bytes": cap,
            "explicit_harness_loop_count": HARNESS_LOOP_CONTROL[identifier][0],
            "explicit_harness_loop_max_iterations": HARNESS_LOOP_CONTROL[identifier][1],
            "support_seed_syntactic_calls": SEMANTIC_SEED_SYNTACTIC_CALLS.get(identifier, 0),
            "support_seed_max_dynamic_calls_per_input": SEMANTIC_SEED_MAX_DYNAMIC_CALLS.get(identifier, 0),
            "support_seed_iterations_per_call": (
                f"32+input_len<=32+{cap}" if identifier in SEMANTIC_SEED_SYNTACTIC_CALLS else None
            ),
            "malloc_limit_mb": RSS_LIMIT_MB,
            "rejection_control": {
                "caller_rng_max_bytes": None,
                "fixed_signing_attempt_window_per_call": fixed_signing_window,
                "internal_attempt_cap": None if unbounded_internal else fixed_signing_window,
                "release_blocker": (
                    "internal-rejection-loop-timeout-bounded-not-attempt-bounded"
                    if unbounded_internal
                    else None
                ),
                "timeout_bounded": unbounded_internal,
                "unbounded_internal_primitives": list(SOURCE_UNBOUNDED_PRIMITIVES.get(identifier, ())),
            },
            "rss_limit_mb": RSS_LIMIT_MB,
            "stack_limit_kib": 8_192,
            "timeout_seconds": timeout_seconds,
        },
        "runner_input_cap_bytes": cap,
        "seed_selector_path": SEED_FOR_TARGET.get(identifier),
        "dictionary_selector_path": DICTIONARY_FOR_TARGET[identifier],
        "source": source,
        "source_sha256": TARGET_SOURCE_SHA256[identifier],
        "tier": tier,
    }


def build_registry() -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    for identifier, (source, cap) in EXISTING_SMOKE_TARGETS.items():
        targets.append(
            _target_record(
                identifier,
                source,
                cap,
                kind="existing-smoke",
                algorithms=(),
                mapped_rows=0,
                tier="secondary",
            )
        )
    for identifier, cap in SEMANTIC_TARGET_CAPS.items():
        targets.append(
            _target_record(
                identifier,
                f"fuzz/fuzz_targets/{identifier}.rs",
                cap,
                kind="semantic-candidate",
                algorithms=CRITICAL_ALGORITHMS[identifier],
                mapped_rows=EXPECTED_TARGET_ROW_COUNTS[identifier],
                tier="critical",
            )
        )
    targets.sort(key=lambda item: item["id"])
    grouped = [target for group in SMOKE_GROUPS.values() for target in group]
    registered = [target["id"] for target in targets]
    if sorted(grouped) != registered or len(grouped) != len(set(grouped)):
        raise FuzzingError("the four smoke groups must partition the exact target registry")
    return {
        "content_policy": f"{CONTENT_PREFIX}-target-registry-v1",
        "schema_version": SCHEMA_VERSION,
        "smoke_groups": [
            {"group_id": group, "target_ids": list(targets_in_group)}
            for group, targets_in_group in sorted(SMOKE_GROUPS.items())
        ],
        "status": STATUS,
        "targets": targets,
    }


def policy_semantic_sha256() -> str:
    return sha256_bytes(canonical_json(build_policy()))


def registry_semantic_sha256() -> str:
    return sha256_bytes(canonical_json(build_registry()))


def assert_code_pins() -> None:
    policy_digest = policy_semantic_sha256()
    registry_digest = registry_semantic_sha256()
    if EXPECTED_POLICY_SEMANTIC_SHA256 == "UNSTABLE" or EXPECTED_REGISTRY_SEMANTIC_SHA256 == "UNSTABLE":
        raise FuzzingError(
            "normative semantic SHA-256 pins remain UNSTABLE; run the integration pin step"
        )
    if policy_digest != EXPECTED_POLICY_SEMANTIC_SHA256:
        raise FuzzingError("in-code policy semantic digest differs from its literal trust anchor")
    if registry_digest != EXPECTED_REGISTRY_SEMANTIC_SHA256:
        raise FuzzingError("in-code registry semantic digest differs from its literal trust anchor")


def load_atomic_rows(repo: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    raw = read_regular_file(
        repo,
        "assurance/atomic-operations.toml",
        label="atomic operations",
    )
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise FuzzingError(f"cannot parse atomic operations: {error}") from error
    exact_keys(
        document,
        {"operation", "schema-version", "unreviewed-gap", "unreviewed-gap-defaults"},
        label="atomic operations root",
    )
    if document["schema-version"] != 2:
        raise FuzzingError("atomic operations schema version differs")
    operations = document["operation"]
    gaps = document["unreviewed-gap"]
    defaults = document["unreviewed-gap-defaults"]
    if len(operations) != EXPECTED_CURATED_ROWS or len(gaps) != EXPECTED_UNREVIEWED_GAPS:
        raise FuzzingError(
            f"atomic row counts differ: curated={len(operations)} gaps={len(gaps)}"
        )
    identifiers = [str(row.get("id", "")) for row in [*operations, *gaps]]
    if any(not value for value in identifiers) or len(identifiers) != len(set(identifiers)):
        raise FuzzingError("atomic row IDs are empty or duplicated")
    return operations, gaps, defaults


def build_row_mapping(repo: Path) -> dict[str, Any]:
    operations, gaps, defaults = load_atomic_rows(repo)
    rows: list[dict[str, Any]] = []
    per_target: dict[str, int] = {target: 0 for target in CRITICAL_ALGORITHMS}
    for source_kind, source_rows in (
        ("curated-operation", operations),
        ("unreviewed-gap", gaps),
    ):
        for source in source_rows:
            identifier = source["id"]
            algorithm = str(source.get("algorithm", ""))
            target = ALGORITHM_TARGET.get(algorithm) if source_kind == "curated-operation" else None
            if target is not None:
                per_target[target] += 1
                disposition = "mapped-planned-semantic-blocked"
                blockers = (["final-subject-binding-unstable"] if STATUS != "STABLE-final-subject-bound" else []) + [
                    "instrumentation-positive-control-unproven",
                    "no-independent-implementation-closure",
                    "persistent-campaign-unprovisioned",
                    "semantic-target-not-operationally-evidenced",
                ]
                reason = "critical family is mapped, but no operational campaign evidence is accepted"
            elif source_kind == "unreviewed-gap":
                disposition = "explicit-blocker"
                blockers = ["atomic-row-unreviewed"] + (["final-subject-binding-unstable"] if STATUS != "STABLE-final-subject-bound" else []) + [
                    "no-reviewed-semantic-target",
                    "persistent-campaign-unprovisioned",
                ]
                reason = "unreviewed atomic gap cannot acquire fuzz assurance"
            else:
                disposition = "explicit-blocker"
                blockers = (["final-subject-binding-unstable"] if STATUS != "STABLE-final-subject-bound" else []) + [
                    "outside-package-c-critical-family",
                    "persistent-campaign-unprovisioned",
                ]
                reason = "row is outside the exact Package C critical-family selector"
            prior = source.get("fuzz-target", defaults.get("fuzz-target", "blocked: unreviewed gap"))
            rows.append(
                {
                    "algorithm": algorithm,
                    "accepted_differential_evidence": "none",
                    "blocker_codes": blockers,
                    "disposition": disposition,
                    "prior_fuzz_disposition": str(prior),
                    "reason": reason,
                    "release_status": "blocked",
                    "row_id": identifier,
                    "row_kind": str(source.get("row-kind", "")),
                    "source_kind": source_kind,
                    "source_record_sha256": sha256_bytes(canonical_json(source)),
                    "target_id": target,
                }
            )
    rows.sort(key=lambda item: item["row_id"])
    if len(rows) != EXPECTED_TOTAL_ROWS or len({row["row_id"] for row in rows}) != len(rows):
        raise FuzzingError("generated row mapping is incomplete or duplicated")
    mapped = sum(row["target_id"] is not None for row in rows)
    if mapped != EXPECTED_CRITICAL_ROWS or per_target != EXPECTED_TARGET_ROW_COUNTS:
        raise FuzzingError(
            f"critical selector drift: total={mapped} per_target={dict(sorted(per_target.items()))}"
        )
    # Never bind the containing assurance ledger here: doing so would create a
    # self-cycle once that ledger binds this generated mapping.
    input_paths = (
        "assurance/atomic-operations.toml",
        "assurance/public-api-snapshot.json",
    )
    inputs = []
    for path in input_paths:
        digest, size = sha256_regular_file(repo, path, label=f"mapping input {path}")
        inputs.append({"path": path, "sha256": digest, "size": size})
    return {
        "content_policy": f"{CONTENT_PREFIX}-row-mapping-v1",
        "counts": {
            "critical_family_rows": mapped,
            "curated_rows": len(operations),
            "explicit_blocker_rows": len(rows) - mapped,
            "release_blocked_rows": len(rows),
            "total_atomic_rows": len(rows),
            "unreviewed_gap_rows": len(gaps),
        },
        "generated_inputs": inputs,
        "per_target_counts": [
            {"row_count": count, "target_id": target}
            for target, count in sorted(per_target.items())
        ],
        "policy_semantic_sha256": policy_semantic_sha256(),
        "registry_semantic_sha256": registry_semantic_sha256(),
        "rows": rows,
        "rows_sha256": sha256_bytes(canonical_json(rows)),
        "schema_version": SCHEMA_VERSION,
        "source_binding": build_policy()["source_binding"],
        "status": STATUS,
    }


def _extract_integer_expression(expression: str) -> int:
    try:
        tree = ast.parse(expression.strip(), mode="eval")
    except SyntaxError as error:
        raise FuzzingError(f"invalid INPUT_MAX expression: {expression!r}") from error

    def evaluate(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            if node.value < 0:
                raise FuzzingError("negative INPUT_MAX is forbidden")
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
            left, right = evaluate(node.left), evaluate(node.right)
            return left + right if isinstance(node.op, ast.Add) else left * right
        raise FuzzingError("INPUT_MAX may contain only nonnegative integers, +, and *")

    value = evaluate(tree)
    if value <= 0 or value > 16 * 1024 * 1024:
        raise FuzzingError("INPUT_MAX is outside the reviewed bound")
    return value


def _strip_rust_comments_and_literals(text: str) -> str:
    """Blank comments/string literals while preserving code offsets/newlines."""

    result = list(text)
    index = 0
    length = len(text)

    def blank(start: int, end: int) -> None:
        for offset in range(start, end):
            if result[offset] != "\n":
                result[offset] = " "

    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            end = length if end < 0 else end
            blank(index, end)
            index = end
            continue
        if text.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < length and depth:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise FuzzingError("unterminated Rust block comment")
            blank(start, index)
            continue
        raw_match = re.match(r'(?:br|r)(?P<hashes>#{0,255})"', text[index:])
        if raw_match:
            start = index
            terminator = '"' + raw_match.group("hashes")
            index += raw_match.end()
            end = text.find(terminator, index)
            if end < 0:
                raise FuzzingError("unterminated Rust raw string")
            index = end + len(terminator)
            blank(start, index)
            continue
        prefix_length = 1 if text[index] == '"' else 2 if text.startswith('b"', index) else 0
        if prefix_length:
            start = index
            index += prefix_length
            escaped = False
            while index < length:
                character = text[index]
                index += 1
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    break
            else:
                raise FuzzingError("unterminated Rust string")
            blank(start, index)
            continue
        index += 1
    return "".join(result)


def source_input_cap(raw: bytes, *, label: str) -> int:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FuzzingError(f"{label} is not UTF-8") from error
    code = _strip_rust_comments_and_literals(text)
    matches = re.findall(r"(?m)^const INPUT_MAX: usize = ([^;]+);$", code)
    if len(matches) != 1:
        raise FuzzingError(f"{label} must contain exactly one private INPUT_MAX constant")
    entries = list(re.finditer(r"\bfuzz_target\s*!", code))
    if len(entries) != 1:
        raise FuzzingError(f"{label} must contain exactly one fuzz_target entry")
    prologue = re.compile(
        r"\bfuzz_target\s*!\s*\(\s*\|(?P<raw>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*&\s*\[\s*u8\s*\]\s*\|"
        r"\s*\{\s*let\s+(?P=raw)\s*=\s*&\s*(?P=raw)\s*\[\s*\.\.\s*(?P=raw)"
        r"\s*\.\s*len\s*\(\s*\)\s*\.\s*min\s*\(\s*INPUT_MAX\s*\)\s*\]\s*;"
    )
    match = prologue.search(code)
    if match is None or match.start() != entries[0].start():
        raise FuzzingError(
            f"{label} must cap the owned raw fuzz parameter as its first executable statement"
        )
    return _extract_integer_expression(matches[0])


def cargo_fuzz_bins(repo: Path) -> dict[str, str]:
    raw = read_regular_file(repo, "fuzz/Cargo.toml", label="fuzz Cargo.toml")
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise FuzzingError(f"cannot parse fuzz Cargo.toml: {error}") from error
    result: dict[str, str] = {}
    for index, record in enumerate(document.get("bin", [])):
        exact_keys(record, {"bench", "doc", "name", "path", "test"}, label=f"Cargo bin[{index}]")
        name, path = record["name"], record["path"]
        if not isinstance(name, str) or TARGET_ID.fullmatch(name) is None or name in result:
            raise FuzzingError("fuzz Cargo bins contain an invalid or duplicate target")
        if record["bench"] is not False or record["doc"] is not False or record["test"] is not False:
            raise FuzzingError(f"fuzz Cargo bin {name} must disable test/doc/bench")
        validate_relative_path(path, label=f"Cargo bin source for {name}")
        result[name] = f"fuzz/{path}"
    return result


def verify_registry_against_sources(repo: Path, registry: dict[str, Any]) -> None:
    bins = cargo_fuzz_bins(repo)
    support_raw = read_regular_file(repo, "fuzz/fuzz_targets/support.rs", label="semantic support source")
    support_code = _strip_rust_comments_and_literals(support_raw.decode("utf-8"))
    if support_code.count("for (index, byte) in output.iter_mut().enumerate()") != 1 or support_code.count("for (index, source) in input.iter().enumerate()") != 1:
        raise FuzzingError("semantic support seed loop forms differ")
    if support_code.count("ChaCha20Rng::from_seed(seed(input, domain))") != 1:
        raise FuzzingError("semantic support rng/seed transitive binding differs")
    records = registry["targets"]
    registered = {record["id"]: record for record in records}
    if set(bins) != set(registered):
        raise FuzzingError(
            f"Cargo/registry target mismatch: missing={sorted(set(bins)-set(registered))} "
            f"extra={sorted(set(registered)-set(bins))}"
        )
    for identifier, record in registered.items():
        if bins[identifier] != record["source"]:
            raise FuzzingError(f"Cargo/registry source mismatch for {identifier}")
        raw = read_regular_file(repo, record["source"], label=f"target source {identifier}")
        if sha256_bytes(raw) != record["source_sha256"]:
            raise FuzzingError(f"target source SHA-256 differs for {identifier}")
        cap = source_input_cap(raw, label=f"target source {identifier}")
        expected = record["resource_limits"]["input_max_bytes"]
        if cap != expected or record["harness_input_cap_bytes"] != expected or record["runner_input_cap_bytes"] != expected:
            raise FuzzingError(f"registry/runner/harness input cap mismatch for {identifier}")
        code = _strip_rust_comments_and_literals(raw.decode("utf-8"))
        expected_count, expected_max, required_fragments = HARNESS_LOOP_CONTROL[identifier]
        actual_count = len(re.findall(r"\b(?:for|while|loop)\b", code))
        if actual_count != expected_count:
            raise FuzzingError(f"explicit harness loop count differs for {identifier}")
        if record["resource_limits"]["explicit_harness_loop_max_iterations"] != expected_max:
            raise FuzzingError(f"registry harness loop maximum differs for {identifier}")
        for fragment in required_fragments:
            expected_occurrences = 4 if identifier == "stream_frames" and fragment == "for _ in 0..4096" else 2 if identifier == "stream_frames" and fragment == "for _ in 0..SEMANTIC_READ_MAX" else 1
            if code.count(fragment) != expected_occurrences:
                raise FuzzingError(f"reviewed harness loop form differs for {identifier}: {fragment}")
        seed_calls = len(re.findall(r"support::seed\s*\(", code))
        rng_calls = len(re.findall(r"support::rng\s*\(", code))
        expected_seed_calls = SEMANTIC_SEED_SYNTACTIC_CALLS.get(identifier, 0)
        if seed_calls + rng_calls != expected_seed_calls:
            raise FuzzingError(f"semantic support seed call multiplicity differs for {identifier}")
        if identifier == "ecdsa_semantic":
            exact_fragments = {
                "support::selector($input.get(1).copied().unwrap_or(0), 6)": 1,
                "support::selector(selector, 4)": 1,
                "<$scheme>::keypair(&mut rng)": 4,
                "<$scheme>::sign(message, &secret)": 6,
                "let repeated =": 1,
            }
            for fragment, count in exact_fragments.items():
                if code.count(fragment) != count:
                    raise FuzzingError(f"ECDSA semantic state shape differs: {fragment}")
            state = record["semantic_state_control"]
            if state != {
                "curve_states": 4,
                "max_ec_keygen_calls_per_input": 1,
                "max_rfc6979_sign_calls_per_input": 2,
                "operation_states_per_curve": 6,
                "state_names": [
                    "deterministic",
                    "key-roundtrip",
                    "sign-verify",
                    "signature-roundtrip",
                    "wrong-message",
                    "wrong-signature",
                ],
            }:
                raise FuzzingError("ECDSA registry semantic state model differs")


def build_source_bindings(repo: Path) -> dict[str, Any]:
    registry = build_registry()
    paths = {
        "fuzz/Cargo.lock",
        "fuzz/Cargo.toml",
        "fuzz/fuzz_targets/support.rs",
        *(target["source"] for target in registry["targets"]),
        *PACKAGE_C_CONTROL_INPUTS,
    }
    files = []
    for path in sorted(paths):
        digest, size, mode = sha256_regular_file_with_mode(
            repo, path, label=f"fuzz source binding {path}"
        )
        expected_mode = PACKAGE_C_CONTROL_INPUTS.get(path, (None, "100644"))[1]
        git_mode = canonical_git_mode(mode, expected_mode, label=f"fuzz source binding {path}")
        files.append(
            {
                "git_mode": git_mode,
                "path": path,
                "sha256": digest,
                "size": size,
            }
        )
        if path in PACKAGE_C_CONTROL_INPUTS and digest != PACKAGE_C_CONTROL_INPUTS[path][0]:
            raise FuzzingError(f"Package C workflow/release control input differs: {path}")
    control_rows = [row for row in files if row["path"] in PACKAGE_C_CONTROL_INPUTS]
    validate_control_source_binding_rows(control_rows)
    control_digest = sha256_bytes(
        (
            json.dumps(
                control_rows,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    )
    if control_digest != CONTROL_INPUTS_SHA256:
        raise FuzzingError("Package C compact control-input binding digest differs")
    return {
        "content_policy": "dcrypt-fuzzing-source-bindings-v1",
        "counts": {
            "cargo_control_files": 2,
            "ci_release_control_files": len(PACKAGE_C_CONTROL_INPUTS),
            "shared_support_files": 1,
            "target_source_files": 17,
            "total_files": len(files),
        },
        "files": files,
        "files_sha256": sha256_bytes(canonical_json(files)),
        "registry_semantic_sha256": registry_semantic_sha256(),
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
    }


def parse_target_listing(stdout: str, returncode: int, registry_ids: set[str]) -> list[str]:
    if returncode != 0:
        raise FuzzingError(f"cargo fuzz list failed with status {returncode}")
    rows = stdout.splitlines()
    if not rows or any(TARGET_ID.fullmatch(row) is None for row in rows):
        raise FuzzingError("cargo fuzz list produced an empty or invalid target")
    if rows != sorted(set(rows)):
        raise FuzzingError("cargo fuzz list must be sorted and duplicate-free")
    if set(rows) != registry_ids:
        raise FuzzingError("cargo fuzz list differs from the authoritative registry")
    return rows


def canonical_fuzz_argv(
    target: dict[str, Any], *, artifact_prefix: str, dictionary_path: str | None = None
) -> list[str]:
    if not isinstance(artifact_prefix, str) or not artifact_prefix.endswith("/"):
        raise FuzzingError("artifact prefix must be a nonempty directory path ending in slash")
    return [
        f"-runs={SMOKE_RUNS}",
        f"-seed={SMOKE_SEED}",
        f"-max_len={target['runner_input_cap_bytes']}",
        f"-timeout={target['resource_limits']['timeout_seconds']}",
        f"-rss_limit_mb={target['resource_limits']['rss_limit_mb']}",
        f"-malloc_limit_mb={target['resource_limits']['malloc_limit_mb']}",
        "-jobs=1",
        "-workers=1",
        "-ignore_crashes=0",
        "-ignore_ooms=0",
        "-ignore_timeouts=0",
        f"-dict={dictionary_path or target['dictionary_selector_path']}",
        f"-artifact_prefix={artifact_prefix}",
    ]


def verify_fuzz_argv(
    arguments: list[str],
    *,
    target: dict[str, Any],
    artifact_prefix: str,
    dictionary_path: str | None = None,
) -> None:
    if not isinstance(arguments, list) or any(not isinstance(item, str) for item in arguments):
        raise FuzzingError("fuzz argv must be a string list")
    expected = canonical_fuzz_argv(
        target, artifact_prefix=artifact_prefix, dictionary_path=dictionary_path
    )
    observed: set[str] = set()
    for argument in arguments:
        if re.fullmatch(r"-[A-Za-z][A-Za-z0-9_]*=[^=\s]+", argument) is None:
            raise FuzzingError(f"noncanonical or positional fuzz argument: {argument!r}")
        key, value = argument[1:].split("=", 1)
        if key in observed:
            raise FuzzingError(f"duplicate fuzz control: -{key}")
        observed.add(key)
    if arguments != expected:
        raise FuzzingError("fuzz argv differs in order, cardinality, name, or value")


def require_private_contained_path(root: Path, candidate: Path, *, label: str) -> None:
    root_resolved = root.resolve(strict=True)
    candidate_resolved = candidate.resolve(strict=True)
    if root_resolved == candidate_resolved or root_resolved not in candidate_resolved.parents:
        raise FuzzingError(f"{label} escapes the private temporary root")
    root_mode = stat.S_IMODE(root_resolved.stat().st_mode)
    candidate_mode = stat.S_IMODE(candidate_resolved.stat().st_mode)
    if root_mode != 0o700 or candidate_mode != 0o700:
        raise FuzzingError(f"{label} and private root must have mode 0700")


def corpus_object_record(
    *,
    confidentiality: str,
    git_mode: str,
    kind: str,
    path: str,
    sha256: str,
    size: int,
    target_ids: list[str],
) -> dict[str, Any]:
    semantic_states = ["dictionary-token-set"] if kind == "dictionary" else [Path(path).name]
    finalized = STATUS == "STABLE-final-subject-bound"
    review_id = (
        f"package-c-bootstrap-review-v1:{FRAMEWORK_SUBJECT_COMMIT}"
        if finalized
        else "package-c-bootstrap-review-pending-final-subject"
    )
    return {
        "confidentiality": confidentiality,
        "first_seen": "2026-08-12T00:00:00Z",
        "git_mode": git_mode,
        "kind": kind,
        "minimization": {
            "algorithm": None,
            "executions": 0,
            "minimized_size": size,
            "original_size": size,
            "semantic_preserved": True,
            "source_sha256": sha256,
            "status": "authored-bootstrap-not-minimized",
        },
        "path": path,
        "promotion": {
            "attestation_sha256": None,
            "authenticated_writer": False,
            "from_fork": False,
            "reviewer": review_id,
            "status": "blocked-authoritative-writer-unprovisioned",
        },
        "provenance": {
            "in_repo_author": "package-c-fuzz-writer-reviewed-bootstrap",
            "lineage": "authored-public-bootstrap-v1",
            "review_id": review_id,
            "source_commit": FRAMEWORK_SUBJECT_COMMIT if finalized else None,
            "source_kind": "in-repository-authored-bootstrap",
            "source_uri": None,
            "writer_identity": None,
        },
        "retention": {
            "class": "current-corpus",
            "expires_at": None,
            "indefinite": True,
            "minimum_days": None,
        },
        "semantic_states": semantic_states,
        "sha256": sha256,
        "size": size,
        "target_ids": target_ids,
    }


def validate_bootstrap_subject_provenance(
    provenance: dict[str, Any],
    promotion: dict[str, Any],
    *,
    status: str,
    subject_commit: str,
) -> None:
    """Reject pending, null, or coherently rebound bootstrap identity at STABLE."""

    if status == "UNSTABLE-awaiting-final-subject-binding":
        expected_review = "package-c-bootstrap-review-pending-final-subject"
        expected_commit = None
    elif status == "STABLE-final-subject-bound" and re.fullmatch(r"[0-9a-f]{40}", subject_commit):
        expected_review = f"package-c-bootstrap-review-v1:{subject_commit}"
        expected_commit = subject_commit
    else:
        raise FuzzingError("corpus bootstrap subject status/commit differs")
    if (
        provenance["source_commit"] != expected_commit
        or provenance["review_id"] != expected_review
        or promotion["reviewer"] != expected_review
    ):
        raise FuzzingError("bootstrap corpus final-subject provenance differs")


def operational_corpus_object_template() -> dict[str, Any]:
    """Closed future record shape; nulls and status are explicit blockers."""

    return {
        "confidentiality": "private-campaign-corpus",
        "first_seen": None,
        "git_mode": "100644",
        "kind": "campaign",
        "minimization": {
            "algorithm": None,
            "executions": None,
            "minimized_size": None,
            "original_size": None,
            "semantic_preserved": None,
            "source_sha256": None,
            "status": "blocked-unprovisioned",
        },
        "path": None,
        "promotion": {
            "attestation_sha256": None,
            "authenticated_writer": False,
            "from_fork": False,
            "reviewer": None,
            "status": "blocked-authoritative-writer-unprovisioned",
        },
        "provenance": {
            "in_repo_author": None,
            "lineage": None,
            "review_id": None,
            "source_commit": None,
            "source_kind": "campaign-generated",
            "source_uri": None,
            "writer_identity": None,
        },
        "retention": {
            "class": "daily-corpus",
            "expires_at": None,
            "indefinite": False,
            "minimum_days": 30,
        },
        "semantic_states": [],
        "sha256": None,
        "size": None,
        "target_ids": [],
    }


def validate_operational_corpus_object(record: dict[str, Any]) -> None:
    template = operational_corpus_object_template()
    item = exact_keys(record, set(template), label="operational corpus object")
    minimization = exact_keys(item["minimization"], set(template["minimization"]), label="operational corpus minimization")
    promotion = exact_keys(item["promotion"], set(template["promotion"]), label="operational corpus promotion")
    provenance = exact_keys(item["provenance"], set(template["provenance"]), label="operational corpus provenance")
    retention = exact_keys(item["retention"], set(template["retention"]), label="operational corpus retention")
    if item == template:
        return
    if item["kind"] not in {"campaign", "regression"} or item["git_mode"] != "100644" or item["confidentiality"] != "private-campaign-corpus":
        raise FuzzingError("operational corpus kind/mode/confidentiality differs")
    if not isinstance(item["path"], str) or not item["path"].startswith("private/"):
        raise FuzzingError("operational corpus object path is not private/relative")
    validate_relative_path(item["path"], label="operational corpus object path")
    if not isinstance(item["sha256"], str) or HEX64.fullmatch(item["sha256"]) is None or not isinstance(item["size"], int) or isinstance(item["size"], bool) or item["size"] <= 0:
        raise FuzzingError("operational corpus object digest/size differs")
    parse_utc(item["first_seen"], label="operational corpus first_seen")
    if not isinstance(item["target_ids"], list) or not item["target_ids"] or item["target_ids"] != sorted(set(item["target_ids"])) or any(target not in build_registry_ids() for target in item["target_ids"]):
        raise FuzzingError("operational corpus target bindings differ")
    if not isinstance(item["semantic_states"], list) or not item["semantic_states"] or item["semantic_states"] != sorted(set(item["semantic_states"])):
        raise FuzzingError("operational corpus semantic states differ")
    if (
        minimization["status"] != "campaign-minimized"
        or not isinstance(minimization["algorithm"], str)
        or not minimization["algorithm"]
        or not isinstance(minimization["executions"], int)
        or minimization["executions"] <= 0
        or not isinstance(minimization["source_sha256"], str)
        or HEX64.fullmatch(minimization["source_sha256"]) is None
        or minimization["semantic_preserved"] is not True
        or not isinstance(minimization["original_size"], int)
        or not isinstance(minimization["minimized_size"], int)
        or minimization["minimized_size"] != item["size"]
        or minimization["original_size"] < minimization["minimized_size"]
    ):
        raise FuzzingError("operational corpus minimization evidence differs")
    if provenance["source_kind"] != "campaign-generated" or not provenance["lineage"] or not provenance["review_id"] or not provenance["writer_identity"] or provenance["source_commit"] is None or re.fullmatch(r"[0-9a-f]{40}", provenance["source_commit"]) is None:
        raise FuzzingError("operational corpus writer/reviewer provenance differs")
    allowed_retention = {
        "daily-corpus": (30, False),
        "weekly-corpus": (364, False),
        "current-corpus": (None, True),
        "regression-corpus": (None, True),
    }
    if retention["class"] not in allowed_retention or (retention["minimum_days"], retention["indefinite"]) != allowed_retention[retention["class"]]:
        raise FuzzingError("operational corpus retention class differs")
    if retention["indefinite"]:
        if retention["expires_at"] is not None:
            raise FuzzingError("indefinite corpus object has an expiry")
    else:
        if retention["expires_at"] is None:
            raise FuzzingError("finite corpus object expiry is absent")
        expiry = parse_utc(retention["expires_at"], label="corpus expiry")
        first_seen = parse_utc(item["first_seen"], label="corpus first_seen")
        minimum_expiry = first_seen + dt.timedelta(days=retention["minimum_days"])
        if expiry < minimum_expiry:
            raise FuzzingError("finite corpus object expires before its exact minimum retention")
    if promotion["from_fork"] is not False:
        raise FuzzingError("operational corpus promotion from a fork is forbidden")
    if promotion["status"] == "blocked-authoritative-writer-unprovisioned":
        if promotion["authenticated_writer"] is not False or promotion["attestation_sha256"] is not None:
            raise FuzzingError("blocked operational corpus object claimed authority")
        return
    if not authorize_authoritative_corpus_write(
        writer_role="trusted-corpus-writer",
        authenticated=promotion["authenticated_writer"],
        from_fork=promotion["from_fork"],
        reviewed=bool(promotion["reviewer"]),
    ):
        raise FuzzingError("operational corpus writer/store authority remains unprovisioned")


def validate_corpus_manifest(document: dict[str, Any]) -> None:
    expected_top = {
        "content_policy", "counts", "files_sha256", "operational_object_template", "operational_promotion_record",
        "registry_semantic_sha256", "schema_version", "source_binding", "status", "targets",
    }
    manifest = exact_keys(document, expected_top, label="corpus manifest")
    if manifest["content_policy"] != f"{CONTENT_PREFIX}-corpus-manifest-v1" or manifest["schema_version"] != 1:
        raise FuzzingError("corpus manifest normative identity differs")
    if manifest["status"] != STATUS or manifest["source_binding"] != build_policy()["source_binding"]:
        raise FuzzingError("corpus manifest final-subject source binding differs")
    promotion = exact_keys(
        manifest["operational_promotion_record"],
        {"attestation_sha256", "authenticated_writer", "from_fork", "manifest_sha256", "reviewer", "status"},
        label="operational corpus promotion record",
    )
    if promotion != {
        "attestation_sha256": None,
        "authenticated_writer": False,
        "from_fork": False,
        "manifest_sha256": None,
        "reviewer": None,
        "status": "blocked-unprovisioned",
    }:
        raise FuzzingError("unprovisioned operational corpus promotion record claimed authority")
    if manifest["operational_object_template"] != operational_corpus_object_template():
        raise FuzzingError("operational corpus object template claimed evidence or changed shape")
    validate_operational_corpus_object(manifest["operational_object_template"])
    allowed_kinds = {"bootstrap", "dictionary"}
    seen: set[str] = set()
    all_objects: dict[str, dict[str, Any]] = {}
    for target in manifest["targets"]:
        target_record = exact_keys(
            target,
            {"authoritative_write_status", "corpus_status", "dictionaries", "dictionary_selector_path", "promotion_status", "seeds", "seed_selector_path", "target_id"},
            label="corpus target",
        )
        if target_record["target_id"] in seen:
            raise FuzzingError("corpus manifest target duplicated")
        seen.add(target_record["target_id"])
        for item in [*target_record["seeds"], *target_record["dictionaries"]]:
            exact_keys(
                item,
                {"confidentiality", "first_seen", "git_mode", "kind", "minimization", "path", "promotion", "provenance", "retention", "semantic_states", "sha256", "size", "target_ids"},
                label="corpus object",
            )
            if item["kind"] not in allowed_kinds or item["git_mode"] != "100644" or not item["target_ids"]:
                raise FuzzingError("corpus object kind/mode/target binding differs")
            if target_record["target_id"] not in item["target_ids"]:
                raise FuzzingError("corpus object omits containing target binding")
            if item["first_seen"] != "2026-08-12T00:00:00Z" or not item["semantic_states"]:
                raise FuzzingError("corpus object time/semantic state is absent")
            minimization = exact_keys(item["minimization"], {"algorithm", "executions", "minimized_size", "original_size", "semantic_preserved", "source_sha256", "status"}, label="corpus minimization")
            provenance = exact_keys(item["provenance"], {"in_repo_author", "lineage", "review_id", "source_commit", "source_kind", "source_uri", "writer_identity"}, label="corpus provenance")
            retention = exact_keys(item["retention"], {"class", "expires_at", "indefinite", "minimum_days"}, label="corpus retention")
            object_promotion = exact_keys(item["promotion"], {"attestation_sha256", "authenticated_writer", "from_fork", "reviewer", "status"}, label="corpus object promotion")
            if minimization != {
                "algorithm": None, "executions": 0, "minimized_size": item["size"], "original_size": item["size"],
                "semantic_preserved": True, "source_sha256": item["sha256"], "status": "authored-bootstrap-not-minimized",
            }:
                raise FuzzingError("bootstrap corpus object falsely claims campaign minimization")
            if provenance["source_kind"] != "in-repository-authored-bootstrap" or provenance["writer_identity"] is not None or not provenance["in_repo_author"] or not provenance["review_id"] or not provenance["lineage"]:
                raise FuzzingError("bootstrap corpus provenance differs")
            validate_bootstrap_subject_provenance(
                provenance,
                object_promotion,
                status=manifest["status"],
                subject_commit=manifest["source_binding"]["framework_subject_commit"],
            )
            if retention != {"class": "current-corpus", "expires_at": None, "indefinite": True, "minimum_days": None}:
                raise FuzzingError("bootstrap corpus retention differs")
            if object_promotion["authenticated_writer"] or object_promotion["from_fork"] or object_promotion["attestation_sha256"] is not None or object_promotion["status"] != "blocked-authoritative-writer-unprovisioned":
                raise FuzzingError("bootstrap corpus object claimed operational promotion")
            prior = all_objects.get(item["path"])
            if prior is not None and prior != item:
                raise FuzzingError("shared corpus object was coherently relabeled")
            all_objects[item["path"]] = item
    if seen != build_registry_ids() or manifest["files_sha256"] != sha256_bytes(canonical_json([all_objects[path] for path in sorted(all_objects)])):
        raise FuzzingError("corpus manifest target/file closure differs")


def build_corpus_manifest(repo: Path) -> dict[str, Any]:
    registry_ids = build_registry_ids()
    if (
        set(SEED_FOR_TARGET) != registry_ids
        or set(REVIEWED_SEED_MEMBERS) != registry_ids
        or set(DICTIONARY_FOR_TARGET) != registry_ids
    ):
        raise FuzzingError("code-pinned seed/dictionary selectors differ from the registry")
    seeds_by_target: dict[str, list[dict[str, Any]]] = {target: [] for target in registry_ids}
    for target, path in sorted(SEED_FOR_TARGET.items()):
        members = [
            f"fuzz/{path}/{member}"
            for member in list_directory_exact(
                repo,
                f"fuzz/{path}",
                REVIEWED_SEED_MEMBERS[target],
                label=f"reviewed seed directory {target}",
            )
        ]
        for member in members:
            digest, size = sha256_regular_file(repo, member, label=f"reviewed seed {member}")
            mode = stat.S_IMODE((repo / member).lstat().st_mode)
            git_mode = canonical_nonexecutable_mode(mode, label=f"reviewed seed {member}")
            seeds_by_target[target].append(corpus_object_record(
                confidentiality="public-bootstrap-seed", git_mode=git_mode, kind="bootstrap",
                path=member, sha256=digest, size=size, target_ids=[target],
            ))
    dictionary_files: dict[str, dict[str, Any]] = {}
    for path in sorted(set(DICTIONARY_FOR_TARGET.values())):
        repo_path = f"fuzz/{path}"
        digest, size = sha256_regular_file(repo, repo_path, label=f"reviewed dictionary {repo_path}")
        mode = stat.S_IMODE((repo / repo_path).lstat().st_mode)
        git_mode = canonical_nonexecutable_mode(mode, label=f"reviewed dictionary {path}")
        dictionary_files[path] = corpus_object_record(
            confidentiality="public-bootstrap-dictionary", git_mode=git_mode, kind="dictionary",
            path=repo_path, sha256=digest, size=size,
            target_ids=sorted(target for target, selector in DICTIONARY_FOR_TARGET.items() if selector == path),
        )
    targets = []
    for identifier in sorted(seeds_by_target):
        dictionary_selector = DICTIONARY_FOR_TARGET[identifier]
        dictionary = dictionary_files[dictionary_selector]
        targets.append(
            {
                "authoritative_write_status": "disabled-unprovisioned",
                "corpus_status": "smoke-seeds-only-no-persistent-campaign-corpus",
                "dictionaries": [dictionary],
                "dictionary_selector_path": dictionary_selector,
                "promotion_status": "blocked-no-authenticated-writer-review",
                "seeds": sorted(seeds_by_target[identifier], key=lambda item: item["path"]),
                "seed_selector_path": SEED_FOR_TARGET.get(identifier),
                "target_id": identifier,
            }
        )
    all_files_by_path = {
        file["path"]: file
        for target in targets
        for file in [*target["seeds"], *target["dictionaries"]]
    }
    all_files = [all_files_by_path[path] for path in sorted(all_files_by_path)]
    result = {
        "content_policy": f"{CONTENT_PREFIX}-corpus-manifest-v1",
        "counts": {
            "dictionary_files": len(dictionary_files),
            "reviewed_seed_files": sum(len(value) for value in seeds_by_target.values()),
            "targets": len(targets),
        },
        "files_sha256": sha256_bytes(canonical_json(all_files)),
        "operational_object_template": operational_corpus_object_template(),
        "operational_promotion_record": {
            "attestation_sha256": None,
            "authenticated_writer": False,
            "from_fork": False,
            "manifest_sha256": None,
            "reviewer": None,
            "status": "blocked-unprovisioned",
        },
        "registry_semantic_sha256": registry_semantic_sha256(),
        "schema_version": SCHEMA_VERSION,
        "source_binding": build_policy()["source_binding"],
        "status": STATUS,
        "targets": targets,
    }
    validate_corpus_manifest(result)
    return result


def build_registry_ids() -> set[str]:
    return {record["id"] for record in build_registry()["targets"]}


SECURITY_PATH_PREFIXES = (
    ".github/workflows/",
    "assurance/",
    "crates/",
    "fuzz/",
    "migration/",
    "tools/release-dcrypt.sh",
    "tools/verify-implementation-boundary.py",
    "tools/verify-publish-ready.sh",
    "tools/verify-remote-release-ready.py",
)


def parse_canonical_lines(raw: bytes, *, label: str, paths: bool) -> list[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FuzzingError(f"{label} is not UTF-8") from error
    if not text or not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise FuzzingError(f"{label} must be nonempty LF-terminated canonical text")
    rows = text[:-1].split("\n")
    if any(not row or unicodedata.normalize("NFC", row) != row for row in rows):
        raise FuzzingError(f"{label} contains empty or non-NFC rows")
    if rows != sorted(set(rows)):
        raise FuzzingError(f"{label} must be sorted and duplicate-free")
    if paths:
        for row in rows:
            validate_relative_path(row, label=f"{label} path")
    return rows


def select_changed_rows(repo: Path, row_ids: list[str]) -> dict[str, Any]:
    mapping = build_row_mapping(repo)
    by_id = {row["row_id"]: row for row in mapping["rows"]}
    unknown = sorted(set(row_ids) - set(by_id))
    if unknown:
        raise FuzzingError(f"unknown changed atomic rows: {unknown[:3]}")
    targets: set[str] = set()
    blocker_rows: list[dict[str, Any]] = []
    for identifier in row_ids:
        row = by_id[identifier]
        if row["target_id"] is None:
            blocker_rows.append(
                {
                    "blocker_codes": row["blocker_codes"],
                    "row_id": identifier,
                    "status": "HOLD",
                }
            )
        else:
            targets.add(row["target_id"])
    return {
        "blocker_rows": blocker_rows,
        "selected_target_ids": sorted(targets),
        "status": "HOLD" if blocker_rows else "selected",
    }


def select_changed_paths(repo: Path, paths: list[str]) -> dict[str, Any]:
    operations, gaps, _ = load_atomic_rows(repo)
    source_prefixes: dict[str, set[str]] = {}
    crate_directories: dict[str, str] = {}
    for directory in (repo / "crates").iterdir():
        if directory.is_dir() and not directory.is_symlink():
            crate_directories[directory.name.replace("_", "-")] = directory.name
    for row in [*operations, *gaps]:
        crate = str(row.get("crate", ""))
        short = crate.removeprefix("dcrypt-")
        guessed = short.replace("-", "_")
        source_prefixes.setdefault(f"crates/{guessed}/", set()).add(row["id"])
        actual = crate_directories.get(short)
        if actual is not None:
            source_prefixes.setdefault(f"crates/{actual}/", set()).add(row["id"])
    all_targets = sorted(build_registry_ids())
    row_ids: set[str] = set()
    select_all_reasons: list[str] = []
    unknown_paths: list[str] = []
    for path in paths:
        if path.startswith("crates/"):
            matched = set().union(*(ids for prefix, ids in source_prefixes.items() if path.startswith(prefix)))
            if matched:
                row_ids.update(matched)
            else:
                select_all_reasons.append(path)
        elif path.startswith(SECURITY_PATH_PREFIXES) or path.startswith("Cargo"):
            select_all_reasons.append(path)
        else:
            unknown_paths.append(path)
    if unknown_paths:
        raise FuzzingError(f"unclassified changed paths: {unknown_paths[:3]}")
    if select_all_reasons:
        return {
            "blocker_rows": [],
            "fail_safe_all_reasons": sorted(select_all_reasons),
            "selected_target_ids": all_targets,
            "status": "selected-all-fail-safe",
        }
    result = select_changed_rows(repo, sorted(row_ids))
    result["fail_safe_all_reasons"] = []
    if not result["selected_target_ids"] and not result["blocker_rows"]:
        raise FuzzingError("changed paths selected zero rows and zero targets")
    return result


def authorize_authoritative_corpus_write(
    *, writer_role: str, authenticated: bool, from_fork: bool, reviewed: bool
) -> bool:
    """Package C ships no identity, so every current write is rejected.

    Even the syntactically privileged tuple remains false until a separately
    provisioned, code-reviewed identity/store binding replaces UNSTABLE state.
    """

    if not all(isinstance(value, bool) for value in (authenticated, from_fork, reviewed)):
        raise FuzzingError("writer authorization flags must be booleans")
    if not isinstance(writer_role, str) or not writer_role:
        raise FuzzingError("writer role must be a nonempty string")
    if from_fork or not authenticated or not reviewed or writer_role != "trusted-corpus-writer":
        return False
    return False  # authoritative store and signing identity are unprovisioned


def authorize_private_crash_store_write(
    *, writer_role: str, authenticated: bool, from_fork: bool, confidentiality: str
) -> bool:
    if not all(isinstance(value, bool) for value in (authenticated, from_fork)):
        raise FuzzingError("private crash writer flags must be booleans")
    if confidentiality != "private" or from_fork or not authenticated:
        return False
    # Deliberately separate from the corpus-writer role and still unprovisioned.
    if writer_role != "trusted-private-crash-writer":
        return False
    return False


def bounded_rejection_fixture(outcomes: list[bool], limit: int) -> int:
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise FuzzingError("controlled rejection limit must be positive")
    if len(outcomes) > limit or any(not isinstance(value, bool) for value in outcomes):
        raise FuzzingError("controlled rejection fixture exceeds its reviewed limit")
    for attempt, accepted in enumerate(outcomes, start=1):
        if accepted:
            return attempt
    raise FuzzingError("controlled rejection loop exhausted")


def validate_sanitizer_assignment(document: dict[str, Any]) -> None:
    controls = {item["id"]: item for item in document["controls"]}
    all_targets = sorted(build_registry_ids())
    if controls["asan"]["assigned_target_ids"] != all_targets:
        raise FuzzingError("ASan assignment must contain every target exactly once")
    if controls["lsan"]["assigned_target_ids"] != all_targets:
        raise FuzzingError("LSan allocation-bearing assignment differs")
    if controls["careful-ub"]["assigned_target_ids"] != all_targets:
        raise FuzzingError("integer/UB lane assignment must contain every target exactly once")
    if controls["msan"]["assigned_target_ids"] or controls["tsan"]["assigned_target_ids"]:
        raise FuzzingError("blocked MSan/TSan lanes may not silently acquire targets")
    if controls["asan"]["target_binary_markers"] != ["__asan_init"]:
        raise FuzzingError("ASan target marker closure differs")
    if controls["lsan"]["target_binary_markers"] != list(INTEGRATED_ASAN_FUNCTION_SYMBOLS[1:]):
        raise FuzzingError("integrated LSan target marker closure differs")
    if document.get("integrated_address_runtime") != {
        "asan_options": INTEGRATED_ASAN_OPTIONS,
        "defined_function_symbols": list(INTEGRATED_ASAN_FUNCTION_SYMBOLS),
        "runtime_sha256": INTEGRATED_ASAN_RUNTIME_SHA256,
    }:
        raise FuzzingError("integrated address-sanitizer runtime binding differs")


def build_sanitizer_controls() -> dict[str, Any]:
    all_targets = sorted(build_registry_ids())
    allocation_targets = all_targets
    controls = [
        {
            "id": "asan",
            "assigned_target_ids": all_targets,
            "local_control_status": "required-live-execution-not-sealed",
            "operational_status": "blocked-no-per-target-campaign-instrumentation-attestation",
            "positive_control_requirement": "real memory-safety violation detected by AddressSanitizer",
            "report_patterns": ["ERROR: AddressSanitizer:", "SUMMARY: AddressSanitizer:"],
            "target_binary_markers": ["__asan_init"],
        },
        {
            "id": "careful-ub",
            "assigned_target_ids": all_targets,
            "local_control_status": "blocked-separate-safe-rust-overflow-control-not-implemented",
            "operational_status": "blocked-no-separate-integer-ub-campaign-lane",
            "positive_control_requirement": "separate reviewed safe-Rust checked-overflow diagnostic; not a UBSan claim",
            "report_patterns": [],
            "target_binary_markers": [],
        },
        {
            "id": "lsan",
            "assigned_target_ids": allocation_targets,
            "local_control_status": "required-live-execution-not-sealed",
            "operational_status": "blocked-no-per-target-campaign-instrumentation-attestation",
            "positive_control_requirement": "real intentional leak detected by integrated LeakSanitizer in address mode; standalone leak mode is supplemental",
            "report_patterns": [
                "ERROR: LeakSanitizer: detected memory leaks",
                "SUMMARY: AddressSanitizer:",
            ],
            "target_binary_markers": list(INTEGRATED_ASAN_FUNCTION_SYMBOLS[1:]),
        },
        {
            "id": "msan",
            "assigned_target_ids": [],
            "local_control_status": "blocked-complete-instrumented-closure-unprovisioned",
            "operational_status": "blocked-complete-instrumented-closure-unprovisioned",
            "positive_control_requirement": "real uninitialized read with complete instrumented closure",
            "report_patterns": ["WARNING: MemorySanitizer:", "SUMMARY: MemorySanitizer:"],
            "target_binary_markers": ["__msan_init"],
        },
        {
            "id": "tsan",
            "assigned_target_ids": [],
            "local_control_status": "blocked-no-deliberately-concurrent-positive-control",
            "operational_status": "blocked-no-authorized-concurrent-positive-control",
            "positive_control_requirement": "real data race in deliberately concurrent fixture",
            "report_patterns": ["WARNING: ThreadSanitizer:", "SUMMARY: ThreadSanitizer:"],
            "target_binary_markers": ["__tsan_init"],
        },
    ]
    return {
        "actual_positive_controls_observed": 0,
        "content_policy": f"{CONTENT_PREFIX}-sanitizer-controls-v1",
        "controls": controls,
        "lane_policy": {
            "asan": "continuous-all-17-targets-required",
            "careful-ub": "separate-integer-and-undefined-behavior-all-17-targets-required",
            "lsan": "all-allocation-bearing-targets-required",
            "msan": "blocked-until-complete-instrumented-closure",
            "tsan": "blocked-no-deliberately-concurrent-target",
        },
        "forbidden_environment_fragments": [
            "detect_leaks=0",
            "exitcode=0",
            "halt_on_error=0",
        ],
        "integrated_address_runtime": {
            "asan_options": INTEGRATED_ASAN_OPTIONS,
            "defined_function_symbols": list(INTEGRATED_ASAN_FUNCTION_SYMBOLS),
            "runtime_sha256": INTEGRATED_ASAN_RUNTIME_SHA256,
        },
        "panic_is_sanitizer_proof": False,
        "parser_fixtures_are_operational_evidence": False,
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
    }


def sanitizer_report_matches(control: dict[str, Any], output: str, returncode: int) -> bool:
    if returncode == 0 or not isinstance(output, str):
        return False
    if "panicked at" in output and not any(pattern in output for pattern in control["report_patterns"]):
        return False
    return all(pattern in output for pattern in control["report_patterns"])


def build_campaign_status() -> dict[str, Any]:
    targets = []
    for target in build_registry()["targets"]:
        targets.append(
            {
                "attestation_status": "unsigned-unprovisioned",
                "blocker_codes": [
                    "authenticated-writer-unprovisioned",
                    "comparable-coverage-baseline-absent",
                    *(["final-subject-binding-unstable"] if STATUS != "STABLE-final-subject-bound" else []),
                    "persistent-campaign-not-executed",
                    "per-target-instrumentation-attestation-absent",
                    "signed-attestation-unprovisioned",
                ],
                "campaign_attestation_sha256": None,
                "campaign_status": "not-executed-unprovisioned",
                "corpus_files_sha256": None,
                "corpus_manifest_sha256": None,
                "coverage": {
                    "comparison_config_sha256": None,
                    "current_artifact_sha256": None,
                    "edge_baseline": None,
                    "edge_current": None,
                    "function_baseline": None,
                    "function_current": None,
                    "prior_artifact_sha256": None,
                    "regression_status": "blocked-no-comparable-baseline",
                    "semantic_state_baseline": None,
                    "semantic_state_baseline_sha256": None,
                    "semantic_state_current": None,
                    "semantic_state_current_sha256": None,
                },
                "coverage_status": "blocked-no-comparable-baseline",
                "crash_status": "no-observation-not-evidence",
                "delivered_rc_core_seconds": 0,
                "delivered_weekly_core_seconds": 0,
                "evidence_classification": "first-party-structural-non-evidence",
                "freshness_status": "blocked-no-campaign-end-time",
                "freeze": {"commit": None, "time": None, "tree": None},
                "instrumentation": {
                    "lanes": [],
                    "sanitizer_assignment_sha256": None,
                    "status": "blocked-no-per-target-campaign-instrumentation-attestation",
                },
                "observed_outcomes": {
                    "crashes": None,
                    "ooms": None,
                    "rejection_exhaustions": None,
                    "timeouts": None,
                    "unbounded_allocations": None,
                },
                "required_freshness_seconds": target["required_freshness_seconds"],
                "required_rc_core_seconds": target["required_rc_core_seconds"],
                "required_weekly_core_seconds": target["required_weekly_core_seconds"],
                "resource_status": "configured-not-observed",
                "resource_limits_sha256": None,
                "sanitizer_status": "blocked-no-per-target-campaign-instrumentation-attestation",
                "rc_shards": [],
                "rc_window": {"end": None, "start": None},
                "subject": {"commit": None, "tree": None},
                "target_id": target["id"],
                "target_binary_sha256": None,
                "target_source_sha256": None,
                "toolchain": {
                    "cargo_fuzz_executable_sha256": None,
                    "cargo_fuzz_provenance_sha256": None,
                    "cargo_fuzz_source_tree_sha256": None,
                    "cargo_fuzz_version_sha256": None,
                    "cargo_sha256": None,
                    "cargo_version_sha256": None,
                    "linker_sha256": None,
                    "linker_version_sha256": None,
                    "profiler_config_sha256": None,
                    "runtime_objects_sha256": None,
                    "rustc_sha256": None,
                    "rustc_version_sha256": None,
                    "symbol_inspector_sha256": None,
                    "symbol_inspector_version_sha256": None,
                },
                "weekly_shards": [],
                "weekly_window": {"end": None, "start": None},
                "writer_identity": None,
                "writer_identity_status": "unprovisioned",
            }
        )
    result = {
        "as_of": "2026-08-12T00:00:00Z",
        "content_policy": f"{CONTENT_PREFIX}-campaign-status-v1",
        "counts": {
            "blocked_targets": len(targets),
            "operationally_passing_targets": 0,
            "targets": len(targets),
        },
        "release_gate": {
            "exit_code": 3,
            "status": "HOLD",
        },
        "schema_version": SCHEMA_VERSION,
        "source_binding": build_policy()["source_binding"],
        "status": STATUS,
        "targets": targets,
    }
    validate_campaign_status(result)
    return result


def validate_campaign_status(document: dict[str, Any]) -> None:
    campaign = exact_keys(
        document,
        {"as_of", "content_policy", "counts", "release_gate", "schema_version", "source_binding", "status", "targets"},
        label="campaign status",
    )
    if campaign["content_policy"] != f"{CONTENT_PREFIX}-campaign-status-v1" or campaign["schema_version"] != 1:
        raise FuzzingError("campaign normative identity differs")
    if campaign["release_gate"] not in ({"exit_code": 3, "status": "HOLD"}, {"exit_code": 0, "status": "PASS"}):
        raise FuzzingError("campaign release gate is not exact HOLD/3 or PASS/0")
    registry_by_id = {target["id"]: target for target in build_registry()["targets"]}
    sanitizer_controls = build_sanitizer_controls()
    assignment_sha256 = sha256_bytes(canonical_json(sanitizer_controls))
    expected_instrumentation: dict[str, list[dict[str, Any]]] = {}
    for identifier in sorted(registry_by_id):
        expected_instrumentation[identifier] = [
            {
                "binary_markers": list(control["target_binary_markers"]),
                "lane_id": control["id"],
            }
            for control in sanitizer_controls["controls"]
            if identifier in control["assigned_target_ids"]
        ]
    expected_fields = {
        "attestation_status", "blocker_codes", "campaign_attestation_sha256", "campaign_status",
        "corpus_files_sha256", "corpus_manifest_sha256", "coverage", "coverage_status", "crash_status",
        "delivered_rc_core_seconds", "delivered_weekly_core_seconds", "evidence_classification", "freshness_status",
        "freeze", "instrumentation",
        "observed_outcomes", "required_freshness_seconds", "required_rc_core_seconds", "required_weekly_core_seconds",
        "resource_limits_sha256", "resource_status", "sanitizer_status", "rc_shards", "rc_window", "subject",
        "target_binary_sha256", "target_id", "target_source_sha256", "toolchain", "weekly_shards",
        "weekly_window", "writer_identity", "writer_identity_status",
    }
    seen: list[str] = []
    passing_toolchain: dict[str, Any] | None = None
    global_campaign_attestations: set[str] = set()
    global_shard_attestations: set[str] = set()
    global_shard_ids: set[str] = set()
    for record in campaign["targets"]:
        target = exact_keys(record, expected_fields, label="campaign target record")
        identifier = target["target_id"]
        if identifier not in registry_by_id or identifier in seen:
            raise FuzzingError("campaign target is unknown or duplicated")
        seen.append(identifier)
        registry_target = registry_by_id[identifier]
        if (
            target["required_freshness_seconds"] != registry_target["required_freshness_seconds"]
            or target["required_rc_core_seconds"] != registry_target["required_rc_core_seconds"]
            or target["required_weekly_core_seconds"] != registry_target["required_weekly_core_seconds"]
        ):
            raise FuzzingError("campaign target budget/freshness rebound")
        coverage = exact_keys(target["coverage"], {"comparison_config_sha256", "current_artifact_sha256", "edge_baseline", "edge_current", "function_baseline", "function_current", "prior_artifact_sha256", "regression_status", "semantic_state_baseline", "semantic_state_baseline_sha256", "semantic_state_current", "semantic_state_current_sha256"}, label="campaign coverage")
        instrumentation = exact_keys(target["instrumentation"], {"lanes", "sanitizer_assignment_sha256", "status"}, label="campaign instrumentation")
        outcomes = exact_keys(target["observed_outcomes"], {"crashes", "ooms", "rejection_exhaustions", "timeouts", "unbounded_allocations"}, label="campaign outcomes")
        subject = exact_keys(target["subject"], {"commit", "tree"}, label="campaign subject")
        freeze = exact_keys(target["freeze"], {"commit", "time", "tree"}, label="campaign freeze")
        toolchain = exact_keys(
            target["toolchain"],
            {
                "cargo_fuzz_executable_sha256", "cargo_fuzz_provenance_sha256", "cargo_fuzz_source_tree_sha256",
                "cargo_fuzz_version_sha256", "cargo_sha256", "cargo_version_sha256", "linker_sha256",
                "linker_version_sha256", "profiler_config_sha256", "runtime_objects_sha256", "rustc_sha256",
                "rustc_version_sha256", "symbol_inspector_sha256", "symbol_inspector_version_sha256",
            },
            label="campaign toolchain",
        )
        weekly_window = exact_keys(target["weekly_window"], {"end", "start"}, label="weekly campaign window")
        rc_window = exact_keys(target["rc_window"], {"end", "start"}, label="RC campaign window")
        if target["campaign_status"] not in {"not-executed-unprovisioned", "operational-passing"}:
            raise FuzzingError("campaign target status is unreviewed")
        nullable_values = [
            target["campaign_attestation_sha256"], target["corpus_files_sha256"], target["corpus_manifest_sha256"],
            target["resource_limits_sha256"], target["writer_identity"],
            target["target_binary_sha256"], target["target_source_sha256"], subject["commit"], subject["tree"],
            freeze["commit"], freeze["time"], freeze["tree"], weekly_window["start"], weekly_window["end"],
            rc_window["start"], rc_window["end"], instrumentation["sanitizer_assignment_sha256"],
            *coverage.values(), *outcomes.values(), *toolchain.values(),
        ]
        # Status strings in coverage are blockers, not evidence values.
        nullable_values.remove(coverage["regression_status"])
        if target["campaign_status"] == "not-executed-unprovisioned":
            if (
                any(value is not None for value in nullable_values)
                or target["weekly_shards"]
                or target["rc_shards"]
                or instrumentation["lanes"]
            ):
                raise FuzzingError("unexecuted campaign record contains claimed operational evidence")
            if target["delivered_rc_core_seconds"] != 0 or target["delivered_weekly_core_seconds"] != 0 or not target["blocker_codes"]:
                raise FuzzingError("unexecuted campaign record lacks exact budget blockers")
            continue
        digest_values = [
            target["campaign_attestation_sha256"], target["corpus_files_sha256"], target["corpus_manifest_sha256"],
            target["resource_limits_sha256"],
            target["target_binary_sha256"], target["target_source_sha256"],
            instrumentation["sanitizer_assignment_sha256"],
            coverage["comparison_config_sha256"], coverage["current_artifact_sha256"], coverage["prior_artifact_sha256"],
            coverage["semantic_state_baseline_sha256"], coverage["semantic_state_current_sha256"],
            *toolchain.values(),
        ]
        if any(not isinstance(value, str) or HEX64.fullmatch(value) is None for value in digest_values):
            raise FuzzingError("passing campaign lacks exact identity digests")
        if target["campaign_attestation_sha256"] in global_campaign_attestations:
            raise FuzzingError("campaign attestation is reused across target records")
        global_campaign_attestations.add(target["campaign_attestation_sha256"])
        if target["target_source_sha256"] != registry_target["source_sha256"] or target["resource_limits_sha256"] != sha256_bytes(canonical_json(registry_target["resource_limits"])):
            raise FuzzingError("passing campaign target source/resource identity rebound")
        if any(not isinstance(subject[key], str) or re.fullmatch(r"[0-9a-f]{40}", subject[key]) is None for key in ("commit", "tree")):
            raise FuzzingError("passing campaign subject binding differs")
        source_binding = campaign["source_binding"]
        if subject != {"commit": source_binding["framework_subject_commit"], "tree": source_binding["framework_subject_tree"]}:
            raise FuzzingError("passing campaign subject differs from root source binding")
        if freeze["commit"] != subject["commit"] or freeze["tree"] != subject["tree"]:
            raise FuzzingError("passing campaign freeze differs from exact subject")
        freeze_time = parse_utc(freeze["time"], label="campaign freeze time")
        if not isinstance(target["writer_identity"], str) or not target["writer_identity"]:
            raise FuzzingError("passing campaign writer identity is absent")
        if passing_toolchain is None:
            passing_toolchain = toolchain
        elif toolchain != passing_toolchain:
            raise FuzzingError("passing campaign target toolchain identities differ")
        as_of = parse_utc(campaign["as_of"], label="campaign as_of")
        if freeze_time > as_of:
            raise FuzzingError("passing campaign freeze is in the future")
        window_times: dict[str, tuple[dt.datetime, dt.datetime]] = {}
        for purpose, window in (("weekly", weekly_window), ("rc", rc_window)):
            start = parse_utc(window["start"], label=f"{purpose} campaign start")
            end = parse_utc(window["end"], label=f"{purpose} campaign end")
            if start >= end or end > as_of or int((as_of - end).total_seconds()) > target["required_freshness_seconds"]:
                raise FuzzingError(f"passing {purpose} campaign window/freshness differs")
            window_times[purpose] = (start, end)
        if int((window_times["weekly"][1] - window_times["weekly"][0]).total_seconds()) > 7 * 24 * 60 * 60:
            raise FuzzingError("passing weekly campaign window exceeds the exact seven-day maximum")
        if window_times["rc"][0] < freeze_time:
            raise FuzzingError("RC campaign window begins before the exact freeze")
        all_shard_ids: set[str] = set()
        all_attestations: set[str] = set()
        all_intervals: list[tuple[dt.datetime, dt.datetime]] = []
        totals: dict[str, int] = {}
        for purpose, shards in (("weekly", target["weekly_shards"]), ("rc", target["rc_shards"])):
            if not shards:
                raise FuzzingError(f"passing campaign has no {purpose} shards")
            projection = []
            window_start, window_end = window_times[purpose]
            for shard in shards:
                record = exact_keys(shard, {"allocated_cores", "attestation_sha256", "cpu_seconds", "end", "shard_id", "start", "target_id", "writer_identity"}, label=f"{purpose} campaign shard")
                if (
                    not isinstance(record["attestation_sha256"], str)
                    or HEX64.fullmatch(record["attestation_sha256"]) is None
                    or not isinstance(record["writer_identity"], str)
                    or record["writer_identity"] != target["writer_identity"]
                    or record["shard_id"] in all_shard_ids
                    or record["shard_id"] in global_shard_ids
                    or record["attestation_sha256"] in all_attestations
                    or record["attestation_sha256"] in global_shard_attestations
                ):
                    raise FuzzingError("campaign shard writer/identity/attestation differs or is reused")
                shard_start = parse_utc(record["start"], label=f"{purpose} shard start")
                shard_end = parse_utc(record["end"], label=f"{purpose} shard end")
                if shard_start < window_start or shard_end > window_end or (purpose == "rc" and shard_start < freeze_time):
                    raise FuzzingError("campaign shard lies outside its exact evidence window")
                if any(shard_start < prior_end and prior_start < shard_end for prior_start, prior_end in all_intervals):
                    raise FuzzingError("weekly and RC campaign evidence intervals overlap")
                all_shard_ids.add(record["shard_id"])
                global_shard_ids.add(record["shard_id"])
                all_attestations.add(record["attestation_sha256"])
                global_shard_attestations.add(record["attestation_sha256"])
                all_intervals.append((shard_start, shard_end))
                projection.append({key: record[key] for key in ("allocated_cores", "cpu_seconds", "end", "shard_id", "start", "target_id")})
            totals[purpose] = aggregate_core_seconds(projection, target_id=identifier)
        if (
            target["delivered_weekly_core_seconds"] != totals["weekly"]
            or target["delivered_rc_core_seconds"] != totals["rc"]
            or totals["weekly"] < target["required_weekly_core_seconds"]
            or totals["rc"] < target["required_rc_core_seconds"]
        ):
            raise FuzzingError("passing campaign independent weekly/RC budget accounting differs")
        coverage_ints = [coverage[key] for key in ("edge_baseline", "edge_current", "function_baseline", "function_current", "semantic_state_baseline", "semantic_state_current")]
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in coverage_ints):
            raise FuzzingError("passing campaign coverage counters differ")
        expected_state_count = len(registry_target["reviewed_semantic_states"])
        expected_state_digest = registry_target["reviewed_semantic_states_sha256"]
        if (
            coverage["semantic_state_baseline"] != expected_state_count
            or coverage["semantic_state_current"] != expected_state_count
            or coverage["semantic_state_baseline_sha256"] != expected_state_digest
            or coverage["semantic_state_current_sha256"] != expected_state_digest
        ):
            raise FuzzingError("passing campaign semantic-state inventory differs from registry")
        if coverage_regressed(coverage["edge_baseline"], coverage["edge_current"]) or coverage_regressed(coverage["function_baseline"], coverage["function_current"]) or coverage["semantic_state_current"] < coverage["semantic_state_baseline"] or coverage["regression_status"] != "passing-no-regression":
            raise FuzzingError("passing campaign coverage regressed or is incomparable")
        if any(value != 0 for value in outcomes.values()):
            raise FuzzingError("passing campaign observed a crash/timeout/OOM/allocation/rejection failure")
        lanes = instrumentation["lanes"]
        expected_lanes = expected_instrumentation[identifier]
        if len(lanes) != len(expected_lanes):
            raise FuzzingError("passing campaign sanitizer lane cardinality differs")
        lane_projection = []
        control_digests: set[str] = set()
        for lane in lanes:
            lane_record = exact_keys(
                lane,
                {"binary_markers", "lane_id", "positive_control_artifact_sha256", "status"},
                label="campaign instrumentation lane",
            )
            digest = lane_record["positive_control_artifact_sha256"]
            if not isinstance(digest, str) or HEX64.fullmatch(digest) is None or digest in control_digests:
                raise FuzzingError("campaign instrumentation positive-control identity differs or is reused")
            control_digests.add(digest)
            if lane_record["status"] != "passing-target-binary-and-live-control-attested":
                raise FuzzingError("campaign instrumentation lane status differs")
            lane_projection.append({"binary_markers": lane_record["binary_markers"], "lane_id": lane_record["lane_id"]})
        if (
            lane_projection != expected_lanes
            or instrumentation["sanitizer_assignment_sha256"] != assignment_sha256
            or instrumentation["status"] != "passing-per-target-attested"
        ):
            raise FuzzingError("passing campaign instrumentation closure differs")
        if target["blocker_codes"] or target["attestation_status"] != "authenticated-signed" or target["writer_identity_status"] != "authenticated-trusted" or target["freshness_status"] != "passing" or target["coverage_status"] != "passing" or target["resource_status"] != "passing-observed" or target["sanitizer_status"] != "passing-attested" or target["crash_status"] != "passing-zero-observed" or target["evidence_classification"] != "first-party-operational-evidence":
            raise FuzzingError("passing campaign status fields are incoherent")
    if seen != sorted(registry_by_id):
        raise FuzzingError("campaign target order/cardinality differs from registry")
    passing = sum(record["campaign_status"] == "operational-passing" for record in campaign["targets"])
    expected_counts = {"blocked_targets": 17 - passing, "operationally_passing_targets": passing, "targets": 17}
    if campaign["counts"] != expected_counts:
        raise FuzzingError("campaign counts differ from target statuses")
    if passing == 17:
        if campaign["release_gate"] != {"exit_code": 0, "status": "PASS"} or campaign["status"] != "operational-passing":
            raise FuzzingError("fully passing campaign lacks PASS/0 root status")
    elif campaign["release_gate"] != {"exit_code": 3, "status": "HOLD"}:
        raise FuzzingError("campaign with blockers lacks HOLD/3 root status")
    elif campaign["status"] != STATUS:
        raise FuzzingError("blocked campaign root status differs from exact structural HOLD status")


def simulate_crash_lifecycle() -> dict[str, Any]:
    raw = b"prefix-private-CRASH-suffix"
    minimized = b"CRASH"

    def signature(value: bytes, *, fixed: bool = False) -> str | None:
        if not fixed and b"CRASH" in value:
            return "fixture-panic:controlled-crash-v1"
        return None

    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="dcrypt-fuzz-crash-private-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        temporary_path = root / "raw-input"
        descriptor = os.open(
            temporary_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
        if stat.S_IMODE(temporary_path.lstat().st_mode) != 0o600:
            raise FuzzingError("crash simulator raw input mode is not 0600")
        observed = read_regular_file(root, "raw-input", label="simulated private crash input")
        reproductions = [signature(observed) for _ in range(3)]
        if reproductions != ["fixture-panic:controlled-crash-v1"] * 3:
            raise FuzzingError("simulated crash did not reproduce three times")
        if signature(minimized) != reproductions[0]:
            raise FuzzingError("simulated minimized input did not preserve the failure")
        if signature(minimized, fixed=True) is not None:
            raise FuzzingError("simulated post-fix regression still crashes")
        raw_digest = sha256_bytes(raw)
        minimized_digest = sha256_bytes(minimized)
        cluster_id = sha256_bytes(
            canonical_json(
                {
                    "affected_rows": ["fixture.atomic-row"],
                    "failure_class": reproductions[0],
                    "minimized_input_sha256": minimized_digest,
                    "target_id": "fixture_crash_target",
                }
            )
        )
        occurrence_ids = [
            sha256_bytes(canonical_json({"cluster_id": cluster_id, "input_sha256": raw_digest})),
            sha256_bytes(canonical_json({"cluster_id": cluster_id, "input_sha256": raw_digest})),
        ]
        deduplicated = len(set(occurrence_ids))
    assert temporary_path is not None
    deleted = not temporary_path.exists()
    if not deleted:
        raise FuzzingError("temporary crash input survived cleanup")
    return {
        "cluster_id": cluster_id,
        "content_policy": f"{CONTENT_PREFIX}-crash-simulation-v1",
        "deduplicated_occurrence_count": deduplicated,
        "external_handoff": {
            "external_receipt": None,
            "status": "simulated-unfiled",
        },
        "minimized_input_sha256": minimized_digest,
        "raw_input_sha256": raw_digest,
        "regression_record": {
            "post_fix_crashes": False,
            "pre_fix_reproduces": True,
            "public_promotion_authorized": False,
            "status": "local-simulated-not-promoted",
        },
        "reproduction_attempts": 3,
        "reproduction_successes": 3,
        "sanitizer_evidence_status": "not-sanitizer-evidence-controlled-panic-only",
        "schema_version": SCHEMA_VERSION,
        "simulation_status": "passed-local-only",
        "status": STATUS,
        "temporary_raw_input_deleted": deleted,
    }


def build_coverage_document(mapping: dict[str, Any]) -> str:
    lines = [
        "# Package C fuzz-assurance coverage",
        "",
        f"Status: **{STATUS}**.",
        "",
        "This document is generated. Mapping is scope intent only; it is not persistent",
        "campaign, sanitizer, coverage, crash, or release evidence.",
        "",
        "## Counts",
        "",
        f"- Total atomic rows: {mapping['counts']['total_atomic_rows']}",
        f"- Exact critical-family rows mapped: {mapping['counts']['critical_family_rows']}",
        f"- Explicit blocker rows: {mapping['counts']['explicit_blocker_rows']}",
        f"- Release-blocked rows: {mapping['counts']['release_blocked_rows']}",
        "",
        "## Planned semantic targets",
        "",
        "| Target | Atomic rows | Status |",
        "|---|---:|---|",
    ]
    for record in mapping["per_target_counts"]:
        lines.append(
            f"| `{record['target_id']}` | {record['row_count']} | candidate / unaccepted / unprovisioned |"
        )
    lines.extend(
        [
            "",
            "## Release disposition",
            "",
            "Release verification returns 3. No row is promoted by this structural framework.",
            "Final source/evidence subject hashes must be integrated and independently reviewed.",
            "",
        ]
    )
    return "\n".join(lines)
