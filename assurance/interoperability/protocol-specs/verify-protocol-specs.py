#!/usr/bin/env python3
"""Fail-closed verifier for the candidate ECIES/hybrid behavior freeze."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any


EXPECTED_FILES = {
    "ARTIFACTS.sha256",
    "CURRENT-BEHAVIOR.md",
    "README.md",
    "current-behavior.json",
    "protocol-spec.schema.json",
    "protocol-specs-selftest.py",
    "rebind-final-subject.py",
    "verify-protocol-specs.py",
}
EXPECTED_FILE_GIT_MODES = {
    "ARTIFACTS.sha256": "100644",
    "CURRENT-BEHAVIOR.md": "100644",
    "README.md": "100644",
    "current-behavior.json": "100644",
    "protocol-spec.schema.json": "100644",
    "protocol-specs-selftest.py": "100755",
    "rebind-final-subject.py": "100755",
    "verify-protocol-specs.py": "100755",
}
MANIFESTED_FILES = EXPECTED_FILES - {"ARTIFACTS.sha256"}

# These values are deliberately independent of ARTIFACTS.sha256. The latter
# checks package completeness, while these reviewed pins ensure an attacker
# cannot alter normative semantics and merely recompute the mutable manifest.
# The containing verifier is authenticated by the reviewed Git subject/evidence
# binding; no file can safely authenticate its own bytes.
EXPECTED_REVIEWED_ARTIFACT_DIGESTS = {
    "CURRENT-BEHAVIOR.md": "4438f5d21a3231111240ed7bc8af4589733ff7a103511ce76a3eb0d70563fa3f",
    "README.md": "8b10fc6d61614dba0b95e4bb085324ac5bbc2ed63959822441ec3a4f34f407c8",
    "current-behavior.json": "c504a07379055335d455bc9eb46b0acc9f81172d6eb0d2424e76ea5f9e18540e",
    "protocol-spec.schema.json": "c444f5ba500d1feed253b7e46b6db287996924feb4ba15d419ff5206c06e471c",
    "rebind-final-subject.py": "c289a5d0c3d8840608a56be5262e497ca8f85f4d0c00bf8bb5fc8471326f286d",
}

EXPECTED_SOURCE_ROLES = {
    "Cargo.lock": "exact dependency resolution for the bound workspace",
    "Cargo.toml": "workspace membership and dependency topology",
    "crates/algorithms/Cargo.toml": "primitive feature and dependency manifest",
    "crates/algorithms/src/aead/chacha20poly1305/mod.rs": "ECIES ChaCha20-Poly1305 primitive semantics",
    "crates/algorithms/src/aead/gcm/mod.rs": "ECIES AES-256-GCM primitive semantics",
    "crates/algorithms/src/aead/mod.rs": "AEAD module and export topology",
    "crates/algorithms/src/ec/k256/mod.rs": "K-256 curve implementation boundary",
    "crates/algorithms/src/ec/mod.rs": "elliptic-curve module and export topology",
    "crates/algorithms/src/ec/p224/mod.rs": "P-224 curve implementation boundary",
    "crates/algorithms/src/ec/p256/mod.rs": "P-256 curve implementation boundary",
    "crates/algorithms/src/ec/p384/mod.rs": "P-384 curve implementation boundary",
    "crates/algorithms/src/ec/p521/mod.rs": "P-521 curve implementation boundary",
    "crates/algorithms/src/hash/sha2/mod.rs": "SHA-2 primitive semantics used by bound transcripts",
    "crates/algorithms/src/kdf/hkdf/mod.rs": "HKDF primitive semantics used by bound transcripts",
    "crates/algorithms/src/kdf/mod.rs": "KDF module and export topology",
    "crates/algorithms/src/lib.rs": "primitive crate export and feature boundary",
    "crates/api/Cargo.toml": "public API feature and dependency manifest",
    "crates/api/src/error/mod.rs": "public API error taxonomy and exports",
    "crates/api/src/lib.rs": "public API crate export boundary",
    "crates/api/src/traits/kem.rs": "public KEM operation contract",
    "crates/api/src/traits/mod.rs": "public trait export topology",
    "crates/api/src/traits/pke.rs": "public PKE operation contract",
    "crates/api/src/traits/serialize.rs": "public serialization contract",
    "crates/api/src/traits/signature.rs": "public signature operation contract",
    "crates/hybrid/Cargo.toml": "hybrid feature and dependency manifest",
    "crates/hybrid/src/kem/ecdh_k256_ml_kem_512.rs": "exported hybrid KEM suite",
    "crates/hybrid/src/kem/ecdh_p256_ml_kem_512.rs": "exported hybrid KEM suite",
    "crates/hybrid/src/kem/ecdh_p256_ml_kem_768.rs": "exported hybrid KEM suite",
    "crates/hybrid/src/kem/ecdh_p384_ml_kem_1024.rs": "exported hybrid KEM suite",
    "crates/hybrid/src/kem/ecdh_p521_ml_kem_1024.rs": "exported hybrid KEM suite",
    "crates/hybrid/src/kem/engine.rs": "hybrid KEM object encoding, combiner, and failure sequencing",
    "crates/hybrid/src/kem/mod.rs": "hybrid KEM module declarations and public exports",
    "crates/hybrid/src/kem/traits.rs": "hybrid KEM suite identifiers and dimensions",
    "crates/hybrid/src/lib.rs": "hybrid crate module export boundary",
    "crates/hybrid/src/sign/ecdsa_ml_dsa.rs": "hybrid signature framing, component order, and message use",
    "crates/hybrid/src/sign/mod.rs": "hybrid signature module declaration and public export",
    "crates/kem/Cargo.toml": "KEM feature and dependency manifest",
    "crates/kem/src/ecdh/k256/mod.rs": "ECDH-K256 component semantics",
    "crates/kem/src/ecdh/mod.rs": "classical KEM component transcript concatenation",
    "crates/kem/src/ecdh/p256/mod.rs": "ECDH-P256 component semantics",
    "crates/kem/src/ecdh/p384/mod.rs": "ECDH-P384 component semantics",
    "crates/kem/src/ecdh/p521/mod.rs": "ECDH-P521 component semantics",
    "crates/kem/src/error/mod.rs": "KEM component error conversion",
    "crates/kem/src/lib.rs": "KEM crate feature gates, modules, aliases, and exports",
    "crates/kem/src/ml_kem/kem.rs": "ML-KEM component encodings and implicit rejection",
    "crates/kem/src/ml_kem/mod.rs": "ML-KEM parameter aliases and public exports",
    "crates/kem/src/ml_kem/params.rs": "ML-KEM implementation parameter values and encoded lengths",
    "crates/kem/src/ml_kem/pke.rs": "ML-KEM underlying encryption and decoding behavior",
    "crates/params/Cargo.toml": "parameter crate feature and dependency manifest",
    "crates/params/src/lib.rs": "parameter crate export boundary",
    "crates/params/src/pqc/ml_dsa.rs": "ML-DSA parameter values and encoded lengths",
    "crates/params/src/pqc/ml_kem.rs": "ML-KEM public parameter values and encoded lengths",
    "crates/params/src/pqc/mod.rs": "post-quantum parameter module export topology",
    "crates/pke/Cargo.toml": "PKE feature and dependency manifest",
    "crates/pke/src/ecies/mod.rs": "ECIES frame and common KDF transcript",
    "crates/pke/src/ecies/p224/mod.rs": "ECIES P-224 suite",
    "crates/pke/src/ecies/p256/mod.rs": "ECIES P-256 suite",
    "crates/pke/src/ecies/p384/mod.rs": "ECIES P-384 suite",
    "crates/pke/src/ecies/p521/mod.rs": "ECIES P-521 suite",
    "crates/pke/src/error.rs": "ECIES public error conversion",
    "crates/pke/src/lib.rs": "PKE crate feature gates and public exports",
    "crates/sign/Cargo.toml": "signature feature and dependency manifest",
    "crates/sign/src/dilithium/encoding.rs": "ML-DSA canonical key and signature encodings",
    "crates/sign/src/dilithium/mod.rs": "ML-DSA-65 component mode, context, randomizer, and encodings",
    "crates/sign/src/dilithium/sign.rs": "ML-DSA signing and verification transcript leaf",
    "crates/sign/src/ecdsa/mod.rs": "ECDSA module declarations and public exports",
    "crates/sign/src/ecdsa/common.rs": "ECDSA DER, RFC 6979, and low-S helpers",
    "crates/sign/src/ecdsa/p384/mod.rs": "ECDSA P-384 component semantics",
    "crates/sign/src/error.rs": "signature component error conversion",
    "crates/sign/src/lib.rs": "signature crate feature gates and public exports",
}

EXPECTED_SUBJECT_COMMIT = '889cb8c4dc13a78679dc8a7677916484a9966f65'
EXPECTED_SUBJECT_TREE = '0d44b68b186913de68844d09b7e498bcda14d109'
EXPECTED_SUBJECT_MANIFEST_SHA256 = '95902d2ff4a2f99808ba5d404fbce3175b787b93fdc1538cb55ad350e69505c7'
EXPECTED_SUBJECT_FILE_COUNT = 1511
EXPECTED_CURATED_OPERATIONS_SHA256 = '082cc81db8f9fcd9222b195af43208040811ae5f2e5e4565c249fecf6e10dcc8'
EXPECTED_BINDING_STAGE = 'final-subject-candidate-review-required'
EXPECTED_FINAL_REBIND_REQUIRED = False

SUBJECT_ROOTS = ["."]
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

EXPECTED_ECIES_SUITES = [
    ("ECIES-P224-HKDF-SHA256-ChaCha20Poly1305", "P-224", "SHA-256", "ChaCha20-Poly1305", 57, 91, "dcrypt-v3/ECIES-P224/HKDF-SHA256/ChaCha20Poly1305", "transitional"),
    ("ECIES-P256-HKDF-SHA256-ChaCha20Poly1305", "P-256", "SHA-256", "ChaCha20-Poly1305", 65, 99, "dcrypt-v3/ECIES-P256/HKDF-SHA256/ChaCha20Poly1305", "supported"),
    ("ECIES-P384-HKDF-SHA384-AES256GCM", "P-384", "SHA-384", "AES-256-GCM", 97, 131, "dcrypt-v3/ECIES-P384/HKDF-SHA384/AES-256-GCM", "supported"),
    ("ECIES-P521-HKDF-SHA512-AES256GCM", "P-521", "SHA-512", "AES-256-GCM", 133, 167, "dcrypt-v3/ECIES-P521/HKDF-SHA512/AES-256-GCM", "supported"),
]

EXPECTED_HYBRID_KEM_SUITES = [
    ("ECDH-K256-ML-KEM-512", "ECDH-K256", "ML-KEM-512", 833, 1664, 801, 33, 32, "SHA-256", "dcrypt-v3/ECDH-K256-KEM/shared-secret"),
    ("ECDH-P256-ML-KEM-512", "ECDH-P256", "ML-KEM-512", 833, 1664, 801, 33, 32, "SHA-256", "dcrypt-v3/ECDH-P256-KEM/shared-secret"),
    ("ECDH-P256-ML-KEM-768", "ECDH-P256", "ML-KEM-768", 1217, 2432, 1121, 33, 32, "SHA-256", "dcrypt-v3/ECDH-P256-KEM/shared-secret"),
    ("ECDH-P384-ML-KEM-1024", "ECDH-P384", "ML-KEM-1024", 1617, 3216, 1617, 49, 48, "SHA-384", "dcrypt-v3/ECDH-P384-KEM/shared-secret"),
    ("ECDH-P521-ML-KEM-1024", "ECDH-P521", "ML-KEM-1024", 1635, 3234, 1635, 67, 64, "SHA-512", "dcrypt-v3/ECDH-P521-KEM/shared-secret"),
]

EXPECTED_SIGNATURE_OBJECTS = [
    ("public_key", "dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/public/v2", 48, "2106"),
    ("secret_key", "dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/secret/v2", 48, "4137"),
    (
        "signature",
        "dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/signature/v2",
        51,
        "3369 + DER_length; generated low-S mathematical range 3377..3472 bytes",
    ),
]

EXPECTED_ECIES_ERROR_BEHAVIOR = [
    (
        "outer frame is empty, truncated, length-inconsistent, or has trailing bytes",
        "InvalidCiphertext with context ECIES",
    ),
    (
        "recipient public key passed to encrypt is noncanonical, invalid, or identity",
        "InvalidKey with context ECIES recipient public key",
    ),
    (
        "decoded nonce length is not 12",
        "underlying nonce/primitive error converted to the API error type; not normalized as an ECIES decryption failure",
    ),
    (
        "decoded AEAD payload is shorter than the 16-byte tag",
        "InvalidCiphertext with context ECIES AEAD payload",
    ),
    (
        "decoded ephemeral public key is wrong-length, noncanonical, invalid, or identity",
        "InvalidCiphertext with context ECIES ephemeral public key",
    ),
    (
        "ECDH produces the identity during decrypt",
        "DecryptionFailed with context ECIES Decryption",
    ),
    (
        "wrong recipient secret key, wrong AAD, modified ciphertext, or modified tag reaches AEAD authentication",
        "DecryptionFailed with context ECIES Decryption: AEAD authentication failed",
    ),
]

EXPECTED_HYBRID_KEM_ERROR_BEHAVIOR = [
    (
        "composite object byte length is not exactly the selected suite length",
        "InvalidLength before component decoding",
    ),
    (
        "classical component object decoding fails",
        "classical decoder error; post-quantum component is not decoded",
    ),
    (
        "classical decapsulation fails after object decoding",
        "post-quantum decapsulation still runs, an all-zero classical placeholder of the specified shared-secret length is combined, the derived value is discarded, and the classical error is returned",
    ),
    (
        "only post-quantum decapsulation fails after object decoding",
        "an all-zero post-quantum placeholder is combined, the derived value is discarded, and the post-quantum error is returned",
    ),
    (
        "both component decapsulations fail",
        "both placeholders are combined and discarded; the classical error has precedence",
    ),
    (
        "valid-width ML-KEM ciphertext is modified",
        "ML-KEM implicit rejection produces a pseudorandom component secret; hybrid decapsulation can return Ok with a different final secret",
    ),
    (
        "wrong but valid hybrid secret key is used",
        "decapsulation normally returns Ok with a different final secret",
    ),
]

EXPECTED_HYBRID_SIGNATURE_ERROR_BEHAVIOR = [
    (
        "label is absent, truncated, or not the exact expected object label",
        "SerializationError with context Hybrid signature decoding",
    ),
    (
        "component length is missing, overflows, exceeds the input, or trailing bytes remain",
        "SerializationError or InvalidLength with context Hybrid signature decoding",
    ),
    (
        "component object encoding is invalid or noncanonical",
        "the relevant ECDSA or ML-DSA decoder error",
    ),
    (
        "verification is requested",
        "ECDSA verification runs first; ML-DSA verification runs only if ECDSA succeeds; success requires both",
    ),
    (
        "wrong message, wrong key, or tampered signature",
        "the first failing component returns its verification error; failures are not collapsed to one hybrid error",
    ),
]


class VerificationError(Exception):
    pass


def fail(message: str) -> None:
    raise VerificationError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse {path.name}: {error}")


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def ensure_regular_file(path: Path, allowed_root: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    if stat.S_ISLNK(mode):
        fail(f"symlink is forbidden for {label}")
    if not stat.S_ISREG(mode):
        fail(f"regular file required for {label}")
    if path.lstat().st_nlink != 1:
        fail(f"hardlink is forbidden for {label}")
    try:
        path.resolve(strict=True).relative_to(allowed_root.resolve(strict=True))
    except (OSError, ValueError):
        fail(f"{label} escapes its allowed root")


def canonical_git_mode(filesystem_mode: int, expected_git_mode: str, label: str) -> str:
    """Normalize safe umask materializations to reviewed Git executable intent."""

    mode = stat.S_IMODE(filesystem_mode)
    if expected_git_mode == "100644":
        allowed = {0o600, 0o640, 0o644, 0o660, 0o664}
    elif expected_git_mode == "100755":
        allowed = {0o700, 0o750, 0o755, 0o770, 0o775}
    else:
        fail(f"invalid reviewed Git mode for {label}: {expected_git_mode}")
    if mode not in allowed:
        fail(
            f"{label} mode mismatch: filesystem mode {mode:04o} does not preserve "
            f"reviewed Git mode {expected_git_mode}"
        )
    return expected_git_mode


def reject_symlinks_and_unexpected_files(spec_dir: Path) -> None:
    ensure_regular_file(spec_dir / "verify-protocol-specs.py", spec_dir, "verifier")
    actual: set[str] = set()
    for root, dirs, files in os.walk(spec_dir, topdown=True, followlinks=False):
        root_path = Path(root)
        for name in list(dirs):
            child = root_path / name
            if child.is_symlink():
                fail(f"symlink directory is forbidden: {child.relative_to(spec_dir)}")
            fail(f"nested directory is forbidden: {child.relative_to(spec_dir)}")
        for name in files:
            child = root_path / name
            ensure_regular_file(child, spec_dir, f"artifact {name}")
            expected_mode = EXPECTED_FILE_GIT_MODES.get(name)
            if expected_mode is not None:
                canonical_git_mode(child.lstat().st_mode, expected_mode, f"artifact {name}")
            actual.add(child.relative_to(spec_dir).as_posix())
    if actual != EXPECTED_FILES:
        missing = sorted(EXPECTED_FILES - actual)
        extra = sorted(actual - EXPECTED_FILES)
        fail(f"artifact set mismatch; missing={missing}, extra={extra}")


def verify_reviewed_artifact_digests(spec_dir: Path) -> None:
    """Pin normative/policy artifacts independently of the mutable manifest."""
    for name, expected_digest in sorted(EXPECTED_REVIEWED_ARTIFACT_DIGESTS.items()):
        actual_digest = sha256(spec_dir / name)
        if actual_digest != expected_digest:
            fail(
                f"reviewed authoritative digest mismatch: {name}: "
                f"expected {expected_digest}, got {actual_digest}"
            )


def check_closed_schema(schema: Any, pointer: str = "$") -> None:
    if isinstance(schema, dict):
        if schema.get("type") == "object" and schema.get("additionalProperties") is not False:
            fail(f"schema object is not closed at {pointer}")
        for key, value in schema.items():
            check_closed_schema(value, f"{pointer}/{key}")
    elif isinstance(schema, list):
        for index, value in enumerate(schema):
            check_closed_schema(value, f"{pointer}/{index}")


def resolve_ref(root_schema: dict[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        fail(f"only local schema references are allowed: {reference}")
    value: Any = root_schema
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or part not in value:
            fail(f"unresolved schema reference: {reference}")
        value = value[part]
    return value


def validate_schema(instance: Any, schema: dict[str, Any], root: dict[str, Any], pointer: str = "$") -> None:
    if "$ref" in schema:
        validate_schema(instance, resolve_ref(root, schema["$ref"]), root, pointer)
        return
    if "const" in schema and instance != schema["const"]:
        fail(f"schema const mismatch at {pointer}")
    if "enum" in schema and instance not in schema["enum"]:
        fail(f"schema enum mismatch at {pointer}")

    expected_type = schema.get("type")
    type_ok = {
        "array": isinstance(instance, list),
        "boolean": isinstance(instance, bool),
        "integer": isinstance(instance, int) and not isinstance(instance, bool),
        "object": isinstance(instance, dict),
        "string": isinstance(instance, str),
    }.get(expected_type, True)
    if not type_ok:
        fail(f"schema type mismatch at {pointer}: expected {expected_type}")

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        missing = set(schema.get("required", [])) - set(instance)
        if missing:
            fail(f"schema required property missing at {pointer}: {sorted(missing)}")
        if schema.get("additionalProperties") is False:
            extra = set(instance) - set(properties)
            if extra:
                fail(f"schema additional property at {pointer}: {sorted(extra)}")
        for key, value in instance.items():
            if key in properties:
                validate_schema(value, properties[key], root, f"{pointer}/{key}")
    elif isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            fail(f"schema minItems violation at {pointer}")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            fail(f"schema maxItems violation at {pointer}")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in instance]
            if len(encoded) != len(set(encoded)):
                fail(f"schema uniqueItems violation at {pointer}")
        if "items" in schema:
            for index, value in enumerate(instance):
                validate_schema(value, schema["items"], root, f"{pointer}/{index}")
    elif isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            fail(f"schema minLength violation at {pointer}")
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            fail(f"schema pattern mismatch at {pointer}")
    elif isinstance(instance, int) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            fail(f"schema minimum violation at {pointer}")
        if "maximum" in schema and instance > schema["maximum"]:
            fail(f"schema maximum violation at {pointer}")


def verify_manifest(spec_dir: Path) -> None:
    lines = (spec_dir / "ARTIFACTS.sha256").read_text(encoding="utf-8").splitlines()
    expected_lines = [f"{sha256(spec_dir / name)}  {name}" for name in sorted(MANIFESTED_FILES)]
    if lines != expected_lines:
        fail("ARTIFACTS.sha256 is stale, noncanonical, incomplete, or reordered")


def run_git(repo_root: Path, arguments: list[str], *, binary: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=not binary,
    )


def subject_path_included(path_value: str) -> bool:
    normalized = path_value[2:] if path_value.startswith("./") else path_value
    if normalized in SUBJECT_EXCLUDED_FILES:
        return False
    if normalized == "assurance" or normalized.startswith("assurance/"):
        return False
    return True


def validate_relative_path(raw_path: str, label: str) -> None:
    pure = PurePosixPath(raw_path)
    if (
        not raw_path
        or pure.is_absolute()
        or ".." in pure.parts
        or "." in pure.parts
        or str(pure) != raw_path
        or "\\" in raw_path
    ):
        fail(f"unsafe or noncanonical {label} path: {raw_path}")


def git_tree_entries(repo_root: Path, source_commit: str) -> dict[str, tuple[str, str]]:
    result = run_git(
        repo_root,
        ["ls-tree", "-r", "-z", "--full-tree", source_commit, "--", *SUBJECT_ROOTS],
        binary=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        fail(f"subject manifest cannot inspect bound Git tree: {detail}")
    entries: dict[str, tuple[str, str]] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path_value = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            fail("subject manifest encountered an invalid Git tree record")
        if object_type != "blob" or mode not in {"100644", "100755"}:
            fail(f"subject manifest scope contains a non-regular Git entry: {path_value}")
        validate_relative_path(path_value, "bound subject")
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
        fail("subject manifest cannot open git cat-file pipes")
    digests: dict[str, str] = {}
    for expected in identifiers:
        process.stdin.write((expected + "\n").encode("ascii"))
        process.stdin.flush()
        header_bytes = process.stdout.readline()
        if not header_bytes.endswith(b"\n"):
            fail("subject manifest received truncated git cat-file output")
        header = header_bytes[:-1].decode("ascii", "replace")
        parts = header.split(" ")
        if len(parts) != 3 or parts[0] != expected or parts[1] != "blob":
            fail(f"subject manifest received unexpected git cat-file header: {header}")
        try:
            size = int(parts[2])
        except ValueError:
            fail(f"subject manifest received invalid git cat-file size: {header}")
        remaining = size
        digest = hashlib.sha256()
        while remaining:
            chunk = process.stdout.read(min(1024 * 1024, remaining))
            if not chunk:
                fail(f"subject manifest received truncated blob: {expected}")
            digest.update(chunk)
            remaining -= len(chunk)
        if process.stdout.read(1) != b"\n":
            fail(f"subject manifest received invalid blob delimiter: {expected}")
        digests[expected] = digest.hexdigest()
    process.stdin.close()
    if process.stdout.read(1) != b"":
        fail("subject manifest received trailing git cat-file output")
    stderr = process.stderr.read()
    returncode = process.wait()
    if returncode != 0:
        fail(
            "subject manifest cannot read bound blobs: "
            + stderr.decode("utf-8", "replace").strip()
        )
    return digests


def verify_current_subject(
    repo_root: Path,
    declared: dict[str, tuple[str, str]],
) -> None:
    listing = run_git(
        repo_root,
        ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", *SUBJECT_ROOTS],
        binary=True,
    )
    if listing.returncode != 0:
        fail("subject manifest cannot inspect current subject paths")
    try:
        all_current = {
            raw.decode("utf-8") for raw in listing.stdout.split(b"\0") if raw
        }
    except UnicodeDecodeError:
        fail("subject manifest current subject contains a non-UTF-8 path")
    current = {path for path in all_current if subject_path_included(path)}
    declared_paths = set(declared)
    if current != declared_paths:
        fail(
            "subject manifest current/bound path set mismatch: "
            f"new={sorted(current - declared_paths)}, "
            f"removed={sorted(declared_paths - current)}"
        )
    present_sentinels = [
        path for path in SUBJECT_ABSENT_BUILD_INPUTS if os.path.lexists(repo_root / path)
    ]
    if present_sentinels:
        fail(f"subject manifest absence sentinel exists in current tree: {present_sentinels}")
    for path_value, (expected_digest, expected_mode) in declared.items():
        path = repo_root / PurePosixPath(path_value)
        ensure_regular_file(path, repo_root, f"current subject {path_value}")
        if sha256(path) != expected_digest:
            fail(f"subject manifest current digest mismatch: {path_value}")
        canonical_git_mode(
            path.lstat().st_mode,
            expected_mode,
            f"subject manifest current path {path_value}",
        )


def verify_subject_binding(
    data: dict[str, Any],
    repo_root: Path,
    *,
    check_current_subject: bool,
    require_final_subject: bool,
) -> dict[str, tuple[str, str]]:
    binding = data["subject_binding"]
    expected_binding = {
        "binding_stage": EXPECTED_BINDING_STAGE,
        "curated_operations_path": "assurance/curated-operations.toml",
        "curated_operations_sha256": EXPECTED_CURATED_OPERATIONS_SHA256,
        "final_rebind_required": EXPECTED_FINAL_REBIND_REQUIRED,
        "manifest_file_count": EXPECTED_SUBJECT_FILE_COUNT,
        "manifest_include_policy": SUBJECT_INCLUDE_POLICY,
        "source_commit": EXPECTED_SUBJECT_COMMIT,
        "source_tree": EXPECTED_SUBJECT_TREE,
        "subject_manifest_path": "assurance/subject-manifest.json",
        "subject_manifest_sha256": EXPECTED_SUBJECT_MANIFEST_SHA256,
    }
    if binding != expected_binding:
        fail("subject binding differs from the reviewed exact binding")
    if require_final_subject and binding["final_rebind_required"]:
        fail("final subject binding is required but this freeze remains interim-rebind-required")

    manifest_path = repo_root / binding["subject_manifest_path"]
    curated_path = repo_root / binding["curated_operations_path"]
    ensure_regular_file(manifest_path, repo_root, "subject manifest")
    ensure_regular_file(curated_path, repo_root, "curated operations")
    if sha256(manifest_path) != binding["subject_manifest_sha256"]:
        fail("subject manifest digest differs from the reviewed binding")
    if sha256(curated_path) != binding["curated_operations_sha256"]:
        fail("curated operations digest differs from the reviewed binding")

    manifest = load_json(manifest_path)
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
    if list(manifest) != expected_root_keys:
        fail("subject manifest root keys are noncanonical, missing, or extra")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("source_commit") != binding["source_commit"]
        or manifest.get("source_tree") != binding["source_tree"]
        or manifest.get("roots") != SUBJECT_ROOTS
        or manifest.get("root_files") != SUBJECT_ROOT_FILES
        or manifest.get("absent_build_inputs") != SUBJECT_ABSENT_BUILD_INPUTS
        or manifest.get("include_policy") != SUBJECT_INCLUDE_POLICY
    ):
        fail("subject manifest provenance, scope, or include policy mismatch")
    if manifest_path.read_bytes() != (
        json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=False) + "\n"
    ).encode("utf-8"):
        fail("subject manifest is not canonical generator-form JSON")

    resolved = run_git(repo_root, ["rev-parse", f"{binding['source_commit']}^{{tree}}"])
    if resolved.returncode != 0:
        fail("subject source commit cannot be resolved in this repository")
    if resolved.stdout.strip() != binding["source_tree"]:
        fail("subject source tree does not match the bound source commit")
    committed = git_tree_entries(repo_root, binding["source_commit"])
    bound_sentinels = set(SUBJECT_ABSENT_BUILD_INPUTS) & set(committed)
    if bound_sentinels:
        fail(f"subject manifest absence sentinel exists in bound commit: {sorted(bound_sentinels)}")

    rows = manifest.get("files")
    if not isinstance(rows, list):
        fail("subject manifest files must be an array")
    if len(rows) != binding["manifest_file_count"]:
        fail("subject manifest file count differs from the reviewed binding")
    declared: dict[str, tuple[str, str]] = {}
    paths_in_order: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or list(row) != ["path", "sha256", "git_mode"]:
            fail(f"subject manifest files[{index}] keys are invalid or noncanonical")
        path_value = row.get("path")
        digest = row.get("sha256")
        git_mode = row.get("git_mode")
        if not isinstance(path_value, str):
            fail(f"subject manifest files[{index}] path is invalid")
        validate_relative_path(path_value, "subject manifest")
        if not subject_path_included(path_value):
            fail(f"subject manifest binds an excluded path: {path_value}")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            fail(f"subject manifest files[{index}] digest is invalid")
        if git_mode not in {"100644", "100755"}:
            fail(f"subject manifest files[{index}] mode is invalid")
        if path_value in declared:
            fail(f"subject manifest has duplicate path: {path_value}")
        declared[path_value] = (digest, git_mode)
        paths_in_order.append(path_value)
    if paths_in_order != sorted(paths_in_order):
        fail("subject manifest file rows are not sorted by path")
    if set(declared) != set(committed):
        fail(
            "subject manifest path set mismatch: "
            f"missing={sorted(set(committed) - set(declared))}, "
            f"stale={sorted(set(declared) - set(committed))}"
        )

    blob_digests = git_blob_sha256s(
        repo_root, [object_id for _mode, object_id in committed.values()]
    )
    for path_value, (digest, git_mode) in declared.items():
        committed_mode, object_id = committed[path_value]
        if committed_mode != git_mode:
            fail(f"subject manifest bound-commit mode mismatch: {path_value}")
        if blob_digests.get(object_id) != digest:
            fail(f"subject manifest bound-commit digest mismatch: {path_value}")

    if check_current_subject or not binding["final_rebind_required"]:
        verify_current_subject(repo_root, declared)
    return declared


def verify_sources(
    data: dict[str, Any],
    repo_root: Path,
    subject_rows: dict[str, tuple[str, str]],
) -> None:
    bindings: dict[str, str] = {}
    roles: dict[str, str] = {}
    paths_in_order: list[str] = []
    for entry in data["source_bindings"]:
        raw_path = entry["path"]
        validate_relative_path(raw_path, "source binding")
        if raw_path in bindings:
            fail(f"duplicate source binding: {raw_path}")
        bindings[raw_path] = entry["sha256"]
        roles[raw_path] = entry["role"]
        paths_in_order.append(raw_path)
    if paths_in_order != sorted(paths_in_order):
        fail("source bindings are not sorted by path")
    if roles != EXPECTED_SOURCE_ROLES:
        fail("source binding path/role set differs from the reviewed freeze set")
    for raw_path, expected_digest in bindings.items():
        subject_row = subject_rows.get(raw_path)
        if subject_row is None or subject_row[0] != expected_digest:
            fail(f"critical source binding differs from complete subject manifest: {raw_path}")
        path = repo_root / PurePosixPath(raw_path)
        ensure_regular_file(path, repo_root, f"bound source {raw_path}")
        actual_digest = sha256(path)
        if actual_digest != expected_digest:
            fail(f"bound source digest mismatch: {raw_path}: {actual_digest}")


def verify_authoritative_rendering(data: dict[str, Any], rendering: str) -> None:
    """Cross-check high-risk registry values against the reviewed Markdown."""
    required_fragments = {
        "non-evidentiary status": "It accepts no oracle and clears no assurance blocker.",
        "clean-room stop": "Reference acceptance remains blocked until reviewers explicitly address",
        "ECIES grammar": "u8(R_len) || R || u8(N_len) || N || u32be(CT_len) || C || T",
        "ECIES version limitation": "The `dcrypt-v3` text exists only in HKDF literals.",
        "hybrid KEM version limitation": "The `v2` literal is only HKDF info, not an object header.",
        "hybrid-signature transcript limitation": (
            "The hybrid framing label, component public keys, component lengths, suite name, "
            "and `v2` marker are not signed by either component."
        ),
        "Git binding caveat": (
            "Those embedded digests do not authenticate the verifier itself: the reviewed Git "
            "subject/evidence binding must bind the verifier's exact bytes"
        ),
        "complete subject boundary": (
            "The complete subject manifest, not the 70-entry critical subset, is the coverage boundary."
        ),
    }
    for label, fragment in required_fragments.items():
        if fragment not in rendering:
            fail(f"authoritative rendering is missing {label}")

    binding = data["subject_binding"]
    binding_article = "an" if binding["binding_stage"].startswith("interim") else "a"
    expected_binding_fragment = (
        f"This candidate currently has {binding_article} **{binding['binding_stage']}** binding. "
        f"It binds source commit `{binding['source_commit']}`, source tree "
        f"`{binding['source_tree']}`, canonical `assurance/subject-manifest.json` SHA-256 "
        f"`{binding['subject_manifest_sha256']}` ({binding['manifest_file_count']:,} owned "
        f"subject files under include policy `{binding['manifest_include_policy']}`), and "
        f"`assurance/curated-operations.toml` SHA-256 "
        f"`{binding['curated_operations_sha256']}`."
    )
    if expected_binding_fragment not in rendering:
        fail("authoritative rendering disagrees with the exact subject binding")

    for suite in data["ecies"]["suites"]:
        row = (
            f"| `{suite['name']}` | {suite['curve']} | {suite['point_length']} | "
            f"{suite['hash']} | {suite['aead']} | `{suite['info_ascii']}` | "
            f"{suite['ciphertext_overhead']} |"
        )
        if row not in rendering:
            fail(f"authoritative rendering disagrees with ECIES suite {suite['name']}")

    for suite in data["hybrid_kem"]["suites"]:
        row = (
            f"| `{suite['name']}` | `{suite['classical_suite_id']}` | "
            f"`{suite['post_quantum_suite_id']}` | {suite['public_key_length']} | "
            f"{suite['secret_key_length']} | {suite['ciphertext_length']} | "
            f"{suite['classical_shared_secret_length']} |"
        )
        if row not in rendering:
            fail(f"authoritative rendering disagrees with hybrid KEM suite {suite['name']}")

    for framed_object in data["hybrid_signature"]["object_encodings"]:
        if f"`{framed_object['label_ascii']}`" not in rendering:
            fail(
                "authoritative rendering omits hybrid-signature label "
                f"{framed_object['name']}"
            )


def verify_semantics(data: dict[str, Any]) -> None:
    assurance = data["assurance_effect"]
    if assurance != {
        "accepted_oracle_count": 0,
        "counts_as_interoperability_evidence": False,
        "counts_as_release_unblocking_evidence": False,
        "purpose": "candidate current-behavior freeze for independent review before clean-room reference work",
    }:
        fail("assurance effect must remain exactly non-evidentiary")
    if data["clean_room_acceptance"]["status"] != "blocked":
        fail("clean-room acceptance must remain blocked")

    ecies = data["ecies"]
    if ecies["frame"]["grammar"] != "u8(R_len) || R || u8(N_len) || N || u32be(CT_len) || C || T":
        fail("ECIES frame grammar changed")
    if [field["name"] for field in ecies["frame"]["fields"]] != [
        "R_len", "R", "N_len", "N", "CT_len", "C_and_T"
    ]:
        fail("ECIES frame field order changed")
    if ecies["kdf"] != {
        "ikm": "fixed-width ECDH shared-point x-coordinate || exact uncompressed ephemeral public key R || exact uncompressed recipient public key",
        "okm_length": 32,
        "operation": "HKDF-Extract then HKDF-Expand",
        "salt_ascii": "dcrypt-v3/ECIES/extract",
        "suite_info_source": "exact per-suite info_ascii value",
    }:
        fail("ECIES KDF description changed")
    observed_ecies = [
        (
            s["name"], s["curve"], s["hash"], s["aead"], s["point_length"],
            s["ciphertext_overhead"], s["info_ascii"], s["status"],
        )
        for s in ecies["suites"]
    ]
    if observed_ecies != EXPECTED_ECIES_SUITES:
        fail("ECIES suite order or dimensions changed")
    if [(rule["condition"], rule["outcome"]) for rule in ecies["error_behavior"]] != EXPECTED_ECIES_ERROR_BEHAVIOR:
        fail("ECIES error behavior changed")
    for suite in ecies["suites"]:
        if suite["ciphertext_overhead"] != suite["point_length"] + 34:
            fail(f"ECIES overhead derivation mismatch: {suite['name']}")
    if ecies["versioning"]["in_band_suite_identifier"] or ecies["versioning"]["in_band_version_identifier"]:
        fail("ECIES must remain recorded as out-of-band dispatch")

    hybrid_kem = data["hybrid_kem"]
    if hybrid_kem["combiner"] != {
        "hash": "SHA-256",
        "ikm": "u32be(len(classical_ss)) || classical_ss || u32be(len(post_quantum_ss)) || post_quantum_ss",
        "info": "ASCII(dcrypt-hybrid-kem/v2) || u32be(len(classical_suite_id)) || classical_suite_id || u32be(len(post_quantum_suite_id)) || post_quantum_suite_id || u32be(len(hybrid_ciphertext)) || hybrid_ciphertext",
        "okm_length": 32,
        "operation": "HKDF-Extract then HKDF-Expand",
        "salt": "empty byte string (implementation passes None)",
    }:
        fail("hybrid KEM combiner changed")
    observed_hybrid = [
        (
            s["name"], s["classical_suite_id"], s["post_quantum_suite_id"],
            s["public_key_length"], s["secret_key_length"], s["ciphertext_length"],
            s["classical_ciphertext_length"], s["classical_shared_secret_length"],
            s["classical_kdf_hash"], s["classical_kdf_info_ascii"],
        )
        for s in hybrid_kem["suites"]
    ]
    if observed_hybrid != EXPECTED_HYBRID_KEM_SUITES:
        fail("hybrid KEM suite order or dimensions changed")
    if [
        (rule["condition"], rule["outcome"])
        for rule in hybrid_kem["error_behavior"]
    ] != EXPECTED_HYBRID_KEM_ERROR_BEHAVIOR:
        fail("hybrid KEM error behavior changed")
    if hybrid_kem["versioning"]["in_band_suite_identifier"] or hybrid_kem["versioning"]["in_band_version_identifier"]:
        fail("hybrid KEM objects must remain recorded as out-of-band dispatch")
    lengths = [(s["public_key_length"], s["secret_key_length"], s["ciphertext_length"]) for s in hybrid_kem["suites"]]
    if lengths.count((833, 1664, 801)) != 2:
        fail("hybrid KEM equal-length suite ambiguity is missing")

    hybrid_signature = data["hybrid_signature"]
    observed_objects = [
        (o["name"], o["label_ascii"], o["label_length"], o["total_length"])
        for o in hybrid_signature["object_encodings"]
    ]
    if observed_objects != EXPECTED_SIGNATURE_OBJECTS:
        fail("hybrid signature labels, lengths, or order changed")
    if [
        (rule["condition"], rule["outcome"])
        for rule in hybrid_signature["error_behavior"]
    ] != EXPECTED_HYBRID_SIGNATURE_ERROR_BEHAVIOR:
        fail("hybrid signature error behavior changed")
    for obj in hybrid_signature["object_encodings"]:
        if len(obj["label_ascii"].encode("ascii")) != obj["label_length"]:
            fail(f"hybrid signature label length mismatch: {obj['name']}")
    if hybrid_signature["signing"] != {
        "component_order": "ECDSA signs first, then ML-DSA",
        "message_to_ecdsa": "the caller's raw message bytes",
        "message_to_ml_dsa": "pure-mode formatted bytes 0x00 || 0x00 || caller raw message",
        "not_signed": "the hybrid framing label, component public keys, component lengths, suite name, and v2 marker are not included in either signed message",
    }:
        fail("hybrid signature message/transcript behavior changed")
    if not hybrid_signature["versioning"]["in_band_suite_identifier"] or not hybrid_signature["versioning"]["in_band_version_identifier"]:
        fail("hybrid signature framing labels must remain recorded as in-band identifiers")


def parse_args() -> argparse.Namespace:
    own_dir = Path(__file__).absolute().parent
    default_repo = own_dir.parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-dir", type=Path, default=own_dir)
    parser.add_argument("--repo-root", type=Path, default=default_repo)
    parser.add_argument(
        "--check-current-subject",
        action="store_true",
        help="require every current owned subject path, digest, and mode to match the bound manifest",
    )
    parser.add_argument(
        "--require-final-subject",
        action="store_true",
        help="reject an interim binding that still requires the explicit final-subject rebind",
    )
    return parser.parse_args()


def run() -> None:
    args = parse_args()
    spec_dir = args.spec_dir.absolute()
    repo_root = args.repo_root.absolute()
    if spec_dir.is_symlink() or repo_root.is_symlink():
        fail("spec-dir and repo-root must not be symlinks")
    reject_symlinks_and_unexpected_files(spec_dir)
    verify_reviewed_artifact_digests(spec_dir)
    schema_path = spec_dir / "protocol-spec.schema.json"
    data_path = spec_dir / "current-behavior.json"
    rendering_path = spec_dir / "CURRENT-BEHAVIOR.md"
    schema = load_json(schema_path)
    data = load_json(data_path)
    if schema_path.read_bytes() != canonical_json(schema):
        fail("protocol-spec.schema.json is not canonical sorted-key JSON")
    if data_path.read_bytes() != canonical_json(data):
        fail("current-behavior.json is not canonical sorted-key JSON")
    check_closed_schema(schema)
    validate_schema(data, schema, schema)
    verify_semantics(data)
    subject_rows = verify_subject_binding(
        data,
        repo_root,
        check_current_subject=args.check_current_subject,
        require_final_subject=args.require_final_subject,
    )
    try:
        rendering = rendering_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read authoritative rendering: {error}")
    verify_authoritative_rendering(data, rendering)
    verify_sources(data, repo_root, subject_rows)
    verify_manifest(spec_dir)
    print(
        "protocol-spec verification: PASS "
        f"(ECIES suites=4, hybrid KEM suites=5, hybrid signature suites=1, "
        f"accepted oracles=0, clean-room acceptance=blocked, "
        f"subject stage={data['subject_binding']['binding_stage']}, "
        f"subject files={len(subject_rows)}, critical source bindings={len(EXPECTED_SOURCE_ROLES)}, "
        f"reviewed artifact pins={len(EXPECTED_REVIEWED_ARTIFACT_DIGESTS)})"
    )


if __name__ == "__main__":
    try:
        run()
    except VerificationError as error:
        print(f"protocol-spec verification: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
