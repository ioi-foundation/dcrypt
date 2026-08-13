#!/usr/bin/env python3
"""Fail-closed, deterministic interoperability matrix support for dcrypt.

This module uses only the Python standard library.  It inventories requirements
and candidate oracles; it does not convert a harness, candidate dossier, or
first-party execution into passing assurance evidence.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib
from typing import Any, Iterable


HERE = Path(__file__).absolute().parent
ASSURANCE_DIR = HERE.parent
REPO_ROOT = ASSURANCE_DIR.parent

POLICY_PATH = HERE / "policy.toml"
DOSSIERS_PATH = HERE / "oracle-dossiers.toml"
OVERRIDES_PATH = HERE / "evidence-overrides.toml"
MATRIX_PATH = HERE / "matrix.json"
DOCUMENT_PATH = HERE / "INTEROPERABILITY.md"

FIXED_INPUTS = {
    "atomic-operations": "assurance/atomic-operations.toml",
    "public-api-snapshot": "assurance/public-api-snapshot.json",
    "assurance-ledger": "assurance/ledger.toml",
    "implementation-boundary": "implementation-boundary.toml",
    "root-manifest": "Cargo.toml",
    "root-lockfile": "Cargo.lock",
    "verification-manifest": "verification/Cargo.toml",
    "verification-lockfile": "verification/Cargo.lock",
}

GENERATED_CONTROL_INPUTS = (
    "assurance/interoperability/policy.toml",
    "assurance/interoperability/matrix.schema.json",
    "assurance/interoperability/oracle-dossier.schema.json",
    "assurance/interoperability/evidence-overrides.schema.json",
    "assurance/interoperability/oracle-dossiers.toml",
    "assurance/interoperability/evidence-overrides.toml",
    "assurance/interoperability/interop_lib.py",
    "assurance/interoperability/generate-interoperability-matrix.py",
    "assurance/interoperability/verify-interoperability.py",
    "assurance/interoperability/interoperability-selftest.py",
)

PRESERVATION_FILES = (
    "verification/README.md",
    "verification/src/lib.rs",
)
PRESERVATION_TREES = (
    "verification/tests",
    "verification/vectors",
)

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

POLICY_TOP_KEYS = {
    "schema-version",
    "matrix-version",
    "content-policy",
    "as-of",
    "evidence-promotion-enabled",
    "expected",
    "review",
    "inputs",
    "disposition",
    "published",
    "required-family",
}
EXPECTED_KEYS = {
    "curated-operation-rows",
    "curated-operation-atoms",
    "curated-data-surface-rows",
    "curated-data-surface-atoms",
    "unreviewed-gap-rows",
    "ledger-atomic-rows",
    "ledger-release-blockers",
    "public-api-units",
    "snapshot-profiles",
}
REVIEW_KEYS = {
    "default-owner",
    "default-reviewer",
    "default-deadline",
    "default-expiry",
    "maximum-validity-days",
}
DISPOSITION_KEYS = {
    "operation-status",
    "operation-blocker",
    "data-surface-status",
    "data-surface-rationale",
    "gap-status",
    "gap-blocker",
    "placeholder-direction",
    "placeholder-oracle",
    "placeholder-case-id",
}
PUBLISHED_KEYS = {"packages", "manifests", "manifest-record-sha256"}
FAMILY_KEYS = {
    "id",
    "scope",
    "mapping-kind",
    "atomic-selectors",
    "preservation",
    "disposition",
}

# This code-side contract prevents removal or relabeling of a mandatory B3 or
# preservation family by merely rebasing policy hashes and aggregate counts.
MANDATORY_FAMILY_SELECTORS = {
    "ml-kem-512": ("public-atomic-selector", ("ML-KEM|ML-KEM-512",), False),
    "ml-kem-768": ("public-atomic-selector", ("ML-KEM|ML-KEM-768",), False),
    "ml-kem-1024": ("public-atomic-selector", ("ML-KEM|ML-KEM-1024",), False),
    "ed25519-strict": ("public-atomic-selector", ("Ed25519|Ed25519",), False),
    "ecdsa-p224": ("public-atomic-selector", ("ECDSA|P-224",), False),
    "ecdsa-p256": ("public-atomic-selector", ("ECDSA|P-256",), False),
    "ecdsa-p384": ("public-atomic-selector", ("ECDSA|P-384",), False),
    "ecdsa-p521": ("public-atomic-selector", ("ECDSA|P-521",), False),
    "ecdh-p224": ("public-atomic-selector", ("ECDH KEM|P-224",), False),
    "ecdh-p256": ("public-atomic-selector", ("ECDH KEM|P-256",), False),
    "ecdh-p384": ("public-atomic-selector", ("ECDH KEM|P-384",), False),
    "ecdh-p521": ("public-atomic-selector", ("ECDH KEM|P-521",), False),
    "ecdh-secp256k1": ("public-atomic-selector", ("ECDH KEM|secp256k1",), False),
    "aes-128-gcm": ("public-atomic-selector", ("AES-GCM|AES-128-GCM",), False),
    "aes-256-gcm": ("public-atomic-selector", ("AES-GCM|AES-256-GCM",), False),
    "ghash-private-disposition": ("private-disposition", (), False),
    "chacha20-poly1305": (
        "public-atomic-selector",
        ("ChaCha20-Poly1305|ChaCha20-Poly1305",),
        False,
    ),
    "xchacha20-poly1305-high-level": (
        "public-atomic-selector",
        ("XChaCha20-Poly1305|XChaCha20-Poly1305",),
        False,
    ),
    "bls12-381-second-lineage": (
        "public-atomic-selector",
        ("BLS12-381 signatures|BLS12-381-G2", "BLS12-381|BLS12-381"),
        False,
    ),
    "preserve-ml-dsa-44": ("public-atomic-selector", ("ML-DSA|ML-DSA-44",), True),
    "preserve-ml-dsa-65": ("public-atomic-selector", ("ML-DSA|ML-DSA-65",), True),
    "preserve-ml-dsa-87": ("public-atomic-selector", ("ML-DSA|ML-DSA-87",), True),
    "preserve-bls12-381-current": (
        "public-atomic-selector",
        ("BLS12-381 signatures|BLS12-381-G2", "BLS12-381|BLS12-381"),
        True,
    ),
    "preserve-ethereum-bls": (
        "public-atomic-selector",
        ("BLS12-381 Ethereum consensus signatures|BLS12-381-G2",),
        True,
    ),
    "preserve-traditional-ec": (
        "public-atomic-selector",
        (
            "prime-field elliptic curve|P-224",
            "prime-field elliptic curve|P-256",
            "prime-field elliptic curve|P-384",
            "prime-field elliptic curve|P-521",
            "prime-field elliptic curve|secp256k1",
        ),
        True,
    ),
    "preserve-xchacha20-poly1305": (
        "public-atomic-selector",
        ("XChaCha20-Poly1305|XChaCha20-Poly1305",),
        True,
    ),
}

DOSSIER_KEYS = {
    "id",
    "status",
    "display-name",
    "package",
    "version",
    "source-url",
    "source-commit",
    "source-commit-provenance",
    "archive-sha256",
    "license",
    "license-file-sha256",
    "provenance-status",
    "acquisition-method",
    "acquisition-record",
    "lockfile",
    "lockfile-sha256",
    "dependency-role",
    "offline-artifact-path",
    "offline-artifact-sha256",
    "offline-replay-command",
    "network-policy",
    "implementation-lineage",
    "independence-review-status",
    "lineage-review",
    "source-ancestry",
    "arithmetic-libraries",
    "ffi-backends",
    "generated-tables",
    "shared-primitives",
    "vector-generators",
    "specifications-reference-code",
    "intended-families",
    "tests",
    "owner",
    "reviewer",
    "review-date",
    "deadline",
    "expiry",
}
DOSSIER_LIST_KEYS = {
    "license-file-sha256",
    "source-ancestry",
    "arithmetic-libraries",
    "ffi-backends",
    "generated-tables",
    "shared-primitives",
    "vector-generators",
    "specifications-reference-code",
    "intended-families",
    "tests",
}
DOSSIER_STATUSES = {"candidate", "rejected-as-independent", "retired"}
LINEAGE_STATUSES = {
    "unknown",
    "independent",
    "shared-source-lineage",
    "shared-development-lineage",
    "shared-production-backend",
    "shared-reference-lineage",
}

# These exact declarations predate Package B and are non-production test-only
# dependencies, not oracle integrations. They are immutable here so that a
# package already shared with the verification closure cannot be used as a
# wildcard exception for any other manifest, dependency kind, target, version,
# or alias.
PUBLISHED_NONPRODUCTION_SHARED_BASELINE = {
    ("crates/algorithms/Cargo.toml", "dev-dependencies", "serde", "serde", "=1.0.229"),
    ("crates/algorithms/Cargo.toml", "dev-dependencies", "serde_json", "serde_json", "=1.0.151"),
    ("crates/sign/Cargo.toml", "dev-dependencies", "hex", "hex", "0.4"),
}

# Package B does not authorize any change to the twelve published Cargo
# manifests.  Bind both the exact path/package mapping and the canonical TOML
# record for every manifest in code as well as policy.  This prevents a policy
# rebind from substituting an assurance-owned copy for the real manifest, and
# rejects an arbitrary new external dependency even when its name is absent
# from the verification lock closure.
EXPECTED_PUBLISHED_MANIFEST_PACKAGES = {
    "crates/internal/Cargo.toml": "dcrypt-internal",
    "crates/params/Cargo.toml": "dcrypt-params",
    "crates/api/Cargo.toml": "dcrypt-api",
    "crates/common/Cargo.toml": "dcrypt-common",
    "crates/algorithms/Cargo.toml": "dcrypt-algorithms",
    "crates/symmetric/Cargo.toml": "dcrypt-symmetric",
    "crates/kem/Cargo.toml": "dcrypt-kem",
    "crates/sign/Cargo.toml": "dcrypt-sign",
    "crates/pke/Cargo.toml": "dcrypt-pke",
    "crates/utils/Cargo.toml": "dcrypt-utils",
    "crates/hybrid/Cargo.toml": "dcrypt-hybrid",
    "Cargo.toml": "dcrypt",
}
EXPECTED_PUBLISHED_MANIFEST_RECORD_SHA256 = {
    "crates/internal/Cargo.toml": "5828bd1d90c93fe4843b525f8563d6a2d93d25d3b516530f4e75cb9fb7309c19",
    "crates/params/Cargo.toml": "bf1f1b65502e6d1fb473f90c8cb01fb087df80009086c730542b61f10acc6c6a",
    "crates/api/Cargo.toml": "67b130c216a8b5e3b6ce989f0490b3235bc1041e07b39b94f75b1be197006ebf",
    "crates/common/Cargo.toml": "a86ba48b2605fade26e6d800a9d55d12dd90bc8a864194e5f7bd27697a01cd5b",
    "crates/algorithms/Cargo.toml": "e808403b09b3815fcb62aed5dff254be8a0a3f1c31257cd15b97a53bb58b492e",
    "crates/symmetric/Cargo.toml": "0bda4f80550e099b683ce8acb24720e30d75858414437e0845ad339ddd692d6a",
    "crates/kem/Cargo.toml": "b639a81a049a2bf81c24cf83a2cc8551ed8064d4bfee334eb6fd89bf8834860d",
    "crates/sign/Cargo.toml": "9eb13c393fd26eadf1a7d9963dc46ee5157604feef9ab14619b8d665636a3281",
    "crates/pke/Cargo.toml": "32b027250f560d9ac39a14f3aaa6f72ea482bb50610fc80fc70ff9364d22d03e",
    "crates/utils/Cargo.toml": "af031384c04c58fa40a73b7a303084760c45d79efb468e68986f36f9dee429aa",
    "crates/hybrid/Cargo.toml": "729d12e76d84795c26b2c6f821da046c2faa5065d9e3bef20024fab2e4c0171f",
    "Cargo.toml": "73b5662e222774b3370f6c19385a94aa048f3470bd122045ebb84218eb26043e",
}
EXPECTED_ROOT_LOCK_SHA256 = "0f4a81042e4d73f6313e30d80668606e8528124e97936f669585669e4ce06736"

MATRIX_TOP_KEYS = {
    "schema_version",
    "content_policy",
    "canonicalization",
    "source_binding",
    "generated_inputs",
    "required_families",
    "oracle_dossiers",
    "verification_external_closure",
    "counts",
    "release_gate",
    "rows",
    "unreviewed_gaps",
}
MATRIX_ROW_KEYS = {
    "row_id",
    "row_kind",
    "atomic_record_sha256",
    "key",
    "corpus_test_identifiers",
    "evidence_sha256",
    "evidence_generated_at",
    "evidence_valid_through",
    "execution_status",
    "independent_replay_status",
    "freshness_status",
    "status",
    "blocker",
    "not_applicable_rationale",
    "owner",
    "reviewer",
    "deadline",
    "expiry",
}
MATRIX_KEY_KEYS = {
    "atomic_row_id",
    "crate",
    "public_path",
    "public_unit",
    "public_kind",
    "algorithm",
    "standard",
    "standards_scope",
    "parameter_set",
    "operation",
    "encoding_wire_format",
    "mode_profile",
    "dst_context_prehash",
    "feature_profile",
    "platform",
    "direction",
    "oracle_id",
    "oracle_version",
    "oracle_source_commit",
    "oracle_checksum",
    "oracle_license",
    "oracle_acquisition_provenance",
    "implementation_lineage",
    "shared_dependencies",
    "case_id",
}
GAP_KEYS = {
    "atomic_row_id",
    "row_kind",
    "raw_record_sha256",
    "effective_record_sha256",
    "public_bindings_sha256",
    "public_entry_count",
    "profile_atom_count",
    "status",
    "blocker",
    "owner",
    "reviewer",
    "deadline",
    "expiry",
}


class ValidationError(RuntimeError):
    """Raised for a fail-closed interoperability validation error."""


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _canonical_value(value: Any) -> Any:
    if isinstance(value, dt.date) and not isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    if isinstance(value, float):
        raise ValidationError("floating-point values are forbidden in canonical records")
    raise ValidationError(f"unsupported canonical value type: {type(value).__name__}")


def record_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(_canonical_value(value))).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> list[str]:
    actual = set(value)
    errors: list[str] = []
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        errors.append(f"{label} missing required keys: {missing}")
    if extra:
        errors.append(f"{label} has unexpected keys: {extra}")
    return errors


def _nonempty_string(value: Any, label: str) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return [f"{label} must be a non-empty string"]
    return []


def _string_list(value: Any, label: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        return [f"{label} must be a{' non-empty' if not allow_empty else ''} array"]
    if any(not isinstance(item, str) or not item.strip() for item in value):
        return [f"{label} must contain only non-empty strings"]
    if len(value) != len(set(value)):
        return [f"{label} must not contain duplicates"]
    return []


def _parse_date(value: Any, label: str) -> tuple[dt.date | None, list[str]]:
    if not isinstance(value, str) or not DATE_RE.fullmatch(value):
        return None, [f"{label} must be an ISO date"]
    try:
        return dt.date.fromisoformat(value), []
    except ValueError:
        return None, [f"{label} must be a valid ISO date"]


def _walk_plain_path(root: Path, relative: str, label: str) -> Path:
    if not isinstance(relative, str) or not relative.strip():
        raise ValidationError(f"{label} must be a non-empty relative path")
    raw = Path(relative)
    if raw.is_absolute():
        raise ValidationError(f"{label} must be relative: {relative}")
    if raw.as_posix() != relative:
        raise ValidationError(f"{label} must use one canonical POSIX relative path: {relative}")
    if any(part in {"", ".", ".."} for part in raw.parts):
        raise ValidationError(f"{label} contains a path escape or ambiguous component: {relative}")
    lexical_root = root.absolute()
    for component in [*reversed(lexical_root.parents), lexical_root]:
        try:
            mode = component.lstat().st_mode
        except OSError as exc:
            raise ValidationError(f"cannot inspect {label} root component {component}: {exc}") from exc
        if stat.S_ISLNK(mode):
            raise ValidationError(f"{label} root must not traverse a symlink: {component}")
    if not stat.S_ISDIR(lexical_root.lstat().st_mode):
        raise ValidationError(f"{label} root is not a plain directory: {lexical_root}")
    current = lexical_root
    for part in raw.parts:
        current = current / part
        try:
            current.relative_to(lexical_root)
        except ValueError as exc:
            raise ValidationError(f"{label} escapes repository root: {relative}") from exc
        if current.is_symlink():
            raise ValidationError(f"{label} must not traverse a symlink: {current}")
    if not current.exists():
        raise ValidationError(f"{label} is missing: {relative}")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise ValidationError(f"{label} is not a regular file: {relative}")
    return current


def safe_repo_file(root: Path, relative: str, label: str) -> Path:
    return _walk_plain_path(root, relative, label)


def discover_plain_tree_files(root: Path, relative: str, label: str) -> list[str]:
    """Inventory every regular file under a lexical, symlink-free repository tree."""
    raw = Path(relative)
    if raw.is_absolute() or raw.as_posix() != relative or any(
        part in {"", ".", ".."} for part in raw.parts
    ):
        raise ValidationError(f"{label} must be one canonical relative tree path: {relative}")
    lexical_root = root.absolute()
    directory = lexical_root / raw
    for component in [*reversed(lexical_root.parents), lexical_root]:
        try:
            mode = component.lstat().st_mode
        except OSError as exc:
            raise ValidationError(f"cannot inspect {label} root component {component}: {exc}") from exc
        if stat.S_ISLNK(mode):
            raise ValidationError(f"{label} root must not traverse a symlink: {component}")
    current = lexical_root
    for part in raw.parts:
        current = current / part
        if current.is_symlink():
            raise ValidationError(f"{label} must not traverse a symlink: {current}")
    if not directory.exists() or not stat.S_ISDIR(directory.lstat().st_mode):
        raise ValidationError(f"{label} is missing or not a directory: {relative}")
    discovered: list[str] = []
    for walking_root, directory_names, file_names in os.walk(directory, followlinks=False):
        walking = Path(walking_root)
        for name in list(directory_names):
            candidate = walking / name
            if candidate.is_symlink():
                raise ValidationError(f"{label} contains a symlinked directory: {candidate}")
        for name in file_names:
            candidate = walking / name
            relative_candidate = candidate.relative_to(lexical_root).as_posix()
            safe_repo_file(root, relative_candidate, label)
            discovered.append(relative_candidate)
    if not discovered:
        raise ValidationError(f"{label} contains no regular files: {relative}")
    return sorted(discovered)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot parse JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"JSON root must be an object: {path}")
    return value


def load_toml(path: Path) -> dict[str, Any]:
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError(f"cannot parse TOML {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"TOML root must be a table: {path}")
    return value


def validate_json_schema_instance(
    instance: Any,
    schema: dict[str, Any],
    *,
    root_schema: dict[str, Any] | None = None,
    label: str = "$",
) -> list[str]:
    """Validate the deliberately small JSON-Schema subset used by this control.

    Keeping this evaluator local avoids a mutable PyPI dependency in the audit
    gate. Unsupported validation keywords fail closed instead of being ignored.
    Annotation-only keywords are explicitly allowlisted.
    """
    root_schema = schema if root_schema is None else root_schema
    errors: list[str] = []
    annotation_keywords = {"$schema", "$id", "title", "description", "$defs"}
    supported_keywords = {
        "$ref",
        "type",
        "additionalProperties",
        "required",
        "properties",
        "const",
        "enum",
        "pattern",
        "minLength",
        "format",
        "minItems",
        "maxItems",
        "uniqueItems",
        "items",
        "minimum",
        "oneOf",
        "allOf",
        "if",
        "then",
    }
    unsupported = set(schema) - annotation_keywords - supported_keywords
    if unsupported:
        return [f"{label}: schema uses unsupported validation keywords: {sorted(unsupported)}"]
    if "$ref" in schema:
        reference = schema["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/"):
            return [f"{label}: only local JSON Schema references are permitted"]
        target: Any = root_schema
        try:
            for raw_part in reference[2:].split("/"):
                part = raw_part.replace("~1", "/").replace("~0", "~")
                target = target[part]
        except (KeyError, TypeError) as exc:
            return [f"{label}: unresolved JSON Schema reference {reference}: {exc}"]
        if not isinstance(target, dict):
            return [f"{label}: JSON Schema reference {reference} is not an object"]
        errors.extend(
            validate_json_schema_instance(
                instance, target, root_schema=root_schema, label=label
            )
        )
    if "type" in schema:
        expected_type = schema["type"]
        predicates = {
            "object": lambda value: isinstance(value, dict),
            "array": lambda value: isinstance(value, list),
            "string": lambda value: isinstance(value, str),
            "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
            "boolean": lambda value: isinstance(value, bool),
        }
        predicate = predicates.get(expected_type)
        if predicate is None:
            errors.append(f"{label}: schema has unsupported type {expected_type!r}")
        elif not predicate(instance):
            return errors + [f"{label}: expected JSON Schema type {expected_type}"]
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{label}: does not equal required constant")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{label}: value is outside allowed enum")
    if "pattern" in schema:
        if not isinstance(instance, str) or re.search(schema["pattern"], instance) is None:
            errors.append(f"{label}: string does not match required pattern")
    if "minLength" in schema:
        if not isinstance(instance, str) or len(instance) < schema["minLength"]:
            errors.append(f"{label}: string is shorter than minLength")
    if schema.get("format") == "date":
        _, date_errors = _parse_date(instance, label)
        errors.extend(date_errors)
    elif "format" in schema:
        errors.append(f"{label}: schema has unsupported format {schema['format']!r}")
    if isinstance(instance, dict):
        required = schema.get("required", [])
        if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
            errors.append(f"{label}: schema required must be an array of strings")
        else:
            missing = sorted(set(required) - set(instance))
            if missing:
                errors.append(f"{label}: missing JSON Schema required properties: {missing}")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            errors.append(f"{label}: schema properties must be an object")
            properties = {}
        if schema.get("additionalProperties") is False:
            extra = sorted(set(instance) - set(properties))
            if extra:
                errors.append(f"{label}: JSON Schema rejects additional properties: {extra}")
        for key in sorted(set(instance) & set(properties)):
            child_schema = properties[key]
            if not isinstance(child_schema, dict):
                errors.append(f"{label}.{key}: property schema must be an object")
            else:
                errors.extend(
                    validate_json_schema_instance(
                        instance[key],
                        child_schema,
                        root_schema=root_schema,
                        label=f"{label}.{key}",
                    )
                )
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{label}: has fewer than minItems")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{label}: has more than maxItems")
        if schema.get("uniqueItems") is True:
            fingerprints = [record_sha256(item) for item in instance]
            if len(fingerprints) != len(set(fingerprints)):
                errors.append(f"{label}: violates uniqueItems")
        item_schema = schema.get("items")
        if item_schema is not None:
            if not isinstance(item_schema, dict):
                errors.append(f"{label}: items schema must be an object")
            else:
                for index, item in enumerate(instance):
                    errors.extend(
                        validate_json_schema_instance(
                            item,
                            item_schema,
                            root_schema=root_schema,
                            label=f"{label}[{index}]",
                        )
                    )
    if "minimum" in schema:
        if not isinstance(instance, int) or isinstance(instance, bool) or instance < schema["minimum"]:
            errors.append(f"{label}: value is below minimum")
    if "oneOf" in schema:
        options = schema["oneOf"]
        if not isinstance(options, list) or not options:
            errors.append(f"{label}: schema oneOf must be a non-empty array")
        elif any(not isinstance(option, dict) for option in options):
            errors.append(f"{label}: every oneOf branch must be an object")
        else:
            matches = sum(
                not validate_json_schema_instance(
                    instance, option, root_schema=root_schema, label=label
                )
                for option in options
            )
            if matches != 1:
                errors.append(f"{label}: must match exactly one oneOf branch")
    if "allOf" in schema:
        options = schema["allOf"]
        if not isinstance(options, list):
            errors.append(f"{label}: schema allOf must be an array")
        else:
            for option in options:
                if not isinstance(option, dict):
                    errors.append(f"{label}: allOf branch must be an object")
                else:
                    errors.extend(
                        validate_json_schema_instance(
                            instance, option, root_schema=root_schema, label=label
                        )
                    )
    if "if" in schema:
        condition = schema["if"]
        consequent = schema.get("then")
        if not isinstance(condition, dict) or not isinstance(consequent, dict):
            errors.append(f"{label}: schema if requires an object then branch")
        elif not validate_json_schema_instance(
            instance, condition, root_schema=root_schema, label=label
        ):
            errors.extend(
                validate_json_schema_instance(
                    instance, consequent, root_schema=root_schema, label=label
                )
            )
    elif "then" in schema:
        errors.append(f"{label}: schema then appears without if")
    return errors


def validate_policy(policy: dict[str, Any]) -> list[str]:
    errors = _exact_keys(policy, POLICY_TOP_KEYS, "policy")
    if errors:
        return errors
    if policy["schema-version"] != 1:
        errors.append("policy.schema-version must equal 1")
    if policy["matrix-version"] != 1:
        errors.append("policy.matrix-version must equal 1")
    if policy["content-policy"] != "dcrypt-interoperability-matrix-v1":
        errors.append("policy.content-policy is not the reviewed v1 policy")
    if policy["evidence-promotion-enabled"] is not False:
        errors.append(
            "policy.evidence-promotion-enabled must remain false until a future schema "
            "binds separately typed external review and replay evidence"
        )
    as_of, date_errors = _parse_date(policy["as-of"], "policy.as-of")
    errors.extend(date_errors)
    for name, keys in (
        ("expected", EXPECTED_KEYS),
        ("review", REVIEW_KEYS),
        ("disposition", DISPOSITION_KEYS),
        ("published", PUBLISHED_KEYS),
    ):
        if not isinstance(policy[name], dict):
            errors.append(f"policy.{name} must be a table")
        else:
            errors.extend(_exact_keys(policy[name], keys, f"policy.{name}"))
    if not isinstance(policy["inputs"], dict):
        errors.append("policy.inputs must be a table")
    elif set(policy["inputs"]) != set(FIXED_INPUTS):
        errors.append(
            f"policy.inputs keys must be exactly {sorted(FIXED_INPUTS)}, got {sorted(policy['inputs'])}"
        )
    else:
        for key, digest in policy["inputs"].items():
            if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
                errors.append(f"policy.inputs.{key} must be a lowercase SHA-256")
        if policy["inputs"].get("root-lockfile") != EXPECTED_ROOT_LOCK_SHA256:
            errors.append("policy.inputs.root-lockfile drifts from the code-bound production lockfile")
    if isinstance(policy.get("expected"), dict):
        for key, value in policy["expected"].items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                errors.append(f"policy.expected.{key} must be a positive integer")
    review = policy.get("review", {})
    if isinstance(review, dict) and not _exact_keys(review, REVIEW_KEYS, "policy.review"):
        errors.extend(_nonempty_string(review["default-owner"], "policy.review.default-owner"))
        errors.extend(_nonempty_string(review["default-reviewer"], "policy.review.default-reviewer"))
        deadline, deadline_errors = _parse_date(review["default-deadline"], "policy.review.default-deadline")
        expiry, expiry_errors = _parse_date(review["default-expiry"], "policy.review.default-expiry")
        errors.extend(deadline_errors + expiry_errors)
        maximum = review["maximum-validity-days"]
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
            errors.append("policy.review.maximum-validity-days must be a positive integer")
        if as_of and expiry and (expiry - as_of).days > maximum:
            errors.append("policy default expiry exceeds maximum-validity-days")
        if deadline and expiry and deadline > expiry:
            errors.append("policy default deadline must not be after expiry")
    disposition = policy.get("disposition", {})
    if isinstance(disposition, dict) and not _exact_keys(disposition, DISPOSITION_KEYS, "policy.disposition"):
        expected_values = {
            "operation-status": "blocked",
            "data-surface-status": "not-applicable",
            "gap-status": "blocked",
            "placeholder-direction": "bidirectional-required",
            "placeholder-oracle": "unassigned",
            "placeholder-case-id": "required-coverage",
        }
        for key, expected in expected_values.items():
            if disposition[key] != expected:
                errors.append(f"policy.disposition.{key} must equal {expected!r}")
        for key in DISPOSITION_KEYS:
            errors.extend(_nonempty_string(disposition[key], f"policy.disposition.{key}"))
    published = policy.get("published", {})
    if isinstance(published, dict) and not _exact_keys(published, PUBLISHED_KEYS, "policy.published"):
        errors.extend(_string_list(published["packages"], "policy.published.packages", allow_empty=False))
        errors.extend(_string_list(published["manifests"], "policy.published.manifests", allow_empty=False))
        if len(published["packages"]) != 12 or len(published["manifests"]) != 12:
            errors.append("policy must bind exactly 12 published packages and manifests")
        if published["manifests"] != list(EXPECTED_PUBLISHED_MANIFEST_PACKAGES):
            errors.append("policy published manifest paths/order drift from the code-bound baseline")
        if published["packages"] != list(EXPECTED_PUBLISHED_MANIFEST_PACKAGES.values()):
            errors.append("policy published package names/order drift from the code-bound baseline")
        manifest_hashes = published["manifest-record-sha256"]
        if not isinstance(manifest_hashes, dict):
            errors.append("policy.published.manifest-record-sha256 must be a table")
        else:
            if set(manifest_hashes) != set(EXPECTED_PUBLISHED_MANIFEST_RECORD_SHA256):
                errors.append("policy published manifest record hash paths drift from the code-bound baseline")
            for path, digest in manifest_hashes.items():
                if not isinstance(digest, str) or not HEX64_RE.fullmatch(digest):
                    errors.append(
                        f"policy.published.manifest-record-sha256[{path!r}] must be a lowercase SHA-256"
                    )
            if manifest_hashes != EXPECTED_PUBLISHED_MANIFEST_RECORD_SHA256:
                errors.append("policy published manifest record hashes drift from the code-bound baseline")
    families = policy.get("required-family")
    if not isinstance(families, list) or not families:
        errors.append("policy.required-family must be a non-empty array of tables")
    else:
        ids: list[str] = []
        observed_mappings: dict[str, tuple[str, tuple[str, ...], bool]] = {}
        for index, family in enumerate(families):
            label = f"policy.required-family[{index}]"
            if not isinstance(family, dict):
                errors.append(f"{label} must be a table")
                continue
            errors.extend(_exact_keys(family, FAMILY_KEYS, label))
            if set(family) == FAMILY_KEYS:
                errors.extend(_nonempty_string(family["id"], f"{label}.id"))
                errors.extend(_nonempty_string(family["scope"], f"{label}.scope"))
                errors.extend(_nonempty_string(family["mapping-kind"], f"{label}.mapping-kind"))
                errors.extend(_nonempty_string(family["disposition"], f"{label}.disposition"))
                errors.extend(_string_list(family["atomic-selectors"], f"{label}.atomic-selectors"))
                if not isinstance(family["preservation"], bool):
                    errors.append(f"{label}.preservation must be boolean")
                if family["mapping-kind"] not in {"public-atomic-selector", "private-disposition"}:
                    errors.append(f"{label}.mapping-kind is invalid")
                if family["mapping-kind"] == "public-atomic-selector" and not family["atomic-selectors"]:
                    errors.append(f"{label} public mapping requires atomic selectors")
                if family["mapping-kind"] == "private-disposition" and family["atomic-selectors"]:
                    errors.append(f"{label} private disposition must not claim public atomic selectors")
                ids.append(family["id"])
                observed_mappings[family["id"]] = (
                    family["mapping-kind"],
                    tuple(sorted(family["atomic-selectors"])),
                    family["preservation"],
                )
        if len(ids) != len(set(ids)):
            errors.append("policy.required-family ids must be unique")
        expected_mappings = {
            key: (kind, tuple(sorted(selectors)), preservation)
            for key, (kind, selectors, preservation) in MANDATORY_FAMILY_SELECTORS.items()
        }
        if observed_mappings != expected_mappings:
            missing = sorted(set(expected_mappings) - set(observed_mappings))
            extra = sorted(set(observed_mappings) - set(expected_mappings))
            altered = sorted(
                key
                for key in set(expected_mappings) & set(observed_mappings)
                if expected_mappings[key] != observed_mappings[key]
            )
            errors.append(
                "mandatory interoperability family mapping mismatch: "
                f"missing={missing}, extra={extra}, altered={altered}"
            )
    return errors


def _lock_package_index(lock: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ValidationError("verification lockfile lacks package records")
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise ValidationError("verification lockfile package must be a table")
        key = (str(package.get("name", "")), str(package.get("version", "")))
        if key in result:
            raise ValidationError(f"duplicate verification lockfile package: {key}")
        result[key] = package
    return result


def _verification_dependency_index(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = manifest.get("dev-dependencies")
    if not isinstance(raw, dict):
        raise ValidationError("verification manifest must have a dev-dependencies table")
    result: dict[str, dict[str, Any]] = {}
    for alias, value in raw.items():
        if isinstance(value, str):
            result[alias] = {"package": alias, "version": value}
        elif isinstance(value, dict):
            item = dict(value)
            item["package"] = item.get("package", alias)
            result[alias] = item
        else:
            raise ValidationError(f"verification dependency {alias} has invalid form")
    return result


def _command_network_errors(command: str, label: str) -> list[str]:
    errors: list[str] = []
    lowered = command.lower()
    forbidden = ("curl ", "wget ", "git clone", "cargo fetch", "http://", "https://", "ftp://")
    if any(token in lowered for token in forbidden):
        errors.append(f"{label} permits or requests network access")
    if lowered.strip().startswith("cargo ") and "--offline" not in lowered:
        errors.append(f"{label} cargo command must include --offline")
    if "pip install" in lowered and "--no-index" not in lowered:
        errors.append(f"{label} pip command must include --no-index")
    return errors


def validate_dossiers(
    dossier_document: dict[str, Any],
    *,
    policy: dict[str, Any],
    verification_manifest: dict[str, Any],
    verification_lock: dict[str, Any],
    root: Path = REPO_ROOT,
    validation_date: dt.date | None = None,
) -> list[str]:
    errors = _exact_keys(dossier_document, {"schema-version", "oracle"}, "oracle-dossiers")
    if errors:
        return errors
    if dossier_document["schema-version"] != 1:
        errors.append("oracle-dossiers.schema-version must equal 1")
    records = dossier_document["oracle"]
    if not isinstance(records, list) or not records:
        return errors + ["oracle-dossiers.oracle must be a non-empty array"]
    try:
        lock_index = _lock_package_index(verification_lock)
        dependency_index = _verification_dependency_index(verification_manifest)
    except ValidationError as exc:
        return errors + [str(exc)]
    policy_as_of, _ = _parse_date(policy["as-of"], "policy.as-of")
    current_date = validation_date or dt.datetime.now(dt.timezone.utc).date()
    maximum_days = policy["review"]["maximum-validity-days"]
    lock_digest = policy["inputs"]["verification-lockfile"]
    seen: set[str] = set()
    for index, dossier in enumerate(records):
        label = f"oracle[{index}]"
        if not isinstance(dossier, dict):
            errors.append(f"{label} must be a table")
            continue
        key_errors = _exact_keys(dossier, DOSSIER_KEYS, label)
        errors.extend(key_errors)
        if key_errors:
            continue
        for key in DOSSIER_KEYS - DOSSIER_LIST_KEYS:
            errors.extend(_nonempty_string(dossier[key], f"{label}.{key}"))
        for key in DOSSIER_LIST_KEYS:
            errors.extend(_string_list(dossier[key], f"{label}.{key}"))
        for license_digest in dossier["license-file-sha256"]:
            if re.fullmatch(r"[^:/\\]+:[0-9a-f]{64}", license_digest) is None:
                errors.append(
                    f"{label}.license-file-sha256 entries must be filename:lowercase-sha256"
                )
        oracle_id = dossier["id"]
        if not ID_RE.fullmatch(oracle_id):
            errors.append(f"{label}.id must use lowercase stable identifier syntax")
        if oracle_id in seen:
            errors.append(f"duplicate oracle dossier id: {oracle_id}")
        seen.add(oracle_id)
        if dossier["status"] not in DOSSIER_STATUSES:
            errors.append(f"{label}.status is not allowed")
        if not VERSION_RE.fullmatch(dossier["version"]):
            errors.append(f"{label}.version must be one exact semantic version without a range")
        if not HEX64_RE.fullmatch(dossier["archive-sha256"]):
            errors.append(f"{label}.archive-sha256 must be a lowercase SHA-256")
        if dossier["network-policy"] != "forbidden":
            errors.append(f"{label}.network-policy must be forbidden")
        errors.extend(_command_network_errors(dossier["offline-replay-command"], f"{label}.offline-replay-command"))
        if dossier["implementation-lineage"] not in LINEAGE_STATUSES:
            errors.append(f"{label}.implementation-lineage is not allowed")
        if dossier["provenance-status"] not in {"incomplete", "complete"}:
            errors.append(f"{label}.provenance-status is not allowed")
        if dossier["independence-review-status"] not in {"required", "complete"}:
            errors.append(f"{label}.independence-review-status is not allowed")
        deadline, deadline_errors = _parse_date(dossier["deadline"], f"{label}.deadline")
        expiry, expiry_errors = _parse_date(dossier["expiry"], f"{label}.expiry")
        errors.extend(deadline_errors + expiry_errors)
        if deadline and expiry and deadline > expiry:
            errors.append(f"{label}.deadline must not be after expiry")
        if expiry:
            if expiry < current_date:
                errors.append(f"{label}.expiry is stale")
            if policy_as_of and (expiry - policy_as_of).days > maximum_days:
                errors.append(f"{label}.expiry exceeds maximum-validity-days")
        if dossier["lockfile"] != "verification/Cargo.lock":
            errors.append(f"{label}.lockfile must bind verification/Cargo.lock")
        if dossier["lockfile-sha256"] != lock_digest:
            errors.append(f"{label}.lockfile-sha256 drifts from the pinned verification lockfile")
        matching_aliases = [
            alias
            for alias, dependency in dependency_index.items()
            if dependency["package"] == dossier["package"] and dependency.get("version") == f"={dossier['version']}"
        ]
        if dossier["dependency-role"] not in {"direct", "transitive"}:
            errors.append(f"{label}.dependency-role must be direct or transitive")
        elif dossier["dependency-role"] == "direct" and not matching_aliases:
            errors.append(f"{label} direct package/version is not exactly pinned in verification/Cargo.toml")
        elif dossier["dependency-role"] == "transitive":
            if matching_aliases:
                errors.append(f"{label} transitive dependency is unexpectedly direct")
            dependency_names = {
                str(dependency).split(" ", 1)[0]
                for package_record in lock_index.values()
                for dependency in package_record.get("dependencies", [])
            }
            if dossier["package"] not in dependency_names:
                errors.append(f"{label} transitive package is not referenced by the lockfile dependency graph")
        package = lock_index.get((dossier["package"], dossier["version"]))
        if package is None:
            errors.append(f"{label} package/version is absent from verification/Cargo.lock")
        else:
            if package.get("checksum") != dossier["archive-sha256"]:
                errors.append(f"{label}.archive-sha256 drifts from verification/Cargo.lock")
            if package.get("source") != dossier["source-url"]:
                errors.append(f"{label}.source-url drifts from verification/Cargo.lock")
        for test_path in dossier["tests"]:
            try:
                safe_repo_file(root, test_path, f"{label}.tests")
            except ValidationError as exc:
                errors.append(str(exc))
        if dossier["offline-artifact-path"] != "not-provisioned":
            errors.append(f"{label}.offline-artifact-path must remain not-provisioned in schema v1")
        if dossier["offline-artifact-sha256"] != "not-provisioned":
            errors.append(f"{label}.offline-artifact-sha256 must remain not-provisioned in schema v1")
        if not dossier["offline-replay-command"].startswith("blocked:"):
            errors.append(f"{label}.offline-replay-command cannot authorize execution in schema v1")
        if dossier["status"] == "rejected-as-independent":
            if dossier["implementation-lineage"] in {"unknown", "independent"}:
                errors.append(f"rejected {label} must name its shared lineage class")
            if dossier["independence-review-status"] != "complete":
                errors.append(f"rejected {label} must bind a completed lineage review")
            if dossier["review-date"] == "not-reviewed":
                errors.append(f"rejected {label} must bind the lineage review date")
            if "pending" in dossier["reviewer"].lower():
                errors.append(f"rejected {label} must identify the lineage reviewer")
    return errors


def _dependency_tables(manifest: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(key)
        if isinstance(table, dict):
            yield key, table
    target = manifest.get("target")
    if isinstance(target, dict):
        for target_table in target.values():
            if not isinstance(target_table, dict):
                continue
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target_table.get(key)
                if isinstance(table, dict):
                    yield f"target.{key}", table


def _lock_dependency_target(
    dependency: str,
    *,
    packages_by_name: dict[str, list[tuple[str, str]]],
) -> tuple[str, str] | None:
    parts = dependency.split()
    if not parts:
        return None
    name = parts[0]
    candidates = packages_by_name.get(name, [])
    if len(parts) >= 2 and VERSION_RE.fullmatch(parts[1]):
        exact = [item for item in candidates if item[1] == parts[1]]
        if len(exact) != 1:
            raise ValidationError(f"lockfile dependency {dependency!r} is ambiguous or missing")
        return exact[0]
    if len(candidates) != 1:
        raise ValidationError(f"lockfile dependency {dependency!r} lacks a unique version")
    return candidates[0]


def verification_external_closure(lock: dict[str, Any]) -> list[dict[str, str]]:
    """Recompute the complete external closure reachable from dcrypt-verification."""
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ValidationError("verification lockfile package list is missing")
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    by_name: dict[str, list[tuple[str, str]]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise ValidationError("verification lockfile package entry must be a table")
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValidationError("verification lockfile package lacks name/version")
        key = (name, version)
        if key in indexed:
            raise ValidationError(f"duplicate verification lock package: {name}@{version}")
        indexed[key] = package
        by_name.setdefault(name, []).append(key)
    roots = by_name.get("dcrypt-verification", [])
    if len(roots) != 1:
        raise ValidationError("verification lockfile must contain exactly one dcrypt-verification root")
    pending = [roots[0]]
    seen: set[tuple[str, str]] = set()
    while pending:
        key = pending.pop()
        if key in seen:
            continue
        seen.add(key)
        package = indexed[key]
        for dependency in package.get("dependencies", []):
            if not isinstance(dependency, str):
                raise ValidationError(f"lock dependency for {key} is not a string")
            target = _lock_dependency_target(dependency, packages_by_name=by_name)
            if target is not None and target not in seen:
                pending.append(target)
    result = []
    for key in sorted(seen):
        package = indexed[key]
        source = package.get("source")
        if source is None:
            continue
        checksum = package.get("checksum")
        if not isinstance(source, str) or not isinstance(checksum, str) or not HEX64_RE.fullmatch(checksum):
            raise ValidationError(f"external verification closure package lacks immutable source/checksum: {key}")
        result.append(
            {"name": key[0], "version": key[1], "source": source, "checksum": checksum}
        )
    return result


def validate_isolation(
    *,
    policy: dict[str, Any],
    boundary: dict[str, Any],
    root_manifest: dict[str, Any],
    verification_manifest: dict[str, Any],
    verification_lock: dict[str, Any],
    dossiers: dict[str, Any],
    root: Path = REPO_ROOT,
    published_manifest_documents: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    errors: list[str] = []
    expected_packages = policy["published"]["packages"]
    expected_manifests = policy["published"]["manifests"]
    expected_record_hashes = policy["published"]["manifest-record-sha256"]
    if expected_manifests != list(EXPECTED_PUBLISHED_MANIFEST_PACKAGES):
        errors.append("published manifest paths/order drift from the code-bound twelve-manifest baseline")
    if expected_packages != list(EXPECTED_PUBLISHED_MANIFEST_PACKAGES.values()):
        errors.append("published package names/order drift from the code-bound twelve-package baseline")
    if expected_record_hashes != EXPECTED_PUBLISHED_MANIFEST_RECORD_SHA256:
        errors.append("published manifest record hashes drift from the code-bound baseline")
    if boundary.get("published-packages") != expected_packages:
        errors.append("published package policy drifts from implementation-boundary.toml")
    workspace = root_manifest.get("workspace")
    if not isinstance(workspace, dict) or "verification" not in workspace.get("exclude", []):
        errors.append("root workspace must explicitly exclude verification")
    verification_workspace = verification_manifest.get("workspace")
    if not isinstance(verification_workspace, dict) or verification_workspace.get("members") != ["."]:
        errors.append("verification workspace must remain isolated with members = ['.']")
    package = verification_manifest.get("package")
    if not isinstance(package, dict) or package.get("publish") is not False:
        errors.append("verification package must remain publish = false")
    try:
        verification_dependencies = _verification_dependency_index(verification_manifest)
    except ValidationError as exc:
        errors.append(str(exc))
        verification_dependencies = {}
    for alias, dependency in sorted(verification_dependencies.items()):
        if "path" in dependency:
            continue
        version = dependency.get("version")
        if not isinstance(version, str) or not version.startswith("=") or not VERSION_RE.fullmatch(version[1:]):
            errors.append(f"verification dependency {alias} must use one exact =version pin")
    try:
        external_closure = verification_external_closure(verification_lock)
    except ValidationError as exc:
        errors.append(str(exc))
        external_closure = []
    external_by_name: dict[str, set[str]] = {}
    for item in external_closure:
        external_by_name.setdefault(item["name"], set()).add(item["version"])
    allowed_closure = boundary.get("allowed-normal-build-packages", [])
    if not isinstance(allowed_closure, list):
        errors.append("implementation-boundary allowed-normal-build-packages must be an array")
        allowed_closure = []
    allowed_baseline: dict[str, str] = {}
    for item in allowed_closure:
        if not isinstance(item, str) or item.count("@") != 1:
            errors.append(f"invalid allowed normal/build package identity: {item!r}")
            continue
        name, version = item.split("@", 1)
        allowed_baseline[name] = version
    if allowed_baseline != {"base64": "0.22.1", "hex": "0.4.3"}:
        errors.append(
            "published external normal/build baseline must remain exactly "
            "base64@0.22.1 and hex@0.4.3"
        )
    verification_only_names = set(external_by_name) - set(allowed_baseline)
    if published_manifest_documents is None:
        published_manifest_documents = {}
        for path in policy["published"]["manifests"]:
            try:
                published_manifest_documents[path] = load_toml(
                    safe_repo_file(root, path, "published manifest")
                )
            except ValidationError as exc:
                errors.append(str(exc))
    if set(published_manifest_documents) != set(EXPECTED_PUBLISHED_MANIFEST_PACKAGES):
        errors.append(
            "published manifest document set must be the exact code-bound twelve paths: "
            f"expected={sorted(EXPECTED_PUBLISHED_MANIFEST_PACKAGES)}, "
            f"got={sorted(published_manifest_documents)}"
        )
    observed_packages: list[str] = []
    observed_shared_nonproduction: set[tuple[str, str, str, str, str]] = set()
    for path, manifest in published_manifest_documents.items():
        package_table = manifest.get("package")
        if not isinstance(package_table, dict) or not isinstance(package_table.get("name"), str):
            errors.append(f"published manifest {path} lacks a package name")
        else:
            observed_packages.append(package_table["name"])
            expected_package = EXPECTED_PUBLISHED_MANIFEST_PACKAGES.get(path)
            if expected_package is None or package_table["name"] != expected_package:
                errors.append(
                    f"published manifest {path} package identity must remain exactly {expected_package!r}"
                )
        expected_record_hash = EXPECTED_PUBLISHED_MANIFEST_RECORD_SHA256.get(path)
        if expected_record_hash is None or record_sha256(manifest) != expected_record_hash:
            errors.append(f"published manifest {path} canonical record drifts from the code-bound baseline")
        for dependency_kind, table in _dependency_tables(manifest):
            for alias, value in table.items():
                if isinstance(value, dict):
                    package_name = value.get("package", alias)
                    is_path = "path" in value
                    version_spec = value.get("version")
                else:
                    package_name = alias
                    is_path = False
                    version_spec = value
                if is_path:
                    continue
                identity = (
                    path,
                    dependency_kind,
                    str(alias),
                    str(package_name),
                    str(version_spec),
                )
                if identity in PUBLISHED_NONPRODUCTION_SHARED_BASELINE:
                    observed_shared_nonproduction.add(identity)
                    continue
                if package_name in verification_only_names:
                    errors.append(
                        f"verification-only closure dependency {package_name} leaked into "
                        f"published manifest {path} ({dependency_kind})"
                    )
                elif package_name in allowed_baseline:
                    expected_version = allowed_baseline[package_name]
                    if dependency_kind.endswith("dev-dependencies"):
                        errors.append(
                            f"published baseline package {package_name} is not permitted in "
                            f"{path} ({dependency_kind}) outside the exact preexisting test baseline"
                        )
                    elif version_spec != f"={expected_version}":
                        errors.append(
                            f"published baseline dependency {package_name} must remain exactly "
                            f"={expected_version} in {path} ({dependency_kind})"
                        )
                elif package_name in external_by_name:
                    errors.append(
                        f"unclassified verification closure dependency {package_name} leaked into "
                        f"published manifest {path} ({dependency_kind})"
                    )
    missing_shared_baseline = PUBLISHED_NONPRODUCTION_SHARED_BASELINE - observed_shared_nonproduction
    if missing_shared_baseline:
        errors.append(
            "preexisting non-production shared dependency declaration baseline drift: "
            f"missing={sorted(missing_shared_baseline)}"
        )
    if sorted(observed_packages) != sorted(expected_packages):
        errors.append(
            "published manifest package set drifts from the exact 12-package policy: "
            f"expected={sorted(expected_packages)}, got={sorted(observed_packages)}"
        )
    return errors


def validate_overrides(
    override_document: dict[str, Any],
    *,
    dossiers: dict[str, Any],
    policy: dict[str, Any],
    root: Path = REPO_ROOT,
) -> list[str]:
    allowed_top = {"schema-version", "override"}
    actual_top = set(override_document)
    errors: list[str] = []
    if "schema-version" not in actual_top:
        errors.append("evidence-overrides missing schema-version")
        return errors
    extra = actual_top - allowed_top
    if extra:
        errors.append(f"evidence-overrides has unexpected keys: {sorted(extra)}")
    if override_document["schema-version"] != 1:
        errors.append("evidence-overrides.schema-version must equal 1")
    overrides = override_document.get("override", [])
    if not isinstance(overrides, list):
        return errors + ["evidence-overrides.override must be an array"]
    if policy.get("evidence-promotion-enabled") is not False:
        errors.append("schema v1 must keep evidence promotion disabled")
    if overrides:
        errors.append(
            "evidence overrides are forbidden while evidence-promotion-enabled=false; "
            "schema v1 has no separately typed, exact-bound external review and replay records"
        )
    return errors


def load_inputs(root: Path = REPO_ROOT) -> dict[str, Any]:
    files: dict[str, Path] = {}
    for key, relative in FIXED_INPUTS.items():
        files[key] = safe_repo_file(root, relative, f"input {key}")
    files["policy"] = safe_repo_file(root, "assurance/interoperability/policy.toml", "policy")
    files["dossiers"] = safe_repo_file(
        root, "assurance/interoperability/oracle-dossiers.toml", "oracle dossiers"
    )
    files["overrides"] = safe_repo_file(
        root, "assurance/interoperability/evidence-overrides.toml", "evidence overrides"
    )
    files["matrix-schema"] = safe_repo_file(
        root, "assurance/interoperability/matrix.schema.json", "matrix schema"
    )
    files["dossier-schema"] = safe_repo_file(
        root, "assurance/interoperability/oracle-dossier.schema.json", "oracle dossier schema"
    )
    files["overrides-schema"] = safe_repo_file(
        root,
        "assurance/interoperability/evidence-overrides.schema.json",
        "evidence overrides schema",
    )
    policy = load_toml(files["policy"])
    errors = validate_policy(policy)
    if errors:
        raise ValidationError("\n".join(errors))
    for key, expected in policy["inputs"].items():
        actual = sha256_path(files[key])
        if actual != expected:
            errors.append(f"input digest drift for {FIXED_INPUTS[key]}: expected {expected}, got {actual}")
    if errors:
        raise ValidationError("\n".join(errors))
    result = {
        "root": root.absolute(),
        "files": files,
        "policy": policy,
        "atomic": load_toml(files["atomic-operations"]),
        "snapshot": load_json(files["public-api-snapshot"]),
        "ledger": load_toml(files["assurance-ledger"]),
        "boundary": load_toml(files["implementation-boundary"]),
        "root_manifest": load_toml(files["root-manifest"]),
        "root_lock": load_toml(files["root-lockfile"]),
        "verification_manifest": load_toml(files["verification-manifest"]),
        "verification_lock": load_toml(files["verification-lockfile"]),
        "dossiers": load_toml(files["dossiers"]),
        "overrides": load_toml(files["overrides"]),
        "matrix_schema": load_json(files["matrix-schema"]),
        "dossier_schema": load_json(files["dossier-schema"]),
        "overrides_schema": load_json(files["overrides-schema"]),
    }
    return result


def standards_scope(operation: dict[str, Any]) -> str:
    support = str(operation.get("support", "")).lower()
    standard = str(operation.get("standard", "")).lower()
    algorithm = str(operation.get("algorithm", "")).lower()
    compatibility_markers = ("compatibility", "deprecated", "legacy")
    if any(marker in standard or marker in algorithm for marker in compatibility_markers):
        return "compatibility"
    if support == "transitional":
        return "transitional"
    project_markers = ("dcrypt ", "caller-owned")
    if any(marker in standard for marker in project_markers):
        return "project-specified"
    return "standardized"


def _profile_platform(profile: str) -> str:
    if not isinstance(profile, str) or "/" not in profile:
        raise ValidationError(f"snapshot profile lacks exact target identity: {profile!r}")
    return profile.split("/", 1)[1]


def _source_graph(inputs: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    atomic = inputs["atomic"]
    snapshot = inputs["snapshot"]
    operations = atomic.get("operation")
    gaps = atomic.get("unreviewed-gap")
    defaults = atomic.get("unreviewed-gap-defaults")
    if atomic.get("schema-version") != 2 or not isinstance(operations, list) or not isinstance(gaps, list) or not isinstance(defaults, dict):
        raise ValidationError("atomic operations input does not match schema version 2")
    entries = snapshot.get("entries")
    if snapshot.get("schema_version") != 2 or not isinstance(entries, list):
        raise ValidationError("public API snapshot does not match schema version 2")
    ids = [item.get("id") for item in operations + gaps if isinstance(item, dict)]
    if len(ids) != len(operations) + len(gaps) or any(not isinstance(item, str) or not item for item in ids):
        raise ValidationError("every atomic operation and gap requires a non-empty id")
    if len(ids) != len(set(ids)):
        raise ValidationError("atomic operation and gap ids must be globally unique")
    links: dict[str, list[dict[str, Any]]] = {item: [] for item in ids}
    unknown_refs: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("operation_refs"), list):
            raise ValidationError("snapshot entry operation_refs must be an array")
        for reference in entry["operation_refs"]:
            if reference not in links:
                unknown_refs.add(str(reference))
            else:
                links[reference].append(entry)
    if unknown_refs:
        raise ValidationError(f"snapshot contains unknown atomic operation refs: {sorted(unknown_refs)[:5]}")
    missing = [key for key, value in links.items() if not value]
    if missing:
        raise ValidationError(f"atomic rows missing from snapshot operation_refs: {missing[:5]}")
    return operations, gaps, links


def validate_source_graph(inputs: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    policy = inputs["policy"]
    expected = policy["expected"]
    try:
        operations, gaps, links = _source_graph(inputs)
    except ValidationError as exc:
        return [str(exc)]
    operation_rows = [item for item in operations if item.get("row-kind") == "operation"]
    data_rows = [item for item in operations if item.get("row-kind") == "data-surface"]
    if len(operation_rows) != expected["curated-operation-rows"]:
        errors.append("curated operation row count drift")
    if len(data_rows) != expected["curated-data-surface-rows"]:
        errors.append("curated data-surface row count drift")
    if len(gaps) != expected["unreviewed-gap-rows"]:
        errors.append("unreviewed gap row count drift")
    operation_atoms = 0
    data_atoms = 0
    for operation in operations:
        linked = links[operation["id"]]
        linked_paths = {entry.get("path") for entry in linked}
        if linked_paths != set(operation.get("public-paths", [])):
            errors.append(f"{operation['id']} public paths drift from snapshot operation refs")
        for entry in linked:
            if entry.get("package") != operation.get("crate"):
                errors.append(f"{operation['id']} crate drifts from snapshot package")
            profiles = entry.get("profiles")
            if not isinstance(profiles, list) or not profiles:
                errors.append(f"{operation['id']} snapshot entry has no profiles")
                continue
            try:
                for profile in profiles:
                    _profile_platform(profile)
            except ValidationError as exc:
                errors.append(str(exc))
            if operation["row-kind"] == "operation":
                operation_atoms += len(profiles)
            else:
                data_atoms += len(profiles)
    if operation_atoms != expected["curated-operation-atoms"]:
        errors.append(f"curated operation atom count drift: {operation_atoms}")
    if data_atoms != expected["curated-data-surface-atoms"]:
        errors.append(f"curated data-surface atom count drift: {data_atoms}")
    if len(inputs["snapshot"].get("entries", [])) != expected["public-api-units"]:
        errors.append("public API unit count drift")
    if len(inputs["snapshot"].get("profiles", [])) != expected["snapshot-profiles"]:
        errors.append("snapshot profile count drift")
    ledger_atomic_path = inputs["ledger"].get("atomic-operations")
    if ledger_atomic_path != "atomic-operations.toml":
        errors.append("ledger atomic-operations path is not the expected assurance-local binding")
    ledger_blockers = sum(
        1 for item in operations if item.get("release-readiness") == "blocked"
    ) + (
        len(gaps)
        if inputs["atomic"].get("unreviewed-gap-defaults", {}).get("release-readiness") == "blocked"
        else 0
    )
    if len(operations) + len(gaps) != expected["ledger-atomic-rows"]:
        errors.append("ledger atomic row count drift")
    if ledger_blockers != expected["ledger-release-blockers"]:
        errors.append("ledger release blocker count drift")
    return errors


def _placeholder_oracle(policy: dict[str, Any]) -> dict[str, Any]:
    disposition = policy["disposition"]
    return {
        "direction": disposition["placeholder-direction"],
        "oracle_id": disposition["placeholder-oracle"],
        "oracle_version": "not-selected",
        "oracle_source_commit": "not-selected",
        "oracle_checksum": "not-selected",
        "oracle_license": "not-selected",
        "oracle_acquisition_provenance": "not-selected",
        "implementation_lineage": "unknown",
        "shared_dependencies": [],
        "case_id": disposition["placeholder-case-id"],
    }


def _matrix_key(
    operation: dict[str, Any],
    entry: dict[str, Any],
    profile: str,
    oracle: dict[str, Any],
) -> dict[str, Any]:
    return {
        "atomic_row_id": operation["id"],
        "crate": operation["crate"],
        "public_path": entry["path"],
        "public_unit": entry["unit"],
        "public_kind": entry["kind"],
        "algorithm": operation["algorithm"],
        "standard": operation["standard"],
        "standards_scope": standards_scope(operation),
        "parameter_set": operation["parameter-set"],
        "operation": operation["operation"],
        "encoding_wire_format": operation["encoding"],
        "mode_profile": operation["mode-profile"],
        "dst_context_prehash": operation["dst-context-prehash"],
        "feature_profile": profile,
        "platform": _profile_platform(profile),
        **oracle,
    }


def _base_row(
    *,
    operation: dict[str, Any],
    entry: dict[str, Any],
    profile: str,
    policy: dict[str, Any],
    data_surface: bool,
) -> dict[str, Any]:
    review = policy["review"]
    disposition = policy["disposition"]
    oracle = _placeholder_oracle(policy)
    if data_surface:
        oracle.update(
            {
                "direction": "not-applicable",
                "oracle_id": "not-applicable",
                "oracle_version": "not-applicable",
                "oracle_source_commit": "not-applicable",
                "oracle_checksum": "not-applicable",
                "oracle_license": "not-applicable",
                "oracle_acquisition_provenance": "not-applicable",
                "implementation_lineage": "not-applicable",
                "case_id": "public-metadata-not-applicable",
            }
        )
    key = _matrix_key(operation, entry, profile, oracle)
    row_kind = "data-surface" if data_surface else "operation"
    status = disposition["data-surface-status"] if data_surface else disposition["operation-status"]
    blocker = "" if data_surface else disposition["operation-blocker"]
    rationale = disposition["data-surface-rationale"] if data_surface else ""
    row = {
        "row_id": "interop." + record_sha256({"row_kind": row_kind, "key": key}),
        "row_kind": row_kind,
        "atomic_record_sha256": record_sha256(operation),
        "key": key,
        "corpus_test_identifiers": [],
        "evidence_sha256": "not-generated",
        "evidence_generated_at": "not-generated",
        "evidence_valid_through": "not-generated",
        "execution_status": "not-executed",
        "independent_replay_status": "not-replayed",
        "freshness_status": "missing",
        "status": status,
        "blocker": blocker,
        "not_applicable_rationale": rationale,
        "owner": review["default-owner"],
        "reviewer": review["default-reviewer"],
        "deadline": review["default-deadline"],
        "expiry": review["default-expiry"],
    }
    return row


def build_matrix(
    inputs: dict[str, Any], *, validation_date: dt.date | None = None
) -> dict[str, Any]:
    current_date = validation_date or dt.datetime.now(dt.timezone.utc).date()
    validation_errors = validate_source_graph(inputs)
    validation_errors += validate_dossiers(
        inputs["dossiers"],
        policy=inputs["policy"],
        verification_manifest=inputs["verification_manifest"],
        verification_lock=inputs["verification_lock"],
        root=inputs["root"],
        validation_date=current_date,
    )
    validation_errors += validate_overrides(
        inputs["overrides"], dossiers=inputs["dossiers"], policy=inputs["policy"], root=inputs["root"]
    )
    validation_errors += validate_isolation(
        policy=inputs["policy"],
        boundary=inputs["boundary"],
        root_manifest=inputs["root_manifest"],
        verification_manifest=inputs["verification_manifest"],
        verification_lock=inputs["verification_lock"],
        dossiers=inputs["dossiers"],
        root=inputs["root"],
    )
    if validation_errors:
        raise ValidationError("\n".join(validation_errors))
    policy = inputs["policy"]
    operations, gaps, links = _source_graph(inputs)
    rows: list[dict[str, Any]] = []
    for operation in sorted(operations, key=lambda item: item["id"]):
        for entry in sorted(links[operation["id"]], key=lambda item: item["path"]):
            for profile in sorted(entry["profiles"]):
                if operation["row-kind"] == "data-surface":
                    rows.append(
                        _base_row(
                            operation=operation,
                            entry=entry,
                            profile=profile,
                            policy=policy,
                            data_surface=True,
                        )
                    )
                else:
                    rows.append(
                        _base_row(
                            operation=operation,
                            entry=entry,
                            profile=profile,
                            policy=policy,
                            data_surface=False,
                        )
                    )
    rows.sort(key=lambda item: item["row_id"])
    if len({item["row_id"] for item in rows}) != len(rows):
        raise ValidationError("generated interoperability row ids are not unique")
    defaults = inputs["atomic"]["unreviewed-gap-defaults"]
    gap_items: list[dict[str, Any]] = []
    review = policy["review"]
    disposition = policy["disposition"]
    for gap in sorted(gaps, key=lambda item: item["id"]):
        effective = copy.deepcopy(defaults)
        effective.update(gap)
        binding_records = [
            list(item)
            for item in sorted(
                {
                    (entry["package"], entry["path"], profile)
                    for entry in links[gap["id"]]
                    for profile in entry["profiles"]
                }
            )
        ]
        gap_items.append(
            {
                "atomic_row_id": gap["id"],
                "row_kind": gap.get("row-kind", "operation"),
                "raw_record_sha256": record_sha256(gap),
                "effective_record_sha256": record_sha256(effective),
                "public_bindings_sha256": record_sha256(binding_records),
                "public_entry_count": len(links[gap["id"]]),
                "profile_atom_count": len(binding_records),
                "status": disposition["gap-status"],
                "blocker": disposition["gap-blocker"],
                "owner": review["default-owner"],
                "reviewer": review["default-reviewer"],
                "deadline": review["default-deadline"],
                "expiry": review["default-expiry"],
            }
        )
    dossier_test_paths = {
        path for dossier in inputs["dossiers"]["oracle"] for path in dossier["tests"]
    }
    preservation_tree_paths = {
        path
        for tree in PRESERVATION_TREES
        for path in discover_plain_tree_files(inputs["root"], tree, "verification preservation tree")
    }
    control_paths = sorted(
        set(FIXED_INPUTS.values())
        | set(GENERATED_CONTROL_INPUTS)
        | set(PRESERVATION_FILES)
        | preservation_tree_paths
        | set(policy["published"]["manifests"])
        | dossier_test_paths
    )
    generated_inputs = []
    for relative in control_paths:
        path = safe_repo_file(inputs["root"], relative, "generated input")
        generated_inputs.append({"path": relative, "sha256": sha256_path(path)})
    dossier_summaries = [
        {
            "id": item["id"],
            "record_sha256": record_sha256(item),
            "status": item["status"],
            "provenance_status": item["provenance-status"],
            "implementation_lineage": item["implementation-lineage"],
            "independence_review_status": item["independence-review-status"],
            "owner": item["owner"],
            "reviewer": item["reviewer"],
            "deadline": item["deadline"],
            "expiry": item["expiry"],
        }
        for item in sorted(inputs["dossiers"]["oracle"], key=lambda item: item["id"])
    ]
    verification_closure = verification_external_closure(inputs["verification_lock"])
    operation_ids_by_selector: dict[str, list[str]] = {}
    for operation in operations:
        selector = f"{operation['algorithm']}|{operation['parameter-set']}"
        operation_ids_by_selector.setdefault(selector, []).append(operation["id"])
    family_summaries: list[dict[str, Any]] = []
    for family in sorted(policy["required-family"], key=lambda item: item["id"]):
        matched_ids = sorted(
            {
                atomic_id
                for selector in family["atomic-selectors"]
                for atomic_id in operation_ids_by_selector.get(selector, [])
            }
        )
        missing_selectors = sorted(
            selector for selector in family["atomic-selectors"] if selector not in operation_ids_by_selector
        )
        if missing_selectors:
            raise ValidationError(
                f"mandatory family {family['id']} selectors match no curated atomic rows: {missing_selectors}"
            )
        if family["mapping-kind"] == "public-atomic-selector" and not matched_ids:
            raise ValidationError(f"mandatory public family {family['id']} has no curated atomic row mapping")
        if family["mapping-kind"] == "private-disposition" and matched_ids:
            raise ValidationError(f"private family {family['id']} unexpectedly maps public atomic rows")
        family_summaries.append(
            {
                "id": family["id"],
                "scope": family["scope"],
                "mapping_kind": family["mapping-kind"],
                "atomic_selectors": sorted(family["atomic-selectors"]),
                "matched_atomic_row_count": len(matched_ids),
                "matched_atomic_row_ids_sha256": record_sha256(matched_ids),
                "preservation": family["preservation"],
                "disposition": family["disposition"],
                "owner": review["default-owner"],
                "reviewer": review["default-reviewer"],
                "deadline": review["default-deadline"],
                "expiry": review["default-expiry"],
            }
        )
    operation_rows = [item for item in rows if item["row_kind"] == "operation"]
    data_rows = [item for item in rows if item["row_kind"] == "data-surface"]
    passing_atoms = {
        (
            item["key"]["atomic_row_id"],
            item["key"]["public_path"],
            item["key"]["feature_profile"],
            item["key"]["platform"],
        )
        for item in operation_rows
        if item["status"] == "pass"
    }
    blocked_atoms = {
        (
            item["key"]["atomic_row_id"],
            item["key"]["public_path"],
            item["key"]["feature_profile"],
            item["key"]["platform"],
        )
        for item in operation_rows
        if item["status"] == "blocked"
    }
    counts = {
        "curated_operation_rows": sum(1 for item in operations if item["row-kind"] == "operation"),
        "curated_operation_atoms": policy["expected"]["curated-operation-atoms"],
        "curated_data_surface_rows": sum(1 for item in operations if item["row-kind"] == "data-surface"),
        "curated_data_surface_atoms": len(data_rows),
        "unreviewed_gap_rows": len(gap_items),
        "generated_matrix_rows": len(rows),
        "passing_operation_atoms": len(passing_atoms),
        "blocked_operation_atoms": len(blocked_atoms),
        "not_applicable_data_surface_atoms": len(data_rows),
        "blocked_unreviewed_gaps": sum(1 for item in gap_items if item["status"] == "blocked"),
        "interoperability_blockers": len(blocked_atoms)
        + sum(1 for item in gap_items if item["status"] == "blocked"),
        "ledger_atomic_release_blockers": policy["expected"]["ledger-release-blockers"],
        "accepted_oracle_dossiers": sum(1 for item in dossier_summaries if item["status"] == "accepted"),
        "candidate_oracle_dossiers": sum(1 for item in dossier_summaries if item["status"] == "candidate"),
        "rejected_as_independent_oracle_dossiers": sum(
            1 for item in dossier_summaries if item["status"] == "rejected-as-independent"
        ),
    }
    return {
        "schema_version": policy["matrix-version"],
        "content_policy": policy["content-policy"],
        "canonicalization": {
            "encoding": "UTF-8",
            "key_order": "Unicode-code-point-ascending",
            "separators": "comma-colon-no-whitespace",
            "final_newline": True,
            "floats": "forbidden",
            "duplicate_keys": "forbidden",
        },
        "source_binding": {
            "snapshot_source_commit": inputs["snapshot"]["source_commit"],
            "snapshot_source_tree": inputs["snapshot"]["source_tree"],
            "ledger_source_commit": inputs["ledger"]["source-commit"],
            "ledger_source_tree": inputs["ledger"]["source-tree"],
            "atomic_operations_sha256": policy["inputs"]["atomic-operations"],
            "public_api_snapshot_sha256": policy["inputs"]["public-api-snapshot"],
            "assurance_ledger_sha256": policy["inputs"]["assurance-ledger"],
        },
        "generated_inputs": generated_inputs,
        "required_families": family_summaries,
        "oracle_dossiers": dossier_summaries,
        "verification_external_closure": {
            "root_package": "dcrypt-verification@0.0.0",
            "packages": verification_closure,
            "package_count": len(verification_closure),
            "set_sha256": record_sha256(verification_closure),
            "published_baseline_exceptions": ["base64@0.22.1", "hex@0.4.3"],
            "promotion_enabled": False,
        },
        "counts": counts,
        "release_gate": {
            "status": "blocked" if counts["interoperability_blockers"] else "pass",
            "evidence_promotion_enabled": False,
            "structural_ci_may_pass_with_blockers": True,
            "release_mode_must_fail_with_blockers": True,
            "no_scaffold_or_candidate_counts_as_evidence": True,
            "counting_semantics": "6,184 exact curated operation public-path/profile/platform atoms plus 8,632 individually digest-bound unreviewed gaps; 56 public metadata atoms are explicit N/A and do not pass evidence",
        },
        "rows": rows,
        "unreviewed_gaps": {
            "defaults_sha256": record_sha256(defaults),
            "set_sha256": record_sha256(gap_items),
            "items": gap_items,
        },
    }


def render_document(matrix: dict[str, Any]) -> bytes:
    counts = matrix["counts"]
    scope_counts: dict[str, int] = {}
    algorithm_counts: dict[str, int] = {}
    for row in matrix["rows"]:
        if row["row_kind"] != "operation":
            continue
        scope = row["key"]["standards_scope"]
        algorithm = row["key"]["algorithm"]
        scope_counts[scope] = scope_counts.get(scope, 0) + 1
        algorithm_counts[algorithm] = algorithm_counts.get(algorithm, 0) + 1
    lines = [
        "# dcrypt Interoperability Completeness Matrix",
        "",
        "Status: **candidate framework; all executable interoperability atoms remain blocked**.",
        "",
        "This document is generated from `matrix.json`. Candidate oracle dossiers, existing",
        "test harnesses, and generated matrix bytes are not passing assurance evidence.",
        "Evidence promotion is disabled in schema v1: dossiers cannot be accepted, override",
        "records must be empty, and no matrix operation row can have passing status.",
        "",
        "## Counts",
        "",
        f"- Curated operation rows: {counts['curated_operation_rows']}",
        f"- Exact operation path/profile/platform atoms: {counts['curated_operation_atoms']}",
        f"- Blocked operation atoms: {counts['blocked_operation_atoms']}",
        f"- Passing operation atoms: {counts['passing_operation_atoms']}",
        f"- Curated data-surface rows: {counts['curated_data_surface_rows']}",
        f"- Explicit N/A data-surface atoms: {counts['not_applicable_data_surface_atoms']}",
        f"- Individually digest-bound blocked unreviewed gaps: {counts['blocked_unreviewed_gaps']}",
        f"- Interoperability blocker atoms: {counts['interoperability_blockers']}",
        f"- Existing assurance-ledger atomic blockers (unchanged): {counts['ledger_atomic_release_blockers']}",
        f"- Accepted oracle dossiers: {counts['accepted_oracle_dossiers']}",
        f"- Candidate oracle dossiers: {counts['candidate_oracle_dossiers']}",
        f"- Rejected-as-independent oracle dossiers: {counts['rejected_as_independent_oracle_dossiers']}",
        "",
        "The interoperability blocker count is a separate completeness dimension. It must",
        "not be added to or substituted for the 9,198 atomic assurance-ledger blockers.",
        "",
        "## Standards-scope atoms",
        "",
    ]
    for name, count in sorted(scope_counts.items()):
        lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## Algorithm atoms", ""])
    for name, count in sorted(algorithm_counts.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"- `{name}`: {count}")
    lines.extend(
        [
            "",
            "## Gate semantics",
            "",
            "CI mode validates deterministic bytes, exact source correspondence, all closed",
            "records, candidate provenance, isolation, and fail-closed blockers. Release mode",
            "must fail while any operation atom or unreviewed gap is blocked. The 56 public",
            "metadata atoms are explicitly N/A because they have no executable direction;",
            "their bytes and aliases remain bound by the assurance ledger.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def validate_matrix(matrix: dict[str, Any], expected: dict[str, Any], *, as_of: dt.date) -> list[str]:
    errors = _exact_keys(matrix, MATRIX_TOP_KEYS, "matrix")
    if errors:
        return errors
    if matrix.get("schema_version") != 1 or matrix.get("content_policy") != "dcrypt-interoperability-matrix-v1":
        errors.append("matrix schema/content policy mismatch")
    closure = matrix.get("verification_external_closure")
    if isinstance(closure, dict):
        packages = closure.get("packages")
        if not isinstance(packages, list):
            errors.append("matrix verification external closure packages must be an array")
        else:
            if closure.get("package_count") != len(packages):
                errors.append("matrix verification external closure package count mismatch")
            if closure.get("set_sha256") != record_sha256(packages):
                errors.append("matrix verification external closure digest mismatch")
        if closure.get("promotion_enabled") is not False:
            errors.append("matrix evidence promotion must remain disabled")
    rows = matrix.get("rows")
    if not isinstance(rows, list):
        return errors + ["matrix.rows must be an array"]
    ids: set[str] = set()
    for index, row in enumerate(rows):
        label = f"matrix.rows[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{label} must be an object")
            continue
        key_errors = _exact_keys(row, MATRIX_ROW_KEYS, label)
        errors.extend(key_errors)
        if key_errors:
            continue
        if not isinstance(row["key"], dict):
            errors.append(f"{label}.key must be an object")
            continue
        errors.extend(_exact_keys(row["key"], MATRIX_KEY_KEYS, f"{label}.key"))
        expected_id = "interop." + record_sha256({"row_kind": row["row_kind"], "key": row["key"]})
        if row["row_id"] != expected_id:
            errors.append(f"{label}.row_id does not bind the exact canonical key")
        if row["row_id"] in ids:
            errors.append(f"duplicate matrix row id: {row['row_id']}")
        ids.add(row["row_id"])
        if row["status"] not in {"blocked", "not-applicable"}:
            errors.append(f"{label}.status is invalid")
        if row["status"] == "blocked":
            if not row["blocker"]:
                errors.append(f"{label} blocked row lacks blocker")
        else:
            if row["row_kind"] != "data-surface" or not row["not_applicable_rationale"]:
                errors.append(f"{label} N/A is permitted only for justified data surfaces")
        for field in ("owner", "reviewer"):
            errors.extend(_nonempty_string(row[field], f"{label}.{field}"))
        _, deadline_errors = _parse_date(row["deadline"], f"{label}.deadline")
        expiry, expiry_errors = _parse_date(row["expiry"], f"{label}.expiry")
        errors.extend(deadline_errors + expiry_errors)
        if expiry and expiry < as_of:
            errors.append(f"{label}.expiry is stale")
    gaps = matrix.get("unreviewed_gaps")
    if not isinstance(gaps, dict) or set(gaps) != {"defaults_sha256", "set_sha256", "items"}:
        errors.append("matrix.unreviewed_gaps must be a closed object")
    else:
        items = gaps["items"]
        if not isinstance(items, list):
            errors.append("matrix.unreviewed_gaps.items must be an array")
        else:
            gap_ids: set[str] = set()
            for index, item in enumerate(items):
                label = f"matrix.unreviewed_gaps.items[{index}]"
                if not isinstance(item, dict):
                    errors.append(f"{label} must be an object")
                    continue
                errors.extend(_exact_keys(item, GAP_KEYS, label))
                if set(item) != GAP_KEYS:
                    continue
                if item["atomic_row_id"] in gap_ids:
                    errors.append(f"duplicate gap id: {item['atomic_row_id']}")
                gap_ids.add(item["atomic_row_id"])
                if item["status"] != "blocked" or not item["blocker"]:
                    errors.append(f"{label} must remain explicitly blocked")
                for digest_key in (
                    "raw_record_sha256",
                    "effective_record_sha256",
                    "public_bindings_sha256",
                ):
                    if not HEX64_RE.fullmatch(str(item[digest_key])):
                        errors.append(f"{label}.{digest_key} must be a SHA-256")
                for field in ("owner", "reviewer"):
                    errors.extend(_nonempty_string(item[field], f"{label}.{field}"))
                _, deadline_errors = _parse_date(item["deadline"], f"{label}.deadline")
                expiry, expiry_errors = _parse_date(item["expiry"], f"{label}.expiry")
                errors.extend(deadline_errors + expiry_errors)
                if expiry and expiry < as_of:
                    errors.append(f"{label}.expiry is stale")
            if record_sha256(items) != gaps["set_sha256"]:
                errors.append("unreviewed gap set digest mismatch")
    if canonical_json_bytes(matrix) != canonical_json_bytes(expected):
        errors.append("matrix content differs from deterministic regeneration")
    return errors


def validate_schema_documents(inputs: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for name in ("matrix_schema", "dossier_schema", "overrides_schema"):
        schema = inputs[name]
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"{name} must declare JSON Schema 2020-12")
        if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
            errors.append(f"{name} root must be a closed object")
    errors.extend(
        validate_json_schema_instance(
            inputs["dossiers"],
            inputs["dossier_schema"],
            label="oracle-dossiers",
        )
    )
    errors.extend(
        validate_json_schema_instance(
            inputs["overrides"],
            inputs["overrides_schema"],
            label="evidence-overrides",
        )
    )
    return errors


def full_validation(
    inputs: dict[str, Any], *, validation_date: dt.date | None = None
) -> tuple[dict[str, Any], list[str]]:
    current_date = validation_date or dt.datetime.now(dt.timezone.utc).date()
    errors = validate_schema_documents(inputs)
    expected = build_matrix(inputs, validation_date=current_date)
    matrix = load_json(safe_repo_file(inputs["root"], "assurance/interoperability/matrix.json", "matrix"))
    errors.extend(
        validate_json_schema_instance(
            matrix,
            inputs["matrix_schema"],
            label="interoperability-matrix",
        )
    )
    errors.extend(validate_matrix(matrix, expected, as_of=current_date))
    expected_document = render_document(expected)
    document_path = safe_repo_file(
        inputs["root"], "assurance/interoperability/INTEROPERABILITY.md", "generated document"
    )
    if document_path.read_bytes() != expected_document:
        errors.append("INTEROPERABILITY.md differs from deterministic regeneration")
    return expected, errors
