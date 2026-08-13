#!/usr/bin/env python3
"""Descriptor-anchored import of an already-produced private Package F bundle.

Capture is intentionally a byte copier, not a runner or trust decision.  It
does not execute tools, contact a network service, validate a signer, accept a
result, or make any captured record promotion eligible.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True

# This module intentionally has no import edge to model.py.  The normative
# model includes repository inspection helpers backed by subprocess; capture
# must remain a capability-minimal byte copier even if a future model import
# hook or helper changes.  selftest.py independently proves that these frozen
# role schemas and trust anchors remain byte-for-byte equal to the model.
REPO = Path(__file__).resolve().parent.parent.parent
R_F_COMMIT = "889cb8c4dc13a78679dc8a7677916484a9966f65"
R_F_TREE = "0d44b68b186913de68844d09b7e498bcda14d109"
R_F_SUBJECT_MANIFEST_SHA256 = (
    "95902d2ff4a2f99808ba5d404fbce3175b787b93fdc1538cb55ad350e69505c7"
)
SBOM_IDS = ("production", "verification", "fuzz", "migration", "bench")
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
ARTIFACT_SUBJECT_SET_SHA256 = (
    "41cae985d2507f82ec0a90a4242cf814536474fa643b21078b60ae2b0186d099"
)
ROLE_CAPS = {
    "first-party-build-candidate": {
        "files": 64, "per_file": 67_108_864, "total": 536_870_912,
    },
    "signature-transparency-candidate": {
        "files": 32, "per_file": 16_777_216, "total": 67_108_864,
    },
    "independent-rebuild-candidate": {
        "files": 64, "per_file": 67_108_864, "total": 536_870_912,
    },
}
ROLE_POLICIES = {
    "first-party-build-candidate":
        "dcrypt-package-f-first-party-build-candidate-v1",
    "signature-transparency-candidate":
        "dcrypt-package-f-signature-transparency-candidate-v1",
    "independent-rebuild-candidate":
        "dcrypt-package-f-independent-rebuild-candidate-v1",
}
ROLE_STATUSES = {
    "first-party-build-candidate": "collected-unreviewed",
    "signature-transparency-candidate": "collected-unverified",
    "independent-rebuild-candidate": "collected-unreviewed",
}
CAPTURE_ADMISSIBLE_ROLES = frozenset(ROLE_CAPS)
ARTIFACT_CLASSES = (
    "sbom", "signature-envelope", "attestation", "certificate-chain",
    "trust-root", "transparency-proof", "source-archive", "crate-archive",
    "build-manifest", "rebuild-report",
)
MAX_CANDIDATE_BYTES = 1_048_576
RENAME_NOREPLACE = 1


class PackageFError(RuntimeError):
    """A capture-bound Package F invariant failed closed."""


def _expected_role_cap(role: str) -> dict[str, int]:
    """Return an unaliased literal cap so mutable module state cannot broaden it."""

    if role == "first-party-build-candidate":
        return {"files": 64, "per_file": 67_108_864, "total": 536_870_912}
    if role == "signature-transparency-candidate":
        return {"files": 32, "per_file": 16_777_216, "total": 67_108_864}
    if role == "independent-rebuild-candidate":
        return {"files": 64, "per_file": 67_108_864, "total": 536_870_912}
    raise PackageFError(f"capture role has no code-pinned resource profile: {role}")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False
        )
        + "\n"
    ).encode("utf-8")


def _compact_json(value: Any) -> bytes:
    return (
        json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        )
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
        raise PackageFError(f"{label} is not strict JSON: {error}") from error
    _assert_nfc(value, label=label)
    if require_canonical and canonical_json(value) != raw:
        raise PackageFError(f"{label} is not canonical JSON")
    return value


def safe_relative_path(value: str, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 1024
    ):
        raise PackageFError(f"{label} is not a bounded path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or "//" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(len(part.encode("utf-8")) > 255 for part in path.parts)
    ):
        raise PackageFError(f"{label} is not canonical relative POSIX")
    return value


def _closed_object(properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(properties),
        "type": "object",
    }


def _digest_schema() -> dict[str, Any]:
    return {"pattern": "^[0-9a-f]{64}$", "type": "string"}


def _artifact_schema(
    subject_id: str | None = None,
    artifact_class: str | None = None,
    *,
    maximum_size: int,
) -> dict[str, Any]:
    return _closed_object({
        "artifact_class": (
            {"enum": list(ARTIFACT_CLASSES)}
            if artifact_class is None
            else {"const": artifact_class}
        ),
        "file_mode": {"const": "0600"},
        "path": {
            "maxLength": 512,
            "minLength": 1,
            "pattern": "^(?!(?:.*?/)?(?:\\.|\\.\\.)(?:/|$))[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*$",
            "type": "string",
        },
        "sha256": _digest_schema(),
        "size": {"maximum": maximum_size, "minimum": 1, "type": "integer"},
        "subject_id": (
            {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9._+@/-]+$",
                "type": "string",
            }
            if subject_id is None
            else {"const": subject_id}
        ),
    })


def _role_artifact_specs(role: str) -> tuple[tuple[str, str], ...]:
    if role == "first-party-build-candidate":
        return tuple(sorted(ARTIFACT_SUBJECTS))
    if role == "signature-transparency-candidate":
        return (
            ("attestation", "attestation"),
            ("certificate-chain", "certificate-chain"),
            ("signature-envelope", "signature-envelope"),
            ("transparency-proof", "transparency-proof"),
            ("trust-root", "trust-root"),
        )
    if role == "independent-rebuild-candidate":
        return tuple(sorted((
            *ARTIFACT_SUBJECTS,
            ("independent-build-manifest", "build-manifest"),
            ("rebuild-comparison-report", "rebuild-report"),
        )))
    raise PackageFError(f"unknown capture role artifact closure: {role}")


def _subject_schema() -> dict[str, Any]:
    return _closed_object({
        "r_commit": {"const": R_F_COMMIT},
        "r_tree": {"const": R_F_TREE},
        "subject_manifest_sha256": {"const": R_F_SUBJECT_MANIFEST_SHA256},
    })


def _role_data_schema(role: str) -> dict[str, Any]:
    if role == "first-party-build-candidate":
        return _closed_object({
            "accepted_subjects": {"const": 0},
            "artifact_subject_count": {"const": 18},
            "cache_policy": {"const": "cold-bound-provisioning-only"},
            "crate_archive_count": {"const": 12},
            "producer_class": {"const": "first-party"},
            "environment_sha256": _digest_schema(),
            "invocation_sha256": _digest_schema(),
            "materials_sha256": _digest_schema(),
            "network_policy": {"const": "offline"},
            "producer_identity_sha256": _digest_schema(),
            "artifact_subject_set_sha256": {
                "const": ARTIFACT_SUBJECT_SET_SHA256
            },
            "command_target_profile_sha256": _digest_schema(),
            "dsse_envelope_sha256": _digest_schema(),
            "in_toto_statement_sha256": _digest_schema(),
            "in_toto_statement_type": {
                "const": "https://in-toto.io/Statement/v1"
            },
            "slsa_predicate_sha256": _digest_schema(),
            "slsa_predicate_type": {"const": "https://slsa.dev/provenance/v1"},
            "source_and_lock_input_set_sha256": _digest_schema(),
            "sbom_count": {"const": 5},
            "sbom_format": {"const": "CycloneDX"},
            "sbom_spec_version": {"const": "1.6"},
            "source_archive_count": {"const": 1},
            "toolchain_distribution_verified": {"const": False},
            "toolchain_bundle_sha256": _digest_schema(),
            "workspace_ids": {"const": list(SBOM_IDS)},
        })
    if role == "signature-transparency-candidate":
        return _closed_object({
            "accepted_attestations": {"const": 0},
            "cryptographic_verification_completed": {"const": False},
            "dsse_payload_type": {"const": "application/vnd.in-toto+json"},
            "envelope_sha256": _digest_schema(),
            "identity_verified": {"const": False},
            "first_party_artifact_set_sha256": _digest_schema(),
            "in_toto_statement_type": {
                "const": "https://in-toto.io/Statement/v1"
            },
            "signed_subject_set_sha256": {"const": ARTIFACT_SUBJECT_SET_SHA256},
            "slsa_predicate_type": {"const": "https://slsa.dev/provenance/v1"},
            "signature_count": {"const": 18},
            "signer_identity_sha256": _digest_schema(),
            "subject_count": {"const": 18},
            "timestamp_binding_sha256": _digest_schema(),
            "transparency_verified": {"const": False},
            "trust_root_sha256": _digest_schema(),
            "trust_root_verified": {"const": False},
        })
    if role == "independent-rebuild-candidate":
        return _closed_object({
            "accepted_rebuilds": {"const": 0},
            "administrative_independence_claimed": {"const": True},
            "administrative_independence_verified": {"const": False},
            "artifact_subject_count": {"const": 18},
            "byte_comparison_report_sha256": _digest_schema(),
            "cache_policy": {"const": "cold-bound-provisioning-only"},
            "artifact_subject_set_sha256": {
                "const": ARTIFACT_SUBJECT_SET_SHA256
            },
            "command_target_profile_sha256": _digest_schema(),
            "environment_sha256": _digest_schema(),
            "first_party_artifact_set_sha256": _digest_schema(),
            "invocation_sha256": _digest_schema(),
            "materials_sha256": _digest_schema(),
            "matching_subjects": {"minimum": 0, "maximum": 18, "type": "integer"},
            "mismatching_subjects": {
                "minimum": 0, "maximum": 18, "type": "integer"
            },
            "network_policy": {"const": "offline"},
            "producer_identity_sha256": _digest_schema(),
            "replayer_identity_sha256": _digest_schema(),
            "toolchain_bundle_sha256": _digest_schema(),
            "source_and_lock_input_set_sha256": _digest_schema(),
        })
    raise PackageFError(f"unknown Package F capture role: {role}")


def _role_schema(role: str) -> dict[str, Any]:
    specs = _role_artifact_specs(role)
    maximum_size = _expected_role_cap(role)["per_file"]
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
            "maxItems": len(specs),
            "minItems": len(specs),
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
    })


def artifact_set_sha256(artifacts: list[dict[str, Any]]) -> str:
    return sha256_bytes(_compact_json(artifacts))


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
        if (
            not isinstance(value, str)
            or len(value) < schema.get("minLength", 0)
            or len(value) > schema.get("maxLength", 1 << 30)
        ):
            raise PackageFError(f"{label} string differs")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise PackageFError(f"{label} pattern differs")
    elif kind == "integer":
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < schema.get("minimum", -(1 << 63))
            or value > schema.get("maximum", 1 << 63)
        ):
            raise PackageFError(f"{label} integer differs")
    elif kind == "boolean" and not isinstance(value, bool):
        raise PackageFError(f"{label} boolean differs")


def _validate_closed_schema(value: Any, schema: dict[str, Any], *, label: str) -> None:
    if schema.get("type") == "object":
        if not isinstance(value, dict) or set(value) != set(schema["required"]):
            raise PackageFError(f"{label} object closure differs")
        for key, item in value.items():
            _validate_closed_schema(
                item, schema["properties"][key], label=f"{label}.{key}"
            )
        return
    if schema.get("type") == "array":
        if (
            not isinstance(value, list)
            or len(value) < schema.get("minItems", 0)
            or len(value) > schema.get("maxItems", 1 << 30)
        ):
            raise PackageFError(f"{label} array differs")
        if "const" in schema:
            if not _same_json_value(value, schema["const"]):
                raise PackageFError(f"{label} array constant differs")
            return
        for index, item in enumerate(value):
            _validate_closed_schema(
                item, schema["items"], label=f"{label}[{index}]"
            )
        for index, condition in enumerate(schema.get("allOf", [])):
            matches = 0
            for item in value:
                try:
                    _validate_closed_schema(
                        item, condition["contains"], label=f"{label} contains"
                    )
                except PackageFError:
                    continue
                matches += 1
            if not condition["minContains"] <= matches <= condition["maxContains"]:
                raise PackageFError(
                    f"{label} exact role artifact mapping {index} differs"
                )
        return
    _schema_scalar(value, schema, label=label)


def validate_evidence_candidate(value: Any, *, capture: bool = False) -> str:
    if not isinstance(value, dict) or not isinstance(
        value.get("artifact_role"), str
    ):
        raise PackageFError("candidate lacks an exact role")
    role = value["artifact_role"]
    if role not in CAPTURE_ADMISSIBLE_ROLES:
        raise PackageFError(f"Package F role is not capture-admissible: {role}")
    _validate_closed_schema(value, _role_schema(role), label="candidate")
    artifacts = value["artifacts"]
    paths = [row["path"] for row in artifacts]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise PackageFError("candidate artifact paths are not sorted and unique")
    for path in paths:
        safe_relative_path(path, label="candidate artifact path")
    if value["raw_artifact_set_sha256"] != artifact_set_sha256(artifacts):
        raise PackageFError("candidate artifact-set digest differs")
    subject_classes = [
        (row["subject_id"], row["artifact_class"]) for row in artifacts
    ]
    if role == "first-party-build-candidate" and sorted(
        subject_classes
    ) != sorted(ARTIFACT_SUBJECTS):
        raise PackageFError("first-party artifact subject closure differs")
    if role == "independent-rebuild-candidate" and sorted(
        subject_classes
    ) != sorted((
        *ARTIFACT_SUBJECTS,
        ("independent-build-manifest", "build-manifest"),
        ("rebuild-comparison-report", "rebuild-report"),
    )):
        raise PackageFError("independent rebuild artifact closure differs")
    if role == "signature-transparency-candidate" and sorted(
        subject_classes
    ) != sorted((
        ("attestation", "attestation"),
        ("certificate-chain", "certificate-chain"),
        ("signature-envelope", "signature-envelope"),
        ("transparency-proof", "transparency-proof"),
        ("trust-root", "trust-root"),
    )):
        raise PackageFError("signature/transparency artifact closure differs")
    by_subject = {row["subject_id"]: row for row in artifacts}
    if role == "signature-transparency-candidate" and (
        value["role_data"]["envelope_sha256"]
        != by_subject["signature-envelope"]["sha256"]
        or value["role_data"]["trust_root_sha256"]
        != by_subject["trust-root"]["sha256"]
    ):
        raise PackageFError("signature named artifact digest join differs")
    if role == "independent-rebuild-candidate" and (
        value["role_data"]["byte_comparison_report_sha256"]
        != by_subject["rebuild-comparison-report"]["sha256"]
    ):
        raise PackageFError("rebuild comparison artifact digest join differs")
    if value["trusted"] is not False or value["promotion_eligible"] is not False:
        raise PackageFError("Package F candidates never imply trust or promotion")
    if role == "independent-rebuild-candidate":
        data = value["role_data"]
        if data["matching_subjects"] + data["mismatching_subjects"] != 18:
            raise PackageFError("rebuild comparison totals differ")
        if data["producer_identity_sha256"] == data["replayer_identity_sha256"]:
            raise PackageFError(
                "rebuild producer/replayer identities are not separated"
            )
    return role


def _os_error(label: str, error: OSError) -> PackageFError:
    """Return an error which cannot disclose a private path or candidate value."""

    return PackageFError(f"{label} failed with operating-system errno {error.errno}")


def _basic_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
    )


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _private_directory(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and metadata.st_mode & 0o7000 == 0
    )


def _private_file(metadata: os.stat_result, maximum: int) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and metadata.st_mode & 0o7000 == 0
        and 0 <= metadata.st_size <= maximum
    )


def _canonical_absolute(path: Path, *, label: str) -> Path:
    raw = os.fspath(path)
    if (
        not path.is_absolute()
        or not raw.startswith("/")
        or raw.startswith("//")
        or raw != os.path.normpath(raw)
        or not path.name
        or ".git" in path.parts
    ):
        raise PackageFError(f"{label} must be a canonical absolute path without .git")
    return path


def _open_directory_chain(
    path: Path, *, label: str
) -> tuple[int, tuple[tuple[int, ...], ...]]:
    """Open every absolute-path component with openat and O_NOFOLLOW."""

    path = _canonical_absolute(path, label=label)
    descriptor = -1
    identities: list[tuple[int, ...]] = []
    try:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise PackageFError(f"{label} root is not a directory")
        identities.append(_basic_identity(metadata))
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise PackageFError(f"{label} contains a nondirectory component")
            identities.append(_basic_identity(metadata))
        return descriptor, tuple(identities)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise _os_error(f"opening {label}", error) from error
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _assert_directory_chain(
    path: Path, expected: tuple[tuple[int, ...], ...], *, label: str
) -> None:
    descriptor, observed = _open_directory_chain(path, label=label)
    try:
        if observed != expected:
            raise PackageFError(f"{label} identity changed during capture")
    finally:
        os.close(descriptor)


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _entry_absent(parent_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise _os_error("checking destination absence", error) from error
    raise PackageFError("destination must not already exist")


def _bounded_directory_names(
    descriptor: int, expected_count: int, *, label: str
) -> list[str]:
    """Enumerate no more than the exact expected closure plus one sentinel."""

    names: list[str] = []
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > expected_count:
                    raise PackageFError(f"{label} contains a surplus entry")
    except OSError as error:
        raise _os_error(f"enumerating {label}", error) from error
    return names


def _validate_roots(
    source: Path, destination: Path
) -> tuple[
    Path,
    Path,
    int,
    int,
    tuple[tuple[int, ...], ...],
    tuple[tuple[int, ...], ...],
    tuple[int, ...],
]:
    source = _canonical_absolute(source, label="source bundle root")
    destination = _canonical_absolute(destination, label="destination")
    repo = REPO.resolve(strict=True)
    if (
        _inside(source, repo)
        or _inside(destination, repo)
        or _inside(source, destination)
        or _inside(destination, source)
        or source == destination
    ):
        raise PackageFError("source or destination overlaps a forbidden boundary")

    source_fd = -1
    parent_fd = -1
    repo_fd = -1
    git_fd = -1
    try:
        source_fd, source_chain = _open_directory_chain(
            source, label="source bundle root"
        )
        source_metadata = os.fstat(source_fd)
        if not _private_directory(source_metadata):
            raise PackageFError("source bundle root is not current-owner mode 0700")
        source_identity = _stable_identity(source_metadata)

        parent_fd, parent_chain = _open_directory_chain(
            destination.parent, label="destination parent"
        )
        parent_metadata = os.fstat(parent_fd)
        if not _private_directory(parent_metadata):
            raise PackageFError("destination parent is not current-owner mode 0700")
        repo_fd, _repo_chain = _open_directory_chain(repo, label="repository root")
        try:
            git_fd = os.open(
                ".git",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=repo_fd,
            )
        except OSError as error:
            raise _os_error("opening repository metadata", error) from error
        repo_identity = _basic_identity(os.fstat(repo_fd))
        git_identity = _basic_identity(os.fstat(git_fd))
        source_basic = _basic_identity(source_metadata)
        parent_basic = _basic_identity(parent_metadata)
        if (
            repo_identity in source_chain
            or repo_identity in parent_chain
            or git_identity in source_chain
            or git_identity in parent_chain
            or source_basic in parent_chain
            or parent_basic in source_chain
        ):
            raise PackageFError("descriptor identities overlap a forbidden boundary")
        _entry_absent(parent_fd, destination.name)
        return (
            source,
            destination,
            source_fd,
            parent_fd,
            source_chain,
            parent_chain,
            source_identity,
        )
    except BaseException:
        if source_fd >= 0:
            os.close(source_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        raise
    finally:
        if repo_fd >= 0:
            os.close(repo_fd)
        if git_fd >= 0:
            os.close(git_fd)


def _read_descriptor(
    descriptor: int, metadata: os.stat_result, *, label: str
) -> bytes:
    expected = _stable_identity(metadata)
    chunks: list[bytes] = []
    remaining = metadata.st_size
    try:
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                raise PackageFError(f"{label} was truncated during capture")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) != b"":
            raise PackageFError(f"{label} grew during capture")
        if _stable_identity(os.fstat(descriptor)) != expected:
            raise PackageFError(f"{label} metadata changed during capture")
    except OSError as error:
        raise _os_error(f"reading {label}", error) from error
    return b"".join(chunks)


def _open_candidate(root_fd: int) -> tuple[int, os.stat_result]:
    descriptor = -1
    try:
        descriptor = os.open(
            "candidate.json",
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        metadata = os.fstat(descriptor)
        if not _private_file(metadata, MAX_CANDIDATE_BYTES):
            raise PackageFError("candidate record is not a bounded private regular file")
        return descriptor, metadata
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise _os_error("opening candidate record", error) from error
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _candidate_contract(
    candidate: dict[str, Any]
) -> tuple[
    dict[str, int],
    dict[str, dict[str, Any]],
    set[str],
    set[str],
]:
    role = validate_evidence_candidate(candidate, capture=True)
    if role not in ROLE_CAPS:
        raise PackageFError("capture role has no code-pinned resource profile")
    caps = _expected_role_cap(role)
    if ROLE_CAPS[role] != caps or set(caps) != {"files", "per_file", "total"} or any(
        not isinstance(value, int) or isinstance(value, bool) or value <= 0
        for value in caps.values()
    ):
        raise PackageFError("code-pinned role cap closure differs")

    artifacts = candidate["artifacts"]
    if len(artifacts) > caps["files"]:
        raise PackageFError("candidate exceeds its role-specific file cap")
    if candidate["raw_artifact_set_sha256"] != artifact_set_sha256(artifacts):
        raise PackageFError("candidate raw-artifact set digest differs")

    records: dict[str, dict[str, Any]] = {}
    expected_files = {"candidate.json"}
    expected_directories: set[str] = set()
    declared_total = 0
    for record in artifacts:
        relative = safe_relative_path(record["path"], label="candidate artifact")
        parts = PurePosixPath(relative).parts
        if ".git" in parts or relative == "candidate.json":
            raise PackageFError("candidate artifact uses a forbidden path")
        if record["size"] > caps["per_file"]:
            raise PackageFError("candidate exceeds its role-specific per-file cap")
        declared_total += record["size"]
        records[relative] = record
        expected_files.add(relative)
        for end in range(1, len(parts)):
            expected_directories.add("/".join(parts[:end]))
    if declared_total > caps["total"]:
        raise PackageFError("candidate exceeds its role-specific aggregate cap")
    if len(records) != len(artifacts):
        raise PackageFError("candidate artifact paths contain duplicates")
    if expected_files & expected_directories:
        raise PackageFError("candidate artifact paths contain a file/directory conflict")
    return caps, records, expected_files, expected_directories

def _expected_children(
    relative: str, expected_files: set[str], expected_directories: set[str]
) -> dict[str, str]:
    prefix = f"{relative}/" if relative else ""
    children: dict[str, str] = {}
    for path in expected_files:
        if path.startswith(prefix):
            remainder = path[len(prefix):]
            if "/" not in remainder:
                children[remainder] = "file"
    for path in expected_directories:
        if path.startswith(prefix):
            remainder = path[len(prefix):]
            if "/" not in remainder:
                if children.setdefault(remainder, "directory") != "directory":
                    raise PackageFError("bundle path type closure conflicts")
    return children


def _scan_source_tree(
    root_fd: int,
    expected_files: set[str],
    expected_directories: set[str],
    records: dict[str, dict[str, Any]],
    caps: dict[str, int],
) -> tuple[dict[str, tuple[int, ...]], dict[str, tuple[int, ...]]]:
    file_identities: dict[str, tuple[int, ...]] = {}
    directory_identities: dict[str, tuple[int, ...]] = {}
    seen_directories = {_basic_identity(os.fstat(root_fd))[:2]}

    def visit(descriptor: int, relative: str) -> None:
        expected = _expected_children(relative, expected_files, expected_directories)
        names = _bounded_directory_names(
            descriptor, len(expected), label="source bundle directory"
        )
        if set(names) != set(expected):
            raise PackageFError("source bundle path closure differs")
        for name in sorted(names):
            child = f"{relative}/{name}" if relative else name
            if name == ".git":
                raise PackageFError("source bundle contains a forbidden .git component")
            try:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                raise _os_error("stating source bundle member", error) from error
            if expected[name] == "directory":
                if not _private_directory(metadata):
                    raise PackageFError("source bundle contains an unsafe directory")
                child_fd = -1
                try:
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                    opened = os.fstat(child_fd)
                    if _stable_identity(opened) != _stable_identity(metadata):
                        raise PackageFError("source directory changed during traversal")
                    key = (opened.st_dev, opened.st_ino)
                    if key in seen_directories:
                        raise PackageFError("source bundle aliases a directory")
                    seen_directories.add(key)
                    directory_identities[child] = _stable_identity(opened)
                    visit(child_fd, child)
                except OSError as error:
                    raise _os_error("opening source directory", error) from error
                finally:
                    if child_fd >= 0:
                        os.close(child_fd)
            else:
                maximum = (
                    MAX_CANDIDATE_BYTES
                    if child == "candidate.json"
                    else caps["per_file"]
                )
                if not _private_file(metadata, maximum):
                    raise PackageFError("source bundle contains an unsafe file")
                expected_size = (
                    metadata.st_size
                    if child == "candidate.json"
                    else records[child]["size"]
                )
                if metadata.st_size != expected_size:
                    raise PackageFError("source artifact size differs from its declaration")
                file_identities[child] = _stable_identity(metadata)

    visit(root_fd, "")
    if set(file_identities) != expected_files or set(directory_identities) != expected_directories:
        raise PackageFError("source bundle identity closure differs")
    return file_identities, directory_identities


def _open_source_artifact(
    root_fd: int,
    relative: str,
    file_identities: dict[str, tuple[int, ...]],
    directory_identities: dict[str, tuple[int, ...]],
) -> tuple[int, os.stat_result]:
    parts = PurePosixPath(relative).parts
    current = os.dup(root_fd)
    try:
        prefix: list[str] = []
        for component in parts[:-1]:
            prefix.append(component)
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = next_descriptor
            if _stable_identity(os.fstat(current)) != directory_identities["/".join(prefix)]:
                raise PackageFError("source directory identity changed before read")
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
            dir_fd=current,
        )
        metadata = os.fstat(descriptor)
        if _stable_identity(metadata) != file_identities[relative]:
            os.close(descriptor)
            raise PackageFError("source file identity changed before read")
        return descriptor, metadata
    except OSError as error:
        raise _os_error("opening source artifact", error) from error
    finally:
        os.close(current)


def _create_staging(parent_fd: int) -> tuple[str, int, tuple[int, ...]]:
    for _attempt in range(32):
        name = f".dcrypt-package-f-capture-{os.urandom(16).hex()}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        except OSError as error:
            raise _os_error("creating capture staging directory", error) from error
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            os.fchmod(descriptor, 0o700)
            metadata = os.fstat(descriptor)
            if not _private_directory(metadata):
                raise PackageFError("capture staging directory metadata differs")
            return name, descriptor, _basic_identity(metadata)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError as cleanup_error:
                raise PackageFError(
                    "capture staging initialization failed and ambiguous private "
                    "staging residue was preserved"
                ) from cleanup_error
            raise
    raise PackageFError("cannot allocate an exclusive capture staging directory")


def _open_destination_parent(
    root_fd: int,
    relative: str,
    directory_identities: dict[str, tuple[int, ...]],
) -> int:
    current = os.dup(root_fd)
    prefix: list[str] = []
    try:
        for component in PurePosixPath(relative).parts[:-1]:
            prefix.append(component)
            key = "/".join(prefix)
            if key not in directory_identities:
                child_fd = -1
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                    child_fd = os.open(
                        component,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=current,
                    )
                    os.fchmod(child_fd, 0o700)
                    metadata = os.fstat(child_fd)
                    if not _private_directory(metadata):
                        raise PackageFError("destination directory metadata differs")
                    directory_identities[key] = _basic_identity(metadata)
                except BaseException:
                    if child_fd >= 0:
                        os.close(child_fd)
                    try:
                        os.rmdir(component, dir_fd=current)
                    except OSError:
                        pass
                    raise
            else:
                child_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                if _basic_identity(os.fstat(child_fd)) != directory_identities[key]:
                    os.close(child_fd)
                    raise PackageFError("destination directory identity changed")
            os.close(current)
            current = child_fd
        return current
    except OSError as error:
        os.close(current)
        raise _os_error("opening destination directory", error) from error
    except BaseException:
        os.close(current)
        raise


def _complete_write(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise PackageFError("destination write made no progress")
        view = view[written:]


def _unlink_open_destination(
    parent_fd: int, name: str, descriptor: int
) -> None:
    """Remove only the directory entry which still names our open file."""

    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _basic_identity(opened) == _basic_identity(named):
            os.unlink(name, dir_fd=parent_fd)
    except OSError:
        pass


def _verify_written_descriptor(
    descriptor: int,
    *,
    expected_size: int,
    expected_sha256: str,
) -> tuple[int, ...]:
    os.fsync(descriptor)
    metadata = os.fstat(descriptor)
    if not _private_file(metadata, expected_size) or metadata.st_size != expected_size:
        raise PackageFError("destination file metadata differs")
    expected_identity = _stable_identity(metadata)
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(1 << 20, remaining))
        if not chunk:
            raise PackageFError("destination file was truncated")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1) != b"" or digest.hexdigest() != expected_sha256:
        raise PackageFError("destination file bytes differ")
    if _stable_identity(os.fstat(descriptor)) != expected_identity:
        raise PackageFError("destination file metadata changed during verification")
    return expected_identity


def _write_bytes(
    root_fd: int,
    relative: str,
    raw: bytes,
    expected_sha256: str,
    directory_identities: dict[str, tuple[int, ...]],
) -> tuple[int, ...]:
    parent_fd = _open_destination_parent(root_fd, relative, directory_identities)
    descriptor = -1
    complete = False
    name = PurePosixPath(relative).name
    try:
        descriptor = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(descriptor, 0o600)
        _complete_write(descriptor, raw)
        identity = _verify_written_descriptor(
            descriptor, expected_size=len(raw), expected_sha256=expected_sha256
        )
        complete = True
        return identity
    except OSError as error:
        raise _os_error("writing destination file", error) from error
    finally:
        if descriptor >= 0 and not complete:
            _unlink_open_destination(parent_fd, name, descriptor)
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _copy_artifact(
    root_fd: int,
    relative: str,
    source_fd: int,
    source_metadata: os.stat_result,
    expected_size: int,
    expected_sha256: str,
    directory_identities: dict[str, tuple[int, ...]],
) -> tuple[int, ...]:
    parent_fd = _open_destination_parent(root_fd, relative, directory_identities)
    destination_fd = -1
    source_identity = _stable_identity(source_metadata)
    complete = False
    name = PurePosixPath(relative).name
    try:
        destination_fd = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(destination_fd, 0o600)
        digest = hashlib.sha256()
        remaining = expected_size
        while remaining:
            chunk = os.read(source_fd, min(1 << 20, remaining))
            if not chunk:
                raise PackageFError("source artifact was truncated during copy")
            digest.update(chunk)
            _complete_write(destination_fd, chunk)
            remaining -= len(chunk)
        if os.read(source_fd, 1) != b"":
            raise PackageFError("source artifact grew during copy")
        if (
            digest.hexdigest() != expected_sha256
            or _stable_identity(os.fstat(source_fd)) != source_identity
        ):
            raise PackageFError("source artifact identity differs from its declaration")
        identity = _verify_written_descriptor(
            destination_fd,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
        )
        complete = True
        return identity
    except OSError as error:
        raise _os_error("copying artifact", error) from error
    finally:
        if destination_fd >= 0 and not complete:
            _unlink_open_destination(parent_fd, name, destination_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(parent_fd)


def _open_known_directory(
    root_fd: int,
    relative: str,
    directory_identities: dict[str, tuple[int, ...]],
) -> int:
    current = os.dup(root_fd)
    prefix: list[str] = []
    try:
        for component in PurePosixPath(relative).parts if relative else ():
            prefix.append(component)
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = next_descriptor
            if _basic_identity(os.fstat(current)) != directory_identities["/".join(prefix)]:
                raise PackageFError("destination directory identity changed")
        return current
    except OSError as error:
        os.close(current)
        raise _os_error("opening captured directory", error) from error
    except BaseException:
        os.close(current)
        raise


def _verify_destination_tree(
    root_fd: int,
    expected_files: dict[str, tuple[int, str]],
    expected_directories: set[str],
    file_identities: dict[str, tuple[int, ...]],
    directory_identities: dict[str, tuple[int, ...]],
) -> None:
    def visit(descriptor: int, relative: str) -> None:
        wanted = _expected_children(
            relative, set(expected_files), expected_directories
        )
        names = _bounded_directory_names(
            descriptor, len(wanted), label="captured bundle directory"
        )
        if set(names) != set(wanted):
            raise PackageFError("captured destination closure differs")
        for name in sorted(names):
            child = f"{relative}/{name}" if relative else name
            if wanted[name] == "directory":
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    metadata = os.fstat(child_fd)
                    if (
                        not _private_directory(metadata)
                        or _basic_identity(metadata) != directory_identities[child]
                    ):
                        raise PackageFError("captured destination directory differs")
                    visit(child_fd, child)
                finally:
                    os.close(child_fd)
            else:
                file_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    metadata = os.fstat(file_fd)
                    size, digest = expected_files[child]
                    if (
                        _stable_identity(metadata) != file_identities[child]
                        or not _private_file(metadata, size)
                        or metadata.st_size != size
                    ):
                        raise PackageFError("captured destination file differs")
                    observed = _read_descriptor(
                        file_fd, metadata, label="captured destination file"
                    )
                    if sha256_bytes(observed) != digest:
                        raise PackageFError("captured destination digest differs")
                finally:
                    os.close(file_fd)

    visit(root_fd, "")


def _fsync_directories(
    root_fd: int,
    directory_identities: dict[str, tuple[int, ...]],
) -> None:
    for relative in sorted(
        directory_identities, key=lambda value: (value.count("/"), value), reverse=True
    ):
        descriptor = _open_known_directory(root_fd, relative, directory_identities)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    os.fsync(root_fd)


def _rename_noreplace(
    parent_fd: int, source_name: str, destination_name: str
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, "renameat2", None)
    if function is None:
        raise PackageFError("atomic no-overwrite finalization is unavailable")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    result = function(
        parent_fd,
        os.fsencode(source_name),
        parent_fd,
        os.fsencode(destination_name),
        RENAME_NOREPLACE,
    )
    if result != 0:
        value = ctypes.get_errno()
        raise PackageFError(
            f"atomic no-overwrite finalization failed with operating-system errno {value}"
        )


def _cleanup_known(
    parent_fd: int,
    root_name: str | None,
    root_identity: tuple[int, ...] | None,
    file_identities: dict[str, tuple[int, ...]],
    directory_identities: dict[str, tuple[int, ...]],
) -> None:
    """Remove invocation-recorded entries inside the private same-UID boundary."""

    if root_name is None or root_identity is None:
        return
    failures = 0
    root_fd = -1
    try:
        root_fd = os.open(
            root_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        if _basic_identity(os.fstat(root_fd)) != root_identity:
            raise PackageFError("capture rollback root identity differs")
        for relative in sorted(file_identities, reverse=True):
            try:
                parent_relative = PurePosixPath(relative).parent.as_posix()
                if parent_relative == ".":
                    parent_relative = ""
                parent = _open_known_directory(
                    root_fd, parent_relative, directory_identities
                )
                try:
                    metadata = os.stat(
                        PurePosixPath(relative).name,
                        dir_fd=parent,
                        follow_symlinks=False,
                    )
                    if _stable_identity(metadata) == file_identities[relative]:
                        os.unlink(PurePosixPath(relative).name, dir_fd=parent)
                    else:
                        failures += 1
                finally:
                    os.close(parent)
            except FileNotFoundError:
                continue
            except (OSError, PackageFError):
                failures += 1
        for relative in sorted(
            directory_identities,
            key=lambda value: (value.count("/"), value),
            reverse=True,
        ):
            parent_relative = PurePosixPath(relative).parent.as_posix()
            if parent_relative == ".":
                parent_relative = ""
            try:
                parent = _open_known_directory(
                    root_fd, parent_relative, directory_identities
                )
                try:
                    metadata = os.stat(
                        PurePosixPath(relative).name,
                        dir_fd=parent,
                        follow_symlinks=False,
                    )
                    if _basic_identity(metadata) == directory_identities[relative]:
                        os.rmdir(PurePosixPath(relative).name, dir_fd=parent)
                    else:
                        failures += 1
                finally:
                    os.close(parent)
            except FileNotFoundError:
                continue
            except (OSError, PackageFError):
                failures += 1
    except FileNotFoundError:
        return
    except OSError as error:
        raise _os_error("opening capture rollback root", error) from error
    finally:
        if root_fd >= 0:
            os.close(root_fd)
    try:
        metadata = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        if _basic_identity(metadata) == root_identity:
            os.rmdir(root_name, dir_fd=parent_fd)
        else:
            failures += 1
    except FileNotFoundError:
        pass
    except OSError:
        failures += 1
    try:
        os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        os.fsync(parent_fd)
        if failures:
            raise PackageFError("capture rollback encountered an owned-entry failure")
        return
    except OSError as error:
        raise _os_error("verifying capture rollback", error) from error
    raise PackageFError("capture rollback is incomplete; private output was preserved")


def capture(source: Path, destination: Path) -> dict[str, Any]:
    (
        source,
        destination,
        source_fd,
        parent_fd,
        source_chain,
        parent_chain,
        source_root_identity,
    ) = _validate_roots(source, destination)

    cleanup_name: str | None = None
    staging_identity: tuple[int, ...] | None = None
    destination_directories: dict[str, tuple[int, ...]] = {}
    destination_files: dict[str, tuple[int, ...]] = {}
    staging_fd = -1
    try:
        candidate_fd, candidate_metadata = _open_candidate(source_fd)
        try:
            candidate_raw = _read_descriptor(
                candidate_fd, candidate_metadata, label="candidate record"
            )
        finally:
            os.close(candidate_fd)
        candidate = parse_json_strict(
            candidate_raw, label="candidate record", require_canonical=True
        )
        if not isinstance(candidate, dict):
            raise PackageFError("candidate record root is not an object")
        caps, records, expected_files, expected_directories = _candidate_contract(candidate)
        declared_artifact_total = sum(record["size"] for record in records.values())
        if len(candidate_raw) + declared_artifact_total > caps["total"]:
            raise PackageFError("candidate and artifacts exceed the role-specific aggregate cap")

        source_files, source_directories = _scan_source_tree(
            source_fd,
            expected_files,
            expected_directories,
            records,
            caps,
        )
        if source_files["candidate.json"] != _stable_identity(candidate_metadata):
            raise PackageFError("candidate record changed after validation")

        cleanup_name, staging_fd, staging_identity = _create_staging(parent_fd)
        destination_files["candidate.json"] = _write_bytes(
            staging_fd,
            "candidate.json",
            candidate_raw,
            sha256_bytes(candidate_raw),
            destination_directories,
        )
        artifact_total = 0
        for relative in sorted(records):
            record = records[relative]
            artifact_fd, artifact_metadata = _open_source_artifact(
                source_fd,
                relative,
                source_files,
                source_directories,
            )
            try:
                destination_files[relative] = _copy_artifact(
                    staging_fd,
                    relative,
                    artifact_fd,
                    artifact_metadata,
                    record["size"],
                    record["sha256"],
                    destination_directories,
                )
            finally:
                os.close(artifact_fd)
            artifact_total += record["size"]
            if len(candidate_raw) + artifact_total > caps["total"]:
                raise PackageFError("actual bundle exceeds its role-specific aggregate cap")

        observed_files, observed_directories = _scan_source_tree(
            source_fd,
            expected_files,
            expected_directories,
            records,
            caps,
        )
        if observed_files != source_files or observed_directories != source_directories:
            raise PackageFError("source bundle changed during capture")
        if _stable_identity(os.fstat(source_fd)) != source_root_identity:
            raise PackageFError("source bundle root changed during capture")
        _assert_directory_chain(
            source, source_chain, label="source bundle root"
        )

        expected_destination_files = {
            "candidate.json": (len(candidate_raw), sha256_bytes(candidate_raw)),
            **{
                relative: (record["size"], record["sha256"])
                for relative, record in records.items()
            },
        }
        if set(destination_directories) != expected_directories:
            raise PackageFError("destination directory closure differs")
        _fsync_directories(staging_fd, destination_directories)
        _verify_destination_tree(
            staging_fd,
            expected_destination_files,
            expected_directories,
            destination_files,
            destination_directories,
        )
        _assert_directory_chain(
            destination.parent, parent_chain, label="destination parent"
        )
        _entry_absent(parent_fd, destination.name)
        _rename_noreplace(parent_fd, cleanup_name, destination.name)
        cleanup_name = destination.name
        os.fsync(parent_fd)

        os.close(staging_fd)
        staging_fd = os.open(
            destination.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        if _basic_identity(os.fstat(staging_fd)) != staging_identity:
            raise PackageFError("final destination descriptor identity differs")
        _verify_destination_tree(
            staging_fd,
            expected_destination_files,
            expected_directories,
            destination_files,
            destination_directories,
        )
        _fsync_directories(staging_fd, destination_directories)
        os.fsync(parent_fd)
        _assert_directory_chain(
            destination.parent, parent_chain, label="destination parent"
        )

        cleanup_name = None
        return {
            "artifact_count": len(records),
            "candidate_sha256": sha256_bytes(candidate_raw),
            "artifact_role": candidate["artifact_role"],
            "promotion_eligible": False,
            "status": "captured-unreviewed-not-accepted",
            "trusted": False,
            "total_bytes": len(candidate_raw) + artifact_total,
        }
    finally:
        if staging_fd >= 0:
            os.close(staging_fd)
        try:
            _cleanup_known(
                parent_fd,
                cleanup_name,
                staging_identity,
                destination_files,
                destination_directories,
            )
        finally:
            os.close(source_fd)
            os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--source-bundle-root", required=True)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args()
    try:
        result = capture(Path(args.source_bundle_root), Path(args.destination))
        sys.stdout.buffer.write(canonical_json(result))
        return 0
    except PackageFError as error:
        print(f"Package F capture HOLD: {error}", file=sys.stderr)
        return 3
    except (OSError, UnicodeError, ValueError) as error:
        error_number = error.errno if isinstance(error, OSError) else None
        suffix = f" (errno={error_number})" if error_number is not None else ""
        print(f"Package F capture HOLD: invalid private bundle{suffix}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
