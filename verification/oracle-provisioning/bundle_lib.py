#!/usr/bin/env python3
"""Shared, standard-library-only helpers for the oracle source bundle."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tarfile
import tomllib
import zlib
from pathlib import Path, PurePosixPath
from typing import Any


FORMAT = "dcrypt-oracle-provisioning-manifest-v2"
SUBJECT_FORMAT = "dcrypt-oracle-subject-inputs-v1"
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
URL_TEMPLATE = "https://static.crates.io/crates/{name}/{name}-{version}.crate"
EXPECTED_PACKAGE_COUNT = 138
EXPECTED_TARGET_COUNT = 6
EXPECTED_TEST_COUNT = 30
MAX_ARCHIVE_SIZE = 16 * 1024 * 1024
MAX_MEMBER_COUNT = 10_000
MAX_MEMBER_SIZE = 32 * 1024 * 1024
MAX_UNPACKED_SIZE = 128 * 1024 * 1024
MAX_TAR_STREAM_SIZE = 256 * 1024 * 1024
MAX_BUNDLE_SIZE = 64 * 1024 * 1024
MAX_TOTAL_MEMBER_COUNT = 100_000
MAX_TOTAL_UNPACKED_SIZE = 512 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_PATH_COMPONENT_BYTES = 255
# This is intentionally updated by rebind-final-subject.py together with the
# canonical manifest.  A canonical but coherently rewritten manifest is not a
# trusted root unless reviewed code pins its exact bytes here.
EXPECTED_NORMATIVE_MANIFEST_SHA256 = "0dde2147528b88475ace869ff4e24b509eb48c472220938252e9cab5cafd62f7"
# Independent of the rebindable normative-root pin: exact six target IDs,
# source paths/digests, and ordered 30-name inventory are frozen semantics.
# rebind-final-subject.py deliberately cannot rewrite this constant.
EXPECTED_TEST_SEMANTICS_SHA256 = "b8a53f254470bc6b6f1601bda9bc63a08f3134ae907adf96d436ffbdb9641605"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
NAME = re.compile(r"[A-Za-z0-9_-]+\Z")
VERSION = re.compile(r"[A-Za-z0-9.+-]+\Z")
TARGET = re.compile(r"[a-z][a-z0-9_]*\Z")
TEST = re.compile(r"[A-Za-z_][A-Za-z0-9_:]*\Z")


class BundleError(RuntimeError):
    """An input failed a fail-closed provisioning check."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def cargo_config(vendor_path: Path) -> str:
    return (
        "[net]\n"
        "offline = true\n\n"
        "[source.crates-io]\n"
        'replace-with = "dcrypt-oracle-vendor"\n\n'
        "[source.dcrypt-oracle-vendor]\n"
        f"directory = {json.dumps(str(vendor_path.resolve()))}\n"
    )


def _exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        raise BundleError(
            f"{context} keys differ: missing={sorted(expected - actual)!r} "
            f"extra={sorted(actual - expected)!r}"
        )


def _hex64(value: Any, context: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise BundleError(f"{context} must be a lowercase SHA-256 hex digest")
    return value


def archive_filename(name: str, version: str) -> str:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise BundleError(f"noncanonical crate name: {name!r}")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise BundleError(f"noncanonical crate version: {version!r}")
    return f"{name}-{version}.crate"


def acquisition_url(name: str, version: str) -> str:
    return URL_TEMPLATE.format(name=name, version=version)


def lock_records(lock_path: Path) -> list[dict[str, str]]:
    _regular_unlinked_file(lock_path, "lockfile")
    try:
        parsed = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise BundleError(f"cannot parse lockfile {lock_path}: {error}") from error
    result: list[dict[str, str]] = []
    for package in parsed.get("package", []):
        source = package.get("source")
        if not isinstance(source, str) or not source.startswith("registry+"):
            continue
        if source != CRATES_IO_SOURCE:
            raise BundleError(
                f"unapproved registry source for {package.get('name')} "
                f"{package.get('version')}: {source!r}"
            )
        name = package.get("name")
        version = package.get("version")
        checksum = package.get("checksum")
        if not isinstance(name, str) or not isinstance(version, str):
            raise BundleError("registry lock record lacks a string name or version")
        archive_filename(name, version)
        _hex64(checksum, f"lock checksum for {name} {version}")
        result.append(
            {"checksum": checksum, "name": name, "source": source, "version": version}
        )
    result.sort(key=lambda item: (item["name"], item["version"], item["source"]))
    identities = [(item["name"], item["version"], item["source"]) for item in result]
    if len(identities) != len(set(identities)):
        raise BundleError("duplicate registry package identity in lockfile")
    return result


def validate_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BundleError("manifest root must be an object")
    _exact_keys(
        value,
        {
            "acquisition",
            "environment",
            "format",
            "oracle_effect",
            "package_count",
            "packages",
            "subject",
            "tests",
            "workspace",
        },
        "manifest",
    )
    if value["format"] != FORMAT:
        raise BundleError(f"unsupported manifest format: {value['format']!r}")
    acquisition = value["acquisition"]
    if not isinstance(acquisition, dict):
        raise BundleError("acquisition must be an object")
    _exact_keys(
        acquisition,
        {"aggregate_limits", "aggregate_totals", "cache_reuse_permitted", "transport", "url_template"},
        "acquisition",
    )
    if acquisition["cache_reuse_permitted"] is not False:
        raise BundleError("acquisition may not reuse a Cargo or developer cache")
    if acquisition["transport"] != "https" or acquisition["url_template"] != URL_TEMPLATE:
        raise BundleError("acquisition policy is not the required cold HTTPS policy")
    limits = acquisition["aggregate_limits"]
    required_limits = {
        "max_archive_bytes": MAX_ARCHIVE_SIZE,
        "max_bundle_bytes": MAX_BUNDLE_SIZE,
        "max_member_bytes": MAX_MEMBER_SIZE,
        "max_member_count_per_archive": MAX_MEMBER_COUNT,
        "max_total_member_count": MAX_TOTAL_MEMBER_COUNT,
        "max_total_unpacked_bytes": MAX_TOTAL_UNPACKED_SIZE,
        "max_unpacked_bytes_per_archive": MAX_UNPACKED_SIZE,
    }
    if limits != required_limits:
        raise BundleError("aggregate_limits differ from the reviewed fail-closed constants")
    totals = acquisition["aggregate_totals"]
    if not isinstance(totals, dict):
        raise BundleError("aggregate_totals must be an object")
    _exact_keys(totals, {"archive_bytes", "member_count", "unpacked_bytes"}, "aggregate_totals")
    for field in ("archive_bytes", "member_count", "unpacked_bytes"):
        if not isinstance(totals[field], int) or isinstance(totals[field], bool) or totals[field] < 0:
            raise BundleError(f"aggregate_totals.{field} must be a nonnegative integer")

    environment = value["environment"]
    if not isinstance(environment, dict):
        raise BundleError("environment must be an object")
    _exact_keys(
        environment,
        {"cargo_invocation", "host", "host_tools", "network_isolation", "toolchain"},
        "environment",
    )
    if environment["cargo_invocation"] != {
        "locked": True,
        "offline": True,
        "profile": "release",
        "target_linker": "/usr/bin/x86_64-linux-gnu-gcc-13",
    }:
        raise BundleError("Cargo invocation must be release, locked, and offline")
    if not isinstance(environment["host"], str) or not environment["host"]:
        raise BundleError("environment.host must be a nonempty string")
    required_host_tools = [
        {"name": name, "provenance_status": "external_unprovisioned_blocker"}
        for name in (
            "bubblewrap",
            "kernel-and-host-runner",
            "python3",
            "rust-toolchain-distribution",
            "strace",
            "system-c-compiler-and-linker",
        )
    ]
    if environment["host_tools"] != required_host_tools:
        raise BundleError("host tools must remain exact external provenance blockers")
    required_isolation = {
        "bubblewrap_mode": "--unshare-all",
        "hidden_host_paths": ["/run", "/tmp", "/var/run"],
        "mount_policy": "minimal_explicit_mounts_no_host_root_bind",
        "network_trace_policy": "external_strace_exact_fail_closed_network_syscall_allowlist",
    }
    if environment["network_isolation"] != required_isolation:
        raise BundleError("network isolation policy differs from the reviewed minimum")
    toolchain = environment["toolchain"]
    if not isinstance(toolchain, dict):
        raise BundleError("environment.toolchain must be an object")
    _exact_keys(
        toolchain,
        {"cargo_commit", "distribution_status", "llvm", "requested", "rustc_commit"},
        "environment.toolchain",
    )
    if toolchain["distribution_status"] != "external_unprovisioned_blocker":
        raise BundleError("Rust toolchain distribution must remain blocked")
    for field in ("cargo_commit", "rustc_commit"):
        if not isinstance(toolchain[field], str) or not HEX40.fullmatch(toolchain[field]):
            raise BundleError(f"toolchain.{field} must be lowercase SHA-1 hex")
    for field in ("llvm", "requested"):
        if not isinstance(toolchain[field], str) or not toolchain[field]:
            raise BundleError(f"toolchain.{field} must be a nonempty string")

    workspace = value["workspace"]
    if not isinstance(workspace, dict):
        raise BundleError("workspace must be an object")
    _exact_keys(workspace, {"lockfile", "manifest"}, "workspace")
    for field, expected_path in (
        ("lockfile", "verification/Cargo.lock"),
        ("manifest", "verification/Cargo.toml"),
    ):
        record = workspace[field]
        if not isinstance(record, dict):
            raise BundleError(f"workspace.{field} must be an object")
        _exact_keys(record, {"path", "sha256"}, f"workspace.{field}")
        if record["path"] != expected_path:
            raise BundleError(f"workspace.{field}.path is not exact")
        _hex64(record["sha256"], f"workspace.{field}.sha256")

    subject = value["subject"]
    if not isinstance(subject, dict):
        raise BundleError("subject must be an object")
    _exact_keys(
        subject,
        {
            "binding_kind",
            "inputs",
            "rebind_policy",
            "source_commit",
            "source_tree",
            "subsequent_assurance_binding_required",
        },
        "subject",
    )
    if subject["binding_kind"] != "exact_prior_commit_and_tree_candidate_not_self_binding":
        raise BundleError("subject binding must state its non-self-binding semantics")
    if subject["rebind_policy"] != "rerun_after_every_subsequent_subject_change_before_replay":
        raise BundleError("subject rebind policy is not fail closed")
    if subject["subsequent_assurance_binding_required"] is not True:
        raise BundleError("subject candidate must require a subsequent assurance binding")
    for field in ("source_commit", "source_tree"):
        if not isinstance(subject[field], str) or not HEX40.fullmatch(subject[field]):
            raise BundleError(f"subject.{field} must be lowercase Git object hex")
    subject_inputs = subject["inputs"]
    if not isinstance(subject_inputs, dict):
        raise BundleError("subject.inputs must be an object")
    _exact_keys(subject_inputs, {"file_count", "path", "sha256"}, "subject.inputs")
    if subject_inputs["path"] != "verification/oracle-provisioning/subject-inputs.json":
        raise BundleError("subject.inputs.path is not canonical")
    if (
        not isinstance(subject_inputs["file_count"], int)
        or isinstance(subject_inputs["file_count"], bool)
        or subject_inputs["file_count"] < 1
    ):
        raise BundleError("subject.inputs.file_count must be positive")
    _hex64(subject_inputs["sha256"], "subject.inputs.sha256")

    tests = value["tests"]
    if not isinstance(tests, dict):
        raise BundleError("tests must be an object")
    _exact_keys(tests, {"oracle_effect", "target_count", "targets", "test_count"}, "tests")
    if tests["oracle_effect"] != "regression_execution_only_all_oracle_lineage_statuses_remain_blocked":
        raise BundleError("test execution may not promote oracle lineage into evidence")
    targets = tests["targets"]
    if (
        not isinstance(targets, list)
        or tests["target_count"] != EXPECTED_TARGET_COUNT
        or tests["target_count"] != len(targets)
    ):
        raise BundleError(f"tests must bind exactly {EXPECTED_TARGET_COUNT} targets")
    observed_test_count = 0
    previous_target = ""
    for index, target_record in enumerate(targets):
        context = f"tests.targets[{index}]"
        if not isinstance(target_record, dict):
            raise BundleError(f"{context} must be an object")
        _exact_keys(
            target_record,
            {"expected_tests", "source", "source_sha256", "target"},
            context,
        )
        target = target_record["target"]
        if not isinstance(target, str) or not TARGET.fullmatch(target) or target <= previous_target:
            raise BundleError("test target names must be valid and strictly sorted")
        if target_record["source"] != f"tests/{target}.rs":
            raise BundleError(f"{context}.source is not exact")
        _hex64(target_record["source_sha256"], f"{context}.source_sha256")
        expected_tests = target_record["expected_tests"]
        if (
            not isinstance(expected_tests, list)
            or expected_tests != sorted(set(expected_tests))
            or any(not isinstance(test, str) or not TEST.fullmatch(test) for test in expected_tests)
        ):
            raise BundleError(f"{context}.expected_tests must be valid, unique, and sorted")
        observed_test_count += len(expected_tests)
        previous_target = target
    if tests["test_count"] != EXPECTED_TEST_COUNT or observed_test_count != EXPECTED_TEST_COUNT:
        raise BundleError(f"tests must bind exactly {EXPECTED_TEST_COUNT} test names")
    actual_test_semantics = hashlib.sha256(canonical_json(tests)).hexdigest()
    if actual_test_semantics != EXPECTED_TEST_SEMANTICS_SHA256:
        raise BundleError(
            "test semantics differ from the independent immutable code pin: "
            f"expected {EXPECTED_TEST_SEMANTICS_SHA256}, got {actual_test_semantics}"
        )

    if value["oracle_effect"] != "provisioning_only_all_oracle_lineage_statuses_remain_blocked":
        raise BundleError("oracle_effect may not promote provisioning into assurance evidence")
    packages = value["packages"]
    if not isinstance(packages, list) or len(packages) != EXPECTED_PACKAGE_COUNT:
        raise BundleError(f"packages must contain exactly {EXPECTED_PACKAGE_COUNT} records")
    if (
        not isinstance(value["package_count"], int)
        or isinstance(value["package_count"], bool)
        or value["package_count"] != len(packages)
        or value["package_count"] != EXPECTED_PACKAGE_COUNT
    ):
        raise BundleError("package_count does not match packages")
    expected_order: list[tuple[str, str, str]] = []
    computed_totals = {"archive_bytes": 0, "member_count": 0, "unpacked_bytes": 0}
    for index, package in enumerate(packages):
        context = f"packages[{index}]"
        if not isinstance(package, dict):
            raise BundleError(f"{context} must be an object")
        _exact_keys(
            package,
            {"archive", "name", "publisher_claims", "source", "version"},
            context,
        )
        name = package["name"]
        version = package["version"]
        expected_file = archive_filename(name, version)
        if package["source"] != CRATES_IO_SOURCE:
            raise BundleError(f"{context}.source is not the pinned crates.io source")
        archive = package["archive"]
        if not isinstance(archive, dict):
            raise BundleError(f"{context}.archive must be an object")
        _exact_keys(
            archive,
            {"file", "member_count", "sha256", "size", "unpacked_size", "url"},
            f"{context}.archive",
        )
        if archive["file"] != expected_file:
            raise BundleError(f"{context}.archive.file is noncanonical")
        if archive["url"] != acquisition_url(name, version):
            raise BundleError(f"{context}.archive.url is noncanonical")
        _hex64(archive["sha256"], f"{context}.archive.sha256")
        for field in ("member_count", "size", "unpacked_size"):
            if not isinstance(archive[field], int) or isinstance(archive[field], bool):
                raise BundleError(f"{context}.archive.{field} must be an integer")
            if archive[field] < (1 if field != "unpacked_size" else 0):
                raise BundleError(f"{context}.archive.{field} is out of range")
        if archive["size"] > MAX_ARCHIVE_SIZE:
            raise BundleError(f"{context}.archive.size exceeds the reviewed safety limit")
        if archive["member_count"] > MAX_MEMBER_COUNT:
            raise BundleError(f"{context}.archive.member_count exceeds the reviewed safety limit")
        if archive["unpacked_size"] > MAX_UNPACKED_SIZE:
            raise BundleError(f"{context}.archive.unpacked_size exceeds the reviewed safety limit")
        computed_totals["archive_bytes"] += archive["size"]
        computed_totals["member_count"] += archive["member_count"]
        computed_totals["unpacked_bytes"] += archive["unpacked_size"]
        claims = package["publisher_claims"]
        if not isinstance(claims, dict):
            raise BundleError(f"{context}.publisher_claims must be an object")
        _exact_keys(
            claims,
            {"license_expression", "license_file", "license_files", "repository", "vcs"},
            f"{context}.publisher_claims",
        )
        for field in ("license_expression", "license_file", "repository"):
            if claims[field] is not None and not isinstance(claims[field], str):
                raise BundleError(f"{context}.publisher_claims.{field} must be string or null")
        license_files = claims["license_files"]
        if not isinstance(license_files, list):
            raise BundleError(f"{context}.publisher_claims.license_files must be an array")
        last_path = ""
        for entry in license_files:
            if not isinstance(entry, dict):
                raise BundleError(f"{context} license file entry must be an object")
            _exact_keys(entry, {"path", "sha256"}, f"{context} license file")
            if not isinstance(entry["path"], str) or entry["path"] <= last_path:
                raise BundleError(f"{context} license file paths must be strictly sorted")
            _safe_relative(entry["path"], f"{context} license path")
            _hex64(entry["sha256"], f"{context} license file digest")
            last_path = entry["path"]
        vcs = claims["vcs"]
        if vcs is not None:
            if not isinstance(vcs, dict):
                raise BundleError(f"{context}.publisher_claims.vcs must be object or null")
            _exact_keys(
                vcs,
                {"dirty", "git_sha1", "path_in_vcs", "record_sha256"},
                f"{context}.publisher_claims.vcs",
            )
            if not isinstance(vcs["git_sha1"], str) or not re.fullmatch(
                r"[0-9a-f]{40}", vcs["git_sha1"]
            ):
                raise BundleError(f"{context} VCS git_sha1 is not lowercase SHA-1 hex")
            if vcs["path_in_vcs"] is not None and not isinstance(vcs["path_in_vcs"], str):
                raise BundleError(f"{context} VCS path_in_vcs must be string or null")
            if vcs["dirty"] is not None and not isinstance(vcs["dirty"], bool):
                raise BundleError(f"{context} VCS dirty must be boolean or null")
            _hex64(vcs["record_sha256"], f"{context} VCS record digest")
        expected_order.append((name, version, package["source"]))
    if expected_order != sorted(expected_order) or len(expected_order) != len(set(expected_order)):
        raise BundleError("packages must be strictly sorted by unique (name, version, source)")
    if computed_totals != totals:
        raise BundleError("aggregate_totals do not equal the exact package records")
    if computed_totals["archive_bytes"] > MAX_BUNDLE_SIZE:
        raise BundleError("aggregate archive bytes exceed the reviewed bundle limit")
    if computed_totals["member_count"] > MAX_TOTAL_MEMBER_COUNT:
        raise BundleError("aggregate member count exceeds the reviewed bundle limit")
    if computed_totals["unpacked_bytes"] > MAX_TOTAL_UNPACKED_SIZE:
        raise BundleError("aggregate unpacked bytes exceed the reviewed bundle limit")
    return value


def load_manifest(path: Path) -> dict[str, Any]:
    _regular_unlinked_file(path, "manifest")
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BundleError(f"cannot parse manifest {path}: {error}") from error
    if raw != canonical_json(value):
        raise BundleError("manifest bytes are not canonical sorted, indented UTF-8 JSON")
    validated = validate_manifest(value)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_NORMATIVE_MANIFEST_SHA256:
        raise BundleError(
            "normative manifest digest differs from the code-pinned reviewed root: "
            f"expected {EXPECTED_NORMATIVE_MANIFEST_SHA256}, got {digest}"
        )
    return validated


def compare_manifest_to_lock(manifest: dict[str, Any], lock_path: Path) -> None:
    actual_lock_digest = sha256_file(lock_path)
    expected_lock_digest = manifest["workspace"]["lockfile"]["sha256"]
    if actual_lock_digest != expected_lock_digest:
        raise BundleError(
            f"lockfile digest mismatch: expected {expected_lock_digest}, got {actual_lock_digest}"
        )
    expected = [
        {
            "checksum": package["archive"]["sha256"],
            "name": package["name"],
            "source": package["source"],
            "version": package["version"],
        }
        for package in manifest["packages"]
    ]
    actual = lock_records(lock_path)
    if actual != expected:
        raise BundleError("manifest registry package set differs from Cargo.lock")


def _safe_relative(value: str, context: str) -> PurePosixPath:
    if (
        not value
        or "\\" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or value.startswith("/")
    ):
        raise BundleError(f"{context} is not a safe POSIX relative path: {value!r}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise BundleError(f"{context} is not valid Unicode text: {value!r}") from error
    if len(encoded) > MAX_PATH_BYTES:
        raise BundleError(f"{context} exceeds the reviewed path-length limit: {value!r}")
    path = PurePosixPath(value)
    if any(part in ("", ".", "..") for part in path.parts) or str(path) != value:
        raise BundleError(f"{context} is not a canonical POSIX relative path: {value!r}")
    if any(len(part.encode("utf-8")) > MAX_PATH_COMPONENT_BYTES for part in path.parts):
        raise BundleError(f"{context} has an oversized path component: {value!r}")
    return path


def _member_path(member: tarfile.TarInfo, root: str) -> tuple[str, str | None]:
    raw = member.name
    if member.isdir() and raw.endswith("/"):
        raw = raw[:-1]
    path = _safe_relative(raw, "crate member path")
    if path.parts[0] != root:
        raise BundleError(f"crate member is outside canonical root {root!r}: {member.name!r}")
    if len(path.parts) == 1:
        if not member.isdir():
            raise BundleError("crate root member must be a directory")
        return raw, None
    return raw, PurePosixPath(*path.parts[1:]).as_posix()


def _decode_single_gzip_tar(path: Path) -> bytes:
    """Return one bounded gzip member whose tar trailer consumes all bytes."""
    _regular_unlinked_file(path, "archive")
    compressed_size = path.stat().st_size
    if compressed_size < 1 or compressed_size > MAX_ARCHIVE_SIZE:
        raise BundleError(f"crate archive exceeds the reviewed safety limit: {path}")
    try:
        compressed = path.read_bytes()
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = decoder.decompress(compressed, MAX_TAR_STREAM_SIZE + 1)
        if decoder.unconsumed_tail or len(raw) > MAX_TAR_STREAM_SIZE:
            raise BundleError("decompressed tar stream exceeds the reviewed safety limit")
        raw += decoder.flush(MAX_TAR_STREAM_SIZE + 1 - len(raw))
    except (OSError, zlib.error) as error:
        raise BundleError(f"invalid gzip stream {path}: {error}") from error
    if len(raw) > MAX_TAR_STREAM_SIZE:
        raise BundleError("decompressed tar stream exceeds the reviewed safety limit")
    if not decoder.eof:
        raise BundleError("crate archive gzip member is truncated")
    if decoder.unused_data:
        raise BundleError("crate archive has trailing or concatenated gzip data")
    if len(raw) % 512:
        raise BundleError("decompressed tar length is not a 512-byte multiple")
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
        archive.getmembers()
        trailer_offset = archive.offset
        archive.close()
    except (OSError, tarfile.TarError) as error:
        raise BundleError(f"invalid tar stream {path}: {error}") from error
    trailer = raw[trailer_offset:]
    if trailer_offset % 512 or len(trailer) < 1024 or any(trailer):
        raise BundleError("tar stream lacks an exact all-zero end-of-archive trailer")
    return raw


def inspect_archive(
    path: Path, name: str, version: str
) -> tuple[list[tuple[str, int]], int, int]:
    """Return regular-file relative paths/sizes, member count and unpacked size."""
    raw = _decode_single_gzip_tar(path)
    root = f"{name}-{version}"
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            seen: set[str] = set()
            files: list[tuple[str, int]] = []
            unpacked_size = 0
            member_count = 0
            for member in archive:
                member_count += 1
                if member_count > MAX_MEMBER_COUNT:
                    raise BundleError(
                        "crate archive member count exceeds the reviewed safety limit"
                    )
                normalized, relative = _member_path(member, root)
                if normalized in seen:
                    raise BundleError(f"duplicate crate member path: {normalized!r}")
                seen.add(normalized)
                if member.mode & 0o7000:
                    raise BundleError(f"privileged mode bits on crate member: {normalized!r}")
                if member.isdir():
                    if member.size != 0:
                        raise BundleError(f"directory crate member has nonzero size: {normalized!r}")
                    continue
                if not member.isreg():
                    raise BundleError(
                        f"symlink, hardlink, or special crate member rejected: {normalized!r}"
                    )
                if relative is None:
                    raise BundleError("regular crate member has no relative path")
                if relative == ".cargo-checksum.json":
                    raise BundleError("archive may not supply Cargo's generated checksum file")
                if member.size < 0:
                    raise BundleError(f"negative member size: {normalized!r}")
                if member.size > MAX_MEMBER_SIZE:
                    raise BundleError(
                        f"crate member exceeds the reviewed safety limit: {normalized!r}"
                    )
                files.append((relative, member.size))
                unpacked_size += member.size
                if unpacked_size > MAX_UNPACKED_SIZE:
                    raise BundleError(
                        "crate archive unpacked size exceeds the reviewed safety limit"
                    )
            if not member_count or not files:
                raise BundleError("crate archive has no members or no regular files")
            files.sort()
            return files, member_count, unpacked_size
    except (OSError, tarfile.TarError) as error:
        raise BundleError(f"invalid crate archive {path}: {error}") from error


def _read_archive_files(path: Path, name: str, version: str) -> dict[str, bytes]:
    inspect_archive(path, name, version)
    raw = _decode_single_gzip_tar(path)
    root = f"{name}-{version}"
    result: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive.getmembers():
                _, relative = _member_path(member, root)
                if not member.isreg():
                    continue
                if relative is None or relative in result:
                    raise BundleError("duplicate or root regular member")
                stream = archive.extractfile(member)
                if stream is None:
                    raise BundleError(f"cannot read archive member {member.name!r}")
                data = stream.read()
                if len(data) != member.size:
                    raise BundleError(f"truncated archive member {member.name!r}")
                result[relative] = data
    except (OSError, tarfile.TarError) as error:
        raise BundleError(f"cannot read crate archive {path}: {error}") from error
    return result


def publisher_claims(path: Path, name: str, version: str) -> dict[str, Any]:
    files = _read_archive_files(path, name, version)
    cargo_toml = files.get("Cargo.toml")
    if cargo_toml is None:
        raise BundleError(f"{name} {version} lacks normalized Cargo.toml")
    try:
        cargo = tomllib.loads(cargo_toml.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise BundleError(f"invalid normalized Cargo.toml in {name} {version}: {error}") from error
    package = cargo.get("package")
    if not isinstance(package, dict):
        raise BundleError(f"{name} {version} Cargo.toml lacks [package]")
    if package.get("name") != name or package.get("version") != version:
        raise BundleError(f"archive Cargo.toml identity differs for {name} {version}")
    license_files: list[dict[str, str]] = []
    for relative, content in files.items():
        basename = PurePosixPath(relative).name.upper()
        if basename.startswith(("LICENSE", "COPYING", "UNLICENSE")):
            license_files.append(
                {"path": relative, "sha256": hashlib.sha256(content).hexdigest()}
            )
    license_files.sort(key=lambda item: item["path"])
    vcs: dict[str, Any] | None = None
    vcs_raw = files.get(".cargo_vcs_info.json")
    if vcs_raw is not None:
        try:
            record = json.loads(vcs_raw)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise BundleError(f"invalid VCS record in {name} {version}: {error}") from error
        git = record.get("git") if isinstance(record, dict) else None
        sha1 = git.get("sha1") if isinstance(git, dict) else None
        if not isinstance(sha1, str) or not re.fullmatch(r"[0-9a-f]{40}", sha1):
            raise BundleError(f"invalid publisher VCS SHA-1 claim in {name} {version}")
        path_in_vcs = record.get("path_in_vcs")
        if path_in_vcs is not None and not isinstance(path_in_vcs, str):
            raise BundleError(f"invalid path_in_vcs claim in {name} {version}")
        dirty = git.get("dirty")
        if dirty is not None and not isinstance(dirty, bool):
            raise BundleError(f"invalid dirty claim in {name} {version}")
        vcs = {
            "dirty": dirty,
            "git_sha1": sha1,
            "path_in_vcs": path_in_vcs,
            "record_sha256": hashlib.sha256(vcs_raw).hexdigest(),
        }
    return {
        "license_expression": package.get("license") if isinstance(package.get("license"), str) else None,
        "license_file": package.get("license-file") if isinstance(package.get("license-file"), str) else None,
        "license_files": license_files,
        "repository": package.get("repository") if isinstance(package.get("repository"), str) else None,
        "vcs": vcs,
    }


def archive_facts(path: Path, name: str, version: str) -> dict[str, Any]:
    if path.stat().st_size > MAX_ARCHIVE_SIZE:
        raise BundleError(f"crate archive exceeds the reviewed safety limit: {path}")
    files, member_count, unpacked_size = inspect_archive(path, name, version)
    del files
    return {
        "file": archive_filename(name, version),
        "member_count": member_count,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
        "unpacked_size": unpacked_size,
        "url": acquisition_url(name, version),
    }


def _regular_unlinked_file(path: Path, context: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BundleError(f"cannot stat {context} {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise BundleError(f"{context} is not a regular file: {path}")
    if metadata.st_nlink != 1:
        raise BundleError(f"{context} has {metadata.st_nlink} hard links: {path}")


def verify_bundle(manifest: dict[str, Any], bundle_dir: Path) -> None:
    try:
        metadata = bundle_dir.lstat()
    except OSError as error:
        raise BundleError(f"cannot stat bundle directory {bundle_dir}: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BundleError("bundle path must be a real directory, not a symlink")
    expected = {package["archive"]["file"] for package in manifest["packages"]}
    try:
        actual = {entry.name for entry in os.scandir(bundle_dir)}
    except OSError as error:
        raise BundleError(f"cannot enumerate bundle directory: {error}") from error
    if actual != expected:
        raise BundleError(
            f"bundle entries differ: missing={sorted(expected - actual)!r} "
            f"extra={sorted(actual - expected)!r}"
        )
    actual_totals = {"archive_bytes": 0, "member_count": 0, "unpacked_bytes": 0}
    for package in manifest["packages"]:
        archive = package["archive"]
        path = bundle_dir / archive["file"]
        _regular_unlinked_file(path, "archive")
        if path.stat().st_size != archive["size"]:
            raise BundleError(f"archive size mismatch: {archive['file']}")
        digest = sha256_file(path)
        if digest != archive["sha256"]:
            raise BundleError(
                f"archive checksum mismatch for {archive['file']}: "
                f"expected {archive['sha256']}, got {digest}"
            )
        facts = archive_facts(path, package["name"], package["version"])
        if facts != archive:
            raise BundleError(f"archive structural facts differ: {archive['file']}")
        actual_totals["archive_bytes"] += facts["size"]
        actual_totals["member_count"] += facts["member_count"]
        actual_totals["unpacked_bytes"] += facts["unpacked_size"]
        if actual_totals["archive_bytes"] > MAX_BUNDLE_SIZE:
            raise BundleError("actual aggregate archive bytes exceed the reviewed bundle limit")
        if actual_totals["member_count"] > MAX_TOTAL_MEMBER_COUNT:
            raise BundleError("actual aggregate member count exceeds the reviewed bundle limit")
        if actual_totals["unpacked_bytes"] > MAX_TOTAL_UNPACKED_SIZE:
            raise BundleError("actual aggregate unpacked bytes exceed the reviewed bundle limit")
        claims = publisher_claims(path, package["name"], package["version"])
        if claims != package["publisher_claims"]:
            raise BundleError(f"publisher claims differ: {archive['file']}")
    if actual_totals != manifest["acquisition"]["aggregate_totals"]:
        raise BundleError("actual bundle aggregate facts differ from the normative manifest")


def _filesystem_entries(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    stack: list[tuple[Path, PurePosixPath | None]] = [(root, None)]
    while stack:
        directory, relative_root = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise BundleError(f"cannot enumerate materialized directory {directory}: {error}") from error
        for entry in entries:
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise BundleError(f"cannot stat materialized entry {entry.path}: {error}") from error
            relative = (
                PurePosixPath(entry.name)
                if relative_root is None
                else relative_root / entry.name
            )
            _safe_relative(relative.as_posix(), "materialized vendor path")
            path = Path(entry.path)
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != 0o755:
                    raise BundleError(f"materialized directory mode is not 0755: {path}")
                directories.add(relative.as_posix())
                stack.append((path, relative))
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise BundleError(f"materialized file has hard links: {path}")
                if stat.S_IMODE(metadata.st_mode) != 0o644:
                    raise BundleError(f"materialized file mode is not 0644: {path}")
                files.add(relative.as_posix())
            else:
                raise BundleError(f"materialized symlink or special entry rejected: {path}")
    return files, directories


def verify_vendor(manifest: dict[str, Any], bundle_dir: Path, vendor_dir: Path) -> None:
    try:
        vendor_metadata = vendor_dir.lstat()
    except OSError as error:
        raise BundleError(f"cannot stat vendor directory: {error}") from error
    if not stat.S_ISDIR(vendor_metadata.st_mode) or stat.S_ISLNK(vendor_metadata.st_mode):
        raise BundleError("vendor path must be a real directory")
    if stat.S_IMODE(vendor_metadata.st_mode) != 0o755:
        raise BundleError("vendor directory mode is not 0755")
    expected_dirs = {f"{package['name']}-{package['version']}" for package in manifest["packages"]}
    try:
        entries = {entry.name: entry for entry in os.scandir(vendor_dir)}
    except OSError as error:
        raise BundleError(f"cannot enumerate vendor directory: {error}") from error
    if set(entries) != expected_dirs:
        raise BundleError(
            f"vendor crates differ: missing={sorted(expected_dirs - set(entries))!r} "
            f"extra={sorted(set(entries) - expected_dirs)!r}"
        )
    for package in manifest["packages"]:
        crate_id = f"{package['name']}-{package['version']}"
        crate_dir = vendor_dir / crate_id
        metadata = crate_dir.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise BundleError(f"vendor crate is not a real directory: {crate_id}")
        if stat.S_IMODE(metadata.st_mode) != 0o755:
            raise BundleError(f"vendor crate mode is not 0755: {crate_id}")
        archive_path = bundle_dir / package["archive"]["file"]
        _regular_unlinked_file(archive_path, "archive")
        if (
            archive_path.stat().st_size != package["archive"]["size"]
            or sha256_file(archive_path) != package["archive"]["sha256"]
        ):
            raise BundleError(f"archive changed before vendor verification: {crate_id}")
        contents = _read_archive_files(archive_path, package["name"], package["version"])
        checksums = {
            relative: hashlib.sha256(content).hexdigest()
            for relative, content in sorted(contents.items())
        }
        checksum_record = {
            "files": checksums,
            "package": package["archive"]["sha256"],
        }
        expected_files = set(contents) | {".cargo-checksum.json"}
        expected_directories: set[str] = set()
        for relative in expected_files:
            parent = PurePosixPath(relative).parent
            while parent != PurePosixPath("."):
                expected_directories.add(parent.as_posix())
                parent = parent.parent
        actual_files, actual_directories = _filesystem_entries(crate_dir)
        if actual_files != expected_files:
            raise BundleError(
                f"vendor files differ for {crate_id}: "
                f"missing={sorted(expected_files - actual_files)!r} "
                f"extra={sorted(actual_files - expected_files)!r}"
            )
        if actual_directories != expected_directories:
            raise BundleError(
                f"vendor directories differ for {crate_id}: "
                f"missing={sorted(expected_directories - actual_directories)!r} "
                f"extra={sorted(actual_directories - expected_directories)!r}"
            )
        checksum_path = crate_dir / ".cargo-checksum.json"
        if checksum_path.read_bytes() != canonical_json(checksum_record):
            raise BundleError(f"vendor checksum record differs for {crate_id}")
        for relative, expected_content in contents.items():
            path = crate_dir.joinpath(*PurePosixPath(relative).parts)
            if sha256_file(path) != checksums[relative] or path.read_bytes() != expected_content:
                raise BundleError(f"materialized vendor content differs: {crate_id}/{relative}")


def manifest_package(lock_record: dict[str, str], archive_path: Path) -> dict[str, Any]:
    name = lock_record["name"]
    version = lock_record["version"]
    _regular_unlinked_file(archive_path, "archive")
    digest = sha256_file(archive_path)
    if digest != lock_record["checksum"]:
        raise BundleError(
            f"download checksum differs from Cargo.lock for {name} {version}: "
            f"expected {lock_record['checksum']}, got {digest}"
        )
    facts = archive_facts(archive_path, name, version)
    return {
        "archive": facts,
        "name": name,
        "publisher_claims": publisher_claims(archive_path, name, version),
        "source": lock_record["source"],
        "version": version,
    }


def extract_to_vendor(archive_path: Path, package: dict[str, Any], vendor_dir: Path) -> None:
    name = package["name"]
    version = package["version"]
    _regular_unlinked_file(archive_path, "archive")
    if (
        archive_path.stat().st_size != package["archive"]["size"]
        or sha256_file(archive_path) != package["archive"]["sha256"]
    ):
        raise BundleError(f"archive changed before extraction: {name}-{version}")
    files, _, _ = inspect_archive(archive_path, name, version)
    expected_sizes = dict(files)
    contents = _read_archive_files(archive_path, name, version)
    if set(contents) != set(expected_sizes):
        raise BundleError(f"archive contents changed during verification: {archive_path}")
    crate_dir = vendor_dir / f"{name}-{version}"
    crate_dir.mkdir(mode=0o755)
    crate_dir.chmod(0o755)
    checksums: dict[str, str] = {}
    for relative in sorted(contents):
        data = contents[relative]
        if len(data) != expected_sizes[relative]:
            raise BundleError(f"archive member size changed: {relative}")
        destination = crate_dir.joinpath(*PurePosixPath(relative).parts)
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        parent = destination.parent
        while parent != crate_dir.parent:
            parent.chmod(0o755)
            parent = parent.parent
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        os.fchmod(descriptor, 0o644)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        checksums[relative] = hashlib.sha256(data).hexdigest()
    checksum_record = {
        "files": checksums,
        "package": package["archive"]["sha256"],
    }
    checksum_path = crate_dir / ".cargo-checksum.json"
    descriptor = os.open(
        checksum_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    os.fchmod(descriptor, 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(canonical_json(checksum_record))
