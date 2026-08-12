#!/usr/bin/env python3
"""Verify dcrypt's public-API assurance ledger without third-party packages.

The committed snapshot is an exact, normalized projection of rustdoc JSON.  A
normal verification regenerates the projection with the pinned toolchain and
fails closed when a reachable export or public API member is not present in the
classified snapshot.  ``--self-test`` is intentionally offline and exercises
the positive and required negative fixtures without invoking Cargo or rustdoc.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any, Iterable


SCHEMA_VERSION = 2
SNAPSHOT_SCHEMA_VERSION = 2
UNCLASSIFIED = "UNCLASSIFIED"
PROFILE_ALL = "all-features"
PROFILE_BARE = "no-default-features"
PROFILE_NOSTD = "boundary-no-std"
CLASSIFICATIONS = {
    "supported-operation",
    "transitional-legacy",
    "metadata-only",
    "internal-like-low-level",
    "intentionally-unsupported",
}
OPERATION_CLASSIFICATIONS = {"supported-operation", "transitional-legacy"}
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
HEX_GIT_ID = re.compile(r"^[0-9a-f]{40}$")
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
SUBJECT_EXCLUDED_MUTABLE_ROOTS = {
    ".git",
    "assurance",
    "fuzz/artifacts",
    "fuzz/corpus",
    "fuzz/target",
    "internal",
    "migration/legacy-xchacha20poly1305/target",
    "target",
    "tools/__pycache__",
    "tools/bench-processor/target",
    "verification/target",
}
SUBJECT_EXCLUDED_FILES = {
    ".gitignore",
    "tools/bench-processor/Cargo.lock",
    "tools/cargo_snapshot.sh",
    "tools/codebase_snapshot.sh",
    "tools/codebase_snapshot2.sh",
    "tools/tree.sh",
}
CALLABLE_KINDS = {
    "assoc_const", "constant", "function", "macro", "static", "trait", "trait_impl"
}
DATA_KINDS = {"field", "variant"}
OPERATION_TRAIT_MARKERS = (
    "AeadDecryptOperation", "AeadEncryptOperation", "AuthenticatedCipher",
    "BlockCipher}", "BlockCipherMode}", "DecryptOperation}", "DeriveKeyXof}",
    "EncryptOperation}", "ExtendableOutputFunction}", "HashFunction}",
    "KdfOperation}", "KeyDerivationFunction}", "KeyedXof}", "MacAlgorithm}",
    "Operation}", "PasswordHashFunction}", "StreamCipher}",
    "::Kem}", "::Pke}", "::Signature}", "::Aead}",
)

BUILD_SHAPING_ENV_EXACT = {
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTDOC",
    "CARGO_BUILD_RUSTDOCFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_TARGET_DIR",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
}
BUILD_SHAPING_ENV_PATTERN = re.compile(
    r"^CARGO_TARGET_.+_(?:RUSTFLAGS|RUSTDOCFLAGS|LINKER|RUNNER)$"
)
TARGET_CFG_NON_API_ALLOWLIST = {
    "crates/algorithms/src/aead/chacha20poly1305/tests.rs": {
        '#[cfg(target_pointer_width="64")]',
    },
    "crates/algorithms/src/aead/gcm/tests.rs": {
        '#[cfg(target_pointer_width="64")]',
    },
    # These two exact block-local queries sit inside one unconditional,
    # inventoried public function.  A new item-level target cfg in this file
    # does not inherit the exception.
    "crates/internal/src/lib.rs": {
        '#[cfg(target_feature="sse2")]',
        '#[cfg(not(target_feature="sse2"))]',
    },
}

# These four historical evidence rows previously accepted free-form libtest
# filters.  Two of those filters selected zero tests while Cargo still exited
# successfully.  Package B binds them to one exact cold runner which itself
# code-pins the six target names, all 30 test names, their source bytes, the
# complete verification lock closure, and Cargo's release/locked/offline mode.
ORACLE_REPLAY_COMMAND = (
    'python3 -B verification/oracle-provisioning/replay.py '
    '--manifest verification/oracle-provisioning/manifest.json '
    '--lock verification/Cargo.lock '
    '--archives "${DCRYPT_ORACLE_ARCHIVES:?}" '
    '--materialized "${DCRYPT_ORACLE_MATERIALIZED:?}" '
    '--toolchain-root "${DCRYPT_ORACLE_TOOLCHAIN_ROOT:?}"'
)
ORACLE_REPLAY_EVIDENCE_IDS = {
    "acvp-traditional-ec",
    "acvp-post-quantum",
    "bls-interoperability",
    "xchacha-interoperability",
}
ORACLE_REPLAY_REQUIRED_ARTIFACTS = {
    "verification/Cargo.lock",
    "verification/Cargo.toml",
    "verification/oracle-provisioning/bundle_lib.py",
    "verification/oracle-provisioning/manifest.json",
    "verification/oracle-provisioning/replay.py",
    "verification/oracle-provisioning/run-targets.py",
    "verification/oracle-provisioning/subject_lib.py",
    "verification/oracle-provisioning/subject-inputs.json",
    "verification/tests/bls12_381_interop.rs",
    "verification/tests/ethereum_consensus_bls.rs",
    "verification/tests/legacy_xchacha20poly1305.rs",
    "verification/tests/ml_dsa_interop.rs",
    "verification/tests/traditional_ec_interop.rs",
    "verification/tests/xchacha20poly1305.rs",
}


def subject_path_included(path_value: str) -> bool:
    """Select every tracked input under the exact reviewed subject roots."""

    normalized = path_value[2:] if path_value.startswith("./") else path_value
    if normalized in SUBJECT_EXCLUDED_FILES:
        return False
    if normalized == "assurance" or normalized.startswith("assurance/"):
        return False
    if normalized in SUBJECT_ROOT_FILES:
        return True
    return True


def target_profile(mode: str, target: str) -> str:
    return f"{mode}/{target}"


def policy_inventory_profiles(policy: dict[str, Any]) -> list[str]:
    targets = policy.get("targets", {})
    if not isinstance(targets, dict) or not all(
        isinstance(key, str) and isinstance(value, str) and value
        for key, value in targets.items()
    ):
        raise AssuranceFailure("implementation boundary has an invalid target map")
    nostd_target = targets.get("no-std")
    if not isinstance(nostd_target, str):
        raise AssuranceFailure("implementation boundary has no no-std target")
    profiles = [
        target_profile(PROFILE_ALL, target)
        for label, target in targets.items()
        if label != "no-std"
    ]
    profiles.append(target_profile(PROFILE_NOSTD, nostd_target))
    return sorted(profiles)


def ledger_snapshot_profiles(ledger: dict[str, Any]) -> list[str]:
    profiles: set[str] = set()
    for record in ledger.get("profile", []):
        if not isinstance(record, dict) or record.get("api-inventory") is not True:
            continue
        if record.get("mode") == PROFILE_NOSTD:
            target = record.get("target")
            if isinstance(target, str):
                profiles.add(target_profile(PROFILE_NOSTD, target))
        elif isinstance(record.get("id"), str):
            profiles.add(record["id"])
    return sorted(profiles)


class AssuranceFailure(Exception):
    """A deterministic verification failure suitable for a release gate."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            return tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise AssuranceFailure(f"cannot read TOML {path}: {error}") from error


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            value = json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        raise AssuranceFailure(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise AssuranceFailure(f"JSON root must be an object: {path}")
    return value


def git_blob_sha256s(
    repo: Path, object_ids: Iterable[str]
) -> tuple[dict[str, str], str | None]:
    """Hash many bound blobs through one fail-closed `git cat-file --batch`."""

    identifiers = sorted(set(object_ids))
    if not identifiers:
        return {}, None
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"], cwd=repo,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    stdout, stderr = process.communicate(
        ("\n".join(identifiers) + "\n").encode("ascii")
    )
    if process.returncode != 0:
        return {}, stderr.decode("utf-8", "replace").strip() or "git cat-file failed"
    cursor = 0
    result: dict[str, str] = {}
    for expected in identifiers:
        newline = stdout.find(b"\n", cursor)
        if newline < 0:
            return {}, "truncated git cat-file header"
        header = stdout[cursor:newline].decode("ascii", "replace")
        cursor = newline + 1
        parts = header.split(" ")
        if len(parts) != 3 or parts[0] != expected or parts[1] != "blob":
            return {}, f"unexpected git cat-file header: {header}"
        try:
            size = int(parts[2])
        except ValueError:
            return {}, f"invalid git cat-file size: {header}"
        end = cursor + size
        if end >= len(stdout) or stdout[end:end + 1] != b"\n":
            return {}, f"truncated git cat-file blob: {expected}"
        result[expected] = hashlib.sha256(stdout[cursor:end]).hexdigest()
        cursor = end + 1
    if cursor != len(stdout):
        return {}, "unexpected trailing git cat-file output"
    return result, None


def validate_subject_manifest(
    manifest: dict[str, Any], *, repo: Path, source_commit: Any, source_tree: Any
) -> list[str]:
    """Bind the exact committed production/evidence subject and current bytes.

    The manifest is deliberately anchored twice: every digest must match the
    immutable Git object named by ``source_commit`` and the current worktree.
    Merely regenerating a manifest after an implementation change therefore
    cannot make stale evidence current.  Only files outside the explicit
    subject (for example, the assurance implementation itself) may differ from
    the bound commit.
    """

    errors: list[str] = []
    if manifest.get("schema_version") != 1:
        errors.append("subject manifest schema_version mismatch")
    if (
        manifest.get("source_commit") != source_commit
        or manifest.get("source_tree") != source_tree
    ):
        errors.append("subject manifest source provenance mismatch")
    roots = manifest.get("roots")
    root_files = manifest.get("root_files")
    absent_build_inputs = manifest.get("absent_build_inputs")
    if (
        roots != SUBJECT_ROOTS
        or root_files != SUBJECT_ROOT_FILES
        or absent_build_inputs != SUBJECT_ABSENT_BUILD_INPUTS
        or manifest.get("include_policy") != SUBJECT_INCLUDE_POLICY
    ):
        return [*errors, "subject manifest roots/root_files/absence sentinels are invalid"]
    if not isinstance(source_commit, str) or HEX_GIT_ID.fullmatch(source_commit) is None:
        return [*errors, "subject manifest cannot resolve an invalid source commit"]

    resolved_tree = run_command(
        ["git", "rev-parse", f"{source_commit}^{{tree}}"], cwd=repo
    )
    if resolved_tree.returncode != 0 or resolved_tree.stdout.strip() != source_tree:
        errors.append("subject manifest source tree does not match bound commit")

    scope = [*roots, *root_files, *absent_build_inputs]
    tree_result = run_command(
        ["git", "ls-tree", "-r", "-z", "--full-tree", source_commit, "--", *scope],
        cwd=repo,
        text=False,
    )
    committed: dict[str, tuple[str, str]] = {}
    all_bound_paths: set[str] = set()
    if tree_result.returncode != 0:
        return [*errors, "subject manifest cannot inspect bound Git tree"]
    for raw_record in tree_result.stdout.split(b"\0"):
        if not raw_record:
            continue
        try:
            metadata, raw_path = raw_record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path_value = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            errors.append("subject manifest encountered an invalid Git tree record")
            continue
        if object_type != "blob" or mode == "120000":
            errors.append(f"subject manifest scope contains a non-regular Git entry: {path_value}")
            continue
        all_bound_paths.add(path_value)
        if subject_path_included(path_value):
            committed[path_value] = (object_id, mode)

    listed_result = run_command(
        [
            "git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
            "--", *scope,
        ],
        cwd=repo,
        text=False,
    )
    if listed_result.returncode != 0:
        return [*errors, "subject manifest cannot inspect current subject paths"]
    all_current_paths = {
        value.decode("utf-8")
        for value in listed_result.stdout.split(b"\0")
        if value
    }
    current_paths = {path for path in all_current_paths if subject_path_included(path)}
    committed_paths = set(committed)
    unexpectedly_bound = all_bound_paths & set(absent_build_inputs)
    if unexpectedly_bound:
        errors.append(
            "subject manifest absence sentinel exists in bound commit: "
            f"{sorted(unexpectedly_bound)}"
        )
    unexpectedly_current = all_current_paths & set(absent_build_inputs)
    unexpectedly_current.update(
        path_value
        for path_value in absent_build_inputs
        if os.path.lexists(repo / path_value)
    )
    if unexpectedly_current:
        errors.append(
            "subject manifest absence sentinel exists in current tree: "
            f"{sorted(unexpectedly_current)}"
        )
    if current_paths != committed_paths:
        errors.append(
            "subject manifest current/bound path set mismatch: "
            f"new={sorted(current_paths-committed_paths)}, "
            f"removed={sorted(committed_paths-current_paths)}"
        )
    rows = manifest.get("files")
    declared: dict[str, tuple[str, str]] = {}
    if not isinstance(rows, list):
        errors.append("subject manifest files must be an array")
        rows = []
    for offset, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"subject manifest files[{offset}] must be an object")
            continue
        path_value, digest, git_mode = row.get("path"), row.get("sha256"), row.get("git_mode")
        if (
            not valid_nonempty_string(path_value)
            or not isinstance(digest, str)
            or HEX_SHA256.fullmatch(digest) is None
            or git_mode not in {"100644", "100755"}
        ):
            errors.append(f"subject manifest files[{offset}] has invalid path/digest/mode")
            continue
        if path_value in declared:
            errors.append(f"subject manifest has duplicate path: {path_value}")
            continue
        declared[path_value] = (digest, git_mode)
    if set(declared) != committed_paths:
        errors.append(
            "subject manifest path set mismatch: "
            f"missing={sorted(committed_paths-set(declared))}, "
            f"stale={sorted(set(declared)-committed_paths)}"
        )
    blob_digests, blob_error = git_blob_sha256s(
        repo, (object_id for object_id, _mode in committed.values())
    )
    if blob_error is not None:
        errors.append(f"subject manifest cannot read bound blobs: {blob_error}")
    for path_value, (digest, git_mode) in declared.items():
        commit_entry = committed.get(path_value)
        if commit_entry is not None:
            if commit_entry[1] != git_mode:
                errors.append(f"subject manifest bound-commit mode mismatch: {path_value}")
            if blob_error is None and blob_digests.get(commit_entry[0]) != digest:
                errors.append(f"subject manifest bound-commit digest mismatch: {path_value}")
        path = safe_repo_file(repo, path_value, f"subject file {path_value}", errors)
        if path is not None:
            if sha256_file(path) != digest:
                errors.append(f"subject manifest current digest mismatch: {path_value}")
            actual_executable = bool(os.lstat(path).st_mode & 0o111)
            expected_executable = git_mode == "100755"
            if actual_executable != expected_executable:
                errors.append(f"subject manifest current mode mismatch: {path_value}")
    return errors


def subject_manifest_document(
    *, repo: Path, source_commit: str, source_tree: str
) -> dict[str, Any]:
    """Create the exact tracked-blob subject manifest for a bound commit."""

    if HEX_GIT_ID.fullmatch(source_commit) is None or HEX_GIT_ID.fullmatch(source_tree) is None:
        raise AssuranceFailure("cannot generate subject manifest for invalid Git provenance")
    resolved_tree = run_command(
        ["git", "rev-parse", f"{source_commit}^{{tree}}"], cwd=repo
    )
    if resolved_tree.returncode != 0 or resolved_tree.stdout.strip() != source_tree:
        raise AssuranceFailure("subject source tree does not match source commit")
    scope = [*SUBJECT_ROOTS, *SUBJECT_ROOT_FILES, *SUBJECT_ABSENT_BUILD_INPUTS]
    listing = run_command(
        ["git", "ls-tree", "-r", "-z", "--full-tree", source_commit, "--", *scope],
        cwd=repo,
        text=False,
    )
    if listing.returncode != 0:
        raise AssuranceFailure("cannot enumerate bound subject tree")
    rows: list[dict[str, str]] = []
    bound_paths: set[str] = set()
    for raw_record in listing.stdout.split(b"\0"):
        if not raw_record:
            continue
        metadata, raw_path = raw_record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        path_value = raw_path.decode("utf-8")
        if object_type != "blob" or mode == "120000":
            raise AssuranceFailure(f"subject contains non-regular Git entry: {path_value}")
        if not subject_path_included(path_value):
            continue
        bound_paths.add(path_value)
        blob = run_command(["git", "cat-file", "blob", object_id], cwd=repo, text=False)
        if blob.returncode != 0:
            raise AssuranceFailure(f"cannot read bound subject blob: {path_value}")
        rows.append(
            {
                "path": path_value,
                "sha256": hashlib.sha256(blob.stdout).hexdigest(),
                "git_mode": mode,
            }
        )
    forbidden = bound_paths & set(SUBJECT_ABSENT_BUILD_INPUTS)
    if forbidden:
        raise AssuranceFailure(
            f"declared absent build input exists in bound commit: {sorted(forbidden)}"
        )
    return {
        "schema_version": 1,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "roots": SUBJECT_ROOTS,
        "root_files": SUBJECT_ROOT_FILES,
        "absent_build_inputs": SUBJECT_ABSENT_BUILD_INPUTS,
        "include_policy": SUBJECT_INCLUDE_POLICY,
        "files": sorted(rows, key=lambda row: row["path"]),
    }


def validate_acvp_vector_manifest(
    vector_manifest: dict[str, Any], *, subject_manifest: dict[str, Any],
    source_commit: Any, source_tree: Any,
) -> list[str]:
    """Require exact row-level provenance for every bound ACVP vector byte."""

    errors: list[str] = []
    root = "tests/src/vectors/acvp_json"
    if vector_manifest.get("schema_version") != 1:
        errors.append("ACVP vector manifest schema_version mismatch")
    if (
        vector_manifest.get("source_commit") != source_commit
        or vector_manifest.get("source_tree") != source_tree
    ):
        errors.append("ACVP vector manifest source provenance mismatch")
    if vector_manifest.get("root") != root:
        errors.append("ACVP vector manifest root mismatch")
    bound = {
        str(row.get("path")): str(row.get("sha256"))
        for row in subject_manifest.get("files", [])
        if isinstance(row, dict)
        and isinstance(row.get("path"), str)
        and (
            row["path"] == root or row["path"].startswith(root + "/")
        )
    }
    rows = vector_manifest.get("files")
    declared: dict[str, str] = {}
    if not isinstance(rows, list):
        return [*errors, "ACVP vector manifest files must be an array"]
    for offset, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"ACVP vector manifest files[{offset}] must be an object")
            continue
        path, digest = row.get("path"), row.get("sha256")
        if (
            not isinstance(path, str) or not path.startswith(root + "/")
            or not isinstance(digest, str) or HEX_SHA256.fullmatch(digest) is None
        ):
            errors.append(f"ACVP vector manifest files[{offset}] is invalid")
            continue
        if path in declared:
            errors.append(f"ACVP vector manifest has duplicate path: {path}")
        declared[path] = digest
    if declared != bound:
        errors.append(
            "ACVP vector manifest differs from bound corpus: "
            f"missing={sorted(set(bound)-set(declared))}, "
            f"stale={sorted(set(declared)-set(bound))}, "
            f"digest-mismatch={sorted(path for path in set(bound)&set(declared) if bound[path] != declared[path])}"
        )
    return errors


def build_environment_preflight(repo: Path) -> list[str]:
    """Fail before invoking Cargo/rustdoc when ambient state can shape a build."""

    errors: list[str] = []
    for name, value in sorted(os.environ.items()):
        if not value:
            continue
        if name in BUILD_SHAPING_ENV_EXACT or BUILD_SHAPING_ENV_PATTERN.fullmatch(name):
            errors.append(f"build-shaping environment is not permitted: {name}")

    config_candidates: set[Path] = set()
    current = repo.resolve()
    for parent in (current, *current.parents):
        config_candidates.add(parent / ".cargo" / "config")
        config_candidates.add(parent / ".cargo" / "config.toml")
    cargo_home_value = os.environ.get("CARGO_HOME")
    cargo_home = (
        Path(cargo_home_value).expanduser()
        if cargo_home_value
        else Path.home() / ".cargo"
    )
    config_candidates.add(cargo_home / "config")
    config_candidates.add(cargo_home / "config.toml")
    for candidate in sorted(config_candidates, key=lambda path: str(path)):
        if os.path.lexists(candidate):
            errors.append(f"ambient Cargo configuration is not permitted: {candidate}")
    return errors


def rust_attributes(source: str) -> Iterable[str]:
    """Yield balanced outer/inner Rust attributes conservatively."""

    offset = 0
    while True:
        match = re.search(r"#\s*!?\s*\[", source[offset:])
        if match is None:
            return
        start = offset + match.start()
        bracket = source.find("[", start, offset + match.end() + 1)
        depth = 1
        cursor = bracket + 1
        in_string = False
        escaped = False
        while cursor < len(source) and depth:
            char = source[cursor]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
            cursor += 1
        if depth:
            # Malformed source will fail Rust compilation; retain the tail so a
            # suspicious cfg is not silently ignored by this policy scan.
            yield source[start:]
            return
        yield source[start:cursor]
        offset = cursor


def not_subexpressions(attribute: str) -> Iterable[str]:
    for match in re.finditer(r"\bnot\s*\(", attribute):
        start = match.end() - 1
        depth = 1
        cursor = start + 1
        in_string = False
        escaped = False
        while cursor < len(attribute) and depth:
            char = attribute[cursor]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            cursor += 1
        yield attribute[start + 1:cursor - 1] if depth == 0 else attribute[start + 1:]


def under_exact_exclusion(relative: str) -> bool:
    return any(
        relative == root or relative.startswith(root + "/")
        for root in SUBJECT_EXCLUDED_MUTABLE_ROOTS
    )


def validate_metadata_source_paths(
    metadata: dict[str, Any], *, repo: Path, manifest: dict[str, Any]
) -> tuple[list[str], set[str]]:
    """Bind Cargo-selected manifests, build scripts, and target source files."""

    errors: list[str] = []
    targets: set[str] = set()
    bound = {
        str(row.get("path"))
        for row in manifest.get("files", [])
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    workspace = set(metadata.get("workspace_members", []))
    for package in metadata.get("packages", []):
        if not isinstance(package, dict) or package.get("id") not in workspace:
            continue
        manifest_path = package.get("manifest_path")
        if not isinstance(manifest_path, str):
            errors.append("Cargo package has no manifest_path")
            continue
        try:
            manifest_relative = Path(manifest_path).resolve().relative_to(repo).as_posix()
        except (OSError, ValueError):
            errors.append(f"Cargo manifest escapes the repository: {manifest_path}")
            continue
        if manifest_relative not in bound:
            errors.append(f"Cargo manifest is absent from the bound subject: {manifest_relative}")
        package_root = (repo / manifest_relative).parent
        for target in package.get("targets", []):
            if not isinstance(target, dict) or not isinstance(target.get("src_path"), str):
                errors.append(f"Cargo target in {manifest_relative} has no src_path")
                continue
            source_value = str(target["src_path"])
            kinds = target.get("kind", [])
            if isinstance(kinds, list) and "custom-build" in kinds:
                errors.append(
                    f"Cargo build scripts are not permitted by the Leg 2 inventory: {source_value}"
                )
            try:
                source = Path(source_value).resolve()
                relative = source.relative_to(repo).as_posix()
                source.relative_to(package_root.resolve())
            except (OSError, ValueError):
                errors.append(
                    f"Cargo target source escapes its package/repository: {source_value}"
                )
                continue
            if under_exact_exclusion(relative):
                errors.append(f"Cargo target source uses a mutable/output root: {relative}")
            if relative not in bound:
                errors.append(f"Cargo target source is absent from the bound subject: {relative}")
            path_errors: list[str] = []
            safe_repo_file(repo, relative, f"Cargo target source {relative}", path_errors)
            errors.extend(path_errors)
            targets.add(relative)
    return sorted(set(errors)), targets


def validate_source_policy(
    repo: Path, manifest: dict[str, Any], *, metadata_target_paths: set[str] | None = None
) -> list[str]:
    """Reject build/inventory inputs which are invisible to the bound subject."""

    errors: list[str] = []
    tracked_result = run_command(["git", "ls-files", "-z", "--cached"], cwd=repo, text=False)
    if tracked_result.returncode != 0:
        return ["cannot enumerate tracked source-policy inputs"]
    tracked = {
        value.decode("utf-8") for value in tracked_result.stdout.split(b"\0") if value
    }

    # Walk with lstat/scandir independently of Git ignore rules.  Every
    # ignored/untracked file beneath a subject root is rejected, regardless of
    # extension; only five exact, reviewed mutable/output subtrees are pruned.
    def walk(directory: Path) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda child: child.name)
        except OSError:
            errors.append(f"cannot inspect source-policy directory: {directory}")
            return
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(repo).as_posix()
            try:
                mode = child.stat(follow_symlinks=False).st_mode
            except OSError:
                errors.append(f"cannot inspect source-policy input: {relative}")
                continue
            if stat.S_ISLNK(mode):
                errors.append(f"symlink is not permitted in assurance subject: {relative}")
                continue
            if relative in SUBJECT_EXCLUDED_FILES:
                continue
            if under_exact_exclusion(relative):
                if not stat.S_ISDIR(mode):
                    errors.append(f"mutable/output exclusion is not a directory: {relative}")
                continue
            if stat.S_ISDIR(mode):
                walk(path)
            elif stat.S_ISREG(mode):
                if relative not in tracked:
                    errors.append(f"ignored or untracked security-relevant input: {relative}")
            else:
                errors.append(f"non-regular assurance subject input: {relative}")

    for root_name in SUBJECT_ROOTS:
        root = repo / root_name
        if not os.path.lexists(root):
            continue
        mode = os.lstat(root).st_mode
        if stat.S_ISLNK(mode):
            errors.append(f"symlink is not permitted in assurance subject: {root_name}")
        elif stat.S_ISDIR(mode):
            walk(root)
        else:
            errors.append(f"subject root is not a directory: {root_name}")

    allowed_negative_features = {"alloc", "std"}
    feature_expression = re.compile(r"\bfeature\s*=\s*\"([^\"]+)\"")
    cfg_asymmetry = re.compile(r"\b(?:doc|doctest|rustdoc)\b")
    cfg_inputs = {
        str(row.get("path"))
        for row in manifest.get("files", [])
        if isinstance(row, dict) and str(row.get("path", "")).endswith(".rs")
    }
    cfg_inputs.update(metadata_target_paths or set())
    bound_paths = {
        str(row.get("path"))
        for row in manifest.get("files", [])
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    pending_cfg_inputs = sorted(cfg_inputs, reverse=True)
    scanned_cfg_inputs: set[str] = set()

    def compiler_input(
        origin: str, value: str, label: str, *, parse_as_rust: bool
    ) -> None:
        if Path(value).is_absolute():
            errors.append(f"{label} uses an absolute compiler input: {origin}:{value}")
            return
        normalized = os.path.normpath(str(Path(origin).parent / value))
        relative = Path(normalized)
        if relative.is_absolute() or not relative.parts or relative.parts[0] == "..":
            errors.append(f"{label} escapes the repository: {origin}:{value}")
            return
        path_value = relative.as_posix()
        if under_exact_exclusion(path_value) or path_value in SUBJECT_EXCLUDED_FILES:
            errors.append(f"{label} uses an excluded input: {origin}:{path_value}")
            return
        if path_value not in bound_paths:
            errors.append(f"{label} input is absent from the bound subject: {origin}:{path_value}")
            return
        path_errors: list[str] = []
        safe_repo_file(repo, path_value, f"{label} input {path_value}", path_errors)
        errors.extend(path_errors)
        if parse_as_rust and not path_errors and path_value not in scanned_cfg_inputs:
            pending_cfg_inputs.append(path_value)

    include_macro = re.compile(
        r"\b(include|include_bytes|include_str)\s*!\s*\(\s*([^\)]*?)\s*\)",
        re.DOTALL,
    )
    ordinary_literal = re.compile(r'^"((?:\\.|[^"\\])*)"$')
    compile_env = re.compile(
        r"\b(env|option_env)\s*!\s*\(\s*([^\)]*?)\s*\)", re.DOTALL
    )
    allowed_compile_env = re.compile(r"^(?:CARGO_MANIFEST_DIR|CARGO_BIN_EXE_[A-Za-z0-9_-]+)$")
    while pending_cfg_inputs:
        path_value = pending_cfg_inputs.pop()
        if path_value in scanned_cfg_inputs:
            continue
        scanned_cfg_inputs.add(path_value)
        if not path_value:
            continue
        path = repo / path_value
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            errors.append(f"cannot inspect Rust source cfg policy: {path_value}")
            continue
        if re.search(
            r"\b(?:include|include_bytes|include_str|env|option_env)\s*(?:/\*|//)",
            source,
        ) or re.search(
            r"\b(?:include|include_bytes|include_str|env|option_env)\s*!\s*(?:/\*|//)",
            source,
        ) or re.search(r"#\s*(?:/\*|//)", source):
            errors.append(
                f"comments may not split compiler-input/cfg syntax: {path_value}"
            )
        for macro in compile_env.finditer(source):
            literal = ordinary_literal.fullmatch(macro.group(2).strip())
            if literal is None:
                errors.append(
                    f"unparseable compile-time environment lookup: {path_value}"
                )
                continue
            name = bytes(literal.group(1), "utf-8").decode("unicode_escape")
            if allowed_compile_env.fullmatch(name) is None:
                errors.append(
                    f"unapproved compile-time environment input: {path_value}:{name}"
                )
        for macro in include_macro.finditer(source):
            literal = ordinary_literal.fullmatch(macro.group(2).strip())
            if literal is None:
                errors.append(f"non-literal compiler include is not permitted: {path_value}")
                continue
            value = bytes(literal.group(1), "utf-8").decode("unicode_escape")
            compiler_input(
                path_value, value, f"{macro.group(1)}!",
                parse_as_rust=macro.group(1) == "include",
            )
        for attribute in rust_attributes(source):
            direct_path = re.match(r"^#\s*!?\s*\[\s*path\b", attribute)
            contains_path_meta = re.search(r"\bpath\s*=", attribute)
            if contains_path_meta and direct_path is None:
                errors.append(
                    f"conditional/nested #[path] is not permitted: {path_value}"
                )
            if direct_path is not None:
                if "/*" in attribute or "//" in attribute or re.search(
                    r"\bpath\s*=\s*r[#\"]", attribute
                ):
                    errors.append(f"unparseable #[path] compiler input: {path_value}")
                else:
                    path_match = re.search(
                        r"\bpath\s*=\s*\"((?:\\.|[^\"\\])*)\"", attribute
                    )
                    if path_match is None:
                        errors.append(f"unparseable #[path] compiler input: {path_value}")
                    else:
                        value = bytes(path_match.group(1), "utf-8").decode("unicode_escape")
                        compiler_input(
                            path_value, value, "#[path]", parse_as_rust=True
                        )
            if re.match(r"^#\s*!?\s*\[\s*cfg(?:_attr)?\b", attribute) is None:
                continue
            if "/*" in attribute or "//" in attribute:
                errors.append(
                    f"comments are not permitted in cfg attributes: {path_value}"
                )
                continue
            if cfg_asymmetry.search(attribute):
                errors.append(
                    f"unmodelled rustdoc-asymmetric cfg in public-API subject: {path_value}"
                )
            if re.search(
                r"\b(?:unix|windows|target_(?:abi|arch|endian|env|family|feature|has_atomic|os|pointer_width|vendor))\b",
                attribute,
            ) and not (
                path_value.startswith(("tests/", "fuzz/", "verification/", "migration/"))
                or re.sub(r"\s+", "", attribute)
                in TARGET_CFG_NON_API_ALLOWLIST.get(path_value, set())
            ):
                errors.append(
                    f"unmodelled target-conditioned public API cfg: {path_value}"
                )
            for expression in not_subexpressions(attribute):
                features = set(feature_expression.findall(expression))
                if re.search(r"\bfeature\s*=\s*r[#\"]", expression):
                    errors.append(
                        f"raw-string feature cfg is not permitted: {path_value}"
                    )
                    continue
                if re.search(r"\bfeature\b", expression) and not features:
                    errors.append(
                        f"unparseable negative feature cfg in public-API subject: {path_value}"
                    )
                    continue
                unsupported = sorted(features - allowed_negative_features)
                for feature in unsupported:
                    errors.append(
                        "uncovered negative feature cfg in public-API subject: "
                        f"{path_value}:{feature}"
                    )
                if re.search(r"\bdebug_assertions\b", expression):
                    errors.append(
                        f"unmodelled release/debug cfg in public-API subject: {path_value}"
                    )
    return sorted(set(errors))


def parse_date(value: Any, label: str, errors: list[str]) -> dt.date | None:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            pass
    errors.append(f"{label} must be an ISO 8601 date")
    return None


def safe_repo_file(repo: Path, value: Any, label: str, errors: list[str]) -> Path | None:
    if not isinstance(value, str) or not value:
        errors.append(f"{label} must be a non-empty repository-relative path")
        return None
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        errors.append(f"{label} escapes the repository: {value}")
        return None
    root = repo.resolve()
    candidate = root / relative
    current = root
    for part in relative.parts:
        current /= part
        if not os.path.lexists(current):
            errors.append(f"{label} does not name a regular file: {value}")
            return None
        try:
            mode = os.lstat(current).st_mode
        except OSError:
            errors.append(f"{label} cannot be inspected safely: {value}")
            return None
        if stat.S_ISLNK(mode):
            errors.append(f"{label} contains a symlink component: {value}")
            return None
    try:
        final_mode = os.lstat(candidate).st_mode
    except OSError:
        errors.append(f"{label} does not name a regular file: {value}")
        return None
    if not stat.S_ISREG(final_mode):
        errors.append(f"{label} does not name a regular file: {value}")
        return None
    return candidate


def resolve_repo_reference(
    *, repo: Path, base: Path, value: Any, label: str, must_exist: bool = True
) -> Path:
    """Resolve a declared input without permitting absolute or repository escapes."""

    if not isinstance(value, str) or not value:
        raise AssuranceFailure(f"{label} must be a non-empty repository-relative path")
    relative = Path(value)
    if relative.is_absolute():
        raise AssuranceFailure(f"{label} must not be absolute: {value}")
    root = repo.resolve()
    try:
        base_relative = base.resolve().relative_to(root)
    except ValueError as error:
        raise AssuranceFailure(f"{label} base escapes the repository") from error
    normalized = os.path.normpath(str(base_relative / relative))
    combined = Path(normalized)
    if combined.is_absolute() or not combined.parts or combined.parts[0] == "..":
        raise AssuranceFailure(f"{label} escapes the repository: {value}")
    resolved = root / combined
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise AssuranceFailure(f"{label} escapes the repository: {value}") from error
    current = root
    for offset, part in enumerate(combined.parts):
        current /= part
        if not os.path.lexists(current):
            if must_exist or offset != len(combined.parts) - 1:
                raise AssuranceFailure(f"{label} does not name a regular file: {value}")
            break
        mode = os.lstat(current).st_mode
        if stat.S_ISLNK(mode):
            raise AssuranceFailure(f"{label} contains a symlink component: {value}")
    if must_exist and not stat.S_ISREG(os.lstat(resolved).st_mode):
        raise AssuranceFailure(f"{label} does not name a regular file: {value}")
    return resolved


def unique_records(
    records: Any, record_name: str, errors: list[str]
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(records, list):
        errors.append(f"[[{record_name}]] must be an array of tables")
        return result
    for offset, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(f"{record_name}[{offset}] must be a table")
            continue
        identifier = record.get("id")
        if not isinstance(identifier, str) or not identifier:
            errors.append(f"{record_name}[{offset}] has no non-empty id")
            continue
        if identifier in result:
            errors.append(f"duplicate {record_name} id: {identifier}")
            continue
        result[identifier] = record
    return result


def effective_operation_rows(
    document: dict[str, Any], errors: list[str] | None = None,
    *, snapshot: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Expand compact, fail-closed gap rows into the effective atomic schema."""

    sink = errors if errors is not None else []
    explicit = document.get("operation", [])
    gaps = document.get("unreviewed-gap", [])
    defaults = document.get("unreviewed-gap-defaults")
    if not isinstance(explicit, list):
        sink.append("[[operation]] must be an array of tables")
        explicit = []
    if not isinstance(gaps, list):
        sink.append("[[unreviewed-gap]] must be an array of tables")
        gaps = []
    if gaps and not isinstance(defaults, dict):
        sink.append("unreviewed-gap-defaults must be a table when gaps exist")
        defaults = {}
    elif defaults is None:
        defaults = {}
    elif not isinstance(defaults, dict):
        sink.append("unreviewed-gap-defaults must be a table")
        defaults = {}
    result = [copy.deepcopy(row) for row in explicit if isinstance(row, dict)]
    for offset, gap in enumerate(gaps):
        if not isinstance(gap, dict):
            sink.append(f"unreviewed-gap[{offset}] must be a table")
            continue
        overlap = set(defaults).intersection(gap)
        if overlap:
            sink.append(
                f"unreviewed-gap[{offset}] overrides fail-closed defaults: "
                f"{sorted(overlap)}"
            )
        row = {**copy.deepcopy(defaults), **copy.deepcopy(gap)}
        for field in ("public-paths", "entrypoints", "profiles", "platforms"):
            row.setdefault(field, [])
        result.append(row)
    if snapshot is not None:
        entries = snapshot.get("entries", [])
        if not isinstance(entries, list):
            sink.append("snapshot entries must be an array before gap expansion")
            entries = []
        by_identity: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for entry in entries:
            if isinstance(entry, dict):
                by_identity.setdefault(
                    (str(entry.get("package", "")), str(entry.get("canonical", ""))), []
                ).append(entry)

        def matches(value: str, package: str) -> list[tuple[dict[str, Any], set[str]]]:
            parsed = parse_entrypoint_binding(
                value, label="compact gap binding", errors=sink, public=True
            )
            if parsed is None:
                return []
            kind, selector, canonical = parsed
            found: list[tuple[dict[str, Any], set[str]]] = []
            for entry in by_identity.get((package, canonical), []):
                if kind == "trait-method":
                    if entry.get("kind") != "trait_impl":
                        continue
                    profiles = {
                        profile
                        for profile, names in entry.get("trait_methods", {}).items()
                        if selector in names
                    }
                else:
                    if entry.get("kind") != kind or canonical.rsplit("::", 1)[-1] != selector:
                        continue
                    profiles = set(entry.get("profiles", []))
                if profiles:
                    found.append((entry, profiles))
            return found

        for row in result:
            if row.get("semantic-review") != "required":
                continue
            package = str(row.get("crate", ""))
            action_matches = [
                pair
                for value in row.get("entrypoint-bindings", [])
                for pair in matches(value, package)
            ]
            public_matches = [
                pair
                for value in row.get("public-bindings", [])
                for pair in matches(value, package)
            ]
            row["entrypoints"] = sorted({str(entry["path"]) for entry, _ in action_matches})
            row["public-paths"] = sorted({str(entry["path"]) for entry, _ in public_matches})
            profile_set = {
                profile for _entry, profiles in (
                    public_matches if row.get("row-kind") == "data-surface" else action_matches
                ) for profile in profiles
            }
            row["profiles"] = sorted({
                f"boundary-no-std/{package}"
                if profile.startswith("boundary-no-std/") else profile
                for profile in profile_set
            })
            row["platforms"] = sorted({profile.rsplit("/", 1)[-1] for profile in profile_set})
    return result


def entry_identity(entry: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(entry.get("package", "")),
        str(entry.get("path", "")),
        str(entry.get("unit", "")),
        str(entry.get("kind", "")),
        str(entry.get("canonical", "")),
    )


def merge_profile_digests(
    target: dict[str, str], incoming: dict[str, str]
) -> None:
    """Bind every deterministic alias/declaration lineage for each profile."""

    for profile, digest in incoming.items():
        previous = target.get(profile)
        if previous is None or previous == digest:
            target[profile] = digest
            continue
        target[profile] = hashlib.sha256(
            json.dumps(
                {"multiple-public-lineages": sorted([previous, digest])},
                sort_keys=True, separators=(",", ":"),
            ).encode()
        ).hexdigest()


def merge_alias_source(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    sources = {
        value
        for value in (existing.get("alias_source"), incoming.get("alias_source"))
        if isinstance(value, str) and value
    }
    if sources:
        # The digest maps above bind every route. The lexicographically first
        # immediate owner is used only to locate the identical canonical
        # descendants during fixed-point expansion.
        existing["alias_source"] = min(sources)


def valid_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def parse_entrypoint_binding(
    value: Any, *, label: str, errors: list[str], public: bool = False
) -> tuple[str, str, str] | None:
    """Parse ``kind:selector|canonical`` without accepting fuzzy matches."""

    if not isinstance(value, str) or value.count("|") != 1:
        errors.append(f"{label} is not an exact entrypoint binding")
        return None
    witness, canonical = value.split("|", 1)
    if witness.count(":") != 1:
        errors.append(f"{label} has an invalid witness selector")
        return None
    kind, selector = witness.split(":", 1)
    allowed_kinds = {
        "assoc_const", "constant", "function", "macro", "static", "trait", "trait-method"
    }
    if public:
        allowed_kinds.update({"enum", "field", "module", "struct", "type_alias", "union", "variant"})
    if kind not in allowed_kinds:
        errors.append(f"{label} has an unsupported witness kind: {kind!r}")
        return None
    if not valid_nonempty_string(selector) or not valid_nonempty_string(canonical):
        errors.append(f"{label} has an empty selector or canonical identity")
        return None
    return kind, selector, canonical


def validate_ledger(
    ledger: dict[str, Any],
    operations_document: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    repo: Path,
    as_of: dt.date,
    mode: str,
    policy: dict[str, Any] | None = None,
    metadata_features: dict[str, set[str]] | None = None,
    check_paths: bool = True,
) -> tuple[list[str], dict[str, int]]:
    """Validate exact API classifications and their reviewable evidence graph."""

    errors: list[str] = []
    metrics = {"exports": 0, "members": 0, "classified": 0, "features": 0,
               "operations": 0, "evidence": 0, "release_blocked": 0}
    if mode not in {"ci", "release"}:
        errors.append(f"invalid verification mode: {mode!r}")
    if ledger.get("schema-version") != SCHEMA_VERSION:
        errors.append(f"unsupported ledger schema-version: {ledger.get('schema-version')!r}")
    if operations_document.get("schema-version") != SCHEMA_VERSION:
        errors.append("atomic operations schema-version mismatch")
    if snapshot.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        errors.append(f"unsupported public API snapshot schema_version: {snapshot.get('schema_version')!r}")

    source_commit = ledger.get("source-commit")
    source_tree = ledger.get("source-tree")
    if not isinstance(source_commit, str) or HEX_GIT_ID.fullmatch(source_commit) is None:
        errors.append("ledger source-commit must be a lowercase 40-hex Git object id")
    if not isinstance(source_tree, str) or HEX_GIT_ID.fullmatch(source_tree) is None:
        errors.append("ledger source-tree must be a lowercase 40-hex Git object id")
    if snapshot.get("source_commit") != source_commit:
        errors.append("ledger/snapshot source commit mismatch")
    if snapshot.get("source_tree") != source_tree:
        errors.append("ledger/snapshot source tree mismatch")

    surfaces = unique_records(ledger.get("surface", []), "surface", errors)
    surface_packages: dict[str, str] = {}
    allowed_status = {"supported", "transitional", "deprecated", "internal-public"}
    for identifier, surface in surfaces.items():
        package = surface.get("package")
        if not valid_nonempty_string(package):
            errors.append(f"surface {identifier} has no package")
        elif package in surface_packages:
            errors.append(f"package {package} has multiple package surfaces: {surface_packages[package]}, {identifier}")
        else:
            surface_packages[str(package)] = identifier
        if surface.get("status") not in allowed_status:
            errors.append(f"surface {identifier} has invalid status")
        if not valid_nonempty_string(surface.get("classification")):
            errors.append(f"surface {identifier} has no classification")

    profile_records = unique_records(ledger.get("profile", []), "profile", errors)
    inventory_profiles: set[str] = set()
    for identifier, profile in profile_records.items():
        support = profile.get("support")
        inventory = profile.get("api-inventory")
        if support not in {"supported", "unsupported"}:
            errors.append(f"profile {identifier} has invalid support classification")
        if not isinstance(inventory, bool):
            errors.append(f"profile {identifier} must declare api-inventory = true/false")
        elif inventory:
            inventory_profiles.add(identifier)
        if support == "unsupported" and not valid_nonempty_string(profile.get("reason")):
            errors.append(f"unsupported profile {identifier} has no reason")
        if support == "unsupported" and inventory is not False:
            errors.append(f"unsupported profile {identifier} cannot be an API inventory profile")
    # Rustdoc merges the exact per-package boundary profiles into a target-
    # qualified snapshot label; operation rows retain package-specific IDs.
    if any(
        profile.get("mode") == PROFILE_NOSTD
        and profile.get("support") == "supported"
        and profile.get("api-inventory") is True
        for profile in profile_records.values()
    ):
        no_std_targets = {
            profile.get("target")
            for profile in profile_records.values()
            if profile.get("mode") == PROFILE_NOSTD
        }
        for no_std_target in no_std_targets:
            if isinstance(no_std_target, str):
                inventory_profiles.add(target_profile(PROFILE_NOSTD, no_std_target))

    operations = unique_records(
        effective_operation_rows(operations_document, errors, snapshot=snapshot),
        "operation", errors
    )
    metrics["operations"] = len(operations)
    operation_string_fields = (
        "row-kind", "crate", "surface", "algorithm", "standard", "parameter-set", "operation",
        "encoding", "mode-profile", "dst-context-prehash", "feature-profile",
        "support", "vector-source", "independent-oracle", "oracle-provenance",
        "fuzz-target", "side-channel-claim", "required-evidence-tier",
        "audit-coverage", "known-limitation", "owner", "release-readiness",
    )
    operation_list_fields = (
        "entrypoint-bindings", "public-bindings", "public-paths", "entrypoints",
        "profiles", "platforms", "required-evidence", "action-selectors",
    )
    for identifier, operation in operations.items():
        for field in operation_string_fields:
            if not valid_nonempty_string(operation.get(field)):
                errors.append(f"operation {identifier} has no {field}")
        for field in operation_list_fields:
            values = operation.get(field)
            allow_empty = (
                operation.get("row-kind") == "data-surface"
                and field in {"entrypoint-bindings", "entrypoints", "action-selectors"}
            )
            if (
                not isinstance(values, list)
                or (not values and not allow_empty)
                or not all(valid_nonempty_string(v) for v in values)
            ):
                errors.append(f"operation {identifier} has invalid {field}")
            elif values != sorted(set(values)):
                errors.append(f"operation {identifier} has non-canonical {field}")
        if operation.get("surface") not in surfaces:
            errors.append(f"operation {identifier} references unknown surface")
        elif surfaces[operation["surface"]].get("package") != operation.get("crate"):
            errors.append(f"operation {identifier} surface/crate mismatch")
        if operation.get("support") not in {"supported", "transitional", "low-level", "unsupported"}:
            errors.append(f"operation {identifier} has invalid support")
        if operation.get("row-kind") not in {"operation", "data-surface"}:
            errors.append(f"operation {identifier} has invalid row-kind")
        if operation.get("release-readiness") not in {"ready", "blocked"}:
            errors.append(f"operation {identifier} has invalid release-readiness")
        elif operation.get("release-readiness") == "blocked":
            metrics["release_blocked"] += 1
            if mode == "release":
                errors.append(f"release-blocked operation: {identifier}: {operation.get('known-limitation')}")
        action = operation.get("operation")
        parameter = operation.get("parameter-set")
        if isinstance(action, str) and ("/" in action or "," in action):
            errors.append(f"operation {identifier} is not atomic: operation={action!r}")
        if isinstance(parameter, str) and ("/" in parameter or "," in parameter):
            errors.append(f"operation {identifier} is not atomic: parameter-set={parameter!r}")
        for profile_id in operation.get("profiles", []):
            profile = profile_records.get(profile_id)
            if profile is None:
                errors.append(f"operation {identifier} references unknown profile {profile_id}")
            elif profile.get("support") != "supported" or profile.get("api-inventory") is not True:
                errors.append(f"operation {identifier} references unsupported profile {profile_id}")
        for offset, binding in enumerate(operation.get("entrypoint-bindings", [])):
            parse_entrypoint_binding(
                binding,
                label=f"operation {identifier} entrypoint-bindings[{offset}]",
                errors=errors,
            )
        binding_selectors = sorted({
            parsed[1]
            for offset, value in enumerate(operation.get("entrypoint-bindings", []))
            if (
                parsed := parse_entrypoint_binding(
                    value,
                    label=f"operation {identifier} selector binding[{offset}]",
                    errors=[],
                )
            ) is not None
        })
        if operation.get("action-selectors") != binding_selectors:
            errors.append(f"operation {identifier} action selectors differ from exact bindings")
        if len(binding_selectors) > 1 and not str(operation.get("mode-profile", "")).startswith(
            "reviewed-equivalent:"
        ):
            errors.append(
                f"operation {identifier} combines selectors without reviewed equivalence"
            )
        for offset, binding in enumerate(operation.get("public-bindings", [])):
            parse_entrypoint_binding(
                binding,
                label=f"operation {identifier} public-bindings[{offset}]",
                errors=errors,
                public=True,
            )
        semantic_review = operation.get("semantic-review")
        deadline = operation.get("semantic-review-deadline")
        if semantic_review not in {"curated", "required"}:
            errors.append(f"operation {identifier} has invalid semantic-review")
        elif semantic_review == "required":
            if operation.get("support") != "low-level" or operation.get("release-readiness") != "blocked":
                errors.append(
                    f"unreviewed operation must be low-level and release-blocked: {identifier}"
                )
            parsed_deadline = parse_date(
                deadline, f"operation {identifier} semantic-review-deadline", errors
            )
            if parsed_deadline is not None and parsed_deadline < as_of:
                errors.append(f"semantic review deadline expired: {identifier}: {parsed_deadline}")
            for field in ("standard", "parameter-set", "encoding"):
                if "unclassified" not in str(operation.get(field, "")).lower() and "pending" not in str(operation.get(field, "")).lower():
                    errors.append(
                        f"unreviewed operation lacks an honest {field} placeholder: {identifier}"
                    )
        else:
            if deadline != "n/a-reviewed":
                errors.append(f"curated operation has invalid review deadline: {identifier}")
            if any(
                "unclassified" in str(operation.get(field, "")).lower()
                for field in ("standard", "parameter-set", "encoding")
            ):
                errors.append(f"curated operation contains an unreviewed placeholder: {identifier}")

    evidence = unique_records(ledger.get("evidence", []), "evidence", errors)
    metrics["evidence"] = len(evidence)
    for identifier, record in evidence.items():
        for field in ("kind", "owner", "reviewer", "applicability", "command"):
            if not valid_nonempty_string(record.get(field)):
                errors.append(f"evidence {identifier} has no {field}")
        if not isinstance(record.get("required"), bool):
            errors.append(f"evidence {identifier} must declare required = true/false")
        if record.get("verdict") not in {"pass", "inconclusive", "fail", "informational"}:
            errors.append(f"evidence {identifier} has invalid verdict")
        if (
            identifier in ORACLE_REPLAY_EVIDENCE_IDS
            and record.get("verdict") != "informational"
        ):
            errors.append(
                f"evidence {identifier} must remain informational until an oracle "
                "dossier and independent replay are accepted"
            )
        if (
            identifier in ORACLE_REPLAY_EVIDENCE_IDS
            and record.get("command") != ORACLE_REPLAY_COMMAND
        ):
            errors.append(
                f"evidence {identifier} command differs from the exact cold oracle replay contract"
            )
        if record.get("source-commit") != source_commit or record.get("source-tree") != source_tree:
            errors.append(f"evidence {identifier} source provenance mismatch")
        reviewed_at = parse_date(record.get("reviewed-at"), f"evidence {identifier} reviewed-at", errors)
        valid_through = parse_date(record.get("valid-through"), f"evidence {identifier} valid-through", errors)
        if reviewed_at is not None and reviewed_at > as_of:
            errors.append(f"evidence {identifier} review date is in the future")
        if valid_through is not None and reviewed_at is not None and valid_through < reviewed_at:
            errors.append(f"evidence {identifier} expires before its review date")
        if mode == "release" and record.get("required") is True and valid_through is not None and valid_through < as_of:
            errors.append(f"expired required evidence: {identifier} (valid through {valid_through.isoformat()}, as of {as_of.isoformat()})")
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            errors.append(f"evidence {identifier} has no artifacts")
        else:
            seen_paths: set[str] = set()
            for offset, artifact in enumerate(artifacts):
                label = f"evidence {identifier} artifacts[{offset}]"
                if not isinstance(artifact, dict):
                    errors.append(f"{label} must be a table")
                    continue
                path_value, digest = artifact.get("path"), artifact.get("sha256")
                if not isinstance(path_value, str) or not path_value:
                    errors.append(f"{label} has no path")
                    continue
                if path_value in seen_paths:
                    errors.append(f"evidence {identifier} has duplicate artifact path: {path_value}")
                seen_paths.add(path_value)
                if not isinstance(digest, str) or HEX_SHA256.fullmatch(digest) is None:
                    errors.append(f"{label} has invalid sha256")
                if check_paths:
                    path = safe_repo_file(repo, path_value, f"{label} path", errors)
                    if path is not None and isinstance(digest, str) and sha256_file(path) != digest:
                        errors.append(f"evidence artifact digest mismatch: {identifier}: {path_value}")
            if identifier in ORACLE_REPLAY_EVIDENCE_IDS:
                missing_replay_artifacts = sorted(
                    ORACLE_REPLAY_REQUIRED_ARTIFACTS - seen_paths
                )
                unexpected_replay_artifacts = sorted(
                    seen_paths - ORACLE_REPLAY_REQUIRED_ARTIFACTS
                )
                if missing_replay_artifacts or unexpected_replay_artifacts:
                    errors.append(
                        f"evidence {identifier} cold replay artifact set differs from "
                        f"the exact contract: missing={missing_replay_artifacts} "
                        f"unexpected={unexpected_replay_artifacts}"
                    )

    for identifier, operation in operations.items():
        required_evidence = operation.get("required-evidence", [])
        if (
            any(
                str(evidence_id).startswith("acvp-")
                and evidence_id != "acvp-harness-integrity"
                for evidence_id in required_evidence
            )
            and "acvp-harness-integrity" not in required_evidence
        ):
            errors.append(
                f"ACVP-backed operation lacks shared harness integrity: {identifier}"
            )
        for evidence_id in operation.get("required-evidence", []):
            if evidence_id not in evidence:
                errors.append(f"operation {identifier} references unknown evidence {evidence_id}")
            elif evidence[evidence_id].get("required") is not True:
                errors.append(f"operation {identifier} references non-required evidence {evidence_id}")
            elif (
                mode == "release"
                and operation.get("release-readiness") == "ready"
                and evidence[evidence_id].get("verdict") != "pass"
            ):
                errors.append(
                    f"release-ready operation {identifier} lacks passing evidence: {evidence_id}"
                )

    harness = evidence.get("acvp-harness-integrity")
    required_harness_paths = {
        "tests/src/suites/acvp/runner.rs",
        "tests/src/suites/acvp/model.rs",
        "tests/src/suites/acvp/loader.rs",
        "tests/src/suites/acvp/dispatcher.rs",
        "tests/src/suites/acvp/engine.rs",
        "tests/src/suites/acvp/error.rs",
        "tests/src/suites/acvp/mod.rs",
        "tests/src/suites/acvp/algorithms/mod.rs",
        "tests/tests/acvp_tests.rs",
        "assurance/acvp-vector-manifest.json",
    }
    if harness is None:
        errors.append("required ACVP harness-integrity evidence is missing")
    else:
        harness_paths = {
            str(artifact.get("path"))
            for artifact in harness.get("artifacts", [])
            if isinstance(artifact, dict)
        }
        if harness_paths != required_harness_paths:
            errors.append(
                "ACVP harness-integrity artifact set mismatch: "
                f"missing={sorted(required_harness_paths-harness_paths)}, "
                f"extra={sorted(harness_paths-required_harness_paths)}"
            )

    entries = snapshot.get("entries", [])
    if not isinstance(entries, list):
        errors.append("snapshot entries must be an array")
        entries = []
    expected_snapshot_profiles = (
        policy_inventory_profiles(policy) if policy is not None else snapshot.get("profiles")
    )
    if snapshot.get("profiles") != expected_snapshot_profiles or not isinstance(expected_snapshot_profiles, list):
        errors.append("snapshot profile set/order is not canonical")
    seen_entries: set[tuple[str, str, str, str, str]] = set()
    entries_by_path: dict[tuple[str, str], dict[str, Any]] = {}
    entries_by_canonical: dict[tuple[str, str], list[dict[str, Any]]] = {}
    operation_ids_by_public_binding: dict[
        tuple[str, str, str, str], list[str]
    ] = {}
    for operation_id, operation in operations.items():
        package = str(operation.get("crate", ""))
        for value in operation.get("public-bindings", []):
            parsed = parse_entrypoint_binding(
                value, label="indexed public binding", errors=[], public=True
            )
            if parsed is not None:
                operation_ids_by_public_binding.setdefault(
                    (package, *parsed), []
                ).append(operation_id)
    for identifiers in operation_ids_by_public_binding.values():
        identifiers.sort()
    for offset, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"snapshot entry[{offset}] must be an object")
            continue
        identity = entry_identity(entry)
        if not all(identity):
            errors.append(f"snapshot entry[{offset}] has an empty identity field")
            continue
        if identity in seen_entries:
            errors.append(f"duplicate public API snapshot entry: {identity[0]} {identity[1]} {identity[2]}")
            continue
        seen_entries.add(identity)
        entries_by_canonical.setdefault((identity[0], identity[4]), []).append(entry)
        path_key = (identity[0], identity[1])
        if path_key in entries_by_path:
            errors.append(
                f"ambiguous duplicate public API path: {identity[0]}:{identity[1]}"
            )
        else:
            entries_by_path[path_key] = entry
        declaration_digests = entry.get("declaration_sha256")
        if (
            not isinstance(declaration_digests, dict)
            or set(declaration_digests) != set(entry.get("profiles", []))
            or not all(
                isinstance(digest, str) and HEX_SHA256.fullmatch(digest) is not None
                for digest in declaration_digests.values()
            )
        ):
            errors.append(f"public API entry has invalid declaration hash: {entry.get('path')}")
        alias_digests = entry.get("alias_binding_sha256")
        if alias_digests is not None and (
            not isinstance(alias_digests, dict)
            or set(alias_digests) != set(entry.get("profiles", []))
            or not all(
                isinstance(digest, str) and HEX_SHA256.fullmatch(digest) is not None
                for digest in alias_digests.values()
            )
        ):
            errors.append(f"public API entry has invalid alias-binding hash: {entry.get('path')}")
        if entry.get("kind") == "trait_impl":
            impl_digest = entry.get("impl_identity_sha256")
            methods = entry.get("trait_methods")
            if not isinstance(impl_digest, str) or HEX_SHA256.fullmatch(impl_digest) is None:
                errors.append(f"trait impl has invalid complete identity: {entry.get('path')}")
            if not isinstance(methods, dict) or set(methods) != set(entry.get("profiles", [])):
                errors.append(f"trait impl has invalid method inventory: {entry.get('path')}")
            elif any(
                not isinstance(names, list)
                or names != sorted(set(names))
                or not all(valid_nonempty_string(name) for name in names)
                for names in methods.values()
            ):
                errors.append(f"trait impl has invalid per-profile methods: {entry.get('path')}")
            method_assurance = entry.get("trait_method_assurance")
            all_methods = {
                name for names in methods.values() for name in names
            } if isinstance(methods, dict) else set()
            if not isinstance(method_assurance, dict) or set(method_assurance) != all_methods:
                errors.append(f"trait impl has incomplete selector assurance: {entry.get('path')}")
            else:
                for selector, record in method_assurance.items():
                    if not isinstance(record, dict):
                        errors.append(
                            f"trait method assurance is invalid: {entry.get('path')}::{selector}"
                        )
                        continue
                    selector_profiles = sorted(
                        profile for profile, names in methods.items() if selector in names
                    )
                    if record.get("profiles") != selector_profiles:
                        errors.append(
                            f"trait method profile assurance mismatch: {entry.get('path')}::{selector}"
                        )
                    method_refs = record.get("operation_refs")
                    if (
                        not isinstance(method_refs, list)
                        or not method_refs
                        or method_refs != sorted(set(method_refs))
                    ):
                        errors.append(
                            f"trait method lacks exact atomic refs: {entry.get('path')}::{selector}"
                        )
                        method_refs = []
                    expected_method_refs = operation_ids_by_public_binding.get(
                        (
                            str(entry.get("package", "")), "trait-method", selector,
                            str(entry.get("canonical", "")),
                        ),
                        [],
                    )
                    if method_refs != expected_method_refs:
                        errors.append(
                            f"trait method refs differ from exact selector bindings: "
                            f"{entry.get('path')}::{selector}"
                        )
                    if record.get("disposition") != "operation-bearing":
                        errors.append(
                            f"trait method is not operation-bearing: {entry.get('path')}::{selector}"
                        )
                    if record.get("classification") not in {
                        "supported-operation", "transitional-legacy", "internal-like-low-level"
                    }:
                        errors.append(
                            f"trait method has invalid classification: {entry.get('path')}::{selector}"
                        )
            if isinstance(method_assurance, dict):
                exact_union = sorted({
                    operation_id
                    for record in method_assurance.values()
                    if isinstance(record, dict)
                    for operation_id in record.get("operation_refs", [])
                })
                if entry.get("operation_refs") != exact_union:
                    errors.append(
                        f"trait impl refs differ from selector union: {entry.get('path')}"
                    )
        unit = entry.get("unit")
        if unit == "export": metrics["exports"] += 1
        elif unit == "member": metrics["members"] += 1
        else: errors.append(f"invalid snapshot unit for {entry.get('path')}: {unit!r}")
        surface_id = entry.get("surface")
        classification = entry.get("classification")
        if surface_id == UNCLASSIFIED or classification == UNCLASSIFIED:
            noun = "public export" if unit == "export" else "public API member"
            errors.append(f"unclassified {noun}: {entry.get('path')}")
        elif surface_id not in surfaces:
            errors.append(f"unknown surface {surface_id!r} for public API entry: {entry.get('path')}")
        elif surfaces[surface_id].get("package") != entry.get("package"):
            errors.append(f"surface/package mismatch for {entry.get('path')}: {surface_id}")
        elif classification not in CLASSIFICATIONS:
            errors.append(f"invalid classification for public API entry: {entry.get('path')}: {classification!r}")
        else:
            metrics["classified"] += 1
        unsupported_fields = (
            "unsupported_reason", "unsupported_owner", "unsupported_review_due"
        )
        if classification == "intentionally-unsupported":
            for field in unsupported_fields[:2]:
                if not valid_nonempty_string(entry.get(field)):
                    errors.append(
                        f"intentionally unsupported entry has no {field}: {entry.get('path')}"
                    )
            due = parse_date(
                entry.get("unsupported_review_due"),
                f"intentionally unsupported entry {entry.get('path')} review due",
                errors,
            )
            if due is not None and due < as_of:
                errors.append(
                    f"intentionally unsupported entry review expired: "
                    f"{entry.get('path')}: {due.isoformat()}"
                )
        elif any(entry.get(field) is not None for field in unsupported_fields):
            errors.append(
                f"supported/classified entry has unsupported-only metadata: {entry.get('path')}"
            )
        profiles = entry.get("profiles")
        if not isinstance(profiles, list) or not profiles or profiles != sorted(set(profiles)):
            errors.append(f"non-canonical profiles for public API entry: {entry.get('path')}")
        else:
            for profile_id in profiles:
                if profile_id not in inventory_profiles:
                    errors.append(f"unknown or non-inventory profile for public API entry: {entry.get('path')}: {profile_id}")
        refs = entry.get("operation_refs")
        if not isinstance(refs, list) or refs != sorted(set(refs)):
            errors.append(f"non-canonical operation refs for public API entry: {entry.get('path')}")
            refs = []
        callable_disposition = entry.get("callable_disposition")
        non_operation_reason = entry.get("non_operation_reason")
        if entry.get("kind") in CALLABLE_KINDS:
            allowed_dispositions = {"operation-bearing"}
            if entry.get("kind") == "trait_impl":
                allowed_dispositions = {"method-container"}
            elif entry.get("kind") == "trait" and not refs:
                allowed_dispositions = {"method-contract"}
            if callable_disposition not in allowed_dispositions:
                errors.append(
                    f"callable public API entry lacks a disposition: {entry.get('path')}"
                )
            elif callable_disposition == "operation-bearing":
                if not refs:
                    errors.append(
                        f"operation-bearing callable has no atomic row: {entry.get('path')}"
                    )
                if non_operation_reason is not None:
                    errors.append(
                        f"operation-bearing callable has a non-operation reason: {entry.get('path')}"
                    )
            elif non_operation_reason is not None:
                errors.append(
                    f"callable container/contract has an obsolete exemption reason: {entry.get('path')}"
                )
        elif callable_disposition is not None or non_operation_reason is not None:
            errors.append(
                f"non-callable public API entry has callable disposition metadata: {entry.get('path')}"
            )
        if entry.get("kind") in DATA_KINDS:
            if entry.get("data_disposition") != "security-or-protocol-data-review-required":
                errors.append(f"public data surface lacks a disposition: {entry.get('path')}")
            if not refs:
                errors.append(f"public data surface lacks an atomic row: {entry.get('path')}")
        elif entry.get("data_disposition") is not None:
            errors.append(f"non-data API entry has a data disposition: {entry.get('path')}")
        if classification in OPERATION_CLASSIFICATIONS and not refs and entry.get("kind") != "trait":
            errors.append(f"operation-classified entry has no operation refs: {entry.get('path')}")
        if classification in {"metadata-only", "intentionally-unsupported"} and refs:
            errors.append(f"metadata/non-operation entry has operation refs: {entry.get('path')}")
        for operation_id in refs:
            if operation_id not in operations:
                errors.append(f"public API entry references unknown operation: {entry.get('path')}: {operation_id}")
            else:
                operation = operations[operation_id]
                if operation.get("crate") != entry.get("package"):
                    errors.append(f"public API entry/operation crate mismatch: {entry.get('path')}: {operation_id}")
                elif entry.get("path") not in operation.get("public-paths", []):
                    errors.append(f"public API entry is absent from operation public-paths: {entry.get('path')}: {operation_id}")
                expected_support = {
                    "supported-operation": "supported",
                    "transitional-legacy": "transitional",
                    "internal-like-low-level": "low-level",
                }.get(classification)
                if entry.get("kind") == "trait_impl":
                    selectors = [
                        selector
                        for value in operation.get("public-bindings", [])
                        if (
                            (parsed := parse_entrypoint_binding(
                                value, label="selector support", errors=[], public=True
                            )) is not None
                            and parsed[0] == "trait-method"
                            and parsed[2] == entry.get("canonical")
                        )
                        for selector in [parsed[1]]
                    ]
                    for selector in selectors:
                        record = entry.get("trait_method_assurance", {}).get(selector, {})
                        method_support = {
                            "supported-operation": "supported",
                            "transitional-legacy": "transitional",
                            "internal-like-low-level": "low-level",
                        }.get(record.get("classification"))
                        if method_support != operation.get("support"):
                            errors.append(
                                "trait method classification/operation support mismatch: "
                                f"{entry.get('path')}::{selector} -> {operation_id}/"
                                f"{operation.get('support')}"
                            )
                elif expected_support is not None and operation.get("support") != expected_support:
                    errors.append(
                        "public API classification/operation support mismatch: "
                        f"{entry.get('path')}: {classification} -> {operation_id}/"
                        f"{operation.get('support')}"
                    )

    for identifier, operation in operations.items():
        if not set(operation.get("entrypoints", [])).issubset(
            set(operation.get("public-paths", []))
        ):
            errors.append(f"operation {identifier} entrypoints are not a public-path subset")
        for public_path in operation.get("public-paths", []):
            entry = entries_by_path.get((operation.get("crate"), public_path))
            if entry is None:
                errors.append(f"operation {identifier} references absent public path: {operation.get('crate')}:{public_path}")
            elif identifier not in entry.get("operation_refs", []):
                errors.append(f"operation {identifier} is not linked back from public path: {public_path}")
        entrypoint_profiles: set[str] = set()
        parsed_bindings = [
            parsed
            for offset, value in enumerate(operation.get("entrypoint-bindings", []))
            if (
                parsed := parse_entrypoint_binding(
                    value,
                    label=f"operation {identifier} entrypoint-bindings[{offset}]",
                    errors=[],
                )
            )
            is not None
        ]
        parsed_public_bindings = [
            parsed
            for offset, value in enumerate(operation.get("public-bindings", []))
            if (
                parsed := parse_entrypoint_binding(
                    value,
                    label=f"operation {identifier} public-bindings[{offset}]",
                    errors=[],
                    public=True,
                )
            ) is not None
        ]

        def binding_matches_entry(
            parsed: tuple[str, str, str], entry: dict[str, Any]
        ) -> bool:
            witness_kind, selector, canonical = parsed
            if canonical != entry.get("canonical"):
                return False
            if witness_kind == "trait-method":
                return entry.get("kind") == "trait_impl" and any(
                    selector in names
                    for names in entry.get("trait_methods", {}).values()
                )
            if witness_kind != entry.get("kind"):
                return False
            return str(canonical).rsplit("::", 1)[-1] == selector

        public_candidates = {
            id(entry): entry
            for _kind, _selector, canonical in parsed_public_bindings
            for entry in entries_by_canonical.get(
                (str(operation.get("crate", "")), canonical), []
            )
        }
        exact_public_paths = sorted(
            entry.get("path")
            for entry in public_candidates.values()
            if any(binding_matches_entry(parsed, entry) for parsed in parsed_public_bindings)
        )
        if operation.get("public-paths") != exact_public_paths:
            errors.append(
                f"operation {identifier} public paths differ from exact public bindings"
            )
        expected_canonicals = {canonical for _kind, _selector, canonical in parsed_bindings}
        observed_canonicals: set[str] = set()
        for entrypoint in operation.get("entrypoints", []):
            entry = entries_by_path.get((operation.get("crate"), entrypoint))
            if entry is None:
                errors.append(
                    f"operation {identifier} references absent entrypoint: "
                    f"{operation.get('crate')}:{entrypoint}"
                )
                continue
            if entrypoint not in operation.get("public-paths", []):
                errors.append(
                    f"operation {identifier} entrypoint is absent from public-paths: {entrypoint}"
                )
            if entry.get("kind") not in {
                "assoc_const", "function", "macro", "trait", "trait_impl", "static", "constant"
            }:
                errors.append(
                    f"operation {identifier} entrypoint has unsupported API kind: "
                    f"{entrypoint}/{entry.get('kind')}"
                )
            canonical = entry.get("canonical")
            if isinstance(canonical, str):
                observed_canonicals.add(canonical)
            matching_bindings = [
                (kind, selector)
                for kind, selector, bound_canonical in parsed_bindings
                if bound_canonical == canonical
            ]
            if not matching_bindings:
                errors.append(
                    f"operation {identifier} entrypoint lacks an exact canonical binding: {entrypoint}"
                )
            witness_profiles: set[str] = set()
            for witness_kind, selector in matching_bindings:
                actual_kind = entry.get("kind")
                if witness_kind == "trait-method":
                    methods_by_profile = entry.get("trait_methods", {})
                    selector_profiles = {
                        profile
                        for profile, names in methods_by_profile.items()
                        if selector in names
                    } if isinstance(methods_by_profile, dict) else set()
                    if actual_kind != "trait_impl" or not selector_profiles:
                        errors.append(
                            f"operation {identifier} trait-method witness is absent: "
                            f"{entrypoint}/{selector}"
                        )
                    else:
                        witness_profiles.update(selector_profiles)
                elif actual_kind != witness_kind:
                    errors.append(
                        f"operation {identifier} witness kind mismatch: "
                        f"{entrypoint}/{witness_kind}/{actual_kind}"
                    )
                else:
                    witness_profiles.update(entry.get("profiles", []))
                    if str(canonical).rsplit("::", 1)[-1] != selector:
                        errors.append(
                            f"operation {identifier} {witness_kind} selector mismatch: "
                            f"{entrypoint}/{selector}"
                        )
            if entry.get("kind") == "function" and operation.get("semantic-review") == "curated":
                referenced_actions = {
                    operations[reference].get("operation")
                    for reference in entry.get("operation_refs", [])
                    if reference in operations
                }
                if referenced_actions != {operation.get("operation")}:
                    errors.append(
                        f"operation {identifier} function entrypoint spans distinct actions: "
                        f"{entrypoint}/{sorted(str(value) for value in referenced_actions)}"
                    )
                function_name = str(canonical).rsplit("::", 1)[-1]
                non_action_names = {
                    "algorithm_name", "as_bytes", "is_empty", "key", "key_size",
                    "len", "name", "tag_size",
                }
                if function_name in non_action_names:
                    errors.append(
                        f"operation {identifier} uses a non-action function entrypoint: {entrypoint}"
                    )
            if entry.get("kind") == "trait_impl" and operation.get("semantic-review") == "curated":
                reviewed_compatibility_lifecycle = (
                    operation.get("support") == "transitional"
                    and "compatibility" in str(operation.get("standard", "")).lower()
                )
                if (
                    not reviewed_compatibility_lifecycle
                    and not any(marker in str(canonical) for marker in OPERATION_TRAIT_MARKERS)
                ):
                    errors.append(
                        f"operation {identifier} uses a non-operation trait impl entrypoint: {entrypoint}"
                    )
            entrypoint_profiles.update(witness_profiles)
        if observed_canonicals != expected_canonicals:
            errors.append(
                f"operation {identifier} canonical entrypoint set differs from visible aliases"
            )
        entrypoint_candidates = {
            id(entry): entry
            for _kind, _selector, canonical in parsed_bindings
            for entry in entries_by_canonical.get(
                (str(operation.get("crate", "")), canonical), []
            )
        }
        expected_aliases = sorted(
            entry.get("path")
            for entry in entrypoint_candidates.values()
            if any(binding_matches_entry(parsed, entry) for parsed in parsed_bindings)
        )
        if operation.get("entrypoints") != expected_aliases:
            errors.append(
                f"operation {identifier} did not expand every exact canonical alias"
            )
        declared_snapshot_profiles: set[str] = set()
        declared_platforms: set[str] = set()
        for profile_id in operation.get("profiles", []):
            profile = profile_records.get(profile_id)
            if profile is None:
                continue
            target = profile.get("target")
            if isinstance(target, str):
                declared_platforms.add(target)
                if profile.get("mode") == PROFILE_NOSTD:
                    declared_snapshot_profiles.add(target_profile(PROFILE_NOSTD, target))
                else:
                    declared_snapshot_profiles.add(profile_id)
        if operation.get("row-kind") == "data-surface":
            entrypoint_profiles = {
                profile
                for public_path in operation.get("public-paths", [])
                for entry in [entries_by_path.get((operation.get("crate"), public_path))]
                if entry is not None
                for profile in entry.get("profiles", [])
            }
        if entrypoint_profiles != declared_snapshot_profiles:
            errors.append(
                f"operation {identifier} profile set differs from exact entrypoint presence: "
                f"declared={sorted(declared_snapshot_profiles)}, "
                f"entrypoints={sorted(entrypoint_profiles)}"
            )
        if operation.get("platforms") != sorted(declared_platforms):
            errors.append(
                f"operation {identifier} platform set differs from declared profiles"
            )

    if policy is not None:
        packages = policy.get("published-packages")
        if not isinstance(packages, list) or not all(isinstance(p, str) for p in packages):
            errors.append("implementation boundary has invalid published-packages")
            packages = []
        package_set = set(packages)
        targets = policy.get("targets", {})
        expected_all_targets = {
            target for label, target in targets.items() if label != "no-std"
        } if isinstance(targets, dict) else set()
        actual_all_targets: set[str] = set()
        for identifier, profile in profile_records.items():
            if profile.get("mode") != PROFILE_ALL:
                continue
            target = profile.get("target")
            if (
                not isinstance(target, str)
                or identifier != target_profile(PROFILE_ALL, target)
                or set(profile.get("packages", [])) != package_set
                or profile.get("support") != "supported"
                or profile.get("api-inventory") is not True
            ):
                errors.append(f"all-features profile is not target-exact: {identifier}")
            else:
                actual_all_targets.add(target)
        if actual_all_targets != expected_all_targets:
            errors.append("all-features profiles do not exactly cover boundary runtime/cross targets")
        bare = profile_records.get(PROFILE_BARE)
        if bare is None or bare.get("mode") != PROFILE_BARE or set(bare.get("packages", [])) != package_set or bare.get("support") != "unsupported" or bare.get("api-inventory") is not False:
            errors.append("no-default-features must be explicitly unsupported and non-inventory")
        expected_nostd = policy.get("no-std-package-features", {})
        target = policy.get("targets", {}).get("no-std")
        actual_nostd: dict[str, list[str]] = {}
        for identifier, profile in profile_records.items():
            if profile.get("mode") != PROFILE_NOSTD:
                continue
            package = profile.get("package")
            if not isinstance(package, str):
                errors.append(f"profile {identifier} has no package")
                continue
            if package in actual_nostd:
                errors.append(f"duplicate no_std package profile: {package}")
            if profile.get("target") != target or profile.get("support") != "supported" or profile.get("api-inventory") is not True:
                errors.append(f"profile {identifier} has invalid no_std target/support")
            features = profile.get("features")
            if not isinstance(features, list) or not all(isinstance(v, str) for v in features):
                errors.append(f"profile {identifier} has invalid features")
                continue
            actual_nostd[package] = features
        if actual_nostd != expected_nostd:
            errors.append("ledger no_std profile rows differ from implementation-boundary.toml")
        if set(surface_packages) != package_set:
            errors.append(f"package surface set differs from boundary; missing={sorted(package_set-set(surface_packages))}, extra={sorted(set(surface_packages)-package_set)}")

    feature_records = ledger.get("feature", [])
    ledger_features: dict[str, set[str]] = {}
    seen_feature_rows: set[tuple[str, str]] = set()
    allowed_feature_classes = {"capability", "umbrella", "environment", "diagnostic", "acceleration", "compatibility"}
    if not isinstance(feature_records, list):
        errors.append("[[feature]] must be an array of tables")
        feature_records = []
    for offset, feature in enumerate(feature_records):
        if not isinstance(feature, dict):
            errors.append(f"feature[{offset}] must be a table")
            continue
        package, name = feature.get("package"), feature.get("name")
        if not valid_nonempty_string(package) or not valid_nonempty_string(name):
            errors.append(f"feature[{offset}] has no package/name")
            continue
        key = (str(package), str(name))
        if key in seen_feature_rows:
            errors.append(f"duplicate feature classification: {package}/{name}")
            continue
        seen_feature_rows.add(key)
        ledger_features.setdefault(str(package), set()).add(str(name))
        metrics["features"] += 1
        if feature.get("classification") not in allowed_feature_classes:
            errors.append(f"feature {package}/{name} has invalid classification")
        refs = feature.get("surfaces")
        if not isinstance(refs, list) or not refs:
            errors.append(f"feature {package}/{name} has invalid surfaces")
        for surface_id in refs if isinstance(refs, list) else []:
            if surface_id not in surfaces:
                errors.append(f"feature {package}/{name} references unknown surface {surface_id}")
            elif surfaces[surface_id].get("package") != package:
                errors.append(f"feature {package}/{name} surface/package mismatch: {surface_id}")
    if metadata_features is not None:
        for package in sorted(set(metadata_features) | set(ledger_features)):
            for name in sorted(metadata_features.get(package, set()) - ledger_features.get(package, set())):
                errors.append(f"unclassified Cargo feature: {package}/{name}")
            for name in sorted(ledger_features.get(package, set()) - metadata_features.get(package, set())):
                errors.append(f"stale Cargo feature classification: {package}/{name}")
        for identifier, operation in operations.items():
            package = operation.get("crate")
            feature_profile = operation.get("feature-profile")
            if (
                isinstance(package, str)
                and isinstance(feature_profile, str)
                and not feature_profile.startswith("profile-bound:")
                and feature_profile not in metadata_features.get(package, set())
            ):
                errors.append(
                    f"operation {identifier} feature-profile is not a declared Cargo feature: "
                    f"{package}/{feature_profile}"
                )

    return errors, metrics


def run_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess[Any]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=False,
            text=text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise AssuranceFailure(f"cannot run {command[0]}: {error}") from error


def select_toolchain(repo: Path, ledger: dict[str, Any]) -> str:
    requested = ledger.get("rustdoc-toolchain")
    expected_commit = ledger.get("rustdoc-commit")
    expected_cargo_commit = ledger.get("cargo-commit")
    expected_rustc_commit = ledger.get("rustc-commit")
    if (
        not isinstance(requested, str)
        or not isinstance(expected_commit, str)
        or not isinstance(expected_cargo_commit, str)
        or not isinstance(expected_rustc_commit, str)
    ):
        raise AssuranceFailure("ledger rustdoc/cargo toolchain commits are missing")
    candidates = [requested]
    if requested.startswith("nightly-"):
        candidates.append("nightly")
    for candidate in candidates:
        result = run_command(["rustdoc", f"+{candidate}", "-Vv"], cwd=repo)
        if result.returncode != 0:
            continue
        match = re.search(r"^commit-hash:\s*(\S+)$", result.stdout, re.MULTILINE)
        if match and match.group(1) == expected_commit:
            cargo = run_command(["cargo", f"+{candidate}", "-Vv"], cwd=repo)
            cargo_match = re.search(
                r"^commit-hash:\s*(\S+)$", cargo.stdout, re.MULTILINE
            ) if cargo.returncode == 0 else None
            if cargo_match and cargo_match.group(1) == expected_cargo_commit:
                rustc = run_command(["rustc", f"+{candidate}", "-Vv"], cwd=repo)
                rustc_match = re.search(
                    r"^commit-hash:\s*(\S+)$", rustc.stdout, re.MULTILINE
                ) if rustc.returncode == 0 else None
                if rustc_match and rustc_match.group(1) == expected_rustc_commit:
                    return candidate
    raise AssuranceFailure(
        f"pinned rustdoc/cargo {requested} at commits {expected_commit}/"
        f"{expected_cargo_commit}/{expected_rustc_commit} is not installed"
    )


def rustdoc_kind(item: dict[str, Any]) -> str:
    inner = item.get("inner")
    if not isinstance(inner, dict) or len(inner) != 1:
        return "unknown"
    return next(iter(inner))


def is_public(item: dict[str, Any]) -> bool:
    return item.get("visibility") == "public"


class RustdocProjection:
    """Project a rustdoc JSON crate into stable public bindings and members."""

    def __init__(self, document: dict[str, Any], package: str, profile: str):
        self.document = document
        self.package = package
        self.profile = profile
        self.index: dict[str, dict[str, Any]] = document.get("index", {})
        self.paths: dict[str, dict[str, Any]] = document.get("paths", {})
        self.root_id = str(document.get("root"))
        root = self.index.get(self.root_id)
        if root is None:
            raise AssuranceFailure(f"rustdoc root is absent for {package}/{profile}")
        self.root_crate_id = root.get("crate_id")
        self.crate_name = root.get("name")
        if not isinstance(self.crate_name, str):
            raise AssuranceFailure(f"rustdoc root has no name for {package}/{profile}")
        self.entries: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}

    def item(self, item_id: Any) -> dict[str, Any] | None:
        return self.index.get(str(item_id))

    def canonical(self, item_id: Any, fallback: str) -> str:
        path = self.paths.get(str(item_id), {}).get("path")
        if isinstance(path, list) and all(isinstance(part, str) for part in path):
            return "::".join(path)
        return fallback

    def target_kind(self, item_id: Any) -> str:
        path_kind = self.paths.get(str(item_id), {}).get("kind")
        if isinstance(path_kind, str):
            return path_kind
        item = self.item(item_id)
        return rustdoc_kind(item) if item is not None else "unresolved"

    def normalized_impl_identity(self, impl_data: dict[str, Any]) -> dict[str, Any]:
        """Return a profile-stable, complete identity for an explicit trait impl.

        Rustdoc's numeric item ids are build-local.  Replacing every referenced
        id with its canonical path retains self type, trait generic arguments,
        generic parameters and constraints without making the identity depend
        on traversal order or on how many aliases happen to be visible in a
        target profile.
        """

        def normalize(value: Any) -> Any:
            if isinstance(value, list):
                return [normalize(item) for item in value]
            if not isinstance(value, dict):
                return value
            result: dict[str, Any] = {}
            for key, item in sorted(value.items()):
                if key in {"span", "items", "provided_trait_methods"}:
                    continue
                if key == "id":
                    result["canonical_id"] = self.canonical(item, str(item))
                else:
                    result[key] = normalize(item)
            return result

        return normalize(
            {
                "trait": impl_data.get("trait"),
                "for": impl_data.get("for"),
                "generics": impl_data.get("generics"),
                "is_negative": impl_data.get("is_negative"),
                "is_synthetic": impl_data.get("is_synthetic"),
                "blanket_impl": impl_data.get("blanket_impl"),
            }
        )

    @staticmethod
    def api_envelope(record: dict[str, Any]) -> dict[str, Any]:
        """Normalize API-semantic item state without unstable source spans."""

        return {
            key: copy.deepcopy(record.get(key))
            for key in (
                "name", "visibility", "attrs", "deprecation", "stability",
                "const_stability", "docs", "inner",
            )
            if key in record
        }

    def use_binding_digest(
        self, use_item_id: Any, *, target_id: Any, canonical: str, kind: str,
        inherited: str | None = None,
    ) -> str:
        use_item = self.item(use_item_id)
        if use_item is None or rustdoc_kind(use_item) != "use":
            raise AssuranceFailure(
                f"public alias lacks its use binding for {self.package}/{self.profile}"
            )
        envelope: dict[str, Any] = {
            "use": self.api_envelope(use_item),
            "target-canonical": canonical,
            "target-kind": kind,
            "target-id-canonical": self.canonical(target_id, str(target_id)),
        }
        if inherited is not None:
            envelope["inherited-alias-binding-sha256"] = inherited
        return hashlib.sha256(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def add(
        self,
        path: str,
        unit: str,
        kind: str,
        canonical: str,
        item_id: Any = None,
        *,
        impl_identity_sha256: str | None = None,
        trait_methods: list[str] | None = None,
        alias_binding_sha256: str | None = None,
        alias_source: str | None = None,
    ) -> str:
        item = self.item(item_id) if item_id is not None else None
        declaration = self.api_envelope(item) if isinstance(item, dict) else {"kind": kind}
        if isinstance(item, dict) and rustdoc_kind(item) == "impl":
            impl_data = item.get("inner", {}).get("impl", {})
            declaration = {
                "impl": self.api_envelope(item),
                "items": [
                    self.api_envelope(self.item(member_id))
                    for member_id in impl_data.get("items", [])
                    if self.item(member_id) is not None
                ],
            }
        if alias_binding_sha256 is not None:
            if HEX_SHA256.fullmatch(alias_binding_sha256) is None:
                raise AssuranceFailure(
                    f"invalid alias binding digest for {self.package}/{self.profile}: {path}"
                )
            declaration = {
                "alias-binding-sha256": alias_binding_sha256,
                "target": declaration,
            }
        declaration_sha256 = hashlib.sha256(
            json.dumps(declaration, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        # Trait impl display names are unconditionally qualified by the full
        # digest of the complete normalized impl identity.  This avoids both
        # truncated-hash collisions and cross-profile instability when one
        # profile exposes fewer same-name impls than another.
        if kind == "trait_impl":
            if impl_identity_sha256 is None or HEX_SHA256.fullmatch(impl_identity_sha256) is None:
                raise AssuranceFailure(
                    f"trait impl lacks a complete identity for {self.package}/{self.profile}: {path}"
                )
            if path.endswith("}"):
                path = f"{path[:-1]}#{impl_identity_sha256}}}"
            else:
                path = f"{path}#{impl_identity_sha256}"
            canonical = f"{canonical}#{impl_identity_sha256}"
        entry = {
            "package": self.package,
            "path": path,
            "unit": unit,
            "kind": kind,
            "canonical": canonical,
            "declaration_sha256": {self.profile: declaration_sha256},
            "profiles": [self.profile],
        }
        if alias_binding_sha256 is not None:
            entry["alias_binding_sha256"] = {
                self.profile: alias_binding_sha256
            }
            if alias_source is not None:
                entry["alias_source"] = alias_source
        if kind == "trait_impl":
            entry["impl_identity_sha256"] = impl_identity_sha256
            entry["trait_methods"] = {self.profile: sorted(set(trait_methods or []))}
        if any(
            existing.get("path") == path
            and entry_identity(existing) != entry_identity(entry)
            for existing in self.entries.values()
        ):
            raise AssuranceFailure(
                f"unresolved public path collision for {self.package}/{self.profile}: {path}"
            )
        key = entry_identity(entry)
        existing = self.entries.get(key)
        if existing is None:
            self.entries[key] = entry
        else:
            merge_profile_digests(
                existing.setdefault("declaration_sha256", {}),
                entry.get("declaration_sha256", {}),
            )
            if "alias_binding_sha256" in entry:
                merge_profile_digests(
                    existing.setdefault("alias_binding_sha256", {}),
                    entry.get("alias_binding_sha256", {}),
                )
                merge_alias_source(existing, entry)
            existing["profiles"] = sorted(
                set(existing.get("profiles", [])) | set(entry.get("profiles", []))
            )
            if kind == "trait_impl":
                if existing.get("impl_identity_sha256") != impl_identity_sha256:
                    raise AssuranceFailure(
                        f"trait impl identity collision for {self.package}/{self.profile}: {path}"
                    )
                existing.setdefault("trait_methods", {}).update(entry["trait_methods"])
        return declaration_sha256

    def add_variant_fields(
        self, variant_id: Any, visible_path: str, canonical: str,
        *, alias_binding_sha256: str | None = None,
    ) -> None:
        variant = self.item(variant_id)
        if variant is None:
            return
        variant_data = variant.get("inner", {}).get("variant", {}).get("kind", {})
        fields: Iterable[Any] = []
        if isinstance(variant_data, dict):
            struct = variant_data.get("struct")
            if isinstance(struct, dict):
                fields = struct.get("fields", [])
            elif isinstance(variant_data.get("tuple"), list):
                fields = variant_data["tuple"]
        for offset, field_id in enumerate(fields):
            field = self.item(field_id)
            if field is None:
                continue
            name = field.get("name")
            if not isinstance(name, str):
                name = str(offset)
            self.add(
                f"{visible_path}::{name}",
                "member",
                "field",
                f"{canonical}::{name}",
                field_id,
                alias_binding_sha256=alias_binding_sha256,
            )

    def add_members(
        self,
        item_id: Any,
        visible_path: str,
        canonical: str,
        seen: set[str] | None = None,
        alias_binding_sha256: str | None = None,
    ) -> None:
        item = self.item(item_id)
        if item is None or item.get("crate_id") != self.root_crate_id:
            return
        if seen is None:
            seen = set()
        key = str(item_id)
        if key in seen:
            return
        seen = set(seen)
        seen.add(key)
        kind = rustdoc_kind(item)
        data = item.get("inner", {}).get(kind, {})
        if not isinstance(data, dict):
            return

        if kind in {"struct", "union"}:
            fields: Iterable[Any] = []
            if kind == "struct":
                shape = data.get("kind", {})
                if isinstance(shape, dict):
                    if isinstance(shape.get("plain"), dict):
                        fields = shape["plain"].get("fields", [])
                    elif isinstance(shape.get("tuple"), list):
                        fields = shape["tuple"]
            else:
                fields = data.get("fields", [])
            for offset, field_id in enumerate(fields):
                field = self.item(field_id)
                if field is None or not is_public(field):
                    continue
                name = field.get("name")
                if not isinstance(name, str):
                    name = str(offset)
                self.add(
                    f"{visible_path}::{name}", "member", "field", f"{canonical}::{name}", field_id
                    , alias_binding_sha256=alias_binding_sha256
                )

        if kind == "enum":
            for variant_id in data.get("variants", []):
                variant = self.item(variant_id)
                if variant is None or not isinstance(variant.get("name"), str):
                    continue
                name = variant["name"]
                variant_path = f"{visible_path}::{name}"
                variant_canonical = self.canonical(variant_id, f"{canonical}::{name}")
                self.add(
                    variant_path, "member", "variant", variant_canonical, variant_id,
                    alias_binding_sha256=alias_binding_sha256,
                )
                self.add_variant_fields(
                    variant_id, variant_path, variant_canonical,
                    alias_binding_sha256=alias_binding_sha256,
                )

        if kind == "trait":
            for member_id in data.get("items", []):
                member = self.item(member_id)
                if member is None or not isinstance(member.get("name"), str):
                    continue
                name = member["name"]
                self.add(
                    f"{visible_path}::{name}",
                    "member",
                    rustdoc_kind(member),
                    self.canonical(member_id, f"{canonical}::{name}"),
                    member_id,
                    alias_binding_sha256=alias_binding_sha256,
                )

        for impl_id in data.get("impls", []):
            impl_item = self.item(impl_id)
            impl_data = (
                impl_item.get("inner", {}).get("impl") if impl_item is not None else None
            )
            if not isinstance(impl_data, dict):
                continue
            trait = impl_data.get("trait")
            if trait is not None:
                if (
                    impl_data.get("is_synthetic") is True
                    or impl_data.get("blanket_impl") is not None
                    or not isinstance(trait, dict)
                ):
                    continue
                trait_name = trait.get("path")
                if not isinstance(trait_name, str):
                    continue
                impl_identity = self.normalized_impl_identity(impl_data)
                impl_digest = hashlib.sha256(
                    json.dumps(impl_identity, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                trait_methods = sorted(
                    {
                        str(member.get("name"))
                        for member_id in impl_data.get("items", [])
                        if (member := self.item(member_id)) is not None
                        and rustdoc_kind(member) == "function"
                        and isinstance(member.get("name"), str)
                    }
                    | {
                        str(name)
                        for name in impl_data.get("provided_trait_methods", [])
                        if isinstance(name, str)
                    }
                )
                self.add(
                    f"{visible_path}::{{impl {trait_name}}}",
                    "member",
                    "trait_impl",
                    f"{canonical}::{{impl {self.canonical(trait.get('id'), trait_name)}}}",
                    impl_id,
                    impl_identity_sha256=impl_digest,
                    trait_methods=trait_methods,
                    alias_binding_sha256=alias_binding_sha256,
                )
                continue
            for member_id in impl_data.get("items", []):
                member = self.item(member_id)
                if (
                    member is None
                    or not is_public(member)
                    or not isinstance(member.get("name"), str)
                ):
                    continue
                name = member["name"]
                self.add(
                    f"{visible_path}::{name}",
                    "member",
                    rustdoc_kind(member),
                    self.canonical(member_id, f"{canonical}::{name}"),
                    member_id,
                    alias_binding_sha256=alias_binding_sha256,
                )

        if kind == "type_alias":
            target = data.get("type")
            if isinstance(target, dict):
                resolved = target.get("resolved_path")
                if isinstance(resolved, dict) and resolved.get("id") is not None:
                    self.add_members(
                        resolved["id"], visible_path, canonical, seen,
                        alias_binding_sha256=alias_binding_sha256,
                    )

    def walk_module(
        self, module_id: Any, visible_parent: str, module_stack: tuple[str, ...],
        alias_binding_sha256: str | None = None,
    ) -> None:
        module_key = str(module_id)
        if module_key in module_stack:
            return
        module = self.item(module_id)
        module_data = module.get("inner", {}).get("module") if module is not None else None
        if not isinstance(module_data, dict):
            return
        stack = (*module_stack, module_key)
        for child_id in module_data.get("items", []):
            child = self.item(child_id)
            if child is None or not is_public(child):
                continue
            kind = rustdoc_kind(child)
            if kind == "use":
                use = child.get("inner", {}).get("use", {})
                target_id = use.get("id")
                target_kind = self.target_kind(target_id)
                use_canonical = self.canonical(target_id, str(use.get("source", "unresolved")))
                use_binding = self.use_binding_digest(
                    child_id, target_id=target_id, canonical=use_canonical,
                    kind=target_kind, inherited=alias_binding_sha256,
                )
                if use.get("is_glob"):
                    target = self.item(target_id)
                    if target is not None and rustdoc_kind(target) == "module":
                        self.walk_module(
                            target_id, visible_parent, stack,
                            alias_binding_sha256=use_binding,
                        )
                    else:
                        source = use.get("source", "unresolved")
                        self.add(
                            f"{visible_parent}::{{{source}::*}}",
                            "export",
                            "glob_reexport",
                            self.canonical(target_id, str(source)),
                            target_id,
                            alias_binding_sha256=use_binding,
                            alias_source=str(source),
                        )
                    continue
                name = use.get("name")
                if not isinstance(name, str):
                    raise AssuranceFailure(
                        f"unnamed public use in {self.package}/{self.profile}"
                    )
                path = f"{visible_parent}::{name}"
                canonical = self.canonical(target_id, str(use.get("source", name)))
                self.add(
                    path, "export", target_kind, canonical, target_id,
                    alias_binding_sha256=use_binding,
                    alias_source=str(use.get("source", name)),
                )
                target = self.item(target_id)
                if target is not None and target.get("crate_id") == self.root_crate_id:
                    if target_kind == "module":
                        self.walk_module(
                            target_id, path, stack,
                            alias_binding_sha256=use_binding,
                        )
                    else:
                        self.add_members(
                            target_id, path, canonical,
                            alias_binding_sha256=use_binding,
                        )
                continue

            name = child.get("name")
            if not isinstance(name, str):
                raise AssuranceFailure(
                    f"unnamed public {kind} in {self.package}/{self.profile}"
                )
            path = f"{visible_parent}::{name}"
            canonical = self.canonical(child_id, path)
            self.add(
                path, "export", kind, canonical, child_id,
                alias_binding_sha256=alias_binding_sha256,
            )
            if kind == "module":
                self.walk_module(
                    child_id, path, stack,
                    alias_binding_sha256=alias_binding_sha256,
                )
            else:
                self.add_members(
                    child_id, path, canonical,
                    alias_binding_sha256=alias_binding_sha256,
                )

    def project(self) -> list[dict[str, Any]]:
        self.walk_module(self.root_id, self.crate_name, ())
        return sorted(self.entries.values(), key=entry_identity)


def cargo_metadata(
    repo: Path, toolchain: str, *, manifest_path: Path | None = None
) -> dict[str, Any]:
    command = [
        "cargo", f"+{toolchain}", "metadata", "--locked", "--offline",
        "--no-deps", "--format-version", "1",
    ]
    if manifest_path is not None:
        command.extend(["--manifest-path", str(manifest_path)])
    result = run_command(command, cwd=repo)
    if result.returncode != 0:
        raise AssuranceFailure(f"cargo metadata failed:\n{result.stderr.strip()}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AssuranceFailure(f"cargo metadata returned invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise AssuranceFailure("cargo metadata root is not an object")
    return value


def metadata_feature_map(
    metadata: dict[str, Any], packages: list[str]
) -> dict[str, set[str]]:
    by_name = {
        package.get("name"): package
        for package in metadata.get("packages", [])
        if isinstance(package, dict) and isinstance(package.get("name"), str)
    }
    workspace_members = set(metadata.get("workspace_members", []))
    publishable = {
        record["name"]
        for record in metadata.get("packages", [])
        if isinstance(record, dict)
        and record.get("id") in workspace_members
        and record.get("publish") != []
        and isinstance(record.get("name"), str)
    }
    if publishable != set(packages):
        raise AssuranceFailure(
            "Cargo publishable workspace package set differs from "
            f"implementation-boundary.toml; missing={sorted(set(packages) - publishable)}, "
            f"extra={sorted(publishable - set(packages))}"
        )
    result: dict[str, set[str]] = {}
    for package in packages:
        record = by_name.get(package)
        if record is None:
            raise AssuranceFailure(f"published package absent from cargo metadata: {package}")
        features = record.get("features")
        if not isinstance(features, dict):
            raise AssuranceFailure(f"cargo metadata features are invalid for {package}")
        result[package] = set(features)
    return result


def rustdoc_json_path(target_dir: Path, crate_name: str, target: str | None) -> Path:
    filename = f"{crate_name.replace('-', '_')}.json"
    if target is None:
        return target_dir / "doc" / filename
    return target_dir / target / "doc" / filename


def generate_live_entries(
    repo: Path,
    ledger: dict[str, Any],
    policy: dict[str, Any],
    *,
    keep_target: Path | None = None,
) -> list[dict[str, Any]]:
    packages = policy.get("published-packages")
    nostd = policy.get("no-std-package-features")
    target = policy.get("targets", {}).get("no-std")
    if (
        not isinstance(packages, list)
        or not all(isinstance(value, str) for value in packages)
        or not isinstance(nostd, dict)
        or not isinstance(target, str)
    ):
        raise AssuranceFailure("implementation boundary lacks public-API profile policy")
    toolchain = select_toolchain(repo, ledger)
    expected_format = ledger.get("rustdoc-format-version")
    if not isinstance(expected_format, int):
        raise AssuranceFailure("ledger rustdoc-format-version is missing")

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if keep_target is None:
        temporary = tempfile.TemporaryDirectory(prefix="dcrypt-assurance-rustdoc-")
        target_dir = Path(temporary.name)
    else:
        target_dir = keep_target.resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

    merged: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    try:
        target_map = policy.get("targets", {})
        if not isinstance(target_map, dict):
            raise AssuranceFailure("implementation boundary target map is invalid")
        all_feature_targets = sorted(
            value for key, value in target_map.items() if key != "no-std"
        )
        for package in packages:
            profiles = [
                (target_profile(PROFILE_ALL, rust_target), ["--all-features"], rust_target)
                for rust_target in all_feature_targets
            ]
            profiles.append(
                (
                    target_profile(PROFILE_NOSTD, target),
                    ["--no-default-features"]
                    + (["--features", ",".join(nostd[package])] if nostd[package] else []),
                    target,
                )
            )
            for profile, flags, rust_target in profiles:
                command = [
                    "cargo",
                    f"+{toolchain}",
                    "rustdoc",
                    "--quiet",
                    "--locked",
                    "--offline",
                    "-p",
                    package,
                    "--lib",
                    *flags,
                ]
                if rust_target is not None:
                    command.extend(["--target", rust_target])
                command.extend(
                    [
                        "--",
                        "-Z",
                        "unstable-options",
                        "--output-format",
                        "json",
                        "--document-hidden-items",
                    ]
                )
                result = run_command(command, cwd=repo, env=env)
                if result.returncode != 0:
                    raise AssuranceFailure(
                        f"rustdoc projection failed for {package}/{profile}:\n"
                        f"{result.stderr.strip()}"
                    )
                json_path = rustdoc_json_path(target_dir, package, rust_target)
                document = load_json(json_path)
                if document.get("format_version") != expected_format:
                    raise AssuranceFailure(
                        f"rustdoc JSON format mismatch for {package}/{profile}: "
                        f"expected {expected_format}, got {document.get('format_version')}"
                    )
                for entry in RustdocProjection(document, package, profile).project():
                    key = entry_identity(entry)
                    existing = merged.get(key)
                    if existing is None:
                        merged[key] = entry
                    else:
                        merge_profile_digests(
                            existing.setdefault("declaration_sha256", {}),
                            entry.get("declaration_sha256", {}),
                        )
                        if "alias_binding_sha256" in entry:
                            merge_profile_digests(
                                existing.setdefault("alias_binding_sha256", {}),
                                entry.get("alias_binding_sha256", {}),
                            )
                            merge_alias_source(existing, entry)
                        if entry.get("kind") == "trait_impl":
                            if existing.get("impl_identity_sha256") != entry.get("impl_identity_sha256"):
                                raise AssuranceFailure(
                                    f"trait impl identity changed across profiles: {entry.get('path')}"
                                )
                            existing.setdefault("trait_methods", {}).update(
                                entry.get("trait_methods", {})
                            )
                        existing["profiles"] = sorted(
                            set(existing["profiles"]) | set(entry["profiles"])
                        )
    finally:
        if temporary is not None:
            temporary.cleanup()
    def composed_alias_entry(
        *, alias: dict[str, Any], source: dict[str, Any], package: str,
        path: str, common_profiles: list[str],
    ) -> dict[str, Any]:
        alias_bindings = alias.get("alias_binding_sha256", {})
        if not isinstance(alias_bindings, dict):
            raise AssuranceFailure(f"external alias lacks binding hashes: {alias.get('path')}")
        declaration: dict[str, str] = {}
        chains: dict[str, str] = {}
        for profile in common_profiles:
            root_binding = alias_bindings.get(profile)
            source_declaration = source.get("declaration_sha256", {}).get(profile)
            if not isinstance(root_binding, str) or not isinstance(source_declaration, str):
                raise AssuranceFailure(
                    f"external alias lacks profile binding/declaration: {path}/{profile}"
                )
            source_binding = source.get("alias_binding_sha256", {}).get(profile)
            chain_value: dict[str, str] = {"import-binding": root_binding}
            if isinstance(source_binding, str):
                chain_value["source-alias-binding"] = source_binding
            chain = hashlib.sha256(
                json.dumps(chain_value, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            chains[profile] = chain
            declaration[profile] = hashlib.sha256(
                json.dumps(
                    {
                        "alias-binding-sha256": chain,
                        "source-declaration-sha256": source_declaration,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
        expanded = {
            "package": package,
            "path": path,
            "unit": source["unit"],
            "kind": source["kind"],
            "canonical": source["canonical"],
            "declaration_sha256": declaration,
            "alias_binding_sha256": chains,
            "profiles": common_profiles,
        }
        if source.get("kind") == "trait_impl":
            expanded["impl_identity_sha256"] = source.get("impl_identity_sha256")
            expanded["trait_methods"] = {
                profile: source.get("trait_methods", {}).get(profile, [])
                for profile in common_profiles
            }
        expanded["alias_source"] = str(source.get("path", source.get("canonical", "")))
        return expanded

    # rustdoc leaves a glob from an external crate as a single `use` record.
    # Expand it against the separately generated owning-crate projection so the
    # committed snapshot contains every imported binding rather than a wildcard.
    glob_keys = [
        key for key, entry in merged.items() if entry.get("kind") == "glob_reexport"
    ]
    for glob_key in glob_keys:
        glob = merged.pop(glob_key)
        prefix = f"{glob['canonical']}::"
        visible_parent = glob["path"].split("::{", 1)[0]
        matches = 0
        source_entries = list(merged.values())
        for source in source_entries:
            if not source["path"].startswith(prefix):
                continue
            common_profiles = sorted(set(glob["profiles"]) & set(source["profiles"]))
            if not common_profiles:
                continue
            expanded = composed_alias_entry(
                alias=glob,
                source=source,
                package=glob["package"],
                path=f"{visible_parent}::{source['path'][len(prefix):]}",
                common_profiles=common_profiles,
            )
            key = entry_identity(expanded)
            existing = merged.get(key)
            if existing is None:
                merged[key] = expanded
            else:
                existing["profiles"] = sorted(
                    set(existing["profiles"]) | set(common_profiles)
                )
                merge_profile_digests(
                    existing.setdefault("declaration_sha256", {}),
                    expanded.get("declaration_sha256", {}),
                )
                merge_profile_digests(
                    existing.setdefault("alias_binding_sha256", {}),
                    expanded.get("alias_binding_sha256", {}),
                )
                merge_alias_source(existing, expanded)
                if source.get("kind") == "trait_impl":
                    if existing.get("impl_identity_sha256") != expanded.get("impl_identity_sha256"):
                        raise AssuranceFailure(
                            f"glob-expanded trait impl identity collision: {expanded.get('path')}"
                        )
                    existing.setdefault("trait_methods", {}).update(
                        expanded.get("trait_methods", {})
                    )
            matches += 1
        if matches == 0:
            raise AssuranceFailure(
                f"cannot exactly expand external public glob: {glob['path']} -> "
                f"{glob['canonical']}"
            )

    # Expand every explicit re-export of an item owned by another published
    # crate. Rustdoc records only the `use` binding in the importing crate; it
    # does not repeat module descendants, enum variants, trait methods or type
    # impls. Build those visible API units from the independently projected
    # owner and intersect exact target profiles. This also covers renamed
    # facade modules such as `dcrypt::sign` and renamed type/trait aliases.
    package_by_root = {package.replace("-", "_"): package for package in packages}
    expandable_kinds = {"enum", "module", "struct", "trait", "type_alias", "union"}
    opaque_local_roots = sorted(
        {
            str(entry.get("canonical", "")).split("::", 1)[0]
            for entry in merged.values()
            if entry.get("unit") == "export"
            and entry.get("kind") in expandable_kinds
            and str(entry.get("canonical", "")).startswith("dcrypt_")
            and str(entry.get("canonical", "")).split("::", 1)[0] not in package_by_root
        }
    )
    if opaque_local_roots:
        raise AssuranceFailure(
            f"public aliases have unprojected dcrypt owners: {opaque_local_roots}"
        )
    changed = True
    while changed:
        changed = False
        aliases = [
            copy.deepcopy(entry)
            for entry in merged.values()
            if entry.get("unit") == "export"
            and entry.get("kind") in expandable_kinds
            and str(entry.get("canonical", "")).split("::", 1)[0] in package_by_root
            and str(entry.get("canonical", "")).split("::", 1)[0]
            != str(entry.get("package", "")).replace("-", "_")
        ]
        owner_entries = list(merged.values())
        for alias in aliases:
            canonical_root = str(alias["canonical"])
            immediate_root = str(alias.get("alias_source", "")).split("::", 1)[0]
            owner = package_by_root.get(
                immediate_root,
                package_by_root[canonical_root.split("::", 1)[0]],
            )
            owner_visible_roots = sorted(
                {
                    str(candidate.get("path"))
                    for candidate in owner_entries
                    if candidate.get("package") == owner
                    and candidate.get("unit") == "export"
                    and candidate.get("canonical") == canonical_root
                }
            )
            if canonical_root == owner.replace("-", "_"):
                owner_visible_roots.append(canonical_root)
            for source in owner_entries:
                if source.get("package") != owner:
                    continue
                source_path = str(source.get("path", ""))
                matching_roots = [
                    root for root in owner_visible_roots
                    if source_path.startswith(root + "::")
                ]
                if not matching_roots:
                    continue
                # Prefer the longest owner-visible root so nested aliases retain
                # their actual spelling rather than a canonical/private path.
                visible_root = max(matching_roots, key=len)
                source_canonical = str(source.get("canonical", ""))
                common_profiles = sorted(
                    set(alias.get("profiles", [])) & set(source.get("profiles", []))
                )
                if not common_profiles:
                    continue
                expanded = composed_alias_entry(
                    alias=alias,
                    source=source,
                    package=alias["package"],
                    path=f"{alias['path']}{source_path[len(visible_root):]}",
                    common_profiles=common_profiles,
                )
                key = entry_identity(expanded)
                existing = merged.get(key)
                if existing is None:
                    if any(
                        candidate.get("package") == expanded["package"]
                        and candidate.get("path") == expanded["path"]
                        and entry_identity(candidate) != key
                        for candidate in merged.values()
                    ):
                        raise AssuranceFailure(
                            f"explicit external alias collision: {expanded['package']}:"
                            f"{expanded['path']}"
                        )
                    merged[key] = expanded
                    changed = True
                else:
                    old_profiles = set(existing.get("profiles", []))
                    existing["profiles"] = sorted(old_profiles | set(common_profiles))
                    merge_profile_digests(
                        existing.setdefault("declaration_sha256", {}),
                        expanded["declaration_sha256"],
                    )
                    merge_profile_digests(
                        existing.setdefault("alias_binding_sha256", {}),
                        expanded["alias_binding_sha256"],
                    )
                    merge_alias_source(existing, expanded)
                    if set(existing["profiles"]) != old_profiles:
                        changed = True
                    if source.get("kind") == "trait_impl":
                        if existing.get("impl_identity_sha256") != expanded.get("impl_identity_sha256"):
                            raise AssuranceFailure(
                                f"external alias trait impl identity collision: {expanded['path']}"
                            )
                        existing.setdefault("trait_methods", {}).update(
                            expanded.get("trait_methods", {})
                        )
    return sorted(merged.values(), key=entry_identity)


def compare_live_snapshot(
    live_entries: list[dict[str, Any]], committed_entries: list[dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    live = {entry_identity(entry): entry for entry in live_entries}
    committed = {entry_identity(entry): entry for entry in committed_entries}
    for key in sorted(live.keys() - committed.keys()):
        entry = live[key]
        noun = "public export" if entry["unit"] == "export" else "public API member"
        errors.append(f"unclassified {noun}: {entry['path']}")
    for key in sorted(committed.keys() - live.keys()):
        entry = committed[key]
        noun = "public export" if entry["unit"] == "export" else "public API member"
        errors.append(f"stale classified {noun}: {entry['path']}")
    for key in sorted(live.keys() & committed.keys()):
        actual = live[key].get("profiles")
        expected = committed[key].get("profiles")
        if actual != expected:
            errors.append(
                f"public API profile mismatch for {live[key]['path']}: "
                f"snapshot={expected}, live={actual}"
            )
        actual_declaration = live[key].get("declaration_sha256")
        expected_declaration = committed[key].get("declaration_sha256")
        if actual_declaration != expected_declaration:
            errors.append(
                f"public API declaration mismatch for {live[key]['path']}: "
                f"snapshot={expected_declaration}, live={actual_declaration}"
            )
    return errors


def snapshot_document(
    *,
    repo: Path,
    ledger: dict[str, Any],
    policy_path: Path,
    entries: list[dict[str, Any]],
    old_snapshot: dict[str, Any] | None,
) -> dict[str, Any]:
    old_classifications: dict[
        tuple[str, str, str, str, str], dict[str, Any]
    ] = {}
    if old_snapshot is not None:
        for entry in old_snapshot.get("entries", []):
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("surface"), str)
                and isinstance(entry.get("classification"), str)
                and isinstance(entry.get("operation_refs"), list)
            ):
                old_classifications[entry_identity(entry)] = {
                    key: copy.deepcopy(entry.get(key))
                    for key in (
                        "surface", "classification", "operation_refs",
                        "declaration_sha256", "callable_disposition",
                        "non_operation_reason", "trait_method_assurance",
                        "data_disposition",
                    )
                    if key in entry
                }
    classified_entries = []
    for source in entries:
        entry = copy.deepcopy(source)
        previous = old_classifications.get(entry_identity(entry))
        if previous is None or previous.get("declaration_sha256") != entry.get("declaration_sha256"):
            entry["surface"] = UNCLASSIFIED
            entry["classification"] = UNCLASSIFIED
            entry["operation_refs"] = []
            if entry.get("kind") in CALLABLE_KINDS:
                entry["callable_disposition"] = UNCLASSIFIED
            if entry.get("kind") in DATA_KINDS:
                entry["data_disposition"] = UNCLASSIFIED
        else:
            entry["surface"] = previous["surface"]
            entry["classification"] = previous["classification"]
            entry["operation_refs"] = sorted(set(previous["operation_refs"]))
            if entry.get("kind") in CALLABLE_KINDS:
                entry["callable_disposition"] = previous.get("callable_disposition")
                if previous.get("non_operation_reason") is not None:
                    entry["non_operation_reason"] = previous["non_operation_reason"]
            if entry.get("kind") == "trait_impl" and previous.get("trait_method_assurance") is not None:
                entry["trait_method_assurance"] = previous["trait_method_assurance"]
            if entry.get("kind") in DATA_KINDS:
                entry["data_disposition"] = previous.get("data_disposition")
        classified_entries.append(entry)
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "source_commit": ledger.get("source-commit"),
        "source_tree": ledger.get("source-tree"),
        "boundary_policy_sha256": sha256_file(policy_path),
        "rustdoc_toolchain": ledger.get("rustdoc-toolchain"),
        "rustdoc_commit": ledger.get("rustdoc-commit"),
        "cargo_commit": ledger.get("cargo-commit"),
        "rustc_commit": ledger.get("rustc-commit"),
        "rustdoc_format_version": ledger.get("rustdoc-format-version"),
        "profiles": ledger_snapshot_profiles(ledger),
        "entries": classified_entries,
    }


def write_snapshot(path: Path, assurance_dir: Path, document: dict[str, Any]) -> None:
    resolved = path.resolve()
    try:
        resolved.relative_to(assurance_dir.resolve())
    except ValueError as error:
        raise AssuranceFailure("refusing to write a snapshot outside assurance/") from error
    resolved.parent.mkdir(parents=True, exist_ok=True)
    header = {key: value for key, value in document.items() if key != "entries"}
    rendered_lines = ["{"]
    for key, value in sorted(header.items()):
        rendered_lines.append(
            "  " + json.dumps(key) + ": "
            + json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            + ","
        )
    rendered_lines.append('  "entries": [')
    entries = sorted(
        document.get("entries", []),
        key=lambda item: (
            str(item.get("package", "")), str(item.get("path", "")),
            str(item.get("kind", "")), str(item.get("canonical", "")),
        ),
    )
    for offset, entry in enumerate(entries):
        suffix = "," if offset + 1 < len(entries) else ""
        rendered_lines.append(
            "    " + json.dumps(
                entry, sort_keys=True, ensure_ascii=True, separators=(",", ":")
            ) + suffix
        )
    rendered_lines.extend(["  ]", "}"])
    rendered = "\n".join(rendered_lines) + "\n"
    resolved.write_text(rendered, encoding="utf-8")


def render_supported_algorithms(
    operations_document: dict[str, Any], snapshot: dict[str, Any] | None = None
) -> str:
    errors: list[str] = []
    operations = effective_operation_rows(operations_document, errors)
    if errors:
        raise AssuranceFailure("invalid compact atomic rows: " + "; ".join(errors))
    curated_all = sorted(
        (
            operation for operation in operations
            if operation.get("semantic-review") == "curated"
        ),
        key=lambda value: str(value.get("id", "")),
    )
    curated = [
        operation for operation in curated_all
        if not str(operation.get("id", "")).startswith("alias.")
    ]
    pending = [
        operation for operation in operations
        if operation.get("semantic-review") == "required"
    ]
    lines = [
        "# dcrypt assurance-ledger algorithm inventory",
        "",
        "This file is generated from `atomic-operations.toml`. Do not edit it by hand.",
        "`Ready` is the machine-enforced future-release disposition; `blocked` records",
        "an assurance gap and is never presented as completed evidence.",
        "Only independently curated standardized/transitional rows are expanded below;",
        "unreviewed low-level callables remain exact, release-blocking rows in the TOML",
        "and are summarized here so this document stays human-reviewable.",
        "",
        "| ID | Algorithm | Parameter set | Operation | Support | Ready | Gap / limitation |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for operation in curated:
        cells = [
            operation.get("id", ""), operation.get("algorithm", ""),
            operation.get("parameter-set", ""), operation.get("operation", ""),
            operation.get("support", ""), operation.get("release-readiness", ""),
            operation.get("known-limitation", ""),
        ]
        escaped = [str(value).replace("|", "\\|").replace("\n", " ") for value in cells]
        lines.append("| " + " | ".join(escaped) + " |")
    pending_counts: dict[tuple[str, str], int] = {}
    for operation in pending:
        key = (str(operation.get("crate", "")), str(operation.get("surface", "")))
        pending_counts[key] = pending_counts.get(key, 0) + 1
    lines.extend([
        "", "## Unreviewed low-level callable backlog", "",
        "These rows are classified `internal-like-low-level`, carry no supported",
        "algorithm claim, and block release until their atomic semantics and evidence",
        "are reviewed. Exact IDs and bindings are in `atomic-operations.toml`.", "",
        "| Crate | Surface | Pending rows |",
        "| --- | --- | ---: |",
    ])
    for (package, surface), count in sorted(pending_counts.items()):
        lines.append(f"| {package} | {surface} | {count} |")
    unsupported = sorted(
        (
            entry for entry in (snapshot or {}).get("entries", [])
            if entry.get("classification") == "intentionally-unsupported"
        ),
        key=lambda entry: (str(entry.get("package", "")), str(entry.get("path", ""))),
    )
    lines.extend([
        "", "## Intentionally unsupported public markers", "",
        "These exports are inventoried but make no cryptographic operation claim.", "",
        "| Crate | Public path | Reason | Owner | Review due |",
        "| --- | --- | --- | --- | --- |",
    ])
    for entry in unsupported:
        cells = [
            entry.get("package", ""), entry.get("path", ""),
            entry.get("unsupported_reason", ""), entry.get("unsupported_owner", ""),
            entry.get("unsupported_review_due", ""),
        ]
        lines.append(
            "| " + " | ".join(
                str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells
            ) + " |"
        )
    lines.extend([
        "",
        f"Authoritative curated atomic rows: {len(curated)}",
        f"Derived cross-crate curated alias rows: {len(curated_all) - len(curated)}",
        f"Unreviewed release-blocking low-level rows: {len(pending)}",
        f"Total atomic rows: {len(operations)}",
        "",
    ])
    return "\n".join(lines)


def validate_repository_bindings(
    ledger: dict[str, Any], *, repo: Path, policy: dict[str, Any], errors: list[str]
) -> None:
    commit = ledger.get("source-commit")
    tree = ledger.get("source-tree")
    if isinstance(commit, str) and HEX_GIT_ID.fullmatch(commit):
        resolved = run_command(["git", "rev-parse", f"{commit}^{{commit}}"], cwd=repo)
        if resolved.returncode != 0 or resolved.stdout.strip() != commit:
            errors.append("ledger source-commit is not an available exact Git commit")
        resolved_tree = run_command(["git", "rev-parse", f"{commit}^{{tree}}"], cwd=repo)
        if resolved_tree.returncode != 0 or resolved_tree.stdout.strip() != tree:
            errors.append("ledger source-tree does not match source-commit")
        ancestor = run_command(["git", "merge-base", "--is-ancestor", commit, "HEAD"], cwd=repo)
        if ancestor.returncode != 0:
            errors.append("ledger source-commit is not an ancestor of current HEAD")

    lock_rows = ledger.get("lockfile", [])
    actual: dict[str, str] = {}
    if not isinstance(lock_rows, list):
        errors.append("[[lockfile]] must be an array of tables")
        lock_rows = []
    for offset, row in enumerate(lock_rows):
        if not isinstance(row, dict) or not valid_nonempty_string(row.get("path")):
            errors.append(f"lockfile[{offset}] has no path")
            continue
        path_value = row["path"]
        if path_value in actual:
            errors.append(f"duplicate lockfile binding: {path_value}")
            continue
        digest = row.get("sha256")
        if not isinstance(digest, str) or HEX_SHA256.fullmatch(digest) is None:
            errors.append(f"lockfile {path_value} has invalid sha256")
            continue
        path = safe_repo_file(repo, path_value, f"lockfile {path_value}", errors)
        if path is not None and sha256_file(path) != digest:
            errors.append(f"lockfile digest mismatch: {path_value}")
        actual[path_value] = digest
    expected = {"Cargo.lock", f"{policy.get('verification-workspace')}/Cargo.lock", f"{policy.get('fuzz-workspace')}/Cargo.lock"}
    for row in policy.get("owned-excluded-workspaces", []):
        if isinstance(row, dict) and isinstance(row.get("path"), str):
            expected.add(f"{row['path']}/Cargo.lock")
    if set(actual) != expected:
        errors.append(f"lockfile binding set mismatch: missing={sorted(expected-set(actual))}, extra={sorted(set(actual)-expected)}")


def fixture_self_test(assurance_dir: Path) -> int:
    """Run the standalone adversarial suite used by CI and release review."""

    script = assurance_dir / "assurance-selftest.py"
    result = run_command([sys.executable, "-B", str(script)], cwd=assurance_dir.parent)
    if result.stdout:
        print(result.stdout.strip())
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr.strip(), file=sys.stderr)
        return result.returncode
    return 0


def main(argv: list[str] | None = None) -> int:
    assurance_dir = Path(__file__).resolve().parent
    default_repo = assurance_dir.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=default_repo)
    parser.add_argument("--ledger", type=Path, default=assurance_dir / "ledger.toml")
    parser.add_argument(
        "--snapshot", type=Path, default=assurance_dir / "public-api-snapshot.json"
    )
    parser.add_argument("--mode", choices=("ci", "release"), default="ci")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--snapshot-only",
        action="store_true",
        help="validate committed classifications without invoking rustdoc",
    )
    parser.add_argument(
        "--refresh-snapshot",
        action="store_true",
        help="regenerate the snapshot; all newly observed entries remain UNCLASSIFIED",
    )
    parser.add_argument(
        "--refresh-subject-manifest",
        action="store_true",
        help="regenerate the Git-object-bound subject manifest under assurance/",
    )
    parser.add_argument(
        "--keep-target",
        type=Path,
        help="retain rustdoc build products in this target directory",
    )
    args = parser.parse_args(argv)

    try:
        if args.self_test:
            if args.refresh_snapshot or args.refresh_subject_manifest:
                raise AssuranceFailure("--self-test and refresh modes are mutually exclusive")
            return fixture_self_test(assurance_dir)
        if args.mode == "release" and args.snapshot_only:
            raise AssuranceFailure(
                "release mode requires a live rustdoc inventory; --snapshot-only is diagnostic only"
            )
        if args.refresh_snapshot and args.snapshot_only:
            raise AssuranceFailure(
                "--refresh-snapshot and --snapshot-only are mutually exclusive"
            )
        if args.refresh_subject_manifest and (args.snapshot_only or args.refresh_snapshot):
            raise AssuranceFailure(
                "--refresh-subject-manifest cannot be combined with snapshot modes"
            )
        if args.refresh_snapshot and args.mode == "release":
            raise AssuranceFailure(
                "snapshot refresh is a review operation and cannot run in release mode"
            )

        repo = args.repo.resolve()
        preflight_errors = build_environment_preflight(repo)
        if preflight_errors:
            raise AssuranceFailure("; ".join(preflight_errors))
        ledger_path = args.ledger.resolve()
        try:
            ledger_path.relative_to(repo)
        except ValueError as error:
            raise AssuranceFailure("--ledger must remain inside --repo") from error
        ledger_dir = ledger_path.parent
        ledger = load_toml(ledger_path)
        if args.refresh_subject_manifest:
            subject_value = ledger.get("subject-manifest")
            if not isinstance(subject_value, str) or not subject_value:
                raise AssuranceFailure("ledger subject-manifest path is missing")
            subject_path = resolve_repo_reference(
                repo=repo,
                base=ledger_dir,
                value=subject_value,
                label="ledger subject-manifest",
                must_exist=False,
            )
            try:
                subject_path.relative_to(assurance_dir.resolve())
            except ValueError as error:
                raise AssuranceFailure(
                    "refusing to write a subject manifest outside assurance/"
                ) from error
            document = subject_manifest_document(
                repo=repo,
                source_commit=str(ledger.get("source-commit", "")),
                source_tree=str(ledger.get("source-tree", "")),
            )
            subject_path.write_text(
                json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8"
            )
            print(f"wrote {subject_path} ({len(document['files'])} bound files)")
            return 0
        generator_value = ledger.get("ledger-generator")
        curated_value = ledger.get("curated-operations")
        if not isinstance(generator_value, str) or not generator_value:
            raise AssuranceFailure("ledger generator path is missing")
        if not isinstance(curated_value, str) or not curated_value:
            raise AssuranceFailure("curated operations path is missing")
        generator_path = resolve_repo_reference(
            repo=repo, base=ledger_dir, value=generator_value,
            label="ledger generator",
        )
        curated_path = resolve_repo_reference(
            repo=repo, base=ledger_dir, value=curated_value,
            label="ledger curated-operations",
        )
        if not args.refresh_snapshot:
            generated = run_command(
                [sys.executable, "-B", str(generator_path), "--check"], cwd=repo
            )
            if generated.returncode != 0:
                detail = (generated.stderr or generated.stdout).strip()
                raise AssuranceFailure(
                    "assurance generator reproducibility check failed"
                    + (f": {detail}" if detail else "")
                )
        boundary_value = ledger.get("boundary-policy")
        policy_path = resolve_repo_reference(
            repo=repo,
            base=ledger_dir,
            value=boundary_value,
            label="ledger boundary-policy",
        )
        policy = load_toml(policy_path)
        packages = policy.get("published-packages")
        if not isinstance(packages, list) or not all(isinstance(p, str) for p in packages):
            raise AssuranceFailure("implementation boundary published-packages is invalid")
        toolchain = select_toolchain(repo, ledger)
        metadata = cargo_metadata(repo, toolchain)
        features = metadata_feature_map(metadata, packages)
        isolated_workspace_paths: set[str] = set()
        for key in ("verification-workspace", "fuzz-workspace"):
            value = policy.get(key)
            if isinstance(value, str) and value:
                isolated_workspace_paths.add(value)
        for row in policy.get("owned-excluded-workspaces", []):
            if isinstance(row, dict) and isinstance(row.get("path"), str):
                isolated_workspace_paths.add(row["path"])
        isolated_metadata = [
            cargo_metadata(
                repo,
                toolchain,
                manifest_path=repo / workspace / "Cargo.toml",
            )
            for workspace in sorted(isolated_workspace_paths)
        ]
        operations_value = ledger.get("atomic-operations")
        vector_manifest_value = ledger.get("acvp-vector-manifest")
        generated_doc_value = ledger.get("generated-document")
        snapshot_value = ledger.get("api-snapshot")
        subject_value = ledger.get("subject-manifest")
        if not all(isinstance(value, str) and value for value in (
            operations_value, vector_manifest_value, generated_doc_value,
            snapshot_value, subject_value,
        )):
            raise AssuranceFailure("ledger declared artifact paths are incomplete")
        operations_path = resolve_repo_reference(
            repo=repo, base=ledger_dir, value=operations_value,
            label="ledger atomic-operations",
        )
        vector_manifest_path = resolve_repo_reference(
            repo=repo, base=ledger_dir, value=vector_manifest_value,
            label="ledger ACVP vector manifest",
        )
        generated_doc_path = resolve_repo_reference(
            repo=repo, base=ledger_dir, value=generated_doc_value,
            label="ledger generated-document",
        )
        declared_snapshot = resolve_repo_reference(
            repo=repo, base=ledger_dir, value=snapshot_value,
            label="ledger api-snapshot", must_exist=not args.refresh_snapshot,
        )
        subject_path = resolve_repo_reference(
            repo=repo, base=ledger_dir, value=subject_value,
            label="ledger subject-manifest",
        )
        if declared_snapshot != args.snapshot.resolve():
            raise AssuranceFailure("--snapshot differs from ledger api-snapshot")
        operations = load_toml(operations_path)

        # Validate the immutable/current source subject and every Cargo-selected
        # source path before rustdoc can execute a build script. Cargo metadata
        # itself is locked/offline and does not compile the package.
        subject_manifest = load_json(subject_path)
        vector_manifest = load_json(vector_manifest_path)
        early_errors = validate_subject_manifest(
            subject_manifest,
            repo=repo,
            source_commit=ledger.get("source-commit"),
            source_tree=ledger.get("source-tree"),
        )
        early_errors.extend(validate_acvp_vector_manifest(
            vector_manifest,
            subject_manifest=subject_manifest,
            source_commit=ledger.get("source-commit"),
            source_tree=ledger.get("source-tree"),
        ))
        metadata_target_paths: set[str] = set()
        for metadata_document in [metadata, *isolated_metadata]:
            metadata_errors, target_paths = validate_metadata_source_paths(
                metadata_document, repo=repo, manifest=subject_manifest
            )
            early_errors.extend(metadata_errors)
            metadata_target_paths.update(target_paths)
        early_errors.extend(
            validate_source_policy(
                repo, subject_manifest, metadata_target_paths=metadata_target_paths
            )
        )
        if early_errors:
            raise AssuranceFailure("pre-rustdoc source preflight failed:\n" + "\n".join(
                f"- {error}" for error in sorted(set(early_errors))
            ))

        live_entries: list[dict[str, Any]] | None = None
        if not args.snapshot_only or args.refresh_snapshot:
            live_entries = generate_live_entries(
                repo, ledger, policy, keep_target=args.keep_target
            )

        old_snapshot = load_json(args.snapshot.resolve()) if args.snapshot.exists() else None
        if args.refresh_snapshot:
            assert live_entries is not None
            document = snapshot_document(
                repo=repo,
                ledger=ledger,
                policy_path=policy_path,
                entries=live_entries,
                old_snapshot=old_snapshot,
            )
            write_snapshot(args.snapshot, assurance_dir, document)
            unclassified = sum(
                entry.get("surface") == UNCLASSIFIED
                or entry.get("classification") == UNCLASSIFIED
                for entry in document["entries"]
            )
            print(
                f"wrote {args.snapshot} with {len(document['entries'])} API entries; "
                f"unclassified={unclassified}"
            )
            return 1 if unclassified else 0

        if old_snapshot is None:
            raise AssuranceFailure(f"public API snapshot is missing: {args.snapshot}")
        as_of = dt.datetime.now(dt.timezone.utc).date()
        errors, metrics = validate_ledger(
            ledger,
            operations,
            old_snapshot,
            repo=repo,
            as_of=as_of,
            mode=args.mode,
            policy=policy,
            metadata_features=features,
            check_paths=True,
        )
        validate_repository_bindings(ledger, repo=repo, policy=policy, errors=errors)
        # The same checks ran before rustdoc; do not repeat expensive Git/path
        # traversal after evidence generation.
        for key, path in (
            ("api-snapshot-sha256", args.snapshot.resolve()),
            ("atomic-operations-sha256", operations_path),
            ("curated-operations-sha256", curated_path),
            ("ledger-generator-sha256", generator_path),
            ("acvp-vector-manifest-sha256", vector_manifest_path),
            ("generated-document-sha256", generated_doc_path),
            ("subject-manifest-sha256", subject_path),
        ):
            expected_digest = ledger.get(key)
            if not isinstance(expected_digest, str) or HEX_SHA256.fullmatch(expected_digest) is None:
                errors.append(f"ledger {key} is missing or invalid")
            elif not path.is_file() or sha256_file(path) != expected_digest:
                errors.append(f"declared artifact digest mismatch: {path.name}")
        if generated_doc_path.is_file():
            expected_document = render_supported_algorithms(operations, old_snapshot)
            if generated_doc_path.read_text(encoding="utf-8") != expected_document:
                errors.append("generated supported-algorithm documentation drift")
        expected_policy_hash = old_snapshot.get("boundary_policy_sha256")
        actual_policy_hash = sha256_file(policy_path)
        if expected_policy_hash != actual_policy_hash:
            errors.append(
                "public API snapshot boundary policy digest mismatch: "
                f"snapshot={expected_policy_hash}, current={actual_policy_hash}"
            )
        for key, snapshot_key in (
            ("rustdoc-toolchain", "rustdoc_toolchain"),
            ("rustdoc-commit", "rustdoc_commit"),
            ("cargo-commit", "cargo_commit"),
            ("rustc-commit", "rustc_commit"),
            ("rustdoc-format-version", "rustdoc_format_version"),
        ):
            if ledger.get(key) != old_snapshot.get(snapshot_key):
                errors.append(f"ledger/snapshot {key} mismatch")
        if live_entries is not None:
            errors.extend(compare_live_snapshot(live_entries, old_snapshot.get("entries", [])))

        if errors:
            for error in errors:
                print(f"error: {error}", file=sys.stderr)
            return 1
        total = metrics["exports"] + metrics["members"]
        inventory_mode = "snapshot" if args.snapshot_only else "live rustdoc"
        print(
            "assurance ledger verified: "
            f"{metrics['classified']}/{total} API units classified, "
            f"{metrics['features']} features, {metrics['operations']} operations, "
            f"{metrics['evidence']} evidence records, "
            f"{metrics['release_blocked']} disclosed release blockers "
            f"({inventory_mode}, {args.mode})"
        )
        return 0
    except AssuranceFailure as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
