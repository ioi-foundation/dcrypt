#!/usr/bin/env python3
"""Transactionally rebind the reviewed protocol freeze to a final subject."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any


HEX_GIT_ID = re.compile(r"^[0-9a-f]{40}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
SPEC_RELATIVE_DIR = PurePosixPath("assurance/interoperability/protocol-specs")
SUBJECT_MANIFEST_RELATIVE = PurePosixPath("assurance/subject-manifest.json")
CURATED_RELATIVE = PurePosixPath("assurance/curated-operations.toml")
TRANSACTION_NAME = "dcrypt-protocol-spec-rebind-v1"
JOURNAL_NAME = "journal.json"

EXPECTED_ARTIFACT_GIT_MODES = {
    "ARTIFACTS.sha256": "100644",
    "CURRENT-BEHAVIOR.md": "100644",
    "README.md": "100644",
    "current-behavior.json": "100644",
    "protocol-spec.schema.json": "100644",
    "protocol-specs-selftest.py": "100755",
    "rebind-final-subject.py": "100755",
    "verify-protocol-specs.py": "100755",
}
MANIFESTED_FILES = set(EXPECTED_ARTIFACT_GIT_MODES) - {"ARTIFACTS.sha256"}
DESTINATION_NAMES = (
    "ARTIFACTS.sha256",
    "CURRENT-BEHAVIOR.md",
    "current-behavior.json",
    "verify-protocol-specs.py",
)
TRANSACTION_INPUT_GIT_MODES = {
    CURATED_RELATIVE.as_posix(): "100644",
    SUBJECT_MANIFEST_RELATIVE.as_posix(): "100644",
}

# These normalized pins are intentionally invariant across a legitimate subject
# rebind.  Only subject_binding, critical source SHA fields, and the one rendered
# binding paragraph are removed before hashing.  A committed semantic rewrite
# therefore cannot be blessed merely because it is present at HEAD.
EXPECTED_REVIEWED_REGISTRY_SEMANTICS_SHA256 = (
    "37b0ecf19b57cf4c526af6bcfbbbf51a3f6bfe034dd19e50a0040fd8742c8eff"
)
EXPECTED_REVIEWED_RENDERING_SEMANTICS_SHA256 = (
    "81291f16db5bb9b3353594f427b2e31ed90dc3daa03914757977a11a9ecaeae2"
)
EXPECTED_REVIEWED_CURATED_SHA256 = (
    "5e2b8cf7de029ff79bda08c0709d6c14b58b2ee655ef44966ef0a0a876ab21f4"
)

BINDING_PARAGRAPH_RE = re.compile(
    r"^This candidate currently has (?:a|an) \*\*[^*\n]+\*\* binding\."
    r"[^\n]*table retains support classifications\.$",
    re.MULTILINE,
)
BINDING_PARAGRAPH_SENTINEL = "{{ALLOWLISTED SUBJECT BINDING PARAGRAPH}}"

SUBJECT_ROOT_KEYS = [
    "schema_version",
    "source_commit",
    "source_tree",
    "roots",
    "root_files",
    "absent_build_inputs",
    "include_policy",
    "files",
]
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


class RebindError(Exception):
    """A fail-closed rebind or recovery error."""


class InjectedRebindFault(BaseException):
    """Self-test-only BaseException used to prove transactional rollback."""


def fail(message: str) -> None:
    raise RebindError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any, *, sort_keys: bool) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=sort_keys) + "\n"
    ).encode("utf-8")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse {path}: {error}")


def run_git(
    repo_root: Path,
    arguments: list[str],
    *,
    binary: bool = False,
) -> subprocess.CompletedProcess[Any]:
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
    return normalized != "assurance" and not normalized.startswith("assurance/")


def validate_path(path_value: str, label: str = "subject") -> None:
    pure = PurePosixPath(path_value)
    if (
        not path_value
        or pure.is_absolute()
        or ".." in pure.parts
        or "." in pure.parts
        or str(pure) != path_value
        or "\\" in path_value
    ):
        fail(f"unsafe or noncanonical {label} path: {path_value}")


def ensure_contained(path: Path, allowed_root: Path, label: str) -> None:
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


def ensure_regular(
    path: Path,
    allowed_root: Path,
    label: str,
    *,
    expected_mode: int | None = None,
    expected_git_mode: str | None = None,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"regular nonsymlink file required for {label}")
    if metadata.st_nlink != 1:
        fail(f"hardlink forbidden for {label}: nlink={metadata.st_nlink}")
    if expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode:
        fail(
            f"exact mode {expected_mode:04o} required for {label}; "
            f"got {stat.S_IMODE(metadata.st_mode):04o}"
        )
    if expected_git_mode is not None:
        canonical_git_mode(metadata.st_mode, expected_git_mode, label)
    ensure_contained(path, allowed_root, label)
    return metadata


def capture_input_identity(
    path: Path,
    repo_root: Path,
    label: str,
    expected_git_mode: str,
) -> tuple[bytes, dict[str, int | str]]:
    """Read a transaction input once and bind its stable descriptor metadata."""

    ensure_contained(path, repo_root, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"regular nonsymlink file required for {label}")
        if before.st_nlink != 1:
            fail(f"hardlink forbidden for {label}: nlink={before.st_nlink}")
        canonical_git_mode(before.st_mode, expected_git_mode, label)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        fail(f"cannot read stable transaction input {label}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    fields = (
        "st_dev",
        "st_ino",
        "st_uid",
        "st_gid",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        fail(f"transaction input metadata changed while read: {label}")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        fail(f"transaction input size changed while read: {label}")
    return raw, {
        "ctime_ns": before.st_ctime_ns,
        "device": before.st_dev,
        "gid": before.st_gid,
        "inode": before.st_ino,
        "mode": stat.S_IMODE(before.st_mode),
        "mtime_ns": before.st_mtime_ns,
        "nlink": before.st_nlink,
        "sha256": sha256_bytes(raw),
        "size": before.st_size,
        "uid": before.st_uid,
    }


def validate_input_identities(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != set(TRANSACTION_INPUT_GIT_MODES):
        fail("rebind transaction input identity closure is invalid")
    expected_fields = {
        "ctime_ns",
        "device",
        "gid",
        "inode",
        "mode",
        "mtime_ns",
        "nlink",
        "sha256",
        "size",
        "uid",
    }
    for path, expected_git_mode in TRANSACTION_INPUT_GIT_MODES.items():
        record = value[path]
        if not isinstance(record, dict) or set(record) != expected_fields:
            fail(f"rebind transaction input identity fields are invalid: {path}")
        integer_fields = expected_fields - {"sha256"}
        if any(
            not isinstance(record[field], int) or isinstance(record[field], bool)
            for field in integer_fields
        ) or any(record[field] < 0 for field in integer_fields):
            fail(f"rebind transaction input identity metadata is invalid: {path}")
        if record["nlink"] != 1 or HEX_SHA256.fullmatch(record["sha256"] or "") is None:
            fail(f"rebind transaction input identity digest/link count is invalid: {path}")
        canonical_git_mode(record["mode"], expected_git_mode, f"transaction input {path}")


def capture_transaction_inputs(repo_root: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
    raw_inputs: dict[str, bytes] = {}
    identities: dict[str, Any] = {}
    for relative, expected_git_mode in TRANSACTION_INPUT_GIT_MODES.items():
        raw, identity = capture_input_identity(
            repo_root / PurePosixPath(relative),
            repo_root,
            f"transaction input {relative}",
            expected_git_mode,
        )
        raw_inputs[relative] = raw
        identities[relative] = identity
    validate_input_identities(identities)
    return raw_inputs, identities


def verify_transaction_inputs(repo_root: Path, expected: dict[str, Any]) -> None:
    _raw, actual = capture_transaction_inputs(repo_root)
    if actual != expected:
        fail("transaction input bytes or metadata changed after preflight")


def ensure_real_directory_chain(repo_root: Path, relative: PurePosixPath) -> Path:
    current = repo_root
    ensure_contained(repo_root, repo_root, "repository root")
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            fail(f"cannot stat protocol directory component {current}: {error}")
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            fail(f"real nonsymlink directory required: {current}")
        ensure_contained(current, repo_root, f"protocol directory component {part}")
    return current


def git_blob_at_head(
    repo_root: Path,
    relative: PurePosixPath,
) -> tuple[str, bytes]:
    relative_text = relative.as_posix()
    listing = run_git(
        repo_root,
        ["ls-tree", "-z", "--full-tree", "HEAD", "--", relative_text],
        binary=True,
    )
    if listing.returncode != 0:
        fail(f"cannot inspect committed HEAD entry: {relative_text}")
    records = [record for record in listing.stdout.split(b"\0") if record]
    if len(records) != 1:
        fail(f"exactly one committed HEAD blob required: {relative_text}")
    try:
        metadata, raw_path = records[0].split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        committed_path = raw_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        fail(f"invalid committed HEAD tree record: {relative_text}")
    if committed_path != relative_text or object_type != "blob" or mode not in {
        "100644",
        "100755",
    }:
        fail(f"committed HEAD entry is not the exact regular blob: {relative_text}")
    blob = run_git(repo_root, ["cat-file", "blob", object_id], binary=True)
    if blob.returncode != 0:
        fail(f"cannot read committed HEAD blob: {relative_text}")
    return mode, blob.stdout


def preflight_committed_package(
    repo_root: Path,
    script_path: Path,
) -> tuple[Path, dict[str, bytes], dict[str, int]]:
    spec_dir = ensure_real_directory_chain(repo_root, SPEC_RELATIVE_DIR)
    expected_script = spec_dir / "rebind-final-subject.py"
    if script_path != expected_script:
        fail("rebind tool must execute from the contained canonical protocol-spec path")
    ensure_regular(
        expected_script,
        repo_root,
        "rebind tool",
        expected_git_mode=EXPECTED_ARTIFACT_GIT_MODES["rebind-final-subject.py"],
    )
    try:
        entries = list(os.scandir(spec_dir))
    except OSError as error:
        fail(f"cannot enumerate protocol-spec directory: {error}")
    actual_names = {entry.name for entry in entries}
    expected_names = set(EXPECTED_ARTIFACT_GIT_MODES)
    if actual_names != expected_names:
        fail(
            "protocol-spec artifact set mismatch before rebind; "
            f"missing={sorted(expected_names - actual_names)}, "
            f"extra={sorted(actual_names - expected_names)}"
        )

    originals: dict[str, bytes] = {}
    filesystem_modes: dict[str, int] = {}
    for name, expected_git_mode in sorted(EXPECTED_ARTIFACT_GIT_MODES.items()):
        path = spec_dir / name
        metadata = ensure_regular(
            path,
            repo_root,
            f"protocol artifact {name}",
            expected_git_mode=expected_git_mode,
        )
        git_mode, committed_bytes = git_blob_at_head(
            repo_root, SPEC_RELATIVE_DIR / name
        )
        if git_mode != expected_git_mode:
            fail(f"committed HEAD mode differs from reviewed mode: {name}")
        current_bytes = path.read_bytes()
        if current_bytes != committed_bytes:
            fail(f"protocol artifact differs from exact committed HEAD bytes: {name}")
        originals[name] = current_bytes
        filesystem_modes[name] = stat.S_IMODE(metadata.st_mode)
    return spec_dir, originals, filesystem_modes


def preflight_curated(repo_root: Path) -> tuple[Path, bytes]:
    path = repo_root / CURATED_RELATIVE
    ensure_regular(
        path,
        repo_root,
        "curated operations",
        expected_git_mode="100644",
    )
    git_mode, committed_bytes = git_blob_at_head(repo_root, CURATED_RELATIVE)
    if git_mode != "100644" or path.read_bytes() != committed_bytes:
        fail("curated operations must equal exact committed HEAD reviewed bytes")
    if sha256_bytes(committed_bytes) != EXPECTED_REVIEWED_CURATED_SHA256:
        fail("curated operations differs from the immutable reviewed semantic baseline")
    return path, committed_bytes


def normalized_registry_semantics(value: Any) -> bytes:
    if not isinstance(value, dict) or not isinstance(value.get("source_bindings"), list):
        fail("current behavior registry is malformed")
    normalized = copy.deepcopy(value)
    normalized["subject_binding"] = {"allowlisted": "subject-binding"}
    for index, entry in enumerate(normalized["source_bindings"]):
        if not isinstance(entry, dict) or set(entry) != {"path", "role", "sha256"}:
            fail(f"critical source binding {index} is malformed")
        entry["sha256"] = "0" * 64
    return canonical_json(normalized, sort_keys=True)


def normalized_rendering_semantics(value: str) -> bytes:
    normalized, count = BINDING_PARAGRAPH_RE.subn(
        BINDING_PARAGRAPH_SENTINEL,
        value,
    )
    if count != 1:
        fail("authoritative rendering must contain exactly one binding paragraph")
    return normalized.encode("utf-8")


def verify_reviewed_semantic_baseline(
    registry: Any,
    rendering: str,
) -> None:
    registry_digest = sha256_bytes(normalized_registry_semantics(registry))
    if registry_digest != EXPECTED_REVIEWED_REGISTRY_SEMANTICS_SHA256:
        fail("registry contains a non-allowlisted semantic change")
    rendering_digest = sha256_bytes(normalized_rendering_semantics(rendering))
    if rendering_digest != EXPECTED_REVIEWED_RENDERING_SEMANTICS_SHA256:
        fail("authoritative rendering contains a non-allowlisted semantic change")


def inspect_bound_tree(
    repo_root: Path,
    commit: str,
) -> dict[str, tuple[str, str]]:
    result = run_git(
        repo_root,
        ["ls-tree", "-r", "-z", "--full-tree", commit, "--", *SUBJECT_ROOTS],
        binary=True,
    )
    if result.returncode != 0:
        fail("cannot enumerate expected subject commit")
    entries: dict[str, tuple[str, str]] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path_value = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            fail("invalid Git tree record while rebinding")
        if object_type != "blob" or mode not in {"100644", "100755"}:
            fail(f"non-regular Git subject entry: {path_value}")
        validate_path(path_value)
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
        fail("cannot open expected subject blob pipes")
    result: dict[str, str] = {}
    for expected in identifiers:
        process.stdin.write((expected + "\n").encode("ascii"))
        process.stdin.flush()
        header = process.stdout.readline()
        if not header.endswith(b"\n"):
            fail("truncated git cat-file header")
        parts = header[:-1].decode("ascii", "replace").split(" ")
        if len(parts) != 3 or parts[0] != expected or parts[1] != "blob":
            fail("unexpected git cat-file header")
        try:
            remaining = int(parts[2])
        except ValueError:
            fail("invalid git cat-file size")
        digest = hashlib.sha256()
        while remaining:
            chunk = process.stdout.read(min(1024 * 1024, remaining))
            if not chunk:
                fail("truncated git cat-file blob")
            digest.update(chunk)
            remaining -= len(chunk)
        if process.stdout.read(1) != b"\n":
            fail("invalid git cat-file blob delimiter")
        result[expected] = digest.hexdigest()
    process.stdin.close()
    if process.stdout.read(1) != b"":
        fail("trailing git cat-file output")
    stderr = process.stderr.read()
    returncode = process.wait()
    if returncode != 0:
        fail("cannot read expected subject blobs: " + stderr.decode("utf-8", "replace"))
    return result


def verify_manifest(
    repo_root: Path,
    manifest_path: Path,
    expected_commit: str,
    expected_tree: str,
) -> tuple[dict[str, str], int, str]:
    ensure_regular(
        manifest_path,
        repo_root,
        "subject manifest",
        expected_git_mode="100644",
    )
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict) or list(manifest) != SUBJECT_ROOT_KEYS:
        fail("subject manifest root keys are invalid or noncanonical")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("source_commit") != expected_commit
        or manifest.get("source_tree") != expected_tree
        or manifest.get("roots") != SUBJECT_ROOTS
        or manifest.get("root_files") != SUBJECT_ROOT_FILES
        or manifest.get("absent_build_inputs") != SUBJECT_ABSENT_BUILD_INPUTS
        or manifest.get("include_policy") != SUBJECT_INCLUDE_POLICY
    ):
        fail("subject manifest does not describe the explicit expected commit/tree and scope")
    expected_manifest_bytes = (
        json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=False) + "\n"
    ).encode("utf-8")
    if manifest_path.read_bytes() != expected_manifest_bytes:
        fail("subject manifest is not canonical generator-form JSON")

    committed = inspect_bound_tree(repo_root, expected_commit)
    rows = manifest.get("files")
    if not isinstance(rows, list):
        fail("subject manifest files must be an array")
    declared: dict[str, tuple[str, str]] = {}
    ordered: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or list(row) != ["path", "sha256", "git_mode"]:
            fail(f"subject manifest files[{index}] keys are invalid")
        path_value, digest, mode = row.get("path"), row.get("sha256"), row.get("git_mode")
        if not isinstance(path_value, str):
            fail(f"subject manifest files[{index}] path is invalid")
        validate_path(path_value)
        if not subject_path_included(path_value):
            fail(f"subject manifest contains excluded path: {path_value}")
        if not isinstance(digest, str) or HEX_SHA256.fullmatch(digest) is None:
            fail(f"subject manifest files[{index}] digest is invalid")
        if mode not in {"100644", "100755"} or path_value in declared:
            fail(f"subject manifest files[{index}] mode or uniqueness is invalid")
        declared[path_value] = (digest, mode)
        ordered.append(path_value)
    if ordered != sorted(ordered) or set(declared) != set(committed):
        fail("subject manifest is not a complete sorted enumeration of the expected Git tree")

    blob_digests = git_blob_sha256s(
        repo_root,
        [object_id for _mode, object_id in committed.values()],
    )
    for path_value, (digest, mode) in declared.items():
        commit_mode, object_id = committed[path_value]
        if commit_mode != mode or blob_digests.get(object_id) != digest:
            fail(f"subject manifest row differs from expected Git blob: {path_value}")
        current_path = repo_root / PurePosixPath(path_value)
        metadata = ensure_regular(
            current_path,
            repo_root,
            f"current subject {path_value}",
        )
        canonical_git_mode(
            metadata.st_mode,
            mode,
            f"current subject {path_value}",
        )
        if sha256(current_path) != digest:
            fail(f"current subject differs from expected commit: {path_value}")
    return (
        {path: digest for path, (digest, _mode) in declared.items()},
        len(rows),
        sha256(manifest_path),
    )


def replace_assignment(text: str, name: str, replacement: str) -> str:
    pattern = re.compile(rf"^{re.escape(name)} = .*?$", re.MULTILINE)
    text, count = pattern.subn(f"{name} = {replacement}", text)
    if count != 1:
        fail(f"verifier assignment anchor is not unique: {name}")
    return text


def replace_reviewed_digest(text: str, name: str, digest: str) -> str:
    pattern = re.compile(
        rf'^(    "{re.escape(name)}": ")[0-9a-f]{{64}}(",)$',
        re.MULTILINE,
    )
    text, count = pattern.subn(rf"\g<1>{digest}\g<2>", text)
    if count != 1:
        fail(f"verifier reviewed-digest anchor is not unique: {name}")
    return text


def verify_registry_allowlist(original: Any, candidate: Any) -> None:
    if sha256_bytes(normalized_registry_semantics(original)) != sha256_bytes(
        normalized_registry_semantics(candidate)
    ):
        fail("candidate registry delta exceeds subject binding and critical SHA fields")
    old_rows = original["source_bindings"]
    new_rows = candidate["source_bindings"]
    if len(old_rows) != len(new_rows):
        fail("candidate registry changed critical source binding cardinality")
    for index, (old, new) in enumerate(zip(old_rows, new_rows)):
        if old["path"] != new["path"] or old["role"] != new["role"]:
            fail(f"candidate registry changed critical source identity or role at {index}")
        if set(old) != set(new):
            fail(f"candidate registry changed critical source shape at {index}")


def verify_verifier_allowlist(original: str, candidate: str) -> None:
    old_lines = original.splitlines(keepends=True)
    new_lines = candidate.splitlines(keepends=True)
    if len(old_lines) != len(new_lines):
        fail("candidate verifier changed line cardinality outside the allowlist")
    assignment_names = {
        "EXPECTED_SUBJECT_COMMIT",
        "EXPECTED_SUBJECT_TREE",
        "EXPECTED_SUBJECT_MANIFEST_SHA256",
        "EXPECTED_SUBJECT_FILE_COUNT",
        "EXPECTED_CURATED_OPERATIONS_SHA256",
        "EXPECTED_BINDING_STAGE",
        "EXPECTED_FINAL_REBIND_REQUIRED",
    }
    digest_prefixes = {
        '    "CURRENT-BEHAVIOR.md": ',
        '    "current-behavior.json": ',
    }
    for index, (old, new) in enumerate(zip(old_lines, new_lines), start=1):
        if old == new:
            continue
        assignment = old.split(" = ", 1)[0]
        if assignment in assignment_names and new.startswith(assignment + " = "):
            continue
        if any(old.startswith(prefix) and new.startswith(prefix) for prefix in digest_prefixes):
            continue
        fail(f"candidate verifier delta exceeds reviewed pins/constants at line {index}")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new_file(path: Path, value: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        offset = 0
        while offset < len(value):
            offset += os.write(descriptor, value[offset:])
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace_file_atomically(path: Path, value: bytes, mode: int) -> None:
    temporary = path.parent / f".rebind-tmp-{path.name}"
    if os.path.lexists(temporary):
        fail(f"stale atomic replacement path exists: {temporary.name}")
    write_new_file(temporary, value, mode)
    os.replace(temporary, path)
    fsync_directory(path.parent)


def transaction_path(repo_root: Path) -> Path:
    result = run_git(repo_root, ["rev-parse", "--path-format=absolute", "--git-path", TRANSACTION_NAME])
    if result.returncode != 0:
        fail("cannot resolve the Git-private rebind transaction path")
    path = Path(result.stdout.strip())
    try:
        path.parent.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve transaction parent: {error}")
    return path


def transaction_allowed_names() -> set[str]:
    names = {JOURNAL_NAME, f"{JOURNAL_NAME}.tmp"}
    for artifact in DESTINATION_NAMES:
        names.add(f"{artifact}.original")
        names.add(f"{artifact}.candidate")
    return names


def cleanup_transaction_directory(path: Path) -> None:
    if not path.exists():
        return
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("transaction marker is not a real directory")
    allowed = transaction_allowed_names()
    children = list(path.iterdir())
    unexpected = sorted(child.name for child in children if child.name not in allowed)
    if unexpected:
        fail(f"transaction directory contains unexpected paths: {unexpected}")
    # Keep the durable journal until every backup/candidate has been removed.
    # An interruption can therefore distinguish incomplete cleanup from an
    # active transaction; the final directory removal is the commit point.
    children.sort(key=lambda child: (child.name == JOURNAL_NAME, child.name))
    for child in children:
        child_metadata = child.lstat()
        if stat.S_ISLNK(child_metadata.st_mode) or not stat.S_ISREG(child_metadata.st_mode):
            fail(f"transaction child is not a regular file: {child.name}")
        if child_metadata.st_nlink != 1:
            fail(f"transaction child is hardlinked: {child.name}")
        child.unlink()
    path.rmdir()
    fsync_directory(path.parent)


def journal_path(transaction: Path) -> Path:
    return transaction / JOURNAL_NAME


def write_journal(transaction: Path, journal: dict[str, Any]) -> None:
    destination = journal_path(transaction)
    temporary = transaction / f"{JOURNAL_NAME}.tmp"
    if os.path.lexists(temporary):
        temporary.unlink()
    write_new_file(temporary, canonical_json(journal, sort_keys=True), 0o600)
    os.replace(temporary, destination)
    fsync_directory(transaction)


def read_journal(transaction: Path) -> dict[str, Any]:
    path = journal_path(transaction)
    ensure_regular(path, transaction, "rebind transaction journal", expected_mode=0o600)
    value = load_json(path)
    if not isinstance(value, dict):
        fail("rebind transaction journal root is invalid")
    if set(value) != {
        "artifact_modes",
        "destinations",
        "format_version",
        "inputs",
        "records",
        "state",
    } or value.get("format_version") != 1 or value.get("destinations") != list(DESTINATION_NAMES):
        fail("rebind transaction journal shape is invalid")
    if value.get("state") not in {"prepared", "applying", "complete"}:
        fail("rebind transaction journal state is invalid")
    validate_input_identities(value.get("inputs"))
    records = value.get("records")
    if not isinstance(records, dict) or set(records) != set(DESTINATION_NAMES):
        fail("rebind transaction journal records are invalid")
    artifact_modes = value.get("artifact_modes")
    if not isinstance(artifact_modes, dict) or set(artifact_modes) != set(
        EXPECTED_ARTIFACT_GIT_MODES
    ):
        fail("rebind transaction artifact-mode closure is invalid")
    for name, expected_git_mode in EXPECTED_ARTIFACT_GIT_MODES.items():
        mode = artifact_modes[name]
        if not isinstance(mode, int) or isinstance(mode, bool):
            fail(f"rebind transaction artifact mode is invalid: {name}")
        canonical_git_mode(mode, expected_git_mode, f"rebind transaction artifact {name}")
    for name in DESTINATION_NAMES:
        record = records[name]
        if (
            not isinstance(record, dict)
            or set(record) != {
                "candidate_sha256",
                "mode",
                "original_sha256",
            }
            or not isinstance(record["mode"], int)
            or isinstance(record["mode"], bool)
            or record["mode"] != artifact_modes[name]
            or not isinstance(record["candidate_sha256"], str)
            or HEX_SHA256.fullmatch(record["candidate_sha256"]) is None
            or not isinstance(record["original_sha256"], str)
            or HEX_SHA256.fullmatch(record["original_sha256"]) is None
        ):
            fail(f"rebind transaction record is invalid: {name}")
        canonical_git_mode(
            record["mode"],
            EXPECTED_ARTIFACT_GIT_MODES[name],
            f"rebind transaction record {name}",
        )
    return value


def stage_transaction(
    transaction: Path,
    originals: dict[str, bytes],
    candidates: dict[str, bytes],
    filesystem_modes: dict[str, int],
    input_identities: dict[str, Any],
) -> dict[str, Any]:
    if set(filesystem_modes) != set(EXPECTED_ARTIFACT_GIT_MODES):
        fail("staged transaction artifact-mode closure differs")
    for name, expected_git_mode in EXPECTED_ARTIFACT_GIT_MODES.items():
        mode = filesystem_modes[name]
        if not isinstance(mode, int) or isinstance(mode, bool):
            fail(f"staged transaction artifact mode is invalid: {name}")
        canonical_git_mode(mode, expected_git_mode, f"staged transaction artifact {name}")
    validate_input_identities(input_identities)
    if os.path.lexists(transaction):
        fail("a rebind transaction already exists")
    transaction.mkdir(mode=0o700)
    fsync_directory(transaction.parent)
    records: dict[str, dict[str, Any]] = {}
    try:
        for name in DESTINATION_NAMES:
            original = originals[name]
            candidate = candidates[name]
            mode = filesystem_modes[name]
            canonical_git_mode(
                mode,
                EXPECTED_ARTIFACT_GIT_MODES[name],
                f"staged transaction mode {name}",
            )
            write_new_file(transaction / f"{name}.original", original, 0o600)
            write_new_file(transaction / f"{name}.candidate", candidate, 0o600)
            records[name] = {
                "candidate_sha256": sha256_bytes(candidate),
                "mode": mode,
                "original_sha256": sha256_bytes(original),
            }
        journal = {
            "artifact_modes": dict(sorted(filesystem_modes.items())),
            "destinations": list(DESTINATION_NAMES),
            "format_version": 1,
            "inputs": input_identities,
            "records": records,
            "state": "prepared",
        }
        write_journal(transaction, journal)
        return journal
    except BaseException:
        # No destination is changed before a complete prepared journal exists.
        cleanup_transaction_directory(transaction)
        raise


def verify_destination_bytes(
    spec_dir: Path,
    expected: dict[str, bytes],
    filesystem_modes: dict[str, int],
    label: str,
) -> None:
    for name, value in expected.items():
        path = spec_dir / name
        ensure_regular(
            path,
            spec_dir,
            f"{label} {name}",
            expected_mode=filesystem_modes[name],
        )
        if path.read_bytes() != value:
            fail(f"{label} byte mismatch after transaction operation: {name}")


def rollback_transaction(
    transaction: Path,
    spec_dir: Path,
    journal: dict[str, Any],
    repo_root: Path,
) -> None:
    originals: dict[str, bytes] = {}
    for name in DESTINATION_NAMES:
        backup = transaction / f"{name}.original"
        ensure_regular(backup, transaction, f"transaction backup {name}", expected_mode=0o600)
        value = backup.read_bytes()
        if sha256_bytes(value) != journal["records"][name]["original_sha256"]:
            fail(f"transaction backup digest mismatch: {name}")
        originals[name] = value
    for name in DESTINATION_NAMES:
        original_mode = journal["records"][name]["mode"]
        path = spec_dir / name
        temporary = spec_dir / f".rebind-tmp-{name}"
        if os.path.lexists(temporary):
            temp_metadata = temporary.lstat()
            if stat.S_ISLNK(temp_metadata.st_mode) or not stat.S_ISREG(temp_metadata.st_mode):
                fail(f"unsafe interrupted replacement path: {temporary.name}")
            temporary.unlink()
        current_ok = False
        try:
            metadata = path.lstat()
            current_ok = (
                stat.S_ISREG(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and metadata.st_nlink == 1
                and stat.S_IMODE(metadata.st_mode) == original_mode
                and path.read_bytes() == originals[name]
            )
        except OSError:
            current_ok = False
        if not current_ok:
            replace_file_atomically(
                path,
                originals[name],
                original_mode,
            )
    fsync_directory(spec_dir)
    verify_destination_bytes(
        spec_dir,
        originals,
        {name: journal["records"][name]["mode"] for name in DESTINATION_NAMES},
        "rolled-back original",
    )
    if not artifact_modes_match_journal(spec_dir, journal):
        fail("artifact mode changed during transaction rollback")
    verify_transaction_inputs(repo_root, journal["inputs"])
    cleanup_transaction_directory(transaction)


def destinations_match_journal(
    spec_dir: Path,
    journal: dict[str, Any],
    digest_field: str,
) -> bool:
    for name in DESTINATION_NAMES:
        path = spec_dir / name
        try:
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != journal["records"][name]["mode"]
                or sha256(path) != journal["records"][name][digest_field]
            ):
                return False
        except OSError:
            return False
    return True


def artifact_modes_match_journal(spec_dir: Path, journal: dict[str, Any]) -> bool:
    for name in EXPECTED_ARTIFACT_GIT_MODES:
        path = spec_dir / name
        try:
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != journal["artifact_modes"][name]
            ):
                return False
        except OSError:
            return False
    return True


def verify_completed_transaction_for_finalization(
    repo_root: Path,
    spec_dir: Path,
    candidates: dict[str, bytes],
    journal: dict[str, Any],
) -> None:
    verify_transaction_inputs(repo_root, journal["inputs"])
    actual_names = {entry.name for entry in os.scandir(spec_dir)}
    if actual_names != set(EXPECTED_ARTIFACT_GIT_MODES):
        fail("completed transaction artifact set changed before finalization")
    for name, expected_git_mode in EXPECTED_ARTIFACT_GIT_MODES.items():
        path = spec_dir / name
        metadata = ensure_regular(
            path,
            repo_root,
            f"finalization artifact {name}",
            expected_git_mode=expected_git_mode,
        )
        if stat.S_IMODE(metadata.st_mode) != journal["artifact_modes"][name]:
            fail(f"artifact mode changed during retained transaction: {name}")
        if name in candidates:
            expected_bytes = candidates[name]
        else:
            git_mode, expected_bytes = git_blob_at_head(
                repo_root,
                SPEC_RELATIVE_DIR / name,
            )
            if git_mode != expected_git_mode:
                fail(f"committed mode changed before finalization: {name}")
        if path.read_bytes() != expected_bytes:
            fail(f"artifact changed after verified rebind and before finalization: {name}")
    preflight_curated(repo_root)
    verification = subprocess.run(
        [
            sys.executable,
            "-B",
            str(spec_dir / "verify-protocol-specs.py"),
            "--repo-root",
            str(repo_root),
            "--require-final-subject",
            "--check-current-subject",
        ],
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if verification.returncode != 0:
        fail("finalization verifier failed:\n" + verification.stdout + verification.stderr)
    verify_transaction_inputs(repo_root, journal["inputs"])


def recover_or_refuse_existing_transaction(
    repo_root: Path,
    transaction: Path,
    spec_dir: Path,
    *,
    rollback_requested: bool,
    finalize_requested: bool,
) -> bool:
    if not os.path.lexists(transaction):
        if rollback_requested or finalize_requested:
            fail("no rebind transaction exists")
        return False
    metadata = transaction.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("rebind transaction marker is not a real directory")
    if not journal_path(transaction).exists():
        children = list(transaction.iterdir())
        if not children:
            transaction.rmdir()
            fsync_directory(transaction.parent)
            fail("removed an interrupted empty transaction marker; rerun required")
        # Staging writes no destination before the prepared journal.  Prove the
        # package is still the committed baseline before discarding its files.
        preflight_committed_package(
            repo_root,
            spec_dir / "rebind-final-subject.py",
        )
        cleanup_transaction_directory(transaction)
        fail("discarded an interrupted pre-mutation staging marker; rerun required")
    journal = read_journal(transaction)
    inputs_unchanged = True
    try:
        verify_transaction_inputs(repo_root, journal["inputs"])
    except RebindError:
        inputs_unchanged = False
    if journal["state"] != "complete" and destinations_match_journal(
        spec_dir,
        journal,
        "original_sha256",
    ) and artifact_modes_match_journal(spec_dir, journal) and inputs_unchanged:
        cleanup_transaction_directory(transaction)
        if rollback_requested:
            print("final-subject rebind rollback: PASS (originals were already byte-exact)")
            return True
        fail("recovered an interrupted transaction with byte-exact originals; rerun required")
    if rollback_requested:
        rollback_transaction(transaction, spec_dir, journal, repo_root)
        print("final-subject rebind rollback: PASS (byte-exact originals restored)")
        return True
    if finalize_requested:
        if journal["state"] != "complete":
            fail("only a complete verified transaction may be finalized")
        candidates: dict[str, bytes] = {}
        for name in DESTINATION_NAMES:
            path = transaction / f"{name}.candidate"
            if path.exists():
                ensure_regular(
                    path,
                    transaction,
                    f"transaction candidate {name}",
                    expected_mode=0o600,
                )
                value = path.read_bytes()
            else:
                # Explicit finalization may resume after its prior cleanup was
                # interrupted.  The journal digest still authenticates the
                # fully applied destination byte string.
                value = (spec_dir / name).read_bytes()
            if sha256_bytes(value) != journal["records"][name]["candidate_sha256"]:
                fail(f"transaction candidate digest mismatch: {name}")
            candidates[name] = value
        verify_completed_transaction_for_finalization(
            repo_root,
            spec_dir,
            candidates,
            journal,
        )
        cleanup_transaction_directory(transaction)
        print("final-subject rebind transaction finalization: PASS")
        return True
    if journal["state"] != "complete":
        rollback_transaction(transaction, spec_dir, journal, repo_root)
        fail("recovered an interrupted transaction and restored originals; rerun required")
    fail(
        "a complete verified rebind transaction awaits explicit "
        "--finalize-transaction or --rollback-transaction"
    )


def build_candidates(
    spec_dir: Path,
    originals: dict[str, bytes],
    subject_rows: dict[str, str],
    file_count: int,
    manifest_digest: str,
    curated_digest: str,
    expected_commit: str,
    expected_tree: str,
) -> dict[str, bytes]:
    registry_path = spec_dir / "current-behavior.json"
    original_registry = load_json(registry_path)
    original_rendering = originals["CURRENT-BEHAVIOR.md"].decode("utf-8")
    verify_reviewed_semantic_baseline(original_registry, original_rendering)

    registry = copy.deepcopy(original_registry)
    critical_paths: set[str] = set()
    for entry in registry["source_bindings"]:
        path_value = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path_value, str) or path_value in critical_paths:
            fail("critical source bindings are malformed or duplicated")
        if path_value not in subject_rows:
            fail(f"critical source is absent from final subject manifest: {path_value}")
        entry["sha256"] = subject_rows[path_value]
        critical_paths.add(path_value)
    registry["subject_binding"] = {
        "binding_stage": "final-subject-candidate-review-required",
        "curated_operations_path": CURATED_RELATIVE.as_posix(),
        "curated_operations_sha256": curated_digest,
        "final_rebind_required": False,
        "manifest_file_count": file_count,
        "manifest_include_policy": SUBJECT_INCLUDE_POLICY,
        "source_commit": expected_commit,
        "source_tree": expected_tree,
        "subject_manifest_path": SUBJECT_MANIFEST_RELATIVE.as_posix(),
        "subject_manifest_sha256": manifest_digest,
    }
    verify_registry_allowlist(original_registry, registry)
    registry_bytes = canonical_json(registry, sort_keys=True)

    binding_paragraph = (
        "This candidate currently has a **final-subject-candidate-review-required** binding. "
        f"It binds source commit `{expected_commit}`, source tree `{expected_tree}`, "
        f"canonical `{SUBJECT_MANIFEST_RELATIVE.as_posix()}` SHA-256 "
        f"`{manifest_digest}` ({file_count:,} owned subject files under include policy "
        f"`{SUBJECT_INCLUDE_POLICY}`), and `{CURATED_RELATIVE.as_posix()}` SHA-256 "
        f"`{curated_digest}`. The curated-operations binding is required because the ECIES "
        "table retains support classifications."
    )
    rendering, paragraph_count = BINDING_PARAGRAPH_RE.subn(
        binding_paragraph,
        original_rendering,
    )
    if paragraph_count != 1:
        fail("authoritative binding paragraph anchor is not unique")
    if sha256_bytes(normalized_rendering_semantics(rendering)) != (
        EXPECTED_REVIEWED_RENDERING_SEMANTICS_SHA256
    ):
        fail("candidate rendering delta exceeds the exact binding paragraph")
    rendering_bytes = rendering.encode("utf-8")

    original_verifier = originals["verify-protocol-specs.py"].decode("utf-8")
    verifier = original_verifier
    verifier = replace_assignment(verifier, "EXPECTED_SUBJECT_COMMIT", repr(expected_commit))
    verifier = replace_assignment(verifier, "EXPECTED_SUBJECT_TREE", repr(expected_tree))
    verifier = replace_assignment(
        verifier,
        "EXPECTED_SUBJECT_MANIFEST_SHA256",
        repr(manifest_digest),
    )
    verifier = replace_assignment(verifier, "EXPECTED_SUBJECT_FILE_COUNT", str(file_count))
    verifier = replace_assignment(
        verifier,
        "EXPECTED_CURATED_OPERATIONS_SHA256",
        repr(curated_digest),
    )
    verifier = replace_assignment(
        verifier,
        "EXPECTED_BINDING_STAGE",
        repr("final-subject-candidate-review-required"),
    )
    verifier = replace_assignment(verifier, "EXPECTED_FINAL_REBIND_REQUIRED", "False")
    verifier = replace_reviewed_digest(
        verifier,
        "current-behavior.json",
        sha256_bytes(registry_bytes),
    )
    verifier = replace_reviewed_digest(
        verifier,
        "CURRENT-BEHAVIOR.md",
        sha256_bytes(rendering_bytes),
    )
    verify_verifier_allowlist(original_verifier, verifier)
    verifier_bytes = verifier.encode("utf-8")

    proposed = {
        "CURRENT-BEHAVIOR.md": rendering_bytes,
        "current-behavior.json": registry_bytes,
        "verify-protocol-specs.py": verifier_bytes,
    }
    artifact_lines = []
    for name in sorted(MANIFESTED_FILES):
        value = proposed[name] if name in proposed else originals[name]
        artifact_lines.append(f"{sha256_bytes(value)}  {name}")
    proposed["ARTIFACTS.sha256"] = ("\n".join(artifact_lines) + "\n").encode("utf-8")
    if set(proposed) != set(DESTINATION_NAMES):
        fail("candidate destination set exceeds the reviewed allowlist")
    return proposed


def parse_args() -> argparse.Namespace:
    own_dir = Path(__file__).absolute().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=own_dir.parents[2])
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-tree")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--rollback-transaction", action="store_true")
    parser.add_argument("--finalize-transaction", action="store_true")
    parser.add_argument(
        "--fault-after-replacements",
        type=int,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--abrupt-after-replacements",
        type=int,
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def run() -> None:
    args = parse_args()
    if args.rollback_transaction and args.finalize_transaction:
        fail("rollback and finalization are mutually exclusive")
    if args.dry_run and (args.rollback_transaction or args.finalize_transaction):
        fail("dry-run cannot be combined with transaction recovery actions")
    if args.fault_after_replacements is not None and args.fault_after_replacements < 1:
        fail("fault injection replacement count must be positive")
    if args.abrupt_after_replacements is not None and args.abrupt_after_replacements < 1:
        fail("abrupt interruption replacement count must be positive")

    repo_root = args.repo_root.resolve(strict=True)
    script_path = Path(__file__).absolute()
    spec_dir = ensure_real_directory_chain(repo_root, SPEC_RELATIVE_DIR)
    if script_path != spec_dir / "rebind-final-subject.py":
        fail("rebind tool must execute from the canonical contained protocol path")
    transaction = transaction_path(repo_root)
    if recover_or_refuse_existing_transaction(
        repo_root,
        transaction,
        spec_dir,
        rollback_requested=args.rollback_transaction,
        finalize_requested=args.finalize_transaction,
    ):
        return

    if not args.expected_commit or not args.expected_tree:
        fail("normal rebinding requires --expected-commit and --expected-tree")
    if args.expected_commit in {"HEAD", "@"} or args.expected_tree in {"HEAD", "@"}:
        fail("symbolic revisions are forbidden; provide exact 40-hex commit and tree IDs")
    if (
        HEX_GIT_ID.fullmatch(args.expected_commit) is None
        or HEX_GIT_ID.fullmatch(args.expected_tree) is None
    ):
        fail("expected commit and tree must be exact lowercase 40-hex object IDs")

    # No artifact mutation is possible before this complete committed-byte,
    # containment, set, mode, symlink, and hardlink preflight succeeds.
    spec_dir, all_originals, artifact_modes = preflight_committed_package(
        repo_root,
        script_path,
    )
    transaction_input_raw, transaction_input_identities = capture_transaction_inputs(
        repo_root
    )
    _curated_path, curated_bytes = preflight_curated(repo_root)
    if curated_bytes != transaction_input_raw[CURATED_RELATIVE.as_posix()]:
        fail("curated operations changed across preflight reads")
    curated_digest = sha256_bytes(curated_bytes)

    head = run_git(repo_root, ["rev-parse", "HEAD"])
    tree = run_git(repo_root, ["rev-parse", f"{args.expected_commit}^{{tree}}"])
    if head.returncode != 0 or head.stdout.strip() != args.expected_commit:
        fail("HEAD must be the explicit expected subject commit before rebinding")
    if tree.returncode != 0 or tree.stdout.strip() != args.expected_tree:
        fail("expected tree does not match the explicit expected commit")

    changed = run_git(
        repo_root,
        ["diff", "--name-only", "-z", "HEAD", "--", *SUBJECT_ROOTS],
        binary=True,
    )
    untracked = run_git(
        repo_root,
        ["ls-files", "--others", "--exclude-standard", "-z", "--", *SUBJECT_ROOTS],
        binary=True,
    )
    if changed.returncode != 0 or untracked.returncode != 0:
        fail("cannot inspect current worktree before rebinding")
    try:
        dirty_paths = {
            raw.decode("utf-8")
            for raw in (changed.stdout + untracked.stdout).split(b"\0")
            if raw
        }
    except UnicodeDecodeError:
        fail("worktree contains a non-UTF-8 path")
    dirty_subject = sorted(path for path in dirty_paths if subject_path_included(path))
    if dirty_subject:
        fail(f"non-assurance subject changes must be committed before rebinding: {dirty_subject}")
    present_sentinels = [
        path for path in SUBJECT_ABSENT_BUILD_INPUTS if os.path.lexists(repo_root / path)
    ]
    if present_sentinels:
        fail(f"declared absent build input exists: {present_sentinels}")

    manifest_path = repo_root / SUBJECT_MANIFEST_RELATIVE
    subject_rows, file_count, manifest_digest = verify_manifest(
        repo_root,
        manifest_path,
        args.expected_commit,
        args.expected_tree,
    )
    if manifest_digest != sha256_bytes(
        transaction_input_raw[SUBJECT_MANIFEST_RELATIVE.as_posix()]
    ):
        fail("subject manifest changed across preflight reads")
    candidates = build_candidates(
        spec_dir,
        all_originals,
        subject_rows,
        file_count,
        manifest_digest,
        curated_digest,
        args.expected_commit,
        args.expected_tree,
    )
    destination_originals = {name: all_originals[name] for name in DESTINATION_NAMES}
    verify_transaction_inputs(repo_root, transaction_input_identities)

    print(
        "final-subject rebind candidate: "
        f"commit={args.expected_commit} tree={args.expected_tree} files={file_count} "
        f"manifest_sha256={manifest_digest} curated_sha256={curated_digest}"
    )
    if args.dry_run:
        verify_destination_bytes(
            spec_dir,
            destination_originals,
            artifact_modes,
            "dry-run original",
        )
        print("dry-run: no files changed")
        return

    journal: dict[str, Any] | None = None
    try:
        journal = stage_transaction(
            transaction,
            destination_originals,
            candidates,
            artifact_modes,
            transaction_input_identities,
        )
        replacements = 0
        journal["state"] = "applying"
        write_journal(transaction, journal)
        for name in DESTINATION_NAMES:
            replace_file_atomically(
                spec_dir / name,
                candidates[name],
                artifact_modes[name],
            )
            replacements += 1
            if args.abrupt_after_replacements == replacements:
                # Deliberately bypass every Python cleanup path.  The durable
                # applying journal must drive byte-exact recovery next run.
                os._exit(86)
            if args.fault_after_replacements == replacements:
                raise InjectedRebindFault(
                    f"injected after {replacements} destination replacement(s)"
                )
        verify_destination_bytes(
            spec_dir,
            candidates,
            artifact_modes,
            "staged candidate",
        )
        verification = subprocess.run(
            [
                sys.executable,
                "-B",
                str(spec_dir / "verify-protocol-specs.py"),
                "--repo-root",
                str(repo_root),
                "--require-final-subject",
                "--check-current-subject",
            ],
            cwd=repo_root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if verification.returncode != 0:
            fail("post-rebind verifier failed:\n" + verification.stdout + verification.stderr)
        verify_transaction_inputs(repo_root, transaction_input_identities)
        verify_destination_bytes(
            spec_dir,
            candidates,
            artifact_modes,
            "verified candidate",
        )
        if not artifact_modes_match_journal(spec_dir, journal):
            fail("artifact mode changed before transaction completion")
        journal["state"] = "complete"
        write_journal(transaction, journal)
        print(verification.stdout.strip())
        print(
            "final-subject rebind: PASS; complete transaction retained for explicit "
            "--finalize-transaction or --rollback-transaction"
        )
    except BaseException as original_error:
        if journal is None:
            raise
        try:
            rollback_transaction(transaction, spec_dir, journal, repo_root)
            verify_destination_bytes(
                spec_dir,
                destination_originals,
                artifact_modes,
                "post-failure original",
            )
        except BaseException as rollback_error:
            raise RebindError(
                "rebind failed and byte-exact rollback could not be verified: "
                f"original={original_error!r}; rollback={rollback_error!r}"
            ) from rollback_error
        raise


if __name__ == "__main__":
    try:
        run()
    except InjectedRebindFault as error:
        print(f"final-subject rebind: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
    except RebindError as error:
        print(f"final-subject rebind: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
