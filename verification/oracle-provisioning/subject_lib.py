#!/usr/bin/env python3
"""Generate, verify, and materialize the exact isolated-workspace subject."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

from bundle_lib import (
    BundleError,
    HEX40,
    HEX64,
    SUBJECT_FORMAT,
    _exact_keys,
    _regular_unlinked_file,
    _safe_relative,
    canonical_json,
    sha256_file,
)


VERIFICATION_ROOT = "verification"
EXCLUDED_VERIFICATION_PREFIXES = [
    "verification/clean-room-protocol-reference",
    "verification/oracle-provisioning",
    "verification/target",
]
CONFIG_DIRECTORIES = [".cargo", "verification/.cargo"]
CONFIG_CANDIDATES = [
    ".cargo/config",
    ".cargo/config.toml",
    "verification/.cargo/config",
    "verification/.cargo/config.toml",
]
ROOT_FILES = ["Cargo.lock", "Cargo.toml"]
ROOT_PACKAGE_SCOPES = ["src"]
ROOT_AUTO_TARGET_DIRECTORIES = ["benches", "examples", "src", "tests"]
ROOT_BUILD_SCRIPT = "build.rs"
VECTOR_ROOT = "verification/vectors/ethereum_consensus_spec_tests"
VECTOR_PROVENANCE = f"{VECTOR_ROOT}/PROVENANCE.md"
EXPECTED_ETHEREUM_VECTOR_COUNT = 20
POST_SUBJECT_ALLOWED_FILES = [
    "verification/oracle-provisioning/bundle_lib.py",
    "verification/oracle-provisioning/manifest.json",
    "verification/oracle-provisioning/subject-inputs.json",
]
POST_SUBJECT_ALLOWED_PREFIXES = ["assurance"]
REBIND_ALLOWED_DIRTY_PREFIXES = ["assurance"]
REBIND_ALLOWED_DIRTY_FILES = [
    ".gitignore",
    "verification/oracle-provisioning/bundle_lib.py",
    "verification/oracle-provisioning/manifest.json",
    "verification/oracle-provisioning/subject-inputs.json",
]


def _git(repo_root: Path, arguments: list[str], *, text: bool = False) -> bytes | str:
    command = ["git", "-C", str(repo_root), *arguments]
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )
    if completed.returncode != 0:
        stderr = completed.stderr if text else completed.stderr.decode("utf-8", "replace")
        raise BundleError(f"Git command failed ({' '.join(command)}): {stderr.strip()}")
    return completed.stdout


def _commit_identity(repo_root: Path, commit: str) -> tuple[str, str]:
    if not isinstance(commit, str) or not HEX40.fullmatch(commit):
        raise BundleError("subject commit must be an exact lowercase 40-hex object name")
    resolved = str(_git(repo_root, ["rev-parse", "--verify", f"{commit}^{{commit}}"], text=True)).strip()
    if resolved != commit:
        raise BundleError(f"subject commit resolves unexpectedly: expected {commit}, got {resolved}")
    tree = str(_git(repo_root, ["rev-parse", f"{commit}^{{tree}}"], text=True)).strip()
    if not HEX40.fullmatch(tree):
        raise BundleError("subject tree is not an exact lowercase 40-hex object name")
    return resolved, tree


def _tree_entries(repo_root: Path, commit: str) -> dict[str, tuple[str, str]]:
    raw = _git(repo_root, ["ls-tree", "-r", "-z", commit])
    assert isinstance(raw, bytes)
    result: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_type, oid = metadata.decode("ascii").split(" ")
            path = encoded_path.decode("utf-8")
        except (UnicodeError, ValueError) as error:
            raise BundleError("cannot parse canonical Git tree entry") from error
        _safe_relative(path, "Git subject path")
        if object_type != "blob":
            raise BundleError(f"non-blob recursive Git tree entry: {path}")
        if mode not in ("100644", "100755", "120000") or not HEX40.fullmatch(oid):
            raise BundleError(f"unsupported Git tree metadata for {path}")
        result[path] = (mode, oid)
    return result


def _git_file(repo_root: Path, commit: str, path: str) -> bytes:
    data = _git(repo_root, ["show", f"{commit}:{path}"])
    assert isinstance(data, bytes)
    return data


def _dependency_tables(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    tables: list[dict[str, Any]] = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(key)
        if isinstance(table, dict):
            tables.append(table)
    target = manifest.get("target")
    if isinstance(target, dict):
        for target_record in target.values():
            if not isinstance(target_record, dict):
                continue
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target_record.get(key)
                if isinstance(table, dict):
                    tables.append(table)
    return tables


def _path_dependency_roots(repo_root: Path, commit: str, entries: dict[str, tuple[str, str]]) -> list[str]:
    queue = ["verification/Cargo.toml"]
    visited_manifests: set[str] = set()
    roots: set[str] = set()
    while queue:
        manifest_path = queue.pop(0)
        if manifest_path in visited_manifests:
            continue
        visited_manifests.add(manifest_path)
        try:
            manifest = tomllib.loads(_git_file(repo_root, commit, manifest_path).decode("utf-8"))
        except (UnicodeError, tomllib.TOMLDecodeError) as error:
            raise BundleError(f"cannot parse bound Cargo manifest {manifest_path}: {error}") from error
        for table in _dependency_tables(manifest):
            for dependency in table.values():
                if not isinstance(dependency, dict) or not isinstance(dependency.get("path"), str):
                    continue
                base = PurePosixPath(manifest_path).parent
                raw_parts = [*base.parts, *PurePosixPath(dependency["path"]).parts]
                normalized: list[str] = []
                for part in raw_parts:
                    if part in ("", "."):
                        continue
                    if part == "..":
                        if not normalized:
                            raise BundleError(f"path dependency escapes repository: {dependency['path']}")
                        normalized.pop()
                    else:
                        normalized.append(part)
                root = PurePosixPath(*normalized).as_posix()
                _safe_relative(root, "path dependency root")
                dependency_manifest = f"{root}/Cargo.toml"
                if dependency_manifest not in entries:
                    raise BundleError(f"path dependency manifest is absent at {commit}: {dependency_manifest}")
                roots.add(root)
                queue.append(dependency_manifest)
    return sorted(roots)


def _workspace_manifest_paths(
    repo_root: Path, commit: str, entries: dict[str, tuple[str, str]]
) -> list[str]:
    try:
        root_manifest = tomllib.loads(_git_file(repo_root, commit, "Cargo.toml").decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise BundleError(f"cannot parse root workspace Cargo.toml: {error}") from error
    workspace = root_manifest.get("workspace")
    members = workspace.get("members") if isinstance(workspace, dict) else None
    if not isinstance(members, list) or any(not isinstance(member, str) for member in members):
        raise BundleError("root Cargo.toml lacks an exact workspace.members array")
    result = ["Cargo.toml"]
    for member in members:
        if any(character in member for character in "*?["):
            raise BundleError(f"workspace glob is unsupported by the subject freezer: {member!r}")
        path = f"{PurePosixPath(member).as_posix().rstrip('/')}/Cargo.toml"
        _safe_relative(path, "workspace member manifest")
        if path not in entries:
            raise BundleError(f"workspace member manifest is absent at {commit}: {path}")
        result.append(path)
    return sorted(set(result))


def _parse_bound_manifest(repo_root: Path, commit: str, path: str) -> dict[str, Any]:
    try:
        value = tomllib.loads(_git_file(repo_root, commit, path).decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise BundleError(f"cannot parse bound Cargo manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise BundleError(f"bound Cargo manifest is not a table: {path}")
    return value


def _normalize_workspace_path(manifest_path: str, raw: str) -> str:
    base = PurePosixPath(manifest_path).parent
    parts: list[str] = []
    for part in (*base.parts, *PurePosixPath(raw).parts):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise BundleError(f"explicit Cargo workspace escapes repository: {raw}")
            parts.pop()
        else:
            parts.append(part)
    root = PurePosixPath(*parts).as_posix()
    _safe_relative(root, "explicit Cargo workspace root")
    return f"{root.rstrip('/')}/Cargo.toml"


def _workspace_discovery(
    repo_root: Path,
    commit: str,
    entries: dict[str, tuple[str, str]],
    path_roots: list[str],
) -> dict[str, Any]:
    """Freeze every Cargo.toml presence/absence probed to select workspaces."""
    package_manifests = [
        "verification/Cargo.toml",
        *[f"{root}/Cargo.toml" for root in path_roots],
    ]
    records: list[dict[str, Any]] = []
    all_candidates: set[str] = set()
    for package_manifest in sorted(package_manifests):
        manifest = _parse_bound_manifest(repo_root, commit, package_manifest)
        workspace = manifest.get("workspace")
        package = manifest.get("package")
        explicit = package.get("workspace") if isinstance(package, dict) else None
        if isinstance(workspace, dict):
            candidates = [package_manifest]
            selected = package_manifest
            selection = "manifest_defines_workspace"
        elif isinstance(explicit, str):
            selected = _normalize_workspace_path(package_manifest, explicit)
            candidates = [selected]
            selection = "explicit_package_workspace"
            if selected not in entries:
                raise BundleError(
                    f"explicit Cargo workspace manifest is absent at {commit}: {selected}"
                )
            if not isinstance(
                _parse_bound_manifest(repo_root, commit, selected).get("workspace"), dict
            ):
                raise BundleError(f"explicit Cargo workspace lacks [workspace]: {selected}")
        elif explicit is not None:
            raise BundleError(f"package.workspace is not a string in {package_manifest}")
        else:
            candidates = []
            selected = ""
            parent = PurePosixPath(package_manifest).parent.parent
            while True:
                candidate = (
                    "Cargo.toml"
                    if not parent.parts
                    else f"{parent.as_posix()}/Cargo.toml"
                )
                candidates.append(candidate)
                if candidate in entries and isinstance(
                    _parse_bound_manifest(repo_root, commit, candidate).get("workspace"), dict
                ):
                    selected = candidate
                    break
                if not parent.parts:
                    break
                parent = parent.parent
            if not selected:
                raise BundleError(
                    f"no repository-contained Cargo workspace found for {package_manifest}"
                )
            selection = "nearest_ancestor_workspace"
        all_candidates.update(candidates)
        records.append(
            {
                "candidate_manifests": candidates,
                "package_manifest": package_manifest,
                "selected_workspace_manifest": selected,
                "selection": selection,
            }
        )
    present = sorted(candidate for candidate in all_candidates if candidate in entries)
    return {
        "absent_candidates": sorted(all_candidates - set(present)),
        "package_records": records,
        "present_candidates": present,
    }


def _root_package_discovery(entries: dict[str, tuple[str, str]]) -> dict[str, Any]:
    """Freeze Cargo's default root-package build-script and auto-target probes."""
    directory_records: list[dict[str, str]] = []
    auto_target_files: set[str] = set()
    for directory in ROOT_AUTO_TARGET_DIRECTORIES:
        present = any(_under(path, directory) for path in entries)
        directory_records.append(
            {"path": directory, "state": "present_directory" if present else "absent"}
        )
        for path in entries:
            relative = PurePosixPath(path)
            if not _under(path, directory):
                continue
            parts = relative.parts
            direct_rust_file = len(parts) == 2 and parts[-1].endswith(".rs")
            nested_main = (
                directory in ("benches", "examples", "tests")
                and len(parts) == 3
                and parts[-1] == "main.rs"
            )
            if direct_rust_file or nested_main:
                auto_target_files.add(path)
    return {
        "auto_target_directories": directory_records,
        "auto_target_files": sorted(auto_target_files),
        "build_script": {
            "path": ROOT_BUILD_SCRIPT,
            "state": "present_file" if ROOT_BUILD_SCRIPT in entries else "absent",
        },
    }


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _excluded(path: str, prefixes: list[str]) -> bool:
    return any(_under(path, prefix) for prefix in prefixes)


def generate_subject_inputs(repo_root: Path, commit: str) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    source_commit, source_tree = _commit_identity(repo_root, commit)
    entries = _tree_entries(repo_root, source_commit)
    path_roots = _path_dependency_roots(repo_root, source_commit, entries)
    workspace_manifests = _workspace_manifest_paths(repo_root, source_commit, entries)
    workspace_discovery = _workspace_discovery(
        repo_root, source_commit, entries, path_roots
    )
    root_package_discovery = _root_package_discovery(entries)
    scopes = [
        {
            "excluded_prefixes": EXCLUDED_VERIFICATION_PREFIXES,
            "path": VERIFICATION_ROOT,
            "policy": "all_tracked_regular_files_except_explicit_prefixes",
        },
        *[
            {
                "excluded_prefixes": [f"{path}/target"],
                "path": path,
                "policy": "root_workspace_package_regular_files_except_generated_target",
            }
            for path in ROOT_PACKAGE_SCOPES
        ],
        *[
            {
                "excluded_prefixes": [f"{path}/target"],
                "path": path,
                "policy": "all_tracked_regular_files_except_generated_target",
            }
            for path in path_roots
        ],
    ]
    selected: set[str] = (
        set(ROOT_FILES)
        | set(workspace_manifests)
        | set(workspace_discovery["present_candidates"])
        | set(root_package_discovery["auto_target_files"])
    )
    if root_package_discovery["build_script"]["state"] == "present_file":
        selected.add(ROOT_BUILD_SCRIPT)
    for path in entries:
        for scope in scopes:
            if _under(path, scope["path"]) and not _excluded(path, scope["excluded_prefixes"]):
                selected.add(path)
                break
        if any(_under(path, directory) for directory in CONFIG_DIRECTORIES):
            selected.add(path)
    files: list[dict[str, Any]] = []
    for path in sorted(selected):
        if path not in entries:
            raise BundleError(f"required subject file is absent at {source_commit}: {path}")
        mode, oid = entries[path]
        if mode == "120000":
            raise BundleError(f"subject symlink is not permitted: {path}")
        content = _git_file(repo_root, source_commit, path)
        files.append(
            {
                "git_blob": oid,
                "git_mode": mode,
                "path": path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    selected_paths = {record["path"] for record in files}
    vector_paths = sorted(
        path for path in selected_paths if _under(path, VECTOR_ROOT) and path.endswith("/data.yaml")
    )
    if len(vector_paths) != EXPECTED_ETHEREUM_VECTOR_COUNT or VECTOR_PROVENANCE not in selected_paths:
        raise BundleError(
            "Ethereum vector closure must contain PROVENANCE.md and exactly "
            f"{EXPECTED_ETHEREUM_VECTOR_COUNT} data.yaml files"
        )
    present_config = sorted(path for path in CONFIG_CANDIDATES if path in entries)
    result = {
        "config_discovery": {
            "absent_candidates": sorted(set(CONFIG_CANDIDATES) - set(present_config)),
            "directories": CONFIG_DIRECTORIES,
            "present_candidates": present_config,
        },
        "file_count": len(files),
        "files": files,
        "format": SUBJECT_FORMAT,
        "path_dependency_roots": path_roots,
        "post_subject_delta_policy": {
            "allowed_committed_files": POST_SUBJECT_ALLOWED_FILES,
            "allowed_committed_prefixes": POST_SUBJECT_ALLOWED_PREFIXES,
            "allowed_worktree_files": REBIND_ALLOWED_DIRTY_FILES,
            "allowed_worktree_prefixes": REBIND_ALLOWED_DIRTY_PREFIXES,
            "source_must_be_ancestor": True,
        },
        "root_package_discovery": root_package_discovery,
        "root_files": ROOT_FILES,
        "scopes": scopes,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "vector_set": {
            "data_yaml_count": len(vector_paths),
            "data_yaml_paths": vector_paths,
            "provenance_path": VECTOR_PROVENANCE,
            "root": VECTOR_ROOT,
        },
        "workspace_discovery": workspace_discovery,
        "workspace_manifest_paths": workspace_manifests,
    }
    return validate_subject_inputs(result)


def validate_subject_inputs(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BundleError("subject-input root must be an object")
    _exact_keys(
        value,
        {
            "config_discovery",
            "file_count",
            "files",
            "format",
            "path_dependency_roots",
            "post_subject_delta_policy",
            "root_package_discovery",
            "root_files",
            "scopes",
            "source_commit",
            "source_tree",
            "vector_set",
            "workspace_discovery",
            "workspace_manifest_paths",
        },
        "subject inputs",
    )
    if value["format"] != SUBJECT_FORMAT:
        raise BundleError("unsupported subject-input format")
    for field in ("source_commit", "source_tree"):
        if not isinstance(value[field], str) or not HEX40.fullmatch(value[field]):
            raise BundleError(f"subject inputs {field} is not exact lowercase Git hex")
    if value["root_files"] != ROOT_FILES:
        raise BundleError("subject root_files differ from the reviewed set")
    root_discovery = value["root_package_discovery"]
    if not isinstance(root_discovery, dict):
        raise BundleError("root_package_discovery must be an object")
    _exact_keys(
        root_discovery,
        {"auto_target_directories", "auto_target_files", "build_script"},
        "root_package_discovery",
    )
    directories = root_discovery["auto_target_directories"]
    if (
        not isinstance(directories, list)
        or [record.get("path") if isinstance(record, dict) else None for record in directories]
        != ROOT_AUTO_TARGET_DIRECTORIES
    ):
        raise BundleError("root auto-target directory records differ from Cargo defaults")
    for index, record in enumerate(directories):
        if not isinstance(record, dict):
            raise BundleError(f"root auto-target directory {index} must be an object")
        _exact_keys(record, {"path", "state"}, f"root auto-target directory {index}")
        if record["state"] not in ("absent", "present_directory"):
            raise BundleError(f"root auto-target directory {index} has an invalid state")
    build_script = root_discovery["build_script"]
    if not isinstance(build_script, dict):
        raise BundleError("root build-script discovery must be an object")
    _exact_keys(build_script, {"path", "state"}, "root build-script discovery")
    if build_script["path"] != ROOT_BUILD_SCRIPT or build_script["state"] not in (
        "absent",
        "present_file",
    ):
        raise BundleError("root build-script discovery differs from Cargo defaults")
    auto_target_files = root_discovery["auto_target_files"]
    if (
        not isinstance(auto_target_files, list)
        or auto_target_files != sorted(set(auto_target_files))
    ):
        raise BundleError("root auto-target files must be sorted and unique")
    for path in auto_target_files:
        if not isinstance(path, str):
            raise BundleError("root auto-target path must be a string")
        parts = PurePosixPath(path).parts
        if not (
            len(parts) == 2
            and parts[0] in ROOT_AUTO_TARGET_DIRECTORIES
            and parts[-1].endswith(".rs")
        ) and not (
            len(parts) == 3
            and parts[0] in ("benches", "examples", "tests")
            and parts[-1] == "main.rs"
        ):
            raise BundleError(f"unsupported root auto-target candidate: {path}")
    roots = value["path_dependency_roots"]
    if not isinstance(roots, list) or roots != sorted(set(roots)):
        raise BundleError("path_dependency_roots must be a sorted unique array")
    for path in roots:
        if not isinstance(path, str):
            raise BundleError("path dependency root must be a string")
        _safe_relative(path, "path dependency root")
    if value["post_subject_delta_policy"] != {
        "allowed_committed_files": POST_SUBJECT_ALLOWED_FILES,
        "allowed_committed_prefixes": POST_SUBJECT_ALLOWED_PREFIXES,
        "allowed_worktree_files": REBIND_ALLOWED_DIRTY_FILES,
        "allowed_worktree_prefixes": REBIND_ALLOWED_DIRTY_PREFIXES,
        "source_must_be_ancestor": True,
    }:
        raise BundleError("post-subject delta policy differs from the reviewed allowlist")
    scopes = value["scopes"]
    expected_scopes = [
        {
            "excluded_prefixes": EXCLUDED_VERIFICATION_PREFIXES,
            "path": VERIFICATION_ROOT,
            "policy": "all_tracked_regular_files_except_explicit_prefixes",
        },
        *[
            {
                "excluded_prefixes": [f"{path}/target"],
                "path": path,
                "policy": "root_workspace_package_regular_files_except_generated_target",
            }
            for path in ROOT_PACKAGE_SCOPES
        ],
        *[
            {
                "excluded_prefixes": [f"{path}/target"],
                "path": path,
                "policy": "all_tracked_regular_files_except_generated_target",
            }
            for path in roots
        ],
    ]
    if scopes != expected_scopes:
        raise BundleError("subject scopes differ from the path-dependency closure")
    config = value["config_discovery"]
    if not isinstance(config, dict):
        raise BundleError("config_discovery must be an object")
    _exact_keys(config, {"absent_candidates", "directories", "present_candidates"}, "config_discovery")
    if config["directories"] != CONFIG_DIRECTORIES:
        raise BundleError("Cargo config discovery directories differ")
    present = config["present_candidates"]
    absent = config["absent_candidates"]
    if (
        not isinstance(present, list)
        or not isinstance(absent, list)
        or present != sorted(set(present))
        or absent != sorted(set(absent))
        or sorted(present + absent) != CONFIG_CANDIDATES
    ):
        raise BundleError("Cargo config candidate partition is not exact")
    workspace_discovery = value["workspace_discovery"]
    if not isinstance(workspace_discovery, dict):
        raise BundleError("workspace_discovery must be an object")
    _exact_keys(
        workspace_discovery,
        {"absent_candidates", "package_records", "present_candidates"},
        "workspace_discovery",
    )
    workspace_present = workspace_discovery["present_candidates"]
    workspace_absent = workspace_discovery["absent_candidates"]
    records = workspace_discovery["package_records"]
    if (
        not isinstance(workspace_present, list)
        or not isinstance(workspace_absent, list)
        or workspace_present != sorted(set(workspace_present))
        or workspace_absent != sorted(set(workspace_absent))
        or set(workspace_present) & set(workspace_absent)
        or not isinstance(records, list)
    ):
        raise BundleError("Cargo workspace discovery partition is not canonical")
    expected_package_manifests = sorted(
        ["verification/Cargo.toml", *[f"{root}/Cargo.toml" for root in roots]]
    )
    observed_package_manifests: list[str] = []
    candidate_union: set[str] = set()
    for index, record in enumerate(records):
        context = f"workspace_discovery.package_records[{index}]"
        if not isinstance(record, dict):
            raise BundleError(f"{context} must be an object")
        _exact_keys(
            record,
            {
                "candidate_manifests",
                "package_manifest",
                "selected_workspace_manifest",
                "selection",
            },
            context,
        )
        package_manifest = record["package_manifest"]
        selected_workspace = record["selected_workspace_manifest"]
        candidates = record["candidate_manifests"]
        selection = record["selection"]
        if not isinstance(package_manifest, str) or not package_manifest.endswith("/Cargo.toml"):
            raise BundleError(f"{context}.package_manifest is invalid")
        _safe_relative(package_manifest, "workspace package manifest")
        if (
            not isinstance(candidates, list)
            or not candidates
            or len(candidates) != len(set(candidates))
            or not isinstance(selected_workspace, str)
            or selected_workspace not in candidates
            or selected_workspace not in workspace_present
        ):
            raise BundleError(f"{context} candidates or selected workspace are invalid")
        for candidate in candidates:
            if not isinstance(candidate, str) or (
                candidate != "Cargo.toml" and not candidate.endswith("/Cargo.toml")
            ):
                raise BundleError(f"{context} contains an invalid Cargo.toml candidate")
            _safe_relative(candidate, "Cargo workspace discovery candidate")
        if selection == "manifest_defines_workspace":
            if candidates != [package_manifest] or selected_workspace != package_manifest:
                raise BundleError(f"{context} self-workspace selection is inconsistent")
        elif selection == "explicit_package_workspace":
            if candidates != [selected_workspace]:
                raise BundleError(f"{context} explicit workspace selection is inconsistent")
        elif selection == "nearest_ancestor_workspace":
            if candidates[-1] != selected_workspace or package_manifest in candidates:
                raise BundleError(f"{context} ancestor workspace selection is inconsistent")
        else:
            raise BundleError(f"{context}.selection is unsupported")
        observed_package_manifests.append(package_manifest)
        candidate_union.update(candidates)
    if observed_package_manifests != expected_package_manifests:
        raise BundleError("Cargo workspace discovery packages differ from the exact closure")
    if candidate_union != set(workspace_present) | set(workspace_absent):
        raise BundleError("Cargo workspace discovery candidate partition is incomplete")
    workspace_manifests = value["workspace_manifest_paths"]
    if (
        not isinstance(workspace_manifests, list)
        or workspace_manifests != sorted(set(workspace_manifests))
        or "Cargo.toml" not in workspace_manifests
    ):
        raise BundleError("workspace_manifest_paths must be sorted, unique, and include Cargo.toml")
    files = value["files"]
    if (
        not isinstance(files, list)
        or not isinstance(value["file_count"], int)
        or isinstance(value["file_count"], bool)
        or value["file_count"] != len(files)
        or not files
    ):
        raise BundleError("subject file_count differs from files")
    previous = ""
    paths: set[str] = set()
    for index, record in enumerate(files):
        context = f"subject files[{index}]"
        if not isinstance(record, dict):
            raise BundleError(f"{context} must be an object")
        _exact_keys(record, {"git_blob", "git_mode", "path", "sha256", "size"}, context)
        path = record["path"]
        if not isinstance(path, str) or path <= previous:
            raise BundleError("subject file paths must be strictly sorted")
        _safe_relative(path, "subject file path")
        if record["git_mode"] not in ("100644", "100755"):
            raise BundleError(f"{context}.git_mode is not a regular-file mode")
        if not isinstance(record["git_blob"], str) or not HEX40.fullmatch(record["git_blob"]):
            raise BundleError(f"{context}.git_blob is invalid")
        if not isinstance(record["sha256"], str) or not HEX64.fullmatch(record["sha256"]):
            raise BundleError(f"{context}.sha256 is invalid")
        if not isinstance(record["size"], int) or isinstance(record["size"], bool) or record["size"] < 0:
            raise BundleError(f"{context}.size is invalid")
        paths.add(path)
        previous = path
    for path in paths:
        if _excluded(path, EXCLUDED_VERIFICATION_PREFIXES):
            raise BundleError(f"self-referential or non-execution verification path included: {path}")
        covered = path in ROOT_FILES or path in workspace_manifests
        covered = covered or path in auto_target_files
        covered = covered or (
            build_script["state"] == "present_file" and path == ROOT_BUILD_SCRIPT
        )
        covered = covered or any(_under(path, directory) for directory in CONFIG_DIRECTORIES)
        covered = covered or any(
            _under(path, scope["path"]) and not _excluded(path, scope["excluded_prefixes"])
            for scope in scopes
        )
        if not covered:
            raise BundleError(f"subject file lies outside every reviewed execution scope: {path}")
    if not set(ROOT_FILES).issubset(paths) or not set(workspace_manifests).issubset(paths):
        raise BundleError("subject file set omits root or workspace manifests")
    if set(auto_target_files) - paths:
        raise BundleError("subject file set omits a root Cargo auto-target candidate")
    if (ROOT_BUILD_SCRIPT in paths) != (build_script["state"] == "present_file"):
        raise BundleError("root build-script presence differs from the subject file set")
    directory_states = {record["path"]: record["state"] for record in directories}
    for target_path in auto_target_files:
        if directory_states[PurePosixPath(target_path).parts[0]] != "present_directory":
            raise BundleError("root auto-target file lies under a recorded absent directory")
    if set(present) - paths:
        raise BundleError("present Cargo config candidate is absent from subject files")
    if set(workspace_present) - paths:
        raise BundleError("present Cargo workspace candidate is absent from subject files")
    vectors = value["vector_set"]
    if not isinstance(vectors, dict):
        raise BundleError("vector_set must be an object")
    _exact_keys(vectors, {"data_yaml_count", "data_yaml_paths", "provenance_path", "root"}, "vector_set")
    vector_paths = vectors["data_yaml_paths"]
    if (
        vectors["root"] != VECTOR_ROOT
        or vectors["provenance_path"] != VECTOR_PROVENANCE
        or vectors["data_yaml_count"] != EXPECTED_ETHEREUM_VECTOR_COUNT
        or not isinstance(vector_paths, list)
        or vector_paths != sorted(set(vector_paths))
        or len(vector_paths) != EXPECTED_ETHEREUM_VECTOR_COUNT
        or any(not _under(path, VECTOR_ROOT) or not path.endswith("/data.yaml") for path in vector_paths)
        or set(vector_paths) - paths
        or VECTOR_PROVENANCE not in paths
    ):
        raise BundleError("Ethereum vector set is not the exact 20-vector plus provenance closure")
    return value


def load_subject_inputs(path: Path) -> dict[str, Any]:
    _regular_unlinked_file(path, "subject-input manifest")
    try:
        raw = path.read_bytes()
        import json

        value = json.loads(raw)
    except (OSError, UnicodeError, ValueError) as error:
        raise BundleError(f"cannot parse subject-input manifest {path}: {error}") from error
    if raw != canonical_json(value):
        raise BundleError("subject-input manifest is not canonical JSON")
    return validate_subject_inputs(value)


def _walk_regular_files(root: Path, relative_root: str, excluded_prefixes: list[str]) -> set[str]:
    if not root.exists() and not root.is_symlink():
        return set()
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BundleError(f"subject scope root must be a real directory: {root}")
    files: set[str] = set()
    stack = [(root, relative_root)]
    while stack:
        directory, relative = stack.pop()
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = f"{relative}/{entry.name}"
            if _excluded(path, excluded_prefixes):
                continue
            entry_metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(entry_metadata.st_mode):
                stack.append((Path(entry.path), path))
            elif stat.S_ISREG(entry_metadata.st_mode):
                if entry_metadata.st_nlink != 1:
                    raise BundleError(f"subject file has hard links: {path}")
                files.add(path)
            else:
                raise BundleError(f"subject symlink or special file rejected: {path}")
    return files


def _allowed_path(path: str, exact: list[str], prefixes: list[str]) -> bool:
    return path in exact or any(_under(path, prefix) for prefix in prefixes)


def _nul_paths(raw: bytes) -> set[str]:
    result: set[str] = set()
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            path = encoded.decode("utf-8")
        except UnicodeError as error:
            raise BundleError("Git reported a non-UTF-8 changed path") from error
        _safe_relative(path, "changed Git path")
        result.add(path)
    return result


def verify_post_subject_delta(repo_root: Path, value: dict[str, Any]) -> None:
    source = value["source_commit"]
    head = str(_git(repo_root, ["rev-parse", "HEAD"], text=True)).strip()
    ancestor = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", source, head],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if ancestor.returncode != 0:
        raise BundleError("bound subject commit is not an ancestor of current HEAD")
    committed_raw = _git(repo_root, ["diff", "--name-only", "-z", f"{source}..{head}"])
    assert isinstance(committed_raw, bytes)
    committed = _nul_paths(committed_raw)
    disallowed_committed = post_subject_disallowed_paths(committed)
    if disallowed_committed:
        raise BundleError(
            "post-subject committed delta contains non-binding/non-assurance paths: "
            f"{sorted(disallowed_committed)!r}"
        )


def post_subject_disallowed_paths(changed: set[str]) -> set[str]:
    """Reject committed drift outside assurance and the exact rebind artifacts."""
    return {
        path
        for path in changed
        if not _allowed_path(
            path, POST_SUBJECT_ALLOWED_FILES, POST_SUBJECT_ALLOWED_PREFIXES
        )
    }


def verify_rebind_worktree_scope(
    repo_root: Path, *, allow_generated_binding_files: bool
) -> None:
    changed: set[str] = set()
    for arguments in (
        ["diff", "--name-only", "-z"],
        ["diff", "--cached", "--name-only", "-z"],
        ["ls-files", "--others", "--exclude-standard", "-z"],
    ):
        raw = _git(repo_root, arguments)
        assert isinstance(raw, bytes)
        changed.update(_nul_paths(raw))
    disallowed = rebind_disallowed_paths(
        changed, allow_generated_binding_files=allow_generated_binding_files
    )
    if disallowed:
        raise BundleError(
            "final rebind refuses dirty non-assurance subject paths: "
            f"{sorted(disallowed)!r}"
        )


def rebind_disallowed_paths(
    changed: set[str], *, allow_generated_binding_files: bool
) -> set[str]:
    allowed_files = [".gitignore"]
    if allow_generated_binding_files:
        allowed_files = REBIND_ALLOWED_DIRTY_FILES
    return {
        path
        for path in changed
        if not _allowed_path(
            path, allowed_files, REBIND_ALLOWED_DIRTY_PREFIXES
        )
    }


def _observed_root_auto_targets(root: Path, value: dict[str, Any]) -> set[str]:
    observed: set[str] = set()
    for record in value["root_package_discovery"]["auto_target_directories"]:
        relative = record["path"]
        directory = root / relative
        exists = directory.exists() or directory.is_symlink()
        if record["state"] == "absent":
            if exists:
                raise BundleError(
                    f"previously absent root Cargo auto-target directory appeared: {relative}"
                )
            continue
        if not exists:
            raise BundleError(f"root Cargo auto-target directory disappeared: {relative}")
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise BundleError(f"root Cargo auto-target path is not a real directory: {relative}")
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            entry_metadata = entry.stat(follow_symlinks=False)
            entry_path = f"{relative}/{entry.name}"
            if stat.S_ISREG(entry_metadata.st_mode):
                if entry_metadata.st_nlink != 1:
                    raise BundleError(f"root Cargo auto-target candidate has hard links: {entry_path}")
                if entry.name.endswith(".rs"):
                    observed.add(entry_path)
            elif stat.S_ISDIR(entry_metadata.st_mode):
                if relative in ("benches", "examples", "tests"):
                    nested = Path(entry.path) / "main.rs"
                    if nested.exists() or nested.is_symlink():
                        _regular_unlinked_file(nested, "nested root Cargo auto-target")
                        observed.add(f"{entry_path}/main.rs")
            else:
                raise BundleError(f"root Cargo auto-target entry is linked or special: {entry_path}")
    return observed


def _verify_discovery_state(root: Path, value: dict[str, Any]) -> None:
    expected_targets = set(value["root_package_discovery"]["auto_target_files"])
    observed_targets = _observed_root_auto_targets(root, value)
    if observed_targets != expected_targets:
        raise BundleError(
            "root Cargo auto-target discovery drifted: "
            f"missing={sorted(expected_targets - observed_targets)!r} "
            f"extra={sorted(observed_targets - expected_targets)!r}"
        )
    build = value["root_package_discovery"]["build_script"]
    build_path = root / build["path"]
    build_exists = build_path.exists() or build_path.is_symlink()
    if build["state"] == "absent":
        if build_exists:
            raise BundleError("previously absent root Cargo build.rs appeared")
    else:
        _regular_unlinked_file(build_path, "root Cargo build script")
    for path in value["workspace_discovery"]["absent_candidates"]:
        candidate = root / path
        if candidate.exists() or candidate.is_symlink():
            raise BundleError(f"previously absent Cargo workspace manifest appeared: {path}")


def verify_subject_inputs(
    repo_root: Path, value: dict[str, Any], *, verify_repository_state: bool = True
) -> None:
    validate_subject_inputs(value)
    if verify_repository_state:
        verify_post_subject_delta(repo_root, value)
    regenerated = generate_subject_inputs(repo_root, value["source_commit"])
    if regenerated != value:
        raise BundleError("subject-input manifest differs from its exact Git commit closure")
    expected = {record["path"]: record for record in value["files"]}
    for path, record in expected.items():
        current = repo_root / path
        _regular_unlinked_file(current, "current subject input")
        metadata = current.lstat()
        current_mode = stat.S_IMODE(metadata.st_mode)
        expected_executable = record["git_mode"] == "100755"
        if current_mode & 0o7000 or bool(current_mode & 0o111) != expected_executable:
            raise BundleError(f"current subject input executable/special mode differs: {path}")
        if metadata.st_size != record["size"] or sha256_file(current) != record["sha256"]:
            raise BundleError(f"current subject input bytes differ from bound commit: {path}")
    for scope in value["scopes"]:
        actual = _walk_regular_files(
            repo_root / scope["path"], scope["path"], scope["excluded_prefixes"]
        )
        expected_scope = {path for path in expected if _under(path, scope["path"])}
        if actual != expected_scope:
            raise BundleError(
                f"current subject scope differs for {scope['path']}: "
                f"missing={sorted(expected_scope - actual)!r} extra={sorted(actual - expected_scope)!r}"
            )
    for directory in CONFIG_DIRECTORIES:
        actual = _walk_regular_files(repo_root / directory, directory, [])
        expected_config = {path for path in expected if _under(path, directory)}
        if actual != expected_config:
            raise BundleError(
                f"Cargo config discovery directory drifted for {directory}: "
                f"missing={sorted(expected_config - actual)!r} extra={sorted(actual - expected_config)!r}"
            )
    for path in value["config_discovery"]["absent_candidates"]:
        candidate = repo_root / path
        if candidate.exists() or candidate.is_symlink():
            raise BundleError(f"previously absent Cargo configuration appeared: {path}")
    _verify_discovery_state(repo_root, value)


def _snapshot_files(root: Path) -> set[str]:
    return _walk_regular_files(root, "", [])


def verify_subject_snapshot(value: dict[str, Any], snapshot: Path) -> None:
    metadata = snapshot.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BundleError("subject snapshot must be a real directory")
    _verify_discovery_state(snapshot, value)
    expected = {record["path"]: record for record in value["files"]}
    actual = {path.lstrip("/") for path in _snapshot_files(snapshot)}
    if actual != set(expected):
        raise BundleError(
            "subject snapshot entries differ: "
            f"missing={sorted(set(expected) - actual)!r} extra={sorted(actual - set(expected))!r}"
        )
    for path, record in expected.items():
        materialized = snapshot.joinpath(*PurePosixPath(path).parts)
        _regular_unlinked_file(materialized, "materialized subject input")
        expected_mode = 0o755 if record["git_mode"] == "100755" else 0o644
        if stat.S_IMODE(materialized.lstat().st_mode) != expected_mode:
            raise BundleError(f"materialized subject mode differs: {path}")
        if materialized.stat().st_size != record["size"] or sha256_file(materialized) != record["sha256"]:
            raise BundleError(f"materialized subject bytes differ: {path}")


def materialize_subject(
    repo_root: Path,
    value: dict[str, Any],
    destination: Path,
    *,
    verify_repository_state: bool = True,
) -> None:
    verify_subject_inputs(
        repo_root, value, verify_repository_state=verify_repository_state
    )
    destination.mkdir(mode=0o755)
    destination.chmod(0o755)
    for record in value["files"]:
        relative = PurePosixPath(record["path"])
        source = repo_root.joinpath(*relative.parts)
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        parent = target.parent
        while parent != destination.parent:
            parent.chmod(0o755)
            parent = parent.parent
        mode = 0o755 if record["git_mode"] == "100755" else 0o644
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        os.fchmod(descriptor, mode)
        with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                output_stream.write(chunk)
    verify_subject_snapshot(value, destination)
