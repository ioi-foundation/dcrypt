#!/usr/bin/env python3
"""Descriptor-anchored import of an already-produced private Package E bundle.

Capture is intentionally a byte copier, not a runner or trust decision.  It
does not execute tools, contact a network service, validate a signer, accept a
result, or make any captured record promotion eligible.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True

from model import (
    REPO,
    ROLE_CAPS,
    PackageEError,
    artifact_set_sha256,
    canonical_json,
    parse_json_strict,
    safe_relative_path,
    sha256_bytes,
    validate_evidence_candidate,
)

MAX_CANDIDATE_BYTES = 1_048_576
RENAME_NOREPLACE = 1


def _os_error(label: str, error: OSError) -> PackageEError:
    """Return an error which cannot disclose a private path or candidate value."""

    return PackageEError(f"{label} failed with operating-system errno {error.errno}")


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
        raise PackageEError(f"{label} must be a canonical absolute path without .git")
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
            raise PackageEError(f"{label} root is not a directory")
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
                raise PackageEError(f"{label} contains a nondirectory component")
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
            raise PackageEError(f"{label} identity changed during capture")
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
    raise PackageEError("destination must not already exist")


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
                    raise PackageEError(f"{label} contains a surplus entry")
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
        raise PackageEError("source or destination overlaps a forbidden boundary")

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
            raise PackageEError("source bundle root is not current-owner mode 0700")
        source_identity = _stable_identity(source_metadata)

        parent_fd, parent_chain = _open_directory_chain(
            destination.parent, label="destination parent"
        )
        parent_metadata = os.fstat(parent_fd)
        if not _private_directory(parent_metadata):
            raise PackageEError("destination parent is not current-owner mode 0700")
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
            raise PackageEError("descriptor identities overlap a forbidden boundary")
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
                raise PackageEError(f"{label} was truncated during capture")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) != b"":
            raise PackageEError(f"{label} grew during capture")
        if _stable_identity(os.fstat(descriptor)) != expected:
            raise PackageEError(f"{label} metadata changed during capture")
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
            raise PackageEError("candidate record is not a bounded private regular file")
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
        raise PackageEError("capture role has no code-pinned resource profile")
    caps = ROLE_CAPS[role]
    if set(caps) != {"files", "per_file", "total"} or any(
        not isinstance(value, int) or isinstance(value, bool) or value <= 0
        for value in caps.values()
    ):
        raise PackageEError("code-pinned role cap closure differs")

    artifacts = candidate["artifacts"]
    if len(artifacts) > caps["files"]:
        raise PackageEError("candidate exceeds its role-specific file cap")
    if candidate["raw_artifact_set_sha256"] != artifact_set_sha256(artifacts):
        raise PackageEError("candidate raw-artifact set digest differs")

    records: dict[str, dict[str, Any]] = {}
    expected_files = {"candidate.json"}
    expected_directories: set[str] = set()
    declared_total = 0
    for record in artifacts:
        relative = safe_relative_path(record["path"], label="candidate artifact")
        parts = PurePosixPath(relative).parts
        if ".git" in parts or relative == "candidate.json":
            raise PackageEError("candidate artifact uses a forbidden path")
        if record["size"] > caps["per_file"]:
            raise PackageEError("candidate exceeds its role-specific per-file cap")
        declared_total += record["size"]
        records[relative] = record
        expected_files.add(relative)
        for end in range(1, len(parts)):
            expected_directories.add("/".join(parts[:end]))
    if declared_total > caps["total"]:
        raise PackageEError("candidate exceeds its role-specific aggregate cap")
    if len(records) != len(artifacts):
        raise PackageEError("candidate artifact paths contain duplicates")
    if expected_files & expected_directories:
        raise PackageEError("candidate artifact paths contain a file/directory conflict")
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
                    raise PackageEError("bundle path type closure conflicts")
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
            raise PackageEError("source bundle path closure differs")
        for name in sorted(names):
            child = f"{relative}/{name}" if relative else name
            if name == ".git":
                raise PackageEError("source bundle contains a forbidden .git component")
            try:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                raise _os_error("stating source bundle member", error) from error
            if expected[name] == "directory":
                if not _private_directory(metadata):
                    raise PackageEError("source bundle contains an unsafe directory")
                child_fd = -1
                try:
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                    opened = os.fstat(child_fd)
                    if _stable_identity(opened) != _stable_identity(metadata):
                        raise PackageEError("source directory changed during traversal")
                    key = (opened.st_dev, opened.st_ino)
                    if key in seen_directories:
                        raise PackageEError("source bundle aliases a directory")
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
                    raise PackageEError("source bundle contains an unsafe file")
                expected_size = (
                    metadata.st_size
                    if child == "candidate.json"
                    else records[child]["size"]
                )
                if metadata.st_size != expected_size:
                    raise PackageEError("source artifact size differs from its declaration")
                file_identities[child] = _stable_identity(metadata)

    visit(root_fd, "")
    if set(file_identities) != expected_files or set(directory_identities) != expected_directories:
        raise PackageEError("source bundle identity closure differs")
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
                raise PackageEError("source directory identity changed before read")
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
            dir_fd=current,
        )
        metadata = os.fstat(descriptor)
        if _stable_identity(metadata) != file_identities[relative]:
            os.close(descriptor)
            raise PackageEError("source file identity changed before read")
        return descriptor, metadata
    except OSError as error:
        raise _os_error("opening source artifact", error) from error
    finally:
        os.close(current)


def _create_staging(parent_fd: int) -> tuple[str, int, tuple[int, ...]]:
    for _attempt in range(32):
        name = f".dcrypt-package-e-capture-{os.urandom(16).hex()}"
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
                raise PackageEError("capture staging directory metadata differs")
            return name, descriptor, _basic_identity(metadata)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
    raise PackageEError("cannot allocate an exclusive capture staging directory")


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
                        raise PackageEError("destination directory metadata differs")
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
                    raise PackageEError("destination directory identity changed")
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
            raise PackageEError("destination write made no progress")
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
        raise PackageEError("destination file metadata differs")
    expected_identity = _stable_identity(metadata)
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(1 << 20, remaining))
        if not chunk:
            raise PackageEError("destination file was truncated")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1) != b"" or digest.hexdigest() != expected_sha256:
        raise PackageEError("destination file bytes differ")
    if _stable_identity(os.fstat(descriptor)) != expected_identity:
        raise PackageEError("destination file metadata changed during verification")
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
                raise PackageEError("source artifact was truncated during copy")
            digest.update(chunk)
            _complete_write(destination_fd, chunk)
            remaining -= len(chunk)
        if os.read(source_fd, 1) != b"":
            raise PackageEError("source artifact grew during copy")
        if (
            digest.hexdigest() != expected_sha256
            or _stable_identity(os.fstat(source_fd)) != source_identity
        ):
            raise PackageEError("source artifact identity differs from its declaration")
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
                raise PackageEError("destination directory identity changed")
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
            raise PackageEError("captured destination closure differs")
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
                        raise PackageEError("captured destination directory differs")
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
                        raise PackageEError("captured destination file differs")
                    observed = _read_descriptor(
                        file_fd, metadata, label="captured destination file"
                    )
                    if sha256_bytes(observed) != digest:
                        raise PackageEError("captured destination digest differs")
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
        raise PackageEError("atomic no-overwrite finalization is unavailable")
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
        raise PackageEError(
            f"atomic no-overwrite finalization failed with operating-system errno {value}"
        )


def _cleanup_known(
    parent_fd: int,
    root_name: str | None,
    root_identity: tuple[int, ...] | None,
    file_identities: dict[str, tuple[int, ...]],
    directory_identities: dict[str, tuple[int, ...]],
) -> None:
    """Remove only invocation-owned identities, or report an incomplete rollback."""

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
            raise PackageEError("capture rollback root identity differs")
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
            except (OSError, PackageEError):
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
            except (OSError, PackageEError):
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
            raise PackageEError("capture rollback encountered an owned-entry failure")
        return
    except OSError as error:
        raise _os_error("verifying capture rollback", error) from error
    raise PackageEError("capture rollback is incomplete; private output was preserved")


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
            raise PackageEError("candidate record root is not an object")
        caps, records, expected_files, expected_directories = _candidate_contract(candidate)

        source_files, source_directories = _scan_source_tree(
            source_fd,
            expected_files,
            expected_directories,
            records,
            caps,
        )
        if source_files["candidate.json"] != _stable_identity(candidate_metadata):
            raise PackageEError("candidate record changed after validation")

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
            if artifact_total > caps["total"]:
                raise PackageEError("actual bundle exceeds its role-specific aggregate cap")

        observed_files, observed_directories = _scan_source_tree(
            source_fd,
            expected_files,
            expected_directories,
            records,
            caps,
        )
        if observed_files != source_files or observed_directories != source_directories:
            raise PackageEError("source bundle changed during capture")
        if _stable_identity(os.fstat(source_fd)) != source_root_identity:
            raise PackageEError("source bundle root changed during capture")
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
            raise PackageEError("destination directory closure differs")
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
            raise PackageEError("final destination descriptor identity differs")
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
    except PackageEError as error:
        print(f"Package E capture HOLD: {error}", file=sys.stderr)
        return 3
    except (OSError, UnicodeError, ValueError) as error:
        error_number = error.errno if isinstance(error, OSError) else None
        suffix = f" (errno={error_number})" if error_number is not None else ""
        print(f"Package E capture HOLD: invalid private bundle{suffix}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
