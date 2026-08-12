#!/usr/bin/env python3
"""Shared exact compiler/linker probe for temp-only Package C fixtures."""

from __future__ import annotations

import os
import hashlib
import json
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from fuzzing_lib import (
    FuzzingError,
    INTEGRATED_ASAN_FUNCTION_SYMBOLS,
    INTEGRATED_ASAN_RUNTIME_SHA256,
    canonical_json,
    sha256_bytes,
)


PINNED_RUSTC_VERSION = """rustc 1.99.0-nightly (1a98b1e13 2026-08-07)
binary: rustc
commit-hash: 1a98b1e135b254f209c67d447b6d8bcd56a859e0
commit-date: 2026-08-07
host: x86_64-unknown-linux-gnu
release: 1.99.0-nightly
LLVM version: 23.1.0
"""
PINNED_RUSTC_SHA256 = "64059bd9ea1d1e4ac3e272a0beb63108d527d1e3eb7d53609b067cb79050169b"
READELF_VERSION_PATTERN = re.compile(r"^GNU readelf \(GNU Binutils for Ubuntu\) 2\.42$")
PINNED_SANITIZER_RUNTIME_SHA256 = {
    "address": INTEGRATED_ASAN_RUNTIME_SHA256,
    "leak": "5d2197d6aa53633c9736d1d06e3ddc5c15b79ef15fee5c805399dcdeac39968b",
}
PINNED_CARGO_SHA256 = "ad3e2db9a328de3e2071c0053f6745d2589ca5b80ca5ac834243d3cc8e360dbe"
PINNED_CARGO_FUZZ_CRATE_SHA256 = "5acfd01930e49823e58c30dd8012d3338a620377d7c7d4cc140ca4b2169400e2"
PINNED_CARGO_FUZZ_LOCK_SHA256 = "f64e1eceaceb7be6365539911f45d73bfe7b3afc8370281cca943a8a28b395b3"
PINNED_CARGO_FUZZ_VCS_SHA1 = "984c861c8dfea28055254c5f1d2659ab2cd63f76"
PINNED_CARGO_VERSION_PREFIX = "cargo 1.99.0-nightly (c79e8f894 2026-08-04)\n"
PINNED_CARGO_FUZZ_VERSION = "cargo-fuzz 0.13.2\n"

LINKER_WRAPPER_SOURCE = r'''#!/usr/bin/python3
import os, sys
log = os.environ["DCRYPT_LINKER_ARGV_LOG"]
fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as stream:
    stream.write(b"\0".join(value.encode("utf-8") for value in sys.argv))
real = os.environ["DCRYPT_REAL_LINKER"]
os.execve(real, [real, *sys.argv[1:]], {"LANG":"C","LC_ALL":"C","PATH":"/usr/bin:/bin","TZ":"UTC"})
'''

FUZZ_BUILD_LINKER_WRAPPER_SOURCE = r'''#!/usr/bin/python3
import json, os, sys
real = os.environ["DCRYPT_REAL_LINKER"]
log = os.environ["DCRYPT_LINKER_ARGV_LOG"]
record = (json.dumps(sys.argv, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
fd = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
try:
    if os.write(fd, record) != len(record):
        raise SystemExit(98)
finally:
    os.close(fd)
os.execve(real, [real, *sys.argv[1:]], {"LANG":"C","LC_ALL":"C","PATH":"/usr/bin:/bin","TZ":"UTC"})
'''


def _strict_json_file(path: Path, *, label: str) -> Any:
    if not path.is_file() or path.is_symlink():
        raise FuzzingError(f"{label} is absent or unsafe")
    try:
        return __import__("json").loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=lambda pairs: _unique_json_pairs(pairs, label=label),
        )
    except (UnicodeError, ValueError) as error:
        raise FuzzingError(f"{label} is not strict JSON") from error


def _unique_json_pairs(pairs: list[tuple[str, Any]], *, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key in {label}: {key}")
        result[key] = value
    return result


def _verify_cargo_fuzz_source(archive: Path, source_root: Path) -> dict[str, Any]:
    if not archive.is_file() or archive.is_symlink() or not source_root.is_dir() or source_root.is_symlink():
        raise FuzzingError("cargo-fuzz archive/source root has an unsafe type")
    if sha256_bytes(archive.read_bytes()) != PINNED_CARGO_FUZZ_CRATE_SHA256:
        raise FuzzingError("cargo-fuzz crate archive SHA-256 differs")
    archive_records: dict[str, dict[str, Any]] = {}
    with tarfile.open(archive, mode="r:gz") as stream:
        for member in stream.getmembers():
            prefix = "cargo-fuzz-0.13.2/"
            if not member.name.startswith(prefix) or member.name == prefix or not member.isfile():
                raise FuzzingError("cargo-fuzz archive contains a wrong root or non-regular member")
            relative = member.name[len(prefix) :]
            if relative in archive_records or not relative or ".." in Path(relative).parts:
                raise FuzzingError("cargo-fuzz archive contains duplicate/escaping source member")
            extracted = stream.extractfile(member)
            if extracted is None:
                raise FuzzingError("cargo-fuzz archive member cannot be read")
            raw = extracted.read()
            archive_records[relative] = {
                "mode": member.mode & 0o777,
                "sha256": sha256_bytes(raw),
                "size": len(raw),
            }
    source_records: dict[str, dict[str, Any]] = {}
    cargo_ok_seen = False
    for path in sorted(source_root.rglob("*")):
        relative = path.relative_to(source_root).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            if path.is_symlink():
                raise FuzzingError("cargo-fuzz source contains symlink directory")
            continue
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise FuzzingError("cargo-fuzz source contains link/special member")
        if relative == ".cargo-ok":
            if path.read_bytes() != b'{"v":1}' or stat.S_IMODE(metadata.st_mode) & 0o111:
                raise FuzzingError("Cargo registry extraction marker differs")
            cargo_ok_seen = True
            continue
        raw = path.read_bytes()
        source_records[relative] = {
            # Cargo extraction may apply umask; compare executable intent.
            "mode": 0o755 if stat.S_IMODE(metadata.st_mode) & 0o111 else 0o644,
            "sha256": sha256_bytes(raw),
            "size": len(raw),
        }
    if not cargo_ok_seen:
        raise FuzzingError("Cargo registry extraction marker is absent")
    normalized_archive = {
        path: {**record, "mode": 0o755 if record["mode"] & 0o111 else 0o644}
        for path, record in archive_records.items()
    }
    if source_records != normalized_archive:
        raise FuzzingError("cargo-fuzz extracted source tree differs from exact archive closure")
    return {
        "archive_sha256": PINNED_CARGO_FUZZ_CRATE_SHA256,
        "lock_sha256": source_records["Cargo.lock"]["sha256"],
        "source_files": len(source_records),
        "source_tree_sha256": sha256_bytes(canonical_json(source_records)),
    }


def _validate_exact_candidates(paths: list[Path], *, label: str) -> Path:
    if len(paths) != 1:
        raise FuzzingError(f"{label} candidate set is absent or ambiguous")
    path = paths[0]
    if not path.is_absolute() or path.is_symlink():
        raise FuzzingError(f"{label} candidate is not an absolute non-symlink path")
    return path


def _resolve_discovery_executable(candidates: list[Path], *, label: str) -> Path:
    """Resolve an allowlisted discovery executable to one real identity.

    Missing allowlisted locations are ignored. Multiple spellings are accepted
    only when they resolve to the same real file. A symlink may not escape to a
    path that is absent from the explicit allowlist.
    """

    if not isinstance(candidates, list) or not candidates:
        raise FuzzingError(f"{label} candidate list is empty")
    if any(not isinstance(path, Path) or not path.is_absolute() for path in candidates):
        raise FuzzingError(f"{label} candidates must be absolute paths")
    allowlisted = set(candidates)
    resolved_records: list[Path] = []
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            try:
                resolved = candidate.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise FuzzingError(f"{label} candidate has an unsafe symlink chain") from error
            if resolved not in allowlisted:
                raise FuzzingError(f"{label} symlink target escapes the exact allowlist")
        else:
            resolved = candidate.resolve(strict=True)
        final = resolved.stat()
        required_uid = 0 if resolved.is_relative_to(Path("/usr")) else os.getuid()
        if (
            not stat.S_ISREG(final.st_mode)
            or stat.S_IMODE(final.st_mode) & 0o111 == 0
            or stat.S_IMODE(final.st_mode) & 0o022
            or final.st_uid != required_uid
            or final.st_nlink != 1
        ):
            raise FuzzingError(f"{label} resolved identity is not an executable regular file")
        resolved_records.append(resolved)
    if not resolved_records or len(set(resolved_records)) != 1:
        raise FuzzingError(f"{label} did not resolve one exact identity")
    return resolved_records[0]


def _validate_cargo_fuzz_install_records(installs: Any) -> dict[str, Any]:
    if not isinstance(installs, dict):
        raise FuzzingError("Cargo install provenance installs field is not an object")
    record_id = "cargo-fuzz 0.13.2 (registry+https://github.com/rust-lang/crates.io-index)"
    try:
        install = installs[record_id]
    except KeyError as error:
        raise FuzzingError("cargo-fuzz installer provenance record is absent") from error
    expected_install_keys = {
        "all_features", "bins", "features", "no_default_features", "profile", "rustc", "target", "version_req"
    }
    if not isinstance(install, dict) or set(install) != expected_install_keys or (
        install.get("version_req") != "=0.13.2"
        or install.get("bins") != ["cargo-fuzz"]
        or install.get("features") != []
        or install.get("all_features") is not False
        or install.get("no_default_features") is not False
        or install.get("profile") != "release"
        or install.get("target") != "x86_64-unknown-linux-gnu"
        or install.get("rustc") != PINNED_RUSTC_VERSION
    ):
        raise FuzzingError("cargo-fuzz installer provenance differs from exact locked build")
    owners = [key for key, value in installs.items() if isinstance(value, dict) and "cargo-fuzz" in value.get("bins", [])]
    if owners != [record_id]:
        raise FuzzingError("cargo-fuzz binary ownership is absent or ambiguous")
    return {"record_id": record_id, **install}


def _validate_host_tool_identity(
    *,
    path: Path,
    allowed_real_paths: list[Path],
    version: bytes,
    version_pattern: re.Pattern[bytes],
    label: str,
    required_uid: int,
) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink() or path not in allowed_real_paths:
        raise FuzzingError(f"{label} resolved path differs from reviewed host locations")
    metadata = path.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_uid != required_uid
        or metadata.st_nlink != 1
    ):
        raise FuzzingError(f"{label} is not an executable regular file")
    if version_pattern.fullmatch(version) is None:
        raise FuzzingError(f"{label} version identity differs from the reviewed Ubuntu family")
    return {
        "executable_sha256": sha256_bytes(path.read_bytes()),
        "resolved_path": str(path),
        "version_sha256": sha256_bytes(version),
    }


def _regular_exact(path: Path, expected_sha256: str, *, label: str) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise FuzzingError(f"{label} is not an absolute regular non-symlink file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_uid not in {0, os.getuid()}
        ):
            raise FuzzingError(f"{label} ownership/mode/link identity differs")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise FuzzingError(f"{label} metadata drifted while read")
    raw = b"".join(chunks)
    if sha256_bytes(raw) != expected_sha256:
        raise FuzzingError(f"{label} executable/object SHA-256 differs")
    return raw


def _open_absolute_nofollow(path: Path, *, directory: bool, label: str) -> int:
    """Open an absolute path without following any component symlink."""

    if not path.is_absolute() or not path.parts or path.parts[0] != "/":
        raise FuzzingError(f"{label} must be absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, component in enumerate(path.parts[1:]):
            final = index == len(path.parts[1:]) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if not final or directory:
                flags |= os.O_DIRECTORY
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise FuzzingError(f"{label} path component is absent, a symlink, or unsafe") from error


def _copy_open_file_to_private(
    source_fd: int,
    destination: Path,
    *,
    executable: bool,
    allow_multiple_links: bool,
    label: str,
) -> dict[str, Any]:
    before = os.fstat(source_fd)
    _validate_snapshot_source_metadata(
        before,
        executable=executable,
        allow_multiple_links=allow_multiple_links,
        required_uid=os.getuid(),
        label=label,
    )
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    destination_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o700 if executable else 0o600,
    )
    hasher = __import__("hashlib").sha256()
    size = 0
    try:
        while chunk := os.read(source_fd, 1024 * 1024):
            hasher.update(chunk)
            size += len(chunk)
            if os.write(destination_fd, chunk) != len(chunk):
                raise FuzzingError(f"{label} private snapshot write was short")
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
    after = os.fstat(source_fd)
    _require_stable_metadata(before, after, label=label)
    if size != before.st_size:
        raise FuzzingError(f"{label} original size differs from bytes read")
    snapshot_fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        snapshot_meta = os.fstat(snapshot_fd)
        snapshot_hasher = __import__("hashlib").sha256()
        while chunk := os.read(snapshot_fd, 1024 * 1024):
            snapshot_hasher.update(chunk)
    finally:
        os.close(snapshot_fd)
    expected_mode = 0o700 if executable else 0o600
    if (
        not stat.S_ISREG(snapshot_meta.st_mode)
        or snapshot_meta.st_uid != os.getuid()
        or snapshot_meta.st_nlink != 1
        or stat.S_IMODE(snapshot_meta.st_mode) != expected_mode
        or snapshot_meta.st_size != size
        or snapshot_hasher.hexdigest() != hasher.hexdigest()
    ):
        raise FuzzingError(f"{label} private snapshot identity differs")
    return {
        "original_mode": format(stat.S_IMODE(before.st_mode), "04o"),
        "original_executable": bool(stat.S_IMODE(before.st_mode) & 0o111),
        "original_nlink": before.st_nlink,
        "original_uid": before.st_uid,
        "private_mode": format(expected_mode, "04o"),
        "sha256": hasher.hexdigest(),
        "size": size,
    }


def _validate_snapshot_source_metadata(
    metadata: Any,
    *,
    executable: bool,
    allow_multiple_links: bool,
    required_uid: int,
    label: str,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != required_uid
        or (not allow_multiple_links and metadata.st_nlink != 1)
        or metadata.st_nlink < 1
        or stat.S_IMODE(metadata.st_mode) & 0o002
        or (executable and stat.S_IMODE(metadata.st_mode) & 0o111 == 0)
    ):
        raise FuzzingError(f"{label} original owner/type/mode/link identity differs")


def _require_stable_metadata(before: Any, after: Any, *, label: str) -> None:
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise FuzzingError(f"{label} metadata drifted while read")


def _snapshot_home_file(source: Path, destination: Path, *, executable: bool, label: str) -> dict[str, Any]:
    """Descriptor-snapshot one current-uid HOME input into private storage."""

    if not source.is_absolute() or not destination.is_absolute():
        raise FuzzingError(f"{label} path is unsafe")
    source_fd = _open_absolute_nofollow(source, directory=False, label=label)
    try:
        return _copy_open_file_to_private(
            source_fd,
            destination,
            executable=executable,
            allow_multiple_links=not executable,
            label=label,
        )
    finally:
        os.close(source_fd)


def _snapshot_home_tree(source: Path, destination: Path, *, label: str) -> dict[str, Any]:
    """Snapshot a complete current-uid source tree with before/after closure."""

    if not source.is_absolute():
        raise FuzzingError(f"{label} root path is unsafe")

    def inventory(*, copy_to: Path | None) -> tuple[dict[str, tuple[int, int, int, int, int, int, int, str]], dict[str, dict[str, Any]]]:
        records: dict[str, tuple[int, int, int, int, int, int, int, str]] = {}
        copied: dict[str, dict[str, Any]] = {}
        root_descriptor = _open_absolute_nofollow(source, directory=True, label=label)
        pending = [("", root_descriptor)]
        while pending:
            relative, descriptor = pending.pop()
            try:
                root_meta = os.fstat(descriptor)
                if (
                    not stat.S_ISDIR(root_meta.st_mode)
                    or root_meta.st_uid != os.getuid()
                    or stat.S_IMODE(root_meta.st_mode) & 0o002
                ):
                    raise FuzzingError(f"{label} directory owner/type/mode differs")
                entries = sorted(os.listdir(descriptor))
                records[relative] = (
                    root_meta.st_dev, root_meta.st_ino, root_meta.st_mode, root_meta.st_nlink,
                    root_meta.st_size, root_meta.st_mtime_ns, root_meta.st_ctime_ns, "directory",
                )
                for name in reversed(entries):
                    metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    child_relative = f"{relative}/{name}".lstrip("/")
                    if stat.S_ISDIR(metadata.st_mode):
                        child_descriptor = os.open(
                            name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor,
                        )
                        if copy_to is not None:
                            output_directory = copy_to / child_relative
                            output_directory.mkdir(mode=0o700)
                            os.chmod(output_directory, 0o700)
                        pending.append((child_relative, child_descriptor))
                    elif stat.S_ISREG(metadata.st_mode):
                        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o002:
                            raise FuzzingError(f"{label} file owner/type/mode/link identity differs")
                        records[child_relative] = (
                            metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
                            metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns, "file",
                        )
                        if copy_to is not None:
                            child_descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                            try:
                                opened = os.fstat(child_descriptor)
                                stable_fields = (
                                    "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"
                                )
                                if any(getattr(opened, field) != getattr(metadata, field) for field in stable_fields):
                                    raise FuzzingError(f"{label} member metadata lookup differs")
                                copied[child_relative] = _copy_open_file_to_private(
                                    child_descriptor,
                                    copy_to / child_relative,
                                    executable=False,
                                    allow_multiple_links=True,
                                    label=f"{label} member {child_relative}",
                                )
                            finally:
                                os.close(child_descriptor)
                    else:
                        raise FuzzingError(f"{label} contains a link or special object")
            finally:
                os.close(descriptor)
        return records, copied

    before, _unused = inventory(copy_to=None)
    if destination.exists() or destination.is_symlink():
        raise FuzzingError(f"{label} private destination already exists")
    destination.mkdir(mode=0o700, parents=True)
    during, snapshot_records = inventory(copy_to=destination)
    after, _unused = inventory(copy_to=None)
    if before != during or before != after:
        raise FuzzingError(f"{label} tree membership or metadata drifted while snapshotted")
    return {
        "files": len(snapshot_records),
        "original_executable_paths": sorted(
            path for path, record in snapshot_records.items() if record["original_executable"]
        ),
        "snapshot_manifest_sha256": sha256_bytes(canonical_json(snapshot_records)),
    }


def _stable_private_executable(path: Path, private_root: Path, *, label: str) -> dict[str, Any]:
    if not path.is_absolute() or not private_root.is_absolute():
        raise FuzzingError(f"{label} path/root must be absolute")
    try:
        relative = path.relative_to(private_root)
    except ValueError as error:
        raise FuzzingError(f"{label} escapes the private root") from error
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise FuzzingError(f"{label} path is noncanonical")
    current = private_root
    root_metadata = current.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or root_metadata.st_uid != os.getuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise FuzzingError(f"{label} private root is unsafe")
    for component in relative.parts[:-1]:
        current = current / component
        metadata = current.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o002
        ):
            raise FuzzingError(f"{label} ancestor is unsafe")
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink < 1
        or before.st_mode & 0o7000
        or before.st_mode & 0o002
        or before.st_mode & 0o111 == 0
    ):
        raise FuzzingError(f"{label} is not a safe private executable")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != identity:
            raise FuzzingError(f"{label} changed before descriptor read")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != identity or size != before.st_size:
            raise FuzzingError(f"{label} changed during descriptor read")
        return {
            "device": before.st_dev,
            "inode": before.st_ino,
            "nlink": before.st_nlink,
            "sha256": digest.hexdigest(),
            "size": size,
        }
    except OSError as error:
        raise FuzzingError(f"cannot safely inspect {label}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _reviewed_fuzz_link_output(value: str, binary: Path, private_root: Path) -> Path | None:
    candidate = Path(value)
    if not candidate.is_absolute() or candidate.as_posix() != value:
        return None
    expected_root = binary.parent / "build" / "dcrypt-fuzz"
    try:
        relative = candidate.relative_to(expected_root)
        candidate.relative_to(private_root)
    except ValueError:
        return None
    if (
        len(relative.parts) != 3
        or re.fullmatch(r"[0-9a-f]{16}", relative.parts[0]) is None
        or relative.parts[1] != "out"
        or relative.parts[2] != binary.name
    ):
        return None
    return candidate


def verify_fuzz_linker_log(
    path: Path,
    *,
    wrapper: Path,
    binary: Path,
    private_root: Path,
    tools: dict[str, Any],
) -> dict[str, Any]:
    """Verify the actual linker invocation that produced one fuzz binary."""

    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_nlink != 1
        or stat.S_IMODE(path.stat().st_mode) != 0o600
    ):
        raise FuzzingError("private fuzz linker log is missing or unsafe")
    if not wrapper.is_file() or wrapper.is_symlink() or stat.S_IMODE(wrapper.stat().st_mode) != 0o700:
        raise FuzzingError("private fuzz linker wrapper is missing or unsafe")
    if wrapper.read_text(encoding="utf-8") != FUZZ_BUILD_LINKER_WRAPPER_SOURCE:
        raise FuzzingError("private fuzz linker wrapper source differs")
    raw = path.read_bytes()
    try:
        lines = raw.decode("ascii").splitlines()
        records = [json.loads(line) for line in lines]
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FuzzingError("private fuzz linker log is not canonical JSON lines") from error
    if not records or any(
        not isinstance(record, list)
        or len(record) < 4
        or record[0] != str(wrapper)
        or any(not isinstance(value, str) for value in record)
        for record in records
    ):
        raise FuzzingError("private fuzz linker invocation shape differs")
    canonical = b"".join(
        (json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        for record in records
    )
    if canonical != raw:
        raise FuzzingError("private fuzz linker log is not canonical")
    candidates: list[tuple[list[str], Path]] = []
    for record in records:
        output_indexes = [index for index, value in enumerate(record) if value == "-o"]
        reviewed_outputs = [
            _reviewed_fuzz_link_output(record[index + 1], binary, private_root)
            for index in output_indexes
            if index + 1 < len(record)
        ]
        reviewed_outputs = [value for value in reviewed_outputs if value is not None]
        if reviewed_outputs:
            if len(output_indexes) != 1 or len(reviewed_outputs) != 1:
                raise FuzzingError("reviewed fuzz linker invocation has duplicate/ambiguous output flags")
            candidates.append((record, reviewed_outputs[0]))
    if len(candidates) != 1:
        raise FuzzingError("linker log lacks exactly one reviewed private fuzz build output")
    target_argv, linked_output = candidates[0]
    linked_identity = _stable_private_executable(
        linked_output, private_root, label="actual linked fuzz output"
    )
    final_identity = _stable_private_executable(
        binary, private_root, label="materialized final fuzz binary"
    )
    if (
        linked_identity["sha256"] != final_identity["sha256"]
        or linked_identity["size"] != final_identity["size"]
    ):
        raise FuzzingError("materialized final fuzz binary differs from actual linked output")
    same_inode = (
        linked_identity["device"], linked_identity["inode"]
    ) == (final_identity["device"], final_identity["inode"])
    if same_inode and (linked_identity["nlink"] < 2 or final_identity["nlink"] < 2):
        raise FuzzingError("fuzz binary hardlink relation has inconsistent link metadata")
    materialization = "hardlink-same-inode" if same_inode else "copied-byte-identical"
    runtime_suffix = "librustc-nightly_rt.asan.a"
    runtime_values = [value for value in target_argv if value.endswith(runtime_suffix)]
    runtime_paths: list[Path] = []
    for value in runtime_values:
        if not value.startswith("-Wl,/") or "," in value[len("-Wl,") :]:
            raise FuzzingError("fuzz ASan runtime linker argument has an unreviewed wrapper")
        runtime_paths.append(Path(value[len("-Wl,") :]))
    if len(runtime_paths) != 1:
        raise FuzzingError("fuzz binary linker invocation lacks exactly one reviewed ASan runtime")
    _regular_exact(runtime_paths[0], PINNED_SANITIZER_RUNTIME_SHA256["address"], label="fuzz ASan runtime")
    runtime_symbol_proofs = verify_binary_symbols(
        runtime_paths[0], INTEGRATED_ASAN_FUNCTION_SYMBOLS, tools=tools
    )
    normalized_argv = [value.replace(str(private_root), "<PRIVATE_TMP>") for value in target_argv]
    return {
        "actual_linker_invocation_observed": True,
        "asan_runtime_sha256": PINNED_SANITIZER_RUNTIME_SHA256["address"],
        "asan_runtime_defined_function_proofs": runtime_symbol_proofs,
        "host_linker_executable_sha256": tools["linker_identity"]["executable_sha256"],
        "host_linker_version_sha256": tools["linker_identity"]["version_sha256"],
        "linker_invocation_count": len(records),
        "linker_log_sha256": sha256_bytes(raw),
        "linker_wrapper_sha256": sha256_bytes(FUZZ_BUILD_LINKER_WRAPPER_SOURCE.encode("utf-8")),
        "linked_output_path_suffix": linked_output.relative_to(private_root).as_posix(),
        "linked_output_sha256": linked_identity["sha256"],
        "materialized_binary_relation": materialization,
        "materialized_final_binary_sha256": final_identity["sha256"],
        "target_linker_argv_sha256": sha256_bytes(canonical_json(normalized_argv)),
    }


def pinned_toolchain() -> dict[str, Any]:
    discovery_env = {"HOME": os.environ.get("HOME", ""), "PATH": "/usr/bin:/bin"}
    rustup_path = _resolve_discovery_executable(
        [Path(os.environ.get("HOME", "")) / ".cargo/bin/rustup", Path("/usr/bin/rustup")],
        label="rustup discovery executable",
    )
    candidates: list[tuple[str, str]] = []
    explicit = os.environ.get("DCRYPT_FUZZ_RUSTC")
    if explicit is not None:
        candidates.append(("explicit", explicit))
    for alias in ("nightly-2026-08-08", "nightly"):
        result = subprocess.run(
            [str(rustup_path), "which", "--toolchain", alias, "rustc"],
            capture_output=True,
            timeout=15,
            env=discovery_env,
        )
        if result.returncode == 0:
            candidates.append((f"rustup:{alias}", result.stdout.decode("utf-8").strip()))
    validated: list[tuple[str, str]] = []
    for method, path in candidates:
        try:
            _regular_exact(Path(path), PINNED_RUSTC_SHA256, label="pinned rustc candidate")
        except FuzzingError:
            continue
        validated.append((method, path))
    if not validated or len({str(Path(path).resolve(strict=True)) for _, path in validated}) != 1:
        raise FuzzingError("rustc discovery did not resolve one exact pinned binary")
    rustc_path = str(Path(validated[0][1]).resolve(strict=True))
    _regular_exact(Path(rustc_path), PINNED_RUSTC_SHA256, label="pinned rustc")
    cc_resolved = Path("/usr/bin/cc").resolve(strict=True)
    readelf_resolved = Path("/usr/bin/readelf").resolve(strict=True)
    env = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "0", "TZ": "UTC"}
    rustc_version = subprocess.run([rustc_path, "-Vv"], check=True, capture_output=True, timeout=15, env=env).stdout
    cc_version = subprocess.run(
        [str(cc_resolved), "--version"], check=True, capture_output=True, timeout=15, env=env
    ).stdout.splitlines(keepends=True)[0]
    readelf_version = subprocess.run([str(readelf_resolved), "--version"], check=True, capture_output=True, timeout=15, env=env).stdout.decode().splitlines()[0]
    if rustc_version.decode() != PINNED_RUSTC_VERSION:
        raise FuzzingError("compiler identity differs from exact Package C pin")
    cc_identity = _validate_host_tool_identity(
        path=cc_resolved,
        allowed_real_paths=[Path("/usr/bin/x86_64-linux-gnu-gcc-13")],
        version=cc_version,
        version_pattern=re.compile(rb"^(?:cc|x86_64-linux-gnu-gcc-13) \(Ubuntu 13\.3\.0-[0-9A-Za-z.+:~]+\) 13\.3\.0\n$"),
        label="C linker",
        required_uid=0,
    )
    readelf_pattern = re.compile(READELF_VERSION_PATTERN.pattern.encode())
    readelf_identity = _validate_host_tool_identity(
        path=readelf_resolved,
        allowed_real_paths=[Path("/usr/bin/x86_64-linux-gnu-readelf"), Path("/usr/bin/readelf")],
        version=(readelf_version + "\n").encode(),
        version_pattern=re.compile(readelf_pattern.pattern + b"\n"),
        label="ELF symbol inspector",
        required_uid=0,
    )
    return {
        "linker_identity": cc_identity,
        "linker_path": str(cc_resolved),
        "compile_env": env,
        "readelf_identity": readelf_identity,
        "readelf_sha256": readelf_identity["executable_sha256"],
        "readelf_path": str(readelf_resolved),
        "rustc_path": rustc_path,
        "rustc_discovery_methods": sorted(method for method, _ in validated),
        "rustc_sha256": PINNED_RUSTC_SHA256,
        "rustc_version": rustc_version,
        "rustup_discovery_path": str(rustup_path),
    }


def pinned_cargo_tools(private_root: Path) -> dict[str, Any]:
    if (
        not private_root.is_absolute()
        or not private_root.is_dir()
        or private_root.is_symlink()
        or private_root.stat().st_uid != os.getuid()
        or private_root.stat().st_nlink != 2
        or stat.S_IMODE(private_root.stat().st_mode) != 0o700
    ):
        raise FuzzingError("cargo-fuzz private snapshot root must be a 0700 current-uid directory")
    toolchain = pinned_toolchain()
    discovery_env = {"HOME": os.environ.get("HOME", ""), "PATH": "/usr/bin:/bin"}
    cargo_candidates: list[tuple[str, str]] = []
    explicit_cargo = os.environ.get("DCRYPT_FUZZ_CARGO")
    if explicit_cargo:
        cargo_candidates.append(("explicit", explicit_cargo))
    for alias in ("nightly-2026-08-08", "nightly"):
        result = subprocess.run(
            [toolchain["rustup_discovery_path"], "which", "--toolchain", alias, "cargo"],
            capture_output=True,
            timeout=15,
            env=discovery_env,
        )
        if result.returncode == 0:
            cargo_candidates.append((f"rustup:{alias}", result.stdout.decode().strip()))
    valid_cargo = []
    for method, candidate in cargo_candidates:
        try:
            _regular_exact(Path(candidate), PINNED_CARGO_SHA256, label="pinned cargo candidate")
        except FuzzingError:
            continue
        valid_cargo.append((method, str(Path(candidate).resolve(strict=True))))
    if not valid_cargo or len({path for _, path in valid_cargo}) != 1:
        raise FuzzingError("cargo discovery did not resolve one exact pinned binary")
    cargo_path = valid_cargo[0][1]
    fuzz_candidates = []
    explicit_fuzz = os.environ.get("DCRYPT_FUZZ_CARGO_FUZZ")
    candidate_paths = [
        explicit_fuzz,
        f"{os.environ.get('HOME', '')}/.cargo/bin/cargo-fuzz",
        "/usr/local/bin/cargo-fuzz",
        "/usr/bin/cargo-fuzz",
    ]
    for candidate in candidate_paths:
        if not candidate:
            continue
        path = Path(candidate)
        if not path.is_absolute() or not path.is_file() or path.is_symlink():
            continue
        fuzz_candidates.append(str(path.resolve(strict=True)))
    cargo_fuzz_original = _validate_exact_candidates([Path(value) for value in fuzz_candidates], label="cargo-fuzz executable")
    cargo_home = Path(os.environ.get("HOME", "")) / ".cargo"
    crate_archives = sorted(cargo_home.glob("registry/cache/*/cargo-fuzz-0.13.2.crate"))
    source_roots = sorted(cargo_home.glob("registry/src/*/cargo-fuzz-0.13.2"))
    archive_candidate = _validate_exact_candidates(crate_archives, label="cargo-fuzz archive")
    source_candidate = _validate_exact_candidates(source_roots, label="cargo-fuzz source")
    matching_archives = [archive_candidate]
    matching_sources = [source_candidate]
    snapshot_root = private_root / "cargo-fuzz-provenance"
    snapshot_root.mkdir(mode=0o700)
    cargo_fuzz_snapshot = snapshot_root / "bin/cargo-fuzz"
    cargo_fuzz_snapshot_record = _snapshot_home_file(
        cargo_fuzz_original,
        cargo_fuzz_snapshot,
        executable=True,
        label="cargo-fuzz executable",
    )
    archive_snapshot = snapshot_root / "archive/cargo-fuzz-0.13.2.crate"
    archive_snapshot_record = _snapshot_home_file(
        matching_archives[0],
        archive_snapshot,
        executable=False,
        label="cargo-fuzz archive",
    )
    source_snapshot = snapshot_root / "source/cargo-fuzz-0.13.2"
    source_snapshot_record = _snapshot_home_tree(
        matching_sources[0],
        source_snapshot,
        label="cargo-fuzz source tree",
    )
    install_manifest = cargo_home / ".crates2.json"
    install_snapshot = snapshot_root / "install/.crates2.json"
    install_snapshot_record = _snapshot_home_file(
        install_manifest,
        install_snapshot,
        executable=False,
        label="Cargo install provenance",
    )
    source_projection = _verify_cargo_fuzz_source(archive_snapshot, source_snapshot)
    if source_snapshot_record["original_executable_paths"]:
        raise FuzzingError("cargo-fuzz extracted source executable intent differs from exact archive")
    if source_projection["lock_sha256"] != PINNED_CARGO_FUZZ_LOCK_SHA256:
        raise FuzzingError("cargo-fuzz source projection lock SHA-256 differs")
    vcs_record = _strict_json_file(
        source_snapshot / ".cargo_vcs_info.json",
        label="cargo-fuzz VCS provenance snapshot",
    )
    if vcs_record != {"git": {"sha1": PINNED_CARGO_FUZZ_VCS_SHA1}, "path_in_vcs": ""}:
        raise FuzzingError("cargo-fuzz VCS provenance differs")
    try:
        installs = _strict_json_file(install_snapshot, label="Cargo install provenance snapshot")["installs"]
    except (KeyError, TypeError) as error:
        raise FuzzingError("cargo-fuzz installer provenance record is absent") from error
    install_projection = _validate_cargo_fuzz_install_records(installs)
    executable_metadata = cargo_fuzz_snapshot.stat()
    if (
        executable_metadata.st_uid != os.getuid()
        or executable_metadata.st_nlink != 1
        or stat.S_IMODE(executable_metadata.st_mode) != 0o700
    ):
        raise FuzzingError("private cargo-fuzz executable must be current-uid, single-link, and 0700")
    cargo_fuzz_sha256 = sha256_bytes(cargo_fuzz_snapshot.read_bytes())
    provenance_projection = {
        "install": install_projection,
        "private_snapshot": {
            "archive": archive_snapshot_record,
            "executable": cargo_fuzz_snapshot_record,
            "install": install_snapshot_record,
            "source": source_snapshot_record,
        },
        "source": source_projection,
        "vcs_sha1": PINNED_CARGO_FUZZ_VCS_SHA1,
    }
    env = {
        "CARGO": cargo_path,
        "CARGO_NET_OFFLINE": "true",
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "RUSTC": toolchain["rustc_path"],
        "SOURCE_DATE_EPOCH": "0",
        "TZ": "UTC",
    }
    cargo_version = subprocess.run(
        [cargo_path, "--version", "--verbose"], check=True, capture_output=True, timeout=15, env=env
    ).stdout
    fuzz_version = subprocess.run(
        [str(cargo_fuzz_snapshot), "--version"], check=True, capture_output=True, timeout=15, env=env
    ).stdout
    if not cargo_version.startswith(PINNED_CARGO_VERSION_PREFIX.encode()) or fuzz_version.decode() != PINNED_CARGO_FUZZ_VERSION:
        raise FuzzingError("cargo or cargo-fuzz identity differs from exact Package C pin")
    return {
        "cargo_discovery_methods": sorted(method for method, _ in valid_cargo),
        "cargo_fuzz_original_executed": False,
        "cargo_fuzz_path": str(cargo_fuzz_snapshot),
        "cargo_fuzz_crate_sha256": PINNED_CARGO_FUZZ_CRATE_SHA256,
        "cargo_fuzz_executable_sha256": cargo_fuzz_sha256,
        "cargo_fuzz_lock_sha256": PINNED_CARGO_FUZZ_LOCK_SHA256,
        "cargo_fuzz_provenance_sha256": sha256_bytes(canonical_json(provenance_projection)),
        "cargo_fuzz_source_tree_sha256": source_projection["source_tree_sha256"],
        "cargo_fuzz_vcs_sha1": PINNED_CARGO_FUZZ_VCS_SHA1,
        "cargo_fuzz_version_sha256": sha256_bytes(fuzz_version),
        "cargo_path": cargo_path,
        "cargo_sha256": PINNED_CARGO_SHA256,
        "cargo_version_sha256": sha256_bytes(cargo_version),
        "environment": env,
        "rustc_path": toolchain["rustc_path"],
        "rustc_sha256": toolchain["rustc_sha256"],
        "rustc_version_sha256": sha256_bytes(toolchain["rustc_version"]),
        "toolchain": toolchain,
    }


def compile_fixture(
    root: Path,
    *,
    source: Path,
    binary: Path,
    sanitizer: str | None,
) -> dict[str, Any]:
    tools = pinned_toolchain()
    wrapper = root / f"linker-{source.stem}.py"
    linker_log = root / f"linker-{source.stem}.argv"
    wrapper.write_text(LINKER_WRAPPER_SOURCE, encoding="utf-8")
    os.chmod(wrapper, 0o700)
    argv = [
        tools["rustc_path"],
        "--edition=2021",
        "-Copt-level=0",
        "-Cdebuginfo=0",
        "-Cstrip=none",
        f"-Clinker={wrapper}",
        f"--remap-path-prefix={root}=<PRIVATE_TMP>",
    ]
    if sanitizer is not None:
        if sanitizer not in PINNED_SANITIZER_RUNTIME_SHA256:
            raise FuzzingError("unreviewed sanitizer requested")
        argv.append(f"-Zsanitizer={sanitizer}")
    argv.extend(["-o", str(binary), str(source)])
    env = {
        **tools["compile_env"],
        "DCRYPT_LINKER_ARGV_LOG": str(linker_log),
        "DCRYPT_REAL_LINKER": tools["linker_path"],
    }
    compiled = subprocess.run(argv, capture_output=True, timeout=60, env=env)
    if compiled.returncode != 0 or not linker_log.is_file() or linker_log.is_symlink():
        raise FuzzingError("fixture compilation or linker argv capture failed")
    linker_argv_raw = linker_log.read_bytes()
    linker_args = linker_argv_raw.split(b"\0")
    if str(binary).encode() not in linker_args:
        raise FuzzingError("captured linker argv lacks exact output path")
    runtime_records = []
    if sanitizer is not None:
        suffix = f"librustc-nightly_rt.{sanitizer.replace('address', 'asan').replace('leak', 'lsan')}.a"
        runtime_values = [value.decode() for value in linker_args if value.decode(errors="ignore").endswith(suffix)]
        runtime_paths = []
        for value in runtime_values:
            if not value.startswith("-Wl,/") or "," in value[len("-Wl,") :]:
                raise FuzzingError("sanitizer runtime linker argument has an unreviewed wrapper")
            runtime_paths.append(Path(value[len("-Wl,") :]))
        if len(runtime_paths) != 1:
            raise FuzzingError("captured linker argv lacks exactly one reviewed sanitizer runtime")
        runtime = runtime_paths[0]
        expected = PINNED_SANITIZER_RUNTIME_SHA256[sanitizer]
        _regular_exact(runtime, expected, label=f"{sanitizer} runtime")
        runtime_records.append({"path_suffix": suffix, "sha256": expected})
    required_symbol = None if sanitizer is None else "__asan_init" if sanitizer == "address" else "__lsan_init"
    if required_symbol is not None:
        symbol_proof = verify_binary_symbol(binary, required_symbol, tools=tools)
    else:
        symbol_proof = None
    return {
        "binary_sha256": sha256_bytes(binary.read_bytes()),
        "linker_executable_sha256": tools["linker_identity"]["executable_sha256"],
        "linker_version_sha256": tools["linker_identity"]["version_sha256"],
        "compiler_argv_sha256": sha256_bytes(canonical_json([value.replace(str(root), "<PRIVATE_TMP>") for value in argv])),
        "linker_argv_sha256": sha256_bytes(linker_argv_raw.replace(str(root).encode(), b"<PRIVATE_TMP>")),
        "linker_wrapper_sha256": sha256_bytes(LINKER_WRAPPER_SOURCE.encode()),
        "readelf_executable_sha256": tools["readelf_sha256"],
        "required_symbol": required_symbol,
        "required_symbol_proof": symbol_proof,
        "rustc_executable_sha256": tools["rustc_sha256"],
        "runtime_objects": runtime_records,
        "toolchain_identity_sha256": sha256_bytes(tools["rustc_version"]),
    }


def _defined_function_symbol_row(symbol_table: bytes, symbol: str) -> bytes:
    """Return one exact defined ELF FUNC row, ignoring undefined references."""

    if not re.fullmatch(r"(?:__[A-Za-z0-9_]+|LLVMFuzzerTestOneInput)", symbol):
        raise FuzzingError("unreviewed instrumentation symbol name")
    try:
        lines = symbol_table.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise FuzzingError(
            f"instrumentation symbol proof failed: symbol={symbol}, class=non-ascii-table"
        ) from error
    matching: list[tuple[bytes, list[str]]] = []
    for raw_line, line in zip(symbol_table.splitlines(), lines, strict=True):
        fields = line.split()
        if fields and fields[-1] == symbol:
            if len(fields) != 8 or not fields[0].endswith(":"):
                raise FuzzingError(
                    f"instrumentation symbol proof failed: symbol={symbol}, class=malformed-row"
                )
            matching.append((raw_line.strip(), fields))
    defined = [row for row, fields in matching if fields[6] != "UND"]
    if len(defined) != 1:
        raise FuzzingError(
            f"instrumentation symbol proof failed: symbol={symbol}, class=missing-or-ambiguous-defined-function"
        )
    fields = next(fields for row, fields in matching if row == defined[0])
    if fields[3] != "FUNC" or fields[4] not in {"GLOBAL", "WEAK"} or fields[5] != "DEFAULT":
        raise FuzzingError(
            f"instrumentation symbol proof failed: symbol={symbol}, class=wrong-defined-symbol-type"
        )
    return defined[0]


def verify_binary_symbols(
    binary: Path, symbols: list[str] | tuple[str, ...], *, tools: dict[str, Any] | None = None
) -> list[dict[str, str]]:
    if not symbols or len(symbols) != len(set(symbols)):
        raise FuzzingError("instrumentation symbol request closure is empty or duplicated")
    for symbol in symbols:
        if not re.fullmatch(r"(?:__[A-Za-z0-9_]+|LLVMFuzzerTestOneInput)", symbol):
            raise FuzzingError("unreviewed instrumentation symbol name")
    selected = pinned_toolchain() if tools is None else tools
    result = subprocess.run(
        [selected["readelf_path"], "-Ws", str(binary)],
        capture_output=True,
        timeout=15,
        env=selected["compile_env"],
    )
    if result.returncode != 0:
        raise FuzzingError("instrumentation symbol proof failed: class=inspector-error")
    table_sha256 = sha256_bytes(result.stdout)
    proofs = []
    for symbol in symbols:
        row = _defined_function_symbol_row(result.stdout, symbol)
        proofs.append(
            {
                "defined_function_row_sha256": sha256_bytes(row),
                "inspector_executable_sha256": selected["readelf_identity"]["executable_sha256"],
                "inspector_version_sha256": selected["readelf_identity"]["version_sha256"],
                "symbol": symbol,
                "symbol_table_sha256": table_sha256,
            }
        )
    return proofs


def verify_binary_symbol(
    binary: Path, symbol: str, *, tools: dict[str, Any] | None = None
) -> dict[str, str]:
    return verify_binary_symbols(binary, [symbol], tools=tools)[0]
