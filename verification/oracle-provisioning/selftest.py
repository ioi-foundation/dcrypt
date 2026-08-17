#!/usr/bin/env python3
"""Adversarial self-tests for fail-closed bundle and materialization checks."""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Callable

sys.dont_write_bytecode = True

from bundle_lib import (  # noqa: E402
    BundleError,
    canonical_json,
    compare_manifest_to_lock,
    extract_to_vendor,
    inspect_archive,
    load_manifest,
    MAX_ARCHIVE_SIZE,
    MAX_MEMBER_COUNT,
    MAX_UNPACKED_SIZE,
    validate_manifest,
    verify_bundle,
    verify_vendor,
)
from replay import (
    EXPECTED_NETWORK_CALL_COUNT,
    EXPECTED_SEQPACKET_SOCKETPAIR_COUNT,
    EXPECTED_STREAM_SOCKETPAIR_COUNT,
    exact_namespace_setup_lines,
    verify_network_trace,
)
from subject_lib import (
    load_subject_inputs,
    materialize_subject,
    post_subject_disallowed_paths,
    rebind_disallowed_paths,
    verify_subject_inputs,
    verify_subject_snapshot,
)


def expect_failure(label: str, action: Callable[[], object], fragment: str = "") -> None:
    try:
        action()
    except BundleError as error:
        if fragment and fragment not in str(error):
            raise RuntimeError(
                f"{label}: failed for the wrong reason: expected {fragment!r}, got {error!r}"
            ) from error
        print(f"PASS reject {label}: {error}")
        return
    raise RuntimeError(f"{label}: unexpectedly accepted")


def write_tar(path: Path, members: list[tuple[str, bytes, bytes | None, int]]) -> None:
    """Write (name, tar type, content, mode) entries."""
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, member_type, content, mode in members:
            item = tarfile.TarInfo(name)
            item.type = member_type
            item.mode = mode
            item.mtime = 0
            if member_type == tarfile.REGTYPE:
                assert content is not None
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
            else:
                if content is not None:
                    item.size = len(content)
                if member_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    item.linkname = "target"
                archive.addfile(item, io.BytesIO(content) if content is not None else None)


def structural_tar_tests(root: Path) -> int:
    crate_root = "sample-1.0.0"
    canonical = root / "canonical.crate"
    write_tar(
        canonical,
        [(f"{crate_root}/Cargo.toml", tarfile.REGTYPE, b"[package]\n", 0o644)],
    )
    files, count, unpacked = inspect_archive(canonical, "sample", "1.0.0")
    if files != [("Cargo.toml", 10)] or count != 1 or unpacked != 10:
        raise RuntimeError("canonical synthetic archive facts differ")
    cases = [
        (
            "path traversal",
            [(f"{crate_root}/../escape", tarfile.REGTYPE, b"x", 0o644)],
            "canonical POSIX relative path",
        ),
        (
            "absolute path",
            [("/absolute", tarfile.REGTYPE, b"x", 0o644)],
            "safe POSIX relative path",
        ),
        (
            "noncanonical repeated separator",
            [(f"{crate_root}//file", tarfile.REGTYPE, b"x", 0o644)],
            "canonical POSIX relative path",
        ),
        (
            "control character path",
            [(f"{crate_root}/bad\nname", tarfile.REGTYPE, b"x", 0o644)],
            "safe POSIX relative path",
        ),
        (
            "wrong crate root",
            [("other-1.0.0/file", tarfile.REGTYPE, b"x", 0o644)],
            "outside canonical root",
        ),
        (
            "symlink member",
            [(f"{crate_root}/link", tarfile.SYMTYPE, None, 0o777)],
            "symlink, hardlink, or special",
        ),
        (
            "hardlink member",
            [(f"{crate_root}/link", tarfile.LNKTYPE, None, 0o644)],
            "symlink, hardlink, or special",
        ),
        (
            "FIFO member",
            [(f"{crate_root}/pipe", tarfile.FIFOTYPE, None, 0o644)],
            "symlink, hardlink, or special",
        ),
        (
            "privileged mode bits",
            [(f"{crate_root}/file", tarfile.REGTYPE, b"x", 0o4755)],
            "privileged mode bits",
        ),
        (
            "archive supplied Cargo checksum",
            [(f"{crate_root}/.cargo-checksum.json", tarfile.REGTYPE, b"{}", 0o644)],
            "may not supply",
        ),
        (
            "duplicate member",
            [
                (f"{crate_root}/file", tarfile.REGTYPE, b"x", 0o644),
                (f"{crate_root}/file", tarfile.REGTYPE, b"y", 0o644),
            ],
            "duplicate crate member",
        ),
    ]
    for index, (label, members, fragment) in enumerate(cases):
        path = root / f"malformed-{index}.crate"
        write_tar(path, members)
        expect_failure(
            label,
            lambda path=path: inspect_archive(path, "sample", "1.0.0"),
            fragment,
        )
    directory_nonzero = root / "directory-nonzero.crate"
    directory = tarfile.TarInfo(crate_root)
    directory.type = tarfile.DIRTYPE
    directory.mode = 0o755
    directory.mtime = 0
    directory.size = 1
    regular = tarfile.TarInfo(f"{crate_root}/Cargo.toml")
    regular.type = tarfile.REGTYPE
    regular.mode = 0o644
    regular.mtime = 0
    regular_content = b"[package]\n"
    regular.size = len(regular_content)
    raw_tar = (
        directory.tobuf(format=tarfile.PAX_FORMAT)
        + regular.tobuf(format=tarfile.PAX_FORMAT)
        + regular_content
        + b"\0" * (512 - len(regular_content))
        + b"\0" * 1024
    )
    directory_nonzero.write_bytes(gzip.compress(raw_tar, mtime=0))
    expect_failure(
        "directory member nonzero size",
        lambda: inspect_archive(directory_nonzero, "sample", "1.0.0"),
        "directory crate member has nonzero size",
    )
    trailing = root / "trailing-data.crate"
    trailing.write_bytes(canonical.read_bytes() + b"trailing")
    expect_failure(
        "gzip trailing data",
        lambda: inspect_archive(trailing, "sample", "1.0.0"),
        "trailing or concatenated gzip data",
    )
    concatenated = root / "concatenated-gzip.crate"
    concatenated.write_bytes(canonical.read_bytes() + canonical.read_bytes())
    expect_failure(
        "concatenated gzip members",
        lambda: inspect_archive(concatenated, "sample", "1.0.0"),
        "trailing or concatenated gzip data",
    )
    return 4 + len(cases)


def exact_bundle_tests(
    root: Path, manifest: dict[str, object], source_archives: Path
) -> int:
    first = copy.deepcopy(manifest["packages"][0])  # type: ignore[index]
    single = copy.deepcopy(manifest)
    single["package_count"] = 1
    single["packages"] = [first]
    single["acquisition"]["aggregate_totals"] = {
        "archive_bytes": first["archive"]["size"],  # type: ignore[index]
        "member_count": first["archive"]["member_count"],  # type: ignore[index]
        "unpacked_bytes": first["archive"]["unpacked_size"],  # type: ignore[index]
    }
    filename = first["archive"]["file"]  # type: ignore[index]
    source = source_archives / filename

    valid = root / "valid"
    valid.mkdir()
    shutil.copyfile(source, valid / filename)
    verify_bundle(single, valid)
    print("PASS accept exact one-archive bundle")

    empty = root / "missing"
    empty.mkdir()
    expect_failure("missing archive", lambda: verify_bundle(single, empty), "missing=")

    extra = root / "extra"
    shutil.copytree(valid, extra)
    (extra / "unexpected").write_bytes(b"unexpected")
    expect_failure("extra archive", lambda: verify_bundle(single, extra), "extra=")

    corrupt = root / "corrupt"
    shutil.copytree(valid, corrupt)
    path = corrupt / filename
    data = path.read_bytes()
    path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    expect_failure("corrupt archive", lambda: verify_bundle(single, corrupt), "checksum mismatch")

    symlink = root / "symlink"
    symlink.mkdir()
    os.symlink(source, symlink / filename)
    expect_failure("symlink archive", lambda: verify_bundle(single, symlink), "regular file")

    hardlink_source = root / "hardlink-source.crate"
    shutil.copyfile(source, hardlink_source)
    hardlink = root / "hardlink"
    hardlink.mkdir()
    os.link(hardlink_source, hardlink / filename)
    expect_failure("hardlink archive", lambda: verify_bundle(single, hardlink), "hard links")

    fifo = root / "fifo"
    fifo.mkdir()
    os.mkfifo(fifo / filename)
    expect_failure("special archive", lambda: verify_bundle(single, fifo), "regular file")

    manifest_path = root / "manifest-noncanonical.json"
    manifest_path.write_text(json.dumps(single), encoding="utf-8")
    expect_failure("noncanonical manifest", lambda: load_manifest(manifest_path), "not canonical")
    extra_key = copy.deepcopy(single)
    extra_key["unexpected"] = True
    manifest_path.write_bytes(canonical_json(extra_key))
    expect_failure("unknown manifest key", lambda: load_manifest(manifest_path), "keys differ")
    return 9


def vendor_tests(
    root: Path, manifest: dict[str, object], source_archives: Path
) -> int:
    first = copy.deepcopy(manifest["packages"][0])  # type: ignore[index]
    single = copy.deepcopy(manifest)
    single["package_count"] = 1
    single["packages"] = [first]
    single["acquisition"]["aggregate_totals"] = {
        "archive_bytes": first["archive"]["size"],  # type: ignore[index]
        "member_count": first["archive"]["member_count"],  # type: ignore[index]
        "unpacked_bytes": first["archive"]["unpacked_size"],  # type: ignore[index]
    }
    filename = first["archive"]["file"]  # type: ignore[index]
    source = source_archives / filename
    pristine = root / "vendor-pristine"
    pristine.mkdir(mode=0o755)
    pristine.chmod(0o755)
    extract_to_vendor(source, first, pristine)
    verify_vendor(single, source_archives, pristine)
    print("PASS accept exact materialized vendor crate")

    crate_id = f"{first['name']}-{first['version']}"  # type: ignore[index]
    corrupt = root / "vendor-corrupt"
    shutil.copytree(pristine, corrupt)
    cargo_toml = corrupt / crate_id / "Cargo.toml"
    cargo_toml.write_bytes(cargo_toml.read_bytes() + b"\n")
    expect_failure("corrupt vendor file", lambda: verify_vendor(single, source_archives, corrupt))

    symlink = root / "vendor-symlink"
    shutil.copytree(pristine, symlink)
    os.symlink("Cargo.toml", symlink / crate_id / "unexpected-link")
    expect_failure("vendor symlink", lambda: verify_vendor(single, source_archives, symlink), "symlink")

    hardlink = root / "vendor-hardlink"
    shutil.copytree(pristine, hardlink)
    os.link(hardlink / crate_id / "Cargo.toml", hardlink / crate_id / "unexpected-hardlink")
    expect_failure("vendor hardlink", lambda: verify_vendor(single, source_archives, hardlink), "hard links")

    extra_dir = root / "vendor-extra-dir"
    shutil.copytree(pristine, extra_dir)
    unexpected_directory = extra_dir / crate_id / "unexpected-empty"
    unexpected_directory.mkdir(mode=0o755)
    unexpected_directory.chmod(0o755)
    expect_failure(
        "vendor extra directory",
        lambda: verify_vendor(single, source_archives, extra_dir),
        "vendor directories differ",
    )
    bad_mode = root / "vendor-bad-mode"
    shutil.copytree(pristine, bad_mode)
    (bad_mode / crate_id / "Cargo.toml").chmod(0o755)
    expect_failure(
        "vendor executable file mode",
        lambda: verify_vendor(single, source_archives, bad_mode),
        "mode is not 0644",
    )
    return 6


def normative_root_tests(
    root: Path, manifest: dict[str, object], subject: dict[str, object]
) -> int:
    cases: list[tuple[str, str, int]] = [
        ("aggregate archive cap", "size", MAX_ARCHIVE_SIZE),
        ("aggregate member cap", "member_count", MAX_MEMBER_COUNT),
        ("aggregate unpacked cap", "unpacked_size", MAX_UNPACKED_SIZE),
    ]
    total = 0
    total_field = {
        "size": "archive_bytes",
        "member_count": "member_count",
        "unpacked_size": "unpacked_bytes",
    }
    fragments = {
        "size": "aggregate archive bytes",
        "member_count": "aggregate member count",
        "unpacked_size": "aggregate unpacked bytes",
    }
    for label, field, limit in cases:
        changed = copy.deepcopy(manifest)
        for package in changed["packages"]:  # type: ignore[index]
            package["archive"][field] = limit
        changed["acquisition"]["aggregate_totals"][total_field[field]] = (  # type: ignore[index]
            limit * changed["package_count"]  # type: ignore[index,operator]
        )
        for other_field, archive_field in (
            ("archive_bytes", "size"),
            ("member_count", "member_count"),
            ("unpacked_bytes", "unpacked_size"),
        ):
            changed["acquisition"]["aggregate_totals"][other_field] = sum(  # type: ignore[index]
                package["archive"][archive_field] for package in changed["packages"]  # type: ignore[index]
            )
        expect_failure(label, lambda changed=changed: validate_manifest(changed), fragments[field])
        total += 1

    mutated_name = copy.deepcopy(manifest)
    names = mutated_name["tests"]["targets"][0]["expected_tests"]  # type: ignore[index]
    names[0] = "aaa_mutated_test_name"
    names.sort()
    expect_failure(
        "frozen test-name mutation with unchanged count",
        lambda: validate_manifest(mutated_name),
        "independent immutable code pin",
    )
    total += 1

    reordered_names = copy.deepcopy(manifest)
    reordered_names["tests"]["targets"][0]["expected_tests"].reverse()  # type: ignore[index]
    expect_failure(
        "frozen test-name reorder",
        lambda: validate_manifest(reordered_names),
        "valid, unique, and sorted",
    )
    total += 1

    substituted_target = copy.deepcopy(manifest)
    target = substituted_target["tests"]["targets"][-1]  # type: ignore[index]
    target["target"] = "zz_substituted_target"
    target["source"] = "tests/zz_substituted_target.rs"
    expect_failure(
        "coherent frozen target and source-path substitution",
        lambda: validate_manifest(substituted_target),
        "independent immutable code pin",
    )
    total += 1

    substituted_hash = copy.deepcopy(manifest)
    source_hash = substituted_hash["tests"]["targets"][0]["source_sha256"]  # type: ignore[index]
    substituted_hash["tests"]["targets"][0]["source_sha256"] = (  # type: ignore[index]
        ("0" if source_hash[0] != "0" else "1") + source_hash[1:]
    )
    expect_failure(
        "frozen source-hash substitution",
        lambda: validate_manifest(substituted_hash),
        "independent immutable code pin",
    )
    total += 1

    reordered_targets = copy.deepcopy(manifest)
    reordered_targets["tests"]["targets"].reverse()  # type: ignore[index]
    expect_failure(
        "frozen target reorder",
        lambda: validate_manifest(reordered_targets),
        "strictly sorted",
    )
    total += 1

    coherent_subject = copy.deepcopy(subject)
    replacement_commit = "0" * 40 if subject["source_commit"] != "0" * 40 else "1" * 40
    replacement_tree = "1" * 40 if subject["source_tree"] != "1" * 40 else "2" * 40
    coherent_subject["source_commit"] = replacement_commit
    coherent_subject["source_tree"] = replacement_tree
    coherent_subject_path = root / "coherent-subject-inputs.json"
    coherent_subject_path.write_bytes(canonical_json(coherent_subject))
    coherent_manifest = copy.deepcopy(manifest)
    coherent_manifest["subject"]["source_commit"] = replacement_commit  # type: ignore[index]
    coherent_manifest["subject"]["source_tree"] = replacement_tree  # type: ignore[index]
    coherent_manifest["subject"]["inputs"] = {  # type: ignore[index]
        "file_count": coherent_subject["file_count"],
        "path": "verification/oracle-provisioning/subject-inputs.json",
        "sha256": hashlib.sha256(coherent_subject_path.read_bytes()).hexdigest(),
    }
    validate_manifest(coherent_manifest)
    coherent_manifest_path = root / "coherent-rebind-manifest.json"
    coherent_manifest_path.write_bytes(canonical_json(coherent_manifest))
    expect_failure(
        "coherent manifest plus subject rebind without reviewed code pin",
        lambda: load_manifest(coherent_manifest_path),
        "code-pinned reviewed root",
    )
    return total + 1


def subject_snapshot_tests(
    root: Path, repo_root: Path, subject: dict[str, object]
) -> int:
    verify_subject_inputs(  # type: ignore[arg-type]
        repo_root, subject, verify_repository_state=False
    )
    pristine = root / "subject-pristine"
    materialize_subject(  # type: ignore[arg-type]
        repo_root, subject, pristine, verify_repository_state=False
    )
    verify_subject_snapshot(subject, pristine)  # type: ignore[arg-type]
    print("PASS accept exact Git-bound subject snapshot")
    records = subject["files"]  # type: ignore[index]
    subject_paths = {record["path"] for record in records}
    forbidden_prefixes = (
        "verification/oracle-provisioning/",
        "verification/clean-room-protocol-reference/",
        "verification/target/",
    )
    if any(path.startswith(forbidden_prefixes) for path in subject_paths):
        raise RuntimeError("subject closure contains a self-referential or generated path")
    print("PASS subject closure excludes exact self-binding/scaffold/output prefixes")
    first_path = records[0]["path"]

    missing = root / "subject-missing"
    shutil.copytree(pristine, missing)
    (missing / first_path).unlink()
    expect_failure(
        "subject snapshot missing input",
        lambda: verify_subject_snapshot(subject, missing),  # type: ignore[arg-type]
        "missing=",
    )

    extra = root / "subject-extra"
    shutil.copytree(pristine, extra)
    (extra / "verification/untracked-build-input.rs").write_bytes(b"extra")
    expect_failure(
        "subject snapshot extra input",
        lambda: verify_subject_snapshot(subject, extra),  # type: ignore[arg-type]
        "extra=",
    )

    config = root / "subject-config-drift"
    shutil.copytree(pristine, config)
    config_path = config / "verification/.cargo/config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("[net]\noffline = false\n", encoding="utf-8")
    expect_failure(
        "subject Cargo config discovery drift",
        lambda: verify_subject_snapshot(subject, config),  # type: ignore[arg-type]
        "extra=",
    )

    workspace = root / "subject-workspace-discovery-drift"
    shutil.copytree(pristine, workspace)
    workspace_manifest = workspace / "crates/Cargo.toml"
    workspace_manifest.write_text("[workspace]\n", encoding="utf-8")
    expect_failure(
        "subject Cargo ancestor-workspace discovery drift",
        lambda: verify_subject_snapshot(subject, workspace),  # type: ignore[arg-type]
        "previously absent Cargo workspace manifest appeared",
    )

    build_script = root / "subject-root-build-script-drift"
    shutil.copytree(pristine, build_script)
    (build_script / "build.rs").write_text("fn main() {}\n", encoding="utf-8")
    expect_failure(
        "subject root Cargo build-script discovery drift",
        lambda: verify_subject_snapshot(subject, build_script),  # type: ignore[arg-type]
        "previously absent root Cargo build.rs appeared",
    )

    absent_target_directory = root / "subject-root-auto-target-directory-drift"
    shutil.copytree(pristine, absent_target_directory)
    (absent_target_directory / "examples").mkdir()
    expect_failure(
        "subject root Cargo auto-target directory discovery drift",
        lambda: verify_subject_snapshot(subject, absent_target_directory),  # type: ignore[arg-type]
        "previously absent root Cargo auto-target directory appeared",
    )

    extra_target = root / "subject-root-auto-target-file-drift"
    shutil.copytree(pristine, extra_target)
    (extra_target / "tests/src").mkdir()
    (extra_target / "tests/src/main.rs").write_text("#[test] fn shadow() {}\n", encoding="utf-8")
    expect_failure(
        "subject root Cargo auto-target file discovery drift",
        lambda: verify_subject_snapshot(subject, extra_target),  # type: ignore[arg-type]
        "root Cargo auto-target discovery drifted",
    )

    corrupt = root / "subject-vector-corrupt"
    shutil.copytree(pristine, corrupt)
    vector_path = subject["vector_set"]["data_yaml_paths"][0]  # type: ignore[index]
    vector = corrupt / vector_path
    vector.write_bytes(vector.read_bytes() + b"\n")
    expect_failure(
        "subject Ethereum vector corruption",
        lambda: verify_subject_snapshot(subject, corrupt),  # type: ignore[arg-type]
        "bytes differ",
    )
    return 10


def rebind_path_policy_tests() -> int:
    changed = {
        ".gitignore",
        "assurance/interoperability/protocol-specs/example.toml",
        "verification/oracle-provisioning/bundle_lib.py",
        "verification/oracle-provisioning/manifest.json",
        "verification/oracle-provisioning/subject-inputs.json",
        "verification/oracle-provisioning/replay.py",
        "verification/tests/xchacha20poly1305.rs",
    }
    expected_before_write = {
        "verification/oracle-provisioning/bundle_lib.py",
        "verification/oracle-provisioning/manifest.json",
        "verification/oracle-provisioning/subject-inputs.json",
        "verification/oracle-provisioning/replay.py",
        "verification/tests/xchacha20poly1305.rs",
    }
    observed_before_write = rebind_disallowed_paths(
        changed, allow_generated_binding_files=False
    )
    if observed_before_write != expected_before_write:
        raise RuntimeError("pre-write final-rebind allowlist differs")
    expected_after_write = {
        "verification/oracle-provisioning/replay.py",
        "verification/tests/xchacha20poly1305.rs",
    }
    observed_after_write = rebind_disallowed_paths(
        changed, allow_generated_binding_files=True
    )
    if observed_after_write != expected_after_write:
        raise RuntimeError("post-write final-rebind allowlist differs")
    print("PASS exact pre/post final-rebind path allowlists")
    committed = {
        ".gitignore",
        "assurance/interoperability/protocol-specs/example.toml",
        "verification/oracle-provisioning/bundle_lib.py",
        "verification/oracle-provisioning/manifest.json",
        "verification/oracle-provisioning/replay.py",
        "verification/oracle-provisioning/subject-inputs.json",
        "verification/tests/xchacha20poly1305.rs",
    }
    disallowed_committed = post_subject_disallowed_paths(committed)
    if disallowed_committed != {
        ".gitignore",
        "verification/oracle-provisioning/replay.py",
        "verification/tests/xchacha20poly1305.rs",
    }:
        raise RuntimeError("persistent post-subject committed allowlist differs")
    print("PASS reject post-subject committed replay/security-tool drift")
    return 2


def network_trace_tests(root: Path) -> int:
    setup = exact_namespace_setup_lines("1", "101", "102")
    for index in range(EXPECTED_STREAM_SOCKETPAIR_COUNT):
        pid = 1000 + index
        first = 10_000 + (index * 2)
        second = first + 1
        setup.append(
            f"{pid} socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, "
            f"0, [3<UNIX-STREAM:[{first}]>, 5<UNIX-STREAM:[{second}]>]) = 0"
        )
    seqpacket_start = len(setup)
    for index in range(EXPECTED_SEQPACKET_SOCKETPAIR_COUNT):
        pid = 2000 + index
        first = 20_000 + (index * 2)
        second = first + 1
        setup.extend(
            [
                f"{pid} socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, "
                f"[15<UNIX:[{first}]>, 16<UNIX:[{second}]>]) = 0",
                f'{pid} recvfrom(15<UNIX:[{first}]>, "", 8, 0, NULL, NULL) = 0',
            ]
        )
    setup[seqpacket_start] = setup[seqpacket_start].replace(" socketpair", "   socketpair")
    setup[seqpacket_start + 1] = setup[seqpacket_start + 1].replace(" recvfrom", "   recvfrom")
    if len(setup) != EXPECTED_NETWORK_CALL_COUNT:
        raise RuntimeError("synthetic exact network trace has wrong call count")
    valid = root / "network-valid.trace"
    valid.write_text("\n".join(setup) + "\n", encoding="utf-8")
    counts = verify_network_trace(valid)
    if counts["calls"] != len(setup):
        raise RuntimeError("valid network trace count differs")
    print("PASS accept exact namespace-local network syscall trace")

    split = root / "network-split-valid.trace"
    split_lines = setup.copy()
    split_pid = split_lines[seqpacket_start + 1].split(maxsplit=1)[0]
    split_lines[seqpacket_start + 1 : seqpacket_start + 2] = [
        f'{split_pid} recvfrom(15<UNIX:[20000]>, "", 8, 0,  <unfinished ...>',
        f"{split_pid} <... recvfrom resumed>NULL, NULL) = 0",
    ]
    split.write_text("\n".join(split_lines) + "\n", encoding="utf-8")
    split_counts = verify_network_trace(split)
    if split_counts != counts:
        raise RuntimeError("split syscall trace did not normalize to the exact logical trace")
    print("PASS accept exact unfinished/resumed rendering of an allowlisted syscall")

    split_mutations = [
        (
            "resumed syscall with wrong PID",
            1,
            f"{int(split_pid) + 1} <... recvfrom resumed>NULL, NULL) = 0",
            "resumes without a matching unfinished syscall",
        ),
        (
            "resumed syscall with wrong name",
            1,
            f"{split_pid} <... socketpair resumed>NULL, NULL) = 0",
            "resumed syscall name differs",
        ),
        (
            "unfinished syscall without completion",
            1,
            None,
            "has no resumed completion",
        ),
        (
            "new syscall before resumed completion",
            1,
            f"{split_pid} socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM",
            "starts a new syscall before resuming",
        ),
    ]
    for index, (label, relative_index, replacement, fragment) in enumerate(split_mutations):
        changed = split_lines.copy()
        target_index = seqpacket_start + 1 + relative_index
        if replacement is None:
            del changed[target_index]
        else:
            changed[target_index] = replacement
        path = root / f"network-split-malicious-{index}.trace"
        path.write_text("\n".join(changed) + "\n", encoding="utf-8")
        expect_failure(label, lambda path=path: verify_network_trace(path), fragment)
    replacements = [
        (
            "internet socket syscall",
            7,
            "9 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = -1 EPERM",
            "not an exact allowlisted form",
        ),
        (
            "connect syscall even on AF_UNIX",
            7,
            "9 connect(3<UNIX:[3]>, {sa_family=AF_UNIX}, 2) = 0",
            "not an exact allowlisted form",
        ),
        (
            "unknown AF_UNIX socket type",
            7,
            "9 socket(AF_UNIX, SOCK_STREAM, 0) = 3<UNIX:[3]>",
            "not an exact allowlisted form",
        ),
        (
            "tab PID/call separator",
            7,
            setup[7].replace(" socketpair", "\tsocketpair"),
            "exact ASCII-space PID/call separator",
        ),
        (
            "forged namespace bind arguments and return",
            2,
            "1 bind(GARBAGE) = GARBAGE",
            "namespace setup network trace line 3 is not exact",
        ),
        (
            "failed socketpair return",
            7,
            setup[7].replace(" = 0", " = -1 EPERM (Operation not permitted)"),
            "not an exact allowlisted form",
        ),
        (
            "socketpair extra argument",
            7,
            setup[7].replace(", 0, [", ", 0, GARBAGE, ["),
            "not an exact allowlisted form",
        ),
        (
            "recvfrom extra argument",
            seqpacket_start + 1,
            setup[seqpacket_start + 1].replace(", NULL, NULL)", ", NULL, NULL, GARBAGE)"),
            "not an exact allowlisted form",
        ),
        (
            "recvfrom failed return",
            seqpacket_start + 1,
            setup[seqpacket_start + 1].replace(" = 0", " = -1 EIO (Input/output error)"),
            "not an exact allowlisted form",
        ),
        (
            "recvfrom forged endpoint annotation",
            seqpacket_start + 1,
            setup[seqpacket_start + 1].replace("[20000]", "[99999]"),
            "lacks its exact prior seqpacket endpoint",
        ),
    ]
    for index, (label, line_index, line, fragment) in enumerate(replacements):
        path = root / f"network-malicious-{index}.trace"
        changed = setup.copy()
        changed[line_index] = line
        path.write_text("\n".join(changed) + "\n", encoding="utf-8")
        expect_failure(label, lambda path=path: verify_network_trace(path), fragment)

    reordered = root / "network-reordered.trace"
    changed = setup.copy()
    changed[seqpacket_start], changed[seqpacket_start + 1] = (
        changed[seqpacket_start + 1],
        changed[seqpacket_start],
    )
    reordered.write_text("\n".join(changed) + "\n", encoding="utf-8")
    expect_failure(
        "recvfrom before matching socketpair",
        lambda: verify_network_trace(reordered),
        "lacks its exact prior seqpacket endpoint",
    )

    truncated = root / "network-truncated.trace"
    truncated.write_text("\n".join(setup), encoding="utf-8")
    expect_failure(
        "truncated final newline",
        lambda: verify_network_trace(truncated),
        "canonical LF text",
    )

    missing = root / "network-missing.trace"
    missing.write_text("\n".join(setup[:-1]) + "\n", encoding="utf-8")
    expect_failure(
        "missing network trace line",
        lambda: verify_network_trace(missing),
        "call count differs",
    )
    return 2 + len(split_mutations) + len(replacements) + 3


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        subject = load_subject_inputs(args.manifest.parent / "subject-inputs.json")
        compare_manifest_to_lock(manifest, args.lock)
        verify_bundle(manifest, args.archives)
        with tempfile.TemporaryDirectory(prefix="dcrypt-oracle-provisioning-selftest-") as temporary:
            root = Path(temporary)
            total = structural_tar_tests(root)
            total += exact_bundle_tests(root, manifest, args.archives)
            total += vendor_tests(root, manifest, args.archives)
            total += normative_root_tests(root, manifest, subject)
            total += subject_snapshot_tests(root, args.repo_root.resolve(), subject)
            total += rebind_path_policy_tests()
            total += network_trace_tests(root)
            changed_lock = root / "Cargo.lock"
            changed_lock.write_bytes(args.lock.read_bytes() + b"\n")
            expect_failure(
                "changed lockfile",
                lambda: compare_manifest_to_lock(manifest, changed_lock),
                "lockfile digest mismatch",
            )
            total += 1
        print(f"self-test passed: {total} positive/negative cases")
        return 0
    except (BundleError, OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
