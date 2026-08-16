#!/usr/bin/env python3
"""Run the exact subject cold, locked, offline, and in a minimal sandbox."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from bundle_lib import (  # noqa: E402
    BundleError,
    _regular_unlinked_file,
    canonical_json,
    cargo_config,
    compare_manifest_to_lock,
    load_manifest,
    verify_bundle,
    verify_vendor,
)
from subject_lib import load_subject_inputs, verify_subject_snapshot  # noqa: E402


MAX_NETWORK_TRACE_BYTES = 1024 * 1024
EXPECTED_NETWORK_CALL_COUNT = 253
EXPECTED_STREAM_SOCKETPAIR_COUNT = 18
EXPECTED_SEQPACKET_SOCKETPAIR_COUNT = 114
TRACE_LINE = re.compile(
    r"(?P<pid>[1-9][0-9]*)(?P<separator> +)(?P<call>[^ ].*)\Z"
)
SETUP_UNIX_SOCKET = re.compile(
    r"(?P<pid>[1-9][0-9]*) socket\(AF_UNIX, SOCK_DGRAM\|SOCK_CLOEXEC, 0\) "
    r"= 5<UNIX:\[(?P<inode>[1-9][0-9]*)\]>\Z"
)
SETUP_NETLINK_SOCKET = re.compile(
    r"(?P<pid>[1-9][0-9]*) socket\(AF_NETLINK, SOCK_RAW\|SOCK_CLOEXEC, "
    r"NETLINK_ROUTE\) = 5<NETLINK:\[(?P<inode>[1-9][0-9]*)\]>\Z"
)
STREAM_SOCKETPAIR = re.compile(
    r"(?P<pid>[1-9][0-9]*) socketpair\(AF_UNIX, "
    r"SOCK_STREAM\|SOCK_CLOEXEC\|SOCK_NONBLOCK, 0, "
    r"\[3<UNIX-STREAM:\[(?P<first>[1-9][0-9]*)\]>, "
    r"5<UNIX-STREAM:\[(?P<second>[1-9][0-9]*)\]>\]\) = 0\Z"
)
SEQPACKET_SOCKETPAIR = re.compile(
    r"(?P<pid>[1-9][0-9]*) socketpair\(AF_UNIX, "
    r"SOCK_SEQPACKET\|SOCK_CLOEXEC, 0, "
    r"\[15<UNIX:\[(?P<first>[1-9][0-9]*)\]>, "
    r"16<UNIX:\[(?P<second>[1-9][0-9]*)\]>\]\) = 0\Z"
)
UNIX_RECVFROM = re.compile(
    r"(?P<pid>[1-9][0-9]*) recvfrom\(15<UNIX:\[(?P<inode>[1-9][0-9]*)\]>, "
    r'"", 8, 0, NULL, NULL\) = 0\Z'
)


def _load_record(path: Path) -> dict[str, object]:
    _regular_unlinked_file(path, "materialization record")
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BundleError(f"cannot parse materialization record: {error}") from error
    if raw != canonical_json(value) or not isinstance(value, dict):
        raise BundleError("materialization record is not canonical JSON")
    return value


def exact_namespace_setup_lines(pid: str, unix_inode: str, netlink_inode: str) -> list[str]:
    if not all(re.fullmatch(r"[1-9][0-9]*", value) for value in (pid, unix_inode, netlink_inode)):
        raise BundleError("namespace setup identities must be positive canonical decimal")
    if unix_inode == netlink_inode:
        raise BundleError("namespace setup socket inode annotations are not distinct")
    return [
        f"{pid} socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0) = 5<UNIX:[{unix_inode}]>",
        f"{pid} socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) "
        f"= 5<NETLINK:[{netlink_inode}]>",
        f"{pid} bind(5<NETLINK:[{netlink_inode}]>, "
        "{sa_family=AF_NETLINK, nl_pid=1, nl_groups=00000000}, 12) = 0",
        f"{pid} sendto(5<NETLINK:[{netlink_inode}]>, "
        "[{nlmsg_len=40, nlmsg_type=0x14 /* NLMSG_??? */, "
        "nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|0x600, nlmsg_seq=0, nlmsg_pid=1}, "
        '"\\x02\\x08\\x80\\xfe\\x01\\x00\\x00\\x00\\x08\\x00\\x02\\x00'
        '\\x7f\\x00\\x00\\x01\\x08\\x00\\x01\\x00\\x7f\\x00\\x00\\x01"], '
        "40, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 40",
        f"{pid} recvfrom(5<NETLINK:[{netlink_inode}]>, "
        "[{nlmsg_len=36, nlmsg_type=NLMSG_ERROR, nlmsg_flags=NLM_F_CAPPED, "
        "nlmsg_seq=0, nlmsg_pid=1}, {error=0, msg={nlmsg_len=40, "
        "nlmsg_type=0x14 /* NLMSG_??? */, "
        "nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|0x600, nlmsg_seq=0, nlmsg_pid=1}}], "
        "1024, 0, NULL, NULL) = 36",
        f"{pid} sendto(5<NETLINK:[{netlink_inode}]>, "
        "[{nlmsg_len=32, nlmsg_type=0x10 /* NLMSG_??? */, "
        "nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK, nlmsg_seq=1, nlmsg_pid=1}, "
        '"\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x01\\x00\\x00\\x00'
        '\\x01\\x00\\x00\\x00"], 32, 0, '
        "{sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 32",
        f"{pid} recvfrom(5<NETLINK:[{netlink_inode}]>, "
        "[{nlmsg_len=36, nlmsg_type=NLMSG_ERROR, nlmsg_flags=NLM_F_CAPPED, "
        "nlmsg_seq=1, nlmsg_pid=1}, {error=0, msg={nlmsg_len=32, "
        "nlmsg_type=0x10 /* NLMSG_??? */, nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK, "
        "nlmsg_seq=1, nlmsg_pid=1}}], 1024, 0, NULL, NULL) = 36",
    ]


def verify_network_trace(path: Path) -> dict[str, int]:
    _regular_unlinked_file(path, "external network trace")
    size = path.stat().st_size
    if size > MAX_NETWORK_TRACE_BYTES:
        raise BundleError("external network trace exceeds its reviewed size cap")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise BundleError(f"cannot read external network trace: {error}") from error
    if not text or not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise BundleError("external network trace must be nonempty canonical LF text")
    raw_lines = text.splitlines()
    if len(raw_lines) != EXPECTED_NETWORK_CALL_COUNT:
        raise BundleError(
            "external network trace call count differs: "
            f"expected {EXPECTED_NETWORK_CALL_COUNT}, got {len(raw_lines)}"
        )
    lines: list[str] = []
    for number, line in enumerate(raw_lines, 1):
        parsed_line = TRACE_LINE.fullmatch(line)
        if parsed_line is None:
            raise BundleError(
                f"network trace line {number} lacks an exact ASCII-space PID/call separator"
            )
        lines.append(f"{parsed_line.group('pid')} {parsed_line.group('call')}")
    counts = {
        "af_netlink_socket": 0,
        "af_unix_socket": 0,
        "af_unix_socketpair": 0,
        "calls": 0,
        "netlink_bind": 0,
        "netlink_recvfrom": 0,
        "netlink_sendto": 0,
        "unix_recvfrom": 0,
    }
    unix_setup = SETUP_UNIX_SOCKET.fullmatch(lines[0])
    netlink_setup = SETUP_NETLINK_SOCKET.fullmatch(lines[1])
    if unix_setup is None or netlink_setup is None:
        raise BundleError("first two network trace lines are not exact namespace setup sockets")
    setup_pid = unix_setup.group("pid")
    netlink_inode = netlink_setup.group("inode")
    if netlink_setup.group("pid") != setup_pid:
        raise BundleError("namespace setup socket process identities differ")
    if unix_setup.group("inode") == netlink_inode:
        raise BundleError("namespace setup socket inode annotations are not distinct")
    expected_setup = exact_namespace_setup_lines(
        setup_pid, unix_setup.group("inode"), netlink_inode
    )[2:]
    if lines[2:7] != expected_setup:
        mismatch = next(
            index
            for index, (actual, expected) in enumerate(zip(lines[2:7], expected_setup), 3)
            if actual != expected
        )
        raise BundleError(f"namespace setup network trace line {mismatch} is not exact")
    counts.update(
        {
            "af_netlink_socket": 1,
            "af_unix_socket": 1,
            "calls": 7,
            "netlink_bind": 1,
            "netlink_recvfrom": 2,
            "netlink_sendto": 2,
        }
    )
    pending_seqpacket: dict[tuple[str, str], str] = {}
    stream_count = 0
    seqpacket_count = 0
    for number, line in enumerate(lines[7:], 8):
        stream = STREAM_SOCKETPAIR.fullmatch(line)
        if stream is not None:
            if stream.group("first") == stream.group("second"):
                raise BundleError(f"AF_UNIX stream pair inodes repeat at line {number}")
            stream_count += 1
            counts["af_unix_socketpair"] += 1
            counts["calls"] += 1
            continue
        seqpacket = SEQPACKET_SOCKETPAIR.fullmatch(line)
        if seqpacket is not None:
            if seqpacket.group("first") == seqpacket.group("second"):
                raise BundleError(f"AF_UNIX seqpacket pair inodes repeat at line {number}")
            key = (seqpacket.group("pid"), seqpacket.group("first"))
            if key in pending_seqpacket:
                raise BundleError(f"duplicate pending AF_UNIX seqpacket at line {number}")
            pending_seqpacket[key] = seqpacket.group("second")
            seqpacket_count += 1
            counts["af_unix_socketpair"] += 1
            counts["calls"] += 1
            continue
        received = UNIX_RECVFROM.fullmatch(line)
        if received is not None:
            key = (received.group("pid"), received.group("inode"))
            if key not in pending_seqpacket:
                raise BundleError(
                    f"AF_UNIX recvfrom lacks its exact prior seqpacket endpoint at line {number}"
                )
            del pending_seqpacket[key]
            counts["unix_recvfrom"] += 1
            counts["calls"] += 1
            continue
        raise BundleError(f"network trace line {number} is not an exact allowlisted form: {line!r}")
    if pending_seqpacket:
        raise BundleError("AF_UNIX seqpacket endpoints lack exact successful recvfrom completion")
    if stream_count != EXPECTED_STREAM_SOCKETPAIR_COUNT:
        raise BundleError(
            "AF_UNIX stream socketpair count differs: "
            f"expected {EXPECTED_STREAM_SOCKETPAIR_COUNT}, got {stream_count}"
        )
    if seqpacket_count != EXPECTED_SEQPACKET_SOCKETPAIR_COUNT:
        raise BundleError(
            "AF_UNIX seqpacket socketpair count differs: "
            f"expected {EXPECTED_SEQPACKET_SOCKETPAIR_COUNT}, got {seqpacket_count}"
        )
    if counts["calls"] != EXPECTED_NETWORK_CALL_COUNT:
        raise BundleError("parsed network call count differs from the exact trace length")
    return counts


def _real_directory(path: Path, context: str) -> None:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BundleError(f"{context} must be a real directory: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument("--materialized", required=True, type=Path)
    parser.add_argument("--toolchain-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        os.umask(0o077)
        manifest = load_manifest(args.manifest)
        compare_manifest_to_lock(manifest, args.lock)
        verify_bundle(manifest, args.archives)
        materialized = args.materialized
        _real_directory(materialized, "materialized root")
        cargo_home = materialized / "cargo-home"
        vendor = materialized / "vendor"
        subject = materialized / "subject"
        config = materialized / "cargo-config.toml"
        record_path = materialized / "materialization.json"
        _real_directory(cargo_home, "empty CARGO_HOME")
        if any(cargo_home.iterdir()):
            raise BundleError("CARGO_HOME must be empty before replay")
        _real_directory(vendor, "materialized vendor")
        _real_directory(subject, "materialized subject")
        _regular_unlinked_file(config, "Cargo source configuration")
        expected_entries = {
            "cargo-config.toml",
            "cargo-home",
            "materialization.json",
            "subject",
            "vendor",
        }
        actual_entries = {entry.name for entry in os.scandir(materialized)}
        if actual_entries != expected_entries:
            raise BundleError(
                "materialized entries differ before replay: "
                f"missing={sorted(expected_entries - actual_entries)!r} "
                f"extra={sorted(actual_entries - expected_entries)!r}"
            )
        subject_inputs_path = args.manifest.parent / "subject-inputs.json"
        subject_inputs = load_subject_inputs(subject_inputs_path)
        subject_raw = subject_inputs_path.read_bytes()
        if manifest["subject"]["inputs"] != {
            "file_count": subject_inputs["file_count"],
            "path": "verification/oracle-provisioning/subject-inputs.json",
            "sha256": hashlib.sha256(subject_raw).hexdigest(),
        }:
            raise BundleError("normative manifest does not bind exact subject-input bytes")
        if (
            manifest["subject"]["source_commit"] != subject_inputs["source_commit"]
            or manifest["subject"]["source_tree"] != subject_inputs["source_tree"]
        ):
            raise BundleError("normative and materialized subject Git bindings differ")
        verify_subject_snapshot(subject_inputs, subject)
        record = _load_record(record_path)
        expected_record = {
            "cargo_home_initially_empty": True,
            "lockfile_sha256": manifest["workspace"]["lockfile"]["sha256"],
            "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
            "package_count": manifest["package_count"],
            "subject_commit": subject_inputs["source_commit"],
            "subject_inputs_sha256": hashlib.sha256(subject_raw).hexdigest(),
            "subject_tree": subject_inputs["source_tree"],
        }
        if record != expected_record:
            raise BundleError("materialization record differs from current bound inputs")
        if config.read_text(encoding="utf-8") != cargo_config(Path("/provision/vendor")):
            raise BundleError("Cargo source configuration differs from the virtual fail-closed template")
        verify_vendor(manifest, args.archives, vendor)

        bubblewrap = shutil.which("bwrap")
        strace = shutil.which("strace")
        if not bubblewrap or not strace:
            raise BundleError("replay requires external-unprovisioned bubblewrap and strace")
        toolchain = args.toolchain_root.resolve()
        _real_directory(toolchain, "Rust toolchain root")
        if toolchain.name != manifest["environment"]["toolchain"]["requested"]:
            raise BundleError("Rust toolchain directory name differs from the normative request")
        for relative in ("bin/cargo", "bin/rustc", "bin/rustdoc"):
            tool = toolchain / relative
            _regular_unlinked_file(tool, "Rust toolchain executable")
            if not os.access(tool, os.X_OK):
                raise BundleError(f"Rust toolchain executable lacks execute permission: {tool}")
        runner_root = Path(__file__).resolve().parent
        _real_directory(runner_root, "oracle provisioning runner root")
        target = materialized / "target"
        trace = materialized / "network.trace"
        if target.exists() or target.is_symlink() or trace.exists() or trace.is_symlink():
            raise BundleError("target and external network trace must not preexist")
        target.mkdir(mode=0o700)
        target.chmod(0o700)

        sandbox = [
            bubblewrap,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--dir",
            "/etc",
            "--ro-bind",
            "/etc/ld.so.cache",
            "/etc/ld.so.cache",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/run",
            "--dir",
            "/var",
            "--dir",
            "/var/run",
            "--dir",
            "/nonexistent",
            "--ro-bind",
            str(toolchain),
            "/toolchain",
            "--ro-bind",
            str(subject),
            "/subject",
            "--ro-bind",
            str(runner_root),
            "/runner",
            "--dir",
            "/provision",
            "--ro-bind",
            str(vendor),
            "/provision/vendor",
            "--ro-bind",
            str(config),
            "/provision/cargo-config.toml",
            "--ro-bind",
            str(args.manifest.resolve()),
            "/provision/manifest.json",
            "--bind",
            str(cargo_home),
            "/cargo",
            "--bind",
            str(target),
            "/output",
            "--chdir",
            "/subject/verification",
            "--setenv",
            "HOME",
            "/nonexistent",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--setenv",
            "PATH",
            "/toolchain/bin:/usr/bin",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--setenv",
            "TZ",
            "UTC",
            "--",
            "/usr/bin/python3",
            "-B",
            "/runner/run-targets.py",
            "--normative-manifest",
            "/provision/manifest.json",
            "--cargo-home",
            "/cargo",
            "--cargo-config",
            "/provision/cargo-config.toml",
            "--target-dir",
            "/output",
            "--toolchain-root",
            "/toolchain",
            "--verification-manifest",
            "/subject/verification/Cargo.toml",
        ]
        command = [
            strace,
            "-f",
            "-qq",
            "-yy",
            "-s",
            "256",
            "-e",
            "trace=%network",
            "-e",
            "signal=none",
            "-o",
            str(trace),
            *sandbox,
        ]
        print("exec:", " ".join(command), file=sys.stderr)
        completed = subprocess.run(
            command,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        trace_counts = verify_network_trace(trace)
        if completed.returncode != 0:
            raise BundleError(f"exact-target runner failed with exit status {completed.returncode}")
        verify_subject_snapshot(subject_inputs, subject)
        verify_vendor(manifest, args.archives, vendor)
        print(
            "offline replay passed under --unshare-all with no host root, /tmp, /run, "
            f"or /var/run mount; allowlisted network calls={trace_counts['calls']} "
            f"AF_UNIX socketpairs={trace_counts['af_unix_socketpair']}; "
            "oracle lineage remains blocked"
        )
        return 0
    except (BundleError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
