#!/usr/bin/env python3
"""Fail closed on exact integration-test identity, then execute every target."""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from bundle_lib import BundleError, load_manifest, sha256_file


RESULT = re.compile(
    r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out"
)


def output_field(output: str, label: str) -> str:
    prefix = f"{label}: "
    matches = [line[len(prefix) :] for line in output.splitlines() if line.startswith(prefix)]
    if len(matches) != 1:
        raise BundleError(f"tool output lacks unique {label!r} field")
    return matches[0]


def run(command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normative-manifest", required=True, type=Path)
    parser.add_argument("--cargo-home", required=True, type=Path)
    parser.add_argument("--cargo-config", required=True, type=Path)
    parser.add_argument("--target-dir", required=True, type=Path)
    parser.add_argument("--toolchain-root", required=True, type=Path)
    parser.add_argument("--verification-manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        if os.environ.get("DCRYPT_ORACLE_CHILD_STDERR_TO_STDOUT") == "1":
            os.dup2(sys.stdout.fileno(), sys.stderr.fileno())
        normative = load_manifest(args.normative_manifest)
        inventory = normative["tests"]
        required_environment = normative["environment"]
        manifest_metadata = args.verification_manifest.lstat()
        if (
            not stat.S_ISREG(manifest_metadata.st_mode)
            or args.verification_manifest.is_symlink()
            or manifest_metadata.st_nlink != 1
        ):
            raise BundleError("verification Cargo.toml must be a regular unlinked file")
        actual_manifest_digest = sha256_file(args.verification_manifest)
        if actual_manifest_digest != normative["workspace"]["manifest"]["sha256"]:
            raise BundleError(
                "verification Cargo.toml digest differs from the normative manifest"
            )
        cargo = args.toolchain_root / "bin/cargo"
        rustc = args.toolchain_root / "bin/rustc"
        rustdoc = args.toolchain_root / "bin/rustdoc"
        for tool in (cargo, rustc, rustdoc):
            if not tool.is_file() or tool.is_symlink():
                raise BundleError(f"toolchain executable is absent or linked: {tool}")
        environment = {
            "CARGO_BUILD_JOBS": "1",
            "CARGO_HOME": str(args.cargo_home),
            "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(args.target_dir),
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": required_environment[
                "cargo_invocation"
            ]["target_linker"],
            "CARGO_TERM_COLOR": "never",
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": f"{args.toolchain_root}/bin:/usr/bin",
            "RUSTC": str(rustc),
            "RUSTDOC": str(rustdoc),
            "TMPDIR": "/tmp",
            "TZ": "UTC",
            "CC": required_environment["cargo_invocation"]["target_linker"],
        }
        cargo_version = run([str(cargo), "-vV"], environment)
        rustc_version = run([str(rustc), "-vV"], environment)
        if cargo_version.returncode != 0 or rustc_version.returncode != 0:
            raise BundleError("cannot identify the pinned Cargo/Rust toolchain")
        expected_toolchain = required_environment["toolchain"]
        if output_field(cargo_version.stdout, "commit-hash") != expected_toolchain["cargo_commit"]:
            raise BundleError("Cargo commit differs from the normative manifest")
        if output_field(rustc_version.stdout, "commit-hash") != expected_toolchain["rustc_commit"]:
            raise BundleError("rustc commit differs from the normative manifest")
        if output_field(cargo_version.stdout, "host") != required_environment["host"]:
            raise BundleError("Cargo host differs from the normative manifest")
        if output_field(rustc_version.stdout, "host") != required_environment["host"]:
            raise BundleError("rustc host differs from the normative manifest")
        if output_field(rustc_version.stdout, "LLVM version") != expected_toolchain["llvm"]:
            raise BundleError("LLVM version differs from the normative manifest")
        print(
            "verified execution toolchain: "
            f"rustc={expected_toolchain['rustc_commit']} "
            f"cargo={expected_toolchain['cargo_commit']} host={required_environment['host']}"
        )
        base = [
            str(cargo),
            "--config",
            str(args.cargo_config),
            "test",
            "--manifest-path",
            str(args.verification_manifest),
            "--release",
            "--locked",
            "--offline",
        ]
        observed: dict[str, list[str]] = {}
        for entry in inventory["targets"]:
            target = entry["target"]
            source = args.verification_manifest.parent / entry["source"]
            source_metadata = source.lstat()
            if not stat.S_ISREG(source_metadata.st_mode) or source.is_symlink():
                raise BundleError(f"test target source is not a regular file: {source}")
            if source_metadata.st_nlink != 1:
                raise BundleError(f"test target source has hard links: {source}")
            actual_source_digest = sha256_file(source)
            if actual_source_digest != entry["source_sha256"]:
                raise BundleError(
                    f"test target source digest differs for {target}: "
                    f"expected {entry['source_sha256']}, got {actual_source_digest}"
                )
            command = [*base, "--test", target, "--", "--list", "--format", "terse"]
            completed = run(command, environment)
            if completed.returncode != 0:
                raise BundleError(
                    f"test listing failed for exact target {target} with status "
                    f"{completed.returncode}:\n{completed.stderr}{completed.stdout}"
                )
            tests: list[str] = []
            rejected: list[str] = []
            for line in completed.stdout.splitlines():
                if line.endswith(": test"):
                    tests.append(line[: -len(": test")])
                elif line.strip():
                    rejected.append(line)
            if rejected:
                raise BundleError(f"unrecognized listing output for {target}: {rejected!r}")
            if tests != sorted(set(tests)):
                raise BundleError(f"Cargo listed duplicate or unsorted tests for {target}")
            expected = entry["expected_tests"]
            if tests != expected:
                raise BundleError(
                    f"test inventory mismatch for {target}: "
                    f"missing={sorted(set(expected) - set(tests))!r} "
                    f"extra={sorted(set(tests) - set(expected))!r}"
                )
            observed[target] = tests
            ignored_command = [
                *base,
                "--test",
                target,
                "--",
                "--list",
                "--ignored",
                "--format",
                "terse",
            ]
            ignored = run(ignored_command, environment)
            if ignored.returncode != 0 or ignored.stdout.strip():
                raise BundleError(
                    f"target {target} has ignored tests or ignored listing failed: "
                    f"status={ignored.returncode} output={ignored.stdout!r}"
                )
        print(
            "verified exact test inventory: "
            + ", ".join(f"{target}={len(tests)}" for target, tests in observed.items())
        )
        for entry in inventory["targets"]:
            target = entry["target"]
            command = [*base, "--test", target, "--", "--format", "terse"]
            print("exec:", " ".join(command), file=sys.stderr)
            completed = run(command, environment)
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            if completed.returncode != 0:
                raise BundleError(
                    f"exact target {target} failed with status {completed.returncode}"
                )
            results = RESULT.findall(completed.stdout)
            expected_count = len(entry["expected_tests"])
            if results != [(str(expected_count), "0", "0", "0", "0")]:
                raise BundleError(
                    f"exact target {target} produced unexpected test result summaries: {results!r}"
                )
        print(
            f"executed {sum(len(tests) for tests in observed.values())} exact tests in "
            f"{len(observed)} exact targets; oracle lineage remains blocked"
        )
        return 0
    except (BundleError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
