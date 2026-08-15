#!/usr/bin/env python3
"""Build every publishable crate twice and require byte-identical archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGES = (
    "dcrypt-internal", "dcrypt-params", "dcrypt-api", "dcrypt-common",
    "dcrypt-algorithms", "dcrypt-symmetric", "dcrypt-kem", "dcrypt-sign",
    "dcrypt-pke", "dcrypt-utils", "dcrypt-hybrid", "dcrypt",
)


class RebuildError(RuntimeError):
    pass


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def workspace_version() -> str:
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0:
        raise RebuildError("cargo metadata failed")
    metadata = json.loads(result.stdout)
    versions = {row["version"] for row in metadata["packages"] if row["name"] in PACKAGES}
    if len(versions) != 1:
        raise RebuildError(f"publishable package versions differ: {sorted(versions)}")
    return versions.pop()


def build_set(target: pathlib.Path, version: str) -> dict[str, pathlib.Path]:
    environment = os.environ.copy()
    environment.update({
        "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
    })
    command = [
        "cargo", "+1.93.1", "package", "--workspace",
        "--exclude", "dcrypt-tests", "--allow-dirty", "--no-verify",
        "--locked", "--offline", "--target-dir", str(target),
    ]
    result = subprocess.run(
        command, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    if result.returncode != 0:
        sys.stderr.buffer.write(result.stdout[-16384:])
        raise RebuildError("cargo workspace package failed")
    archives = {}
    for package in PACKAGES:
        path = target / "package" / f"{package}-{version}.crate"
        if not path.is_file() or path.is_symlink():
            raise RebuildError(f"package archive is absent: {path.name}")
        archives[package] = path
    observed = {path.name for path in (target / "package").glob("*.crate")}
    expected = {path.name for path in archives.values()}
    if observed != expected:
        raise RebuildError(f"package archive closure differs: {sorted(observed ^ expected)}")
    return archives


def verify(output: pathlib.Path) -> dict:
    version = workspace_version()
    with tempfile.TemporaryDirectory(prefix="dcrypt-rebuild-a-") as first_name, tempfile.TemporaryDirectory(prefix="dcrypt-rebuild-b-") as second_name:
        first = build_set(pathlib.Path(first_name), version)
        second = build_set(pathlib.Path(second_name), version)
        rows = []
        output.mkdir(parents=True, exist_ok=True)
        expected_names = {f"{package}-{version}.crate" for package in PACKAGES} | {"manifest.json"}
        unexpected = {path.name for path in output.iterdir() if path.is_file()} - expected_names
        if unexpected:
            raise RebuildError(f"unexpected output members: {sorted(unexpected)}")
        for package in PACKAGES:
            first_hash = sha256(first[package])
            second_hash = sha256(second[package])
            if first_hash != second_hash or first[package].stat().st_size != second[package].stat().st_size:
                raise RebuildError(f"repeat package bytes differ for {package}@{version}")
            destination = output / f"{package}-{version}.crate"
            shutil.copyfile(first[package], destination)
            rows.append({
                "byte_equal": True,
                "name": package,
                "sha256": first_hash,
                "size": destination.stat().st_size,
                "version": version,
            })
        manifest = {
            "classification": "two-clean-target-first-party-repeatable-package-proof",
            "content_policy": "dcrypt-repeatable-packages-v1",
            "independent_producer_claimed": False,
            "packages": rows,
            "passed": True,
            "schema_version": 1,
            "toolchain": subprocess.run(
                ["rustc", "+1.93.1", "--version", "--verbose"], cwd=ROOT,
                text=True, stdout=subprocess.PIPE, check=True,
            ).stdout.strip().splitlines(),
        }
        (output / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return manifest


def check(output: pathlib.Path) -> dict:
    manifest_path = output / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if set(data) != {"classification", "content_policy", "independent_producer_claimed", "packages", "passed", "schema_version", "toolchain"}:
        raise RebuildError("repeat-package manifest closure differs")
    if data["content_policy"] != "dcrypt-repeatable-packages-v1" or data["passed"] is not True:
        raise RebuildError("repeat-package manifest identity differs")
    if data["independent_producer_claimed"] is not False or len(data["packages"]) != 12:
        raise RebuildError("repeat-package evidence claim/count differs")
    if [row["name"] for row in data["packages"]] != list(PACKAGES):
        raise RebuildError("repeat-package order differs")
    for row in data["packages"]:
        archive = output / f"{row['name']}-{row['version']}.crate"
        if row.get("byte_equal") is not True or sha256(archive) != row.get("sha256") or archive.stat().st_size != row.get("size"):
            raise RebuildError(f"repeat-package artifact differs for {row.get('name')}")
    return data


def self_test() -> None:
    if len(PACKAGES) != 12 or PACKAGES[-1] != "dcrypt":
        raise AssertionError("publishable package closure differs")
    if len(set(PACKAGES)) != len(PACKAGES):
        raise AssertionError("publishable package closure has duplicates")


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--run", action="store_true")
    action.add_argument("--check", action="store_true")
    action.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("repeatable package self-test passed")
            return 0
        if args.output is None:
            parser.error("--run/--check requires --output")
        if args.run:
            data = verify(args.output)
            print(f"repeatable package proof passed: packages={len(data['packages'])} output={args.output}")
        else:
            data = check(args.output)
            print(f"repeatable package artifacts verified: packages={len(data['packages'])}")
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RebuildError, subprocess.SubprocessError) as error:
        print(f"repeatable package verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
