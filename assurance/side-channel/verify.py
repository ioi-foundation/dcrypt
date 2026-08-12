#!/usr/bin/env python3
"""Fail-closed Package D structural and release verification."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from generate import expected_outputs
from model import (
    FRAMEWORK,
    PackageDError,
    artifact_source_files,
    build_evidence_schema,
    parse_json,
    read_regular,
    sha256_bytes,
    validate_package_document,
)


EXPECTED_FILES = tuple(
    sorted((*artifact_source_files(), "ARTIFACTS.json", "package-d.json", "schema.json"))
)


def _actual_files() -> tuple[str, ...]:
    files: list[str] = []
    for root, directories, names in os.walk(FRAMEWORK, topdown=True, followlinks=False):
        directories.sort()
        names.sort()
        for directory in directories:
            path = Path(root) / directory
            if path.is_symlink() or directory == "__pycache__":
                raise PackageDError(f"Package D contains a forbidden directory: {path}")
        for name in names:
            path = Path(root) / name
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o7000
                or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o640, 0o644, 0o660, 0o664}
                or name.endswith(".pyc")
            ):
                raise PackageDError(f"Package D member is not a safe nonexecutable regular file: {path}")
            files.append(path.relative_to(FRAMEWORK).as_posix())
    return tuple(sorted(files))


def _validate_artifacts(document: Any, expected: dict[str, bytes]) -> None:
    if not isinstance(document, dict) or set(document) != {
        "content_policy", "files", "release_gate", "schema_version", "status"
    }:
        raise PackageDError("Package D artifact manifest root closure differs")
    if (
        document["content_policy"] != "dcrypt-package-d-artifact-closure-v1"
        or document["schema_version"] != 1
        or document["status"] != "HOLD-structural-foundation-only"
        or document["release_gate"] != {"exit_code": 3, "status": "HOLD"}
        or not isinstance(document["files"], list)
        or len(document["files"]) != 11
    ):
        raise PackageDError("Package D artifact manifest identity differs")
    expected_paths = sorted(set(EXPECTED_FILES) - {"ARTIFACTS.json"})
    if [row.get("path") for row in document["files"]] != expected_paths:
        raise PackageDError("Package D artifact manifest path closure differs")
    for row in document["files"]:
        if set(row) != {"git_mode", "kind", "path", "sha256", "size"}:
            raise PackageDError("Package D artifact row closure differs")
        path = row["path"]
        raw, _metadata = read_regular(FRAMEWORK / path, label=f"sealed Package D member {path}")
        expected_kind = "generated" if path in {"package-d.json", "schema.json"} else "reviewed-source"
        if (
            row["git_mode"] != "100644"
            or row["kind"] != expected_kind
            or row["sha256"] != sha256_bytes(raw)
            or row["size"] != len(raw)
        ):
            raise PackageDError(f"Package D artifact row differs: {path}")
        if path in expected and raw != expected[path]:
            raise PackageDError(f"Package D generated member differs: {path}")


def validate_artifact_document(document: Any) -> None:
    """Validate a synthetic artifact manifest against the live exact closure."""

    _validate_artifacts(document, expected_outputs())


def verify_structural() -> dict[str, Any]:
    if _actual_files() != EXPECTED_FILES:
        raise PackageDError(
            f"Package D directory closure differs: expected={list(EXPECTED_FILES)} actual={list(_actual_files())}"
        )
    expected = expected_outputs()
    for relative, raw in expected.items():
        actual, _metadata = read_regular(
            FRAMEWORK / relative, label=f"Package D generated artifact {relative}"
        )
        if actual != raw:
            raise PackageDError(f"Package D generated artifact differs: {relative}")
    package_raw, _metadata = read_regular(FRAMEWORK / "package-d.json", label="Package D baseline")
    package = parse_json(package_raw, label="Package D baseline", require_canonical=True)
    if not isinstance(package, dict):
        raise PackageDError("Package D baseline is not an object")
    validate_package_document(package)
    schema_raw, _metadata = read_regular(FRAMEWORK / "schema.json", label="Package D evidence schema")
    schema = parse_json(schema_raw, label="Package D evidence schema", require_canonical=True)
    if schema != build_evidence_schema():
        raise PackageDError("Package D evidence schema differs from reviewed semantics")
    artifacts_raw, _metadata = read_regular(FRAMEWORK / "ARTIFACTS.json", label="Package D artifact manifest")
    artifacts = parse_json(artifacts_raw, label="Package D artifact manifest", require_canonical=True)
    _validate_artifacts(artifacts, expected)
    counts = package["counts"]
    return {
        "atomic_rows": counts["total_atomic_rows"],
        "compiler_controls": counts["compiler_controls"],
        "dedicated_timing_runs": counts["dedicated_timing_runs"],
        "local_timing_controls": counts["local_timing_controls"],
        "physical_profiles": counts["accepted_physical_profiles"],
        "production_source_files": counts["production_source_files"],
        "release_blocked_rows": counts["release_blocked_rows"],
        "release_gate": "HOLD",
        "secret_taint_runs": counts["secret_taint_runs"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ci", action="store_true")
    mode.add_argument("--release", action="store_true")
    args = parser.parse_args()
    try:
        result = verify_structural()
        if args.release:
            print(
                "Package D release HOLD: all 9,298 rows remain blocked; dedicated timing, "
                "taint, transitive compiler/secret-flow, platform, physical, and external-audit "
                "evidence are not accepted",
                file=sys.stderr,
            )
            return 3
        print(
            "Package D structural verification passed: "
            f"rows={result['atomic_rows']} sources={result['production_source_files']} "
            f"timing={result['local_timing_controls']} compiler={result['compiler_controls']} "
            "operational-promotions=0 release=HOLD"
        )
        return 0
    except (OSError, PackageDError, UnicodeError, ValueError) as error:
        print(f"Package D verification HOLD: {error}", file=sys.stderr)
        return 3 if args.release else 1


if __name__ == "__main__":
    raise SystemExit(main())
