#!/usr/bin/env python3
"""Fail-closed Package E structural and release verification."""

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
    PackageEError,
    artifact_source_files,
    build_package_document,
    build_schema,
    parse_json_strict,
    read_regular_once,
    sha256_bytes,
    validate_package_document,
)

EXPECTED_FILES = tuple(
    sorted((*artifact_source_files(), "ARTIFACTS.json", "package-e.json", "schema.json"))
)


def _actual_files() -> tuple[str, ...]:
    files: list[str] = []
    for root, directories, names in os.walk(FRAMEWORK, topdown=True, followlinks=False):
        directories.sort()
        names.sort()
        for directory in directories:
            path = Path(root) / directory
            if path.is_symlink() or directory == "__pycache__" or directory not in {"fixtures"}:
                raise PackageEError(f"Package E contains a forbidden directory: {path}")
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
                raise PackageEError(f"Package E member does not map to Git mode 100644: {path}")
            files.append(path.relative_to(FRAMEWORK).as_posix())
    return tuple(sorted(files))


def _validate_artifacts(document: Any, expected: dict[str, bytes]) -> None:
    if not isinstance(document, dict) or set(document) != {
        "content_policy", "files", "promotion_effect", "release_gate",
        "schema_version", "status",
    }:
        raise PackageEError("Package E artifact manifest root closure differs")
    if (
        document["content_policy"] != "dcrypt-package-e-artifact-closure-v1"
        or document["schema_version"] != 1
        or document["status"] != "local-breaking-removal-complete"
        or document["promotion_effect"] != "none"
        or document["release_gate"] != {"exit_code": 3, "status": "HOLD"}
        or not isinstance(document["files"], list)
        or len(document["files"]) != 11
    ):
        raise PackageEError("Package E artifact manifest identity differs")
    expected_paths = sorted(set(EXPECTED_FILES) - {"ARTIFACTS.json"})
    if [row.get("path") for row in document["files"]] != expected_paths:
        raise PackageEError("Package E artifact manifest path closure differs")
    for row in document["files"]:
        if set(row) != {"git_mode", "kind", "path", "sha256", "size"}:
            raise PackageEError("Package E artifact row closure differs")
        relative = row["path"]
        raw, _metadata = read_regular_once(
            FRAMEWORK / relative, label=f"sealed Package E member {relative}"
        )
        expected_kind = "generated" if relative in {"package-e.json", "schema.json"} else "reviewed-source"
        if (
            row["git_mode"] != "100644"
            or row["kind"] != expected_kind
            or row["sha256"] != sha256_bytes(raw)
            or row["size"] != len(raw)
            or (relative in expected and raw != expected[relative])
        ):
            raise PackageEError(f"Package E artifact row differs: {relative}")


def validate_artifact_document(document: Any) -> None:
    _validate_artifacts(document, expected_outputs())


def verify_structural() -> dict[str, Any]:
    actual = _actual_files()
    if actual != EXPECTED_FILES:
        raise PackageEError(
            f"Package E directory closure differs: expected={list(EXPECTED_FILES)} actual={list(actual)}"
        )
    expected = expected_outputs()
    for relative, raw in expected.items():
        actual_raw, _metadata = read_regular_once(
            FRAMEWORK / relative, label=f"Package E generated artifact {relative}"
        )
        if actual_raw != raw:
            raise PackageEError(f"Package E generated artifact differs: {relative}")
    package_raw, _metadata = read_regular_once(
        FRAMEWORK / "package-e.json", label="Package E document"
    )
    package = parse_json_strict(package_raw, label="Package E document", require_canonical=True)
    validate_package_document(package)
    if package != build_package_document():
        raise PackageEError("Package E document differs from reviewed semantics")
    schema_raw, _metadata = read_regular_once(FRAMEWORK / "schema.json", label="Package E schema")
    schema = parse_json_strict(schema_raw, label="Package E schema", require_canonical=True)
    if schema != build_schema():
        raise PackageEError("Package E schema differs from closed reviewed semantics")
    artifacts_raw, _metadata = read_regular_once(
        FRAMEWORK / "ARTIFACTS.json", label="Package E artifact manifest"
    )
    artifacts = parse_json_strict(
        artifacts_raw, label="Package E artifact manifest", require_canonical=True
    )
    _validate_artifacts(artifacts, expected)
    return {
        "atomic_rows": package["counts"]["expanded_curated_atomic_rows"]
        + package["counts"]["unreviewed_gap_rows"],
        "public_identities": package["counts"]["public_identities"],
        "removed_public_identities": package["public_removal"]["removed_public_identities"],
        "release_gate": "HOLD",
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
                "Package E release HOLD: v4 version preparation and publication remain unauthorized",
                file=sys.stderr,
            )
            return 3
        print(
            "Package E structural verification passed: "
            f"rows={result['atomic_rows']} public={result['public_identities']} "
            f"removed={result['removed_public_identities']} release=HOLD"
        )
        return 0
    except (OSError, PackageEError, UnicodeError, ValueError) as error:
        print(f"Package E verification HOLD: {error}", file=sys.stderr)
        return 3 if args.release else 1


if __name__ == "__main__":
    raise SystemExit(main())
