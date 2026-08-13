#!/usr/bin/env python3
"""Fail-closed Package F structural and release verification."""

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
    FRAMEWORK, PackageFError, artifact_source_files, build_package_document,
    build_schema, parse_json_strict, read_regular_once, sha256_bytes,
    validate_package_document,
)

EXPECTED_FILES = tuple(sorted((*artifact_source_files(), "ARTIFACTS.json", "package-f.json", "schema.json")))


def _actual_files() -> tuple[str, ...]:
    files: list[str] = []
    for root, directories, names in os.walk(FRAMEWORK, topdown=True, followlinks=False):
        directories.sort()
        names.sort()
        for directory in directories:
            path = Path(root) / directory
            if path.is_symlink() or directory == "__pycache__" or directory not in {"fixtures"}:
                raise PackageFError(f"Package F contains a forbidden directory: {path}")
        for name in names:
            path = Path(root) / name
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1 or metadata.st_mode & 0o7000
                or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o640, 0o644, 0o660, 0o664}
                or name.endswith(".pyc")
            ):
                raise PackageFError(f"Package F member does not map to Git mode 100644: {path}")
            files.append(path.relative_to(FRAMEWORK).as_posix())
    return tuple(sorted(files))


def _validate_artifacts(document: Any, expected: dict[str, bytes]) -> None:
    if not isinstance(document, dict) or set(document) != {
        "content_policy", "files", "promotion_effect", "release_gate", "schema_version", "status",
    }:
        raise PackageFError("Package F artifact manifest root closure differs")
    if (
        document["content_policy"] != "dcrypt-package-f-artifact-closure-v1"
        or document["schema_version"] != 1
        or document["status"] != "local-foundation-complete-operational-evidence-absent"
        or document["promotion_effect"] != "none"
        or document["release_gate"] != {"exit_code": 3, "status": "HOLD"}
        or not isinstance(document["files"], list) or len(document["files"]) != 11
    ):
        raise PackageFError("Package F artifact manifest identity differs")
    expected_paths = sorted(set(EXPECTED_FILES) - {"ARTIFACTS.json"})
    if [row.get("path") for row in document["files"]] != expected_paths:
        raise PackageFError("Package F artifact path closure differs")
    for row in document["files"]:
        if set(row) != {"git_mode", "kind", "path", "sha256", "size"}:
            raise PackageFError("Package F artifact row closure differs")
        relative = row["path"]
        raw, _metadata = read_regular_once(FRAMEWORK / relative, label=f"sealed Package F member {relative}")
        expected_kind = "generated" if relative in {"package-f.json", "schema.json"} else "reviewed-source"
        if (
            row["git_mode"] != "100644" or row["kind"] != expected_kind
            or row["sha256"] != sha256_bytes(raw) or row["size"] != len(raw)
            or (relative in expected and raw != expected[relative])
        ):
            raise PackageFError(f"Package F artifact row differs: {relative}")


def verify_structural() -> dict[str, Any]:
    actual = _actual_files()
    if actual != EXPECTED_FILES:
        raise PackageFError(f"Package F directory closure differs: expected={list(EXPECTED_FILES)} actual={list(actual)}")
    expected = expected_outputs()
    for relative, raw in expected.items():
        observed, _metadata = read_regular_once(FRAMEWORK / relative, label=f"Package F output {relative}")
        if observed != raw:
            raise PackageFError(f"Package F generated artifact differs: {relative}")
    package_raw, _metadata = read_regular_once(FRAMEWORK / "package-f.json", label="Package F document")
    package = parse_json_strict(package_raw, label="Package F document", require_canonical=True)
    validate_package_document(package)
    if package != build_package_document():
        raise PackageFError("Package F document differs from reviewed semantics")
    schema_raw, _metadata = read_regular_once(FRAMEWORK / "schema.json", label="Package F schema")
    schema = parse_json_strict(schema_raw, label="Package F schema", require_canonical=True)
    if schema != build_schema():
        raise PackageFError("Package F schema differs from reviewed roles")
    artifacts_raw, _metadata = read_regular_once(FRAMEWORK / "ARTIFACTS.json", label="Package F artifact manifest")
    artifacts = parse_json_strict(artifacts_raw, label="Package F artifact manifest", require_canonical=True)
    _validate_artifacts(artifacts, expected)
    return {
        "locks": package["counts"]["tracked_lockfiles"],
        "occurrences": package["counts"]["lock_package_occurrences"],
        "subjects": package["counts"]["artifact_subjects"], "release_gate": "HOLD",
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
                "Package F release HOLD: operational SBOM, signature, independent rebuild, environment, and archive evidence remain unaccepted",
                file=sys.stderr,
            )
            return 3
        print(
            "Package F structural verification passed: "
            f"locks={result['locks']} occurrences={result['occurrences']} "
            f"subjects={result['subjects']} release=HOLD"
        )
        return 0
    except (OSError, PackageFError, UnicodeError, ValueError) as error:
        print(f"Package F verification HOLD: {error}", file=sys.stderr)
        return 3 if args.release else 1


if __name__ == "__main__":
    raise SystemExit(main())
