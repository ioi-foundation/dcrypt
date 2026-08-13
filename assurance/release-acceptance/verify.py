#!/usr/bin/env python3
"""Fail-closed Package G structural and phased release verification."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import stat
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from generate import expected_outputs
from model import (
    FRAMEWORK, REPO, PackageGBlocker, PackageGError, artifact_source_files,
    build_package_document, build_schema, evaluate_foundation_temporal_state, foundation_record,
    identical, parse_json_strict, read_regular_once, sha256_bytes, verify_immutable_projection,
    verify_current_topology_scope,
)

G_FILES = {
    "ARTIFACTS.json", "README.md", "fixtures/control.json", "generate.py", "model.py",
    "package-g.json", "policy.toml", "schema.json", "selftest.py", "verify.py",
}


def _actual_g_files() -> set[str]:
    files: set[str] = set()
    for root, directories, names in os.walk(FRAMEWORK, topdown=True, followlinks=False):
        directories.sort()
        names.sort()
        for directory in list(directories):
            path = Path(root) / directory
            if path.is_symlink() or directory == "__pycache__" or directory not in {"fixtures"}:
                raise PackageGError(f"Package G contains forbidden directory: {path}")
        for name in names:
            path = Path(root) / name
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1 or metadata.st_mode & 0o7000
                or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o640, 0o644, 0o660, 0o664}
                or name.endswith(".pyc")
            ):
                raise PackageGError(f"Package G member does not map to Git mode 100644: {path}")
            files.add(path.relative_to(FRAMEWORK).as_posix())
    return files


def _validate_artifacts(document: Any, expected: dict[str, bytes]) -> None:
    if not isinstance(document, dict) or set(document) != {
        "content_policy", "files", "promotion_effect", "release_gate", "schema_version", "status",
    }:
        raise PackageGError("Package G artifact manifest root closure differs")
    if not identical(document, {
        "content_policy": "dcrypt-package-g-artifact-closure-v1",
        "files": document["files"], "promotion_effect": "none",
        "release_gate": {"exit_code": 3, "status": "HOLD"}, "schema_version": 1,
        "status": "pre-version-foundation-active-consumer-wiring",
    }):
        raise PackageGError("Package G artifact manifest identity differs")
    rows = document["files"]
    sources = artifact_source_files()
    if not isinstance(rows, list) or len(rows) != 13 or [row.get("path") for row in rows] != [row[0] for row in sources]:
        raise PackageGError("Package G artifact path closure differs")
    for row, (relative, git_mode, kind) in zip(rows, sources, strict=True):
        if not isinstance(row, dict) or set(row) != {"git_mode", "kind", "path", "sha256", "size"}:
            raise PackageGError(f"Package G artifact row closure differs: {relative}")
        if relative.endswith("package-g.json"):
            raw = expected["package-g.json"]
        elif relative.endswith("schema.json"):
            raw = expected["schema.json"]
        else:
            raw, _metadata = read_regular_once(REPO / relative, label=f"Package G authorized member {relative}")
        if not identical(row, {
            "git_mode": git_mode, "kind": kind, "path": relative,
            "sha256": sha256_bytes(raw), "size": len(raw),
        }):
            raise PackageGError(f"Package G artifact row differs: {relative}")


def verify_structural(evaluation_date: dt.date | None = None) -> dict[str, Any]:
    if _actual_g_files() != G_FILES:
        raise PackageGError("Package G directory closure differs")
    expected = expected_outputs()
    for relative, raw in expected.items():
        observed, _metadata = read_regular_once(FRAMEWORK / relative, label=f"Package G generated output {relative}")
        if observed != raw:
            raise PackageGError(f"Package G generated artifact differs: {relative}")
    package_raw, _metadata = read_regular_once(FRAMEWORK / "package-g.json", label="Package G document")
    package = parse_json_strict(package_raw, label="Package G document", require_canonical=True)
    if not identical(package, build_package_document()):
        raise PackageGError("Package G document differs")
    schema_raw, _metadata = read_regular_once(FRAMEWORK / "schema.json", label="Package G schema")
    schema = parse_json_strict(schema_raw, label="Package G schema", require_canonical=True)
    if not identical(schema, build_schema()):
        raise PackageGError("Package G schema differs")
    artifacts_raw, _metadata = read_regular_once(FRAMEWORK / "ARTIFACTS.json", label="Package G artifact manifest")
    artifacts = parse_json_strict(artifacts_raw, label="Package G artifact manifest", require_canonical=True)
    _validate_artifacts(artifacts, expected)
    projection = verify_immutable_projection()
    topology_state = verify_current_topology_scope()
    temporal_state = evaluate_foundation_temporal_state(evaluation_date)
    return {
        "projection": projection, "record": foundation_record(),
        "temporal_state": temporal_state, "topology_state": topology_state,
    }


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ci", action="store_true")
    mode.add_argument("--release", action="store_true")
    parser.add_argument("--phase", required=True, choices=("foundation", "prepublish", "postpublish"))
    args = parser.parse_args()
    if args.ci and args.phase != "foundation":
        parser.error("--ci requires --phase foundation")
    try:
        result = verify_structural()
        if args.ci:
            print(
                "Package G structural verification passed: "
                f"A_F={result['projection']['commit']} antecedents={len(result['projection']['antecedents'])} "
                f"topology={result['topology_state']} "
                f"temporal_blockers={','.join(result['temporal_state']['blocker_ids'])} release=HOLD"
            )
            return 0
        print(
            f"Package G release HOLD: phase={args.phase} acceptance disabled; "
            "operational evidence remains unaccepted; "
            f"temporal_blockers={','.join(result['temporal_state']['blocker_ids'])}",
            file=sys.stderr,
        )
        return 3
    except PackageGBlocker as error:
        print(f"Package G release HOLD: {error}", file=sys.stderr)
        return 3
    except (OSError, PackageGError, UnicodeError, ValueError) as error:
        print(f"Package G verification invalid: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
