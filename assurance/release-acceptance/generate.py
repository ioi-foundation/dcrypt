#!/usr/bin/env python3
"""Generate canonical Package G structural foundation artifacts."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

from model import (
    FRAMEWORK, REPO, PackageGError, artifact_source_files, build_package_document,
    build_schema, canonical_json, read_regular_once, sha256_bytes,
)


def expected_outputs() -> dict[str, bytes]:
    outputs = {
        "package-g.json": canonical_json(build_package_document()),
        "schema.json": canonical_json(build_schema()),
    }
    rows: list[dict[str, object]] = []
    for relative, git_mode, kind in artifact_source_files():
        if relative == "assurance/release-acceptance/package-g.json":
            raw = outputs["package-g.json"]
        elif relative == "assurance/release-acceptance/schema.json":
            raw = outputs["schema.json"]
        else:
            raw, _metadata = read_regular_once(REPO / relative, label=f"Package G authorized member {relative}")
        rows.append({
            "git_mode": git_mode, "kind": kind, "path": relative,
            "sha256": sha256_bytes(raw), "size": len(raw),
        })
    if len(rows) != 13 or len({row["path"] for row in rows}) != 13:
        raise PackageGError("Package G artifact closure must contain thirteen non-self rows")
    outputs["ARTIFACTS.json"] = canonical_json({
        "content_policy": "dcrypt-package-g-artifact-closure-v1",
        "files": rows,
        "promotion_effect": "none",
        "release_gate": {"exit_code": 3, "status": "HOLD"},
        "schema_version": 1,
        "status": "pre-version-foundation-active-consumer-wiring",
    })
    return outputs


def _atomic_write(path: Path, raw: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        outputs = expected_outputs()
        if args.check:
            differences: list[str] = []
            for relative, expected in outputs.items():
                try:
                    actual, _metadata = read_regular_once(FRAMEWORK / relative, label=f"Package G output {relative}")
                except (OSError, PackageGError):
                    differences.append(relative)
                    continue
                if actual != expected:
                    differences.append(relative)
            if differences:
                raise PackageGError(f"generated Package G artifacts differ: {differences}")
            print(f"Package G generation check passed: {len(outputs)} artifacts")
        else:
            for relative, raw in outputs.items():
                _atomic_write(FRAMEWORK / relative, raw)
            print(f"generated {len(outputs)} canonical Package G artifacts")
        return 0
    except (OSError, PackageGError, UnicodeError, ValueError) as error:
        print(f"Package G generation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
