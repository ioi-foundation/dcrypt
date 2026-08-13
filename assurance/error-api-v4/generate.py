#!/usr/bin/env python3
"""Generate canonical Package E structural assurance artifacts."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

from model import (
    FRAMEWORK,
    PackageEError,
    artifact_source_files,
    build_package_document,
    build_schema,
    canonical_json,
    read_regular_once,
    sha256_bytes,
)


def expected_outputs() -> dict[str, bytes]:
    outputs = {
        "package-e.json": canonical_json(build_package_document()),
        "schema.json": canonical_json(build_schema()),
    }
    records: list[dict[str, object]] = []
    for relative in artifact_source_files():
        raw, _metadata = read_regular_once(
            FRAMEWORK / relative, label=f"Package E reviewed source {relative}"
        )
        records.append(
            {
                "git_mode": "100644",
                "kind": "reviewed-source",
                "path": relative,
                "sha256": sha256_bytes(raw),
                "size": len(raw),
            }
        )
    for relative, raw in sorted(outputs.items()):
        records.append(
            {
                "git_mode": "100644",
                "kind": "generated",
                "path": relative,
                "sha256": sha256_bytes(raw),
                "size": len(raw),
            }
        )
    records.sort(key=lambda row: str(row["path"]))
    if len(records) != 11 or len({row["path"] for row in records}) != 11:
        raise PackageEError("Package E artifact closure must contain eleven non-self rows")
    outputs["ARTIFACTS.json"] = canonical_json(
        {
            "content_policy": "dcrypt-package-e-artifact-closure-v1",
            "files": records,
            "promotion_effect": "none",
            "release_gate": {"exit_code": 3, "status": "HOLD"},
            "schema_version": 1,
            "status": "local-breaking-removal-complete",
        }
    )
    return outputs


def _atomic_write(path: Path, raw: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            view = memoryview(raw)
            while view:
                written = stream.write(view)
                if written is None or written <= 0:
                    raise PackageEError(f"short write for generated artifact {path.name}")
                view = view[written:]
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
            for relative, expected in sorted(outputs.items()):
                try:
                    actual, _metadata = read_regular_once(
                        FRAMEWORK / relative,
                        label=f"Package E generated artifact {relative}",
                    )
                except PackageEError:
                    differences.append(relative)
                    continue
                if actual != expected:
                    differences.append(relative)
            if differences:
                raise PackageEError(f"generated Package E artifacts differ: {differences}")
            print(f"Package E generation check passed: {len(outputs)} artifacts")
        else:
            for relative, raw in sorted(outputs.items()):
                _atomic_write(FRAMEWORK / relative, raw)
            print(f"generated {len(outputs)} canonical Package E artifacts")
        return 0
    except (OSError, PackageEError, UnicodeError, ValueError) as error:
        print(f"Package E generation HOLD: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
