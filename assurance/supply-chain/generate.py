#!/usr/bin/env python3
"""Generate canonical Package F structural assurance artifacts."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

from model import (
    FRAMEWORK, PackageFError, artifact_source_files, build_package_document,
    build_schema, canonical_json, read_regular_once, sha256_bytes,
)


def expected_outputs() -> dict[str, bytes]:
    outputs = {
        "package-f.json": canonical_json(build_package_document()),
        "schema.json": canonical_json(build_schema()),
    }
    rows: list[dict[str, object]] = []
    for relative in artifact_source_files():
        raw, _metadata = read_regular_once(
            FRAMEWORK / relative, label=f"Package F reviewed source {relative}"
        )
        rows.append({
            "git_mode": "100644", "kind": "reviewed-source", "path": relative,
            "sha256": sha256_bytes(raw), "size": len(raw),
        })
    for relative, raw in sorted(outputs.items()):
        rows.append({
            "git_mode": "100644", "kind": "generated", "path": relative,
            "sha256": sha256_bytes(raw), "size": len(raw),
        })
    rows.sort(key=lambda row: str(row["path"]))
    if len(rows) != 11 or len({row["path"] for row in rows}) != 11:
        raise PackageFError("Package F artifact closure must contain eleven non-self rows")
    outputs["ARTIFACTS.json"] = canonical_json({
        "content_policy": "dcrypt-package-f-artifact-closure-v1",
        "files": rows, "promotion_effect": "none",
        "release_gate": {"exit_code": 3, "status": "HOLD"},
        "schema_version": 1,
        "status": "local-foundation-complete-operational-evidence-absent",
    })
    return outputs


def _atomic_write(path: Path, raw: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            view = memoryview(raw)
            while view:
                written = stream.write(view)
                if written is None or written <= 0:
                    raise PackageFError(f"short write for {path.name}")
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
                        FRAMEWORK / relative, label=f"Package F output {relative}"
                    )
                except PackageFError:
                    differences.append(relative)
                    continue
                if actual != expected:
                    differences.append(relative)
            if differences:
                raise PackageFError(f"generated Package F artifacts differ: {differences}")
            print(f"Package F generation check passed: {len(outputs)} artifacts")
        else:
            for relative, raw in sorted(outputs.items()):
                _atomic_write(FRAMEWORK / relative, raw)
            print(f"generated {len(outputs)} canonical Package F artifacts")
        return 0
    except (OSError, PackageFError, UnicodeError, ValueError) as error:
        print(f"Package F generation HOLD: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
