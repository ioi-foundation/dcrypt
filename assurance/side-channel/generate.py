#!/usr/bin/env python3
"""Generate the canonical Package D structural assurance artifacts."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

from model import (
    FRAMEWORK,
    PackageDError,
    artifact_source_files,
    build_evidence_schema,
    build_package_document,
    canonical_json,
    read_regular,
    sha256_bytes,
)


def expected_outputs() -> dict[str, bytes]:
    package = canonical_json(build_package_document())
    schema = canonical_json(build_evidence_schema())
    outputs = {"package-d.json": package, "schema.json": schema}
    records: list[dict[str, object]] = []
    for relative in artifact_source_files():
        raw, _metadata = read_regular(
            FRAMEWORK / relative, label=f"Package D reviewed source {relative}"
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
    if len(records) != 11 or len({record["path"] for record in records}) != 11:
        raise PackageDError("Package D artifact closure must contain exactly eleven non-self rows")
    artifacts = {
        "content_policy": "dcrypt-package-d-artifact-closure-v1",
        "files": sorted(records, key=lambda record: str(record["path"])),
        "release_gate": {"exit_code": 3, "status": "HOLD"},
        "schema_version": 1,
        "status": "HOLD-structural-foundation-only",
    }
    outputs["ARTIFACTS.json"] = canonical_json(artifacts)
    return outputs


def _atomic_write(path: Path, raw: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            view = memoryview(raw)
            while view:
                written = stream.write(view)
                if written is None or written <= 0:
                    raise PackageDError(f"short write for generated artifact {path.name}")
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
                    actual, _metadata = read_regular(
                        FRAMEWORK / relative,
                        label=f"Package D generated artifact {relative}",
                    )
                except PackageDError:
                    differences.append(relative)
                    continue
                if actual != expected:
                    differences.append(relative)
            if differences:
                raise PackageDError(f"generated Package D artifacts differ: {differences}")
            print(f"Package D generation check passed: {len(outputs)} artifacts")
        else:
            for relative, raw in sorted(outputs.items()):
                _atomic_write(FRAMEWORK / relative, raw)
            print(f"generated {len(outputs)} canonical Package D artifacts")
        return 0
    except (OSError, PackageDError, UnicodeError, ValueError) as error:
        print(f"Package D generation HOLD: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
