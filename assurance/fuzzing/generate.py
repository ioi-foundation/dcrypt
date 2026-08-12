#!/usr/bin/env python3
"""Generate the canonical Package C fuzz-assurance artifact closure."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

from crash_lifecycle import (
    build_crash_bundle_template,
    build_lifecycle_requirements,
    validate_crash_bundle,
    validate_lifecycle_requirements,
)
from fuzzing_lib import (
    FRAMEWORK_DIR,
    REPO_ROOT,
    STATUS,
    FuzzingError,
    assert_code_pins,
    build_campaign_status,
    build_corpus_manifest,
    build_coverage_document,
    build_policy,
    build_registry,
    build_row_mapping,
    build_sanitizer_controls,
    build_source_bindings,
    canonical_json,
    read_regular_file,
    sha256_bytes,
    validate_campaign_status,
    validate_corpus_manifest,
)
from sanitizer_positive import build_control_requirements, validate_control_requirements
from schemas import assert_all_data_objects_closed, closed_schema, crash_bundle_schema


SOURCE_FILES = (
    "README.md",
    "compiler_probe.py",
    "crash_lifecycle.py",
    "fuzzing_lib.py",
    "generate.py",
    "rebind-final-subject.py",
    "run-fuzz-smoke.py",
    "sanitizer_positive.py",
    "schemas.py",
    "select-fuzz-targets.py",
    "selftest.py",
    "verify.py",
)


def _json_outputs() -> dict[str, object]:
    policy = build_policy()
    registry = build_registry()
    mapping = build_row_mapping(REPO_ROOT)
    corpus = build_corpus_manifest(REPO_ROOT)
    sanitizer = build_sanitizer_controls()
    campaign = build_campaign_status()
    validate_campaign_status(campaign)
    validate_corpus_manifest(corpus)
    crash_bundle = build_crash_bundle_template()
    validate_crash_bundle(crash_bundle)
    local_controls = build_control_requirements()
    validate_control_requirements(local_controls)
    crash = build_lifecycle_requirements()
    validate_lifecycle_requirements(crash)
    objects = {
        "campaign-status.json": campaign,
        "corpus-manifest.json": corpus,
        "crash-lifecycle-status.json": crash,
        "crash-bundle-template.json": crash_bundle,
        "local-sanitizer-requirements.json": local_controls,
        "policy.json": policy,
        "row-mapping.json": mapping,
        "sanitizer-controls.json": sanitizer,
        "source-bindings.json": build_source_bindings(REPO_ROOT),
        "target-registry.json": registry,
    }
    schema_titles = {
        "campaign-status.json": "Package C campaign status",
        "corpus-manifest.json": "Package C reviewed corpus manifest",
        "crash-lifecycle-status.json": "Package C crash lifecycle",
        "crash-bundle-template.json": "Package C private crash bundle template",
        "local-sanitizer-requirements.json": "Package C live sanitizer-control requirements",
        "policy.json": "Package C fuzz policy",
        "row-mapping.json": "Package C atomic-row mapping",
        "sanitizer-controls.json": "Package C sanitizer assignment",
        "source-bindings.json": "Package C exact fuzz source bindings",
        "target-registry.json": "Package C target registry",
    }
    for filename, value in list(objects.items()):
        identifier = filename.removesuffix(".json")
        schema = closed_schema(identifier, schema_titles[filename], value)
        assert_all_data_objects_closed(schema)
        objects[f"schemas/{identifier}.schema.json"] = schema
    bundle_schema = crash_bundle_schema()
    assert_all_data_objects_closed(bundle_schema)
    objects["schemas/crash-bundle-template.schema.json"] = bundle_schema
    return objects


def expected_outputs() -> dict[str, bytes]:
    assert_code_pins()
    objects = _json_outputs()
    outputs = {path: canonical_json(value) for path, value in objects.items()}
    mapping = objects["row-mapping.json"]
    assert isinstance(mapping, dict)
    outputs["ROW-COVERAGE.md"] = build_coverage_document(mapping).encode("utf-8")
    records = []
    for relative in SOURCE_FILES:
        raw = read_regular_file(FRAMEWORK_DIR, relative, label=f"framework source {relative}")
        records.append({"kind": "reviewed-source", "path": relative, "sha256": sha256_bytes(raw), "size": len(raw)})
    for relative, raw in sorted(outputs.items()):
        records.append({"kind": "generated", "path": relative, "sha256": sha256_bytes(raw), "size": len(raw)})
    manifest = {
        "content_policy": "dcrypt-fuzzing-artifact-closure-v1",
        "files": sorted(records, key=lambda item: item["path"]),
        "release_gate": "HOLD",
        "schema_version": 1,
        "status": STATUS,
    }
    artifact_schema = closed_schema("artifacts", "Package C sealed artifact closure", manifest)
    assert_all_data_objects_closed(artifact_schema)
    outputs["schemas/artifacts.schema.json"] = canonical_json(artifact_schema)
    records.append(
        {
            "kind": "generated",
            "path": "schemas/artifacts.schema.json",
            "sha256": sha256_bytes(outputs["schemas/artifacts.schema.json"]),
            "size": len(outputs["schemas/artifacts.schema.json"]),
        }
    )
    manifest["files"] = sorted(records, key=lambda item: item["path"])
    outputs["ARTIFACTS.json"] = canonical_json(manifest)
    return outputs


def _atomic_write(relative: str, raw: bytes) -> None:
    destination = FRAMEWORK_DIR / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
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
            differences = []
            for relative, expected in sorted(outputs.items()):
                try:
                    actual = read_regular_file(FRAMEWORK_DIR, relative, label=f"generated output {relative}")
                except FuzzingError:
                    differences.append(relative)
                    continue
                if actual != expected:
                    differences.append(relative)
            if differences:
                raise FuzzingError(f"generated outputs differ: {differences}")
        else:
            for relative, raw in sorted(outputs.items()):
                _atomic_write(relative, raw)
            print(f"generated {len(outputs)} canonical Package C artifacts")
    except (FuzzingError, OSError, ValueError, subprocess.SubprocessError) as error:  # type: ignore[name-defined]
        print(f"generation HOLD: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
