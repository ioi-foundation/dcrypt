#!/usr/bin/env python3
"""Fail-closed verification for the Package C fuzz-assurance closure."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from typing import Any

sys.dont_write_bytecode = True

from fuzzing_lib import (
    EXPECTED_CRITICAL_ROWS,
    EXPECTED_EXPLICIT_BLOCKERS,
    EXPECTED_TOTAL_ROWS,
    FRAMEWORK_DIR,
    REPO_ROOT,
    STATUS,
    FuzzingError,
    assert_code_pins,
    build_registry,
    validate_campaign_status,
    validate_corpus_manifest,
    parse_json,
    read_regular_file,
    verify_registry_against_sources,
)
from generate import SOURCE_FILES, expected_outputs
from crash_lifecycle import validate_crash_bundle
from crash_lifecycle import validate_lifecycle_requirements
from sanitizer_positive import validate_control_requirements


def _validate_schema(value: Any, schema: dict[str, Any], *, label: str) -> None:
    if "anyOf" in schema:
        matches = 0
        for candidate in schema["anyOf"]:
            try:
                _validate_schema(value, candidate, label=label)
                matches += 1
            except FuzzingError:
                pass
        if matches < 1:
            raise FuzzingError(f"{label} matches no anyOf branch")
        return
    expected_type = schema.get("type")
    type_ok = {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
        None: True,
    }.get(expected_type, False)
    if not type_ok:
        raise FuzzingError(f"{label} has wrong schema type")
    if "const" in schema and value != schema["const"]:
        raise FuzzingError(f"{label} differs from schema const")
    if "enum" in schema and value not in schema["enum"]:
        raise FuzzingError(f"{label} differs from schema enum")
    if isinstance(value, dict):
        required = set(schema.get("required", []))
        properties = schema.get("properties", {})
        if set(value) != required or schema.get("additionalProperties") is not False:
            raise FuzzingError(f"{label} object closure differs")
        for key, item in value.items():
            _validate_schema(item, properties[key], label=f"{label}.{key}")
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            raise FuzzingError(f"{label} array length differs")
        if schema.get("uniqueItems") and len({repr(item) for item in value}) != len(value):
            raise FuzzingError(f"{label} array contains duplicates")
        for index, item in enumerate(value):
            _validate_schema(item, schema.get("items", {}), label=f"{label}[{index}]")
    elif isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise FuzzingError(f"{label} integer bound differs")
    elif isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            raise FuzzingError(f"{label} string length differs")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise FuzzingError(f"{label} string pattern differs")


def _actual_file_set() -> set[str]:
    files: set[str] = set()
    for root, directories, names in os.walk(FRAMEWORK_DIR, topdown=True, followlinks=False):
        directories.sort()
        names.sort()
        for directory in directories:
            path = __import__("pathlib").Path(root) / directory
            if path.is_symlink() or directory == "__pycache__":
                raise FuzzingError(f"forbidden directory in framework closure: {path}")
        for name in names:
            path = __import__("pathlib").Path(root) / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or name.endswith(".pyc"):
                raise FuzzingError(f"framework member is not a single-link regular source/artifact: {path}")
            files.add(path.relative_to(FRAMEWORK_DIR).as_posix())
    return files


def verify() -> dict[str, Any]:
    assert_code_pins()
    expected = expected_outputs()
    expected_files = set(SOURCE_FILES) | set(expected)
    actual_files = _actual_file_set()
    if actual_files != expected_files:
        raise FuzzingError(
            f"framework closure differs: missing={sorted(expected_files-actual_files)} "
            f"surplus={sorted(actual_files-expected_files)}"
        )
    for relative, raw in expected.items():
        actual = read_regular_file(FRAMEWORK_DIR, relative, label=f"sealed artifact {relative}")
        if actual != raw:
            raise FuzzingError(f"sealed generated artifact differs: {relative}")
    registry = build_registry()
    verify_registry_against_sources(REPO_ROOT, registry)
    mapping = parse_json(
        read_regular_file(FRAMEWORK_DIR, "row-mapping.json", label="row mapping"), label="row mapping"
    )
    if mapping["counts"] != {
        "critical_family_rows": EXPECTED_CRITICAL_ROWS,
        "curated_rows": 566,
        "explicit_blocker_rows": EXPECTED_EXPLICIT_BLOCKERS,
        "release_blocked_rows": EXPECTED_TOTAL_ROWS,
        "total_atomic_rows": EXPECTED_TOTAL_ROWS,
        "unreviewed_gap_rows": 8632,
    }:
        raise FuzzingError("atomic mapping counts differ")
    if any(item["path"] == "assurance/ledger.toml" for item in mapping["generated_inputs"]):
        raise FuzzingError("row mapping contains the forbidden self-cyclic ledger input")
    for artifact_name in (
        "campaign-status",
        "corpus-manifest",
        "crash-bundle-template",
        "crash-lifecycle-status",
        "local-sanitizer-requirements",
        "policy",
        "row-mapping",
        "sanitizer-controls",
        "source-bindings",
        "target-registry",
    ):
        value = parse_json(
            read_regular_file(FRAMEWORK_DIR, f"{artifact_name}.json", label=artifact_name),
            label=artifact_name,
        )
        schema = parse_json(
            read_regular_file(FRAMEWORK_DIR, f"schemas/{artifact_name}.schema.json", label=f"{artifact_name} schema"),
            label=f"{artifact_name} schema",
        )
        _validate_schema(value, schema, label=artifact_name)
        if artifact_name == "crash-bundle-template":
            validate_crash_bundle(value)
        elif artifact_name == "campaign-status":
            validate_campaign_status(value)
        elif artifact_name == "corpus-manifest":
            validate_corpus_manifest(value)
        elif artifact_name == "local-sanitizer-requirements":
            validate_control_requirements(value)
        elif artifact_name == "crash-lifecycle-status":
            validate_lifecycle_requirements(value)
    campaign = parse_json(
        read_regular_file(FRAMEWORK_DIR, "campaign-status.json", label="campaign status"),
        label="campaign status",
    )
    if campaign["release_gate"] != {"exit_code": 3, "status": "HOLD"}:
        raise FuzzingError("campaign release gate is not exact HOLD/3")
    if campaign["counts"] != {"blocked_targets": 17, "operationally_passing_targets": 0, "targets": 17}:
        raise FuzzingError("campaign status does not block all 17 targets")
    return {
        "critical_family_rows": EXPECTED_CRITICAL_ROWS,
        "explicit_blocker_rows": EXPECTED_EXPLICIT_BLOCKERS,
        "release_gate": "HOLD",
        "status": STATUS,
        "structural_verification": "passed",
        "targets": 17,
        "total_atomic_rows": EXPECTED_TOTAL_ROWS,
    }


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ci", action="store_true")
    mode.add_argument("--release", action="store_true")
    args = parser.parse_args()
    try:
        result = verify()
        sys.stdout.write(__import__("json").dumps(result, sort_keys=True) + "\n")
        return 3 if args.release else 0
    except (FuzzingError, OSError, ValueError) as error:
        print(f"fuzz assurance HOLD: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
