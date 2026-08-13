#!/usr/bin/env python3
"""Deterministic adversarial self-tests for Package G contracts."""

from __future__ import annotations

import copy
import contextlib
import datetime as dt
import io
import re
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from model import (
    FRAMEWORK, PackageGBlocker, PackageGError, build_schema, build_synthetic_records,
    canonical_json, evaluate_foundation_temporal_state, identical, parse_json_strict,
    semantic_sha256, validate_phase_document, verify_current_topology_scope,
    verify_immutable_projection,
)
import verify as verifier


class SchemaFailure(ValueError):
    pass


def _schema_validate(instance: Any, schema: dict[str, Any], root: dict[str, Any]) -> None:
    if "$ref" in schema:
        reference = schema["$ref"]
        if not reference.startswith("#/$defs/"):
            raise SchemaFailure("unsupported reference")
        _schema_validate(instance, root["$defs"][reference.removeprefix("#/$defs/")], root)
        return
    if "not" in schema:
        try:
            _schema_validate(instance, schema["not"], root)
        except SchemaFailure:
            pass
        else:
            raise SchemaFailure("not constraint matched")
    if "oneOf" in schema:
        matches = 0
        for branch in schema["oneOf"]:
            try:
                _schema_validate(instance, branch, root)
            except SchemaFailure:
                continue
            matches += 1
        if matches != 1:
            raise SchemaFailure(f"oneOf matched {matches} branches")
    if "const" in schema and not identical(instance, schema["const"]):
        raise SchemaFailure("const differs")
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(instance, dict):
            raise SchemaFailure("object required")
        required = schema.get("required", [])
        if any(key not in instance for key in required):
            raise SchemaFailure("required property absent")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and not set(instance) <= set(properties):
            raise SchemaFailure("additional property present")
        for key, value in instance.items():
            if key in properties:
                _schema_validate(value, properties[key], root)
    elif kind == "array":
        if not isinstance(instance, list):
            raise SchemaFailure("array required")
        if len(instance) < schema.get("minItems", 0) or len(instance) > schema.get("maxItems", 1 << 60):
            raise SchemaFailure("array length differs")
        if schema.get("uniqueItems"):
            encoded = [canonical_json(value) for value in instance]
            if len(set(encoded)) != len(encoded):
                raise SchemaFailure("array uniqueness differs")
        prefixes = schema.get("prefixItems", [])
        for value, child in zip(instance, prefixes, strict=False):
            _schema_validate(value, child, root)
        if len(instance) > len(prefixes):
            items = schema.get("items", {})
            if items is False:
                raise SchemaFailure("surplus array item")
            for value in instance[len(prefixes):]:
                _schema_validate(value, items, root)
    elif kind == "string":
        if not isinstance(instance, str):
            raise SchemaFailure("string required")
        if len(instance) < schema.get("minLength", 0) or len(instance) > schema.get("maxLength", 1 << 60):
            raise SchemaFailure("string length differs")
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            raise SchemaFailure("string pattern differs")
    elif kind == "integer":
        if not isinstance(instance, int) or isinstance(instance, bool):
            raise SchemaFailure("integer required")
        if instance < schema.get("minimum", -(1 << 100)) or instance > schema.get("maximum", 1 << 100):
            raise SchemaFailure("integer range differs")
    elif kind == "boolean":
        if type(instance) is not bool:
            raise SchemaFailure("boolean required")


def _schema_accepts(value: Any, schema: dict[str, Any]) -> bool:
    try:
        _schema_validate(value, schema, schema)
        return True
    except SchemaFailure:
        return False


def _must_reject(value: dict[str, Any], *, phase: str, day: dt.date) -> None:
    try:
        validate_phase_document(value, expected_phase=phase, evaluation_date=day)
    except PackageGError:
        return
    raise AssertionError("semantic validator accepted adversarial mutation")


def _rebind_synthetic_lineage(records: dict[str, Any]) -> None:
    """Recompute only the synthetic lineage digests after an adversarial mutation."""
    prepublish_digest = semantic_sha256(records["prepublish"])
    predecessor_digest = prepublish_digest
    for prefix in records["prefixes"]:
        prefix["prepublish_record_sha256"] = prepublish_digest
        prefix["prefix_predecessor_sha256"] = predecessor_digest
        predecessor_digest = semantic_sha256(prefix)
    records["postpublish"]["prepublish_record_sha256"] = prepublish_digest
    records["postpublish"]["final_prefix_record_sha256"] = semantic_sha256(records["prefixes"][-1])


def main() -> int:
    try:
        day = dt.date(2026, 8, 13)
        records = build_synthetic_records()
        schema = build_schema()
        validate_phase_document(records["foundation"], expected_phase="foundation", evaluation_date=day)
        validate_phase_document(records["prepublish"], expected_phase="prepublish", evaluation_date=day)
        for index, prefix in enumerate(records["prefixes"]):
            validate_phase_document(
                prefix, expected_phase="registry-prefix", evaluation_date=day,
                lineage_documents={"prepublish": records["prepublish"], "prefix_chain": records["prefixes"][:index]},
            )
        validate_phase_document(
            records["postpublish"], expected_phase="postpublish", evaluation_date=day,
            lineage_documents={
                "prepublish": records["prepublish"], "final_prefix": records["prefixes"][-1],
                "prefix_chain": records["prefixes"][:-1],
            },
        )
        for name in ("foundation", "prepublish", "prefix0", "postpublish"):
            if not _schema_accepts(records[name], schema):
                raise AssertionError(f"exported schema rejected valid {name} record")
        mutations: list[dict[str, Any]] = []
        wrong_type = copy.deepcopy(records["prepublish"]); wrong_type["schema_version"] = True; mutations.append(wrong_type)
        surplus = copy.deepcopy(records["prepublish"]); surplus["bypass"] = True; mutations.append(surplus)
        unsafe = copy.deepcopy(records["prepublish"]); unsafe["candidate_artifacts"][0]["path"] = "../escape"; mutations.append(unsafe)
        overcap = copy.deepcopy(records["prepublish"]); overcap["candidate_artifacts"][0]["size"] = 1073741825; mutations.append(overcap)
        accepted = copy.deepcopy(records["prepublish"]); accepted["producer_obligations"][0]["accepted"] = True; mutations.append(accepted)
        for mutation in mutations:
            _must_reject(mutation, phase="prepublish", day=day)
            if _schema_accepts(mutation, schema):
                raise AssertionError("exported schema accepted adversarial mutation")
        detached = copy.deepcopy(records["prepublish"])
        detached["independent_comparisons"][0]["reviewer"] = "detached"
        _must_reject(detached, phase="prepublish", day=day)

        boundary_path = f"{'a' * 255}/{'b' * 254}/c"
        boundary = copy.deepcopy(records["prepublish"])
        boundary["candidate_artifacts"][0]["path"] = boundary_path
        boundary["producer_obligations"][0]["artifact_path"] = boundary_path
        boundary["candidate_set_sha256"] = semantic_sha256(boundary["candidate_artifacts"])
        validate_phase_document(boundary, expected_phase="prepublish", evaluation_date=day)
        if not _schema_accepts(boundary, schema):
            raise AssertionError("exported schema rejected the runtime 512-character path boundary")
        for bad_path in (f"{'a' * 255}/{'b' * 255}/c", f"private/{'a' * 256}"):
            bad_path_record = copy.deepcopy(records["prepublish"])
            bad_path_record["candidate_artifacts"][0]["path"] = bad_path
            bad_path_record["producer_obligations"][0]["artifact_path"] = bad_path
            bad_path_record["candidate_set_sha256"] = semantic_sha256(bad_path_record["candidate_artifacts"])
            _must_reject(bad_path_record, phase="prepublish", day=day)
            if _schema_accepts(bad_path_record, schema):
                raise AssertionError("exported schema accepted a runtime-rejected path cap")

        substituted_chain = copy.deepcopy(records["prefixes"][:-1])
        substituted_chain[0]["review_decisions"][0]["reviewed_producer_identities"] = ["fake-first", "fake-independent"]
        substituted_chain[0]["review_decisions"][0]["reviewer"] = "fake-reviewer"
        predecessor_digest = semantic_sha256(records["prepublish"])
        for predecessor in substituted_chain:
            predecessor["prefix_predecessor_sha256"] = predecessor_digest
            predecessor_digest = semantic_sha256(predecessor)
        substituted_prefix = copy.deepcopy(records["prefixes"][-1])
        substituted_prefix["prefix_predecessor_sha256"] = predecessor_digest
        try:
            validate_phase_document(
                substituted_prefix, expected_phase="registry-prefix", evaluation_date=day,
                lineage_documents={"prepublish": records["prepublish"], "prefix_chain": substituted_chain},
            )
        except PackageGError:
            pass
        else:
            raise AssertionError("prefix lineage accepted substituted predecessor reviews")

        mismatched_download = copy.deepcopy(records)
        subject_id = "crate-dcrypt-internal"
        independent_obligation = next(
            obligation for obligation in mismatched_download["prepublish"]["producer_obligations"]
            if obligation["producer_class"] == "administratively-independent" and obligation["subject_id"] == subject_id
        )
        independent_obligation["artifact_sha256"] = "f" * 64
        comparison = next(
            item for item in mismatched_download["prepublish"]["independent_comparisons"]
            if item["subject_id"] == subject_id
        )
        comparison["independent_sha256"] = "f" * 64
        comparison["byte_equal"] = False
        _rebind_synthetic_lineage(mismatched_download)
        try:
            validate_phase_document(
                mismatched_download["postpublish"], expected_phase="postpublish", evaluation_date=day,
                lineage_documents={
                    "prepublish": mismatched_download["prepublish"],
                    "final_prefix": mismatched_download["prefixes"][-1],
                    "prefix_chain": mismatched_download["prefixes"][:-1],
                },
            )
        except PackageGError:
            pass
        else:
            raise AssertionError("postpublish accepted a download that differed from independent producer output")

        if _schema_accepts({"role": "acceptance"}, schema):
            raise AssertionError("disabled acceptance role passed schema")
        stale = copy.deepcopy(records["prepublish"])
        try:
            validate_phase_document(stale, expected_phase="prepublish", evaluation_date=dt.date(2026, 11, 10))
        except PackageGBlocker:
            pass
        else:
            raise AssertionError("stale review did not produce typed HOLD blocker")
        future = copy.deepcopy(records["prepublish"])
        future["review_decisions"][0]["reviewed_at"] = "2026-08-14"
        _must_reject(future, phase="prepublish", day=day)
        for raw in (
            b'{"a":1,"a":2}\n', b'{"a":1.5}\n', b'{"a":NaN}\n',
            ' {"a":"e\\u0301"}\n'.encode(),
        ):
            try:
                parse_json_strict(raw, label="adversarial JSON")
            except PackageGError:
                pass
            else:
                raise AssertionError("strict parser accepted adversarial JSON")
        if b'"as_of"' in canonical_json(records):
            raise AssertionError("record payload controls the trusted evaluation date")
        dependency_before = evaluate_foundation_temporal_state(dt.date(2026, 9, 9))
        dependency_equal = evaluate_foundation_temporal_state(dt.date(2026, 9, 10))
        dependency_after = evaluate_foundation_temporal_state(dt.date(2026, 9, 11))
        if (
            dependency_before["dependency_exception"]["expired"] is not False
            or dependency_equal["dependency_exception"]["expired"] is not True
            or dependency_after["dependency_exception"]["expired"] is not True
        ):
            raise AssertionError("dependency exception boundary is not reject-on-or-after")
        evidence_before = evaluate_foundation_temporal_state(dt.date(2026, 11, 8))
        evidence_equal = evaluate_foundation_temporal_state(dt.date(2026, 11, 9))
        evidence_after = evaluate_foundation_temporal_state(dt.date(2026, 11, 10))
        for domain in ("ledger_evidence", "threat_model"):
            if (
                evidence_before[domain]["stale"] is not False
                or evidence_equal[domain]["stale"] is not False
                or evidence_after[domain]["stale"] is not True
            ):
                raise AssertionError(f"{domain} boundary is not valid-through-inclusive")
        for historical_day in (dt.date(2026, 9, 9), dt.date(2026, 9, 10), dt.date(2026, 9, 11)):
            historical = evaluate_foundation_temporal_state(historical_day)
            if (
                historical["historical_advisory"]["replay_required"] is not True
                or historical["historical_advisory"]["expiry_inferred"] is not False
                or "historical-advisory-replay-required" not in historical["blocker_ids"]
            ):
                raise AssertionError("historical advisory deadline acquired an invented expiry rule")
        for untrusted_day in ("2026-08-13", dt.datetime(2026, 8, 13, tzinfo=dt.UTC)):
            try:
                evaluate_foundation_temporal_state(untrusted_day)  # type: ignore[arg-type]
            except PackageGError:
                pass
            else:
                raise AssertionError("foundation temporal evaluator accepted a non-date clock")
        original_argv = sys.argv
        original_structural = verifier.verify_structural
        try:
            verifier.verify_structural = lambda: (_ for _ in ()).throw(
                AssertionError("CI phase misuse reached structural verification")
            )
            for invalid_phase in ("prepublish", "postpublish"):
                sys.argv = ["verify.py", "--ci", "--phase", invalid_phase]
                with contextlib.redirect_stderr(io.StringIO()):
                    try:
                        verifier.main()
                    except SystemExit as error:
                        if error.code != 2:
                            raise AssertionError("CI phase misuse did not return rc2") from error
                    else:
                        raise AssertionError("CI phase misuse did not terminate through argparse")
        finally:
            verifier.verify_structural = original_structural
            sys.argv = original_argv
        verify_immutable_projection()
        verify_current_topology_scope()
        if (FRAMEWORK / "capture.py").exists() or (FRAMEWORK / "rebind-final-subject.py").exists():
            raise AssertionError("unauthorized capture/rebind attack surface present")
        print("Package G adversarial self-tests passed: schema, roles, lineage, clock, topology, and immutable antecedents")
        return 0
    except (AssertionError, OSError, PackageGError, SchemaFailure, UnicodeError, ValueError) as error:
        print(f"Package G self-test failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
