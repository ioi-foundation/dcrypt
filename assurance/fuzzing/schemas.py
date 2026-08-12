#!/usr/bin/env python3
"""Generate closed JSON Schemas from the canonical Package C projections."""

from __future__ import annotations

import sys
from typing import Any

sys.dont_write_bytecode = True

from fuzzing_lib import canonical_json, sha256_bytes


def _deduplicate(schemas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for schema in schemas:
        unique[sha256_bytes(canonical_json(schema))] = schema
    return [unique[key] for key in sorted(unique)]


def schema_for(value: Any, *, key: str = "") -> dict[str, Any]:
    """Return a structural schema; every represented data object is closed."""

    if isinstance(value, dict):
        return {
            "additionalProperties": False,
            "properties": {name: schema_for(item, key=name) for name, item in sorted(value.items())},
            "required": sorted(value),
            "type": "object",
        }
    if isinstance(value, list):
        if not value:
            string_array_keys = {
                "affected_atomic_rows",
                "assigned_target_ids",
                "binary_markers",
                "family_algorithms",
                "host_dependent_fields",
                "report_patterns",
                "required_binary_markers",
                "semantic_states",
                "target_binary_markers",
                "unbounded_internal_primitives",
            }
            object_array_keys = {"dictionaries", "lanes", "rc_shards", "runtime_objects", "seeds", "weekly_shards"}
            if key.endswith("_ids") or key in string_array_keys:
                item = {"maxLength": 16_384, "type": "string"}
            elif key in object_array_keys:
                if key in {"rc_shards", "weekly_shards"}:
                    item = {
                        "additionalProperties": False,
                        "properties": {
                            "allocated_cores": {"maximum": 4096, "minimum": 1, "type": "integer"},
                            "attestation_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
                            "cpu_seconds": {"maximum": 31_536_000, "minimum": 0, "type": "integer"},
                            "end": {"format": "date-time", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", "type": "string"},
                            "shard_id": {"pattern": "^[A-Za-z0-9._:+/-]+$", "type": "string"},
                            "start": {"format": "date-time", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", "type": "string"},
                            "target_id": {"pattern": "^[a-z][a-z0-9_]*$", "type": "string"},
                            "writer_identity": {"maxLength": 4096, "minLength": 1, "type": "string"},
                        },
                        "required": ["allocated_cores", "attestation_sha256", "cpu_seconds", "end", "shard_id", "start", "target_id", "writer_identity"],
                        "type": "object",
                    }
                elif key == "lanes":
                    item = {
                        "additionalProperties": False,
                        "properties": {
                            "binary_markers": {
                                "items": {"pattern": "^(?:__[A-Za-z0-9_]+|LLVMFuzzerTestOneInput)$", "type": "string"},
                                "type": "array",
                                "uniqueItems": True,
                            },
                            "lane_id": {"enum": ["asan", "careful-ub", "lsan", "msan", "tsan"], "type": "string"},
                            "positive_control_artifact_sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
                            "status": {"const": "passing-target-binary-and-live-control-attested", "type": "string"},
                        },
                        "required": ["binary_markers", "lane_id", "positive_control_artifact_sha256", "status"],
                        "type": "object",
                    }
                elif key == "runtime_objects":
                    item = {
                        "additionalProperties": False,
                        "properties": {
                            "path_suffix": {
                                "pattern": "^librustc-nightly_rt\\.(?:asan|lsan)\\.a$",
                                "type": "string",
                            },
                            "sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
                        },
                        "required": ["path_suffix", "sha256"],
                        "type": "object",
                    }
                else:
                    item = {
                        "additionalProperties": False,
                        "properties": {
                            "confidentiality": {"maxLength": 128, "type": "string"},
                            "git_mode": {"const": "100644", "type": "string"},
                            "path": {
                                "pattern": "^(?!/)(?!.*(?:^|/)\\.\\.(?:/|$))[A-Za-z0-9._/+:-]+$",
                                "type": "string",
                            },
                            "provenance": {"maxLength": 1024, "type": "string"},
                            "review_status": {"maxLength": 256, "type": "string"},
                            "sha256": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
                            "size": {"maximum": 67_108_864, "minimum": 0, "type": "integer"},
                        },
                        "required": [
                            "confidentiality",
                            "git_mode",
                            "path",
                            "provenance",
                            "review_status",
                            "sha256",
                            "size",
                        ],
                        "type": "object",
                    }
            else:
                raise ValueError(f"empty array {key!r} lacks a reviewed item schema")
            return {"items": item, "type": "array", "uniqueItems": True}
        candidates = _deduplicate([schema_for(item, key=key) for item in value])
        item_schema = candidates[0] if len(candidates) == 1 else {"anyOf": candidates}
        nonunique_keys = {
            "executions_per_occurrence",
            "input_sizes",
            "output_sizes",
            "reproduction_log_sha256",
        }
        return {
            "items": item_schema,
            "minItems": 1,
            "type": "array",
            "uniqueItems": key not in nonunique_keys,
        }
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        if key == "schema_version":
            return {"const": value, "type": "integer"}
        minimum = -255 if key in {"exit_code", "release_exit_code_with_blockers"} else 0
        return {"maximum": 9_223_372_036_854_775_807, "minimum": minimum, "type": "integer"}
    if isinstance(value, str):
        if value == "UNSTABLE":
            return {"const": "UNSTABLE", "type": "string"}
        if key.endswith("sha256") or key.endswith("_sha256"):
            return {"pattern": "^[0-9a-f]{64}$", "type": "string"}
        if key in {"as_of", "first_seen", "start", "end"}:
            return {
                "format": "date-time",
                "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
                "type": "string",
            }
        if key in {"content_policy", "schema_version"}:
            return {"const": value}
        if key in {"status", "release_status", "simulation_status", "operational_status"}:
            return {"enum": [value], "type": "string"}
        if key in {"path", "source", "seed_selector_path", "dictionary_selector_path"}:
            return {"pattern": "^(?!/)(?!.*(?:^|/)\\.\\.(?:/|$))[A-Za-z0-9._/+:-]+$", "type": "string"}
        if key.endswith("_id") or key == "id":
            return {"minLength": 1, "pattern": "^[A-Za-z0-9._:+/-]+$", "type": "string"}
        return {"maxLength": 16_384, "type": "string"}
    if value is None:
        digest_keys = {
            "algorithm",
            "argv_sha256",
            "attestation_sha256",
            "binary_sha256",
            "cargo_fuzz_executable_sha256",
            "cargo_fuzz_source_sha256",
            "cargo_sha256",
            "cluster_id",
            "comparison_config_sha256",
            "corpus_files_sha256",
            "corpus_manifest_sha256",
            "current_artifact_sha256",
            "environment_sha256",
            "linker_sha256",
            "local_positive_control_sha256",
            "manifest_sha256",
            "minimized_input_sha256",
            "normalized_diagnostic_sha256",
            "occurrence_id",
            "prior_artifact_sha256",
            "profiler_config_sha256",
            "raw_input_sha256",
            "resource_limits_sha256",
            "runtime_objects_sha256",
            "rustc_sha256",
            "sanitizer_assignment_sha256",
            "sha256",
            "source_sha256",
            "target_binary_sha256",
            "target_source_sha256",
            "toolchain_identity_sha256",
        }
        timestamp_keys = {"end", "expires_at", "first_seen", "start", "time"}
        integer_keys = {
            "crashes", "edge_baseline", "edge_current", "executions", "function_baseline", "function_current",
            "minimized_size", "ooms", "original_size", "rejection_exhaustions", "semantic_state_baseline",
            "semantic_state_current", "size", "timeouts", "unbounded_allocations",
        }
        if key in digest_keys and key != "algorithm":
            candidate = {"pattern": "^[0-9a-f]{64}$", "type": "string"}
        elif key in timestamp_keys:
            candidate = {"format": "date-time", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", "type": "string"}
        elif key in {"commit", "source_commit", "subject_commit", "subject_tree", "tree"}:
            candidate = {"pattern": "^[0-9a-f]{40}$", "type": "string"}
        elif key in integer_keys:
            candidate = {"maximum": 9_223_372_036_854_775_807, "minimum": 0, "type": "integer"}
        elif key == "semantic_preserved":
            candidate = {"type": "boolean"}
        elif key == "path":
            candidate = {"pattern": "^(?!/)(?!.*(?:^|/)\\.\\.(?:/|$))[A-Za-z0-9._/+:-]+$", "type": "string"}
        else:
            candidate = {"maxLength": 16_384, "minLength": 1, "type": "string"}
        return {"anyOf": [{"type": "null"}, candidate]}
    raise TypeError(f"unsupported schema example type: {type(value).__name__}")


def closed_schema(identifier: str, title: str, example: Any) -> dict[str, Any]:
    schema = schema_for(example)
    schema["$id"] = f"urn:dcrypt:assurance:fuzzing:{identifier}:v1"
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = title
    return schema


def _nullable(schema: dict[str, Any]) -> dict[str, Any]:
    return {"anyOf": [{"type": "null"}, schema]}


def crash_bundle_schema() -> dict[str, Any]:
    digest = {"pattern": "^[0-9a-f]{64}$", "type": "string"}
    git_oid = {"pattern": "^[0-9a-f]{40}$", "type": "string"}
    nonnegative = {"maximum": 9_223_372_036_854_775_807, "minimum": 0, "type": "integer"}
    positive = {"maximum": 67_108_864, "minimum": 1, "type": "integer"}
    handoff = {
        "additionalProperties": False,
        "properties": {
            "acknowledge_deadline": _nullable({"format": "date-time", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", "type": "string"}),
            "affected_atomic_rows": {"items": {"maxLength": 4096, "minLength": 1, "type": "string"}, "type": "array", "uniqueItems": True},
            "assessment_deadline": _nullable({"format": "date-time", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", "type": "string"}),
            "cluster_id": _nullable(digest),
            "confidentiality": {"const": "private", "type": "string"},
            "created_at": _nullable({"format": "date-time", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", "type": "string"}),
            "disposition": {"enum": ["blocked-unfiled", "filed-external", "private-ready-for-authorized-handoff", "private-triage-open-unfiled", "simulated-unfiled"], "type": "string"},
            "external_receipt": _nullable({"maxLength": 4096, "minLength": 1, "type": "string"}),
            "minimization_duration_seconds": _nullable({"maximum": 900, "minimum": 0, "type": "integer"}),
            "minimization_status": {"enum": ["blocked-not-run", "completed-minimized-replayed"], "type": "string"},
            "minimized_input_sha256": _nullable(digest),
            "owner": _nullable({"maxLength": 4096, "minLength": 1, "type": "string"}),
            "minimization_started_at": _nullable({"format": "date-time", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", "type": "string"}),
            "reproduced_at": _nullable({"format": "date-time", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", "type": "string"}),
            "reproduction_duration_seconds": _nullable({"maximum": 900, "minimum": 0, "type": "integer"}),
            "reproduction_status": {"enum": ["blocked-not-run", "completed-reproduced"], "type": "string"},
            "severity": _nullable({"enum": ["critical", "high", "other"], "type": "string"}),
            "resolution_deadline": _nullable({"format": "date-time", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", "type": "string"}),
            "resolution_kind": _nullable({"enum": ["disposition", "fix", "mitigate"], "type": "string"}),
            "status": {
                "enum": ["authorized-private-handoff", "blocked-unfiled", "filed", "private-triage-open-unfiled", "simulated-unfiled"],
                "type": "string",
            },
            "target_id": _nullable({"pattern": "^[a-z][a-z0-9_]*$", "type": "string"}),
        },
        "required": ["acknowledge_deadline", "affected_atomic_rows", "assessment_deadline", "cluster_id", "confidentiality", "created_at", "disposition", "external_receipt", "minimization_duration_seconds", "minimization_started_at", "minimization_status", "minimized_input_sha256", "owner", "reproduced_at", "reproduction_duration_seconds", "reproduction_status", "resolution_deadline", "resolution_kind", "severity", "status", "target_id"],
        "type": "object",
    }
    minimization = {
        "additionalProperties": False,
        "properties": {
            "algorithm": _nullable({"maxLength": 256, "minLength": 1, "type": "string"}),
            "executions": _nullable(nonnegative),
            "minimized_bytes": _nullable(nonnegative),
            "original_bytes": _nullable(nonnegative),
            "replay_reproduced": {"type": "boolean"},
        },
        "required": ["algorithm", "executions", "minimized_bytes", "original_bytes", "replay_reproduced"],
        "type": "object",
    }
    limits = {
        "additionalProperties": False,
        "properties": {
            "input_max_bytes": _nullable(positive),
            "rss_limit_mb": {"const": 2048, "type": "integer"},
            "stack_limit_kib": {"const": 8192, "type": "integer"},
            "timeout_seconds": _nullable({"maximum": 1200, "minimum": 1, "type": "integer"}),
        },
        "required": ["input_max_bytes", "rss_limit_mb", "stack_limit_kib", "timeout_seconds"],
        "type": "object",
    }
    regression = {
        "additionalProperties": False,
        "properties": {
            "finding_id": _nullable({"maxLength": 4096, "minLength": 1, "type": "string"}),
            "fixed_binary_sha256": _nullable(digest),
            "fixed_source_sha256": _nullable(digest),
            "fix_reference": _nullable({"maxLength": 4096, "minLength": 1, "type": "string"}),
            "fixed_subject": {
                "additionalProperties": False,
                "properties": {"commit": _nullable(git_oid), "tree": _nullable(git_oid)},
                "required": ["commit", "tree"],
                "type": "object",
            },
            "independent_retest_passed": {"type": "boolean"},
            "local_fixed_child_evidence_sha256": _nullable(digest),
            "private_replay_passed": {"type": "boolean"},
            "status": {
                "enum": ["blocked-not-promoted", "fixed-replay-passed", "promoted-private", "reproduces-unfixed", "simulation-fixed-child-passed-not-promoted"],
                "type": "string",
            },
            "test_id": _nullable({"maxLength": 4096, "minLength": 1, "type": "string"}),
            "retest_evidence_sha256": _nullable(digest),
        },
        "required": ["finding_id", "fixed_binary_sha256", "fixed_source_sha256", "fix_reference", "fixed_subject", "independent_retest_passed", "local_fixed_child_evidence_sha256", "private_replay_passed", "retest_evidence_sha256", "status", "test_id"],
        "type": "object",
    }
    retention = {
        "additionalProperties": False,
        "properties": {
            "current_corpus": {"const": "indefinite", "type": "string"},
            "daily_corpus_days": {"const": 30, "type": "integer"},
            "logs_days": {"const": 90, "type": "integer"},
            "regression_corpus": {"const": "indefinite", "type": "string"},
            "weekly_corpus_weeks": {"const": 52, "type": "integer"},
        },
        "required": [
            "current_corpus",
            "daily_corpus_days",
            "logs_days",
            "regression_corpus",
            "weekly_corpus_weeks",
        ],
        "type": "object",
    }
    properties = {
        "affected_atomic_rows": {"items": {"maxLength": 4096, "minLength": 1, "type": "string"}, "type": "array", "uniqueItems": True},
        "argv_sha256": _nullable(digest),
        "binary_sha256": _nullable(digest),
        "cluster_id": _nullable(digest),
        "confidentiality": {"const": "private", "type": "string"},
        "content_policy": {"const": "dcrypt-fuzzing-private-crash-bundle-v1"},
        "corpus_manifest_sha256": _nullable(digest),
        "discovery_subject": {
            "additionalProperties": False,
            "properties": {
                "binding_status": {"enum": ["bound-final-subject", "unbound-structural"], "type": "string"},
                "commit": _nullable(git_oid),
                "manifest_sha256": _nullable(digest),
                "tree": _nullable(git_oid),
            },
            "required": ["binding_status", "commit", "manifest_sha256", "tree"],
            "type": "object",
        },
        "environment_sha256": _nullable(digest),
        "failure_class": _nullable({
            "enum": [
                "controlled-panic-simulation-only", "harness-defect", "oom", "oracle-disagreement",
                "production-defect", "rejection-exhaustion", "sanitizer-configuration-failure",
                "timeout", "unbounded-allocation",
            ],
            "type": "string",
        }),
        "first_seen": _nullable(
            {
                "format": "date-time",
                "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
                "type": "string",
            }
        ),
        "handoff": handoff,
        "limits": limits,
        "minimization": minimization,
        "minimized_input_sha256": _nullable(digest),
        "normalized_diagnostic_sha256": _nullable(digest),
        "normalization_version": {"const": "dcrypt-crash-normalization-v1"},
        "occurrence_id": _nullable(digest),
        "provenance": _nullable({"maxLength": 1024, "minLength": 1, "type": "string"}),
        "private_storage": {
            "additionalProperties": False,
            "properties": {
                "object_locator": _nullable({"pattern": "^private://[A-Za-z0-9._/+:-]+$", "type": "string"}),
                "retention_status": {"enum": ["blocked-storage-unprovisioned", "ephemeral-private-deleted", "retained-private-current"], "type": "string"},
            },
            "required": ["object_locator", "retention_status"],
            "type": "object",
        },
        "raw_diagnostic_log_sha256": _nullable(digest),
        "raw_input_sha256": _nullable(digest),
        "regression": regression,
        "retention": retention,
        "schema_version": {"const": 1, "type": "integer"},
        "status": {
            "enum": [
                "blocked-template-no-evidence",
                "handed-off-with-receipt",
                "private-captured-unresolved",
                "private-fixed-retested",
                "private-ready-for-authorized-handoff",
                "private-validated-local",
                "triage-open",
            ],
            "type": "string",
        },
        "target_id": _nullable({"pattern": "^[a-z][a-z0-9_]*$", "type": "string"}),
        "toolchain_identity_sha256": _nullable(digest),
    }
    return {
        "$id": "urn:dcrypt:assurance:fuzzing:crash-bundle-template:v1",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(properties),
        "title": "Package C private crash bundle template",
        "type": "object",
    }


def assert_all_data_objects_closed(schema: Any, *, label: str = "schema") -> None:
    if isinstance(schema, dict):
        if schema.get("type") == "object" and schema.get("additionalProperties") is not False:
            raise ValueError(f"{label} contains an open data object")
        for key, value in schema.items():
            assert_all_data_objects_closed(value, label=f"{label}.{key}")
    elif isinstance(schema, list):
        for index, value in enumerate(schema):
            assert_all_data_objects_closed(value, label=f"{label}[{index}]")
