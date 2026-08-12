#!/usr/bin/env python3
"""Execute a private, temp-only safe-Rust crash lifecycle simulation."""

from __future__ import annotations

import argparse
import os
import re
import resource
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from fuzzing_lib import FuzzingError, STATUS, build_policy, canonical_json, exact_keys, sha256_bytes
from compiler_probe import PINNED_RUSTC_SHA256, compile_fixture, pinned_toolchain


FIXTURE_SOURCE = r'''#![forbid(unsafe_code)]
use std::io::{self, Read};
fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("fixture stdin");
    if input.windows(5).any(|window| window == b"CRASH") {
        panic!("dcrypt controlled crash fixture v1");
    }
}
'''

FIXED_SOURCE = r'''#![forbid(unsafe_code)]
use std::io::{self, Read};
fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("fixture stdin");
    std::hint::black_box(input);
}
'''


def build_lifecycle_requirements() -> dict[str, Any]:
    """Stable lifecycle predicates; all host observations remain live/private."""

    return {
        "actual_lifecycle_observed": False,
        "controlled_failure_class": "safe-rust-controlled-panic-v1-not-sanitizer-evidence",
        "crash_bundle_template": build_crash_bundle_template(),
        "distinct_occurrences_required": 2,
        "fixed_child_required": True,
        "fixed_source_sha256": sha256_bytes(FIXED_SOURCE.encode("utf-8")),
        "host_dependent_fields": [
            "binary_sha256",
            "compiler_argv_sha256",
            "fixed_binary_sha256",
            "host_linker_identity",
            "host_symbol_inspector_identity",
            "linker_argv_sha256",
            "reproduction_log_sha256",
        ],
        "minimized_trigger_sha256": sha256_bytes(b"CRASH"),
        "normalization_version": "dcrypt-crash-normalization-v1",
        "operational_campaign_evidence": False,
        "pinned_rustc_executable_sha256": PINNED_RUSTC_SHA256,
        "private_temporary_cleanup_required": True,
        "promotion_authorized": False,
        "source_sha256": sha256_bytes(FIXTURE_SOURCE.encode("utf-8")),
        "status": "live-execution-required-not-sealed",
    }


def validate_lifecycle_requirements(document: dict[str, Any]) -> None:
    if document != build_lifecycle_requirements():
        raise FuzzingError("sealed crash lifecycle requirements claimed or rebound live evidence")


def validate_live_source_binding(binding: Any) -> None:
    expected = build_policy()["source_binding"]
    record = exact_keys(binding, set(expected), label="live crash source binding")
    if record != expected:
        raise FuzzingError("live crash source binding is stale, partial, or coherently rebound")
    bound_fields = (
        record["framework_subject_commit"],
        record["framework_subject_tree"],
        record["framework_subject_manifest_sha256"],
    )
    if STATUS == "STABLE-final-subject-bound":
        if (
            re.fullmatch(r"[0-9a-f]{40}", bound_fields[0] or "") is None
            or re.fullmatch(r"[0-9a-f]{40}", bound_fields[1] or "") is None
            or re.fullmatch(r"[0-9a-f]{64}", bound_fields[2] or "") is None
        ):
            raise FuzzingError("final live crash source binding is incomplete")
    elif bound_fields != ("UNSTABLE", "UNSTABLE", "UNSTABLE"):
        raise FuzzingError("unbound live crash source binding is partial")


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_STACK, (8 * 1024 * 1024, 8 * 1024 * 1024))


def _run(binary: Path, value: bytes, env: dict[str, str]) -> tuple[int, bytes]:
    result = subprocess.run(
        [str(binary)],
        input=value,
        capture_output=True,
        timeout=10,
        env=env,
        preexec_fn=_limits,
    )
    return result.returncode, result.stdout + result.stderr


def _normalize(raw: bytes, root: Path) -> str:
    text = raw.decode("utf-8", errors="replace").replace(str(root), "<PRIVATE_TMP>")
    if "dcrypt controlled crash fixture v1" not in text:
        raise FuzzingError("diagnostic lacks the controlled failure marker")
    # The normalized signature intentionally excludes thread, process, address,
    # path, line, and runtime wording. Full private log hashes are retained.
    return "safe-rust-controlled-panic:dcrypt controlled crash fixture v1\n"


def crash_cluster_id(
    *,
    target_id: str,
    failure_class: str,
    affected_atomic_rows: list[str],
    normalized_diagnostic_sha256: str,
    minimized_input_sha256: str,
) -> str:
    if (
        not re.fullmatch(r"[a-z][a-z0-9_]*", target_id)
        or not failure_class
        or affected_atomic_rows != sorted(set(affected_atomic_rows))
        or not affected_atomic_rows
        or any(not isinstance(row, str) or not row for row in affected_atomic_rows)
        or re.fullmatch(r"[0-9a-f]{64}", normalized_diagnostic_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", minimized_input_sha256) is None
    ):
        raise FuzzingError("crash deduplication key fields differ")
    return sha256_bytes(
        canonical_json(
            {
                "affected_atomic_rows": affected_atomic_rows,
                "failure_class": failure_class,
                "minimized_input_sha256": minimized_input_sha256,
                "normalized_diagnostic_sha256": normalized_diagnostic_sha256,
                "target_id": target_id,
            }
        )
    )


def _crashes(binary: Path, value: bytes, env: dict[str, str]) -> tuple[bool, bytes]:
    code, log = _run(binary, value, env)
    return code != 0 and b"dcrypt controlled crash fixture v1" in log, log


def _minimize(binary: Path, raw: bytes, env: dict[str, str]) -> tuple[bytes, int]:
    candidate = raw
    executions = 0
    changed = True
    while changed:
        changed = False
        for index in range(len(candidate)):
            trial = candidate[:index] + candidate[index + 1 :]
            crashes, _ = _crashes(binary, trial, env)
            executions += 1
            if crashes:
                candidate = trial
                changed = True
                break
    return candidate, executions


def build_private_handoff_template() -> dict[str, Any]:
    return {
        "acknowledge_deadline": None,
        "affected_atomic_rows": [],
        "assessment_deadline": None,
        "cluster_id": None,
        "confidentiality": "private",
        "created_at": None,
        "disposition": "blocked-unfiled",
        "external_receipt": None,
        "minimization_duration_seconds": None,
        "minimization_status": "blocked-not-run",
        "minimized_input_sha256": None,
        "owner": None,
        "minimization_started_at": None,
        "reproduced_at": None,
        "reproduction_duration_seconds": None,
        "reproduction_status": "blocked-not-run",
        "severity": None,
        "resolution_deadline": None,
        "resolution_kind": None,
        "status": "blocked-unfiled",
        "target_id": None,
    }


def validate_private_handoff(record: Any, *, allow_simulation: bool = True) -> None:
    template = build_private_handoff_template()
    handoff = exact_keys(record, set(template), label="private crash handoff")
    if handoff["confidentiality"] != "private":
        raise FuzzingError("private handoff confidentiality differs")
    if handoff == template:
        return
    digest = handoff["cluster_id"]
    minimized = handoff["minimized_input_sha256"]
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or not isinstance(minimized, str)
        or re.fullmatch(r"[0-9a-f]{64}", minimized) is None
        or not isinstance(handoff["owner"], str)
        or not handoff["owner"]
        or handoff["severity"] not in {"critical", "high", "other"}
        or not isinstance(handoff["target_id"], str)
        or re.fullmatch(r"[a-z][a-z0-9_]*", handoff["target_id"]) is None
        or handoff["affected_atomic_rows"] != sorted(set(handoff["affected_atomic_rows"]))
        or not handoff["affected_atomic_rows"]
    ):
        raise FuzzingError("private handoff identity/severity/ownership differs")
    created = __import__("fuzzing_lib").parse_utc(handoff["created_at"], label="handoff created")
    acknowledge = __import__("fuzzing_lib").parse_utc(handoff["acknowledge_deadline"], label="handoff acknowledge deadline")
    resolution = __import__("fuzzing_lib").parse_utc(
        handoff["resolution_deadline"], label="handoff resolution deadline"
    )
    assessment_value = handoff["assessment_deadline"]
    if handoff["severity"] == "other":
        assessment = None
        ceilings = (3 * 24 * 60 * 60, 14 * 24 * 60 * 60)
        elapsed = (
            int((acknowledge - created).total_seconds()),
            int((resolution - created).total_seconds()),
        )
        if handoff["resolution_kind"] != "disposition" or assessment_value is not None or not (
            created < acknowledge <= resolution
        ):
            raise FuzzingError("other-severity handoff deadline shape differs")
    else:
        assessment = __import__("fuzzing_lib").parse_utc(
            assessment_value, label="handoff assessment deadline"
        )
        if not (created < acknowledge <= assessment <= resolution):
            raise FuzzingError("private handoff deadline ordering differs")
        if handoff["severity"] == "critical":
            ceilings = (4 * 60 * 60, 24 * 60 * 60, 72 * 60 * 60)
            required_kind = "mitigate"
        else:
            # A calendar day is deliberately stricter than locale-dependent
            # business-day arithmetic and is therefore portable/fail-closed.
            ceilings = (24 * 60 * 60, 3 * 24 * 60 * 60, 7 * 24 * 60 * 60)
            required_kind = "fix"
        elapsed = tuple(
            int((deadline - created).total_seconds())
            for deadline in (acknowledge, assessment, resolution)
        )
        if handoff["resolution_kind"] != required_kind:
            raise FuzzingError("private handoff severity resolution kind differs")
    if any(value > ceiling for value, ceiling in zip(elapsed, ceilings, strict=True)):
        raise FuzzingError("private handoff severity SLA deadline exceeds its ceiling")
    for name in ("reproduction_duration_seconds", "minimization_duration_seconds"):
        value = handoff[name]
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 900:
            raise FuzzingError("private handoff reproduce/minimize duration exceeds 15 minutes")
    reproduced_at = __import__("fuzzing_lib").parse_utc(
        handoff["reproduced_at"], label="handoff reproduced_at"
    )
    minimization_started_at = __import__("fuzzing_lib").parse_utc(
        handoff["minimization_started_at"], label="handoff minimization_started_at"
    )
    if (
        not created <= reproduced_at <= minimization_started_at
        or int((reproduced_at - created).total_seconds()) > 900
        or int((minimization_started_at - created).total_seconds()) > 900
    ):
        raise FuzzingError("private handoff reproduce/minimization start exceeded capture-relative 15 minutes")
    if handoff["reproduction_status"] != "completed-reproduced" or handoff["minimization_status"] != "completed-minimized-replayed":
        raise FuzzingError("private handoff reproduce/minimize status differs")
    allowed = {
        "private-triage-open-unfiled": ("private-triage-open-unfiled", None),
        "simulated-unfiled": ("simulated-unfiled", None),
        "authorized-private-handoff": ("private-ready-for-authorized-handoff", "required"),
        "filed": ("filed-external", "required"),
    }
    if handoff["status"] not in allowed:
        raise FuzzingError("private handoff status is unreviewed")
    disposition, receipt = allowed[handoff["status"]]
    has_receipt = isinstance(handoff["external_receipt"], str) and bool(handoff["external_receipt"])
    if handoff["disposition"] != disposition or (receipt == "required") != has_receipt:
        raise FuzzingError("private handoff disposition/receipt differs")
    if handoff["status"] == "simulated-unfiled" and not allow_simulation:
        raise FuzzingError("simulated handoff is forbidden in this evidence context")


def build_crash_bundle_template() -> dict[str, Any]:
    """Closed field template; nulls are blockers, never inferred evidence."""

    return {
        "affected_atomic_rows": [],
        "argv_sha256": None,
        "binary_sha256": None,
        "cluster_id": None,
        "confidentiality": "private",
        "content_policy": "dcrypt-fuzzing-private-crash-bundle-v1",
        "corpus_manifest_sha256": None,
        "discovery_subject": {
            "binding_status": "unbound-structural",
            "commit": None,
            "manifest_sha256": None,
            "tree": None,
        },
        "environment_sha256": None,
        "failure_class": None,
        "first_seen": None,
        "handoff": build_private_handoff_template(),
        "limits": {
            "input_max_bytes": None,
            "rss_limit_mb": 2048,
            "stack_limit_kib": 8192,
            "timeout_seconds": None,
        },
        "minimization": {
            "algorithm": None,
            "executions": None,
            "minimized_bytes": None,
            "original_bytes": None,
            "replay_reproduced": False,
        },
        "minimized_input_sha256": None,
        "normalized_diagnostic_sha256": None,
        "normalization_version": "dcrypt-crash-normalization-v1",
        "occurrence_id": None,
        "provenance": None,
        "private_storage": {
            "object_locator": None,
            "retention_status": "blocked-storage-unprovisioned",
        },
        "raw_diagnostic_log_sha256": None,
        "raw_input_sha256": None,
        "regression": {
            "finding_id": None,
            "fixed_binary_sha256": None,
            "fixed_source_sha256": None,
            "fix_reference": None,
            "fixed_subject": {
                "commit": None,
                "tree": None,
            },
            "independent_retest_passed": False,
            "local_fixed_child_evidence_sha256": None,
            "private_replay_passed": False,
            "status": "blocked-not-promoted",
            "test_id": None,
            "retest_evidence_sha256": None,
        },
        "retention": {
            "current_corpus": "indefinite",
            "daily_corpus_days": 30,
            "logs_days": 90,
            "regression_corpus": "indefinite",
            "weekly_corpus_weeks": 52,
        },
        "schema_version": 1,
        "status": "blocked-template-no-evidence",
        "target_id": None,
        "toolchain_identity_sha256": None,
    }


def validate_crash_bundle(record: Any) -> None:
    """Enforce status-dependent crash-bundle semantics beyond JSON Schema."""

    template = build_crash_bundle_template()
    bundle = exact_keys(record, set(template), label="private crash bundle")
    handoff = exact_keys(bundle["handoff"], set(template["handoff"]), label="private crash bundle handoff")
    limits = exact_keys(bundle["limits"], set(template["limits"]), label="private crash bundle limits")
    minimization = exact_keys(
        bundle["minimization"], set(template["minimization"]), label="private crash bundle minimization"
    )
    regression = exact_keys(
        bundle["regression"], set(template["regression"]), label="private crash bundle regression"
    )
    discovery_subject = exact_keys(
        bundle["discovery_subject"],
        set(template["discovery_subject"]),
        label="private crash discovery subject",
    )
    fixed_subject = exact_keys(
        regression["fixed_subject"],
        set(template["regression"]["fixed_subject"]),
        label="private crash fixed subject",
    )
    retention = exact_keys(
        bundle["retention"], set(template["retention"]), label="private crash bundle retention"
    )
    if (
        bundle["content_policy"] != template["content_policy"]
        or bundle["confidentiality"] != "private"
        or bundle["normalization_version"] != template["normalization_version"]
        or bundle["schema_version"] != 1
        or retention != template["retention"]
        or limits.get("rss_limit_mb") != 2048
        or limits.get("stack_limit_kib") != 8192
    ):
        raise FuzzingError("private crash bundle normative constants differ")
    evidence_fields = (
        "affected_atomic_rows",
        "argv_sha256",
        "binary_sha256",
        "cluster_id",
        "corpus_manifest_sha256",
        "environment_sha256",
        "failure_class",
        "first_seen",
        "minimized_input_sha256",
        "normalized_diagnostic_sha256",
        "occurrence_id",
        "provenance",
        "raw_diagnostic_log_sha256",
        "raw_input_sha256",
        "target_id",
        "toolchain_identity_sha256",
    )
    if bundle["status"] == "blocked-template-no-evidence":
        if (
            any((bundle[field] != [] if field == "affected_atomic_rows" else bundle[field] is not None) for field in evidence_fields)
            or limits["input_max_bytes"] is not None
            or limits["timeout_seconds"] is not None
            or minimization != template["minimization"]
            or discovery_subject != template["discovery_subject"]
            or handoff != template["handoff"]
            or bundle["private_storage"] != template["private_storage"]
            or regression != template["regression"]
        ):
            raise FuzzingError("blocked crash template contains claimed evidence")
        return
    if any(bundle[field] is None for field in evidence_fields):
        raise FuzzingError("nonblocked crash bundle lacks operational identity/evidence fields")
    digest_fields = (
        "argv_sha256",
        "binary_sha256",
        "cluster_id",
        "corpus_manifest_sha256",
        "environment_sha256",
        "minimized_input_sha256",
        "normalized_diagnostic_sha256",
        "occurrence_id",
        "raw_input_sha256",
        "raw_diagnostic_log_sha256",
        "toolchain_identity_sha256",
    )
    if any(
        re.fullmatch(r"[0-9a-f]{64}", bundle[field]) is None or bundle[field] == "0" * 64
        for field in digest_fields
    ):
        raise FuzzingError("nonblocked crash bundle contains a malformed digest")
    simulation = bundle["status"] == "private-validated-local"
    if simulation and discovery_subject["binding_status"] == "unbound-structural":
        if any(discovery_subject[key] is not None for key in ("commit", "manifest_sha256", "tree")):
            raise FuzzingError("unbound simulation discovery subject contains fake identities")
    elif (
        discovery_subject["binding_status"] != "bound-final-subject"
        or re.fullmatch(r"[0-9a-f]{40}", discovery_subject["commit"] or "") is None
        or discovery_subject["commit"] == "0" * 40
        or re.fullmatch(r"[0-9a-f]{64}", discovery_subject["manifest_sha256"] or "") is None
        or discovery_subject["manifest_sha256"] == "0" * 64
        or re.fullmatch(r"[0-9a-f]{40}", discovery_subject["tree"] or "") is None
        or discovery_subject["tree"] == "0" * 40
    ):
        raise FuzzingError("nonblocked crash discovery subject is unbound or placeholder-valued")
    if (
        re.fullmatch(r"[a-z][a-z0-9_]*", bundle["target_id"]) is None
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", bundle["first_seen"])
        is None
    ):
        raise FuzzingError("nonblocked crash bundle identity/time differs")
    if bundle["affected_atomic_rows"] != sorted(set(bundle["affected_atomic_rows"])) or not bundle["affected_atomic_rows"]:
        raise FuzzingError("nonblocked crash bundle affected-row closure differs")
    expected_cluster = crash_cluster_id(
        affected_atomic_rows=bundle["affected_atomic_rows"],
        failure_class=bundle["failure_class"],
        minimized_input_sha256=bundle["minimized_input_sha256"],
        normalized_diagnostic_sha256=bundle["normalized_diagnostic_sha256"],
        target_id=bundle["target_id"],
    )
    expected_occurrence = sha256_bytes(
        canonical_json({"cluster_id": expected_cluster, "input_sha256": bundle["raw_input_sha256"]})
    )
    if bundle["cluster_id"] != expected_cluster or bundle["occurrence_id"] != expected_occurrence:
        raise FuzzingError("private crash cluster/occurrence identity does not recompute")
    if (
        not isinstance(limits["input_max_bytes"], int)
        or not 1 <= limits["input_max_bytes"] <= 67_108_864
        or not isinstance(limits["timeout_seconds"], int)
        or not 1 <= limits["timeout_seconds"] <= 1200
        or not isinstance(minimization["algorithm"], str)
        or not minimization["algorithm"]
        or not isinstance(minimization["executions"], int)
        or minimization["executions"] < 1
        or not isinstance(minimization["original_bytes"], int)
        or not isinstance(minimization["minimized_bytes"], int)
        or minimization["minimized_bytes"] < 1
        or minimization["minimized_bytes"] > minimization["original_bytes"]
        or minimization["replay_reproduced"] is not True
    ):
        raise FuzzingError("nonblocked crash bundle minimization/limit evidence differs")
    failure_classes = {
        "controlled-panic-simulation-only",
        "harness-defect",
        "oracle-disagreement",
        "oom",
        "production-defect",
        "rejection-exhaustion",
        "sanitizer-configuration-failure",
        "timeout",
        "unbounded-allocation",
    }
    if bundle["failure_class"] not in failure_classes:
        raise FuzzingError("private crash bundle failure class is unreviewed")
    storage = exact_keys(
        bundle["private_storage"],
        set(template["private_storage"]),
        label="private crash bundle storage",
    )
    if (
        not isinstance(storage["object_locator"], str)
        or not storage["object_locator"].startswith("private://")
        or storage["retention_status"] not in {"ephemeral-private-deleted", "retained-private-current"}
    ):
        raise FuzzingError("evidence-bearing crash lacks private storage/retention binding")
    if storage["object_locator"] != f"private://{bundle['target_id']}/{bundle['cluster_id']}":
        raise FuzzingError("private crash object locator does not bind target/cluster")
    validate_private_handoff(handoff)
    if (
        handoff["affected_atomic_rows"] != bundle["affected_atomic_rows"]
        or handoff["cluster_id"] != bundle["cluster_id"]
        or handoff["minimized_input_sha256"] != bundle["minimized_input_sha256"]
        or handoff["target_id"] != bundle["target_id"]
    ):
        raise FuzzingError("private crash handoff does not cross-bind the crash bundle")
    status = bundle["status"]
    expected_handoff = {
        "private-captured-unresolved": ("private-triage-open-unfiled", False),
        "triage-open": ("private-triage-open-unfiled", False),
        "private-fixed-retested": ("authorized-private-handoff", True),
        "private-validated-local": ("simulated-unfiled", False),
        "private-ready-for-authorized-handoff": ("authorized-private-handoff", True),
        "handed-off-with-receipt": ("filed", True),
    }
    if status not in expected_handoff:
        raise FuzzingError("private crash bundle status is unreviewed")
    expected_status, receipt_required = expected_handoff[status]
    has_receipt = isinstance(handoff["external_receipt"], str) and bool(handoff["external_receipt"])
    if handoff["status"] != expected_status or has_receipt != receipt_required:
        raise FuzzingError("private crash bundle handoff/status cross-field mismatch")
    simulation = status == "private-validated-local"
    unresolved = status in {"private-captured-unresolved", "triage-open"}
    if simulation:
        if (
            bundle["failure_class"] != "controlled-panic-simulation-only"
            or storage["retention_status"] != "ephemeral-private-deleted"
            or regression["private_replay_passed"] is not True
            or regression["status"] != "simulation-fixed-child-passed-not-promoted"
            or regression["finding_id"] is not None
            or regression["fix_reference"] is not None
            or fixed_subject != template["regression"]["fixed_subject"]
            or regression["independent_retest_passed"] is not False
            or regression["retest_evidence_sha256"] is not None
            or not isinstance(regression["fixed_source_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", regression["fixed_source_sha256"]) is None
            or not isinstance(regression["fixed_binary_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", regression["fixed_binary_sha256"]) is None
            or not isinstance(regression["local_fixed_child_evidence_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", regression["local_fixed_child_evidence_sha256"]) is None
            or not isinstance(regression["test_id"], str)
            or not regression["test_id"]
        ):
            raise FuzzingError("simulation-only crash bundle overclaims promotion, finding, or independent retest")
    elif unresolved:
        if (
            regression["private_replay_passed"] is not True
            or regression["status"] != "reproduces-unfixed"
            or regression["fix_reference"] is not None
            or fixed_subject != template["regression"]["fixed_subject"]
            or regression["fixed_source_sha256"] is not None
            or regression["fixed_binary_sha256"] is not None
            or regression["local_fixed_child_evidence_sha256"] is not None
            or regression["independent_retest_passed"] is not False
            or regression["retest_evidence_sha256"] is not None
            or not isinstance(regression["finding_id"], str)
            or not regression["finding_id"]
            or not isinstance(regression["test_id"], str)
            or not regression["test_id"]
        ):
            raise FuzzingError("unresolved crash state lacks an exact reproducing private regression")
    else:
        if (
            regression["private_replay_passed"] is not True
            or regression["status"] not in {"fixed-replay-passed", "promoted-private"}
            or not isinstance(regression["finding_id"], str)
            or not regression["finding_id"]
            or not isinstance(regression["test_id"], str)
            or not regression["test_id"]
            or not isinstance(regression["fix_reference"], str)
            or not regression["fix_reference"]
            or re.fullmatch(r"[0-9a-f]{40}", fixed_subject["commit"] or "") is None
            or re.fullmatch(r"[0-9a-f]{40}", fixed_subject["tree"] or "") is None
            or fixed_subject["commit"] == discovery_subject["commit"]
            or not isinstance(regression["fixed_source_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", regression["fixed_source_sha256"]) is None
            or not isinstance(regression["fixed_binary_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", regression["fixed_binary_sha256"]) is None
            or regression["local_fixed_child_evidence_sha256"] is not None
            or not isinstance(regression["retest_evidence_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", regression["retest_evidence_sha256"]) is None
            or regression["independent_retest_passed"] is not True
        ):
            raise FuzzingError("fixed crash state lacks finding/fix/independent retest closure")


def execute_lifecycle() -> dict[str, Any]:
    raw_inputs = (b"prefix-private-CRASH-suffix", b"another-origin--CRASH--tail")
    tools = pinned_toolchain()
    private_root_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="dcrypt-private-crash-") as directory:
        root = Path(directory)
        private_root_path = root
        os.chmod(root, 0o700)
        source = root / "fixture.rs"
        binary = root / "fixture"
        fixed_source = root / "fixed.rs"
        fixed_binary = root / "fixed"
        regression_dir = root / "private-regressions"
        regression_dir.mkdir(mode=0o700)
        source.write_text(FIXTURE_SOURCE, encoding="utf-8")
        fixed_source.write_text(FIXED_SOURCE, encoding="utf-8")
        os.chmod(source, 0o600)
        os.chmod(fixed_source, 0o600)
        for index, raw in enumerate(raw_inputs):
            raw_path = root / f"raw-input-{index}"
            descriptor = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
        crashing_compile = compile_fixture(root, source=source, binary=binary, sanitizer=None)
        fixed_compile = compile_fixture(root, source=fixed_source, binary=fixed_binary, sanitizer=None)
        env = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "RUST_BACKTRACE": "0", "TZ": "UTC"}
        reproduction_logs: list[bytes] = []
        minimized_inputs: list[bytes] = []
        minimizer_execution_counts: list[int] = []
        normalized_values: list[str] = []
        for raw in raw_inputs:
            crashed, log = _crashes(binary, raw, env)
            if not crashed:
                raise FuzzingError("actual crash child did not reproduce")
            reproduction_logs.append(log)
            minimized, executions = _minimize(binary, raw, env)
            if minimized != b"CRASH":
                raise FuzzingError("deterministic minimizer did not reach the unique five-byte trigger")
            minimized_crashed, minimized_log = _crashes(binary, minimized, env)
            if not minimized_crashed:
                raise FuzzingError("minimized input did not reproduce")
            minimized_inputs.append(minimized)
            minimizer_execution_counts.append(executions)
            normalized_values.append(_normalize(minimized_log, root))
        if len(set(normalized_values)) != 1:
            raise FuzzingError("two crash occurrences did not converge to one normalized signature")
        normalized = normalized_values[0]
        if "dcrypt controlled crash fixture v1" not in normalized:
            raise FuzzingError("normalized diagnostic lost the failure signature")
        failure_class = "safe-rust-controlled-panic-v1"
        cluster_id = crash_cluster_id(
            affected_atomic_rows=["fixture.atomic-row"],
            failure_class=failure_class,
            minimized_input_sha256=sha256_bytes(minimized_inputs[0]),
            normalized_diagnostic_sha256=sha256_bytes(normalized.encode()),
            target_id="fixture_crash_target",
        )
        occurrences = [
            sha256_bytes(canonical_json({"cluster_id": cluster_id, "input_sha256": sha256_bytes(raw)}))
            for raw in raw_inputs
        ]
        if len(set(occurrences)) != 2:
            raise FuzzingError("two distinct raw inputs did not produce distinct occurrence IDs")
        occurrence_records = [
            {
                "first_seen": "2026-08-12T00:00:00Z",
                "minimized_input_sha256": sha256_bytes(minimized),
                "minimized_replay_reproduced": True,
                "minimizer_executions": executions,
                "normalized_diagnostic_sha256": sha256_bytes(normalized_value.encode()),
                "occurrence_id": occurrence_id,
                "provenance": "locally-compiled-safe-rust-controlled-private-fixture",
                "raw_input_sha256": sha256_bytes(raw),
            }
            for raw, minimized, executions, normalized_value, occurrence_id in zip(
                raw_inputs,
                minimized_inputs,
                minimizer_execution_counts,
                normalized_values,
                occurrences,
                strict=True,
            )
        ]
        if len(occurrence_records) != 2 or not all(
            record["minimized_replay_reproduced"] for record in occurrence_records
        ):
            raise FuzzingError("both distinct occurrences did not minimize and replay")
        handoff = {
            "acknowledge_deadline": "2026-08-12T00:15:00Z",
            "affected_atomic_rows": ["fixture.atomic-row"],
            "assessment_deadline": None,
            "cluster_id": cluster_id,
            "confidentiality": "private",
            "created_at": "2026-08-12T00:00:00Z",
            "disposition": "simulated-unfiled",
            "external_receipt": None,
            "minimization_duration_seconds": 1,
            "minimization_status": "completed-minimized-replayed",
            "minimized_input_sha256": sha256_bytes(minimized_inputs[0]),
            "owner": "local-controlled-fixture-owner",
            "minimization_started_at": "2026-08-12T00:00:02Z",
            "reproduced_at": "2026-08-12T00:00:01Z",
            "reproduction_duration_seconds": 1,
            "reproduction_status": "completed-reproduced",
            "severity": "other",
            "resolution_deadline": "2026-08-26T00:00:00Z",
            "resolution_kind": "disposition",
            "status": "simulated-unfiled",
            "target_id": "fixture_crash_target",
        }
        validate_private_handoff(handoff)
        regression = regression_dir / cluster_id
        descriptor = os.open(regression, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(minimized_inputs[0])
        if stat.S_IMODE(regression.stat().st_mode) != 0o600:
            raise FuzzingError("private regression mode differs from 0600")
        replay_crashed, replay_log = _crashes(binary, regression.read_bytes(), env)
        if not replay_crashed or _normalize(replay_log, root) != normalized:
            raise FuzzingError("promoted private regression replay differed")
        fixed_code, fixed_log = _run(fixed_binary, regression.read_bytes(), env)
        if fixed_code != 0 or b"dcrypt controlled crash fixture v1" in fixed_log:
            raise FuzzingError("fixed safe-Rust child failed the promoted private regression")
        source_binding = build_policy()["source_binding"]
        validate_live_source_binding(source_binding)
        simulation_failure_class = "controlled-panic-simulation-only"
        simulation_cluster = crash_cluster_id(
            affected_atomic_rows=["fixture.atomic-row"],
            failure_class=simulation_failure_class,
            minimized_input_sha256=sha256_bytes(minimized_inputs[0]),
            normalized_diagnostic_sha256=sha256_bytes(normalized.encode()),
            target_id="fixture_crash_target",
        )
        simulation_handoff = {**handoff, "cluster_id": simulation_cluster}
        simulation_corpus_manifest_sha256 = sha256_bytes(
            canonical_json(
                {
                    "fixture_kind": "local-private-crash-input-set-v1",
                    "input_sha256": sorted(sha256_bytes(raw) for raw in raw_inputs),
                    "minimized_input_sha256": sha256_bytes(minimized_inputs[0]),
                }
            )
        )
        simulation_bundle = build_crash_bundle_template()
        simulation_bundle.update(
            {
                "affected_atomic_rows": ["fixture.atomic-row"],
                "argv_sha256": sha256_bytes(canonical_json([str(binary)])),
                "binary_sha256": sha256_bytes(binary.read_bytes()),
                "cluster_id": simulation_cluster,
                "corpus_manifest_sha256": simulation_corpus_manifest_sha256,
                "discovery_subject": {
                    "binding_status": "bound-final-subject" if STATUS == "STABLE-final-subject-bound" else "unbound-structural",
                    "commit": source_binding["framework_subject_commit"] if STATUS == "STABLE-final-subject-bound" else None,
                    "manifest_sha256": source_binding["framework_subject_manifest_sha256"] if STATUS == "STABLE-final-subject-bound" else None,
                    "tree": source_binding["framework_subject_tree"] if STATUS == "STABLE-final-subject-bound" else None,
                },
                "environment_sha256": sha256_bytes(canonical_json(env)),
                "failure_class": simulation_failure_class,
                "first_seen": "2026-08-12T00:00:00Z",
                "handoff": simulation_handoff,
                "limits": {"input_max_bytes": max(map(len, raw_inputs)), "rss_limit_mb": 2048, "stack_limit_kib": 8192, "timeout_seconds": 10},
                "minimization": {
                    "algorithm": "deterministic-single-byte-deletion-fixed-order-v1",
                    "executions": sum(minimizer_execution_counts),
                    "minimized_bytes": len(minimized_inputs[0]),
                    "original_bytes": max(map(len, raw_inputs)),
                    "replay_reproduced": True,
                },
                "minimized_input_sha256": sha256_bytes(minimized_inputs[0]),
                "normalized_diagnostic_sha256": sha256_bytes(normalized.encode()),
                "occurrence_id": sha256_bytes(
                    canonical_json({"cluster_id": simulation_cluster, "input_sha256": sha256_bytes(raw_inputs[0])})
                ),
                "provenance": "locally-compiled-safe-rust-controlled-private-fixture",
                "private_storage": {"object_locator": f"private://fixture_crash_target/{simulation_cluster}", "retention_status": "ephemeral-private-deleted"},
                "raw_diagnostic_log_sha256": sha256_bytes(reproduction_logs[0]),
                "raw_input_sha256": sha256_bytes(raw_inputs[0]),
                "regression": {
                    "finding_id": None,
                    "fixed_binary_sha256": sha256_bytes(fixed_binary.read_bytes()),
                    "fixed_source_sha256": sha256_bytes(FIXED_SOURCE.encode()),
                    "fix_reference": None,
                    "fixed_subject": {"commit": None, "tree": None},
                    "independent_retest_passed": False,
                    "local_fixed_child_evidence_sha256": sha256_bytes(fixed_log + fixed_binary.read_bytes()),
                    "private_replay_passed": True,
                    "retest_evidence_sha256": None,
                    "status": "simulation-fixed-child-passed-not-promoted",
                    "test_id": "local-controlled-crash-lifecycle-fixture",
                },
                "status": "private-validated-local",
                "target_id": "fixture_crash_target",
                "toolchain_identity_sha256": sha256_bytes(tools["rustc_version"]),
            }
        )
        validate_crash_bundle(simulation_bundle)
        result = {
            "binary_sha256": sha256_bytes(binary.read_bytes()),
            "cluster_id": cluster_id,
            "crash_bundle_template": build_crash_bundle_template(),
            "simulation_crash_bundle": simulation_bundle,
            "content_policy": "dcrypt-fuzzing-crash-lifecycle-v1",
            "deduplicated_cluster_count": 1,
            "distinct_occurrence_count": len(set(occurrences)),
            "environment_sha256": sha256_bytes(canonical_json(env)),
            "failure_class": failure_class,
            "first_seen": "2026-08-12T00:00:00Z",
            "handoff": handoff,
            "minimization": {
                "algorithm": "deterministic-single-byte-deletion-fixed-order-v1",
                "executions_per_occurrence": minimizer_execution_counts,
                "input_sizes": [len(raw) for raw in raw_inputs],
                "output_sizes": [len(value) for value in minimized_inputs],
            },
            "minimized_input_sha256": sha256_bytes(minimized_inputs[0]),
            "normalized_diagnostic_sha256": sha256_bytes(normalized.encode()),
            "operational_campaign_evidence": False,
            "occurrences": occurrence_records,
            "provenance": "locally-compiled-safe-rust-controlled-private-fixture",
            "raw_input_sha256": [sha256_bytes(raw) for raw in raw_inputs],
            "regression": {
                "confidentiality": "private",
                "mode_octal": "0600",
                "normalized_replay_match": True,
                "replay_reproduced": True,
                "retention": "deleted-after-replay",
                "status": "simulated-regression-deleted-after-replay",
            },
            "reproduction_attempts": 2,
            "reproduction_log_sha256": [sha256_bytes(log) for log in reproduction_logs],
            "reproduction_successes": 2,
            "sanitizer_evidence_status": "not-sanitizer-evidence-controlled-panic-only",
            "schema_version": 1,
            "source_sha256": sha256_bytes(FIXTURE_SOURCE.encode()),
            "source_binding": source_binding,
            "status": STATUS,
            "crashing_compiler_probe": crashing_compile,
            "fixed_binary_sha256": sha256_bytes(fixed_binary.read_bytes()),
            "fixed_compiler_probe": fixed_compile,
            "fixed_log_sha256": sha256_bytes(fixed_log),
            "fixed_source_sha256": sha256_bytes(FIXED_SOURCE.encode()),
            "fixed_child_passed": True,
            "rustc_executable_sha256": tools["rustc_sha256"],
            "toolchain_identity_sha256": sha256_bytes(tools["rustc_version"]),
        }
    assert private_root_path is not None
    result["private_temporary_tree_deleted"] = not private_root_path.exists()
    if not result["private_temporary_tree_deleted"]:
        raise FuzzingError("private crash temporary tree survived cleanup")
    if (
        result["simulation_crash_bundle"]["private_storage"]["retention_status"]
        != "ephemeral-private-deleted"
        or result["regression"]["status"] != "simulated-regression-deleted-after-replay"
    ):
        raise FuzzingError("deleted local simulation retained a durable-storage claim")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--execute", action="store_true", required=True)
    parser.parse_args()
    try:
        sys.stdout.buffer.write(canonical_json(execute_lifecycle()))
    except (FuzzingError, OSError, subprocess.SubprocessError) as error:
        print(f"crash lifecycle BLOCKED: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
