#!/usr/bin/env python3
"""Verify a dcrypt candidate audit-freeze bundle without trusting its bytes."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


def _load_generator():
    path = Path(__file__).with_name("generate-audit-freeze.py")
    spec = importlib.util.spec_from_file_location("dcrypt_audit_freeze_generator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = _load_generator()
RELEASE_BLOCKED_EXIT = 3
EXPECTED_RELEASE_BLOCKERS = 9319
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_BUNDLE_FILE_BYTES = 128 * 1024 * 1024
MAX_BUNDLE_TOTAL_BYTES = 256 * 1024 * 1024
FREEZE_KEYS = frozenset(
    (
        "schema_version",
        "content_policy",
        "freeze_id",
        "classification",
        "freeze_date",
        "valid_through",
        "supersession",
        "subject",
        "release_subject",
        "canonicalization",
        "manifest_files",
        "counts",
        "release_gate",
        "generated_evidence_status",
        "commands",
        "command_expectations",
    )
)
ENVELOPE_KEYS = frozenset(
    (
        "schema_version",
        "audit_policy_path",
        "audit_policy_sha256",
        "audit_scope_path",
        "audit_scope_sha256",
        "freeze_id",
        "freeze_json_sha256",
        "sow_path",
        "sow_sha256",
        "subject_commit",
        "subject_tree",
        "status",
    )
)


class ReleaseBlockedError(gen.FreezeError):
    """A fully validated release candidate that still has assurance blockers."""

    def __init__(self, blockers: int):
        if blockers != EXPECTED_RELEASE_BLOCKERS:
            raise gen.FreezeError(
                "release blocker count drift cannot use the validated-blocked exit: "
                f"{blockers} != {EXPECTED_RELEASE_BLOCKERS}"
            )
        self.blockers = blockers
        super().__init__(f"release verification rejected {blockers} unresolved blockers")


def verification_failure_exit_code(exc: gen.FreezeError) -> int:
    return RELEASE_BLOCKED_EXIT if isinstance(exc, ReleaseBlockedError) else 1


def fail(message: str) -> None:
    raise gen.FreezeError(message)


def safe_bundle_files(bundle: Path) -> dict[str, bytes]:
    bundle = gen.reject_symlink_components(bundle)
    if bundle.is_symlink() or not bundle.is_dir():
        fail(f"bundle is not a real directory: {bundle}")
    bundle_status = bundle.lstat()
    directory_fd = gen.open_directory_nofollow(bundle)
    try:
        opened_directory_status = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(opened_directory_status.st_mode)
            or (opened_directory_status.st_dev, opened_directory_status.st_ino)
            != (bundle_status.st_dev, bundle_status.st_ino)
        ):
            fail("bundle directory changed between preflight and descriptor open")
        names: set[str] = set()
        entries: dict[str, os.stat_result] = {}
        total_size = 0
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                name = gen.validate_repo_path(entry.name, label="bundle entry")
                if name in names:
                    fail(f"duplicate bundle entry: {name}")
                names.add(name)
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    fail(f"non-regular bundle entry is forbidden: {name}")
                entry_status = entry.stat(follow_symlinks=False)
                if entry_status.st_nlink != 1:
                    fail(f"hardlinked bundle entry is forbidden: {name}")
                size = entry_status.st_size
                if size > MAX_BUNDLE_FILE_BYTES:
                    fail(f"bundle entry exceeds {MAX_BUNDLE_FILE_BYTES} byte limit: {name}")
                total_size += size
                entries[name] = entry_status
        expected = set(gen.ALLOWED_BUNDLE_FILES)
        if names != expected:
            fail(f"bundle file set mismatch: missing={sorted(expected - names)} unexpected={sorted(names - expected)}")
        if total_size > MAX_BUNDLE_TOTAL_BYTES:
            fail(f"bundle exceeds {MAX_BUNDLE_TOTAL_BYTES} byte aggregate limit")
        contents: dict[str, bytes] = {}
        for name in sorted(entries):
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(name, flags, dir_fd=directory_fd)
            except OSError as exc:
                fail(f"cannot safely open bundle entry {name}: {exc}")
            try:
                before = os.fstat(descriptor)
                scanned = entries[name]
                identity = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
                if any(getattr(before, field) != getattr(scanned, field) for field in identity):
                    fail(f"bundle entry changed between preflight and descriptor open: {name}")
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    fail(f"bundle entry is not an exclusively linked regular file: {name}")
                remaining = before.st_size
                chunks: list[bytes] = []
                while remaining:
                    chunk = os.read(descriptor, min(1024 * 1024, remaining))
                    if not chunk:
                        fail(f"bundle entry was truncated while reading: {name}")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(descriptor, 1):
                    fail(f"bundle entry grew while reading: {name}")
                after = os.fstat(descriptor)
                if any(getattr(after, field) != getattr(before, field) for field in identity):
                    fail(f"bundle entry changed while reading: {name}")
                contents[name] = b"".join(chunks)
            finally:
                os.close(descriptor)
        final_directory_status = os.fstat(directory_fd)
        comparison_fd = gen.open_directory_nofollow(bundle)
        try:
            final_path_status = os.fstat(comparison_fd)
        finally:
            os.close(comparison_fd)
        if (
            (final_directory_status.st_dev, final_directory_status.st_ino)
            != (opened_directory_status.st_dev, opened_directory_status.st_ino)
            or (final_path_status.st_dev, final_path_status.st_ino)
            != (opened_directory_status.st_dev, opened_directory_status.st_ino)
        ):
            fail("bundle directory identity changed while reading")
        final_entries: dict[str, os.stat_result] = {}
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                if entry.name in final_entries:
                    fail(f"duplicate bundle entry during final inventory: {entry.name}")
                final_entries[entry.name] = entry.stat(follow_symlinks=False)
        if set(final_entries) != set(entries):
            fail(
                "bundle file set changed while reading: "
                f"missing={sorted(set(entries) - set(final_entries))} "
                f"unexpected={sorted(set(final_entries) - set(entries))}"
            )
        for name, initial in entries.items():
            final = final_entries[name]
            identity = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(final, field) != getattr(initial, field) for field in identity):
                fail(f"bundle entry identity changed during final inventory: {name}")
        return contents
    finally:
        os.close(directory_fd)


def parse_checksums(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail("SHA256SUMS is not ASCII")
    if not text.endswith("\n") or "\r" in text:
        fail("SHA256SUMS must use LF and end in one LF")
    result: dict[str, str] = {}
    previous = ""
    for line in text.splitlines():
        if len(line) < 67 or line[64:66] != "  ":
            fail(f"malformed SHA256SUMS line: {line!r}")
        digest, name = line[:64], line[66:]
        if not HEX64.fullmatch(digest):
            fail(f"invalid SHA-256 in SHA256SUMS: {digest!r}")
        gen.validate_repo_path(name, label="SHA256SUMS filename")
        if name == "SHA256SUMS":
            fail("SHA256SUMS must never hash itself")
        if name in result:
            fail(f"duplicate SHA256SUMS filename: {name}")
        if previous and name <= previous:
            fail("SHA256SUMS filenames are not in canonical ascending order")
        result[name] = digest
        previous = name
    if set(result) != set(gen.JSON_FILES):
        fail(f"SHA256SUMS must hash exactly the JSON documents: {sorted(result)}")
    return result


def validate_freeze_shape(freeze: dict[str, Any]) -> None:
    if set(freeze) != FREEZE_KEYS:
        fail(f"freeze.json key set mismatch: {sorted(set(freeze) ^ FREEZE_KEYS)}")
    if freeze["schema_version"] != 1 or freeze["content_policy"] != gen.CONTENT_POLICY:
        fail("unsupported freeze schema/content policy")
    if freeze["classification"] != "candidate-rehearsal":
        fail("freeze is not classified as a candidate rehearsal")
    if freeze["freeze_id"] != gen.PRODUCTION_FREEZE_ID:
        fail("freeze identifier differs from the single reviewed candidate identifier")
    for key in ("freeze_date", "valid_through"):
        try:
            dt.date.fromisoformat(freeze[key])
        except (TypeError, ValueError):
            fail(f"freeze.json {key} is not an ISO date")
    subject = freeze["subject"]
    expected_subject_keys = {"commit", "tree", "commit_payload_sha256", "tree_payload_sha256"}
    if not isinstance(subject, dict) or set(subject) != expected_subject_keys:
        fail("freeze subject key set is invalid")
    if not gen.HEX40.fullmatch(subject["commit"]) or not gen.HEX40.fullmatch(subject["tree"]):
        fail("freeze subject commit/tree is not exact lowercase 40-hex")
    if not HEX64.fullmatch(subject["commit_payload_sha256"]) or not HEX64.fullmatch(subject["tree_payload_sha256"]):
        fail("freeze subject payload digests are not SHA-256")
    rows = freeze["manifest_files"]
    if not isinstance(rows, list):
        fail("freeze manifest_files is not an array")
    paths = [row.get("path") for row in rows if isinstance(row, dict)]
    if len(paths) != len(rows) or paths != sorted(gen.SUBORDINATE_FILES):
        fail(
            "freeze.json must hash every subordinate exactly once and omit freeze/envelope/"
            "provisioning-handoff/checksum documents"
        )
    for row in rows:
        if set(row) != {"path", "sha256"} or not HEX64.fullmatch(row["sha256"]):
            fail("invalid freeze manifest_files row")
    gate = freeze["release_gate"]
    if not isinstance(gate, dict) or gate.get("status") != "blocked" or gate.get("total_blockers", 0) <= 0:
        fail("candidate freeze must remain release-blocked")
    if gate.get("release_verification_must_fail_with_blockers") is not True:
        fail("freeze release gate is not fail-closed")
    if freeze["generated_evidence_status"] != "first-party-unreplayed":
        fail("generated candidate evidence is incorrectly represented as independently replayed")
    if freeze["supersession"] != gen.SUPERSESSION_RECORD:
        fail("freeze supersession/invalidation record drift")
    commands = freeze["commands"]
    expectations = freeze["command_expectations"]
    if not isinstance(commands, list) or not all(isinstance(item, str) and item for item in commands):
        fail("freeze command inventory is invalid")
    if not isinstance(expectations, list) or [row.get("command_index") for row in expectations if isinstance(row, dict)] != list(range(len(commands))):
        fail("freeze command expectations do not cover every command exactly once")
    if any(set(row) != {"command_index", "expected"} or not isinstance(row["expected"], str) for row in expectations):
        fail("freeze command expectation row is invalid")
    expected_commands, expected_expectations = gen.freeze_command_inventory(
        freeze["subject"]["commit"], freeze["freeze_id"]
    )
    if commands != expected_commands:
        fail("freeze exact sandbox-internal command inventory drift")
    if expectations != expected_expectations:
        fail("freeze command execution-status/expectation inventory drift")
    if any(any(marker in command for marker in ("<", ">", "$(", "${")) for command in commands):
        fail("freeze command inventory contains a shell placeholder")


def validate_envelope(envelope: dict[str, Any], freeze: dict[str, Any], contents: dict[str, bytes]) -> None:
    if set(envelope) != ENVELOPE_KEYS:
        fail(f"freeze-envelope.json key set mismatch: {sorted(set(envelope) ^ ENVELOPE_KEYS)}")
    if envelope["schema_version"] != 1 or envelope["status"] != "candidate-first-party-unreplayed":
        fail("freeze envelope status/schema is invalid")
    if envelope["freeze_id"] != freeze["freeze_id"]:
        fail("freeze envelope identifier mismatch")
    if envelope["freeze_json_sha256"] != gen.sha256(contents["freeze.json"]):
        fail("freeze envelope does not bind freeze.json")
    if envelope["subject_commit"] != freeze["subject"]["commit"] or envelope["subject_tree"] != freeze["subject"]["tree"]:
        fail("freeze envelope subject mismatch")
    if envelope["sow_path"] != "assurance/audit/sow/RFP-SOW.md" or not HEX64.fullmatch(envelope["sow_sha256"]):
        fail("freeze envelope SOW binding is invalid")
    if envelope["audit_policy_path"] != "assurance/audit/sow/audit-policy.toml" or not HEX64.fullmatch(envelope["audit_policy_sha256"]):
        fail("freeze envelope audit-policy binding is invalid")
    if envelope["audit_scope_path"] != "assurance/audit/sow/audit-scope.toml" or not HEX64.fullmatch(envelope["audit_scope_sha256"]):
        fail("freeze envelope audit-scope binding is invalid")


def validate_provisioning_manifest_shape(manifest: dict[str, Any], contents: dict[str, bytes]) -> None:
    expected_keys = {
        "schema_version", "id", "classification", "status", "subject", "layout",
        "checksum_policy", "network", "checkout_environment", "checkout_umask",
        "sandbox_environment", "operator_stdio", "commands", "toolchain_selection", "subject_inputs",
        "observed_host_tools", "provisioning_policy_binding", "workspace_locks",
        "materialized_payloads", "blocked_operations", "claim",
    }
    if set(manifest) != expected_keys:
        fail("PROVISIONING-MANIFEST.json key set drift")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("id") != gen.PROVISIONING_HANDOFF_ID
        or manifest.get("classification") != "observed-structural-inputs-only"
        or manifest.get("status") != "first-party-materializable-release-blocked"
    ):
        fail("provisioning handoff identity/classification/status drift")
    if manifest.get("network") != {
        "acquisition_authorized": False,
        "materialization_used_network": False,
        "offline_replay_required": True,
        "required_interfaces": ["lo"],
        "marker": "network-disabled-observed-loopback-only",
    }:
        fail("provisioning handoff network marker/policy drift")
    if manifest.get("materialized_payloads") != []:
        fail("provisioning handoff may not claim unavailable payload bytes")
    if manifest.get("operator_stdio") != gen.operator_stdio_policy():
        fail("provisioning handoff operator standard-I/O contract drift")
    subject_inputs = manifest.get("subject_inputs")
    if not isinstance(subject_inputs, list) or any(
        not isinstance(row, dict) or set(row) != {"path", "sha256", "size"}
        for row in subject_inputs
    ):
        fail("provisioning handoff subject-input inventory is malformed")
    subject_input_by_path: dict[str, dict[str, Any]] = {}
    for row in subject_inputs:
        path = row["path"]
        if not isinstance(path, str) or path in subject_input_by_path:
            fail("provisioning handoff subject-input inventory has a missing/duplicate path")
        subject_input_by_path[path] = row
    if not set(gen.TOOLCHAIN_SELECTION_INPUT_PATHS).issubset(subject_input_by_path):
        fail("provisioning handoff omits an authoritative toolchain-selection input")
    expected_selection_inputs = [
        {
            "path": path,
            "sha256": subject_input_by_path[path]["sha256"],
            "size": subject_input_by_path[path]["size"],
        }
        for path in gen.TOOLCHAIN_SELECTION_INPUT_PATHS
    ]
    if manifest.get("toolchain_selection") != {
        "distribution_status": "blocked-not-materialized",
        "root_configuration_files": [],
        "root_configuration_status": "absent-current-subject",
        "selection_inputs": expected_selection_inputs,
    }:
        fail("provisioning handoff toolchain-selection input/absence policy drift")
    if (
        manifest.get("checkout_environment") != gen.closed_git_environment()
        or manifest.get("checkout_umask") != "0022"
    ):
        fail("provisioning no-hardlink checkout environment/umask drift")
    blocked = manifest.get("blocked_operations")
    if (
        not isinstance(blocked, list)
        or len(blocked) != 10
        or len({row.get("id") for row in blocked if isinstance(row, dict)}) != 10
        or any(not isinstance(row, dict) or row.get("status") != "blocked-not-materialized" for row in blocked)
    ):
        fail("provisioning handoff blocked-operation inventory drift")
    policy = manifest.get("provisioning_policy_binding")
    if not isinstance(policy, dict) or policy.get("status") != "blocked" or policy.get("limitation") != "dependency-provision-bundle-unavailable":
        fail("provisioning handoff incorrectly promotes the dependency bundle")
    commands = manifest.get("commands")
    if not isinstance(commands, list) or len(commands) != 5:
        fail("provisioning handoff command inventory drift")
    expected_command_rows = [
        ("prepare-no-hardlink-checkout", "checkout-preparation", "required-external-preparation"),
        ("select-exact-subject", "checkout-preparation", "required-external-preparation"),
        ("materialize-observed-structural-handoff", "provision", "first-party-executable"),
        ("generate-candidate-from-read-only-handoff", "generation", "first-party-executable"),
        ("offline-two-checkout-structural-replay", "verification", "first-party-executable-after-evidence-commit"),
    ]
    if [
        (row.get("id"), row.get("operation"), row.get("status"))
        for row in commands if isinstance(row, dict)
    ] != expected_command_rows:
        fail("provisioning handoff command identity/operation/status drift")
    for row in commands:
        if not isinstance(row, dict) or not isinstance(row.get("argv"), list):
            fail("provisioning handoff command row is malformed")
        if any(
            not isinstance(argument, str)
            or not argument
            or any(marker in argument for marker in ("<", ">", "$(", "${"))
            for argument in row["argv"]
        ):
            fail("provisioning handoff argv contains an empty value or shell placeholder")
    expected_sums = (
        f"{gen.sha256(contents['PROVISIONING-MANIFEST.json'])}  PROVISIONING-MANIFEST.json\n"
    ).encode("ascii")
    if contents.get("PROVISIONING-SHA256SUMS") != expected_sums:
        fail("PROVISIONING-SHA256SUMS is noncanonical or mismatched")


def _verify_bundle_documents(
    bundle: Path,
    *,
    mode: str = "structural",
    as_of: dt.date | None = None,
    contents: dict[str, bytes] | None = None,
) -> tuple[dict[str, Any], dict[str, bytes], dict[str, dict[str, Any]]]:
    if mode not in {"structural", "release", "replay"}:
        fail(f"unsupported verification mode: {mode!r}")
    contents = safe_bundle_files(bundle) if contents is None else contents
    documents = {name: gen.canonical_json_is_exact(contents[name], label=name) for name in gen.JSON_FILES}
    freeze = documents["freeze.json"]
    envelope = documents["freeze-envelope.json"]
    provisioning_manifest = documents["PROVISIONING-MANIFEST.json"]
    validate_freeze_shape(freeze)
    validate_envelope(envelope, freeze, contents)
    validate_provisioning_manifest_shape(provisioning_manifest, contents)
    checksums = parse_checksums(contents["SHA256SUMS"])
    for name, expected in checksums.items():
        if gen.sha256(contents[name]) != expected:
            fail(f"SHA256SUMS mismatch for {name}")
    manifest_rows = {row["path"]: row["sha256"] for row in freeze["manifest_files"]}
    for name in gen.SUBORDINATE_FILES:
        if manifest_rows[name] != gen.sha256(contents[name]):
            fail(f"freeze.json manifest mismatch for {name}")
    assurance = documents["assurance-inputs.json"]
    if envelope["sow_sha256"] != assurance.get("sow_sha256"):
        fail("freeze envelope SOW digest disagrees with assurance-inputs.json")
    if envelope["audit_policy_sha256"] != assurance.get("audit_policy_sha256"):
        fail("freeze envelope audit-policy digest disagrees with assurance-inputs.json")
    if envelope["audit_scope_sha256"] != assurance.get("audit_scope_sha256"):
        fail("freeze envelope audit-scope digest disagrees with assurance-inputs.json")
    source = documents["source-manifest.json"]
    if source.get("subject", {}).get("commit") != freeze["subject"]["commit"]:
        fail("source-manifest subject disagrees with freeze.json")
    limitations = documents["limitations.json"]
    if limitations.get("total_release_blockers") != freeze["release_gate"]["total_blockers"]:
        fail("release blocker totals disagree")
    if limitations.get("atomic_release_blockers") != assurance.get("atomic_release_blockers"):
        fail("atomic release blocker totals disagree")
    effective_date = as_of or dt.datetime.now(dt.timezone.utc).date()
    if effective_date > dt.date.fromisoformat(freeze["valid_through"]):
        fail(f"freeze expired on {freeze['valid_through']} (as of {effective_date.isoformat()})")
    limitation_rows = limitations.get("limitations")
    if not isinstance(limitation_rows, list):
        fail("limitations.json lacks limitation rows")
    for row in limitation_rows:
        if not isinstance(row, dict) or not row.get("id") or not row.get("deadline"):
            fail("limitation row lacks id/deadline")
        try:
            deadline = dt.date.fromisoformat(row["deadline"])
        except (TypeError, ValueError):
            fail(f"limitation {row.get('id')} has invalid deadline")
        if effective_date > deadline:
            fail(f"limitation {row['id']} expired on {deadline.isoformat()} (as of {effective_date.isoformat()})")
    freshness = assurance.get("freshness")
    if not isinstance(freshness, dict):
        fail("assurance-inputs.json lacks freshness evidence")
    deadlines = [dt.date.fromisoformat(freeze["valid_through"])]
    if freshness.get("effective_valid_through") != freeze["valid_through"]:
        fail("freeze valid-through disagrees with the effective bound freshness deadline")
    try:
        historical_deadline = dt.date.fromisoformat(freshness["historical_advisory_review_deadline"])
    except (KeyError, TypeError, ValueError):
        fail("historical advisory freshness deadline is invalid")
    deadlines.append(historical_deadline)
    if effective_date > historical_deadline:
        fail(f"historical advisory inventory expired on {historical_deadline.isoformat()}")
    for family, expected_count in (("ledger_evidence", 17), ("threat_models", 11)):
        rows = freshness.get(family)
        if not isinstance(rows, list) or len(rows) != expected_count:
            fail(f"freshness {family} inventory/count is invalid")
        identifiers: set[str] = set()
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"] in identifiers:
                fail(f"freshness {family} contains a missing/duplicate identity")
            identifiers.add(row["id"])
            try:
                reviewed_at = dt.date.fromisoformat(row["reviewed_at"])
                valid_through = dt.date.fromisoformat(row["valid_through"])
            except (KeyError, TypeError, ValueError):
                fail(f"freshness {family}/{row.get('id')} has invalid dates")
            if reviewed_at > effective_date:
                fail(f"freshness {family}/{row['id']} has a future review date")
            if valid_through < reviewed_at:
                fail(f"freshness {family}/{row['id']} expires before review")
            if effective_date > valid_through:
                fail(f"freshness {family}/{row['id']} expired on {valid_through.isoformat()}")
            deadlines.append(valid_through)
    if min(deadlines).isoformat() != freeze["valid_through"]:
        fail("freeze valid-through is not the earliest bound freshness/limitation deadline")
    expected_controls = [
        {"id": "ledger-generator-check", "command_index": 0, "expected_exit": 0, "status": "expected-pass-bound-inputs-not-executed"},
        {"id": "ledger-snapshot-ci", "command_index": 2, "expected_exit": 0, "status": "expected-pass-structural-bound-artifacts"},
        {"id": "ledger-snapshot-release", "command_index": 3, "expected_exit": 1, "status": "expected-reject-snapshot-not-release-evidence"},
        {"id": "ledger-live-ci", "command_index": 4, "expected_exit": None, "status": "blocked-unprovisioned-toolchain"},
        {"id": "ledger-live-release", "command_index": 5, "expected_exit": None, "atomic_blocked_rows": 9298, "status": "blocked-unprovisioned-and-atomic-release-blocked"},
        {"id": "threat-ci", "command_index": 6, "expected_exit": 0, "status": "expected-pass-bound-inputs-not-executed"},
        {"id": "threat-release", "command_index": 7, "expected_exit": 1, "expected_error_count": 44, "status": "expected-fail-release-controls"},
        {"id": "sow-base", "command_index": 9, "expected_exit": 0, "status": "expected-pass-bound-inputs-not-executed"},
        {"id": "sow-issuance", "command_index": 10, "expected_exit": 1, "status": "expected-fail-uncommissioned-unreplayed"},
    ]
    if assurance.get("control_status") != expected_controls:
        fail("assurance control-status expectations drift")
    blockers = freeze["release_gate"]["total_blockers"]
    result = {
        "freeze_id": freeze["freeze_id"],
        "evaluated_as_of": effective_date.isoformat(),
        "freeze_json_sha256": gen.sha256(contents["freeze.json"]),
        "subject_commit": freeze["subject"]["commit"],
        "subject_tree": freeze["subject"]["tree"],
        "mode": mode,
        "release_blockers": blockers,
        "status": "structurally-valid-blocked" if blockers else "valid",
    }
    return result, contents, documents


def _parse_name_status(data: bytes) -> list[tuple[str, str]]:
    fields = [field for field in data.split(b"\0") if field]
    if len(fields) % 2:
        fail("evidence commit name-status output is malformed")
    rows: list[tuple[str, str]] = []
    for offset in range(0, len(fields), 2):
        try:
            status = fields[offset].decode("ascii")
            path = fields[offset + 1].decode("utf-8")
        except UnicodeDecodeError as exc:
            fail(f"evidence commit path/status encoding is invalid: {exc}")
        gen.validate_repo_path(path, label="evidence commit path")
        rows.append((status, path))
    return rows


def _read_committed_evidence(
    evidence_repo: Path,
    bundle: Path,
) -> tuple[str, str, dict[str, bytes]]:
    evidence_head = gen._git(evidence_repo, "rev-parse", "HEAD").decode().strip()
    gen.require_clean_checkout(evidence_repo, evidence_head, label="evidence")
    expected_bundle = gen.lexical_absolute(
        evidence_repo / "assurance" / "audit" / "freezes" / gen.PRODUCTION_FREEZE_ID
    )
    if gen.lexical_absolute(bundle) != expected_bundle:
        fail(f"bundle must be the exact committed evidence path: {expected_bundle}")
    evidence_payload = gen._git(evidence_repo, "cat-file", "commit", evidence_head)
    _evidence_tree, evidence_parents, _evidence_timestamp = gen.parse_commit_identity(
        evidence_payload, label="evidence commit"
    )
    if len(evidence_parents) != 1:
        fail("evidence commit must have exactly one parent")
    parent = evidence_parents[0]
    prefix = f"assurance/audit/freezes/{gen.PRODUCTION_FREEZE_ID}"
    expected_paths = {f"{prefix}/{name}" for name in gen.ALLOWED_BUNDLE_FILES}
    if gen._git(evidence_repo, "ls-tree", "-r", "-z", parent, "--", prefix):
        fail("freeze output path already exists in the subject parent")
    changes = _parse_name_status(
        gen._git(
            evidence_repo, "diff-tree", "--no-commit-id", "--name-status", "-r", "-z",
            "--no-renames", parent, evidence_head,
        )
    )
    if {path for _, path in changes} != expected_paths or any(status != "A" for status, _ in changes):
        fail("evidence commit delta must add only the exact candidate freeze bundle")
    raw_tree = gen._git(evidence_repo, "ls-tree", "-r", "-z", evidence_head, "--", prefix)
    tree_rows: dict[str, tuple[str, str, str]] = {}
    for item in raw_tree.split(b"\0"):
        if not item:
            continue
        try:
            header, raw_path = item.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split()
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            fail(f"evidence commit tree entry is malformed: {exc}")
        if path in tree_rows:
            fail(f"duplicate evidence commit tree path: {path}")
        tree_rows[path] = (mode, kind, oid)
    if set(tree_rows) != expected_paths:
        fail("evidence commit tree does not contain exactly the expected bundle paths")
    committed_contents: dict[str, bytes] = {}
    committed_total = 0
    for name in gen.ALLOWED_BUNDLE_FILES:
        path = f"{prefix}/{name}"
        mode, kind, oid = tree_rows[path]
        if mode != "100644" or kind != "blob" or not gen.HEX40.fullmatch(oid):
            fail(f"evidence bundle entry must be a 100644 regular blob: {path}")
        raw_size = gen._git(evidence_repo, "cat-file", "-s", oid).decode().strip()
        if not raw_size.isdigit() or int(raw_size) > MAX_BUNDLE_FILE_BYTES:
            fail(f"committed evidence bundle entry exceeds its byte limit: {path}")
        committed_total += int(raw_size)
        committed_contents[name] = gen._git(evidence_repo, "cat-file", "blob", oid)
    if committed_total > MAX_BUNDLE_TOTAL_BYTES:
        fail("committed evidence bundle exceeds aggregate byte limit")
    for option, forbidden in (("-v", lambda tag: tag.islower()), ("-t", lambda tag: tag == "S")):
        records = [item for item in gen._git(evidence_repo, "ls-files", option, "-z", "--", prefix).split(b"\0") if item]
        if len(records) != len(expected_paths):
            fail("evidence index inventory differs from the committed bundle")
        for record in records:
            tag = chr(record[0])
            if forbidden(tag):
                fail("evidence index uses assume-unchanged or skip-worktree flags")
    worktree_contents = safe_bundle_files(bundle)
    for name in gen.ALLOWED_BUNDLE_FILES:
        if committed_contents[name] != worktree_contents[name]:
            fail(f"evidence worktree bytes differ from the committed blob: {prefix}/{name}")
    return evidence_head, parent, committed_contents


def _verify_bundle_internal(
    evidence_repo: Path,
    subject_repo: Path,
    bundle: Path,
    *,
    provision: Path | None = None,
    mode: str = "structural",
    as_of: dt.date | None = None,
) -> dict[str, Any]:
    gen.require_isolated_python()
    gen.require_documented_sandbox_runtime()
    evidence_repo = gen.repository_root(evidence_repo)
    subject_repo = gen.repository_root(subject_repo)
    if evidence_repo == subject_repo:
        fail("evidence and subject must be separate clean checkouts")
    expected_bundle = gen.lexical_absolute(
        evidence_repo / "assurance" / "audit" / "freezes" / gen.PRODUCTION_FREEZE_ID
    )
    if gen.lexical_absolute(bundle) != expected_bundle:
        fail(f"bundle must be the exact committed evidence path: {expected_bundle}")
    evidence_head, subject, contents = _read_committed_evidence(evidence_repo, bundle)
    if provision is not None:
        external_handoff = gen.read_exact_directory_files(
            gen.lexical_absolute(provision), gen.PROVISIONING_HANDOFF_FILES
        )
        embedded_handoff = {
            "PROVISIONING-MANIFEST.json": contents["PROVISIONING-MANIFEST.json"],
            "SHA256SUMS": contents["PROVISIONING-SHA256SUMS"],
        }
        gen.validate_provisioning_handoff_contents(external_handoff, embedded_handoff)
    result, contents, documents = _verify_bundle_documents(
        bundle, mode=mode, as_of=as_of, contents=contents
    )
    freeze = documents["freeze.json"]
    if subject != freeze["subject"]["commit"]:
        fail("evidence parent and freeze subject disagree")
    gen.require_clean_checkout(subject_repo, subject, label="subject replay")
    _, subject_tree = gen.validate_exact_subject(subject_repo, subject)
    if subject_tree != freeze["subject"]["tree"]:
        fail("subject replay tree disagrees with freeze")
    for repo, label in ((evidence_repo, "evidence"), (subject_repo, "subject replay")):
        commit_payload = gen._git(repo, "cat-file", "commit", subject)
        tree_payload = gen._git(repo, "cat-file", "tree", subject_tree)
        if gen.sha256(commit_payload) != freeze["subject"]["commit_payload_sha256"]:
            fail(f"{label} subject commit payload digest disagrees with freeze")
        if gen.sha256(tree_payload) != freeze["subject"]["tree_payload_sha256"]:
            fail(f"{label} subject tree payload digest disagrees with freeze")
    expected = gen.build_bundle_bytes(subject_repo, subject)
    if set(expected) != set(contents):
        fail("regenerated bundle file set differs")
    for name in sorted(expected):
        if expected[name] != contents[name]:
            fail(f"independent deterministic regeneration differs: {name}")
    if gen._git(evidence_repo, "rev-parse", "HEAD").decode().strip() != evidence_head:
        fail("evidence HEAD changed during verification")
    if gen._git(subject_repo, "rev-parse", "HEAD").decode().strip() != subject:
        fail("subject HEAD changed during verification")
    gen.require_clean_checkout(evidence_repo, evidence_head, label="evidence final")
    gen.require_clean_checkout(subject_repo, subject, label="subject replay final")
    blockers = result["release_blockers"]
    if mode == "release" and blockers:
        if blockers != EXPECTED_RELEASE_BLOCKERS:
            fail(
                "release blocker count drift cannot use the validated-blocked exit: "
                f"{blockers} != {EXPECTED_RELEASE_BLOCKERS}"
            )
        raise ReleaseBlockedError(blockers)
    if mode == "replay":
        if blockers:
            fail(f"replay verification rejected {blockers} unresolved blockers")
        if documents["freeze.json"]["generated_evidence_status"] != "independently-replayed":
            fail("replay verification requires independently replayed evidence")
    return {
        **result,
        "evidence_commit": evidence_head,
        "evidence_parent": subject,
    }


def validate_verification_cli_paths(
    evidence_repo: Path, subject_repo: Path, bundle: Path, provision: Path,
) -> None:
    if gen.lexical_absolute(evidence_repo) != Path("/evidence"):
        fail("production verification --repo must be the exact sandbox mapping /evidence")
    if gen.lexical_absolute(subject_repo) != Path("/dcrypt"):
        fail("production verification --subject-repo must be the exact sandbox mapping /dcrypt")
    expected_bundle = Path("/evidence/assurance/audit/freezes") / gen.PRODUCTION_FREEZE_ID
    if gen.lexical_absolute(bundle) != expected_bundle:
        fail(f"production verification --bundle must be exactly {expected_bundle}")
    if gen.lexical_absolute(provision) != Path("/provision"):
        fail("production verification --provision must be the exact read-only mapping /provision")


def reject_backdated_verification(as_of: dt.date | None) -> None:
    today = dt.datetime.now(dt.timezone.utc).date()
    if as_of is not None and as_of < today:
        fail("verification as-of may move forward for expiry testing but may not backdate UTC today")


def verify_bundle(
    evidence_repo: Path,
    subject_repo: Path,
    bundle: Path,
    *,
    provision: Path,
    mode: str = "structural",
    as_of: dt.date | None = None,
) -> dict[str, Any]:
    """Verify only through the exact production two-checkout sandbox contract."""

    gen.require_isolated_python()
    reject_backdated_verification(as_of)
    gen.require_documented_sandbox_runtime(require_evidence=True, require_provision=True)
    validate_verification_cli_paths(evidence_repo, subject_repo, bundle, provision)
    return _verify_bundle_internal(
        evidence_repo, subject_repo, bundle, provision=provision, mode=mode, as_of=as_of
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--subject-repo", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--provision", type=Path)
    parser.add_argument("--mode", choices=("structural", "release", "replay"), default="structural")
    parser.add_argument("--as-of", type=dt.date.fromisoformat)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        try:
            gen.require_isolated_python()
            gen.require_documented_sandbox_runtime(require_empty_output=True)
        except gen.FreezeError as exc:
            print(f"audit-freeze self-test preflight failed: {exc}", file=sys.stderr)
            return 1
        script = Path(__file__).with_name("audit-freeze-selftest.py")
        child_environment = {
            key: value
            for key, value in {
                "DCRYPT_AUDIT_SANDBOX": "unshare-all-v1",
                "DCRYPT_AUDIT_OPERATION": "selftest",
                "CARGO_HOME": "/cargo",
                "CARGO_INCREMENTAL": "0",
                "CARGO_NET_OFFLINE": "true",
                "HOME": "/nonexistent",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PWD": "/dcrypt",
                "SOURCE_DATE_EPOCH": os.environ.get("SOURCE_DATE_EPOCH", ""),
                "TZ": "UTC",
            }.items()
            if os.environ.get(key) == value
        }
        if len(child_environment) != 11:
            print("audit-freeze self-test requires the exact documented sandbox environment", file=sys.stderr)
            return 1
        return subprocess.call(
            ["/usr/bin/python3.12", "-I", "-B", "-S", str(script)], env=child_environment
        )
    if args.bundle is None:
        parser.error("--bundle is required unless --self-test is used")
    if args.subject_repo is None:
        parser.error("--subject-repo is required unless --self-test is used")
    if args.provision is None:
        parser.error("--provision is required unless --self-test is used")
    try:
        gen.require_isolated_python()
        reject_backdated_verification(args.as_of)
        gen.require_documented_sandbox_runtime(require_evidence=True, require_provision=True)
        validate_verification_cli_paths(args.repo, args.subject_repo, args.bundle, args.provision)
        result = verify_bundle(
            args.repo, args.subject_repo, args.bundle, provision=args.provision,
            mode=args.mode, as_of=args.as_of,
        )
        print(
            f"verified {result['freeze_id']} mode={result['mode']} "
            f"status={result['status']} blockers={result['release_blockers']}"
        )
        print(f"evaluated_as_of={result['evaluated_as_of']}")
        print(f"freeze.json sha256={result['freeze_json_sha256']}")
        print(f"subject={result['subject_commit']} tree={result['subject_tree']}")
        return 0
    except ReleaseBlockedError as exc:
        print(
            "audit-freeze release blocked after complete structural validation: "
            f"blockers={exc.blockers}",
            file=sys.stderr,
        )
        return RELEASE_BLOCKED_EXIT
    except gen.FreezeError as exc:
        print(f"audit-freeze verification failed: {exc}", file=sys.stderr)
        return verification_failure_exit_code(exc)


if __name__ == "__main__":
    raise SystemExit(main())
