#!/usr/bin/env python3
"""Adversarial self-tests for Package D's structural and capture contracts."""

from __future__ import annotations

import copy
import ast
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True

import capture
import model
import verify


def _expect_failure(
    function: Callable[..., Any],
    *args: Any,
    exceptions: tuple[type[BaseException], ...] = (model.PackageDError,),
    **kwargs: Any,
) -> None:
    try:
        function(*args, **kwargs)
    except exceptions:
        return
    raise AssertionError(f"negative control unexpectedly passed: {function.__name__}")


def _candidate(role: str, profile_id: str | None = None) -> dict[str, Any]:
    role_artifact_fields = model.ROLE_ARTIFACT_FIELDS[role]
    artifact_fields = {
        **model.COMMON_ARTIFACT_FIELDS,
        **role_artifact_fields,
    }
    artifacts = [
        {
            "path": path,
            "sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
            "size": len(path.encode("utf-8")),
        }
        for path in sorted(artifact_fields)
    ]
    artifact_digests = {
        field: next(row["sha256"] for row in artifacts if row["path"] == path)
        for path, field in artifact_fields.items()
    }
    role_digests = {field: artifact_digests[field] for field in role_artifact_fields.values()}
    profile_id = profile_id or (
        model.ROLE_PROFILES[role][0]
        if role in model.ROLE_PROFILES
        else f"schema-only-{role}-v1"
    )
    role_fields: dict[str, dict[str, Any]] = {
        "local-control": {
            **role_digests,
            "control_id": "local-01",
            "execution_count": 1,
            "result_class": "informational",
        },
        "dedicated-timing": {
            **role_digests,
            "class_balance": "1",
            "negative_control_findings": 0,
            "positive_control_detected": True,
            "sample_count": 2,
            "target_triple": "aarch64-unknown-linux-gnu",
        },
        "secret-taint": {
            **role_digests,
            "address_event_count": 0,
            "branch_event_count": 0,
            "negative_control_findings": 0,
            "positive_control_detected": True,
            "taint_kind": "address",
            "unresolved_event_count": 0,
        },
        "compiler-inventory": {
            **role_digests,
            "emission_count": 1,
            "indirect_target_count": 0,
            "target_triple": "x86_64-unknown-linux-gnu",
            "transitive_closure_complete": False,
            "unresolved_edge_count": 1,
        },
        "platform-runtime": {
            **role_digests,
            "lifecycle_event_count": 1,
            "negative_control_findings": 0,
            "platform": "linux-x86_64",
            "positive_control_detected": True,
        },
        "physical": {
            **role_digests,
            "device_profile": "schema-only-template",
            "trace_count": 1,
        },
        "external-attestation": {**role_digests},
        "acceptance": {
            **role_digests,
            "acceptance_decision": "unreviewed-template",
        },
    }
    if role in model.ROLE_PROFILE_CONTRACTS:
        contract = model.ROLE_PROFILE_CONTRACTS[role][profile_id]
        if role == "dedicated-timing":
            role_fields[role]["target_triple"] = contract["target_triple"]
        elif role == "secret-taint":
            role_fields[role]["taint_kind"] = contract["taint_kind"]
    return {
        "artifact_role": role,
        "artifacts": artifacts,
        "binding": {
            "binary_sha256": artifact_digests["binary_sha256"],
            "build_sha256": artifact_digests["build_sha256"],
            "compiler_sha256": artifact_digests["compiler_sha256"],
            "profile_sha256": (
                model.profile_sha256(role, profile_id)
                if role in model.ROLE_PROFILES
                else "4" * 64
            ),
            "r_commit": model.SUBJECT_COMMIT,
            "r_tree": model.SUBJECT_TREE,
            "source_set_sha256": model.EXPECTED_SOURCE_ROWS_SHA256,
            "subject_manifest_sha256": model.SUBJECT_MANIFEST_SHA256,
            "tool_sha256": artifact_digests["tool_sha256"],
        },
        "content_policy": "dcrypt-package-d-candidate-bundle-v1",
        "environment_sha256": artifact_digests["environment_sha256"],
        "promotion_eligible": False,
        "profile_id": profile_id,
        "raw_artifact_set_sha256": model.artifact_set_sha256(artifacts),
        "schema_version": 1,
        "session_id": "selftest-session",
        "status": "collected-unreviewed",
        "tool_argv_sha256": artifact_digests["tool_argv_sha256"],
        **role_fields[role],
    }


def _write_bundle(root: Path, candidate: dict[str, Any]) -> None:
    root.mkdir(mode=0o700)
    (root / "candidate.json").write_bytes(model.canonical_json(candidate))
    os.chmod(root / "candidate.json", 0o600)
    for artifact in candidate["artifacts"]:
        path = root / artifact["path"]
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(artifact["path"].encode("utf-8"))
        os.chmod(path, 0o600)


def _load_rebind() -> Any:
    path = model.FRAMEWORK / "rebind-final-subject.py"
    spec = importlib.util.spec_from_file_location("dcrypt_package_d_rebind_selftest", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    controls = 0
    package = model.build_package_document()
    verify.verify_structural()
    artifacts_raw, _metadata = model.read_regular(
        model.FRAMEWORK / "ARTIFACTS.json", label="selftest artifact manifest"
    )
    artifacts_document = model.parse_json(
        artifacts_raw, label="selftest artifact manifest", require_canonical=True
    )
    verify.validate_artifact_document(artifacts_document)
    for mutation in ("missing", "surplus", "self", "digest", "mode"):
        changed_artifacts = copy.deepcopy(artifacts_document)
        if mutation == "missing":
            changed_artifacts["files"].pop()
        elif mutation == "surplus":
            changed_artifacts["files"].append(
                {
                    "git_mode": "100644", "kind": "reviewed-source", "path": "surplus",
                    "sha256": "0" * 64, "size": 0,
                }
            )
        elif mutation == "self":
            changed_artifacts["files"].append(
                {
                    "git_mode": "100644", "kind": "generated", "path": "ARTIFACTS.json",
                    "sha256": "0" * 64, "size": 0,
                }
            )
            changed_artifacts["files"].sort(key=lambda row: row["path"])
        elif mutation == "digest":
            changed_artifacts["files"][0]["sha256"] = "0" * 64
        else:
            changed_artifacts["files"][0]["git_mode"] = "100755"
        _expect_failure(verify.validate_artifact_document, changed_artifacts)
        controls += 1
    schema = model.build_evidence_schema()
    for role in model.CAPTURE_ROLES:
        candidate = _candidate(role)
        model.validate_schema_value(candidate, schema, root=schema, label="candidate")
        controls += 1
        if role in model.ROLE_PROFILES:
            model.validate_evidence_candidate(candidate, schema)
            controls += 1
        else:
            _expect_failure(model.validate_evidence_candidate, candidate, schema)
            controls += 1
        extra = copy.deepcopy(candidate)
        extra["cross_role_field"] = True
        _expect_failure(model.validate_evidence_candidate, extra, schema)
        controls += 1
        missing = copy.deepcopy(candidate)
        del missing["promotion_eligible"]
        _expect_failure(model.validate_evidence_candidate, missing, schema)
        controls += 1
    for role in ("dedicated-timing", "secret-taint"):
        for profile_id in model.ROLE_PROFILES[role][1:]:
            model.validate_evidence_candidate(_candidate(role, profile_id), schema)
            controls += 1
    for mutation in (
        "timing-positive",
        "timing-negative",
        "timing-target",
        "timing-balance",
        "taint-positive",
        "taint-negative",
        "taint-kind",
    ):
        role = "dedicated-timing" if mutation.startswith("timing") else "secret-taint"
        changed_control = _candidate(role)
        if mutation.endswith("positive"):
            changed_control["positive_control_detected"] = False
        elif mutation.endswith("negative"):
            changed_control["negative_control_findings"] = 1
        elif mutation == "timing-target":
            changed_control["target_triple"] = "x86_64-unknown-linux-gnu"
        elif mutation == "timing-balance":
            changed_control["class_balance"] = "0.5"
        else:
            changed_control["taint_kind"] = "branch"
        _expect_failure(model.validate_evidence_candidate, changed_control, schema)
        controls += 1
    unknown = _candidate("local-control")
    unknown["artifact_role"] = "unknown"
    _expect_failure(model.validate_evidence_candidate, unknown, schema)
    controls += 1
    promoted = _candidate("local-control")
    promoted["promotion_eligible"] = True
    _expect_failure(model.validate_evidence_candidate, promoted, schema)
    controls += 1
    for mutation in ("profile", "artifact-set", "source-set", "role-artifact"):
        changed_binding = _candidate("dedicated-timing")
        if mutation == "profile":
            changed_binding["binding"]["profile_sha256"] = "0" * 64
        elif mutation == "artifact-set":
            changed_binding["raw_artifact_set_sha256"] = "0" * 64
        elif mutation == "source-set":
            changed_binding["binding"]["source_set_sha256"] = "0" * 64
        else:
            changed_binding["raw_samples_sha256"] = "0" * 64
        _expect_failure(model.validate_evidence_candidate, changed_binding, schema)
        controls += 1
    boolean_integer = _candidate("local-control")
    boolean_integer["execution_count"] = True
    _expect_failure(model.validate_evidence_candidate, boolean_integer, schema)
    controls += 1
    zero_integer = _candidate("local-control")
    zero_integer["execution_count"] = 0
    _expect_failure(model.validate_evidence_candidate, zero_integer, schema)
    controls += 1
    bad_ref = copy.deepcopy(schema)
    bad_ref["oneOf"] = [{"$ref": "https://example.invalid/schema"}]
    _expect_failure(model.validate_evidence_candidate, _candidate("local-control"), bad_ref)
    controls += 1
    recursive = copy.deepcopy(schema)
    recursive["$defs"]["loop"] = {"$ref": "#/$defs/loop"}
    recursive["oneOf"] = [{"$ref": "#/$defs/loop"}]
    _expect_failure(model.validate_evidence_candidate, _candidate("local-control"), recursive)
    controls += 1
    ambiguous = copy.deepcopy(schema)
    ambiguous["oneOf"] = [copy.deepcopy(ambiguous["oneOf"][0]), copy.deepcopy(ambiguous["oneOf"][0])]
    _expect_failure(model.validate_evidence_candidate, _candidate("local-control"), ambiguous)
    controls += 1
    _expect_failure(model.parse_json, b'{"a":1,"a":2}\n', label="duplicate")
    controls += 1
    _expect_failure(model.parse_json, b'{"a":1.0}\n', label="float")
    controls += 1
    _expect_failure(model.parse_json, '{"a":"e\u0301"}\n'.encode(), label="NFC")
    controls += 1
    _expect_failure(model.parse_json, b'{"b":1,"a":2}\n', label="canonical", require_canonical=True)
    controls += 1

    missing_row = copy.deepcopy(package)
    missing_row["atomic_inventory"]["rows"].pop()
    _expect_failure(model.validate_package_document, missing_row)
    controls += 1
    duplicate_row = copy.deepcopy(package)
    duplicate_row["atomic_inventory"]["rows"][-1] = copy.deepcopy(duplicate_row["atomic_inventory"]["rows"][0])
    _expect_failure(model.validate_package_document, duplicate_row)
    controls += 1
    surplus_row = copy.deepcopy(package)
    surplus_row["atomic_inventory"]["rows"].append(copy.deepcopy(surplus_row["atomic_inventory"]["rows"][-1]))
    surplus_row["atomic_inventory"]["rows"][-1]["row_id"] = "surplus-row"
    _expect_failure(model.validate_package_document, surplus_row)
    controls += 1
    substituted_row = copy.deepcopy(package)
    substituted_row["atomic_inventory"]["rows"][0]["row_id"] = "substituted-row"
    _expect_failure(model.validate_package_document, substituted_row)
    controls += 1
    promoted_row = copy.deepcopy(package)
    promoted_row["atomic_inventory"]["rows"][0]["promotion_eligible"] = True
    _expect_failure(model.validate_package_document, promoted_row)
    controls += 1
    missing_source = copy.deepcopy(package)
    missing_source["source_inventory"]["files"].pop()
    _expect_failure(model.validate_package_document, missing_source)
    controls += 1
    surplus_source = copy.deepcopy(package)
    surplus_source["source_inventory"]["files"].append(copy.deepcopy(surplus_source["source_inventory"]["files"][-1]))
    surplus_source["source_inventory"]["files"][-1]["path"] = "crates/surplus/src/lib.rs"
    _expect_failure(model.validate_package_document, surplus_source)
    controls += 1
    substituted_source = copy.deepcopy(package)
    substituted_source["source_inventory"]["files"][0]["path"] = "outside/src/lib.rs"
    _expect_failure(model.validate_package_document, substituted_source)
    controls += 1
    traced_source = copy.deepcopy(package)
    traced_source["source_inventory"]["files"][0]["transitive_closure_complete"] = True
    _expect_failure(model.validate_package_document, traced_source)
    controls += 1
    promoted_timing = copy.deepcopy(package)
    promoted_timing["local_timing_controls"][0]["dedicated_host"] = True
    _expect_failure(model.validate_package_document, promoted_timing)
    controls += 1
    for field in ("dudect", "fixed_vs_random", "promotion_eligible"):
        relabeled_timing = copy.deepcopy(package)
        relabeled_timing["local_timing_controls"][0][field] = True
        _expect_failure(model.validate_package_document, relabeled_timing)
        controls += 1
    missing_taint = copy.deepcopy(package)
    missing_taint["taint_profiles"].pop()
    _expect_failure(model.validate_package_document, missing_taint)
    controls += 1
    duplicate_taint = copy.deepcopy(package)
    duplicate_taint["taint_profiles"][1] = copy.deepcopy(duplicate_taint["taint_profiles"][0])
    _expect_failure(model.validate_package_document, duplicate_taint)
    controls += 1
    physical_pass = copy.deepcopy(package)
    physical_pass["physical_policy"]["status"] = "pass"
    _expect_failure(model.validate_package_document, physical_pass)
    controls += 1
    compiler_promoted = copy.deepcopy(package)
    compiler_promoted["compiler_controls"][0]["accepted_for_transitive_closure"] = True
    _expect_failure(model.validate_package_document, compiler_promoted)
    controls += 1
    for mutation in ("missing", "surplus", "compiler"):
        changed_compiler = copy.deepcopy(package)
        if mutation == "missing":
            changed_compiler["compiler_controls"].pop()
        elif mutation == "surplus":
            changed_compiler["compiler_controls"].append(copy.deepcopy(changed_compiler["compiler_controls"][-1]))
        else:
            changed_compiler["compiler_controls"][0]["compiler_identity"] = "moving-nightly"
        _expect_failure(model.validate_package_document, changed_compiler)
        controls += 1
    for key, value in package["counts"].items():
        changed_count = copy.deepcopy(package)
        changed_count["counts"][key] = value + 1
        _expect_failure(model.validate_package_document, changed_count)
        controls += 1
    for section, key in (
        ("subject_binding", "source_commit"),
        ("input_bindings", None),
        ("evidence_policy", "roles_are_orthogonal"),
        ("capture_contract", "promotion_enabled"),
        ("lifecycle_policy", "status"),
        ("physical_policy", "active_profiles"),
    ):
        changed_semantic = copy.deepcopy(package)
        if section == "input_bindings":
            changed_semantic[section][0]["sha256"] = "0" * 64
        elif section == "subject_binding":
            changed_semantic[section][key] = "0" * 40
        elif section == "physical_policy":
            changed_semantic[section][key] = ["fabricated-profile"]
        elif section == "lifecycle_policy":
            changed_semantic[section][key] = "complete"
        else:
            changed_semantic[section][key] = not changed_semantic[section][key]
        _expect_failure(model.validate_package_document, changed_semantic)
        controls += 1
    for section, key in (
        ("local_timing_controls", "name"),
        ("local_timing_controls", "case_id"),
        ("dedicated_timing_profiles", "stopping_policy"),
        ("dedicated_timing_profiles", "target_triple"),
        ("taint_profiles", "positive_control"),
        ("taint_profiles", "negative_control"),
    ):
        changed_profile = copy.deepcopy(package)
        changed_profile[section][0][key] = "mutated"
        _expect_failure(model.validate_package_document, changed_profile)
        controls += 1
    missing_blocker = copy.deepcopy(package)
    missing_blocker["release_blockers"].pop()
    _expect_failure(model.validate_package_document, missing_blocker)
    controls += 1

    capture_raw, _capture_metadata = model.read_regular(
        model.FRAMEWORK / "capture.py", label="capture source AST"
    )
    capture_tree = ast.parse(capture_raw.decode("utf-8"), filename="capture.py")
    forbidden_imports = {"http", "requests", "socket", "subprocess", "urllib"}
    for node in ast.walk(capture_tree):
        if isinstance(node, ast.Import):
            assert not ({alias.name.split(".")[0] for alias in node.names} & forbidden_imports)
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in forbidden_imports
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert not (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr in {"execv", "execve", "popen", "posix_spawn", "posix_spawnp", "system"}
            )
    controls += 1

    rebind = _load_rebind()
    rebind.validate_changed_paths(list(rebind.CHANGED_PATHS))
    for mutation in (
        list(rebind.CHANGED_PATHS)[1:],
        [*rebind.CHANGED_PATHS, "assurance/surplus"],
        list(reversed(rebind.CHANGED_PATHS)),
    ):
        _expect_failure(
            rebind.validate_changed_paths,
            mutation,
            exceptions=(rebind.RebindError,),
        )
        controls += 1
    c_raw = __import__("subprocess").run(
        [
            sys.executable, "-B", "assurance/fuzzing/rebind-final-subject.py",
            "--package-d-projection", "--expected-r-commit", rebind.R_COMMIT,
            "--expected-r-tree", rebind.R_TREE,
        ],
        cwd=model.REPO,
        capture_output=True,
        check=True,
    ).stdout
    c_projection = rebind._parse_c_projection(c_raw)
    rebind._verify_c_projection_rows(c_projection, revision=None)
    c_missing = copy.deepcopy(c_projection)
    c_missing["changed_files"].pop()
    c_missing["projection_sha256"] = rebind._sha(rebind._canonical({key: value for key, value in c_missing.items() if key != "projection_sha256"}))
    _expect_failure(
        rebind._parse_c_projection,
        rebind._canonical(c_missing),
        exceptions=(rebind.RebindError,),
    )
    controls += 1
    c_invariant = copy.deepcopy(c_projection)
    c_invariant["invariant_files"][0]["sha256"] = "0" * 64
    c_invariant["projection_sha256"] = rebind._sha(rebind._canonical({key: value for key, value in c_invariant.items() if key != "projection_sha256"}))
    rebound = rebind._parse_c_projection(rebind._canonical(c_invariant))
    _expect_failure(
        rebind._verify_c_projection_rows,
        rebound,
        revision=None,
        exceptions=(rebind.RebindError,),
    )
    controls += 1

    with tempfile.TemporaryDirectory(prefix="dcrypt-package-d-selftest-") as directory:
        private = Path(directory)
        os.chmod(private, 0o700)
        destinations = private / "destinations"
        destinations.mkdir(mode=0o700)
        source = private / "source"
        destination = destinations / "captured"
        candidate = _candidate("local-control")
        _write_bundle(source, candidate)
        double_slash_source = Path("//" + source.as_posix().lstrip("/"))
        _expect_failure(
            capture.capture,
            double_slash_source,
            destinations / "double-slash-captured",
        )
        controls += 1
        alias_source = destinations / "same-parent-source"
        _write_bundle(alias_source, _candidate("local-control"))
        _expect_failure(
            capture.capture,
            alias_source,
            destinations / "same-parent-captured",
        )
        controls += 1
        result = capture.capture(source, destination)
        assert result["promotion_eligible"] is False and destination.is_dir()
        assert stat.S_IMODE(destination.stat().st_mode) == 0o700
        controls += 1
        _expect_failure(capture.capture, source, destination)
        controls += 1
        rollback_source = private / "rollback-source"
        rollback_destination = destinations / "rollback-captured"
        _write_bundle(rollback_source, _candidate("local-control"))
        original_destination_verify = capture._verify_destination_tree
        verify_calls = 0

        def fail_after_publication(*args: Any, **kwargs: Any) -> None:
            nonlocal verify_calls
            verify_calls += 1
            original_destination_verify(*args, **kwargs)
            if verify_calls == 2:
                raise model.PackageDError("injected post-publication verification failure")

        capture._verify_destination_tree = fail_after_publication
        try:
            _expect_failure(capture.capture, rollback_source, rollback_destination)
        finally:
            capture._verify_destination_tree = original_destination_verify
        assert verify_calls == 2 and not os.path.lexists(rollback_destination)
        assert not any(
            path.name.startswith(".dcrypt-package-d-capture-")
            for path in destinations.iterdir()
        )
        controls += 1
        bad_digest_source = private / "bad-digest"
        bad_digest = _candidate("local-control")
        bad_digest["artifacts"][0]["sha256"] = "0" * 64
        _write_bundle(bad_digest_source, bad_digest)
        _expect_failure(capture.capture, bad_digest_source, destinations / "bad-digest-captured")
        controls += 1
        bad_size_source = private / "bad-size"
        bad_size = _candidate("local-control")
        bad_size["artifacts"][0]["size"] = 2
        _write_bundle(bad_size_source, bad_size)
        _expect_failure(capture.capture, bad_size_source, destinations / "bad-size-captured")
        controls += 1
        wrong_mode_source = private / "wrong-mode"
        wrong_mode_candidate = _candidate("local-control")
        wrong_mode_path = wrong_mode_candidate["artifacts"][0]["path"]
        _write_bundle(wrong_mode_source, wrong_mode_candidate)
        os.chmod(wrong_mode_source / wrong_mode_path, 0o640)
        _expect_failure(capture.capture, wrong_mode_source, destinations / "wrong-mode-captured")
        controls += 1
        traversal_source = private / "traversal"
        traversal = _candidate("local-control")
        traversal["artifacts"][0]["path"] = "../raw.bin"
        _expect_failure(model.validate_evidence_candidate, traversal)
        controls += 1
        physical_source = private / "physical"
        _write_bundle(physical_source, _candidate("physical"))
        _expect_failure(capture.capture, physical_source, destinations / "physical-captured")
        controls += 1
        acceptance_source = private / "acceptance"
        _write_bundle(acceptance_source, _candidate("acceptance"))
        _expect_failure(capture.capture, acceptance_source, destinations / "acceptance-captured")
        controls += 1
        hardlink_source = private / "hardlink"
        hardlink_candidate = _candidate("local-control")
        hardlink_path = hardlink_candidate["artifacts"][0]["path"]
        _write_bundle(hardlink_source, hardlink_candidate)
        os.unlink(hardlink_source / hardlink_path)
        external = private / "external"
        external.write_bytes(hardlink_path.encode("utf-8"))
        os.chmod(external, 0o600)
        os.link(external, hardlink_source / hardlink_path)
        _expect_failure(capture.capture, hardlink_source, destinations / "hardlink-captured")
        controls += 1
        symlink_source = private / "symlink"
        symlink_candidate = _candidate("local-control")
        symlink_path = symlink_candidate["artifacts"][0]["path"]
        _write_bundle(symlink_source, symlink_candidate)
        os.unlink(symlink_source / symlink_path)
        (symlink_source / symlink_path).symlink_to(external)
        _expect_failure(capture.capture, symlink_source, destinations / "symlink-captured")
        controls += 1
        fifo_source = private / "fifo"
        fifo_candidate = _candidate("local-control")
        fifo_path = fifo_candidate["artifacts"][0]["path"]
        _write_bundle(fifo_source, fifo_candidate)
        os.unlink(fifo_source / fifo_path)
        os.mkfifo(fifo_source / fifo_path, 0o600)
        _expect_failure(capture.capture, fifo_source, destinations / "fifo-captured")
        controls += 1
        candidate_fifo_source = private / "candidate-fifo"
        candidate_fifo_source.mkdir(mode=0o700)
        os.mkfifo(candidate_fifo_source / "candidate.json", 0o600)
        _expect_failure(
            capture.capture,
            candidate_fifo_source,
            destinations / "candidate-fifo-captured",
        )
        controls += 1
        git_source = private / "git-source"
        bad_git = _candidate("local-control")
        bad_git["artifacts"][0]["path"] = ".git/config"
        _expect_failure(model.validate_evidence_candidate, bad_git)
        controls += 1
        malformed_records = (
            b'{"a":1,"a":2}\n',
            b'{"schema_version":1.0}\n',
            '{"name":"e\u0301"}\n'.encode("utf-8"),
            b'{"b":1,"a":2}\n',
        )
        for index, candidate_raw in enumerate(malformed_records):
            malformed_source = private / f"malformed-{index}"
            malformed_source.mkdir(mode=0o700)
            (malformed_source / "candidate.json").write_bytes(candidate_raw)
            os.chmod(malformed_source / "candidate.json", 0o600)
            _expect_failure(
                capture.capture,
                malformed_source,
                destinations / f"malformed-{index}-captured",
            )
            controls += 1

    print(f"Package D self-test passed: {controls} adversarial controls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
