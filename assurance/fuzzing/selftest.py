#!/usr/bin/env python3
"""Adversarial selftests for Package C fail-closed controls."""

from __future__ import annotations

import copy
import datetime as dt
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

from compiler_probe import (
    FUZZ_BUILD_LINKER_WRAPPER_SOURCE,
    PINNED_SANITIZER_RUNTIME_SHA256,
    PINNED_RUSTC_VERSION,
    _defined_function_symbol_row,
    _strict_json_file,
    _validate_cargo_fuzz_install_records,
    _validate_exact_candidates,
    _resolve_discovery_executable,
    _require_stable_metadata,
    _select_exact_pinned_executable,
    _snapshot_home_file,
    _snapshot_home_tree,
    _validate_host_tool_identity,
    _validate_snapshot_source_metadata,
    _verify_cargo_fuzz_source,
    pinned_cargo_tools,
    pinned_toolchain,
    verify_binary_symbol,
    verify_fuzz_linker_log,
)
from crash_lifecycle import (
    build_crash_bundle_template,
    build_lifecycle_requirements,
    crash_cluster_id,
    validate_crash_bundle,
    validate_live_source_binding,
    validate_lifecycle_requirements,
)
from fuzzing_lib import (
    FRAMEWORK_DIR,
    INTEGRATED_ASAN_FUNCTION_SYMBOLS,
    INTEGRATED_ASAN_OPTIONS,
    REPO_ROOT,
    FuzzingError,
    aggregate_core_seconds,
    authorize_authoritative_corpus_write,
    authorize_private_crash_store_write,
    bounded_rejection_fixture,
    budget_ok,
    build_corpus_manifest,
    build_campaign_status,
    build_registry,
    build_sanitizer_controls,
    canonical_fuzz_argv,
    canonical_git_mode,
    canonical_json,
    canonical_nonexecutable_mode,
    coverage_regressed,
    freshness_ok,
    parse_canonical_lines,
    parse_json,
    parse_target_listing,
    sanitizer_report_matches,
    select_changed_rows,
    select_changed_paths,
    source_input_cap,
    validate_sanitizer_assignment,
    verify_fuzz_argv,
    validate_campaign_status,
    validate_bootstrap_subject_provenance,
    validate_corpus_manifest,
    validate_control_source_binding_rows,
    validate_operational_corpus_object,
)
from schemas import assert_all_data_objects_closed, closed_schema, crash_bundle_schema
from sanitizer_positive import build_control_requirements, validate_control_requirements
from importlib.util import module_from_spec, spec_from_file_location


def expect_failure(function, *args, **kwargs) -> None:
    try:
        function(*args, **kwargs)
    except (FuzzingError, RuntimeError, ValueError):
        return
    raise AssertionError(f"negative control unexpectedly passed: {function.__name__}")


def harness(body: str) -> bytes:
    return (
        "#![no_main]\nconst INPUT_MAX: usize = 4096;\nuse libfuzzer_sys::fuzz_target;\n"
        + body
    ).encode()


def main() -> int:
    tests = 0

    def checked(function, *args, **kwargs):
        nonlocal tests
        expect_failure(function, *args, **kwargs)
        tests += 1

    runner_spec = spec_from_file_location("dcrypt_fuzz_smoke_selftest", FRAMEWORK_DIR / "run-fuzz-smoke.py")
    assert runner_spec is not None and runner_spec.loader is not None
    runner_module = module_from_spec(runner_spec)
    runner_spec.loader.exec_module(runner_module)
    rebind_spec = spec_from_file_location(
        "dcrypt_fuzz_rebind_selftest", FRAMEWORK_DIR / "rebind-final-subject.py"
    )
    assert rebind_spec is not None and rebind_spec.loader is not None
    rebind_module = module_from_spec(rebind_spec)
    sys.modules[rebind_spec.name] = rebind_module
    rebind_spec.loader.exec_module(rebind_module)
    package_e_r = "276b78f9b3c2aed91d2548ab9add721c434ded06"
    package_e_tree = "c47c98062c43463818bb61bd3eed75ebaf189e1d"
    package_e = rebind_module.package_e_projection(
        expected_r_commit=package_e_r,
        expected_r_tree=package_e_tree,
    )
    assert set(package_e) == {
        "binding_assignments", "candidate_commit", "changed_files", "content_policy",
        "counts", "invariant_files", "projection_sha256", "r_commit", "r_tree",
        "schema_version", "subject_manifest_sha256",
    }
    assert package_e["candidate_commit"] is None
    assert package_e["counts"] == {
        "critical_family_rows": 372,
        "curated_rows": 566,
        "explicit_blocker_rows": 8826,
        "total_atomic_rows": 9198,
        "unreviewed_gap_rows": 8632,
    }
    assert [row["path"] for row in package_e["changed_files"]] == list(rebind_module.PACKAGE_E_CHANGED_PATHS)
    assert [row["path"] for row in package_e["invariant_files"]] == list(rebind_module.PACKAGE_E_INVARIANT_PATHS)
    package_e_raw = __import__("subprocess").run(
        [
            sys.executable, "-B", "assurance/fuzzing/rebind-final-subject.py",
            "--package-e-projection", "--expected-r-commit", package_e_r,
            "--expected-r-tree", package_e_tree,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout
    assert package_e_raw == rebind_module._canonical_json(package_e)
    checked(
        rebind_module.package_e_projection,
        expected_r_commit=package_e_r,
        expected_r_tree="0" * 40,
    )
    rebind_module.validate_exact_changed_a_paths(
        list(rebind_module.EXPECTED_CHANGED_A_PATHS)
    )
    checked(
        rebind_module.validate_exact_changed_a_paths,
        list(rebind_module.EXPECTED_CHANGED_A_PATHS)[1:],
    )
    checked(
        rebind_module.validate_exact_changed_a_paths,
        [*list(rebind_module.EXPECTED_CHANGED_A_PATHS), "assurance/surplus.txt"],
    )
    checked(
        rebind_module.validate_exact_changed_a_paths,
        list(reversed(rebind_module.EXPECTED_CHANGED_A_PATHS)),
    )
    fabricated_invariant_diff = sorted(
        [
            *rebind_module.EXPECTED_CHANGED_A_PATHS,
            rebind_module.LEGACY_R_INVARIANT_PATHS[0],
        ]
    )
    checked(
        rebind_module.validate_exact_changed_a_paths,
        fabricated_invariant_diff,
    )
    invariant_rows = [
        {
            "git_mode": rebind_module.LEGACY_R_INVARIANTS[path][0],
            "path": path,
            "sha256": rebind_module.LEGACY_R_INVARIANTS[path][1],
            "size": 1,
        }
        for path in rebind_module.LEGACY_R_INVARIANT_PATHS
    ]
    rebind_module.validate_legacy_r_invariant_rows(invariant_rows)
    checked(
        rebind_module.validate_legacy_r_invariant_rows,
        invariant_rows[:-1],
    )
    reordered_invariants = copy.deepcopy(invariant_rows)
    reordered_invariants.reverse()
    checked(
        rebind_module.validate_legacy_r_invariant_rows,
        reordered_invariants,
    )
    rebound_invariant = copy.deepcopy(invariant_rows)
    rebound_invariant[0]["sha256"] = "0" * 64
    checked(
        rebind_module.validate_legacy_r_invariant_rows,
        rebound_invariant,
    )
    protected_current = (REPO_ROOT / ".gitignore").read_bytes()
    protected_committed = __import__("subprocess").run(
        ["git", "show", "HEAD:.gitignore"], cwd=REPO_ROOT, capture_output=True, check=True
    ).stdout
    protected_difference = __import__("subprocess").run(
        ["git", "diff", "--binary", "HEAD", "--", ".gitignore"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout
    topology = rebind_module.validate_gitignore_topology_projection(
        current=protected_current,
        committed=protected_committed,
        difference=protected_difference,
        committed_mode="100644",
        staged=False,
    )
    if protected_current == protected_committed:
        assert topology == "clean-replay" and protected_difference == b""
    else:
        assert topology == "protected-dirty-shared-workspace"
    assert rebind_module.validate_gitignore_topology_projection(
        current=protected_committed,
        committed=protected_committed,
        difference=b"",
        committed_mode="100644",
        staged=False,
    ) == "clean-replay"
    if protected_current != protected_committed:
        rebind_module.validate_protected_gitignore_projection(
            current=protected_current,
            committed=protected_committed,
            difference=protected_difference,
            committed_mode="100644",
            staged=False,
        )
    for mutation in (
        {"current": b""},
        {"current": protected_committed},
        {"difference": protected_difference + b"x"},
        {"committed_mode": "100755"},
        {"staged": True},
    ):
        projection = {
            "current": protected_current,
            "committed": protected_committed,
            "difference": protected_difference,
            "committed_mode": "100644",
            "staged": False,
            **mutation,
        }
        checked(rebind_module.validate_protected_gitignore_projection, **projection)
    checked(
        rebind_module.validate_gitignore_topology_projection,
        current=protected_committed,
        committed=protected_committed,
        difference=b"",
        committed_mode="100755",
        staged=False,
    )
    checked(
        rebind_module.validate_gitignore_topology_projection,
        current=protected_committed,
        committed=protected_committed,
        difference=b"",
        committed_mode="100644",
        staged=True,
    )
    assert rebind_module.validate_post_a_dirty_paths([]) == "clean-replay"
    assert (
        rebind_module.validate_post_a_dirty_paths([".gitignore"])
        == "protected-dirty-shared-workspace"
    )
    checked(rebind_module.validate_post_a_dirty_paths, [".gitignore", "assurance/extra"])
    checked(rebind_module.validate_post_a_dirty_paths, ["assurance/extra", ".gitignore"])
    with tempfile.TemporaryDirectory(prefix="dcrypt-rebind-rollback-") as rollback_directory:
        rollback_root = Path(rollback_directory)
        first_rollback = rollback_root / "first"
        second_rollback = rollback_root / "second"
        first_rollback.write_bytes(b"first-original")
        second_rollback.write_bytes(b"second-original")
        os.chmod(first_rollback, 0o664)
        os.chmod(second_rollback, 0o775)
        rollback = rebind_module.snapshot_regular_paths(rollback_root, ["first", "second"])
        first_rollback.write_bytes(b"changed")
        second_rollback.write_bytes(b"changed")
        os.chmod(first_rollback, 0o600)
        os.chmod(second_rollback, 0o700)
        rebind_module.restore_regular_paths(rollback_root, rollback)
        assert first_rollback.read_bytes() == b"first-original"
        assert second_rollback.read_bytes() == b"second-original"
        assert stat.S_IMODE(first_rollback.stat().st_mode) == 0o664
        assert stat.S_IMODE(second_rollback.stat().st_mode) == 0o775
    synthetic_rows = [
        {
            "disposition": (
                "exact-r-invariant"
                if path in rebind_module.LEGACY_R_INVARIANTS
                else "changed-in-a"
            ),
            "git_mode": rebind_module.KNOWN_A_MODES[path],
            "path": path,
            "sha256": (
                rebind_module.LEGACY_R_INVARIANTS[path][1]
                if path in rebind_module.LEGACY_R_INVARIANTS
                else "1" * 64
            ),
            "size": 1,
        }
        for path in rebind_module.KNOWN_A_PATHS
    ]
    synthetic_manifest_digest = "2" * 64
    next(
        row for row in synthetic_rows if row["path"] == "assurance/subject-manifest.json"
    )["sha256"] = synthetic_manifest_digest
    synthetic_pins = {
        path: (
            "VERIFIED-R-SUBJECT-MANIFEST"
            if path == "assurance/subject-manifest.json"
            else rebind_module.LEGACY_R_INVARIANTS[path][1]
            if path in rebind_module.LEGACY_R_INVARIANTS
            else "1" * 64
        )
        for path in rebind_module.LEGACY_A_MODES
    }
    rebind_module.validate_candidate_rows(
        synthetic_rows,
        manifest_sha256=synthetic_manifest_digest,
        legacy_pins=synthetic_pins,
    )
    missing_candidate_row = copy.deepcopy(synthetic_rows[:-1])
    checked(
        rebind_module.validate_candidate_rows,
        missing_candidate_row,
        manifest_sha256=synthetic_manifest_digest,
        legacy_pins=synthetic_pins,
    )
    reordered_candidate_rows = copy.deepcopy(synthetic_rows)
    reordered_candidate_rows.reverse()
    checked(
        rebind_module.validate_candidate_rows,
        reordered_candidate_rows,
        manifest_sha256=synthetic_manifest_digest,
        legacy_pins=synthetic_pins,
    )
    wrong_candidate_mode = copy.deepcopy(synthetic_rows)
    wrong_candidate_mode[0]["git_mode"] = "100755"
    checked(
        rebind_module.validate_candidate_rows,
        wrong_candidate_mode,
        manifest_sha256=synthetic_manifest_digest,
        legacy_pins=synthetic_pins,
    )
    fabricated_invariant_disposition = copy.deepcopy(synthetic_rows)
    invariant_candidate_row = next(
        row
        for row in fabricated_invariant_disposition
        if row["path"] in rebind_module.LEGACY_R_INVARIANTS
    )
    invariant_candidate_row["disposition"] = "changed-in-a"
    checked(
        rebind_module.validate_candidate_rows,
        fabricated_invariant_disposition,
        manifest_sha256=synthetic_manifest_digest,
        legacy_pins=synthetic_pins,
    )
    coherent_candidate_rebind = copy.deepcopy(synthetic_rows)
    coherent_candidate_rebind[0]["sha256"] = "3" * 64
    coherent_pins = copy.deepcopy(synthetic_pins)
    coherent_pins[coherent_candidate_rebind[0]["path"]] = "3" * 64
    checked(
        rebind_module.validate_candidate_rows,
        coherent_candidate_rebind,
        manifest_sha256=synthetic_manifest_digest,
        legacy_pins=synthetic_pins,
    )
    unstable_pins = copy.deepcopy(synthetic_pins)
    unstable_path = next(
        path for path in unstable_pins if path != "assurance/subject-manifest.json"
    )
    unstable_pins[unstable_path] = "UNSTABLE"
    checked(
        rebind_module.validate_candidate_rows,
        synthetic_rows,
        manifest_sha256=synthetic_manifest_digest,
        legacy_pins=unstable_pins,
    )
    model_source = (FRAMEWORK_DIR / "fuzzing_lib.py").read_text(encoding="utf-8")
    live_binding = {
        name: rebind_module._assignment(model_source, name)
        for name in (
            "STATUS",
            "FRAMEWORK_SUBJECT_COMMIT",
            "FRAMEWORK_SUBJECT_TREE",
            "FRAMEWORK_SUBJECT_MANIFEST_SHA256",
        )
    }
    assert live_binding == {
        "STATUS": "UNSTABLE-awaiting-final-subject-binding",
        "FRAMEWORK_SUBJECT_COMMIT": "UNSTABLE",
        "FRAMEWORK_SUBJECT_TREE": "UNSTABLE",
        "FRAMEWORK_SUBJECT_MANIFEST_SHA256": "UNSTABLE",
    } or (
        live_binding["STATUS"] == rebind_module.FINAL_STATUS
        and rebind_module.HEX40.fullmatch(live_binding["FRAMEWORK_SUBJECT_COMMIT"])
        and rebind_module.HEX40.fullmatch(live_binding["FRAMEWORK_SUBJECT_TREE"])
        and rebind_module.HEX64.fullmatch(
            live_binding["FRAMEWORK_SUBJECT_MANIFEST_SHA256"]
        )
    )
    synthetic_unstable = model_source
    for name, value in (
        ("STATUS", "UNSTABLE-awaiting-final-subject-binding"),
        ("FRAMEWORK_SUBJECT_COMMIT", "UNSTABLE"),
        ("FRAMEWORK_SUBJECT_TREE", "UNSTABLE"),
        ("FRAMEWORK_SUBJECT_MANIFEST_SHA256", "UNSTABLE"),
    ):
        synthetic_unstable = rebind_module._replace_assignment(
            synthetic_unstable, name, value
        )
    candidate_source = rebind_module.build_candidate_source(
        synthetic_unstable,
        commit="a" * 40,
        tree="b" * 40,
        manifest_sha256="c" * 64,
    )
    assert rebind_module._assignment(candidate_source, "STATUS") == rebind_module.FINAL_STATUS
    assert rebind_module.normalized_model_sha256(candidate_source) == rebind_module.NORMALIZED_MODEL_SHA256
    assert rebind_module.build_candidate_source(
        candidate_source,
        commit="a" * 40,
        tree="b" * 40,
        manifest_sha256="c" * 64,
    ) == candidate_source
    model_semantic_drift = synthetic_unstable.replace(
        'RSS_LIMIT_MB = 2_048', 'RSS_LIMIT_MB = 2_049', 1
    )
    checked(
        rebind_module.build_candidate_source,
        model_semantic_drift,
        commit="a" * 40,
        tree="b" * 40,
        manifest_sha256="c" * 64,
    )
    partial_model_binding = rebind_module._replace_assignment(
        synthetic_unstable, "FRAMEWORK_SUBJECT_COMMIT", "a" * 40
    )
    checked(
        rebind_module.build_candidate_source,
        partial_model_binding,
        commit="a" * 40,
        tree="b" * 40,
        manifest_sha256="c" * 64,
    )
    checked(
        rebind_module.build_candidate_source,
        candidate_source,
        commit="d" * 40,
        tree="e" * 40,
        manifest_sha256="f" * 64,
    )
    with tempfile.TemporaryDirectory(prefix="dcrypt-rebind-injected-") as injected_directory:
        injected_root = Path(injected_directory)
        injected_file = injected_root / "model"
        injected_file.write_bytes(b"original")
        os.chmod(injected_file, 0o664)
        injected_snapshot = rebind_module.snapshot_regular_paths(injected_root, ["model"])
        try:
            rebind_module._atomic_write(injected_file, b"candidate", 0o644)
            raise rebind_module.RebindError("injected failure")
        except rebind_module.RebindError:
            rebind_module.restore_regular_paths(injected_root, injected_snapshot)
        assert injected_file.read_bytes() == b"original"
        assert stat.S_IMODE(injected_file.stat().st_mode) == 0o664
    with tempfile.TemporaryDirectory(prefix="dcrypt-rebind-inventory-") as inventory_directory:
        inventory_root = Path(inventory_directory)
        known = inventory_root / "known"
        known.write_bytes(b"known")
        baseline_inventory = rebind_module._framework_inventory(inventory_root)
        concurrent = inventory_root / "concurrent"
        concurrent.write_bytes(b"must-not-be-deleted")
        checked(
            rebind_module._assert_framework_inventory,
            baseline_inventory,
            root_path=inventory_root,
        )
        assert concurrent.read_bytes() == b"must-not-be-deleted"
        special_root = inventory_root / "special-root"
        special_root.mkdir()
        special_known = special_root / "known"
        special_known.write_bytes(b"known")
        special_baseline = rebind_module._framework_inventory(special_root)
        special = special_root / "concurrent-symlink"
        special.symlink_to(special_known)
        checked(
            rebind_module._assert_framework_inventory,
            special_baseline,
            root_path=special_root,
        )
        assert special.is_symlink()

    # Exercise the real transaction's injected-failure path. It must restore
    # the exact model bytes/mode and leave both framework inventory and the
    # protected clean-or-dirty topology unchanged.
    transaction_head = __import__("subprocess").run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, check=True, text=True
    ).stdout.strip()
    transaction_model = FRAMEWORK_DIR / "fuzzing_lib.py"
    transaction_model_raw = transaction_model.read_bytes()
    transaction_model_mode = stat.S_IMODE(transaction_model.stat().st_mode)
    transaction_inventory = rebind_module._framework_inventory()
    checked(
        rebind_module._apply_or_preview,
        model_source + "\n# injected transaction candidate\n",
        commit=transaction_head,
        tree="b" * 40,
        manifest_sha256="c" * 64,
        gitignore_sha256=__import__("hashlib").sha256(protected_current).hexdigest(),
        keep=True,
        inject_failure_after_model=True,
        protected_variant=topology,
    )
    assert transaction_model.read_bytes() == transaction_model_raw
    assert stat.S_IMODE(transaction_model.stat().st_mode) == transaction_model_mode
    assert rebind_module._framework_inventory() == transaction_inventory
    assert (REPO_ROOT / ".gitignore").read_bytes() == protected_current
    marker_target = "aes_gcm_semantic"
    required_markers = runner_module.required_smoke_binary_symbols(marker_target)
    assert required_markers[:4] == list(INTEGRATED_ASAN_FUNCTION_SYMBOLS)
    assert "__lsan_init" not in required_markers
    marker_proofs = [
        {
            "defined_function_row_sha256": "0" * 64,
            "inspector_executable_sha256": "1" * 64,
            "inspector_version_sha256": "2" * 64,
            "symbol": symbol,
            "symbol_table_sha256": "3" * 64,
        }
        for symbol in required_markers
    ]
    runner_module.validate_instrumentation_proofs(marker_target, marker_proofs)
    checked(runner_module.validate_instrumentation_proofs, marker_target, marker_proofs[1:])
    checked(
        runner_module.validate_instrumentation_proofs,
        marker_target,
        [proof for proof in marker_proofs if proof["symbol"] != "__lsan_enable"],
    )
    defined_row = b"3044: 00000000000e1810 71 FUNC GLOBAL DEFAULT 15 __asan_init"
    assert _defined_function_symbol_row(defined_row + b"\n", "__asan_init") == defined_row
    checked(
        _defined_function_symbol_row,
        b"45: 0000000000000000 0 NOTYPE WEAK DEFAULT UND __asan_init\n",
        "__asan_init",
    )
    checked(
        _defined_function_symbol_row,
        defined_row + b"\n" + defined_row + b"\n",
        "__asan_init",
    )
    checked(
        _defined_function_symbol_row,
        b"3044: 00000000000e1810 71 OBJECT GLOBAL DEFAULT 15 __asan_init\n",
        "__asan_init",
    )
    secret_log = b"Base64: U0VDUkVULVNF TlRJTkVM\nSECRET-SENTINEL\n"
    redacted = runner_module._fuzz_failure_summary("aes_gcm_semantic", 86, secret_log)
    assert "Base64:" not in redacted and "SECRET-SENTINEL" not in redacted
    assert __import__("hashlib").sha256(secret_log).hexdigest() in redacted

    # Canonical JSON/data attacks.
    checked(parse_json, b'{"a": 1, "a": 2}\n', label="duplicate")
    checked(parse_json, b'{"x": 1.0}\n', label="float")
    checked(parse_json, b'{"x": NaN}\n', label="nonfinite")
    checked(parse_json, b'{"b": 1, "a": 2}\n', label="reordered")
    checked(parse_canonical_lines, b"b\na\n", label="rows", paths=False)
    checked(parse_canonical_lines, b"a\na\n", label="rows", paths=False)
    checked(parse_canonical_lines, b"../escape\n", label="paths", paths=True)
    checked(parse_canonical_lines, "e\u0301\n".encode(), label="rows", paths=False)
    assert canonical_git_mode(0o664, "100644", label="nonexec fixture") == "100644"
    for checkout_mode in (0o700, 0o750, 0o755, 0o770, 0o775):
        assert canonical_git_mode(
            checkout_mode, "100755", label="umask-varied executable fixture"
        ) == "100755"
    for checkout_mode in (
        0o600, 0o640, 0o644, 0o655, 0o660, 0o664, 0o710, 0o774, 0o4700,
    ):
        checked(
            canonical_git_mode, checkout_mode, "100755",
            label="unreviewed or missing executable intent",
        )
    checked(canonical_git_mode, 0o777, "100755", label="world-write executable")

    # Input-cap lexical bypasses.
    valid = harness("fuzz_target!(|input: &[u8]| { let input = &input[..input.len().min(INPUT_MAX)]; black_box(input); });\n")
    assert source_input_cap(valid, label="valid") == 4096
    checked(source_input_cap, harness("// .min(INPUT_MAX)\nfuzz_target!(|input: &[u8]| { black_box(input); });\n"), label="comment")
    checked(source_input_cap, harness("fuzz_target!(|input: &[u8]| { if false { let input = &input[..input.len().min(INPUT_MAX)]; } });\n"), label="dead")
    checked(source_input_cap, harness("fuzz_target!(|input: &[u8]| { let other = &input[..input.len().min(INPUT_MAX)]; });\n"), label="wrong")
    checked(source_input_cap, harness("fuzz_target!(|input: &[u8]| { black_box(input); let input = &input[..input.len().min(INPUT_MAX)]; });\n"), label="late")
    checked(source_input_cap, valid + b"fuzz_target!(|other: &[u8]| { black_box(other); });\n", label="two entries")

    registry = build_registry()
    timeout_by_target = {
        target["id"]: target["resource_limits"]["timeout_seconds"]
        for target in registry["targets"]
    }
    assert timeout_by_target["hybrid_semantic"] == 30
    assert {
        timeout
        for target_id, timeout in timeout_by_target.items()
        if target_id != "hybrid_semantic"
    } == {2, 10}
    assert all(
        timeout_by_target[target["id"]] == (10 if target["tier"] == "critical" else 2)
        for target in registry["targets"]
        if target["id"] != "hybrid_semantic"
    )
    hybrid_target = next(
        target for target in registry["targets"] if target["id"] == "hybrid_semantic"
    )
    hybrid_argv = canonical_fuzz_argv(hybrid_target, artifact_prefix="/private/artifacts/")
    assert "-timeout=30" in hybrid_argv
    assert "-report_slow_units=30" in hybrid_argv
    source_bindings = __import__("fuzzing_lib").build_source_bindings(REPO_ROOT)
    control_rows = [
        row
        for row in source_bindings["files"]
        if row["path"] in __import__("fuzzing_lib").PACKAGE_C_CONTROL_INPUTS
    ]
    validate_control_source_binding_rows(control_rows)
    checked(validate_control_source_binding_rows, control_rows[1:])
    checked(validate_control_source_binding_rows, list(reversed(control_rows)))
    wrong_control_mode = copy.deepcopy(control_rows)
    wrong_control_mode[1]["git_mode"] = "100644"
    checked(validate_control_source_binding_rows, wrong_control_mode)
    first = registry["targets"][0]
    with tempfile.TemporaryDirectory(prefix="dcrypt-selftest-private-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        artifacts = root / "artifacts"
        artifacts.mkdir(mode=0o700)
        argv = canonical_fuzz_argv(first, artifact_prefix=f"{artifacts}/")
        verify_fuzz_argv(argv, target=first, artifact_prefix=f"{artifacts}/")
        checked(verify_fuzz_argv, argv + ["-skip=x"], target=first, artifact_prefix=f"{artifacts}/")
        checked(verify_fuzz_argv, argv + [argv[0]], target=first, artifact_prefix=f"{artifacts}/")
        checked(verify_fuzz_argv, list(reversed(argv)), target=first, artifact_prefix=f"{artifacts}/")
        checked(verify_fuzz_argv, [item.replace("-ignore_ooms=0", "-ignore_ooms=1") for item in argv], target=first, artifact_prefix=f"{artifacts}/")

        fake = root / "fake-marker"
        fake.write_bytes(b"ELF? __asan_init spoof only")
        os.chmod(fake, 0o700)
        checked(verify_binary_symbol, fake, "__asan_init")
        try:
            runner_module.prove_target_instrumentation(
                "aes_gcm_semantic", fake, tools=pinned_toolchain()
            )
        except FuzzingError as error:
            diagnostic = str(error)
            assert "target=aes_gcm_semantic" in diagnostic
            assert "symbol=unknown" in diagnostic and "class=inspector-error" in diagnostic
            assert str(fake) not in diagnostic and "ELF?" not in diagnostic
            tests += 1
        else:
            raise AssertionError("redacted target instrumentation diagnostic unexpectedly passed")

    # Actual fuzz-linker capture accepts only one canonical target link with
    # the exact pinned ASan runtime and rejects every reviewed bypass shape.
    with tempfile.TemporaryDirectory(prefix="dcrypt-cargo-tools-selftest-") as cargo_tools_directory:
        cargo_tools_root = Path(cargo_tools_directory)
        os.chmod(cargo_tools_root, 0o700)
        initial_cargo_tools = pinned_cargo_tools(cargo_tools_root)
        assert initial_cargo_tools["cargo_fuzz_original_executed"] is False
        assert Path(initial_cargo_tools["cargo_fuzz_path"]).is_relative_to(cargo_tools_root)
        probe = initial_cargo_tools["toolchain"]
    rustc = Path(probe["rustc_path"])
    runtime_candidates = [
        path
        for path in (rustc.parent.parent / "lib/rustlib/x86_64-unknown-linux-gnu/lib").glob(
            "librustc-nightly_rt.asan.a"
        )
        if path.is_file() and not path.is_symlink()
    ]
    if len(runtime_candidates) != 1 or __import__("hashlib").sha256(runtime_candidates[0].read_bytes()).hexdigest() != PINNED_SANITIZER_RUNTIME_SHA256["address"]:
        raise AssertionError("selftest cannot locate the exact pinned ASan runtime")
    runtime = runtime_candidates[0]
    with tempfile.TemporaryDirectory(prefix="dcrypt-linker-selftest-") as directory:
        private = Path(directory)
        os.chmod(private, 0o700)
        snapshot_source = private / "snapshot-source"
        snapshot_source.write_bytes(b"snapshot-fixture")
        os.chmod(snapshot_source, 0o775)
        snapshot_destination = private / "snapshot-private"
        snapshot_record = _snapshot_home_file(
            snapshot_source,
            snapshot_destination,
            executable=True,
            label="snapshot fixture",
        )
        assert snapshot_record["private_mode"] == "0700" and snapshot_destination.read_bytes() == b"snapshot-fixture"
        world_source = private / "world-write-source"
        world_source.write_bytes(b"world")
        os.chmod(world_source, 0o777)
        checked(
            _snapshot_home_file,
            world_source,
            private / "world-private",
            executable=True,
            label="world-writable snapshot fixture",
        )
        symlink_source = private / "symlink-source"
        symlink_source.symlink_to(snapshot_source)
        checked(
            _snapshot_home_file,
            symlink_source,
            private / "symlink-private",
            executable=True,
            label="symlink snapshot fixture",
        )
        metadata = snapshot_source.stat()
        checked(
            _validate_snapshot_source_metadata,
            metadata,
            executable=True,
            allow_multiple_links=False,
            required_uid=os.getuid() + 1,
            label="owner mismatch",
        )
        drift = type("Drift", (), {name: getattr(metadata, name) for name in (
            "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"
        )})()
        drift.st_ctime_ns += 1
        checked(_require_stable_metadata, metadata, drift, label="metadata race")
        source_tree = private / "source-tree"
        source_tree.mkdir(mode=0o775)
        (source_tree / "member").write_bytes(b"member")
        os.chmod(source_tree / "member", 0o664)
        tree_projection = _snapshot_home_tree(
            source_tree,
            private / "private-tree",
            label="source tree fixture",
        )
        assert tree_projection["files"] == 1
        os.chmod(source_tree / "member", 0o775)
        executable_projection = _snapshot_home_tree(
            source_tree,
            private / "private-tree-executable",
            label="source tree executable drift fixture",
        )
        assert executable_projection["original_executable_paths"] == ["member"]
        special_tree = private / "special-tree"
        special_tree.mkdir(mode=0o700)
        (special_tree / "link").symlink_to(snapshot_source)
        checked(
            _snapshot_home_tree,
            special_tree,
            private / "special-private",
            label="special tree fixture",
        )
        wrapper = private / "cc"
        wrapper.write_text(FUZZ_BUILD_LINKER_WRAPPER_SOURCE, encoding="utf-8")
        os.chmod(wrapper, 0o700)
        binary = private / "build/x86_64-unknown-linux-gnu/release/target"
        linked_output = (
            binary.parent
            / "build/dcrypt-fuzz/0123456789abcdef/out/target"
        )
        linked_output.parent.mkdir(parents=True)
        binary.parent.mkdir(parents=True, exist_ok=True)
        linked_output.write_bytes(b"reviewed-fuzz-executable-fixture")
        os.chmod(linked_output, 0o700)
        os.link(linked_output, binary)
        log = private / "linker.jsonl"

        def write_log(records):
            raw = b"".join(
                (__import__("json").dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
                for record in records
            )
            if log.exists() or log.is_symlink():
                log.unlink()
            descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)

        positive_record = [str(wrapper), f"-Wl,{runtime}", "-o", str(linked_output)]
        write_log([positive_record])
        projection = verify_fuzz_linker_log(
            log, wrapper=wrapper, binary=binary, private_root=private, tools=probe
        )
        assert projection["actual_linker_invocation_observed"] is True
        assert [
            item["symbol"] for item in projection["asan_runtime_defined_function_proofs"]
        ] == list(INTEGRATED_ASAN_FUNCTION_SYMBOLS)
        assert projection["materialized_binary_relation"] == "hardlink-same-inode"
        assert projection["linked_output_sha256"] == projection["materialized_final_binary_sha256"]
        binary.unlink()
        binary.write_bytes(linked_output.read_bytes())
        os.chmod(binary, 0o700)
        copied_projection = verify_fuzz_linker_log(
            log, wrapper=wrapper, binary=binary, private_root=private, tools=probe
        )
        assert copied_projection["materialized_binary_relation"] == "copied-byte-identical"
        binary.unlink()
        os.link(linked_output, binary)
        log.unlink()
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        log.symlink_to(wrapper)
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        log.unlink()
        descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(b'["truncated"')
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        write_log([positive_record])
        wrapper.write_text(FUZZ_BUILD_LINKER_WRAPPER_SOURCE + "# drift\n", encoding="utf-8")
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        wrapper.write_text(FUZZ_BUILD_LINKER_WRAPPER_SOURCE, encoding="utf-8")
        write_log([[str(wrapper), f"-Wl,{runtime}", "-o", str(private / "other")]])
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        write_log([[str(wrapper), f"-Wl,{runtime}", "-o", str(linked_output), "-o", str(linked_output)]])
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        write_log([[str(wrapper), "-o", str(linked_output)]])
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        write_log([[str(wrapper), f"-Wl,{runtime}", f"-Wl,{runtime}", "-o", str(linked_output)]])
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        write_log([[str(wrapper), f"-Wl,relative/{runtime.name}", "-o", str(linked_output)]])
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        wrong_runtime = private / runtime.name
        wrong_runtime.write_bytes(b"wrong-runtime")
        os.chmod(wrong_runtime, 0o600)
        write_log([[str(wrapper), f"-Wl,{wrong_runtime}", "-o", str(linked_output)]])
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        second_output = binary.parent / "build/dcrypt-fuzz/fedcba9876543210/out/target"
        second_output.parent.mkdir(parents=True)
        os.link(linked_output, second_output)
        second_record = [str(wrapper), f"-Wl,{runtime}", "-o", str(second_output)]
        write_log([positive_record, second_record])
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        write_log([positive_record])
        binary.unlink()
        binary.write_bytes(b"tampered-materialized-binary")
        os.chmod(binary, 0o700)
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        binary.unlink()
        os.link(linked_output, binary)
        linked_output.unlink()
        linked_output.symlink_to(binary)
        checked(verify_fuzz_linker_log, log, wrapper=wrapper, binary=binary, private_root=private, tools=probe)
        linked_output.unlink()

        duplicate_json = private / "duplicate.json"
        duplicate_json.write_text('{"installs":{},"installs":{}}', encoding="utf-8")
        checked(_strict_json_file, duplicate_json, label="duplicate install provenance")

        # Exact cargo-fuzz archive/source closure rejects a tampered extracted
        # source and marker drift. The live proof also enforces one candidate
        # and unique installer bin ownership.
        cargo_tools_root = private / "cargo-tools-live"
        cargo_tools_root.mkdir(mode=0o700)
        cargo_tools = pinned_cargo_tools(cargo_tools_root)
        assert cargo_tools["cargo_fuzz_original_executed"] is False
        assert Path(cargo_tools["cargo_fuzz_path"]).is_relative_to(cargo_tools_root)
        assert cargo_tools["cargo_fuzz_crate_sha256"] == "5acfd01930e49823e58c30dd8012d3338a620377d7c7d4cc140ca4b2169400e2"
        import shutil
        cargo_root = Path(os.environ["HOME"]) / ".cargo"
        archive = next(cargo_root.glob("registry/cache/*/cargo-fuzz-0.13.2.crate"))
        source = next(cargo_root.glob("registry/src/*/cargo-fuzz-0.13.2"))
        source_copy = private / "cargo-fuzz-source"
        corrupt_archive = private / "cargo-fuzz-corrupt.crate"
        shutil.copyfile(archive, corrupt_archive)
        corrupt_raw = bytearray(corrupt_archive.read_bytes())
        corrupt_raw[len(corrupt_raw) // 2] ^= 1
        corrupt_archive.write_bytes(corrupt_raw)
        checked(_verify_cargo_fuzz_source, corrupt_archive, source)
        shutil.copytree(source, source_copy, copy_function=shutil.copyfile)
        (source_copy / "Cargo.lock").write_bytes((source_copy / "Cargo.lock").read_bytes() + b"\n")
        checked(_verify_cargo_fuzz_source, archive, source_copy)
        shutil.rmtree(source_copy)
        shutil.copytree(source, source_copy, copy_function=shutil.copyfile)
        (source_copy / ".cargo-ok").write_bytes(b'{"v":2}')
        checked(_verify_cargo_fuzz_source, archive, source_copy)
        checked(_validate_exact_candidates, [], label="missing archive")
        checked(_validate_exact_candidates, [archive, archive], label="ambiguous archive")
        pinned_a = private / "pinned-a"
        pinned_b = private / "pinned-b"
        pinned_a.write_bytes(b"same-pinned-tool")
        pinned_b.write_bytes(b"same-pinned-tool")
        os.chmod(pinned_a, 0o700)
        os.chmod(pinned_b, 0o700)
        pinned_sha256 = __import__("hashlib").sha256(b"same-pinned-tool").hexdigest()
        selected, methods = _select_exact_pinned_executable(
            [("dated", str(pinned_a)), ("alias", str(pinned_b))],
            pinned_sha256,
            label="fixture",
        )
        assert selected == str(pinned_a)
        assert methods == ["alias", "dated"]
        checked(
            _select_exact_pinned_executable,
            [("wrong", str(pinned_a))],
            "0" * 64,
            label="fixture",
        )
        missing_discovery = private / "missing-rustup"
        checked(_resolve_discovery_executable, [missing_discovery], label="missing rustup")
        discovery_a = private / "rustup-a"
        discovery_b = private / "rustup-b"
        discovery_a.write_bytes(b"fixture-a")
        discovery_b.write_bytes(b"fixture-b")
        os.chmod(discovery_a, 0o700)
        os.chmod(discovery_b, 0o700)
        checked(
            _resolve_discovery_executable,
            [discovery_a, discovery_b],
            label="ambiguous rustup",
        )
        discovery_alias = private / "rustup-alias"
        discovery_alias.symlink_to(discovery_a)
        assert _resolve_discovery_executable(
            [discovery_alias, discovery_a], label="same rustup identity"
        ) == discovery_a
        escaping_alias = private / "escaping-rustup"
        escaping_alias.symlink_to(discovery_b)
        checked(
            _resolve_discovery_executable,
            [escaping_alias, discovery_a],
            label="escaping rustup",
        )
        measured_tool = private / "measured-tool"
        measured_tool.write_bytes(b"fixture")
        os.chmod(measured_tool, 0o700)
        identity = _validate_host_tool_identity(
            path=measured_tool,
            allowed_real_paths=[measured_tool],
            version=b"fixture 1.0\n",
            version_pattern=__import__("re").compile(rb"^fixture 1\.0\n$"),
            label="measured fixture",
            required_uid=os.getuid(),
        )
        assert identity["executable_sha256"] == __import__("hashlib").sha256(b"fixture").hexdigest()
        checked(
            _validate_host_tool_identity,
            path=measured_tool,
            allowed_real_paths=[measured_tool],
            version=b"spoof 1.0\n",
            version_pattern=__import__("re").compile(rb"^fixture 1\.0\n$"),
            label="spoofed fixture",
            required_uid=os.getuid(),
        )
        checked(
            _validate_host_tool_identity,
            path=measured_tool,
            allowed_real_paths=[private / "other-tool"],
            version=b"fixture 1.0\n",
            version_pattern=__import__("re").compile(rb"^fixture 1\.0\n$"),
            label="wrong tool path",
            required_uid=os.getuid(),
        )
        checked(
            _validate_host_tool_identity,
            path=measured_tool,
            allowed_real_paths=[measured_tool],
            version=b"fixture 1.0\n",
            version_pattern=__import__("re").compile(rb"^fixture 1\.0\n$"),
            label="wrong owner",
            required_uid=os.getuid() + 1,
        )
        valid_install = {
            "cargo-fuzz 0.13.2 (registry+https://github.com/rust-lang/crates.io-index)": {
                "all_features": False,
                "bins": ["cargo-fuzz"],
                "features": [],
                "no_default_features": False,
                "profile": "release",
                "rustc": PINNED_RUSTC_VERSION,
                "target": "x86_64-unknown-linux-gnu",
                "version_req": "=0.13.2",
            }
        }
        assert _validate_cargo_fuzz_install_records(valid_install)["version_req"] == "=0.13.2"
        missing_install = copy.deepcopy(valid_install)
        missing_install[next(iter(missing_install))].pop("profile")
        checked(_validate_cargo_fuzz_install_records, missing_install)
        extra_install = copy.deepcopy(valid_install)
        extra_install[next(iter(extra_install))]["extra"] = True
        checked(_validate_cargo_fuzz_install_records, extra_install)
        wrong_install = copy.deepcopy(valid_install)
        wrong_install[next(iter(wrong_install))]["version_req"] = "0.13.2"
        checked(_validate_cargo_fuzz_install_records, wrong_install)
        duplicate_owner = copy.deepcopy(valid_install)
        duplicate_owner["other"] = {"bins": ["cargo-fuzz"]}
        checked(_validate_cargo_fuzz_install_records, duplicate_owner)

    ids = {target["id"] for target in registry["targets"]}
    listing = "\n".join(sorted(ids)) + "\n"
    parse_target_listing(listing, 0, ids)
    checked(parse_target_listing, listing, 1, ids)
    checked(parse_target_listing, listing + sorted(ids)[0] + "\n", 0, ids)
    checked(parse_target_listing, "\n", 0, ids)

    # Exact numeric boundaries.
    assert not coverage_regressed(100, 98)
    assert coverage_regressed(100, 97)
    assert not coverage_regressed(101, 99)
    checked(coverage_regressed, 0, 0)
    assert budget_ok(72 * 3600, 72 * 3600)
    assert not budget_ok(72 * 3600 - 1, 72 * 3600)
    checked(budget_ok, -1, 1)
    assert freshness_ok("2026-08-11T00:00:00Z", "2026-08-12T00:00:00Z", 86400)
    checked(freshness_ok, "2026-08-12T00:00:01Z", "2026-08-12T00:00:00Z", 86400)
    checked(freshness_ok, "not-time", "2026-08-12T00:00:00Z", 86400)
    checked(
        aggregate_core_seconds,
        [
            {"allocated_cores": 1, "cpu_seconds": 10, "end": "2026-08-12T00:00:10Z", "shard_id": "a", "start": "2026-08-12T00:00:00Z", "target_id": "x"},
            {"allocated_cores": 1, "cpu_seconds": 10, "end": "2026-08-12T00:00:15Z", "shard_id": "b", "start": "2026-08-12T00:00:05Z", "target_id": "x"},
        ],
        target_id="x",
    )

    assert bounded_rejection_fixture([False, True], 2) == 2
    checked(bounded_rejection_fixture, [False, False], 2)
    checked(bounded_rejection_fixture, [False, False, True], 2)

    # No current writer can acquire corpus or private crash authority.
    assert not authorize_authoritative_corpus_write(writer_role="trusted-corpus-writer", authenticated=True, from_fork=False, reviewed=True)
    assert not authorize_authoritative_corpus_write(writer_role="trusted-corpus-writer", authenticated=True, from_fork=True, reviewed=True)
    assert not authorize_private_crash_store_write(writer_role="trusted-private-crash-writer", authenticated=True, from_fork=False, confidentiality="private")
    assert not authorize_private_crash_store_write(writer_role="trusted-private-crash-writer", authenticated=True, from_fork=True, confidentiality="private")

    sanitizers = build_sanitizer_controls()
    validate_sanitizer_assignment(sanitizers)
    bad = copy.deepcopy(sanitizers)
    bad["controls"][0]["assigned_target_ids"] = bad["controls"][0]["assigned_target_ids"][:-1]
    checked(validate_sanitizer_assignment, bad)
    bad_integrated_marker = copy.deepcopy(sanitizers)
    next(item for item in bad_integrated_marker["controls"] if item["id"] == "lsan")[
        "target_binary_markers"
    ] = ["__lsan_init"]
    checked(validate_sanitizer_assignment, bad_integrated_marker)
    bad_integrated_options = copy.deepcopy(sanitizers)
    bad_integrated_options["integrated_address_runtime"]["asan_options"] = "detect_leaks=0"
    checked(validate_sanitizer_assignment, bad_integrated_options)
    asan = next(item for item in sanitizers["controls"] if item["id"] == "asan")
    assert not sanitizer_report_matches(asan, "thread panicked at fixture", 101)
    lsan = next(item for item in sanitizers["controls"] if item["id"] == "lsan")
    assert sanitizer_report_matches(
        lsan,
        "ERROR: LeakSanitizer: detected memory leaks\nSUMMARY: AddressSanitizer: 4096 byte(s) leaked\n",
        87,
    )
    assert not sanitizer_report_matches(
        lsan,
        "ERROR: LeakSanitizer: detected memory leaks\nSUMMARY: LeakSanitizer: 4096 byte(s) leaked\n",
        87,
    )
    assert not sanitizer_report_matches(
        lsan,
        "SUMMARY: AddressSanitizer: 4096 byte(s) leaked\n",
        87,
    )
    assert not sanitizer_report_matches(
        lsan,
        "ERROR: LeakSanitizer: detected memory leaks\n",
        87,
    )
    assert sanitizer_report_matches(asan, "ERROR: AddressSanitizer:\nSUMMARY: AddressSanitizer:", 1)
    sanitizer_requirements = build_control_requirements()
    validate_control_requirements(sanitizer_requirements)
    controls_by_id = {item["control_id"]: item for item in sanitizer_requirements["controls"]}
    assert controls_by_id["asan-integrated-box-leak"]["required_sanitizer"] == "address"
    assert controls_by_id["asan-integrated-box-leak"]["required_runtime_options"] == {
        "ASAN_OPTIONS": INTEGRATED_ASAN_OPTIONS
    }
    assert controls_by_id["asan-integrated-box-leak"]["required_report_patterns"] == [
        "ERROR: LeakSanitizer: detected memory leaks",
        "SUMMARY: AddressSanitizer:",
    ]
    assert controls_by_id["lsan-box-leak"]["required_report_patterns"] == [
        "ERROR: LeakSanitizer: detected memory leaks",
        "SUMMARY: LeakSanitizer:",
    ]
    assert controls_by_id["lsan-box-leak"]["evidence_role"].startswith("supplemental-")
    false_positive = copy.deepcopy(sanitizer_requirements)
    false_positive["actual_positive_controls_observed"] = 3
    checked(validate_control_requirements, false_positive)
    lifecycle_requirements = build_lifecycle_requirements()
    validate_lifecycle_requirements(lifecycle_requirements)
    false_lifecycle = copy.deepcopy(lifecycle_requirements)
    false_lifecycle["promotion_authorized"] = True
    checked(validate_lifecycle_requirements, false_lifecycle)

    # Every critical selector is reachable; every gap is an explicit HOLD.
    mapping_sample = __import__("fuzzing_lib").build_row_mapping(REPO_ROOT)
    critical = next(row for row in mapping_sample["rows"] if row["target_id"] is not None)
    gap = next(row for row in mapping_sample["rows"] if row["source_kind"] == "unreviewed-gap")
    selected = select_changed_rows(REPO_ROOT, [critical["row_id"]])
    assert selected["status"] == "selected" and selected["selected_target_ids"]
    blocked = select_changed_rows(REPO_ROOT, [gap["row_id"]])
    assert blocked["status"] == "HOLD" and blocked["blocker_rows"]
    checked(select_changed_rows, REPO_ROOT, ["unknown.atomic.row"])
    sign_selection = select_changed_paths(REPO_ROOT, ["crates/sign/src/lib.rs"])
    assert sign_selection["status"] == "HOLD"
    assert len(sign_selection["blocker_rows"]) == 282
    assert {row["row_id"] for row in sign_selection["blocker_rows"]} == {
        row["row_id"]
        for row in mapping_sample["rows"]
        if row["source_kind"] == "unreviewed-gap" and ".dcrypt-sign." in row["row_id"]
    }
    remote_release_selection = select_changed_paths(
        REPO_ROOT, ["tools/verify-remote-release-ready.py"]
    )
    assert remote_release_selection["selected_target_ids"] == sorted(ids)
    assert remote_release_selection["fail_safe_all_reasons"] == [
        "tools/verify-remote-release-ready.py"
    ]
    assert canonical_nonexecutable_mode(0o644, label="clean checkout") == "100644"
    assert canonical_nonexecutable_mode(0o664, label="group-writable checkout") == "100644"
    checked(canonical_nonexecutable_mode, 0o755, label="executable drift")
    checked(canonical_nonexecutable_mode, 0o666, label="world-writable drift")

    # Schemas close nested objects and type empty future-evidence arrays.
    schema = closed_schema("fixture", "fixture", {"status": "HOLD", "runtime_objects": []})
    assert_all_data_objects_closed(schema)
    future_items = schema["properties"]["runtime_objects"]
    from verify import _validate_schema
    _validate_schema({"status": "HOLD", "runtime_objects": []}, schema, label="empty-future")
    valid_runtime = {
        "path_suffix": "librustc-nightly_rt.asan.a",
        "sha256": "0" * 64,
    }
    _validate_schema(
        {"status": "HOLD", "runtime_objects": [valid_runtime]},
        schema,
        label="populated-future",
    )
    checked(_validate_schema, {"status": "HOLD", "runtime_objects": ["arbitrary"]}, schema, label="wrong-future")
    checked(
        _validate_schema,
        {"status": "HOLD", "runtime_objects": [{"sha256": "0" * 64}]},
        schema,
        label="missing-future-field",
    )
    extra_runtime = {**valid_runtime, "extra": True}
    checked(
        _validate_schema,
        {"status": "HOLD", "runtime_objects": [extra_runtime]},
        schema,
        label="extra-future-field",
    )
    wrong_runtime = {**valid_runtime, "sha256": "not-a-digest"}
    checked(
        _validate_schema,
        {"status": "HOLD", "runtime_objects": [wrong_runtime]},
        schema,
        label="wrong-future-field",
    )
    bundle_schema = crash_bundle_schema()
    bundle = build_crash_bundle_template()
    _validate_schema(bundle, bundle_schema, label="blocked-crash-template")
    validate_crash_bundle(bundle)
    live_binding = __import__("fuzzing_lib").build_policy()["source_binding"]
    validate_live_source_binding(live_binding)
    stale_live_binding = copy.deepcopy(live_binding)
    stale_live_binding["framework_subject_manifest_sha256"] = "d" * 64
    checked(validate_live_source_binding, stale_live_binding)
    partial_live_binding = copy.deepcopy(live_binding)
    partial_live_binding["framework_subject_commit"] = "e" * 40
    checked(validate_live_source_binding, partial_live_binding)
    populated_bundle = copy.deepcopy(bundle)
    for key in (
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
    ):
        populated_bundle[key] = "1" * 64
    populated_bundle.update(
        {
            "status": "private-fixed-retested",
            "target_id": "ecdsa_semantic",
            "failure_class": "controlled-panic-simulation-only",
            "first_seen": "2026-08-12T00:00:00Z",
            "provenance": "private-local-fixture",
            "affected_atomic_rows": ["fixture.atomic-row"],
        }
    )
    populated_bundle["discovery_subject"] = {
        "binding_status": "bound-final-subject",
        "commit": "2" * 40,
        "manifest_sha256": "6" * 64,
        "tree": "3" * 40,
    }
    populated_bundle["cluster_id"] = crash_cluster_id(
        affected_atomic_rows=populated_bundle["affected_atomic_rows"],
        failure_class=populated_bundle["failure_class"],
        minimized_input_sha256=populated_bundle["minimized_input_sha256"],
        normalized_diagnostic_sha256=populated_bundle["normalized_diagnostic_sha256"],
        target_id=populated_bundle["target_id"],
    )
    populated_bundle["occurrence_id"] = __import__("hashlib").sha256(
        canonical_json(
            {
                "cluster_id": populated_bundle["cluster_id"],
                "input_sha256": populated_bundle["raw_input_sha256"],
            }
        )
    ).hexdigest()
    populated_bundle["limits"].update({"input_max_bytes": 4096, "timeout_seconds": 10})
    populated_bundle["minimization"] = {
        "algorithm": "deterministic-delete-v1",
        "executions": 7,
        "minimized_bytes": 5,
        "original_bytes": 23,
        "replay_reproduced": True,
    }
    populated_bundle["private_storage"] = {
        "object_locator": f"private://ecdsa_semantic/{populated_bundle['cluster_id']}",
        "retention_status": "retained-private-current",
    }
    populated_bundle["handoff"] = {
        "acknowledge_deadline": "2026-08-12T00:15:00Z",
        "affected_atomic_rows": ["fixture.atomic-row"],
        "assessment_deadline": None,
        "cluster_id": populated_bundle["cluster_id"],
        "confidentiality": "private",
        "created_at": "2026-08-12T00:00:00Z",
        "disposition": "private-ready-for-authorized-handoff",
        "external_receipt": "fixture-private-receipt",
        "minimization_duration_seconds": 1,
        "minimization_status": "completed-minimized-replayed",
        "minimized_input_sha256": populated_bundle["minimized_input_sha256"],
        "owner": "fixture-owner",
        "minimization_started_at": "2026-08-12T00:00:02Z",
        "reproduced_at": "2026-08-12T00:00:01Z",
        "reproduction_duration_seconds": 1,
        "reproduction_status": "completed-reproduced",
        "severity": "other",
        "resolution_deadline": "2026-08-26T00:00:00Z",
        "resolution_kind": "disposition",
        "status": "authorized-private-handoff",
        "target_id": "ecdsa_semantic",
    }
    populated_bundle["regression"] = {
        "finding_id": "fixture-finding",
        "fixed_binary_sha256": "7" * 64,
        "fixed_source_sha256": "8" * 64,
        "fix_reference": "fixture-fix-reference",
        "fixed_subject": {"commit": "4" * 40, "tree": "5" * 40},
        "independent_retest_passed": True,
        "local_fixed_child_evidence_sha256": None,
        "private_replay_passed": True,
        "status": "promoted-private",
        "test_id": "fixture-regression-test",
        "retest_evidence_sha256": "4" * 64,
    }
    _validate_schema(populated_bundle, bundle_schema, label="populated-crash-bundle")
    validate_crash_bundle(populated_bundle)
    missing_bundle = copy.deepcopy(populated_bundle)
    missing_bundle.pop("binary_sha256")
    checked(_validate_schema, missing_bundle, bundle_schema, label="missing-crash-field")
    extra_bundle = copy.deepcopy(populated_bundle)
    extra_bundle["extra"] = True
    checked(_validate_schema, extra_bundle, bundle_schema, label="extra-crash-field")
    wrong_bundle = copy.deepcopy(populated_bundle)
    wrong_bundle["binary_sha256"] = "not-a-digest"
    checked(_validate_schema, wrong_bundle, bundle_schema, label="wrong-crash-field")
    coherent_but_mismatched = copy.deepcopy(populated_bundle)
    coherent_but_mismatched["status"] = "private-ready-for-authorized-handoff"
    coherent_but_mismatched["handoff"]["status"] = "simulated-unfiled"
    coherent_but_mismatched["handoff"]["disposition"] = "simulated-unfiled"
    coherent_but_mismatched["handoff"]["external_receipt"] = None
    checked(validate_crash_bundle, coherent_but_mismatched)
    blocked_with_evidence = copy.deepcopy(bundle)
    blocked_with_evidence["binary_sha256"] = "4" * 64
    checked(validate_crash_bundle, blocked_with_evidence)
    bad_failure_class = copy.deepcopy(populated_bundle)
    bad_failure_class["failure_class"] = "arbitrary-defect"
    checked(validate_crash_bundle, bad_failure_class)
    missing_raw_log = copy.deepcopy(populated_bundle)
    missing_raw_log["raw_diagnostic_log_sha256"] = None
    checked(validate_crash_bundle, missing_raw_log)
    zero_corpus_digest = copy.deepcopy(populated_bundle)
    zero_corpus_digest["corpus_manifest_sha256"] = "0" * 64
    checked(validate_crash_bundle, zero_corpus_digest)
    locator_rebind = copy.deepcopy(populated_bundle)
    locator_rebind["private_storage"]["object_locator"] = "private://ecdsa_semantic/" + "f" * 64
    checked(validate_crash_bundle, locator_rebind)
    late_triage = copy.deepcopy(populated_bundle)
    late_triage["handoff"]["reproduction_duration_seconds"] = 901
    checked(validate_crash_bundle, late_triage)
    exact_capture_deadline = copy.deepcopy(populated_bundle)
    exact_capture_deadline["handoff"]["reproduced_at"] = "2026-08-12T00:15:00Z"
    exact_capture_deadline["handoff"]["minimization_started_at"] = "2026-08-12T00:15:00Z"
    validate_crash_bundle(exact_capture_deadline)
    capture_deadline_plus_one = copy.deepcopy(exact_capture_deadline)
    capture_deadline_plus_one["handoff"]["minimization_started_at"] = "2026-08-12T00:15:01Z"
    checked(validate_crash_bundle, capture_deadline_plus_one)
    late_reproduction = copy.deepcopy(exact_capture_deadline)
    late_reproduction["handoff"]["reproduced_at"] = "2026-08-12T00:15:01Z"
    late_reproduction["handoff"]["minimization_started_at"] = "2026-08-12T00:15:01Z"
    checked(validate_crash_bundle, late_reproduction)
    wrong_deadline = copy.deepcopy(populated_bundle)
    wrong_deadline["handoff"]["resolution_deadline"] = "2026-08-11T23:59:59Z"
    checked(validate_crash_bundle, wrong_deadline)
    empty_authorized_receipt = copy.deepcopy(populated_bundle)
    empty_authorized_receipt["handoff"]["external_receipt"] = ""
    checked(validate_crash_bundle, empty_authorized_receipt)
    created = dt.datetime(2026, 8, 12, tzinfo=dt.timezone.utc)

    def timestamp(seconds: int) -> str:
        return (created + dt.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    severity_deadlines = {
        "critical": ("mitigate", (4 * 3600, 24 * 3600, 72 * 3600)),
        "high": ("fix", (24 * 3600, 3 * 86400, 7 * 86400)),
        "other": ("disposition", (3 * 86400, 14 * 86400)),
    }
    for severity, (resolution_kind, ceilings) in severity_deadlines.items():
        exact_sla = copy.deepcopy(populated_bundle)
        handoff = exact_sla["handoff"]
        handoff["severity"] = severity
        handoff["acknowledge_deadline"] = timestamp(ceilings[0])
        if severity == "other":
            handoff["assessment_deadline"] = None
            handoff["resolution_deadline"] = timestamp(ceilings[1])
            deadline_fields = ("acknowledge_deadline", "resolution_deadline")
        else:
            handoff["assessment_deadline"] = timestamp(ceilings[1])
            handoff["resolution_deadline"] = timestamp(ceilings[2])
            deadline_fields = ("acknowledge_deadline", "assessment_deadline", "resolution_deadline")
        handoff["resolution_kind"] = resolution_kind
        validate_crash_bundle(exact_sla)
        for deadline_field in deadline_fields:
            one_second_late = copy.deepcopy(exact_sla)
            parsed = dt.datetime.strptime(
                one_second_late["handoff"][deadline_field], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=dt.timezone.utc)
            one_second_late["handoff"][deadline_field] = (
                parsed + dt.timedelta(seconds=1)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            checked(validate_crash_bundle, one_second_late)
    unresolved_bundle = copy.deepcopy(populated_bundle)
    unresolved_bundle["status"] = "triage-open"
    unresolved_bundle["handoff"]["status"] = "private-triage-open-unfiled"
    unresolved_bundle["handoff"]["disposition"] = "private-triage-open-unfiled"
    unresolved_bundle["handoff"]["external_receipt"] = None
    unresolved_bundle["regression"].update(
        {
            "fix_reference": None,
            "fixed_subject": {"commit": None, "tree": None},
            "fixed_binary_sha256": None,
            "fixed_source_sha256": None,
            "independent_retest_passed": False,
            "local_fixed_child_evidence_sha256": None,
            "retest_evidence_sha256": None,
            "status": "reproduces-unfixed",
        }
    )
    validate_crash_bundle(unresolved_bundle)
    unresolved_claimed_fixed = copy.deepcopy(unresolved_bundle)
    unresolved_claimed_fixed["regression"]["independent_retest_passed"] = True
    checked(validate_crash_bundle, unresolved_claimed_fixed)
    discovery_overwrite = copy.deepcopy(populated_bundle)
    discovery_overwrite["discovery_subject"] = copy.deepcopy(
        discovery_overwrite["regression"]["fixed_subject"]
    )
    discovery_overwrite["discovery_subject"]["binding_status"] = "bound-final-subject"
    discovery_overwrite["discovery_subject"]["manifest_sha256"] = "6" * 64
    checked(validate_crash_bundle, discovery_overwrite)
    fixed_overwrite = copy.deepcopy(populated_bundle)
    fixed_overwrite["regression"]["fixed_subject"] = {
        "commit": fixed_overwrite["discovery_subject"]["commit"],
        "tree": fixed_overwrite["discovery_subject"]["tree"],
    }
    checked(validate_crash_bundle, fixed_overwrite)
    cluster_base = crash_cluster_id(
        affected_atomic_rows=["fixture.atomic-row"],
        failure_class="controlled-panic-simulation-only",
        minimized_input_sha256="1" * 64,
        normalized_diagnostic_sha256="2" * 64,
        target_id="fixture_crash_target",
    )
    cluster_changed_input = crash_cluster_id(
        affected_atomic_rows=["fixture.atomic-row"],
        failure_class="controlled-panic-simulation-only",
        minimized_input_sha256="3" * 64,
        normalized_diagnostic_sha256="2" * 64,
        target_id="fixture_crash_target",
    )
    assert cluster_base != cluster_changed_input
    mutated = copy.deepcopy(build_corpus_manifest(REPO_ROOT))
    mutated["status"] = "passing"
    corpus_schema = closed_schema("corpus", "corpus", build_corpus_manifest(REPO_ROOT))
    checked(_validate_schema, mutated, corpus_schema, label="wrong-status")
    extra = copy.deepcopy(build_corpus_manifest(REPO_ROOT))
    extra["extra"] = True
    checked(_validate_schema, extra, corpus_schema, label="extra")
    corpus = build_corpus_manifest(REPO_ROOT)
    validate_corpus_manifest(corpus)
    final_commit = "a" * 40
    final_review = f"package-c-bootstrap-review-v1:{final_commit}"
    final_provenance = copy.deepcopy(corpus["targets"][0]["seeds"][0]["provenance"])
    final_promotion = copy.deepcopy(corpus["targets"][0]["seeds"][0]["promotion"])
    final_provenance.update({"review_id": final_review, "source_commit": final_commit})
    final_promotion["reviewer"] = final_review
    validate_bootstrap_subject_provenance(
        final_provenance,
        final_promotion,
        status="STABLE-final-subject-bound",
        subject_commit=final_commit,
    )
    final_null = copy.deepcopy(final_provenance)
    final_null["source_commit"] = None
    checked(
        validate_bootstrap_subject_provenance,
        final_null,
        final_promotion,
        status="STABLE-final-subject-bound",
        subject_commit=final_commit,
    )
    final_pending = copy.deepcopy(final_provenance)
    final_pending["review_id"] = "package-c-bootstrap-review-pending-final-subject"
    checked(
        validate_bootstrap_subject_provenance,
        final_pending,
        final_promotion,
        status="STABLE-final-subject-bound",
        subject_commit=final_commit,
    )
    final_rebound = copy.deepcopy(final_provenance)
    final_rebound["source_commit"] = "b" * 40
    checked(
        validate_bootstrap_subject_provenance,
        final_rebound,
        final_promotion,
        status="STABLE-final-subject-bound",
        subject_commit=final_commit,
    )
    corpus_source_rebind = copy.deepcopy(corpus)
    corpus_source_rebind["source_binding"]["framework_subject_commit"] = "c" * 40
    checked(validate_corpus_manifest, corpus_source_rebind)
    corpus_claim = copy.deepcopy(corpus)
    corpus_claim["operational_promotion_record"]["authenticated_writer"] = True
    checked(validate_corpus_manifest, corpus_claim)
    seed_claim = copy.deepcopy(corpus)
    seed_claim["targets"][0]["seeds"][0]["minimization"]["status"] = "campaign-minimized"
    checked(validate_corpus_manifest, seed_claim)
    seed_rebind = copy.deepcopy(corpus)
    seed_rebind["targets"][0]["seeds"][0]["target_ids"] = ["unknown_target"]
    checked(validate_corpus_manifest, seed_rebind)
    operational_object = copy.deepcopy(corpus["operational_object_template"])
    operational_object.update(
        {
            "first_seen": "2026-08-12T00:00:00Z",
            "path": "private/campaign/object-1",
            "semantic_states": ["sign-verify"],
            "sha256": "b" * 64,
            "size": 5,
            "target_ids": ["ecdsa_semantic"],
        }
    )
    operational_object["minimization"] = {
        "algorithm": "deterministic-delete-v1",
        "executions": 8,
        "minimized_size": 5,
        "original_size": 23,
        "semantic_preserved": True,
        "source_sha256": "c" * 64,
        "status": "campaign-minimized",
    }
    operational_object["provenance"] = {
        "in_repo_author": None,
        "lineage": "private-campaign-lineage-v1",
        "review_id": "fixture-review",
        "source_commit": "d" * 40,
        "source_kind": "campaign-generated",
        "source_uri": None,
        "writer_identity": "fixture-writer",
    }
    operational_object["retention"]["expires_at"] = "2026-09-11T00:00:00Z"
    operational_object["promotion"]["reviewer"] = "fixture-reviewer"
    validate_operational_corpus_object(operational_object)
    exact_retention_boundary = copy.deepcopy(operational_object)
    exact_retention_boundary["retention"]["expires_at"] = "2026-09-11T00:00:00Z"
    validate_operational_corpus_object(exact_retention_boundary)
    short_retention = copy.deepcopy(operational_object)
    short_retention["retention"]["expires_at"] = "2026-09-10T23:59:59Z"
    checked(validate_operational_corpus_object, short_retention)
    fork_object = copy.deepcopy(operational_object)
    fork_object["promotion"]["from_fork"] = True
    checked(validate_operational_corpus_object, fork_object)
    unauthorized_object = copy.deepcopy(operational_object)
    unauthorized_object["promotion"].update(
        {"attestation_sha256": "e" * 64, "authenticated_writer": True, "status": "promoted-reviewed"}
    )
    checked(validate_operational_corpus_object, unauthorized_object)

    campaign = build_campaign_status()
    validate_campaign_status(campaign)
    campaign_claim = copy.deepcopy(campaign)
    campaign_claim["targets"][0]["target_binary_sha256"] = "5" * 64
    checked(validate_campaign_status, campaign_claim)
    campaign_budget_rebind = copy.deepcopy(campaign)
    campaign_budget_rebind["targets"][0]["required_weekly_core_seconds"] += 1
    checked(validate_campaign_status, campaign_budget_rebind)
    campaign_dup = copy.deepcopy(campaign)
    campaign_dup["targets"][1]["target_id"] = campaign_dup["targets"][0]["target_id"]
    checked(validate_campaign_status, campaign_dup)
    populated_campaign = copy.deepcopy(campaign)
    populated_campaign["source_binding"]["framework_subject_commit"] = "7" * 40
    populated_campaign["source_binding"]["framework_subject_tree"] = "8" * 40
    populated = populated_campaign["targets"][0]
    registry_target = next(item for item in build_registry()["targets"] if item["id"] == populated["target_id"])
    populated.update(
        {
            "attestation_status": "authenticated-signed",
            "blocker_codes": [],
            "campaign_attestation_sha256": "5" * 64,
            "campaign_status": "operational-passing",
            "corpus_files_sha256": "6" * 64,
            "corpus_manifest_sha256": "6" * 64,
            "coverage_status": "passing",
            "crash_status": "passing-zero-observed",
            "delivered_rc_core_seconds": registry_target["required_rc_core_seconds"],
            "delivered_weekly_core_seconds": registry_target["required_weekly_core_seconds"],
            "evidence_classification": "first-party-operational-evidence",
            "freshness_status": "passing",
            "freeze": {"commit": "7" * 40, "time": "2026-08-11T00:00:00Z", "tree": "8" * 40},
            "rc_window": {"end": "2026-08-12T00:00:00Z", "start": "2026-08-11T00:00:00Z"},
            "resource_limits_sha256": __import__("hashlib").sha256(canonical_json(registry_target["resource_limits"])).hexdigest(),
            "resource_status": "passing-observed",
            "sanitizer_status": "passing-attested",
            "subject": {"commit": "7" * 40, "tree": "8" * 40},
            "target_binary_sha256": "6" * 64,
            "target_source_sha256": registry_target["source_sha256"],
            "weekly_window": {"end": "2026-08-11T00:00:00Z", "start": "2026-08-08T00:00:00Z"},
            "writer_identity": "fixture-authenticated-writer",
            "writer_identity_status": "authenticated-trusted",
        }
    )
    populated["coverage"] = {
        "comparison_config_sha256": "6" * 64,
        "current_artifact_sha256": "6" * 64,
        "edge_baseline": 100,
        "edge_current": 100,
        "function_baseline": 100,
        "function_current": 100,
        "prior_artifact_sha256": "6" * 64,
        "regression_status": "passing-no-regression",
        "semantic_state_baseline": len(registry_target["reviewed_semantic_states"]),
        "semantic_state_baseline_sha256": registry_target["reviewed_semantic_states_sha256"],
        "semantic_state_current": len(registry_target["reviewed_semantic_states"]),
        "semantic_state_current_sha256": registry_target["reviewed_semantic_states_sha256"],
    }
    populated["instrumentation"] = {
        "lanes": [
            {
                "binary_markers": ["__asan_init"],
                "lane_id": "asan",
                "positive_control_artifact_sha256": "1" * 64,
                "status": "passing-target-binary-and-live-control-attested",
            },
            {
                "binary_markers": [],
                "lane_id": "careful-ub",
                "positive_control_artifact_sha256": "2" * 64,
                "status": "passing-target-binary-and-live-control-attested",
            },
            {
                "binary_markers": list(INTEGRATED_ASAN_FUNCTION_SYMBOLS[1:]),
                "lane_id": "lsan",
                "positive_control_artifact_sha256": "3" * 64,
                "status": "passing-target-binary-and-live-control-attested",
            },
        ],
        "sanitizer_assignment_sha256": __import__("hashlib").sha256(canonical_json(build_sanitizer_controls())).hexdigest(),
        "status": "passing-per-target-attested",
    }
    populated["observed_outcomes"] = {
        "crashes": 0,
        "ooms": 0,
        "rejection_exhaustions": 0,
        "timeouts": 0,
        "unbounded_allocations": 0,
    }
    populated["weekly_shards"] = [
        {
            "allocated_cores": 1,
            "attestation_sha256": "9" * 64,
            "cpu_seconds": registry_target["required_weekly_core_seconds"],
            "end": "2026-08-11T00:00:00Z",
            "shard_id": "fixture-weekly-shard",
            "start": "2026-08-08T00:00:00Z",
            "target_id": populated["target_id"],
            "writer_identity": "fixture-authenticated-writer",
        }
    ]
    populated["rc_shards"] = [
        {
            "allocated_cores": 1,
            "attestation_sha256": "a" * 64,
            "cpu_seconds": registry_target["required_rc_core_seconds"],
            "end": "2026-08-12T00:00:00Z",
            "shard_id": "fixture-rc-shard",
            "start": "2026-08-11T00:00:00Z",
            "target_id": populated["target_id"],
            "writer_identity": "fixture-authenticated-writer",
        }
    ]
    populated["toolchain"] = {key: "6" * 64 for key in populated["toolchain"]}
    populated_campaign["counts"] = {"blocked_targets": 16, "operationally_passing_targets": 1, "targets": 17}
    validate_campaign_status(populated_campaign)
    coherent_campaign_rebind = copy.deepcopy(populated_campaign)
    coherent_campaign_rebind["targets"][0]["target_source_sha256"] = "a" * 64
    checked(validate_campaign_status, coherent_campaign_rebind)
    campaign_outcome = copy.deepcopy(populated_campaign)
    campaign_outcome["targets"][0]["observed_outcomes"]["timeouts"] = 1
    checked(validate_campaign_status, campaign_outcome)
    campaign_lane_omission = copy.deepcopy(populated_campaign)
    campaign_lane_omission["targets"][0]["instrumentation"]["lanes"].pop()
    checked(validate_campaign_status, campaign_lane_omission)
    campaign_lane_reorder = copy.deepcopy(populated_campaign)
    campaign_lane_reorder["targets"][0]["instrumentation"]["lanes"].reverse()
    checked(validate_campaign_status, campaign_lane_reorder)
    campaign_marker_rebind = copy.deepcopy(populated_campaign)
    campaign_marker_rebind["targets"][0]["instrumentation"]["lanes"][0]["binary_markers"] = ["__lsan_init"]
    checked(validate_campaign_status, campaign_marker_rebind)
    campaign_zero_semantic_states = copy.deepcopy(populated_campaign)
    campaign_zero_semantic_states["targets"][0]["coverage"]["semantic_state_baseline"] = 0
    campaign_zero_semantic_states["targets"][0]["coverage"]["semantic_state_current"] = 0
    checked(validate_campaign_status, campaign_zero_semantic_states)
    campaign_semantic_identity_rebind = copy.deepcopy(populated_campaign)
    campaign_semantic_identity_rebind["targets"][0]["coverage"]["semantic_state_current_sha256"] = "f" * 64
    checked(validate_campaign_status, campaign_semantic_identity_rebind)
    campaign_rc_before_freeze = copy.deepcopy(populated_campaign)
    campaign_rc_before_freeze["targets"][0]["freeze"]["time"] = "2026-08-11T00:00:01Z"
    checked(validate_campaign_status, campaign_rc_before_freeze)
    campaign_reused_shard = copy.deepcopy(populated_campaign)
    campaign_reused_shard["targets"][0]["rc_shards"][0]["shard_id"] = "fixture-weekly-shard"
    checked(validate_campaign_status, campaign_reused_shard)
    campaign_overlapping_hours = copy.deepcopy(populated_campaign)
    campaign_overlapping_hours["targets"][0]["weekly_window"]["end"] = "2026-08-12T00:00:00Z"
    campaign_overlapping_hours["targets"][0]["weekly_shards"][0]["end"] = "2026-08-12T00:00:00Z"
    checked(validate_campaign_status, campaign_overlapping_hours)
    campaign_exact_week = copy.deepcopy(populated_campaign)
    campaign_exact_week["targets"][0]["weekly_window"]["start"] = "2026-08-04T00:00:00Z"
    campaign_exact_week["targets"][0]["weekly_shards"][0]["start"] = "2026-08-04T00:00:00Z"
    validate_campaign_status(campaign_exact_week)
    campaign_week_plus_one = copy.deepcopy(campaign_exact_week)
    campaign_week_plus_one["targets"][0]["weekly_window"]["start"] = "2026-08-03T23:59:59Z"
    checked(validate_campaign_status, campaign_week_plus_one)
    campaign_old_shifted = copy.deepcopy(campaign_exact_week)
    campaign_old_shifted["targets"][0]["weekly_window"] = {
        "start": "2026-08-03T00:00:00Z",
        "end": "2026-08-10T00:00:00Z",
    }
    campaign_old_shifted["targets"][0]["weekly_shards"][0].update(
        {"start": "2026-08-03T00:00:00Z", "end": "2026-08-10T00:00:00Z"}
    )
    checked(validate_campaign_status, campaign_old_shifted)
    campaign_cross_target_reuse = copy.deepcopy(populated_campaign)
    second_registry = next(
        item for item in build_registry()["targets"] if item["id"] == campaign_cross_target_reuse["targets"][1]["target_id"]
    )
    second = copy.deepcopy(populated)
    second["target_id"] = second_registry["id"]
    second["target_source_sha256"] = second_registry["source_sha256"]
    second["resource_limits_sha256"] = __import__("hashlib").sha256(
        canonical_json(second_registry["resource_limits"])
    ).hexdigest()
    second["required_freshness_seconds"] = second_registry["required_freshness_seconds"]
    second["required_rc_core_seconds"] = second_registry["required_rc_core_seconds"]
    second["required_weekly_core_seconds"] = second_registry["required_weekly_core_seconds"]
    second["campaign_attestation_sha256"] = "4" * 64
    second["delivered_rc_core_seconds"] = second_registry["required_rc_core_seconds"]
    second["delivered_weekly_core_seconds"] = second_registry["required_weekly_core_seconds"]
    second["weekly_shards"][0]["cpu_seconds"] = second_registry["required_weekly_core_seconds"]
    second["weekly_shards"][0]["target_id"] = second_registry["id"]
    second["rc_shards"][0]["cpu_seconds"] = second_registry["required_rc_core_seconds"]
    second["rc_shards"][0]["target_id"] = second_registry["id"]
    campaign_cross_target_reuse["targets"][1] = second
    campaign_cross_target_reuse["counts"] = {
        "blocked_targets": 15,
        "operationally_passing_targets": 2,
        "targets": 17,
    }
    checked(validate_campaign_status, campaign_cross_target_reuse)
    campaign_cross_target_attestation_reuse = copy.deepcopy(campaign_cross_target_reuse)
    campaign_cross_target_attestation_reuse["targets"][1]["weekly_shards"][0]["shard_id"] = "fixture-second-weekly-shard"
    campaign_cross_target_attestation_reuse["targets"][1]["rc_shards"][0]["shard_id"] = "fixture-second-rc-shard"
    checked(validate_campaign_status, campaign_cross_target_attestation_reuse)

    # The final structural binding removes only the exact subject-stage blocker;
    # it must not erase any operational, coverage, oracle, writer, or campaign HOLD.
    fuzzing_module = __import__("fuzzing_lib")
    original_binding = (
        fuzzing_module.STATUS,
        fuzzing_module.FRAMEWORK_SUBJECT_COMMIT,
        fuzzing_module.FRAMEWORK_SUBJECT_TREE,
        fuzzing_module.FRAMEWORK_SUBJECT_MANIFEST_SHA256,
    )
    try:
        fuzzing_module.STATUS = "STABLE-final-subject-bound"
        fuzzing_module.FRAMEWORK_SUBJECT_COMMIT = "a" * 40
        fuzzing_module.FRAMEWORK_SUBJECT_TREE = "b" * 40
        fuzzing_module.FRAMEWORK_SUBJECT_MANIFEST_SHA256 = "c" * 64
        stable_mapping = fuzzing_module.build_row_mapping(REPO_ROOT)
        stable_campaign = fuzzing_module.build_campaign_status()
        stable_corpus = fuzzing_module.build_corpus_manifest(REPO_ROOT)
        fuzzing_module.validate_corpus_manifest(stable_corpus)
        assert all(
            item["provenance"]["source_commit"] == "a" * 40
            and item["provenance"]["review_id"] == "package-c-bootstrap-review-v1:" + "a" * 40
            for target in stable_corpus["targets"]
            for item in [*target["seeds"], *target["dictionaries"]]
        )
        if any(
            blocker.endswith("-unstable")
            for row in stable_mapping["rows"]
            for blocker in row["blocker_codes"]
        ) or any(
            blocker.endswith("-unstable")
            for target in stable_campaign["targets"]
            for blocker in target["blocker_codes"]
        ):
            raise AssertionError("final structural projection retained a stale unstable blocker")
        blocker_sizes = __import__("collections").Counter(
            (row["source_kind"], row["target_id"] is not None, len(row["blocker_codes"]))
            for row in stable_mapping["rows"]
        )
        assert blocker_sizes == {
            ("curated-operation", True, 4): 372,
            ("curated-operation", False, 2): 194,
            ("unreviewed-gap", False, 3): 8632,
        }
        assert all(len(target["blocker_codes"]) == 5 for target in stable_campaign["targets"])
    finally:
        (
            fuzzing_module.STATUS,
            fuzzing_module.FRAMEWORK_SUBJECT_COMMIT,
            fuzzing_module.FRAMEWORK_SUBJECT_TREE,
            fuzzing_module.FRAMEWORK_SUBJECT_MANIFEST_SHA256,
        ) = original_binding

    # The sealed subtree never contains interpreter cache output.
    if any(path.name == "__pycache__" or path.suffix == ".pyc" for path in FRAMEWORK_DIR.rglob("*")):
        raise AssertionError("Python bytecode cache entered the sealed subtree")

    print(f"Package C adversarial selftest passed ({tests} negative controls)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
