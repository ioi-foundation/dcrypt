#!/usr/bin/env python3
"""Adversarial self-tests for Package E migration and capture contracts."""

from __future__ import annotations

import ast
import copy
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
    exceptions: tuple[type[BaseException], ...] = (model.PackageEError,),
    **kwargs: Any,
) -> None:
    try:
        function(*args, **kwargs)
    except exceptions:
        return
    raise AssertionError(f"negative control unexpectedly passed: {function.__name__}")


def _candidate(role: str, artifact_name: str = "report.bin") -> dict[str, Any]:
    raw = artifact_name.encode("utf-8")
    artifacts = [{
        "path": artifact_name,
        "sha256": model.sha256_bytes(raw),
        "size": len(raw),
    }]
    role_data: dict[str, dict[str, Any]] = {
        "downstream-migration-candidate": {
            "compile_succeeded": True,
            "fixture": "tests/tests/error_api_v4_migration.rs",
            "legacy_compile_failed": True,
            "stderr_sha256": "1" * 64,
            "stdout_sha256": "2" * 64,
            "toolchain_sha256": "3" * 64,
        },
        "external-review-candidate": {
            "accepted": False,
            "independent": True,
            "report_sha256": "4" * 64,
            "reviewer_identity_sha256": "5" * 64,
            "signature_sha256": "6" * 64,
        },
        "acceptance": {
            "accepted": False,
            "decision": "disabled",
            "reason": "v1 acceptance is disabled",
        },
    }
    value = {
        "artifact_role": role,
        "artifacts": artifacts,
        "content_policy": model.ROLE_POLICIES[role],
        "promotion_eligible": False,
        "raw_artifact_set_sha256": model.artifact_set_sha256(artifacts),
        "role_data": role_data[role],
        "schema_version": 1,
        "status": model.ROLE_STATUSES[role],
        "subject_binding": {
            "r_commit": model.R_E_COMMIT,
            "r_tree": model.R_E_TREE,
            "subject_manifest_sha256": model.R_E_SUBJECT_MANIFEST_SHA256,
        },
        "trusted": False,
    }
    model.validate_schema_value(value)
    return value


def _write_bundle(root: Path, candidate: dict[str, Any]) -> None:
    root.mkdir(mode=0o700)
    (root / "candidate.json").write_bytes(model.canonical_json(candidate))
    os.chmod(root / "candidate.json", 0o600)
    for artifact in candidate["artifacts"]:
        path = root / artifact["path"]
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(artifact["path"].encode("utf-8"))
        os.chmod(path, 0o600)


def _rewrite_candidate(root: Path, candidate: dict[str, Any]) -> None:
    (root / "candidate.json").write_bytes(model.canonical_json(candidate))
    os.chmod(root / "candidate.json", 0o600)


def _static_capture_policy() -> None:
    raw = (model.FRAMEWORK / "capture.py").read_text(encoding="utf-8")
    tree = ast.parse(raw)
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    forbidden = {"socket", "subprocess", "urllib", "http", "requests", "ssl"}
    if imports & forbidden:
        raise AssertionError(f"capture imports forbidden execution/network modules: {imports & forbidden}")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"system", "popen", "spawn", "run", "call", "check_call", "check_output"}:
                raise AssertionError("capture contains a forbidden command-execution call")


def main() -> int:
    controls = 0
    package = model.build_package_document()
    model.validate_package_document(package)
    controls += 1
    schema = model.build_schema()
    if set(schema) != {"$schema", "oneOf", "title"} or len(schema["oneOf"]) != 4:
        raise AssertionError("closed role schema shape differs")
    controls += 1
    local = model.build_local_removal_proof()
    if model.validate_evidence_candidate(local) != "local-removal-proof":
        raise AssertionError("local removal proof role differs")
    controls += 1

    for role in ("downstream-migration-candidate", "external-review-candidate"):
        candidate = _candidate(role)
        if model.validate_evidence_candidate(candidate, capture=True) != role:
            raise AssertionError("capture-admissible role differs")
        controls += 1
        for mutation in (
            "promotion", "trusted", "digest", "subject", "surplus", "missing",
            "duplicate-path", "traversal", "wrong-role-data",
        ):
            changed = copy.deepcopy(candidate)
            if mutation == "promotion":
                changed["promotion_eligible"] = True
            elif mutation == "trusted":
                changed["trusted"] = True
            elif mutation == "digest":
                changed["raw_artifact_set_sha256"] = "0" * 64
            elif mutation == "subject":
                changed["subject_binding"]["r_commit"] = model.A_D_COMMIT
            elif mutation == "surplus":
                changed["surplus"] = True
            elif mutation == "missing":
                del changed["status"]
            elif mutation == "duplicate-path":
                changed["artifacts"].append(copy.deepcopy(changed["artifacts"][0]))
                changed["raw_artifact_set_sha256"] = model.artifact_set_sha256(changed["artifacts"])
            elif mutation == "traversal":
                changed["artifacts"][0]["path"] = "../escape"
                changed["raw_artifact_set_sha256"] = model.artifact_set_sha256(changed["artifacts"])
            else:
                changed["role_data"]["cross_role_field"] = True
            _expect_failure(model.validate_evidence_candidate, changed, capture=True)
            controls += 1

    acceptance = _candidate("acceptance")
    model.validate_schema_value(acceptance)
    _expect_failure(model.validate_evidence_candidate, acceptance)
    _expect_failure(model.validate_evidence_candidate, acceptance, capture=True)
    controls += 2
    _expect_failure(model.validate_evidence_candidate, local, capture=True)
    controls += 1

    mutated_package = copy.deepcopy(package)
    mutated_package["release_state"]["publish_eligible"] = True
    _expect_failure(model.validate_package_document, mutated_package)
    controls += 1
    mutated_package = copy.deepcopy(package)
    mutated_package["workspace_version"] = "4.0.0"
    _expect_failure(model.validate_package_document, mutated_package)
    controls += 1

    artifacts_raw, _metadata = model.read_regular_once(
        model.FRAMEWORK / "ARTIFACTS.json", label="Package E selftest artifacts"
    )
    artifacts = model.parse_json_strict(
        artifacts_raw, label="Package E selftest artifacts", require_canonical=True
    )
    verify.validate_artifact_document(artifacts)
    for mutation in ("missing", "surplus", "self", "digest", "mode"):
        changed = copy.deepcopy(artifacts)
        if mutation == "missing":
            changed["files"].pop()
        elif mutation == "surplus":
            changed["files"].append({
                "git_mode": "100644", "kind": "reviewed-source", "path": "surplus",
                "sha256": "0" * 64, "size": 0,
            })
        elif mutation == "self":
            changed["files"].append({
                "git_mode": "100644", "kind": "generated", "path": "ARTIFACTS.json",
                "sha256": "0" * 64, "size": 0,
            })
            changed["files"].sort(key=lambda row: row["path"])
        elif mutation == "digest":
            changed["files"][0]["sha256"] = "0" * 64
        else:
            changed["files"][0]["git_mode"] = "100755"
        _expect_failure(verify.validate_artifact_document, changed)
        controls += 1

    _static_capture_policy()
    controls += 1
    with tempfile.TemporaryDirectory(prefix="dcrypt-package-e-capture-") as temporary:
        parent = Path(temporary)
        os.chmod(parent, 0o700)
        source_parent = parent / "source-parent"
        destination_parent = parent / "destination-parent"
        source_parent.mkdir(mode=0o700)
        destination_parent.mkdir(mode=0o700)
        source = source_parent / "source"
        destination = destination_parent / "captured"
        candidate = _candidate("downstream-migration-candidate")
        _write_bundle(source, candidate)
        result = capture.capture(source, destination)
        if (
            result["artifact_role"] != "downstream-migration-candidate"
            or result["promotion_eligible"] is not False
            or result["trusted"] is not False
            or not (destination / "candidate.json").is_file()
            or not (destination / "report.bin").is_file()
        ):
            raise AssertionError("positive descriptor-safe capture differs")
        controls += 1

    def bundle_control(name: str, mutate: Callable[[Path, Path, dict[str, Any]], None]) -> None:
        nonlocal controls
        with tempfile.TemporaryDirectory(prefix="dcrypt-package-e-capture-") as temporary:
            parent = Path(temporary)
            os.chmod(parent, 0o700)
            source_parent = parent / "source-parent"
            destination_parent = parent / "destination-parent"
            source_parent.mkdir(mode=0o700)
            destination_parent.mkdir(mode=0o700)
            source = source_parent / "source"
            destination = destination_parent / "captured"
            candidate = _candidate("external-review-candidate")
            _write_bundle(source, candidate)
            mutate(source, destination, candidate)
            _expect_failure(capture.capture, source, destination)
            controls += 1

    bundle_control("hardlink", lambda source, _destination, _candidate: os.link(source / "report.bin", source / "extra-hardlink"))
    bundle_control("symlink", lambda source, _destination, _candidate: (source / "report.bin").unlink() or (source / "report.bin").symlink_to("candidate.json"))
    bundle_control("surplus", lambda source, _destination, _candidate: (source / "surplus").write_bytes(b"x"))
    bundle_control("existing-output", lambda _source, destination, _candidate: destination.mkdir(mode=0o700))
    bundle_control("world-readable-source", lambda source, _destination, _candidate: os.chmod(source, 0o755))
    bundle_control("world-readable-file", lambda source, _destination, _candidate: os.chmod(source / "candidate.json", 0o644))

    with tempfile.TemporaryDirectory(prefix="dcrypt-package-e-capture-") as temporary:
        parent = Path(temporary)
        os.chmod(parent, 0o700)
        source_parent = parent / "source-parent"
        destination_parent = parent / "destination-parent"
        source_parent.mkdir(mode=0o700)
        destination_parent.mkdir(mode=0o700)
        source = source_parent / "source"
        source.mkdir(mode=0o700)
        os.mkfifo(source / "candidate.json", 0o600)
        _expect_failure(capture.capture, source, destination_parent / "captured")
        controls += 1

    with tempfile.TemporaryDirectory(prefix="dcrypt-package-e-capture-") as temporary:
        parent = Path(temporary)
        os.chmod(parent, 0o700)
        destination_parent = parent / "destination-parent"
        destination_parent.mkdir(mode=0o700)
        _expect_failure(
            capture.capture,
            Path("//") / parent.relative_to("/") / "source",
            destination_parent / "captured",
        )
        controls += 1

    def private_layout(prefix: str) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        context = tempfile.TemporaryDirectory(prefix=prefix)
        parent = Path(context.name)
        os.chmod(parent, 0o700)
        source_parent = parent / "source-parent"
        destination_parent = parent / "destination-parent"
        source_parent.mkdir(mode=0o700)
        destination_parent.mkdir(mode=0o700)
        return context, source_parent / "source", destination_parent, destination_parent / "captured"

    # Exact declared digest/size and role-specific cap controls pass the role
    # schema, then fail in the descriptor-safe raw bundle contract.
    for mutation in ("artifact-digest", "artifact-size", "file-cap", "per-file-cap", "aggregate-cap"):
        context, source, destination_parent, destination = private_layout(
            "dcrypt-package-e-capture-contract-"
        )
        try:
            candidate = _candidate("external-review-candidate")
            if mutation == "artifact-digest":
                candidate["artifacts"][0]["sha256"] = "0" * 64
            elif mutation == "artifact-size":
                candidate["artifacts"][0]["size"] += 1
            elif mutation == "file-cap":
                candidate["artifacts"] = [
                    {
                        "path": f"artifact-{index:02d}.bin",
                        "sha256": model.sha256_bytes(f"artifact-{index:02d}.bin".encode()),
                        "size": len(f"artifact-{index:02d}.bin".encode()),
                    }
                    for index in range(model.ROLE_CAPS["external-review-candidate"]["files"] + 1)
                ]
            elif mutation == "per-file-cap":
                candidate["artifacts"][0]["size"] = (
                    model.ROLE_CAPS["external-review-candidate"]["per_file"] + 1
                )
            else:
                per_file = model.ROLE_CAPS["external-review-candidate"]["per_file"]
                candidate["artifacts"] = [
                    {
                        "path": f"aggregate-{index}.bin",
                        "sha256": model.sha256_bytes(f"aggregate-{index}.bin".encode()),
                        "size": per_file,
                    }
                    for index in range(5)
                ]
            candidate["raw_artifact_set_sha256"] = model.artifact_set_sha256(
                candidate["artifacts"]
            )
            model.validate_schema_value(candidate)
            _write_bundle(source, candidate)
            _expect_failure(capture.capture, source, destination)
            if destination.exists() or any(
                path.name.startswith(".dcrypt-package-e-capture-")
                for path in destination_parent.iterdir()
            ):
                raise AssertionError(f"failed {mutation} capture left destination residue")
            controls += 1
        finally:
            context.cleanup()

    # Artifact FIFO must be rejected without a blocking read.
    context, source, destination_parent, destination = private_layout(
        "dcrypt-package-e-capture-artifact-fifo-"
    )
    try:
        candidate = _candidate("external-review-candidate")
        _write_bundle(source, candidate)
        artifact = source / candidate["artifacts"][0]["path"]
        artifact.unlink()
        os.mkfifo(artifact, 0o600)
        _expect_failure(capture.capture, source, destination)
        controls += 1
    finally:
        context.cleanup()

    # Symlinked ancestry, nonprivate destination parents, and overlapping root
    # identities are all rejected before any candidate bytes are copied.
    for mutation in ("source-symlink", "destination-symlink", "nonprivate-parent", "same-root", "same-parent"):
        with tempfile.TemporaryDirectory(prefix="dcrypt-package-e-capture-roots-") as temporary:
            parent = Path(temporary)
            os.chmod(parent, 0o700)
            source_parent = parent / "source-parent"
            destination_parent = parent / "destination-parent"
            source_parent.mkdir(mode=0o700)
            destination_parent.mkdir(mode=0o700)
            source = source_parent / "source"
            _write_bundle(source, _candidate("external-review-candidate"))
            destination = destination_parent / "captured"
            if mutation == "source-symlink":
                link = parent / "source-link"
                link.symlink_to(source_parent, target_is_directory=True)
                source = link / "source"
            elif mutation == "destination-symlink":
                link = parent / "destination-link"
                link.symlink_to(destination_parent, target_is_directory=True)
                destination = link / "captured"
            elif mutation == "nonprivate-parent":
                os.chmod(destination_parent, 0o755)
            elif mutation == "same-root":
                destination = source
            else:
                alias_source = destination_parent / "alias-source"
                _write_bundle(alias_source, _candidate("external-review-candidate"))
                source = alias_source
            _expect_failure(capture.capture, source, destination)
            controls += 1

    # Inject a failure after atomic publication. Verified cleanup must remove
    # both the published destination and invocation-owned staging residue.
    context, source, destination_parent, destination = private_layout(
        "dcrypt-package-e-capture-rollback-"
    )
    try:
        _write_bundle(source, _candidate("external-review-candidate"))
        original_verify = capture._verify_destination_tree
        verify_calls = 0

        def fail_after_publication(*args: Any, **kwargs: Any) -> None:
            nonlocal verify_calls
            verify_calls += 1
            original_verify(*args, **kwargs)
            if verify_calls == 2:
                raise model.PackageEError("injected post-publication verification failure")

        capture._verify_destination_tree = fail_after_publication
        try:
            _expect_failure(capture.capture, source, destination)
        finally:
            capture._verify_destination_tree = original_verify
        if (
            verify_calls != 2
            or os.path.lexists(destination)
            or any(
                path.name.startswith(".dcrypt-package-e-capture-")
                for path in destination_parent.iterdir()
            )
        ):
            raise AssertionError("post-publication capture rollback left residue")
        controls += 1
    finally:
        context.cleanup()

    # Strict JSON controls are exercised through the real descriptor-anchored
    # capture path, not only through the model parser.
    malformed_records = (
        b'{"a":1,"a":2}\n',
        b'{"schema_version":1.0}\n',
        '{"name":"e\u0301"}\n'.encode("utf-8"),
        b'{"b":1,"a":2}\n',
    )
    for index, candidate_raw in enumerate(malformed_records):
        context, source, destination_parent, destination = private_layout(
            f"dcrypt-package-e-capture-json-{index}-"
        )
        try:
            source.mkdir(mode=0o700)
            (source / "candidate.json").write_bytes(candidate_raw)
            os.chmod(source / "candidate.json", 0o600)
            _expect_failure(capture.capture, source, destination)
            if destination.exists() or any(destination_parent.iterdir()):
                raise AssertionError("malformed candidate capture left residue")
            controls += 1
        finally:
            context.cleanup()

    print(f"Package E self-test passed: adversarial-controls={controls} release=HOLD")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
