#!/usr/bin/env python3
"""Adversarial self-tests for the blocked clean-room reference scaffold."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from common import ValidationError, canonical_bytes, sha256_file, validate_request
from runner import validate_worker_response


ROOT = Path(__file__).resolve().parent
SOURCE_REPO = ROOT.parents[1]
VERIFY = ROOT / "verify-scaffold.py"
RUNNER = ROOT / "runner.py"
WORKER = ROOT / "worker.py"
SUBJECT_ABSENT_BUILD_INPUTS = [
    ".cargo/config",
    ".cargo/config.toml",
    "build.rs",
    "rust-toolchain",
    "rust-toolchain.toml",
]
SUBJECT_EXCLUDED_FILES = {
    ".gitignore",
    "tools/bench-processor/Cargo.lock",
    "tools/cargo_snapshot.sh",
    "tools/codebase_snapshot.sh",
    "tools/codebase_snapshot2.sh",
    "tools/tree.sh",
}
passed = 0


def ok(condition: bool, label: str) -> None:
    global passed
    if not condition:
        raise AssertionError(label)
    passed += 1


def run(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd or ROOT,
        check=False,
        timeout=30,
    )


def run_runner(raw: bytes) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryDirectory(prefix="clean-room-request-") as tmp:
        request = Path(tmp) / "request.json"
        request.write_bytes(raw)
        return run([sys.executable, str(RUNNER), "--request", str(request)])


def response(completed: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    return json.loads(completed.stdout.decode("ascii"))


def rewrite_manifest(root: Path) -> None:
    files = sorted(path for path in root.iterdir() if path.name != "ARTIFACTS.sha256")
    lines = [f"{sha256_file(path)}  {path.name}\n" for path in files]
    (root / "ARTIFACTS.sha256").write_text("".join(lines), encoding="ascii")


def rebind_verifier_artifact_pin(root: Path, name: str) -> None:
    verifier = root / "verify-scaffold.py"
    text = verifier.read_text(encoding="utf-8")
    old = f'    "{name}": "{sha256_file(ROOT / name)}",'
    new = f'    "{name}": "{sha256_file(root / name)}",'
    if text.count(old) != 1:
        raise AssertionError(f"verifier artifact pin is not unique: {name}")
    verifier.write_text(text.replace(old, new), encoding="utf-8")


def coherently_mutated(
    mutator: Any, *, protocol_mutator: Any | None = None
) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryDirectory(prefix="clean-room-mutation-") as tmp:
        repo = Path(tmp) / "repo"
        cloned = run(
            [
                "git",
                "clone",
                "--quiet",
                "--shared",
                "--no-checkout",
                str(SOURCE_REPO),
                str(repo),
            ],
            cwd=Path(tmp),
        )
        if cloned.returncode != 0:
            raise AssertionError(
                "cannot create adversarial Git fixture: "
                + cloned.stderr.decode("utf-8", "replace")
            )
        copy = repo / "verification" / "clean-room-protocol-reference"
        copy.parent.mkdir(parents=True)
        shutil.copytree(ROOT, copy)
        protocol_copy = (
            repo
            / "assurance"
            / "interoperability"
            / "protocol-specs"
            / "current-behavior.json"
        )
        protocol_copy.parent.mkdir(parents=True)
        shutil.copy2(
            SOURCE_REPO
            / "assurance"
            / "interoperability"
            / "protocol-specs"
            / "current-behavior.json",
            protocol_copy,
        )
        for name in ("subject-manifest.json", "curated-operations.toml"):
            source = SOURCE_REPO / "assurance" / name
            destination = repo / "assurance" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        if protocol_mutator is not None:
            protocol_mutator(protocol_copy)
        mutator(copy)
        rewrite_manifest(copy)
        return run([sys.executable, str(copy / "verify-scaffold.py")], cwd=copy)


def rejected(
    completed: subprocess.CompletedProcess[bytes], needle: str, label: str
) -> None:
    ok(
        completed.returncode != 0 and needle.encode("utf-8") in completed.stderr,
        label,
    )


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="ascii"))


def save_json(path: Path, value: Any) -> None:
    path.write_bytes(canonical_bytes(value))


def save_protocol(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def subject_path_included(path_value: str) -> bool:
    return (
        path_value not in SUBJECT_EXCLUDED_FILES
        and path_value != "assurance"
        and not path_value.startswith("assurance/")
    )


def committed_subject_rows(repo: Path, commit: str) -> list[dict[str, str]]:
    listing = run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", commit, "--", "."],
        cwd=repo,
    )
    if listing.returncode != 0:
        raise AssertionError("cannot enumerate adversarial subject commit")
    entries: list[tuple[str, str, str]] = []
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        path_value = raw_path.decode("utf-8")
        if not subject_path_included(path_value):
            continue
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise AssertionError(f"unexpected adversarial tree entry: {path_value}")
        entries.append((path_value, mode, object_id))

    object_ids = sorted({object_id for _path, _mode, object_id in entries})
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=repo,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    request = b"".join((object_id + "\n").encode("ascii") for object_id in object_ids)
    output, error = process.communicate(request, timeout=30)
    if process.returncode != 0:
        raise AssertionError(
            "cannot read adversarial subject blobs: "
            + error.decode("utf-8", "replace")
        )
    digests: dict[str, str] = {}
    offset = 0
    for expected in object_ids:
        end = output.find(b"\n", offset)
        if end < 0:
            raise AssertionError("truncated adversarial Git batch header")
        header = output[offset:end].decode("ascii").split(" ")
        if len(header) != 3 or header[0] != expected or header[1] != "blob":
            raise AssertionError("unexpected adversarial Git batch header")
        size = int(header[2])
        start = end + 1
        finish = start + size
        if finish >= len(output) or output[finish : finish + 1] != b"\n":
            raise AssertionError("truncated adversarial Git batch blob")
        digests[expected] = hashlib.sha256(output[start:finish]).hexdigest()
        offset = finish + 1
    if offset != len(output):
        raise AssertionError("trailing adversarial Git batch output")
    return [
        {"path": path_value, "sha256": digests[object_id], "git_mode": mode}
        for path_value, mode, object_id in sorted(entries)
    ]


def coherent_final_binding(
    *,
    bound_absent_inputs: bool = False,
    commit_final_assurance: bool = False,
    after_rebind: Any | None = None,
) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryDirectory(prefix="clean-room-final-binding-") as tmp:
        repo = Path(tmp) / "repo"
        cloned = run(
            ["git", "clone", "--quiet", "--shared", str(SOURCE_REPO), str(repo)],
            cwd=Path(tmp),
        )
        if cloned.returncode != 0:
            raise AssertionError(
                "cannot create coherent final-binding fixture: "
                + cloned.stderr.decode("utf-8", "replace")
            )
        copy = repo / "verification" / "clean-room-protocol-reference"
        shutil.rmtree(copy)
        shutil.copytree(ROOT, copy)
        if bound_absent_inputs:
            for path_value in SUBJECT_ABSENT_BUILD_INPUTS:
                path = repo / path_value
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    f"adversarial declared-absent input: {path_value}\n",
                    encoding="utf-8",
                )
        for key, value in (
            ("user.email", "clean-room-selftest@example.invalid"),
            ("user.name", "Clean Room Selftest"),
        ):
            configured = run(["git", "config", key, value], cwd=repo)
            if configured.returncode != 0:
                raise AssertionError("cannot configure adversarial Git fixture")
        add_paths = ["verification/clean-room-protocol-reference"]
        if bound_absent_inputs:
            add_paths.extend(SUBJECT_ABSENT_BUILD_INPUTS)
        added = run(["git", "add", "--force", "--", *add_paths], cwd=repo)
        committed = run(
            [
                "git",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                "coherent final-binding subject",
            ],
            cwd=repo,
        )
        if added.returncode != 0 or committed.returncode != 0:
            raise AssertionError(
                "cannot commit coherent final-binding subject: "
                + added.stderr.decode("utf-8", "replace")
                + committed.stderr.decode("utf-8", "replace")
            )
        commit = run(["git", "rev-parse", "HEAD"], cwd=repo).stdout.decode().strip()
        tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=repo).stdout.decode().strip()
        rows = committed_subject_rows(repo, commit)
        manifest = {
            "schema_version": 1,
            "source_commit": commit,
            "source_tree": tree,
            "roots": ["."],
            "root_files": [
                "Cargo.lock",
                "Cargo.toml",
                "CONSTANT_TIME_POLICY.md",
                "README.md",
                "SECURITY.md",
                "deny.toml",
                "implementation-boundary.toml",
            ],
            "absent_build_inputs": SUBJECT_ABSENT_BUILD_INPUTS,
            "include_policy": "production-and-evidence-v1",
            "files": rows,
        }
        manifest_path = repo / "assurance" / "subject-manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        digest_by_path = {row["path"]: row["sha256"] for row in rows}
        protocol_path = (
            repo
            / "assurance"
            / "interoperability"
            / "protocol-specs"
            / "current-behavior.json"
        )
        protocol = load_json(protocol_path)
        for row in protocol["source_bindings"]:
            row["sha256"] = digest_by_path[row["path"]]
        protocol["subject_binding"] = {
            "binding_stage": "final-subject-candidate-review-required",
            "curated_operations_path": "assurance/curated-operations.toml",
            "curated_operations_sha256": sha256_file(
                repo / "assurance" / "curated-operations.toml"
            ),
            "final_rebind_required": False,
            "manifest_file_count": len(rows),
            "manifest_include_policy": "production-and-evidence-v1",
            "source_commit": commit,
            "source_tree": tree,
            "subject_manifest_path": "assurance/subject-manifest.json",
            "subject_manifest_sha256": sha256_file(manifest_path),
        }
        save_protocol(protocol_path, protocol)
        if commit_final_assurance:
            added = run(
                [
                    "git",
                    "add",
                    "--",
                    "assurance/subject-manifest.json",
                    "assurance/interoperability/protocol-specs/current-behavior.json",
                ],
                cwd=repo,
            )
            committed_assurance = run(
                ["git", "commit", "--quiet", "-m", "assurance-only final rebind"],
                cwd=repo,
            )
            clean = run(["git", "status", "--porcelain=v1", "-z"], cwd=repo)
            if (
                added.returncode != 0
                or committed_assurance.returncode != 0
                or clean.returncode != 0
                or clean.stdout
            ):
                raise AssertionError(
                    "cannot construct clean assurance-only S2 final-binding fixture"
                )
        if after_rebind is not None:
            after_rebind(repo)
        return run([sys.executable, str(copy / "verify-scaffold.py")], cwd=copy)


def status_request() -> dict[str, Any]:
    return {
        "operation": "status",
        "payload": {},
        "protocol_version": "dcrypt-clean-room-ipc/1",
        "request_id": "selftest-status",
        "suite_id": None,
    }


def crypto_request(operation: str = "generate-fixture") -> dict[str, Any]:
    return {
        "operation": operation,
        "payload": {
            "direction": "reference-to-dcrypt",
            "input_sha256": "1" * 64,
        },
        "protocol_version": "dcrypt-clean-room-ipc/1",
        "request_id": "selftest-crypto",
        "suite_id": "ECIES-P256-HKDF-SHA256-CHACHA20POLY1305",
    }


def main() -> int:
    baseline = run([sys.executable, str(VERIFY)])
    ok(baseline.returncode == 0, "baseline verifier")

    status_raw = canonical_bytes(status_request())
    status = run_runner(status_raw)
    ok(status.returncode == 3, "status exits release-blocked")
    ok(response(status)["error"]["code"] == "scaffold-only", "status is scaffold-only")
    ok(response(status)["accepted_fixture_count"] == 0, "status has zero fixtures")
    ok(response(status)["accepted_evidence_count"] == 0, "status has zero evidence")

    malformed = run_runner(b"{not-json}\n")
    ok(malformed.returncode == 3 and not malformed.stdout, "malformed request refused")

    noncanonical = run_runner(json.dumps(status_request(), indent=2).encode("ascii") + b"\n")
    ok(noncanonical.returncode == 3 and not noncanonical.stdout, "noncanonical request refused")

    duplicate = status_raw.replace(
        b'"operation":"status"', b'"operation":"status","operation":"status"'
    )
    duplicate_result = run_runner(duplicate)
    ok(duplicate_result.returncode == 3 and not duplicate_result.stdout, "duplicate member refused")

    extra = status_request()
    extra["claim"] = "accepted"
    extra_result = run_runner(canonical_bytes(extra))
    ok(extra_result.returncode == 3 and not extra_result.stdout, "extra member refused")

    wrong_status_shape = status_request()
    wrong_status_shape["suite_id"] = "ECDH-K256+ML-KEM-512"
    wrong_status_result = run_runner(canonical_bytes(wrong_status_shape))
    ok(
        wrong_status_result.returncode == 3 and not wrong_status_result.stdout,
        "status suite smuggling refused",
    )

    network_enabled = run_runner(canonical_bytes(crypto_request()))
    ok(network_enabled.returncode == 3, "network-enabled crypto exits blocked")
    ok(
        response(network_enabled)["error"]["code"] == "network-isolation-unproven",
        "network-enabled crypto fails before backend execution",
    )
    for operation in ("verify-fixture", "accept-fixture"):
        result = run_runner(canonical_bytes(crypto_request(operation)))
        ok(result.returncode == 3, f"{operation} exits blocked")
        ok(
            response(result)["error"]["code"] == "network-isolation-unproven",
            f"{operation} requires network isolation",
        )

    worker_spec = importlib.util.spec_from_file_location("same_process_worker", WORKER)
    assert worker_spec and worker_spec.loader
    worker_module = importlib.util.module_from_spec(worker_spec)
    worker_spec.loader.exec_module(worker_module)
    with tempfile.TemporaryFile() as captured:
        original_stdout = sys.stdout
        try:
            sys.stdout = type("Captured", (), {"buffer": captured})()  # type: ignore[assignment]
            same_process_code = worker_module.main()
        finally:
            sys.stdout = original_stdout
        captured.seek(0)
        same_process_response = json.loads(captured.read().decode("ascii"))
    ok(same_process_code == 3, "same-process worker exits blocked")
    ok(
        same_process_response["error"]["code"] == "same-process-forbidden",
        "same-process worker import fails closed",
    )

    request = status_request()
    fake_challenge = "2" * 64
    reused = {
        "accepted_evidence_count": 0,
        "accepted_fixture_count": 0,
        "challenge": "3" * 64,
        "error": {"code": "scaffold-only", "detail": "reused"},
        "execution_id": "4" * 64,
        "protocol_version": "dcrypt-clean-room-ipc/1",
        "release_status": "release-blocked",
        "request_id": request["request_id"],
        "request_sha256": __import__("hashlib").sha256(status_raw).hexdigest(),
        "status": "refused",
    }
    try:
        validate_worker_response(
            canonical_bytes(reused),
            request=validate_request(request),
            request_raw=status_raw,
            challenge=fake_challenge,
        )
    except ValidationError:
        output_reuse_rejected = True
    else:
        output_reuse_rejected = False
    ok(output_reuse_rejected, "worker output reuse rejected")

    boolean_count = dict(reused)
    boolean_count["challenge"] = fake_challenge
    boolean_count["accepted_fixture_count"] = False
    try:
        validate_worker_response(
            canonical_bytes(boolean_count),
            request=validate_request(request),
            request_raw=status_raw,
            challenge=fake_challenge,
        )
    except ValidationError:
        boolean_count_rejected = True
    else:
        boolean_count_rejected = False
    ok(boolean_count_rejected, "boolean evidence count rejected")

    def forge_backend(copy: Path) -> None:
        slot = load_json(copy / "backend-slot.json")
        slot["status"] = "independently-reviewed"
        slot["backend"] = {"name": "self-attested"}
        slot["approvals"] = [{"reviewer": "forged"}]
        save_json(copy / "backend-slot.json", slot)

    forged_backend = coherently_mutated(forge_backend)
    ok(forged_backend.returncode != 0, "forged accepted backend rejected")

    def forge_fixture(copy: Path) -> None:
        fixtures = load_json(copy / "fixtures.json")
        fixtures["accepted_fixture_count"] = 1
        fixtures["accepted_evidence_count"] = 1
        fixtures["status"] = "accepted"
        fixtures["fixtures"] = [{"fixture_id": "forged"}]
        save_json(copy / "fixtures.json", fixtures)

    forged_fixture = coherently_mutated(forge_fixture)
    ok(forged_fixture.returncode != 0, "forged fixture/evidence promotion rejected")

    def forge_record(copy: Path) -> None:
        records = load_json(copy / "execution-records.json")
        records["accepted_evidence_count"] = 1
        records["records"] = [{"execution_id": "5" * 64}]
        save_json(copy / "execution-records.json", records)

    forged_record = coherently_mutated(forge_record)
    ok(forged_record.returncode != 0, "forged execution evidence rejected")

    def forge_contract(copy: Path) -> None:
        registry = load_json(copy / "suite-registry.json")
        registry["contract_binding"]["status"] = "accepted-interoperability-evidence"
        save_json(copy / "suite-registry.json", registry)

    forged_contract = coherently_mutated(forge_contract)
    ok(forged_contract.returncode != 0, "self-attested protocol promotion rejected")

    def wrong_reviewed_source_digest(copy: Path) -> None:
        registry = load_json(copy / "suite-registry.json")
        registry["contract_binding"]["reviewed_source_sha256"] = "0" * 64
        save_json(copy / "suite-registry.json", registry)

    rejected(
        coherently_mutated(wrong_reviewed_source_digest),
        "immutable protocol source binding changed",
        "wrong reviewed source digest rejected",
    )

    def missing_projection_digest(copy: Path) -> None:
        registry = load_json(copy / "suite-registry.json")
        del registry["contract_binding"]["semantic_projection_sha256"]
        save_json(copy / "suite-registry.json", registry)

    rejected(
        coherently_mutated(missing_projection_digest),
        "immutable protocol source binding changed",
        "missing semantic projection digest rejected",
    )

    def no_scaffold_mutation(_copy: Path) -> None:
        return None

    def remove_protocol(path: Path) -> None:
        path.unlink()

    rejected(
        coherently_mutated(no_scaffold_mutation, protocol_mutator=remove_protocol),
        "working protocol contract is missing",
        "missing working protocol bytes rejected",
    )

    def symlink_protocol(path: Path) -> None:
        path.unlink()
        path.symlink_to("protocol-spec.schema.json")

    rejected(
        coherently_mutated(no_scaffold_mutation, protocol_mutator=symlink_protocol),
        "working protocol contract contains a symlink",
        "symlink working protocol path rejected",
    )

    def fifo_protocol(path: Path) -> None:
        path.unlink()
        os.mkfifo(path)

    rejected(
        coherently_mutated(no_scaffold_mutation, protocol_mutator=fifo_protocol),
        "working protocol contract must be a single-link regular file",
        "special-file working protocol path rejected before read",
    )

    def substitute_protocol(path: Path) -> None:
        path.write_bytes(path.read_bytes() + b" ")

    rejected(
        coherently_mutated(no_scaffold_mutation, protocol_mutator=substitute_protocol),
        "working protocol contract is not canonical sorted-key JSON",
        "noncanonical working protocol substitution rejected",
    )

    def bind_changed_projection(copy: Path) -> None:
        registry = load_json(copy / "suite-registry.json")
        registry["contract_binding"]["semantic_projection_sha256"] = "6" * 64
        save_json(copy / "suite-registry.json", registry)

    def change_semantic_field(path: Path) -> None:
        protocol = load_json(path)
        protocol["ecies"]["frame"]["nonce_length"] = 13
        save_protocol(path, protocol)

    rejected(
        coherently_mutated(
            bind_changed_projection, protocol_mutator=change_semantic_field
        ),
        "immutable protocol source binding changed",
        "semantic drift with coherently changed registry digest rejected",
    )

    def change_normative_prose(path: Path) -> None:
        protocol = load_json(path)
        protocol["ecies"]["ambiguities"][0] += " Rebound prose."
        save_protocol(path, protocol)

    rejected(
        coherently_mutated(no_scaffold_mutation, protocol_mutator=change_normative_prose),
        "working protocol semantic projection differs from reviewed source",
        "normative prose drift rejected",
    )

    def change_evidence_claim(path: Path) -> None:
        protocol = load_json(path)
        protocol["assurance_effect"]["accepted_oracle_count"] = 1
        protocol["assurance_effect"]["counts_as_interoperability_evidence"] = True
        save_protocol(path, protocol)

    rejected(
        coherently_mutated(no_scaffold_mutation, protocol_mutator=change_evidence_claim),
        "working protocol semantic projection differs from reviewed source",
        "protocol evidence promotion rejected",
    )

    def change_source_digest(path: Path) -> None:
        protocol = load_json(path)
        protocol["source_bindings"][0]["sha256"] = "7" * 64
        save_protocol(path, protocol)

    working_protocol = load_json(
        SOURCE_REPO
        / "assurance"
        / "interoperability"
        / "protocol-specs"
        / "current-behavior.json"
    )
    binding_stage = working_protocol["subject_binding"]["binding_stage"]
    if binding_stage == "interim-rebind-required":
        source_digest_mutation = coherently_mutated(
            no_scaffold_mutation,
            protocol_mutator=change_source_digest,
        )
        expected_source_digest_error = (
            "working interim protocol source bindings differ from reviewed source"
        )
    elif binding_stage == "final-subject-candidate-review-required":

        def change_final_source_digest(repo: Path) -> None:
            change_source_digest(
                repo
                / "assurance"
                / "interoperability"
                / "protocol-specs"
                / "current-behavior.json"
            )

        source_digest_mutation = coherent_final_binding(
            after_rebind=change_final_source_digest
        )
        expected_source_digest_error = (
            "working final protocol source digest is not final-subject-bound at 0"
        )
    else:
        raise AssertionError(f"unexpected working protocol binding stage: {binding_stage}")

    rejected(
        source_digest_mutation,
        expected_source_digest_error,
        "unreviewed source rebind rejected",
    )

    def simulate_legitimate_final_rebind(path: Path) -> None:
        protocol = load_json(path)
        protocol["subject_binding"]["binding_stage"] = (
            "final-subject-candidate-review-required"
        )
        protocol["subject_binding"]["final_rebind_required"] = False
        save_protocol(path, protocol)

    final_rebind = coherent_final_binding(commit_final_assurance=True)
    ok(
        final_rebind.returncode == 0
        and b"working_binding=final" in final_rebind.stdout,
        "legitimate final protocol rebind passes without scaffold edit",
    )

    def add_current_absent_inputs(repo: Path) -> None:
        for path_value in SUBJECT_ABSENT_BUILD_INPUTS:
            path = repo / path_value
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                f"adversarial current declared-absent input: {path_value}\n",
                encoding="utf-8",
            )

    current_absence_attack = coherent_final_binding(
        after_rebind=add_current_absent_inputs,
    )
    ok(
        current_absence_attack.returncode != 0
        and b"current protocol subject contains declared-absent build inputs"
        in current_absence_attack.stderr
        and all(
            path_value.encode("utf-8") in current_absence_attack.stderr
            for path_value in SUBJECT_ABSENT_BUILD_INPUTS
        ),
        "all current declared-absent build inputs rejected",
    )

    bound_absence_attack = coherent_final_binding(bound_absent_inputs=True)
    ok(
        bound_absence_attack.returncode != 0
        and b"protocol final subject contains declared-absent build inputs"
        in bound_absence_attack.stderr
        and all(
            path_value.encode("utf-8") in bound_absence_attack.stderr
            for path_value in SUBJECT_ABSENT_BUILD_INPUTS
        ),
        "all committed declared-absent build inputs rejected coherently",
    )

    def change_current_subject_bytes(repo: Path) -> None:
        path = repo / "README.md"
        path.write_bytes(path.read_bytes() + b"\ncoherent-current-drift\n")

    rejected(
        coherent_final_binding(after_rebind=change_current_subject_bytes),
        "current protocol subject digest mismatch: README.md",
        "current subject byte drift rejected",
    )

    def add_current_subject_path(repo: Path) -> None:
        (repo / "UNREVIEWED-SUBJECT-INPUT").write_text(
            "coherent unbound current input\n", encoding="utf-8"
        )

    rejected(
        coherent_final_binding(after_rebind=add_current_subject_path),
        "current protocol subject path set differs from the bound Git subject",
        "unbound current subject path rejected",
    )

    def stage_subject_bytes_then_restore_worktree(repo: Path) -> None:
        path = repo / "README.md"
        original = path.read_bytes()
        path.write_bytes(original + b"staged-only-subject-drift\n")
        staged = run(["git", "add", "--", "README.md"], cwd=repo)
        if staged.returncode != 0:
            raise AssertionError("cannot stage adversarial subject bytes")
        path.write_bytes(original)

    rejected(
        coherent_final_binding(after_rebind=stage_subject_bytes_then_restore_worktree),
        "protocol subject index has staged semantic drift: ['README.md']",
        "staged byte drift hidden by restored worktree rejected",
    )

    def stage_subject_mode(repo: Path) -> None:
        changed = run(["git", "update-index", "--chmod=+x", "README.md"], cwd=repo)
        if changed.returncode != 0:
            raise AssertionError("cannot stage adversarial subject mode")

    rejected(
        coherent_final_binding(after_rebind=stage_subject_mode),
        "protocol subject index has staged semantic drift: ['README.md']",
        "staged mode drift rejected",
    )

    def remove_subject_from_index(repo: Path) -> None:
        removed = run(["git", "rm", "--cached", "--quiet", "--", "README.md"], cwd=repo)
        if removed.returncode != 0:
            raise AssertionError("cannot remove adversarial subject index entry")

    rejected(
        coherent_final_binding(after_rebind=remove_subject_from_index),
        "protocol subject index path set differs from the bound Git subject",
        "cached removal hidden by untracked worktree file rejected",
    )

    def unmerge_subject_index(repo: Path) -> None:
        base = run(["git", "rev-parse", "HEAD:README.md"], cwd=repo)
        if base.returncode != 0:
            raise AssertionError("cannot resolve adversarial base object")
        object_id = base.stdout.decode("ascii").strip()
        payload = (
            f"0 {'0' * 40}\tREADME.md\n"
            f"100644 {object_id} 1\tREADME.md\n"
            f"100644 {object_id} 2\tREADME.md\n"
            f"100644 {object_id} 3\tREADME.md\n"
        ).encode("ascii")
        changed = subprocess.run(
            ["git", "update-index", "--index-info"],
            cwd=repo,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        if changed.returncode != 0:
            raise AssertionError("cannot create adversarial unmerged index entry")

    rejected(
        coherent_final_binding(after_rebind=unmerge_subject_index),
        "protocol subject index has an unmerged entry: README.md",
        "unmerged index entry rejected",
    )

    def mark_subject_intent_to_add(repo: Path) -> None:
        removed = run(
            ["git", "rm", "--cached", "--quiet", "--force", "--", "README.md"],
            cwd=repo,
        )
        added = run(["git", "add", "--intent-to-add", "--", "README.md"], cwd=repo)
        if removed.returncode != 0 or added.returncode != 0:
            raise AssertionError("cannot create adversarial intent-to-add entry")

    rejected(
        coherent_final_binding(after_rebind=mark_subject_intent_to_add),
        "protocol subject index has staged semantic drift: ['README.md']",
        "intent-to-add index entry rejected",
    )

    def mark_subject_skip_worktree(repo: Path) -> None:
        changed = run(
            ["git", "update-index", "--skip-worktree", "README.md"], cwd=repo
        )
        if changed.returncode != 0:
            raise AssertionError("cannot set adversarial skip-worktree flag")

    rejected(
        coherent_final_binding(after_rebind=mark_subject_skip_worktree),
        "protocol subject index has a forbidden cache flag S: README.md",
        "skip-worktree index flag rejected",
    )

    def mark_subject_assume_unchanged(repo: Path) -> None:
        changed = run(
            ["git", "update-index", "--assume-unchanged", "README.md"], cwd=repo
        )
        if changed.returncode != 0:
            raise AssertionError("cannot set adversarial assume-unchanged flag")

    rejected(
        coherent_final_binding(after_rebind=mark_subject_assume_unchanged),
        "protocol subject index has a forbidden cache flag h: README.md",
        "assume-unchanged index flag rejected",
    )

    def mutate_excluded_paths(repo: Path) -> None:
        excluded = sorted(SUBJECT_EXCLUDED_FILES)
        for path_value in excluded:
            path = repo / path_value
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                path.write_bytes(path.read_bytes() + b"excluded-drift\n")
            else:
                path.write_bytes(b"excluded-new\n")
        staged = run(["git", "add", "--force", "--", *excluded], cwd=repo)
        if staged.returncode != 0:
            raise AssertionError("cannot stage documented excluded paths")

    excluded_drift = coherent_final_binding(after_rebind=mutate_excluded_paths)
    ok(
        excluded_drift.returncode == 0
        and b"working_binding=final" in excluded_drift.stdout,
        "assurance and six documented path exclusions stay outside subject closure",
    )

    def false_final_rebind(path: Path) -> None:
        simulate_legitimate_final_rebind(path)
        protocol = load_json(path)
        protocol["subject_binding"]["subject_manifest_sha256"] = "8" * 64
        save_protocol(path, protocol)

    rejected(
        coherently_mutated(no_scaffold_mutation, protocol_mutator=false_final_rebind),
        "protocol final subject manifest digest mismatch",
        "false final-subject rebind rejected",
    )

    def missing_source_commit(copy: Path) -> None:
        registry = load_json(copy / "suite-registry.json")
        registry["contract_binding"]["reviewed_source_commit"] = "0" * 40
        save_json(copy / "suite-registry.json", registry)
        verifier = copy / "verify-scaffold.py"
        text = verifier.read_text(encoding="utf-8")
        text = text.replace(
            'EXPECTED_REVIEWED_SOURCE_COMMIT = "f00be3676dd01643c46a51b2c56be01159ee4796"',
            'EXPECTED_REVIEWED_SOURCE_COMMIT = "0000000000000000000000000000000000000000"',
        )
        verifier.write_text(text, encoding="utf-8")
        rebind_verifier_artifact_pin(copy, "suite-registry.json")

    rejected(
        coherently_mutated(missing_source_commit),
        "immutable reviewed protocol source commit is missing or changed",
        "missing reviewed source commit rejected",
    )

    def wrong_source_commit(copy: Path) -> None:
        wrong = "a39ac9644e71a2379f73329d4ec2ac461b36a6d5"
        registry = load_json(copy / "suite-registry.json")
        registry["contract_binding"]["reviewed_source_commit"] = wrong
        save_json(copy / "suite-registry.json", registry)
        verifier = copy / "verify-scaffold.py"
        text = verifier.read_text(encoding="utf-8")
        text = text.replace(
            'EXPECTED_REVIEWED_SOURCE_COMMIT = "f00be3676dd01643c46a51b2c56be01159ee4796"',
            f'EXPECTED_REVIEWED_SOURCE_COMMIT = "{wrong}"',
        )
        verifier.write_text(text, encoding="utf-8")
        rebind_verifier_artifact_pin(copy, "suite-registry.json")

    rejected(
        coherently_mutated(wrong_source_commit),
        "immutable reviewed protocol source tree is missing or changed",
        "wrong reviewed source commit rejected",
    )

    def missing_source_blob(copy: Path) -> None:
        registry = load_json(copy / "suite-registry.json")
        registry["contract_binding"]["reviewed_source_blob_oid"] = "0" * 40
        save_json(copy / "suite-registry.json", registry)
        verifier = copy / "verify-scaffold.py"
        text = verifier.read_text(encoding="utf-8")
        text = text.replace(
            'EXPECTED_REVIEWED_SOURCE_BLOB_OID = "df50ccdcab03e3e5a8e3f734391268ef18180221"',
            'EXPECTED_REVIEWED_SOURCE_BLOB_OID = "0000000000000000000000000000000000000000"',
        )
        verifier.write_text(text, encoding="utf-8")
        rebind_verifier_artifact_pin(copy, "suite-registry.json")

    rejected(
        coherently_mutated(missing_source_blob),
        "immutable reviewed protocol source blob identity changed",
        "missing reviewed source blob rejected",
    )

    def wrong_source_blob(copy: Path) -> None:
        registry = load_json(copy / "suite-registry.json")
        registry["contract_binding"]["reviewed_source_blob_oid"] = (
            "153ae94dc74c2960bd604dec483de68a4588c498"
        )
        save_json(copy / "suite-registry.json", registry)
        verifier = copy / "verify-scaffold.py"
        text = verifier.read_text(encoding="utf-8")
        text = text.replace(
            'EXPECTED_REVIEWED_SOURCE_BLOB_OID = "df50ccdcab03e3e5a8e3f734391268ef18180221"',
            'EXPECTED_REVIEWED_SOURCE_BLOB_OID = "153ae94dc74c2960bd604dec483de68a4588c498"',
        )
        verifier.write_text(text, encoding="utf-8")
        rebind_verifier_artifact_pin(copy, "suite-registry.json")

    rejected(
        coherently_mutated(wrong_source_blob),
        "immutable reviewed protocol source blob identity changed",
        "wrong reviewed source blob rejected",
    )

    def claim_protocol_acceptance(copy: Path) -> None:
        registry = load_json(copy / "suite-registry.json")
        registry["contract_binding"]["status"] = "accepted-interoperability-evidence"
        registry["evidence_effect"]["accepted_evidence_count"] = 1
        registry["evidence_effect"]["counts_as_interoperability_evidence"] = True
        save_json(copy / "suite-registry.json", registry)

    rejected(
        coherently_mutated(claim_protocol_acceptance),
        "immutable protocol source binding changed",
        "false protocol acceptance rejected",
    )

    def add_source_reference(copy: Path) -> None:
        slot = load_json(copy / "backend-slot.json")
        slot["backend"] = {"source": "../../" + "crates/algorithms/src"}
        save_json(copy / "backend-slot.json", slot)

    source_reference = coherently_mutated(add_source_reference)
    ok(source_reference.returncode != 0, "dcrypt source/path reference rejected")

    def hardlink_artifact(copy: Path) -> None:
        artifact = copy / "README.md"
        peer = copy.parent / "README.peer"
        artifact.rename(peer)
        os.link(peer, artifact)

    rejected(
        coherently_mutated(hardlink_artifact),
        "hardlinked artifact forbidden: README.md",
        "hardlinked scaffold artifact rejected",
    )

    def make_artifact_executable(copy: Path) -> None:
        artifact = copy / "README.md"
        artifact.chmod(artifact.stat().st_mode | 0o111)

    rejected(
        coherently_mutated(make_artifact_executable),
        "executable artifact forbidden: README.md",
        "executable-bit scaffold artifact drift rejected",
    )

    def open_schema(copy: Path) -> None:
        schema = load_json(copy / "fixture.schema.json")
        schema["additionalProperties"] = True
        save_json(copy / "fixture.schema.json", schema)

    opened_schema = coherently_mutated(open_schema)
    ok(opened_schema.returncode != 0, "opened schema rejected")

    print(f"clean-room scaffold self-tests passed: {passed}/57")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
