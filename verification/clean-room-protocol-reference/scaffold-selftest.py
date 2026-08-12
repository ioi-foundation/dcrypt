#!/usr/bin/env python3
"""Adversarial self-tests for the blocked clean-room reference scaffold."""

from __future__ import annotations

import importlib.util
import json
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
VERIFY = ROOT / "verify-scaffold.py"
RUNNER = ROOT / "runner.py"
WORKER = ROOT / "worker.py"
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


def coherently_mutated(mutator: Any) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryDirectory(prefix="clean-room-mutation-") as tmp:
        copy = Path(tmp) / "scaffold"
        shutil.copytree(ROOT, copy)
        mutator(copy)
        rewrite_manifest(copy)
        return run([sys.executable, str(copy / "verify-scaffold.py")], cwd=copy)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="ascii"))


def save_json(path: Path, value: Any) -> None:
    path.write_bytes(canonical_bytes(value))


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
        registry["contract_binding"]["status"] = "final-seal"
        registry["contract_binding"]["sha256"] = "6" * 64
        save_json(copy / "suite-registry.json", registry)

    forged_contract = coherently_mutated(forge_contract)
    ok(forged_contract.returncode != 0, "self-attested protocol seal rejected")

    def add_source_reference(copy: Path) -> None:
        slot = load_json(copy / "backend-slot.json")
        slot["backend"] = {"source": "../../" + "crates/algorithms/src"}
        save_json(copy / "backend-slot.json", slot)

    source_reference = coherently_mutated(add_source_reference)
    ok(source_reference.returncode != 0, "dcrypt source/path reference rejected")

    def open_schema(copy: Path) -> None:
        schema = load_json(copy / "fixture.schema.json")
        schema["additionalProperties"] = True
        save_json(copy / "fixture.schema.json", schema)

    opened_schema = coherently_mutated(open_schema)
    ok(opened_schema.returncode != 0, "opened schema rejected")

    print(f"clean-room scaffold self-tests passed: {passed}/26")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
