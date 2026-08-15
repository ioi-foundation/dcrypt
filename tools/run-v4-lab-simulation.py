#!/usr/bin/env python3
"""Run the complete reproducible v4 software/simulated laboratory."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
SEED = 0xD4C7_4A8
SAMPLES = 20_000
TVLA_THRESHOLD = 4.5
EXPECTED_TIMING_CASES = 29
GENERATED_OUTPUTS = (
    "assurance-report",
    "evidence-manifest.json",
    "evidence-manifest.sig",
    "historical-advisory-replay.json",
    "lab-report.json",
    "packages",
    "sboms",
    "simulation-signing-public.pem",
    "timing-noise-profile.json",
)


class LabError(RuntimeError):
    pass


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def welch_t(first: list[float], second: list[float]) -> float:
    mean_delta = statistics.fmean(first) - statistics.fmean(second)
    denominator = math.sqrt(statistics.variance(first) / len(first) + statistics.variance(second) / len(second))
    return 0.0 if denominator == 0.0 else mean_delta / denominator


def synthetic_controls() -> dict:
    rng = random.Random(SEED)
    positive_fixed = []
    positive_random = []
    negative_fixed = []
    negative_random = []
    for _ in range(SAMPLES):
        positive_fixed.append(rng.gauss(0.0, 0.75))
        positive_random.append(float(rng.randrange(256).bit_count()) + rng.gauss(0.0, 0.75))
        negative_fixed.append(rng.gauss(0.0, 1.0))
        negative_random.append(rng.gauss(0.0, 1.0))
    positive_t = welch_t(positive_fixed, positive_random)
    negative_t = welch_t(negative_fixed, negative_random)
    if abs(positive_t) <= TVLA_THRESHOLD:
        raise LabError("synthetic leakage positive control was not detected")
    if abs(negative_t) > TVLA_THRESHOLD:
        raise LabError("synthetic leakage negative control produced a false positive")

    fault_subject = b"dcrypt-v4-simulated-single-bit-artifact-fault-model-v1"
    baseline = sha256_bytes(fault_subject)
    detected = 0
    for bit_index in range(len(fault_subject) * 8):
        mutated = bytearray(fault_subject)
        mutated[bit_index // 8] ^= 1 << (bit_index % 8)
        if sha256_bytes(bytes(mutated)) != baseline:
            detected += 1
    expected = len(fault_subject) * 8
    if detected != expected:
        raise LabError("single-bit artifact fault model missed a mutation")
    return {
        "artifact_single_bit_fault": {
            "detected": detected, "injected": expected, "passed": True,
            "subject_sha256": baseline,
        },
        "hamming_weight_tvla": {
            "model": "byte-hamming-weight-plus-seeded-gaussian-noise",
            "negative_control_abs_t": abs(negative_t),
            "negative_control_passed": abs(negative_t) <= TVLA_THRESHOLD,
            "positive_control_abs_t": abs(positive_t),
            "positive_control_passed": abs(positive_t) > TVLA_THRESHOLD,
            "samples_per_class": SAMPLES,
            "seed": SEED,
            "threshold": TVLA_THRESHOLD,
        },
    }


def parse_timing_family(raw: bytes) -> dict:
    text = raw.decode("utf-8", errors="replace")
    diagnostics: dict[str, dict] = {}
    current: dict | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Timing diagnostics: "):
            name = stripped.removeprefix("Timing diagnostics: ")
            current = {"name": name}
            diagnostics[name] = current
        elif current is not None and stripped.startswith("Mean A-B: "):
            current["mean_diff_ns"] = float(stripped.removeprefix("Mean A-B: ").removesuffix(" ns"))
        elif current is not None and stripped.startswith("99% paired-bootstrap CI (descriptive): "):
            match = re.fullmatch(
                r"99% paired-bootstrap CI \(descriptive\): \[([-+0-9.eE]+), ([-+0-9.eE]+)\] ns",
                stripped,
            )
            if match is None:
                raise LabError("could not parse timing confidence interval")
            current["ci_lower_ns"] = float(match.group(1))
            current["ci_upper_ns"] = float(match.group(2))
        elif current is not None and stripped.startswith("Practical threshold: "):
            current["practical_threshold_ns"] = float(
                stripped.removeprefix("Practical threshold: ").removesuffix(" ns")
            )

    family_match = re.search(
        r"Blocking timing family: ([0-9]+) cases, Holm FWER alpha=([-+0-9.eE]+)", text
    )
    if family_match is None:
        raise LabError("timing output omitted the blocking family summary")
    family_count = int(family_match.group(1))
    decisions = []
    decision_pattern = re.compile(
        r"^  (.+): primary_p=([-+0-9.eE]+), holm_reject=(true|false), "
        r"practical=(true|false), blocks=(true|false)$",
        re.MULTILINE,
    )
    for match in decision_pattern.finditer(text):
        name = match.group(1)
        diagnostic = diagnostics.get(name)
        required = {"name", "mean_diff_ns", "ci_lower_ns", "ci_upper_ns", "practical_threshold_ns"}
        if diagnostic is None or set(diagnostic) != required:
            raise LabError(f"timing output omitted structured diagnostics for {name}")
        decisions.append({
            **diagnostic,
            "primary_p_value": float(match.group(2)),
            "holm_reject": match.group(3) == "true",
            "exceeds_practical_threshold": match.group(4) == "true",
            "blocks_release": match.group(5) == "true",
        })
    if family_count != EXPECTED_TIMING_CASES or len(decisions) != EXPECTED_TIMING_CASES:
        raise LabError(
            f"timing output contained {family_count} declared and {len(decisions)} parsed cases; "
            f"expected {EXPECTED_TIMING_CASES}"
        )
    return {
        "cases": decisions,
        "family_alpha": float(family_match.group(2)),
        "family_passed": not any(row["blocks_release"] for row in decisions),
    }


def run_command(command_id: str, argv: list[str], environment: dict[str, str]) -> dict:
    completed = subprocess.run(
        argv, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    if completed.returncode != 0:
        sys.stderr.buffer.write(completed.stdout[-32768:])
        raise LabError(f"laboratory command failed: {command_id}")
    result = {
        "argv": argv,
        "id": command_id,
        "output_sha256": sha256_bytes(completed.stdout),
        "passed": True,
    }
    if command_id in {"empirical-host-timing-baseline", "empirical-host-timing-reproduction"}:
        result["timing_family"] = parse_timing_family(completed.stdout)
        if result["timing_family"]["family_passed"] is not True:
            raise LabError(f"timing family blocked the release: {command_id}")
    return result


def count_expected_tests(path: pathlib.Path) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    return sum(len(group.get("tests", [])) for group in data.get("testGroups", []))


def standards_evidence() -> dict:
    vector_root = ROOT / "tests/src/vectors/acvp_json"
    ml_dsa = sum(
        count_expected_tests(vector_root / name / "expectedResults.json")
        for name in (
            "ML-DSA-keyGen-FIPS204", "ML-DSA-sigGen-FIPS204", "ML-DSA-sigVer-FIPS204",
        )
    )
    ml_kem = sum(
        count_expected_tests(vector_root / name / "expectedResults.json")
        for name in ("ML-KEM-keyGen-FIPS203", "ML-KEM-encapDecap-FIPS203")
    )
    if ml_dsa != 615 or ml_kem != 240:
        raise LabError(f"post-quantum vector case closure differs: ML-DSA={ml_dsa} ML-KEM={ml_kem}")
    return {
        "ml_dsa_cases": ml_dsa,
        "ml_kem_cases": ml_kem,
        "passed": True,
        "provenance": "repository-byte-bound-corpus-upstream-acquisition-unverified",
        "total_cases": ml_dsa + ml_kem,
    }


def cpu_busy_snapshot(cpus: set[int]) -> dict[int, tuple[int, int]]:
    rows: dict[int, tuple[int, int]] = {}
    for line in pathlib.Path("/proc/stat").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if not fields or not fields[0].startswith("cpu") or not fields[0][3:].isdigit():
            continue
        cpu = int(fields[0][3:])
        if cpu not in cpus:
            continue
        counters = [int(value) for value in fields[1:]]
        total = sum(counters)
        idle = counters[3] + (counters[4] if len(counters) > 4 else 0)
        rows[cpu] = (total, idle)
    if set(rows) != cpus:
        raise LabError("cannot qualify every eligible CPU from /proc/stat")
    return rows


def cpu_capacity(cpu: int) -> int:
    path = pathlib.Path(f"/sys/devices/system/cpu/cpu{cpu}/cpu_capacity")
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, ValueError):
        return 1


def qualify_timing_cpu(available_cpus: set[int]) -> tuple[int, dict]:
    requested = os.environ.get("DCRYPT_TIMING_CPU")
    capacities = {cpu: cpu_capacity(cpu) for cpu in available_cpus}
    if requested is not None:
        try:
            selected = int(requested)
        except ValueError as error:
            raise LabError("DCRYPT_TIMING_CPU must be an integer") from error
        if selected not in available_cpus:
            raise LabError(f"timing CPU {selected} is outside process affinity")
        return selected, {
            "capacities": capacities,
            "probe_seconds": 0,
            "rule": "explicit-DCRYPT_TIMING_CPU",
        }
    maximum_capacity = max(capacities.values())
    candidates = {cpu for cpu, capacity in capacities.items() if capacity == maximum_capacity}
    before = cpu_busy_snapshot(candidates)
    time.sleep(5)
    after = cpu_busy_snapshot(candidates)
    busy_jiffies = {
        cpu: (after[cpu][0] - before[cpu][0]) - (after[cpu][1] - before[cpu][1])
        for cpu in candidates
    }
    selected = min(candidates, key=lambda cpu: (busy_jiffies[cpu], cpu))
    return selected, {
        "busy_jiffies": busy_jiffies,
        "capacities": capacities,
        "maximum_capacity": maximum_capacity,
        "probe_seconds": 5,
        "rule": "maximum-capacity-then-least-busy-then-lowest-id",
    }


def artifact_rows(root: pathlib.Path) -> list[dict]:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink() and path.name != "lab-report.json":
            rows.append({
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            })
    return rows


def sign_evidence_manifest(output: pathlib.Path, environment: dict[str, str]) -> dict:
    manifest_path = output / "evidence-manifest.json"
    signature_path = output / "evidence-manifest.sig"
    public_key_path = output / "simulation-signing-public.pem"
    manifest = {
        "artifacts": artifact_rows(output),
        "claim": "single-ephemeral-lab-run-origin-no-external-identity",
        "schema_version": 1,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    with tempfile.TemporaryDirectory(prefix="dcrypt-v4-lab-signing-") as temporary:
        private_key = pathlib.Path(temporary) / "ephemeral-private.pem"
        commands = (
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
            ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key_path)],
            [
                "openssl", "pkeyutl", "-sign", "-inkey", str(private_key), "-rawin",
                "-in", str(manifest_path), "-out", str(signature_path),
            ],
            [
                "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key_path),
                "-rawin", "-in", str(manifest_path), "-sigfile", str(signature_path),
            ],
        )
        for argv in commands:
            completed = subprocess.run(
                argv, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False,
            )
            if completed.returncode != 0:
                sys.stderr.buffer.write(completed.stdout)
                raise LabError(f"evidence signature command failed: {' '.join(argv[:2])}")
    return {
        "algorithm": "Ed25519",
        "external_identity_claimed": False,
        "manifest_sha256": sha256_file(manifest_path),
        "public_key_sha256": sha256_file(public_key_path),
        "signature_sha256": sha256_file(signature_path),
        "verified": True,
    }


def clean_generated_output(output: pathlib.Path) -> None:
    for generated_name in GENERATED_OUTPUTS:
        generated_path = output / generated_name
        if generated_path.is_symlink() or generated_path.is_file():
            generated_path.unlink()
        elif generated_path.is_dir():
            shutil.rmtree(generated_path)


def run_lab(output: pathlib.Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    clean_generated_output(output)
    environment = os.environ.copy()
    environment.update({
        "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
    })
    if not hasattr(os, "sched_getaffinity"):
        raise LabError("laboratory timing isolation requires Linux CPU affinity")
    available_cpus = os.sched_getaffinity(0)
    if not available_cpus:
        raise LabError("laboratory process has no eligible CPU")
    timing_cpu, cpu_qualification = qualify_timing_cpu(set(available_cpus))
    timing_profile = (output / "timing-noise-profile.json").resolve()
    environment["DCRYPT_CT_NOISE_PROFILE"] = str(timing_profile)
    environment["DCRYPT_CT_NOISE_POLICY"] = "observe"
    commands = [
        ("historical-advisory-replay", [
            "python3", "-B", "tools/replay-historical-advisories.py", "--run",
            "--output", str(output / "historical-advisory-replay.json"),
        ]),
        ("standards-vector-replay", [
            "cargo", "test", "--release", "--locked", "--offline",
            "-p", "dcrypt-tests", "--test", "acvp_tests",
        ]),
        ("generate-release-sboms", [
            "python3", "-B", "tools/generate-release-sboms.py", "--generate",
            "--output", str(output / "sboms"),
        ]),
        ("verify-release-sboms", [
            "python3", "-B", "tools/generate-release-sboms.py", "--check",
            "--output", str(output / "sboms"),
        ]),
        ("repeatable-package-proof", [
            "python3", "-B", "tools/verify-repeatable-packages.py", "--run",
            "--output", str(output / "packages"),
        ]),
        ("verify-repeatable-packages", [
            "python3", "-B", "tools/verify-repeatable-packages.py", "--check",
            "--output", str(output / "packages"),
        ]),
        ("implementation-boundary-and-platform-builds", [
            "python3", "-B", "tools/verify-implementation-boundary.py",
            "--allow-dirty-provenance",
        ]),
        ("bls-compiler-shape", ["tools/verify-bls-secret-assembly.sh"]),
        ("ghash-compiler-shape", ["tools/verify-ghash-assembly.sh"]),
        ("empirical-host-timing-baseline", [
            "taskset", "-c", str(timing_cpu), "cargo", "test", "--locked",
            "-p", "dcrypt-tests", "--test",
            "constant_time_tests", "--", "--test-threads=1", "--nocapture",
        ]),
        ("empirical-host-timing-reproduction", [
            "taskset", "-c", str(timing_cpu), "cargo", "test", "--locked",
            "-p", "dcrypt-tests", "--test",
            "constant_time_tests", "--", "--test-threads=1", "--nocapture",
        ]),
    ]
    results = [run_command(command_id, argv, environment) for command_id, argv in commands]
    controls = synthetic_controls()
    standards = standards_evidence()
    threat_review = ROOT / "assurance/release-lab/DAYBREAK-THREAT-REVIEW.md"
    review_evidence = {
        "administratively_independent": False,
        "path": threat_review.relative_to(ROOT).as_posix(),
        "sha256": sha256_file(threat_review),
        "type": "OpenAI-Daybreak-adversarial-review",
    }
    signature_evidence = sign_evidence_manifest(output, environment)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, check=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, check=True,
    ).stdout.strip()
    working_tree_status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT,
        stdout=subprocess.PIPE, check=True,
    ).stdout
    report = {
        "artifacts": artifact_rows(output),
        "claims": {
            "actual_product_evidence": [
                "historical-regression-pass", "host-timing-suite-pass",
                "compiler-shape-pass", "supported-target-build-pass",
                "deterministic-sbom-pass", "repeatable-package-byte-pass",
                "ephemeral-ed25519-manifest-signature-pass",
            ],
            "simulation_evidence": [
                "hamming-weight-leakage-analysis-pipeline-calibrated",
                "single-bit-artifact-fault-detection-model-pass",
            ],
            "unclaimed": [
                "measurement-on-a-specific-physical-device",
                "administratively-independent-producer",
                "physical-fault-injection-on-hardware",
                "qualified-host-noise-or-physical-timing-environment",
            ],
        },
        "commands": results,
        "content_policy": "dcrypt-v4-open-simulated-laboratory-v1",
        "generated_at_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "lab_environment": {
            "cpu_affinity": timing_cpu,
            "cpu_qualification": cpu_qualification,
            "timing_profile_sha256": sha256_file(timing_profile),
            "timing_profile_policy": "observational-host-drift",
            "timing_profile_strategy": "fresh-baseline-then-full-statistical-reproduction",
        },
        "passed": True,
        "schema_version": 1,
        "signature_evidence": signature_evidence,
        "simulation_controls": controls,
        "standards_evidence": standards,
        "subject": {
            "commit": head,
            "tree": tree,
            "working_tree_clean": not bool(working_tree_status),
            "working_tree_status_sha256": sha256_bytes(working_tree_status),
        },
        "threat_review": review_evidence,
    }
    (output / "lab-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    report_output = output / "assurance-report"
    completed = subprocess.run(
        [
            sys.executable, "-B", str(ROOT / "tools/generate-v4-assurance-report.py"),
            "--generate", "--lab-output", str(output), "--output", str(report_output),
        ],
        cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if completed.returncode != 0:
        sys.stderr.buffer.write(completed.stdout)
        raise LabError("Assurance Profile generation failed")
    return report


def self_test() -> None:
    controls = synthetic_controls()
    if not controls["hamming_weight_tvla"]["positive_control_passed"]:
        raise AssertionError("positive control failed")
    if not controls["hamming_weight_tvla"]["negative_control_passed"]:
        raise AssertionError("negative control failed")
    if standards_evidence()["total_cases"] != 855:
        raise AssertionError("post-quantum vector closure differs")
    with tempfile.TemporaryDirectory(prefix="dcrypt-v4-lab-cleanup-") as temporary:
        output = pathlib.Path(temporary)
        (output / "packages").mkdir()
        (output / "packages" / "dcrypt-3.0.0.crate").write_bytes(b"stale")
        (output / "sboms").mkdir()
        (output / "sboms" / "production.cdx.json").write_bytes(b"stale")
        (output / "historical-advisory-replay.json").write_bytes(b"stale")
        (output / "preserve.txt").write_bytes(b"caller-owned")
        clean_generated_output(output)
        if any((output / name).exists() for name in GENERATED_OUTPUTS):
            raise AssertionError("generated laboratory output cleanup is incomplete")
        if (output / "preserve.txt").read_bytes() != b"caller-owned":
            raise AssertionError("laboratory cleanup removed an unknown output member")
    case_lines = []
    for index in range(EXPECTED_TIMING_CASES):
        name = f"fixture-{index:02d}"
        case_lines.extend([
            f"Timing diagnostics: {name}",
            "Mean A-B: 0.050 ns",
            "99% paired-bootstrap CI (descriptive): [-0.100, 0.200] ns",
            "Practical threshold: 0.500 ns",
        ])
    case_lines.append("Blocking timing family: 29 cases, Holm FWER alpha=0.01")
    for index in range(EXPECTED_TIMING_CASES):
        case_lines.append(
            f"  fixture-{index:02d}: primary_p=0.50000000, "
            "holm_reject=false, practical=false, blocks=false"
        )
    parsed = parse_timing_family("\n".join(case_lines).encode("utf-8"))
    if not parsed["family_passed"] or len(parsed["cases"]) != EXPECTED_TIMING_CASES:
        raise AssertionError("structured timing parser failed")


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("v4 simulated laboratory self-test passed")
            return 0
        if args.output is None:
            parser.error("--output is required")
        report = run_lab(args.output)
        print(
            f"v4 simulated laboratory passed: commands={len(report['commands'])} "
            f"artifacts={len(report['artifacts'])} report={args.output / 'lab-report.json'} "
            f"profile={args.output / 'assurance-report/assurance-profile.json'}"
        )
        return 0
    except (OSError, UnicodeError, ValueError, LabError, subprocess.SubprocessError) as error:
        print(f"v4 simulated laboratory failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
