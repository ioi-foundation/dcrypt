#!/usr/bin/env python3
"""Build the machine-readable and visual dcrypt v4 Assurance Profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "docs/assurance/report-template.html"
TIMING_COMMANDS = (
    "empirical-host-timing-baseline",
    "empirical-host-timing-reproduction",
)
REQUIRED_COMMANDS = (
    "historical-advisory-replay",
    "standards-vector-replay",
    "generate-release-sboms",
    "verify-release-sboms",
    "repeatable-package-proof",
    "verify-repeatable-packages",
    "implementation-boundary-and-platform-builds",
    "bls-compiler-shape",
    "ghash-compiler-shape",
    *TIMING_COMMANDS,
)


class ReportError(RuntimeError):
    pass


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: pathlib.Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReportError(f"expected a JSON object: {path}")
    return value


def validate_artifacts(lab: pathlib.Path, report: dict) -> None:
    rows = report.get("artifacts")
    if not isinstance(rows, list) or not rows:
        raise ReportError("laboratory artifact inventory is absent")
    observed = set()
    for row in rows:
        if set(row) != {"path", "sha256", "size"}:
            raise ReportError("laboratory artifact row shape differs")
        relative = pathlib.PurePosixPath(row["path"])
        if relative.is_absolute() or ".." in relative.parts or row["path"] in observed:
            raise ReportError("laboratory artifact path is unsafe or duplicated")
        observed.add(row["path"])
        path = lab / pathlib.Path(*relative.parts)
        if not path.is_file() or path.is_symlink():
            raise ReportError(f"laboratory artifact is absent: {row['path']}")
        if path.stat().st_size != row["size"] or sha256(path) != row["sha256"]:
            raise ReportError(f"laboratory artifact differs: {row['path']}")


def command_map(report: dict) -> dict[str, dict]:
    rows = report.get("commands")
    if not isinstance(rows, list):
        raise ReportError("laboratory command results are absent")
    mapped = {row.get("id"): row for row in rows if isinstance(row, dict)}
    if tuple(row.get("id") for row in rows) != REQUIRED_COMMANDS:
        raise ReportError("laboratory command closure or order differs")
    if len(mapped) != len(rows) or any(row.get("passed") is not True for row in rows):
        raise ReportError("a laboratory command did not pass")
    return mapped


def timing_profile(commands: dict[str, dict]) -> dict:
    runs = []
    expected_names = None
    for command_id in TIMING_COMMANDS:
        details = commands[command_id].get("timing_family")
        if not isinstance(details, dict) or details.get("family_passed") is not True:
            raise ReportError(f"structured timing evidence is absent: {command_id}")
        cases = details.get("cases")
        if not isinstance(cases, list) or len(cases) != 29:
            raise ReportError(f"timing family is not exactly 29 cases: {command_id}")
        names = tuple(row.get("name") for row in cases)
        if len(set(names)) != 29 or any(row.get("blocks_release") is not False for row in cases):
            raise ReportError(f"timing family contains duplicate or blocking cases: {command_id}")
        if expected_names is not None and names != expected_names:
            raise ReportError("timing reproduction case order differs from baseline")
        expected_names = names
        runs.append({
            "id": command_id,
            "label": "Baseline" if command_id.endswith("baseline") else "Reproduction",
            "alpha": details["family_alpha"],
            "cases": cases,
        })
    return {
        "blocking_cases": 29,
        "complete_passes": 2,
        "release_blocks": 0,
        "runs": runs,
    }


def build_profile(lab: pathlib.Path) -> dict:
    report_path = lab / "lab-report.json"
    report = load_json(report_path)
    if report.get("schema_version") != 1 or report.get("passed") is not True:
        raise ReportError("laboratory report did not pass")
    validate_artifacts(lab, report)
    commands = command_map(report)

    controls = report.get("simulation_controls", {})
    faults = controls.get("artifact_single_bit_fault", {})
    leakage = controls.get("hamming_weight_tvla", {})
    if faults.get("passed") is not True or faults.get("detected") != faults.get("injected"):
        raise ReportError("artifact-fault simulation did not pass")
    if leakage.get("positive_control_passed") is not True or leakage.get("negative_control_passed") is not True:
        raise ReportError("leakage calibration did not pass")

    advisory = load_json(lab / "historical-advisory-replay.json")
    advisory_rows = advisory.get("results")
    if not isinstance(advisory_rows, list) or len(advisory_rows) != 11 or any(row.get("passed") is not True for row in advisory_rows):
        raise ReportError("historical advisory replay is not exactly 11 passing cases")

    packages = load_json(lab / "packages/manifest.json")
    package_rows = packages.get("packages")
    if not isinstance(package_rows, list) or len(package_rows) != 12 or any(row.get("byte_equal") is not True for row in package_rows):
        raise ReportError("repeatable package evidence is not exactly 12 byte-equal archives")
    versions = {row.get("version") for row in package_rows}
    if len(versions) != 1:
        raise ReportError("package versions differ")
    version = versions.pop()

    sboms = sorted((lab / "sboms").glob("*.cdx.json"))
    if len(sboms) != 5:
        raise ReportError("SBOM evidence is not exactly five documents")

    standards = report.get("standards_evidence", {})
    if (
        standards.get("passed") is not True
        or standards.get("ml_dsa_cases") != 615
        or standards.get("ml_kem_cases") != 240
        or standards.get("total_cases") != 855
    ):
        raise ReportError("post-quantum standards evidence differs")

    signature = report.get("signature_evidence", {})
    if signature.get("verified") is not True or signature.get("algorithm") != "Ed25519":
        raise ReportError("laboratory evidence signature did not verify")

    timing = timing_profile(commands)
    subject = report.get("subject", {})
    if set(subject) != {"commit", "tree", "working_tree_clean", "working_tree_status_sha256"}:
        raise ReportError("laboratory subject is incomplete")

    return {
        "schema_version": 1,
        "content_policy": "dcrypt-v4-assurance-profile-v1",
        "product": "dcrypt",
        "release": {
            "version": version,
            "label": "v4" if version.startswith("4.") else "v4 laboratory rehearsal",
            "channel": (
                "release-candidate" if version.startswith("4.") and subject["working_tree_clean"]
                else "working-tree rehearsal"
            ),
            "subject": subject,
            "generated_at_utc": report["generated_at_utc"],
        },
        "status": {
            "result": "pass",
            "label": (
                "Evidence current for this subject" if subject["working_tree_clean"]
                else "Rehearsal includes uncommitted inputs"
            ),
            "commands_passed": len(commands),
            "commands_total": len(commands),
        },
        "positioning": {
            "category": "Evidence-native cryptography",
            "headline": "Built to be attacked before it is trusted.",
            "summary": "One exact release, measured through an open adversarial laboratory.",
        },
        "metrics": {
            "artifact_faults": {
                "classification": "calibrated-simulation",
                "detected": faults["detected"],
                "injected": faults["injected"],
                "rate": faults["detected"] / faults["injected"],
                "model": "single-bit artifact mutation",
            },
            "leakage_calibration": {
                "classification": "calibrated-simulation",
                "model": leakage["model"],
                "samples_per_class": leakage["samples_per_class"],
                "threshold": leakage["threshold"],
                "positive_control_abs_t": leakage["positive_control_abs_t"],
                "negative_control_abs_t": leakage["negative_control_abs_t"],
            },
            "timing": {"classification": "measured-product-evidence", **timing},
            "historical_replay": {
                "classification": "measured-product-evidence",
                "passed": len(advisory_rows),
                "total": len(advisory_rows),
                "ids": [row["id"] for row in advisory_rows],
            },
            "packages": {
                "classification": "measured-product-evidence",
                "byte_equal": len(package_rows),
                "total": len(package_rows),
                "names": [row["name"] for row in package_rows],
            },
            "sboms": {
                "classification": "measured-product-evidence",
                "deterministic": len(sboms),
                "workspaces": [path.name.removesuffix(".cdx.json") for path in sboms],
            },
            "standards": {
                "classification": "repository-corpus-correctness",
                "total_cases": standards["total_cases"],
                "ml_dsa_cases": standards["ml_dsa_cases"],
                "ml_kem_cases": standards["ml_kem_cases"],
                "provenance": standards["provenance"],
            },
            "platforms": {
                "classification": "build-and-compiler-shape-evidence",
                "configured_targets": 4,
                "targets": [
                    "x86_64-unknown-linux-gnu",
                    "aarch64-unknown-linux-gnu",
                    "wasm32-unknown-unknown",
                    "thumbv7em-none-eabihf",
                ],
            },
        },
        "evidence": {
            "lab_report_sha256": sha256(report_path),
            "manifest_sha256": signature["manifest_sha256"],
            "manifest_signature": {
                "algorithm": "Ed25519",
                "verified": True,
                "external_identity_claimed": False,
            },
            "threat_review": report["threat_review"],
        },
        "scope": {
            "demonstrates": report["claims"]["actual_product_evidence"] + report["claims"]["simulation_evidence"],
            "does_not_claim": report["claims"]["unclaimed"],
        },
    }


def rendered(profile: dict) -> tuple[bytes, bytes]:
    profile_raw = (json.dumps(profile, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    template = TEMPLATE.read_text(encoding="utf-8")
    marker = "__DCRYPT_ASSURANCE_PROFILE__"
    if template.count(marker) != 1:
        raise ReportError("assurance report template marker differs")
    embedded = json.dumps(profile, sort_keys=True, ensure_ascii=False).replace("</", "<\\/")
    html = template.replace(marker, embedded).encode("utf-8")
    return profile_raw, html


def generate(lab: pathlib.Path, output: pathlib.Path, check: bool) -> None:
    profile_raw, html = rendered(build_profile(lab))
    expected = {
        "assurance-profile.json": profile_raw,
        "assurance-report.html": html,
    }
    if check:
        observed = {path.name for path in output.iterdir() if path.is_file()} if output.is_dir() else set()
        if observed != set(expected):
            raise ReportError("assurance report output closure differs")
        for name, raw in expected.items():
            if (output / name).read_bytes() != raw:
                raise ReportError(f"generated assurance output differs: {name}")
        return
    output.mkdir(parents=True, exist_ok=True)
    unexpected = {path.name for path in output.iterdir() if path.is_file()} - set(expected)
    if unexpected:
        raise ReportError(f"unexpected assurance report output: {sorted(unexpected)}")
    for name, raw in expected.items():
        (output / name).write_bytes(raw)


def fixture_report(root: pathlib.Path) -> None:
    (root / "packages").mkdir(parents=True)
    (root / "sboms").mkdir()
    for name in ("bench", "fuzz", "migration", "production", "verification"):
        (root / "sboms" / f"{name}.cdx.json").write_text("{}\n", encoding="utf-8")
    packages = [{"byte_equal": True, "name": f"crate-{index}", "version": "4.0.0"} for index in range(12)]
    (root / "packages/manifest.json").write_text(json.dumps({"packages": packages}) + "\n", encoding="utf-8")
    advisory = {"results": [{"id": f"DCRYPT-2026-{index:04d}", "passed": True} for index in range(1, 12)]}
    (root / "historical-advisory-replay.json").write_text(json.dumps(advisory) + "\n", encoding="utf-8")
    (root / "evidence-manifest.json").write_text("{}\n", encoding="utf-8")
    cases = [{
        "name": f"timing-case-{index:02d}", "primary_p_value": 0.5,
        "holm_reject": False, "exceeds_practical_threshold": False,
        "blocks_release": False, "mean_diff_ns": 0.05,
        "ci_lower_ns": -0.1, "ci_upper_ns": 0.2, "practical_threshold_ns": 0.5,
    } for index in range(29)]
    commands = []
    for command_id in REQUIRED_COMMANDS:
        row = {"id": command_id, "passed": True}
        if command_id in TIMING_COMMANDS:
            row["timing_family"] = {"family_alpha": 0.01, "family_passed": True, "cases": cases}
        commands.append(row)
    report = {
        "artifacts": [], "claims": {
            "actual_product_evidence": ["product-pass"],
            "simulation_evidence": ["simulation-pass"],
            "unclaimed": ["physical-device-measurement"],
        },
        "commands": commands, "generated_at_utc": "2026-08-15T00:00:00+00:00",
        "passed": True, "schema_version": 1,
        "signature_evidence": {"algorithm": "Ed25519", "manifest_sha256": "a" * 64, "verified": True},
        "simulation_controls": {
            "artifact_single_bit_fault": {"detected": 432, "injected": 432, "passed": True},
            "hamming_weight_tvla": {
                "model": "fixture", "negative_control_abs_t": 0.64,
                "negative_control_passed": True, "positive_control_abs_t": 318.93,
                "positive_control_passed": True, "samples_per_class": 20000, "threshold": 4.5,
            },
        },
        "standards_evidence": {
            "ml_dsa_cases": 615, "ml_kem_cases": 240, "passed": True,
            "provenance": "repository-byte-bound-corpus", "total_cases": 855,
        },
        "subject": {
            "commit": "b" * 40, "tree": "c" * 40,
            "working_tree_clean": True, "working_tree_status_sha256": "e" * 64,
        },
        "threat_review": {"type": "fixture"},
    }
    artifact_paths = [
        root / "historical-advisory-replay.json", root / "packages/manifest.json",
        root / "evidence-manifest.json", *sorted((root / "sboms").glob("*.json")),
    ]
    report["artifacts"] = [{
        "path": path.relative_to(root).as_posix(), "sha256": sha256(path), "size": path.stat().st_size,
    } for path in artifact_paths]
    (root / "lab-report.json").write_text(json.dumps(report) + "\n", encoding="utf-8")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="dcrypt-assurance-report-") as name:
        root = pathlib.Path(name)
        fixture_report(root)
        output = root / "report"
        generate(root, output, check=False)
        generate(root, output, check=True)
        profile = load_json(output / "assurance-profile.json")
        if profile["metrics"]["artifact_faults"]["detected"] != 432:
            raise AssertionError("fault metric was not projected")
        if profile["metrics"]["timing"]["blocking_cases"] != 29:
            raise AssertionError("timing metric was not projected")


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--generate", action="store_true")
    action.add_argument("--check", action="store_true")
    action.add_argument("--self-test", action="store_true")
    parser.add_argument("--lab-output", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("v4 Assurance Profile generator self-test passed")
            return 0
        if args.lab_output is None or args.output is None:
            parser.error("--generate/--check require --lab-output and --output")
        generate(args.lab_output.resolve(), args.output.resolve(), check=args.check)
        verb = "verified" if args.check else "generated"
        print(f"{verb} v4 Assurance Profile in {args.output}")
        return 0
    except (OSError, UnicodeError, ValueError, KeyError, json.JSONDecodeError, ReportError) as error:
        print(f"v4 Assurance Profile error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
