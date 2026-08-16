#!/usr/bin/env python3
"""Verify the explicit v4 portable-software release decision."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "assurance/release-profile/policy.toml"
G_COMMIT = "088b2d2fe1e7d7cc3591cfde5040d447010a74bd"
ORACLE_REBIND_COMMIT = "fb285a462de31052b842011a7cf9dae4d525ec2b"
ORACLE_MANIFEST_SHA256 = "3523c3ca4533afe20d66a96d91426ebabbd1b507c3963d06c33f30eed6d8e203"
ORACLE_SUBJECT_COMMIT = "2d2d532f7aef28cbb5450fe1f5c519e507dd8bc6"
DISPOSITIONS = (
    "package-a-atomic-ledger",
    "package-b-independent-interoperability",
    "package-c-persistent-fuzz",
    "package-d-platform-physical",
    "package-e-error-api-v4",
    "package-f-sbom-signature-rebuild",
    "threat-model-review",
    "historical-advisory-replay",
    "terminal-a-g",
)
CONSUMERS = (
    "tools/release-dcrypt.sh",
    "tools/verify-publish-ready.sh",
    "tools/verify-remote-release-ready.py",
    ".github/workflows/security-validation.yml",
)
TOOLS = (
    "tools/replay-historical-advisories.py",
    "tools/generate-release-sboms.py",
    "tools/verify-repeatable-packages.py",
    "tools/run-v4-lab-simulation.py",
    "tools/generate-v4-assurance-report.py",
)
EVIDENCE = (
    "assurance/release-lab/DAYBREAK-THREAT-REVIEW.md",
)


class InvalidProfile(RuntimeError):
    pass


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0:
        raise InvalidProfile(f"git {' '.join(args)} failed")
    return result.stdout.strip()


def load_policy(path: pathlib.Path = POLICY_PATH) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise InvalidProfile(f"cannot parse release profile: {error}") from error


def verify_policy(policy: dict) -> None:
    expected_top = {
        "schema-version", "profile", "target-version", "status",
        "package-g-foundation", "package-g-foundation-status", "authorization",
        "oracle-subject-rebind-commit", "oracle-normative-manifest-sha256",
        "claims", "nonclaims", "disposition", "mandatory-consumers", "mandatory-tools",
        "mandatory-evidence",
    }
    if set(policy) != expected_top:
        raise InvalidProfile("policy top-level closure differs")
    if policy["schema-version"] != 1 or policy["profile"] != "dcrypt-v4-portable-software-release":
        raise InvalidProfile("policy identity differs")
    if policy["target-version"] != "4.0.0" or policy["package-g-foundation"] != G_COMMIT:
        raise InvalidProfile("target version or Package G foundation differs")
    if (
        policy["oracle-subject-rebind-commit"] != ORACLE_REBIND_COMMIT
        or policy["oracle-normative-manifest-sha256"] != ORACLE_MANIFEST_SHA256
    ):
        raise InvalidProfile("oracle subject rebind authority differs")
    if policy["status"] != "AUTHORIZED-WHEN-SOFTWARE-GATES-PASS":
        raise InvalidProfile("release decision is not authorized")

    required_claims = {
        "portable-source-release", "known-critical-or-high-code-findings-allowed",
        "full-repository-release-gates-required", "historical-advisory-replay-required",
        "deterministic-sboms-required", "repeatable-package-bytes-required",
        "registry-checksum-equality-required", "trusted-candidate-checks-required",
        "open-simulated-laboratory-required",
    }
    claims = policy.get("claims")
    if not isinstance(claims, dict) or set(claims) != required_claims:
        raise InvalidProfile("claim closure differs")
    if claims["known-critical-or-high-code-findings-allowed"] is not False:
        raise InvalidProfile("known Critical/High code findings cannot be accepted")
    if any(claims[name] is not True for name in required_claims - {"known-critical-or-high-code-findings-allowed"}):
        raise InvalidProfile("a mandatory software-release claim was disabled")

    required_nonclaims = {
        "physical-leakage-resistance", "fault-injection-resistance", "physical-erasure",
        "untested-native-platform-runtime", "independent-cryptographic-audit",
        "formal-verification", "fips-validation", "independent-reproducible-build-certification",
    }
    nonclaims = policy.get("nonclaims")
    if not isinstance(nonclaims, dict) or set(nonclaims) != required_nonclaims:
        raise InvalidProfile("nonclaim closure differs")
    if any(value is not True for value in nonclaims.values()):
        raise InvalidProfile("a required nonclaim was weakened")

    rows = policy.get("disposition")
    if not isinstance(rows, list) or tuple(row.get("id") for row in rows) != DISPOSITIONS:
        raise InvalidProfile("blocker disposition closure/order differs")
    if any(set(row) != {"id", "decision", "condition"} or not row["condition"] for row in rows):
        raise InvalidProfile("blocker disposition shape differs")
    if tuple(policy["mandatory-consumers"]) != CONSUMERS or tuple(policy["mandatory-tools"]) != TOOLS:
        raise InvalidProfile("mandatory release integration closure differs")
    if tuple(policy["mandatory-evidence"]) != EVIDENCE:
        raise InvalidProfile("mandatory review-evidence closure differs")


def verify_repository(policy: dict) -> None:
    if _git("merge-base", "--is-ancestor", G_COMMIT, "HEAD") != "":
        # `git merge-base --is-ancestor` intentionally has no stdout.
        raise InvalidProfile("unexpected output while resolving Package G ancestry")
    for path in (
        "assurance/release-acceptance/policy.toml",
        "assurance/release-acceptance/package-g.json",
        "assurance/release-acceptance/verify.py",
    ):
        _git("cat-file", "-e", f"{G_COMMIT}:{path}")

    if _git("merge-base", "--is-ancestor", ORACLE_REBIND_COMMIT, "HEAD") != "":
        raise InvalidProfile("unexpected output while resolving oracle-rebind ancestry")
    oracle_manifest_path = ROOT / "verification/oracle-provisioning/manifest.json"
    oracle_manifest_raw = oracle_manifest_path.read_bytes()
    if hashlib.sha256(oracle_manifest_raw).hexdigest() != ORACLE_MANIFEST_SHA256:
        raise InvalidProfile("oracle normative manifest digest differs")
    oracle_manifest = json.loads(oracle_manifest_raw)
    if (
        oracle_manifest.get("subject", {}).get("source_commit") != ORACLE_SUBJECT_COMMIT
        or oracle_manifest.get("subject", {}).get("subsequent_assurance_binding_required") is not True
    ):
        raise InvalidProfile("oracle prior-subject binding differs")
    for path in (
        "verification/oracle-provisioning/bundle_lib.py",
        "verification/oracle-provisioning/manifest.json",
        "verification/oracle-provisioning/subject-inputs.json",
    ):
        _git("cat-file", "-e", f"{ORACLE_REBIND_COMMIT}:{path}")

    strategy = (ROOT / "VERSION_STRATEGY.md").read_text(encoding="utf-8")
    required_strategy = (
        "Passing repository gates is not an",
        "Clearly disclose that independent cryptographic and protocol review",
        "publish only after all blockers are closed",
    )
    if any(marker not in strategy for marker in required_strategy):
        raise InvalidProfile("VERSION_STRATEGY.md release/nonclaim contract differs")

    for relative in (*CONSUMERS, *TOOLS, *EVIDENCE):
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise InvalidProfile(f"mandatory release member is absent or not regular: {relative}")
    integration_marker = "assurance/release-profile/verify.py"
    for relative in CONSUMERS:
        if integration_marker not in (ROOT / relative).read_text(encoding="utf-8"):
            raise InvalidProfile(f"release profile is not wired into {relative}")

    threat_review = (ROOT / EVIDENCE[0]).read_text(encoding="utf-8")
    required_review_markers = (
        "OpenAI Daybreak adversarial review",
        G_COMMIT,
        "No concrete Critical or High code vulnerability was identified",
        "does not claim administrative",
    )
    if any(marker not in threat_review for marker in required_review_markers):
        raise InvalidProfile("Daybreak threat-review evidence contract differs")

    historical = tomllib.loads(
        (ROOT / "assurance/audit/historical-advisory-regressions.toml").read_text(encoding="utf-8")
    )
    rows = historical.get("regression")
    expected_ids = [f"DCRYPT-2026-{index:04d}" for index in range(1, 12)]
    if not isinstance(rows, list) or [row.get("id") for row in rows] != expected_ids:
        raise InvalidProfile("historical advisory inventory is not the exact eleven-row set")
    if any(row.get("status") != "source-bound-replay-required" for row in rows):
        raise InvalidProfile("historical advisory inventory was promoted without replay")


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--phase", required=True, choices=("foundation", "prepublish", "postpublish"))
    args = parser.parse_args()
    try:
        policy = load_policy()
        verify_policy(policy)
        verify_repository(policy)
    except (InvalidProfile, OSError, UnicodeError, ValueError) as error:
        print(f"v4 release profile invalid: {error}", file=sys.stderr)
        return 1
    print(
        f"v4 portable-software profile ready: phase={args.phase}; "
        "Package G certification HOLD preserved; physical/independent-audit claims excluded"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
