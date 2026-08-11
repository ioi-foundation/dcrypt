#!/usr/bin/env python3
"""Adversarial self-tests for the candidate audit-freeze format."""

from __future__ import annotations

import datetime as dt
import copy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Callable


HERE = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = load("dcrypt_freeze_selftest_generator", HERE / "generate-audit-freeze.py")
verify = load("dcrypt_freeze_selftest_verifier", HERE / "verify-audit-freeze.py")


def run(*args: str, cwd: Path, input_data: bytes | None = None) -> bytes:
    git_descriptor: int | None = None
    if args and args[0] == "git":
        git_descriptor = gen.open_bound_git_executable()
        command = (f"/proc/self/fd/{git_descriptor}", *args[1:])
    else:
        command = args
    environment = gen.closed_git_environment() if args and args[0] == "git" else None
    if environment is not None and os.environ.get("SOURCE_DATE_EPOCH", "").isdigit():
        git_date = f"@{os.environ['SOURCE_DATE_EPOCH']} +0000"
        environment["GIT_AUTHOR_DATE"] = git_date
        environment["GIT_COMMITTER_DATE"] = git_date
    try:
        result = subprocess.run(
            command, cwd=cwd, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, pass_fds=(() if git_descriptor is None else (git_descriptor,)),
        )
    finally:
        if git_descriptor is not None:
            os.close(git_descriptor)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.decode('utf-8', 'replace')}")
    return result.stdout


def put(repo: Path, path: str, data: str | bytes) -> None:
    destination = repo / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)


def install_historical_release_objects(repo: Path) -> None:
    run(
        "git", "-c", "pack.writeReverseIndex=false", "fetch", "-q", "--no-tags", str(HERE.parent),
        "refs/tags/v3.0.0:refs/tags/v3.0.0", cwd=repo,
    )
    actual = run("git", "rev-parse", "refs/tags/v3.0.0", cwd=repo).decode().strip()
    if actual != "c3f1dc869df7e61a2c0d4a23833ea6accb5c8b33":
        raise AssertionError(f"historical tag fixture object mismatch: {actual}")


def fixture_policy() -> str:
    return (HERE / "audit" / "freeze-policy.toml").read_text(encoding="utf-8")


def fixture_provisioning() -> str:
    return (HERE / "audit" / "provisioning-lock.toml").read_text(encoding="utf-8")


def make_fixture(repo: Path) -> str:
    repo.mkdir()
    run("git", "init", "-q", cwd=repo)
    run("git", "config", "user.name", "audit-freeze-selftest", cwd=repo)
    run("git", "config", "user.email", "selftest@example.invalid", cwd=repo)
    for cargo_path in sorted(gen.EXPECTED_CARGO_INPUT_SHA256):
        put(repo, cargo_path, (HERE.parent / cargo_path).read_bytes())
    published = ", ".join(f'"{name}"' for name in (
        "dcrypt-internal", "dcrypt-params", "dcrypt-api", "dcrypt-common", "dcrypt-algorithms",
        "dcrypt-symmetric", "dcrypt-kem", "dcrypt-sign", "dcrypt-pke", "dcrypt-utils", "dcrypt-hybrid", "dcrypt",
    ))
    put(repo, "implementation-boundary.toml", f"schema-version = 2\npublished-packages = [{published}]\n")
    for path in ("CHANGELOG.md", "CONSTANT_TIME_POLICY.md", "RELEASE_NOTES.md", "SECURITY.md", "VERSION_STRATEGY.md"):
        put(repo, path, f"# {path}\n")
    put(repo, "deny.toml", "[advisories]\nversion = 2\n")
    put(repo, "rust-toolchain.toml", "[toolchain]\nchannel = \"1.93.1\"\n")
    put(repo, ".gitignore", "target/\n")
    put(repo, "src/lib.rs", "pub fn fixture() {}\n")
    put(repo, ".github/workflows/security-validation.yml", (HERE.parent / ".github/workflows/security-validation.yml").read_bytes())
    ledger = ["schema-version = 2"]
    for index in range(17):
        ledger.extend(
            (
                "[[evidence]]", f'id = "evidence-{index:02d}"', "required = true",
                'owner = "fixture owner"', 'reviewer = "fixture reviewer"',
                "reviewed-at = 2026-08-11", "valid-through = 2026-11-09",
                'verdict = "informational"',
            )
        )
    put(repo, "assurance/ledger.toml", "\n".join(ledger) + "\n")
    atomic = ["schema-version = 2"]
    for index in range(314):
        atomic.extend(("[[operation]]", f'id = "operation-{index:04d}"', 'release-readiness = "blocked"'))
    for index in range(352):
        atomic.extend(("[[operation]]", f'id = "alias.fixture-{index:04d}"', 'release-readiness = "blocked"'))
    atomic.extend(("[unreviewed-gap-defaults]", 'release-readiness = "blocked"'))
    for index in range(8632):
        atomic.extend(("[[unreviewed-gap]]", f'id = "gap-{index:04d}"'))
    put(repo, "assurance/atomic-operations.toml", "\n".join(atomic) + "\n")
    put(repo, "assurance/curated-operations.toml", "schema-version = 2\n")
    put(repo, "assurance/public-api-snapshot.json", gen.canonical_json({"schema_version": 2, "entries": list(range(19021))}))
    put(repo, "assurance/subject-manifest.json", gen.canonical_json({"schema_version": 1, "files": []}))
    put(repo, "assurance/acvp-vector-manifest.json", gen.canonical_json({"schema_version": 1, "files": []}))
    put(repo, "assurance/SUPPORTED-ALGORITHMS.md", "# Fixture algorithms\n")
    put(repo, "assurance/generate-assurance-ledger.py", "# fixture\n")
    put(repo, "assurance/verify-assurance-ledger.py", "# fixture\n")
    put(repo, "assurance/assurance-selftest.py", "# fixture\n")
    put(repo, "assurance/generate-audit-freeze.py", "# bound generator fixture\n")
    put(repo, "assurance/verify-audit-freeze.py", "# bound verifier fixture\n")
    put(repo, "assurance/audit-freeze-selftest.py", "# bound selftest fixture\n")
    put(repo, "assurance/audit/freeze-policy.toml", fixture_policy())
    put(repo, "assurance/audit/README.md", (HERE / "audit" / "README.md").read_bytes())
    put(repo, "assurance/audit/provisioning-lock.toml", fixture_provisioning())
    put(repo, "assurance/audit/audit-freeze.schema.json", (HERE / "audit" / "audit-freeze.schema.json").read_bytes())
    put(repo, "assurance/audit/freeze-envelope.schema.json", (HERE / "audit" / "freeze-envelope.schema.json").read_bytes())
    put(repo, "assurance/audit/provisioning.schema.json", (HERE / "audit" / "provisioning.schema.json").read_bytes())
    historical_bytes = (HERE / "audit" / "historical-advisory-regressions.toml").read_bytes()
    put(repo, "assurance/audit/historical-advisory-regressions.toml", historical_bytes)
    for row in tomllib.loads(historical_bytes.decode("utf-8"))["regression"]:
        source = row["source"]
        if Path(source).suffix:
            put(repo, source, "// historical regression fixture\n")
        else:
            put(repo, f"{source}/fixture.rs", "// historical regression fixture\n")
    put(repo, "assurance/threat-models/README.md", "# Fixture threat model\n")
    threat = [
        "schema-version = 1", "expected-atomic-row-count = 9298",
        "expected-release-blocked-count = 9298",
    ]
    for index in range(11):
        threat.extend(
            (
                "[[model]]", f'id = "TM-FIXTURE-{index:02d}"', 'status = "candidate"',
                'owner = "fixture owner"', 'reviewer = "independent review pending"',
                'independent-review-status = "required"', "reviewed-at = 2026-08-11",
                "valid-through = 2026-11-09", 'mitigations = [{ id = "pending", status = "planned" }]',
                'residual-risk = { rating = "critical", disposition = "mitigate" }',
            )
        )
    put(repo, "assurance/threat-models/threat-models.toml", "\n".join(threat) + "\n")
    put(repo, "assurance/threat-models/verify-threat-models.py", "# fixture\n")
    put(repo, "assurance/threat-models/threat-model-selftest.py", "# fixture\n")
    put(repo, "assurance/audit/sow/RFP-SOW.md", "# Fixture RFP/SOW\nExact subject bytes are bound by the generated envelope.\n")
    put(repo, "assurance/audit/sow/audit-policy.toml", 'schema-version = 1\nstatus = "candidate-uncommissioned"\nexternal-contact-authorized = false\naudit-commissioned = false\n')
    put(repo, "assurance/audit/sow/audit-scope.toml", "schema-version = 1\n")
    put(repo, "assurance/audit/sow/verify-sow.py", "# fixture\n")
    put(repo, "assurance/audit/sow/selftest.py", "# fixture\n")
    for path in (
        "tools/release-dcrypt.sh",
        "tools/verify-publish-ready.sh",
        "tools/verify-remote-release-ready.py",
        "tools/verify-implementation-boundary.py",
        "tools/verify-implementation-boundary.sh",
        "tools/verify-bls-secret-assembly.py",
        "tools/verify-bls-secret-assembly.sh",
        "tools/verify-ghash-assembly.py",
        "tools/verify-ghash-assembly.sh",
        "tools/update-isolated-workspace-versions.py",
    ):
        put(repo, path, "# bound fixture tool\n")
    run("git", "add", ".", cwd=repo)
    run("git", "commit", "-q", "-m", "fixture subject", cwd=repo)
    install_historical_release_objects(repo)
    return run("git", "rev-parse", "HEAD", cwd=repo).decode().strip()


def copy_bundle(source: Path, root: Path, name: str) -> Path:
    destination = root / name
    shutil.copytree(source, destination)
    destination.chmod(0o700)
    return destination


def clone_isolated(source: Path, destination: Path, *, cwd: Path) -> None:
    run(
        "git", "-c", "pack.writeReverseIndex=false", "clone", "-q", "--no-local",
        "--no-hardlinks", str(source), str(destination), cwd=cwd,
    )


def make_evidence_commit(root: Path, subject_repo: Path, encoded: dict[str, bytes], name: str = "evidence") -> tuple[Path, Path]:
    evidence_repo = root / name
    clone_isolated(subject_repo, evidence_repo, cwd=root)
    run("git", "config", "user.name", "audit-freeze-selftest", cwd=evidence_repo)
    run("git", "config", "user.email", "selftest@example.invalid", cwd=evidence_repo)
    bundle = evidence_repo / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID
    bundle.parent.mkdir(parents=True)
    gen.write_bundle(bundle, encoded)
    run("git", "add", "--", str(bundle.relative_to(evidence_repo)), cwd=evidence_repo)
    run("git", "commit", "-q", "-m", "candidate freeze evidence", cwd=evidence_repo)
    return evidence_repo, bundle


def rewrite_checksums(bundle: Path) -> None:
    lines = []
    for name in sorted(gen.JSON_FILES):
        lines.append(f"{gen.sha256((bundle / name).read_bytes())}  {name}\n")
    (bundle / "SHA256SUMS").write_text("".join(lines), encoding="ascii")


def expect_failure(label: str, action: Callable[[], object], contains: str | None = None) -> None:
    try:
        action()
    except (gen.FreezeError, verify.gen.FreezeError) as exc:
        if contains and contains.lower() not in str(exc).lower():
            raise AssertionError(f"{label}: wrong failure: {exc}") from exc
        print(f"ok - rejects {label}")
        return
    except Exception as exc:
        raise AssertionError(
            f"{label}: raised unexpected {type(exc).__name__}, not a fail-closed validation error: {exc}"
        ) from exc
    raise AssertionError(f"{label}: unexpectedly passed")


def mutate_subject(root: Path, fixture: Path, name: str, mutation: Callable[[Path], None]) -> tuple[Path, str]:
    destination = root / f"subject-{name}"
    shutil.copytree(fixture, destination)
    mutation(destination)
    run("git", "add", "-A", cwd=destination)
    run("git", "commit", "-q", "-m", name, cwd=destination)
    subject = run("git", "rev-parse", "HEAD", cwd=destination).decode().strip()
    return destination, subject


def main() -> int:
    gen.require_isolated_python()
    gen.require_documented_sandbox_runtime(require_empty_output=True)
    optimized = subprocess.run(
        [
            "/usr/bin/python3.12", "-I", "-B", "-S", "-O", "-c",
            'import runpy;m=runpy.run_path("/dcrypt/assurance/generate-audit-freeze.py");m["require_isolated_python"]()',
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(os.environ),
        timeout=10,
    )
    if optimized.returncode == 0 or b"forbids Python optimization" not in optimized.stderr:
        raise AssertionError("optimized Python invocation bypassed the self-test assertion policy")
    print("ok - rejects optimized Python execution before assertions can be disabled")
    network_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        network_probe.settimeout(0.25)
        if network_probe.connect_ex(("192.0.2.1", 9)) == 0:
            raise AssertionError("unshared sandbox unexpectedly completed an external network connection")
    finally:
        network_probe.close()
    print("ok - documented sandbox cannot reach an external TEST-NET address")
    with tempfile.TemporaryDirectory(prefix="dcrypt-audit-freeze-selftest-") as temporary:
        root = Path(temporary)
        original_epoch = os.environ["SOURCE_DATE_EPOCH"]
        os.environ["SOURCE_DATE_EPOCH"] = str(int(original_epoch) + 1)
        expect_failure(
            "wrong subject SOURCE_DATE_EPOCH",
            lambda: gen.require_documented_sandbox_runtime(
                expected_source_date_epoch=int(original_epoch)
            ),
            "exact subject commit timestamp",
        )
        os.environ["SOURCE_DATE_EPOCH"] = original_epoch
        with contextlib.chdir(root):
            expect_failure(
                "wrong virtual repository root",
                gen.require_documented_sandbox_runtime,
                "virtual repository root /dcrypt",
            )
        os.environ["DCRYPT_AUDIT_UNEXPECTED"] = "forbidden"
        expect_failure(
            "unexpected sandbox environment",
            gen.require_documented_sandbox_runtime,
            "exact allowlist",
        )
        del os.environ["DCRYPT_AUDIT_UNEXPECTED"]
        mount_base = "".join(
            (
                "1 0 0:1 /newroot / ro - tmpfs tmpfs rw\n",
                "2 1 8:1 /usr /usr ro - ext4 /dev/root rw\n",
                "3 1 8:1 /usr/bin /bin ro - ext4 /dev/root rw\n",
                "4 1 8:1 /usr/lib /lib ro - ext4 /dev/root rw\n",
                "5 1 8:1 /usr/lib64 /lib64 ro - ext4 /dev/root rw\n",
                "6 1 8:1 /etc/ld.so.cache /etc/ld.so.cache ro - ext4 /dev/root rw\n",
                "10 1 8:1 /repo /dcrypt ro - ext4 /dev/root rw\n",
                "20 1 0:20 / /dev rw - tmpfs tmpfs rw\n",
                "21 20 0:6 /null /dev/null rw - devtmpfs udev rw\n",
                "22 20 0:6 /zero /dev/zero rw - devtmpfs udev rw\n",
                "23 20 0:6 /full /dev/full rw - devtmpfs udev rw\n",
                "24 20 0:6 /random /dev/random rw - devtmpfs udev rw\n",
                "25 20 0:6 /urandom /dev/urandom rw - devtmpfs udev rw\n",
                "26 20 0:6 /tty /dev/tty rw - devtmpfs udev rw\n",
                "27 20 0:27 / /dev/pts rw - devpts devpts rw\n",
                "30 1 0:30 / /proc rw - proc proc rw\n",
                "31 1 0:31 / /tmp rw - tmpfs tmpfs rw\n",
                "32 1 0:32 / /cargo rw - tmpfs tmpfs rw\n",
            )
        )
        generation_mount_fixture = mount_base + "33 1 0:33 /dcrypt-audit-output.fixture /output rw - tmpfs tmpfs rw\n"
        verification_mount_fixture = mount_base + "".join(
            (
                "34 1 8:2 /evidence /evidence ro - ext4 /dev/evidence rw\n",
                f"35 1 0:35 /handoff/{gen.PROVISIONING_HANDOFF_ID} /provision ro - tmpfs tmpfs rw\n",
            )
        )
        parsed_mounts = gen.parse_sandbox_mountinfo(generation_mount_fixture)
        gen.validate_sandbox_mount_topology(
            parsed_mounts, require_empty_output=True, require_evidence=False
        )
        gen.validate_sandbox_mount_topology(
            gen.parse_sandbox_mountinfo(verification_mount_fixture),
            require_empty_output=False, require_evidence=True, require_provision=True,
        )
        expect_failure(
            "descendant subject mount",
            lambda: gen.validate_sandbox_mount_topology(
                gen.parse_sandbox_mountinfo(
                    generation_mount_fixture + "13 10 0:3 / /dcrypt/assurance rw - tmpfs tmpfs rw\n"
                ),
                require_empty_output=True, require_evidence=False,
            ),
            "closed contract",
        )
        expect_failure(
            "subject-backed output alias",
            lambda: gen.validate_sandbox_mount_topology(
                gen.parse_sandbox_mountinfo(
                    generation_mount_fixture.replace(
                        "33 1 0:33 /dcrypt-audit-output.fixture /output rw - tmpfs tmpfs rw",
                        "33 1 8:1 /disjoint /output rw - tmpfs tmpfs rw",
                    )
                ),
                require_empty_output=True, require_evidence=False,
            ),
            "different filesystem device",
        )
        expect_failure(
            "unexpected host mount",
            lambda: gen.validate_sandbox_mount_topology(
                gen.parse_sandbox_mountinfo(
                    generation_mount_fixture + "36 1 8:1 / /host rw - ext4 /dev/root rw\n"
                ),
                require_empty_output=True, require_evidence=False,
            ),
            "closed contract",
        )
        expect_failure(
            "missing runtime mount",
            lambda: gen.validate_sandbox_mount_topology(
                gen.parse_sandbox_mountinfo(
                    generation_mount_fixture.replace("2 1 8:1 /usr /usr ro - ext4 /dev/root rw\n", "")
                ),
                require_empty_output=True, require_evidence=False,
            ),
            "closed contract",
        )
        expect_failure(
            "writable runtime mount",
            lambda: gen.validate_sandbox_mount_topology(
                gen.parse_sandbox_mountinfo(generation_mount_fixture.replace("/usr ro", "/usr rw", 1)),
                require_empty_output=True, require_evidence=False,
            ),
            "read-only",
        )
        expect_failure(
            "writable evidence mount",
            lambda: gen.validate_sandbox_mount_topology(
                gen.parse_sandbox_mountinfo(
                    verification_mount_fixture.replace("/evidence ro", "/evidence rw")
                ),
                require_empty_output=False,
                require_evidence=True,
                require_provision=True,
            ),
            "evidence must be an exact read-only mount",
        )
        expect_failure(
            "generation cross-mode evidence mount",
            lambda: gen.validate_sandbox_mount_topology(
                gen.parse_sandbox_mountinfo(
                    generation_mount_fixture
                    + "34 1 8:2 /evidence /evidence ro - ext4 /dev/evidence rw\n"
                ),
                require_empty_output=True, require_evidence=False,
            ),
            "closed contract",
        )
        expect_failure(
            "verification cross-mode output mount",
            lambda: gen.validate_sandbox_mount_topology(
                gen.parse_sandbox_mountinfo(
                    verification_mount_fixture
                    + "36 1 0:36 /dcrypt-audit-output.fixture /output rw - tmpfs tmpfs rw\n"
                ),
                require_empty_output=False, require_evidence=True, require_provision=True,
            ),
            "closed contract",
        )
        expect_failure(
            "missing provisioning mount",
            lambda: gen.validate_sandbox_mount_topology(
                gen.parse_sandbox_mountinfo(
                    verification_mount_fixture.replace(
                        f"35 1 0:35 /handoff/{gen.PROVISIONING_HANDOFF_ID} /provision ro - tmpfs tmpfs rw\n",
                        "",
                    )
                ),
                require_empty_output=False, require_evidence=True, require_provision=True,
            ),
            "closed contract",
        )
        print("ok - subject and .git mounts are read-only under the documented sandbox")
        fixture = root / "fixture"
        subject = make_fixture(fixture)
        first = gen.build_bundle_bytes(fixture, subject)
        second = gen.build_bundle_bytes(fixture, subject)
        assert first == second
        source_manifest = json.loads(first["source-manifest.json"])
        gitignore_rows = [row for row in source_manifest["files"] if row["path"] == ".gitignore"]
        assert len(gitignore_rows) == 1 and gitignore_rows[0]["sha256"] == gen.sha256(b"target/\n")
        assert source_manifest["committed_gitignore_binding"]["sha256"] == gen.sha256(b"target/\n")
        assert source_manifest["committed_gitignore_binding"]["commissioning_dirty_delta_is_context_only"] is True
        handoff_bytes = {
            "PROVISIONING-MANIFEST.json": first["PROVISIONING-MANIFEST.json"],
            "SHA256SUMS": first["PROVISIONING-SHA256SUMS"],
        }
        provisioning_directory = root / "provisioning-handoff"
        gen.write_bundle(
            provisioning_directory, handoff_bytes,
            expected_files=gen.PROVISIONING_HANDOFF_FILES,
        )
        gen.validate_provisioning_handoff_contents(
            gen.read_exact_directory_files(
                provisioning_directory, gen.PROVISIONING_HANDOFF_FILES
            ),
            handoff_bytes,
        )

        def copy_handoff(name: str) -> Path:
            destination = root / name
            shutil.copytree(provisioning_directory, destination)
            destination.chmod(0o555)
            for child in destination.iterdir():
                child.chmod(0o644)
            return destination

        missing_handoff = copy_handoff("provision-missing")
        missing_handoff.chmod(0o755)
        (missing_handoff / "SHA256SUMS").unlink()
        missing_handoff.chmod(0o555)
        expect_failure(
            "missing provisioning handoff input",
            lambda: gen.read_exact_directory_files(
                missing_handoff, gen.PROVISIONING_HANDOFF_FILES
            ),
            "file set mismatch",
        )
        extra_handoff = copy_handoff("provision-extra")
        extra_handoff.chmod(0o755)
        (extra_handoff / "UNEXPECTED").write_text("forbidden\n", encoding="ascii")
        (extra_handoff / "UNEXPECTED").chmod(0o644)
        extra_handoff.chmod(0o555)
        expect_failure(
            "extra provisioning handoff input",
            lambda: gen.read_exact_directory_files(
                extra_handoff, gen.PROVISIONING_HANDOFF_FILES
            ),
            "file set mismatch",
        )
        corrupt_handoff = dict(handoff_bytes)
        corrupt_handoff["PROVISIONING-MANIFEST.json"] += b" "
        expect_failure(
            "corrupt provisioning manifest bytes",
            lambda: gen.validate_provisioning_handoff_contents(
                corrupt_handoff, handoff_bytes
            ),
            "regenerated bytes",
        )
        corrupt_sums = dict(handoff_bytes)
        corrupt_sums["SHA256SUMS"] = b"0" * 64 + b"  PROVISIONING-MANIFEST.json\n"
        expect_failure(
            "corrupt provisioning checksum",
            lambda: gen.validate_provisioning_handoff_contents(corrupt_sums, corrupt_sums),
            "SHA256SUMS",
        )
        network_manifest = json.loads(handoff_bytes["PROVISIONING-MANIFEST.json"])
        network_manifest["network"]["materialization_used_network"] = True
        network_manifest_bytes = gen.canonical_json(network_manifest)
        network_embedded = {
            "PROVISIONING-MANIFEST.json": network_manifest_bytes,
            "PROVISIONING-SHA256SUMS": (
                f"{gen.sha256(network_manifest_bytes)}  PROVISIONING-MANIFEST.json\n"
            ).encode("ascii"),
        }
        expect_failure(
            "provisioning network-use marker promotion",
            lambda: verify.validate_provisioning_manifest_shape(
                network_manifest, network_embedded
            ),
            "network marker",
        )
        symlink_handoff = copy_handoff("provision-symlink")
        symlink_handoff.chmod(0o755)
        (symlink_handoff / "SHA256SUMS").unlink()
        os.symlink("PROVISIONING-MANIFEST.json", symlink_handoff / "SHA256SUMS")
        symlink_handoff.chmod(0o555)
        expect_failure(
            "symlinked provisioning handoff input",
            lambda: gen.read_exact_directory_files(
                symlink_handoff, gen.PROVISIONING_HANDOFF_FILES
            ),
            "uniquely linked",
        )
        hardlink_handoff = copy_handoff("provision-hardlink")
        hardlink_handoff.chmod(0o755)
        hardlink_peer = root / "provision-hardlink-peer"
        os.link(hardlink_handoff / "SHA256SUMS", hardlink_peer)
        hardlink_handoff.chmod(0o555)
        try:
            expect_failure(
                "hardlinked provisioning handoff input",
                lambda: gen.read_exact_directory_files(
                    hardlink_handoff, gen.PROVISIONING_HANDOFF_FILES
                ),
                "uniquely linked",
            )
        finally:
            hardlink_peer.unlink()
        print("ok - provisioning handoff is exact, checksummed, immutable, and fail closed")
        evidence_repo, bundle = make_evidence_commit(root, fixture, first)
        result = verify._verify_bundle_internal(
            evidence_repo, fixture, bundle, provision=provisioning_directory,
            mode="structural", as_of=dt.date(2026, 8, 11)
        )
        assert result["release_blockers"] == 9319  # 9,298 atomic rows plus 21 infrastructure limitations
        print("ok - deterministic generation and structural replay")

        generated_output = Path("/output") / gen.PRODUCTION_FREEZE_ID
        gen.write_bundle(generated_output, first)
        generated = verify.safe_bundle_files(generated_output)
        assert generated == first
        assert set(generated) == set(gen.ALLOWED_BUNDLE_FILES)
        generated_output.chmod(0o700)
        shutil.rmtree(generated_output)
        generated_provision = Path("/output") / gen.PROVISIONING_HANDOFF_ID
        gen.write_bundle(
            generated_provision, handoff_bytes,
            expected_files=gen.PROVISIONING_HANDOFF_FILES,
        )
        assert gen.read_exact_directory_files(
            generated_provision, gen.PROVISIONING_HANDOFF_FILES
        ) == handoff_bytes
        generated_provision.chmod(0o700)
        shutil.rmtree(generated_provision)
        assert not any(Path("/output").iterdir())
        original_open_directory = gen.open_directory_nofollow
        output_open_count = 0

        def inject_output_sibling(path: Path) -> int:
            nonlocal output_open_count
            descriptor = original_open_directory(path)
            if gen.lexical_absolute(path) == Path("/output"):
                output_open_count += 1
                if output_open_count == 2:
                    (Path("/output") / "unexpected-sibling").write_bytes(b"attacker\n")
            return descriptor

        gen.open_directory_nofollow = inject_output_sibling
        try:
            expect_failure(
                "production output sibling injection",
                lambda: gen.write_bundle(Path("/output") / gen.PRODUCTION_FREEZE_ID, first),
                "production /output inventory",
            )
        finally:
            gen.open_directory_nofollow = original_open_directory
            sibling = Path("/output") / "unexpected-sibling"
            if sibling.exists():
                sibling.unlink()
        assert not any(Path("/output").iterdir())

        allocation_parent = root / "allocation-error-output"
        allocation_parent.mkdir()
        original_token_hex = gen.secrets.token_hex
        gen.secrets.token_hex = lambda _size: (_ for _ in ()).throw(OSError("injected entropy failure"))
        try:
            expect_failure(
                "output temporary allocation error cleanup",
                lambda: gen.write_bundle(allocation_parent / "freeze", first),
                "cannot safely write exact output directory",
            )
        finally:
            gen.secrets.token_hex = original_token_hex
        assert not any(allocation_parent.iterdir())
        print("ok - generation and provisioning write only exact bounded output inventories")

        expect_failure(
            "generation CLI repository remap",
            lambda: gen.validate_generation_cli_paths(
                fixture, Path("/output") / gen.PRODUCTION_FREEZE_ID, gen.PRODUCTION_FREEZE_ID
            ),
            "exact sandbox mapping /dcrypt",
        )
        expect_failure(
            "generation CLI output remap",
            lambda: gen.validate_generation_cli_paths(
                Path("/dcrypt"), root / "external-freeze", gen.PRODUCTION_FREEZE_ID
            ),
            "must be exactly /output",
        )
        expect_failure(
            "generation CLI provisioning remap",
            lambda: gen.validate_generation_cli_paths(
                Path("/dcrypt"), Path("/output") / gen.PRODUCTION_FREEZE_ID,
                gen.PRODUCTION_FREEZE_ID, provision=root / "provisioning-handoff",
            ),
            "exact read-only mapping /provision",
        )
        expect_failure(
            "verification CLI evidence remap",
            lambda: verify.validate_verification_cli_paths(
                fixture, Path("/dcrypt"), bundle, Path("/provision")
            ),
            "exact sandbox mapping /evidence",
        )
        expect_failure(
            "verification CLI provisioning remap",
            lambda: verify.validate_verification_cli_paths(
                Path("/evidence"), Path("/dcrypt"),
                Path("/evidence/assurance/audit/freezes") / gen.PRODUCTION_FREEZE_ID,
                root / "provisioning-handoff",
            ),
            "exact read-only mapping /provision",
        )
        print("ok - production CLI paths are fixed to the documented sandbox mappings")

        put(fixture, "untracked-input", "must fail\n")
        expect_failure(
            "unclassified worktree input",
            lambda: gen.build_bundle_bytes(fixture, subject),
            "checkout",
        )
        (fixture / "untracked-input").unlink()

        expect_failure(
            "release mode with unresolved blockers",
            lambda: verify._verify_bundle_internal(evidence_repo, fixture, bundle, mode="release", as_of=dt.date(2026, 8, 11)),
            "blockers",
        )
        expect_failure(
            "replay mode without independent evidence",
            lambda: verify._verify_bundle_internal(evidence_repo, fixture, bundle, mode="replay", as_of=dt.date(2026, 8, 11)),
            "blockers",
        )
        expect_failure(
            "public verifier backdating policy",
            lambda: verify.reject_backdated_verification(
                dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=1)
            ),
            "may not backdate",
        )
        original_runtime_check = verify.gen.require_documented_sandbox_runtime
        original_path_check = verify.validate_verification_cli_paths
        original_internal_verify = verify._verify_bundle_internal
        verify.gen.require_documented_sandbox_runtime = lambda **_kwargs: None
        verify.validate_verification_cli_paths = lambda *_args: None
        verify._verify_bundle_internal = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("backdated public verification reached internal replay")
        )
        try:
            expect_failure(
                "public verify_bundle backdate wiring",
                lambda: verify.verify_bundle(
                    Path("/evidence"), Path("/dcrypt"), Path("/evidence/bundle"),
                    provision=Path("/provision"),
                    as_of=dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=1),
                ),
                "may not backdate",
            )
        finally:
            verify.gen.require_documented_sandbox_runtime = original_runtime_check
            verify.validate_verification_cli_paths = original_path_check
            verify._verify_bundle_internal = original_internal_verify
        expect_failure(
            "expired freeze",
            lambda: verify._verify_bundle_documents(bundle, mode="structural", as_of=dt.date(2027, 1, 1)),
            "expired",
        )
        expect_failure(
            "expired effective bound deadline",
            lambda: verify._verify_bundle_documents(bundle, mode="structural", as_of=dt.date(2026, 9, 11)),
            "freeze expired",
        )

        case = copy_bundle(bundle, root, "command-wrapper-drift")
        command_freeze = json.loads((case / "freeze.json").read_text(encoding="utf-8"))
        command_freeze["commands"][12] = (
            "/usr/bin/python3.12 -I -B -S assurance/audit-freeze-selftest.py"
        )
        (case / "freeze.json").write_bytes(gen.canonical_json(command_freeze))
        expect_failure(
            "unsandboxed recorded self-test command",
            lambda: verify._verify_bundle_documents(case),
            "sandbox-internal command inventory",
        )

        case = copy_bundle(bundle, root, "command-status-drift")
        command_freeze = json.loads((case / "freeze.json").read_text(encoding="utf-8"))
        command_freeze["command_expectations"][12]["expected"] = "pass"
        (case / "freeze.json").write_bytes(gen.canonical_json(command_freeze))
        expect_failure(
            "recorded command pass-status promotion",
            lambda: verify._verify_bundle_documents(case),
            "execution-status/expectation",
        )

        case = copy_bundle(bundle, root, "duplicate-json-key")
        (case / "freeze.json").write_bytes(b'{"schema_version":1,"schema_version":1}\n')
        expect_failure("duplicate JSON key", lambda: verify._verify_bundle_documents(case), "duplicate")
        expect_failure(
            "normalization-colliding JSON object keys",
            lambda: gen.canonical_json({"é": 1, "e\u0301": 2}),
            "object key is not NFC-normalized",
        )

        case = copy_bundle(bundle, root, "noncanonical-json")
        (case / "freeze.json").write_bytes(b" " + (case / "freeze.json").read_bytes())
        expect_failure("noncanonical JSON", lambda: verify._verify_bundle_documents(case), "canonical")

        case = copy_bundle(bundle, root, "missing-file")
        (case / "environment.json").unlink()
        expect_failure("missing manifest", lambda: verify._verify_bundle_documents(case), "file set")

        case = copy_bundle(bundle, root, "unexpected-file")
        (case / "external.tar").write_bytes(b"untrusted")
        expect_failure("unexpected externally sourced input", lambda: verify._verify_bundle_documents(case), "unexpected")

        case = copy_bundle(bundle, root, "symlink")
        (case / "environment.json").unlink()
        (case / "environment.json").symlink_to("freeze.json")
        expect_failure("symlinked input", lambda: verify._verify_bundle_documents(case), "non-regular")

        real_parent = root / "real-bundle-parent"
        real_parent.mkdir()
        parent_case = copy_bundle(bundle, real_parent, "bundle")
        (root / "symlinked-bundle-parent").symlink_to(real_parent, target_is_directory=True)
        expect_failure(
            "symlinked bundle parent",
            lambda: verify._verify_bundle_documents(root / "symlinked-bundle-parent" / parent_case.name),
            "symlinked path component",
        )

        real_output_parent = root / "real-output-parent"
        real_output_parent.mkdir()
        (root / "symlinked-output-parent").symlink_to(real_output_parent, target_is_directory=True)
        expect_failure(
            "symlinked output parent",
            lambda: gen.write_bundle(root / "symlinked-output-parent" / "freeze", first),
            "cannot safely write exact output directory",
        )

        parent_swap = root / "parent-swap-output"
        parent_swap.mkdir()
        parent_substitute = root / "parent-swap-substitute"
        parent_substitute.mkdir()
        put(parent_substitute, "sentinel", "attacker-owned-must-remain\n")
        displaced_parent = root / "parent-swap-displaced"
        original_mkdir = gen.os.mkdir
        parent_swapped = False

        def inject_parent_swap(path, mode=0o777, *, dir_fd=None):
            nonlocal parent_swapped
            result = original_mkdir(path, mode, dir_fd=dir_fd)
            if not parent_swapped and dir_fd is not None and str(path).startswith(".freeze."):
                parent_swapped = True
                parent_swap.rename(displaced_parent)
                parent_substitute.rename(parent_swap)
            return result

        gen.os.mkdir = inject_parent_swap
        try:
            expect_failure(
                "output parent identity swap",
                lambda: gen.write_bundle(parent_swap / "freeze", first),
                "parent path changed",
            )
        finally:
            gen.os.mkdir = original_mkdir
        assert (parent_swap / "sentinel").read_text() == "attacker-owned-must-remain\n"

        outside_output = root / "outside-output-race"
        outside_output.write_bytes(b"outside-must-not-change\n")
        raced_output = root / "raced-output"
        original_open = gen.os.open
        injected_symlink = False

        def inject_output_symlink(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal injected_symlink
            if (
                not injected_symlink
                and path == sorted(gen.ALLOWED_BUNDLE_FILES)[0]
                and dir_fd is not None
            ):
                injected_symlink = True
                os.symlink(
                    outside_output,
                    sorted(gen.ALLOWED_BUNDLE_FILES)[-1],
                    dir_fd=dir_fd,
                )
            return original_open(path, flags, mode, dir_fd=dir_fd)

        gen.os.open = inject_output_symlink
        try:
            expect_failure(
                "temporary output symlink injection",
                lambda: gen.write_bundle(raced_output, first),
                "exclusively create",
            )
        finally:
            gen.os.open = original_open
        assert outside_output.read_bytes() == b"outside-must-not-change\n"

        post_inventory_output = root / "post-inventory-output"
        original_fchmod = gen.os.fchmod
        injected_extra_output = False

        def inject_after_inventory(descriptor: int, mode: int) -> None:
            nonlocal injected_extra_output
            status = os.fstat(descriptor)
            if not injected_extra_output and stat.S_ISDIR(status.st_mode) and mode == 0o555:
                injected_extra_output = True
                extra = original_open(
                    "unexpected-external",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=descriptor,
                )
                os.close(extra)
            original_fchmod(descriptor, mode)

        gen.os.fchmod = inject_after_inventory
        try:
            expect_failure(
                "post-inventory output injection",
                lambda: gen.write_bundle(post_inventory_output, first),
                "inventory differs",
            )
        finally:
            gen.os.fchmod = original_fchmod

        post_read_output = root / "post-read-output"
        original_output_read = gen.os.read
        output_read_calls = 0
        changed_after_read = False

        def inject_after_first_file_read(descriptor: int, size: int) -> bytes:
            nonlocal output_read_calls, changed_after_read
            output_read_calls += 1
            if output_read_calls == 3 and not changed_after_read:
                changed_after_read = True
                staging = next(root.glob(".post-read-output.*"))
                first_name = sorted(gen.ALLOWED_BUNDLE_FILES)[0]
                target = staging / first_name
                payload = bytearray(target.read_bytes())
                payload[0] ^= 1
                target.write_bytes(payload)
            return original_output_read(descriptor, size)

        gen.os.read = inject_after_first_file_read
        try:
            expect_failure(
                "already-read output mutation",
                lambda: gen.write_bundle(post_read_output, first),
                "changed during complete",
            )
        finally:
            gen.os.read = original_output_read
        expect_failure(
            "parent-traversing bundle path",
            lambda: verify._verify_bundle_documents(root / ".." / root.name / "bundle"),
            "parent traversal",
        )

        hardlinked_bundle = copy_bundle(bundle, root, "hardlinked-bundle-entry")
        hardlink_alias = root / "hardlinked-bundle-alias"
        os.link(hardlinked_bundle / "freeze.json", hardlink_alias)
        expect_failure(
            "hardlinked bundle entry",
            lambda: verify._verify_bundle_documents(hardlinked_bundle),
            "hardlinked bundle entry",
        )

        changing_bundle = copy_bundle(bundle, root, "changing-bundle-inventory")
        original_read = verify.os.read
        injected_bundle_entry = False

        def inject_bundle_entry(descriptor: int, size: int) -> bytes:
            nonlocal injected_bundle_entry
            if not injected_bundle_entry:
                injected_bundle_entry = True
                put(changing_bundle, "unexpected-external", "forbidden\n")
            return original_read(descriptor, size)

        verify.os.read = inject_bundle_entry
        try:
            expect_failure(
                "bundle file-set change during descriptor reads",
                lambda: verify._verify_bundle_documents(changing_bundle),
                "file set changed",
            )
        finally:
            verify.os.read = original_read

        swapped_bundle = copy_bundle(bundle, root, "swapped-bundle-entry")
        swapped_outside = root / "swapped-bundle-outside"
        swapped_outside.write_bytes(b"external\n")
        original_verify_open = verify.os.open
        injected_swap = False

        def inject_bundle_symlink(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal injected_swap
            if (
                not injected_swap
                and path == sorted(gen.ALLOWED_BUNDLE_FILES)[0]
                and dir_fd is not None
            ):
                injected_swap = True
                victim = swapped_bundle / sorted(gen.ALLOWED_BUNDLE_FILES)[-1]
                victim.unlink()
                victim.symlink_to(swapped_outside)
            return original_verify_open(path, flags, mode, dir_fd=dir_fd)

        verify.os.open = inject_bundle_symlink
        try:
            expect_failure(
                "bundle symlink identity swap during descriptor reads",
                lambda: verify._verify_bundle_documents(swapped_bundle),
                "safely open bundle entry",
            )
        finally:
            verify.os.open = original_verify_open

        case = copy_bundle(bundle, root, "digest-drift")
        (case / "artifact-manifest.json").write_bytes((case / "artifact-manifest.json").read_bytes().replace(b'"blocked"', b'"pass"', 1))
        expect_failure("bound artifact mutation", lambda: verify._verify_bundle_documents(case), "SHA256SUMS")

        case = copy_bundle(bundle, root, "freeze-omission")
        freeze = json.loads((case / "freeze.json").read_text())
        freeze["manifest_files"].pop()
        (case / "freeze.json").write_bytes(gen.canonical_json(freeze))
        envelope = json.loads((case / "freeze-envelope.json").read_text())
        envelope["freeze_json_sha256"] = gen.sha256((case / "freeze.json").read_bytes())
        (case / "freeze-envelope.json").write_bytes(gen.canonical_json(envelope))
        rewrite_checksums(case)
        expect_failure("freeze.json subordinate omission", lambda: verify._verify_bundle_documents(case), "every subordinate")

        case = copy_bundle(bundle, root, "checksum-self-reference")
        with (case / "SHA256SUMS").open("a", encoding="ascii") as stream:
            stream.write(f"{'0' * 64}  SHA256SUMS\n")
        expect_failure("SHA256SUMS self-reference", lambda: verify._verify_bundle_documents(case), "itself")

        case = copy_bundle(bundle, root, "checksum-omission")
        lines = [line for line in (case / "SHA256SUMS").read_text().splitlines() if not line.endswith("  freeze.json")]
        (case / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        expect_failure("SHA256SUMS freeze omission", lambda: verify._verify_bundle_documents(case), "exactly")

        case = copy_bundle(bundle, root, "envelope-freeze-drift")
        envelope = json.loads((case / "freeze-envelope.json").read_text())
        envelope["freeze_json_sha256"] = "0" * 64
        (case / "freeze-envelope.json").write_bytes(gen.canonical_json(envelope))
        rewrite_checksums(case)
        expect_failure("envelope freeze digest drift", lambda: verify._verify_bundle_documents(case), "bind freeze")

        case = copy_bundle(bundle, root, "envelope-sow-drift")
        envelope = json.loads((case / "freeze-envelope.json").read_text())
        envelope["sow_sha256"] = "0" * 64
        (case / "freeze-envelope.json").write_bytes(gen.canonical_json(envelope))
        rewrite_checksums(case)
        expect_failure("envelope SOW digest drift", lambda: verify._verify_bundle_documents(case), "SOW")

        def subject_failure(name: str, mutation: Callable[[Path], None], expected: str) -> None:
            repo, commit = mutate_subject(root, fixture, name, mutation)
            cargo_semantic_names = {
                "unclassified Cargo root",
                "registry checksum omission",
                "unapproved Git dependency source",
                "bench workspace member injection",
                "nested published-member workspace",
                "root resolver weakening",
                "isolated workspace exclude injection",
                "isolated package workspace redirection",
                "published crate private-registry publish list",
                "non-published workspace promotion",
                "manifest package identity swap",
                "path dependency repository escape",
                "manifest Git dependency",
                "phantom external manifest dependency",
                "excluded cross-workspace path dependency absent from root lock",
                "undeclared direct lock edge",
                "ordinary semver requirement mismatch",
                "workspace-inherited semver requirement mismatch",
                "transitive source-less manifest-lock edge deletion",
                "dev-dependency semver mismatch",
                "build-dependency semver mismatch",
                "target-specific dependency semver mismatch",
                "duplicate locked dependency edge",
                "locked dependency cycle",
                "source-less lock checksum injection",
                "orphan locked package",
                "Cargo patch source reshaping",
                "tracked Cargo source configuration",
                "source-less lock package wrong version",
                "optional manifest dependency edge deletion",
                "duplicate resolved dependency identity",
                "registry reverse dependency on local package",
            }
            try:
                try:
                    if name.startswith("missing required lock ") or name in cargo_semantic_names:
                        checked_repo = gen.repository_root(repo)
                        checked_subject, _tree = gen.validate_exact_subject(checked_repo, commit)
                        _entries, files, all_paths = gen.subject_files(checked_repo, checked_subject)
                        policy = gen.parse_toml(files, "assurance/audit/freeze-policy.toml")
                        provisioning = gen.parse_toml(files, "assurance/audit/provisioning-lock.toml")
                        gen.validate_policy(policy)
                        gen.validate_provisioning(provisioning)
                        rebaseline_path = {
                            "duplicate resolved dependency identity": "Cargo.lock",
                            "registry reverse dependency on local package": "verification/Cargo.lock",
                        }.get(name)
                        previous_digest = None
                        if rebaseline_path is not None:
                            previous_digest = gen.EXPECTED_CARGO_INPUT_SHA256[rebaseline_path]
                            gen.EXPECTED_CARGO_INPUT_SHA256[rebaseline_path] = gen.sha256(
                                files[rebaseline_path]
                            )
                        try:
                            gen.workspace_document(files, all_paths, policy, provisioning)
                        finally:
                            if rebaseline_path is not None and previous_digest is not None:
                                gen.EXPECTED_CARGO_INPUT_SHA256[rebaseline_path] = previous_digest
                    else:
                        gen.build_bundle_bytes(repo, commit)
                except gen.FreezeError as exc:
                    message = str(exc).lower()
                    semantic_cargo = name.startswith("missing required lock ") or name in cargo_semantic_names
                    if expected.lower() not in message and (
                        semantic_cargo or "versioned control digest differs" not in message
                    ):
                        raise AssertionError(f"{name}: wrong failure: {exc}") from exc
                    print(f"ok - rejects {name}")
                else:
                    raise AssertionError(f"{name}: unexpectedly passed")
            finally:
                # The historical-release fixture contains a large complete Git
                # object graph.  Retaining every mutation clone can exhaust the
                # bounded /tmp tmpfs and contaminate later link-count checks.
                shutil.rmtree(repo, ignore_errors=True)

        subject_failure(
            "unclassified Cargo root",
            lambda repo: put(repo, "extra/Cargo.toml", "[workspace]\nmembers = []\n"),
            "Cargo.toml inventory drift",
        )
        for required_lock in (
            "Cargo.lock", "verification/Cargo.lock", "fuzz/Cargo.lock",
            "migration/legacy-xchacha20poly1305/Cargo.lock",
        ):
            subject_failure(
                f"missing required lock {required_lock}",
                lambda repo, path=required_lock: (repo / path).unlink(),
                "Cargo.lock inventory drift",
            )
        subject_failure(
            "unpinned action ref",
            lambda repo: put(
                repo,
                ".github/workflows/security-validation.yml",
                (repo / ".github/workflows/security-validation.yml").read_text().replace("3d3c42e5aac5ba805825da76410c181273ba90b1", "v4", 1),
            ),
            "full commit",
        )
        subject_failure(
            "runner identity drift",
            lambda repo: put(
                repo,
                ".github/workflows/security-validation.yml",
                (repo / ".github/workflows/security-validation.yml").read_text().replace("ubuntu-24.04", "windows-2025"),
            ),
            "runner",
        )
        subject_failure(
            "registry checksum omission",
            lambda repo: put(
                repo,
                "Cargo.lock",
                re.sub(
                    r'^checksum = "[0-9a-f]{64}"\n',
                    "",
                    (repo / "Cargo.lock").read_text(),
                    count=1,
                    flags=re.MULTILINE,
                ),
            ),
            "checksum",
        )
        subject_failure(
            "unapproved Git dependency source",
            lambda repo: put(
                repo,
                "Cargo.lock",
                (repo / "Cargo.lock").read_text().replace(
                    "registry+https://github.com/rust-lang/crates.io-index", "git+https://example.invalid/repo#deadbeef"
                ),
            ),
            "unapproved dependency source",
        )
        subject_failure(
            "stale assurance count",
            lambda repo: put(
                repo,
                "assurance/audit/freeze-policy.toml",
                (repo / "assurance/audit/freeze-policy.toml").read_text().replace("expected-public-api-units = 19021", "expected-public-api-units = 19020"),
            ),
            "expected-public-api-units",
        )
        subject_failure(
            "historical release subject drift",
            lambda repo: put(
                repo,
                "assurance/audit/freeze-policy.toml",
                (repo / "assurance/audit/freeze-policy.toml").read_text().replace(
                    "2ad99cae96efef1636cf5b75e40d5b1d3135b34d", "0ad99cae96efef1636cf5b75e40d5b1d3135b34d"
                ),
            ),
            "release-subject",
        )
        subject_failure(
            "canonicalization policy weakening",
            lambda repo: put(
                repo,
                "assurance/audit/freeze-policy.toml",
                (repo / "assurance/audit/freeze-policy.toml").read_text().replace("final-newline = true", "final-newline = false"),
            ),
            "canonical JSON policy",
        )
        subject_failure(
            "network policy weakening",
            lambda repo: put(
                repo,
                "assurance/audit/freeze-policy.toml",
                (repo / "assurance/audit/freeze-policy.toml").read_text().replace(
                    'network-during-generation = "forbidden"', 'network-during-generation = "allowed"'
                ),
            ),
            "environment/no-network",
        )
        subject_failure(
            "bench workspace reclassification",
            lambda repo: put(
                repo,
                "assurance/audit/freeze-policy.toml",
                (repo / "assurance/audit/freeze-policy.toml").read_text().replace(
                    'status = "blocked"\nlimitation = "bench-processor-unclassified-lock"',
                    'status = "classified"\nlimitation = "bench-processor-unclassified-lock"',
                ),
            ),
            "workspace classifications",
        )
        subject_failure(
            "required artifact deletion",
            lambda repo: put(
                repo,
                "assurance/audit/freeze-policy.toml",
                re.sub(
                    r'\n\[\[required-artifact\]\]\nid = "sbom-production"\nclass = "sbom"\nstatus = "blocked"\nlimitation = "audit-sbom-unavailable"\n',
                    "\n",
                    (repo / "assurance/audit/freeze-policy.toml").read_text(),
                    count=1,
                ),
            ),
            "artifact inventory drift",
        )
        subject_failure(
            "required limitation deletion",
            lambda repo: put(
                repo,
                "assurance/audit/freeze-policy.toml",
                re.sub(
                    r'\n\[\[limitation\]\]\nid = "native-runtime-evidence-unavailable"[\s\S]*?reason = "Cross-compilation is not native AArch64, macOS, or Windows runtime evidence\."\n',
                    "\n",
                    (repo / "assurance/audit/freeze-policy.toml").read_text(),
                    count=1,
                ),
            ),
            "limitation inventory drift",
        )
        subject_failure(
            "missing blocker ownership",
            lambda repo: put(
                repo,
                "assurance/audit/freeze-policy.toml",
                (repo / "assurance/audit/freeze-policy.toml").read_text().replace('owner = "dcrypt release engineering"', 'owner = ""', 1),
            ),
            "owner",
        )
        subject_failure(
            "promoted unavailable artifact",
            lambda repo: put(
                repo,
                "assurance/audit/freeze-policy.toml",
                (repo / "assurance/audit/freeze-policy.toml").read_text().replace('status = "blocked"\nlimitation = "audit-sbom-unavailable"', 'status = "pass"\nlimitation = "audit-sbom-unavailable"', 1),
            ),
            "must map",
        )
        subject_failure(
            "SOW digest fixed-point placeholder",
            lambda repo: put(repo, "assurance/audit/sow/RFP-SOW.md", "freeze-manifest-sha = PENDING\n"),
            "PENDING",
        )
        subject_failure(
            "provisioned action identity drift",
            lambda repo: put(
                repo,
                "assurance/audit/provisioning-lock.toml",
                (repo / "assurance/audit/provisioning-lock.toml").read_text().replace(
                    "3d3c42e5aac5ba805825da76410c181273ba90b1", "0d3c42e5aac5ba805825da76410c181273ba90b1"
                ),
            ),
            "Action provisioning identity drift",
        )
        subject_failure(
            "provisioned compiler identity drift",
            lambda repo: put(
                repo,
                "assurance/audit/provisioning-lock.toml",
                (repo / "assurance/audit/provisioning-lock.toml").read_text().replace(
                    "1a98b1e135b254f209c67d447b6d8bcd56a859e0", "0a98b1e135b254f209c67d447b6d8bcd56a859e0", 1
                ),
            ),
            "compiler identity drift",
        )
        provisioning_base = tomllib.loads(fixture_provisioning())
        provisioning_schema = json.loads(
            (HERE / "audit" / "provisioning.schema.json").read_text(encoding="utf-8")
        )

        def direct_provisioning_failure(
            label: str, family: str, offset: int, field: str, value: object, expected: str
        ) -> None:
            mutated = copy.deepcopy(provisioning_base)
            mutated[family][offset][field] = value

            def check() -> None:
                gen.validate_provisioning(mutated)
                gen.validate_json_schema(
                    gen.toml_json_value(mutated), provisioning_schema,
                    label="direct mutated provisioning",
                )

            expect_failure(label, check, expected)

        direct_provisioning_failure(
            "direct acquisition-tool ID remap", "acquisition-tool", 0, "id", "renamed",
            "acquisition-tool",
        )
        direct_provisioning_failure(
            "direct toolchain ID remap", "toolchain", 0, "id", "renamed", "toolchain row-by-row",
        )
        direct_provisioning_failure(
            "direct action ID remap", "github-action", 0, "id", "renamed", "Action row-by-row",
        )
        direct_provisioning_failure(
            "direct host-tool limitation drift", "host-tool", 0, "limitation",
            "sandbox-kernel-assumptions-unbound", "host-tool inventory",
        )
        direct_provisioning_failure(
            "direct security-tool availability drift", "security-tool", 0, "availability",
            "blocked", "security-tool row-by-row",
        )
        direct_provisioning_failure(
            "direct security-tool limitation drift", "security-tool", 0, "limitation",
            "toolchain-distribution-bundle-unavailable", "security-tool row-by-row",
        )
        direct_provisioning_failure(
            "direct advisory status drift", "advisory-database", 0, "availability",
            "locally-observed-unprovisioned", "advisory-database row-by-row",
        )
        direct_provisioning_failure(
            "direct runner limitation drift", "runner-image", 0, "limitation",
            "container-image-unavailable", "runner-image row-by-row",
        )
        direct_provisioning_failure(
            "direct container status drift", "container-image", 0, "availability",
            "mutable-label-only", "container-image row-by-row",
        )
        subject_failure(
            "unexpected freeze policy input",
            lambda repo: put(
                repo,
                "assurance/audit/freeze-policy.toml",
                (repo / "assurance/audit/freeze-policy.toml").read_text().replace(
                    "schema-version = 1\n", 'schema-version = 1\nunreviewed-input = "forbidden"\n', 1
                ),
            ),
            "unexpected top-level",
        )
        subject_failure(
            "historical regression inventory drift",
            lambda repo: put(
                repo,
                "assurance/audit/historical-advisory-regressions.toml",
                (repo / "assurance/audit/historical-advisory-regressions.toml").read_text().replace(
                    'id = "DCRYPT-2026-0011"', 'id = "DCRYPT-2026-0012"'
                ),
            ),
            "exact IDs",
        )
        subject_failure(
            "missing machine-readable threat model",
            lambda repo: (repo / "assurance/threat-models/threat-models.toml").unlink(),
            "threat-model",
        )
        for label, command_target in (
            ("missing threat-model verifier command target", "assurance/threat-models/verify-threat-models.py"),
            ("missing threat-model selftest command target", "assurance/threat-models/threat-model-selftest.py"),
            ("missing SOW selftest command target", "assurance/audit/sow/selftest.py"),
        ):
            subject_failure(
                label,
                lambda repo, path=command_target: (repo / path).unlink(),
                "required assurance/audit input",
            )

        def add_self_reference(repo: Path) -> None:
            put(repo, "assurance/audit/freezes/dcrypt-v3.0.0-audit-candidate-001/freeze.json", "{}\n")

        subject_failure("subject self-reference", add_self_reference, "own freeze output")
        subject_failure(
            "subject exact freeze-root blob",
            lambda repo: put(repo, f"assurance/audit/freezes/{gen.PRODUCTION_FREEZE_ID}", "forbidden\n"),
            "own freeze output",
        )

        def add_symlink(repo: Path) -> None:
            os.symlink("src/lib.rs", repo / "linked-input")

        subject_failure("symlinked subject input", add_symlink, "symlink")
        subject_failure(
            "tracked Git attributes",
            lambda repo: put(repo, ".gitattributes", "*.py ident eol=crlf\n"),
            "tracked .gitattributes",
        )

        # The bound schemas are executable closed contracts, not documentation-only files.
        freeze_instance = json.loads(first["freeze.json"])
        freeze_schema = json.loads((HERE / "audit/audit-freeze.schema.json").read_text())
        nested_missing = json.loads(json.dumps(freeze_instance))
        del nested_missing["release_gate"]["independent_replay_required"]
        expect_failure(
            "schema nested required field deletion",
            lambda: gen.validate_json_schema(nested_missing, freeze_schema, label="freeze fixture"),
            "required",
        )
        expect_failure(
            "schema boolean/integer const confusion",
            lambda: gen.validate_json_schema(True, {"const": 1}, label="type-sensitive const"),
            "const",
        )
        gen.validate_json_schema(freeze_instance, freeze_schema, label="generated freeze fixture")
        provisioning_instance = tomllib.loads((HERE / "audit/provisioning-lock.toml").read_text())
        provisioning_schema = json.loads((HERE / "audit/provisioning.schema.json").read_text())
        broken_provisioning = json.loads(json.dumps(provisioning_instance))
        del broken_provisioning["host-tool"][0]["path"]
        expect_failure(
            "provisioning schema nested required field deletion",
            lambda: gen.validate_json_schema(broken_provisioning, provisioning_schema, label="provisioning fixture"),
            "required",
        )

        subject_failure(
            "schema weakening",
            lambda repo: put(
                repo,
                "assurance/audit/audit-freeze.schema.json",
                (repo / "assurance/audit/audit-freeze.schema.json").read_text().replace(
                    '"classification": {"const": "candidate-rehearsal"}',
                    '"classification": {"type": "string"}',
                ),
            ),
            "versioned control digest",
        )
        subject_failure(
            "workflow whitespace and nested uses spoof",
            lambda repo: put(
                repo,
                ".github/workflows/security-validation.yml",
                (repo / ".github/workflows/security-validation.yml").read_text().replace(
                    "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                    "        uses : actions/checkout@main\n        with:\n          uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                    1,
                ),
            ),
            "versioned control digest",
        )
        subject_failure(
            "historical regression command substitution",
            lambda repo: put(
                repo,
                "assurance/audit/historical-advisory-regressions.toml",
                (repo / "assurance/audit/historical-advisory-regressions.toml").read_text().replace(
                    "cargo test --locked -p dcrypt-api --lib error::registry", "true", 1
                ),
            ),
            "versioned control digest",
        )
        subject_failure(
            "provisioning row identifier remap",
            lambda repo: put(
                repo,
                "assurance/audit/provisioning-lock.toml",
                (repo / "assurance/audit/provisioning-lock.toml").read_text().replace(
                    'id = "actions-checkout"', 'id = "renamed-checkout"', 1
                ),
            ),
            "versioned control digest",
        )
        subject_failure(
            "expired ledger evidence",
            lambda repo: put(
                repo,
                "assurance/ledger.toml",
                (repo / "assurance/ledger.toml").read_text().replace(
                    "valid-through = 2026-11-09", "valid-through = 2026-08-10", 1
                ),
            ),
            "expires before",
        )
        subject_failure(
            "future threat-model review date",
            lambda repo: put(
                repo,
                "assurance/threat-models/threat-models.toml",
                (repo / "assurance/threat-models/threat-models.toml").read_text().replace(
                    "reviewed-at = 2026-08-11", "reviewed-at = 2026-08-12", 1
                ),
            ),
            "after the freeze date",
        )
        subject_failure(
            "expired threat-model evidence",
            lambda repo: put(
                repo,
                "assurance/threat-models/threat-models.toml",
                (repo / "assurance/threat-models/threat-models.toml").read_text().replace(
                    "valid-through = 2026-11-09", "valid-through = 2026-08-10", 1
                ),
            ),
            "expires before",
        )
        subject_failure(
            "SOW authorization promotion",
            lambda repo: put(
                repo,
                "assurance/audit/sow/audit-policy.toml",
                (repo / "assurance/audit/sow/audit-policy.toml").read_text().replace(
                    "external-contact-authorized = false", "external-contact-authorized = true", 1
                ),
            ),
            "SOW issuance",
        )
        subject_failure(
            "bench workspace member injection",
            lambda repo: put(
                repo,
                "tools/bench-processor/Cargo.toml",
                (repo / "tools/bench-processor/Cargo.toml").read_text().replace(
                    "[workspace]\n", '[workspace]\nmembers = ["../../crates/api"]\n', 1
                ),
            ),
            "explicit empty",
        )
        subject_failure(
            "nested published-member workspace",
            lambda repo: put(
                repo,
                "crates/api/Cargo.toml",
                (repo / "crates/api/Cargo.toml").read_text() + "\n[workspace]\nresolver = \"2\"\n",
            ),
            "nested workspace",
        )
        subject_failure(
            "root resolver weakening",
            lambda repo: put(
                repo,
                "Cargo.toml",
                (repo / "Cargo.toml").read_text().replace('resolver = "2"', 'resolver = "1"', 1),
            ),
            "resolver/default-members",
        )
        subject_failure(
            "isolated workspace exclude injection",
            lambda repo: put(
                repo,
                "verification/Cargo.toml",
                (repo / "verification/Cargo.toml").read_text().replace(
                    'resolver = "2"', 'resolver = "2"\nexclude = ["../crates/api"]', 1
                ),
            ),
            "no excludes/default-members",
        )
        subject_failure(
            "isolated package workspace redirection",
            lambda repo: put(
                repo,
                "fuzz/Cargo.toml",
                (repo / "fuzz/Cargo.toml").read_text().replace(
                    "[package]\n", '[package]\nworkspace = ".."\n', 1
                ),
            ),
            "redirect workspace ownership",
        )
        subject_failure(
            "published crate private-registry publish list",
            lambda repo: put(
                repo,
                "crates/api/Cargo.toml",
                (repo / "crates/api/Cargo.toml").read_text().replace(
                    "publish = true", 'publish = ["private"]', 1
                ),
            ),
            "raw publish policy",
        )
        subject_failure(
            "non-published workspace promotion",
            lambda repo: put(
                repo,
                "verification/Cargo.toml",
                (repo / "verification/Cargo.toml").read_text().replace("publish = false", "publish = true"),
            ),
            "raw publish policy",
        )
        subject_failure(
            "manifest package identity swap",
            lambda repo: (
                put(repo, "crates/api/Cargo.toml", (repo / "crates/api/Cargo.toml").read_text().replace('name = "dcrypt-api"', 'name = "dcrypt-common"')),
                put(repo, "crates/common/Cargo.toml", (repo / "crates/common/Cargo.toml").read_text().replace('name = "dcrypt-common"', 'name = "dcrypt-api"')),
            ),
            "manifest path/package",
        )
        subject_failure(
            "path dependency repository escape",
            lambda repo: put(
                repo,
                "tools/bench-processor/Cargo.toml",
                (repo / "tools/bench-processor/Cargo.toml").read_text().replace(
                    "[dependencies]\n", '[dependencies]\nevil = { path = "../../../outside", version = "=1.0.0" }\n', 1
                ),
            ),
            "escapes repository",
        )
        subject_failure(
            "manifest Git dependency",
            lambda repo: put(
                repo,
                "tools/bench-processor/Cargo.toml",
                (repo / "tools/bench-processor/Cargo.toml").read_text().replace(
                    "[dependencies]\n", '[dependencies]\nevil = { git = "https://example.invalid/x" }\n', 1
                ),
            ),
            "Git/registry source",
        )
        subject_failure(
            "phantom external manifest dependency",
            lambda repo: put(
                repo,
                "Cargo.toml",
                (repo / "Cargo.toml").read_text().replace(
                    "[dependencies]\n", '[dependencies]\nphantom = "=9.9.9"\n', 1
                ),
            ),
            "manifest dependency edge",
        )
        subject_failure(
            "excluded cross-workspace path dependency absent from root lock",
            lambda repo: put(
                repo,
                "tests/Cargo.toml",
                (repo / "tests/Cargo.toml").read_text().replace(
                    "[dev-dependencies]\n",
                    '[dev-dependencies]\ndcrypt-fuzz = { path = "../fuzz", version = "=0.0.0" }\n',
                    1,
                ),
            ),
            "manifest dependency edge",
        )
        subject_failure(
            "undeclared direct lock edge",
            lambda repo: put(
                repo,
                "Cargo.lock",
                (repo / "Cargo.lock").read_text().replace(
                    'name = "dcrypt"\nversion = "3.0.0"\ndependencies = [\n',
                    'name = "dcrypt"\nversion = "3.0.0"\ndependencies = [\n "serde",\n',
                    1,
                ),
            ),
            "exactly match declared",
        )
        subject_failure(
            "optional manifest dependency edge deletion",
            lambda repo: put(
                repo,
                "Cargo.lock",
                (repo / "Cargo.lock").read_text().replace(
                    'name = "dcrypt"\nversion = "3.0.0"\ndependencies = [\n "dcrypt-algorithms",\n',
                    'name = "dcrypt"\nversion = "3.0.0"\ndependencies = [\n',
                    1,
                ),
            ),
            "manifest dependency edge",
        )
        subject_failure(
            "ordinary semver requirement mismatch",
            lambda repo: put(
                repo,
                "tests/Cargo.toml",
                (repo / "tests/Cargo.toml").read_text().replace(
                    'serde = { version = "1", features = ["derive"] }',
                    'serde = { version = "99", features = ["derive"] }',
                    1,
                ),
            ),
            "manifest dependency edge",
        )
        subject_failure(
            "workspace-inherited semver requirement mismatch",
            lambda repo: put(
                repo,
                "Cargo.toml",
                (repo / "Cargo.toml").read_text().replace(
                    'rand        = { version = "0.8.6", default-features = false }',
                    'rand        = { version = "99", default-features = false }',
                    1,
                ),
            ),
            "manifest dependency edge",
        )
        subject_failure(
            "transitive source-less manifest-lock edge deletion",
            lambda repo: put(
                repo,
                "verification/Cargo.lock",
                (repo / "verification/Cargo.lock").read_text().replace(
                    'name = "dcrypt-common"\nversion = "3.0.0"\ndependencies = [\n "dcrypt-api",\n',
                    'name = "dcrypt-common"\nversion = "3.0.0"\ndependencies = [\n',
                    1,
                ),
            ),
            "manifest dependency edge",
        )
        subject_failure(
            "dev-dependency semver mismatch",
            lambda repo: put(
                repo,
                "tests/Cargo.toml",
                (repo / "tests/Cargo.toml").read_text().replace(
                    'proptest = "1"', 'proptest = "99"', 1
                ),
            ),
            "manifest dependency edge",
        )
        subject_failure(
            "build-dependency semver mismatch",
            lambda repo: put(
                repo,
                "tests/Cargo.toml",
                (repo / "tests/Cargo.toml").read_text().replace(
                    '[build-dependencies]\nserde = { version = "1", features = ["derive"] }',
                    '[build-dependencies]\nserde = { version = "99", features = ["derive"] }',
                    1,
                ),
            ),
            "manifest dependency edge",
        )
        subject_failure(
            "target-specific dependency semver mismatch",
            lambda repo: put(
                repo,
                "tests/Cargo.toml",
                (repo / "tests/Cargo.toml").read_text()
                + '\n[target.\'cfg(unix)\'.dependencies]\nserde = { version = "99" }\n',
            ),
            "manifest dependency edge",
        )
        subject_failure(
            "duplicate locked dependency edge",
            lambda repo: put(
                repo,
                "Cargo.lock",
                (repo / "Cargo.lock").read_text().replace(
                    'name = "dcrypt"\nversion = "3.0.0"\ndependencies = [\n "dcrypt-algorithms",\n',
                    'name = "dcrypt"\nversion = "3.0.0"\ndependencies = [\n "dcrypt-algorithms",\n "dcrypt-algorithms",\n',
                    1,
                ),
            ),
            "duplicate locked dependency edge",
        )
        subject_failure(
            "duplicate resolved dependency identity",
            lambda repo: put(
                repo,
                "Cargo.lock",
                (repo / "Cargo.lock").read_text().replace(
                    'name = "dcrypt"\nversion = "3.0.0"\ndependencies = [\n "dcrypt-algorithms",\n',
                    'name = "dcrypt"\nversion = "3.0.0"\ndependencies = [\n "dcrypt-algorithms",\n "dcrypt-algorithms 3.0.0",\n',
                    1,
                ),
            ),
            "same locked dependency identity",
        )
        subject_failure(
            "registry reverse dependency on local package",
            lambda repo: put(
                repo,
                "verification/Cargo.lock",
                (repo / "verification/Cargo.lock").read_text().replace(
                    'name = "glob"\nversion = "0.3.4"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = ',
                    'name = "glob"\nversion = "0.3.4"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\ndependencies = ["dcrypt-api"]\nchecksum = ',
                    1,
                ),
            ),
            "reverse dependency",
        )
        subject_failure(
            "locked dependency cycle",
            lambda repo: put(
                repo,
                "Cargo.lock",
                (repo / "Cargo.lock").read_text().replace(
                    'name = "arrayref"\nversion = "0.3.9"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "76a2e8124351fda1ef8aaaa3bbd7ebbcb486bbcd4225aca0aa0d84bb2db8fecb"',
                    'name = "arrayref"\nversion = "0.3.9"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "76a2e8124351fda1ef8aaaa3bbd7ebbcb486bbcd4225aca0aa0d84bb2db8fecb"\ndependencies = ["arrayref"]',
                    1,
                ),
            ),
            "dependency cycle",
        )
        subject_failure(
            "source-less lock checksum injection",
            lambda repo: put(
                repo,
                "Cargo.lock",
                (repo / "Cargo.lock").read_text().replace(
                    'name = "dcrypt"\nversion = "3.0.0"\n',
                    f'name = "dcrypt"\nversion = "3.0.0"\nchecksum = "{"b" * 64}"\n',
                    1,
                ),
            ),
            "source-less lock row",
        )
        subject_failure(
            "orphan locked package",
            lambda repo: put(
                repo,
                "Cargo.lock",
                (repo / "Cargo.lock").read_text()
                + '\n[[package]]\nname = "orphan-fixture"\nversion = "1.0.0"\n'
                + 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                + f'checksum = "{"a" * 64}"\n',
            ),
            "orphan/unreachable",
        )
        subject_failure(
            "Cargo patch source reshaping",
            lambda repo: put(
                repo,
                "Cargo.toml",
                (repo / "Cargo.toml").read_text() + '\n[patch.crates-io]\nevil = { path = "crates/api" }\n',
            ),
            "[patch]/[replace]",
        )
        subject_failure(
            "tracked Cargo source configuration",
            lambda repo: put(repo, ".cargo/config.toml", '[source.crates-io]\nreplace-with = "evil"\n'),
            "Cargo configuration",
        )
        subject_failure(
            "source-less lock package wrong version",
            lambda repo: put(
                repo,
                "Cargo.lock",
                (repo / "Cargo.lock").read_text().replace(
                    'name = "dcrypt-api"\nversion = "3.0.0"',
                    'name = "dcrypt-api"\nversion = "9.9.9"', 1,
                ),
            ),
            "source-less",
        )
        subject_failure(
            "crate archive order drift",
            lambda repo: put(
                repo,
                "assurance/audit/freeze-policy.toml",
                (repo / "assurance/audit/freeze-policy.toml").read_text().replace(
                    '{ name = "dcrypt-internal", version = "3.0.0", archive = "dcrypt-internal-3.0.0.crate", sha256 = "blocked" },',
                    '{ name = "dcrypt-params", version = "3.0.0", archive = "dcrypt-internal-3.0.0.crate", sha256 = "blocked" },',
                    1,
                ),
            ),
            "twelve-crate member inventory",
        )

        original_git_identity = gen.EXPECTED_HOST_TOOLS["git"]
        original_subprocess_run = gen.subprocess.run
        gen.EXPECTED_HOST_TOOLS["git"] = (
            original_git_identity[0], original_git_identity[1], "0" * 64,
            original_git_identity[3], original_git_identity[4],
        )
        gen.subprocess.run = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unverified Git executable reached subprocess execution")
        )
        try:
            expect_failure(
                "wrong Git digest before first subprocess",
                gen.open_bound_git_executable,
                "Git executable bytes differ",
            )
        finally:
            gen.subprocess.run = original_subprocess_run
            gen.EXPECTED_HOST_TOOLS["git"] = original_git_identity

        # Repository state must not be shapeable by replacement refs, config, or hidden index flags.
        replaced = root / "git-replace"
        shutil.copytree(fixture, replaced)
        replacement = run("git", "commit-tree", "HEAD^{tree}", cwd=replaced, input_data=b"replacement\n").decode().strip()
        run("git", "replace", subject, replacement, cwd=replaced)
        expect_failure("Git replacement ref", lambda: gen.build_bundle_bytes(replaced, subject), "replace refs")

        configured = root / "git-external-diff"
        shutil.copytree(fixture, configured)
        marker = root / "external-diff-ran"
        external = root / "external-diff"
        external.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
        external.chmod(0o755)
        run("git", "config", "diff.external", str(external), cwd=configured)
        expect_failure("Git external diff command config", lambda: gen.build_bundle_bytes(configured, subject), "configuration shaping")
        assert not marker.exists(), "forbidden diff.external command executed"

        fifo_config = root / "git-config-fifo"
        shutil.copytree(fixture, fifo_config)
        (fifo_config / ".git/config").unlink()
        os.mkfifo(fifo_config / ".git/config")
        expect_failure(
            "FIFO Git config before repository-aware Git",
            lambda: gen.repository_root(fifo_config),
            "regular file",
        )

        def expect_pre_git_failure(label: str, repository: Path, expected: str) -> None:
            original_git = gen._git
            gen._git = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("repository-aware Git executed before raw filesystem rejection")
            )
            try:
                expect_failure(label, lambda: gen.repository_root(repository), expected)
            finally:
                gen._git = original_git

        external_commondir = root / "git-external-commondir"
        shutil.copytree(fixture, external_commondir)
        put(external_commondir, ".git/commondir", "../external-common-storage\n")
        expect_pre_git_failure(
            "external Git commondir before repository-aware Git",
            external_commondir,
            "common-dir/worktree indirection",
        )

        fifo_commondir = root / "git-fifo-commondir"
        shutil.copytree(fixture, fifo_commondir)
        os.mkfifo(fifo_commondir / ".git/commondir")
        expect_pre_git_failure(
            "FIFO Git commondir before repository-aware Git",
            fifo_commondir,
            "common-dir/worktree indirection",
        )

        worktree_gitdir = root / "git-worktree-gitdir"
        shutil.copytree(fixture, worktree_gitdir)
        put(worktree_gitdir, ".git/gitdir", "/external/worktree/.git\n")
        expect_pre_git_failure(
            "Git worktree gitdir before repository-aware Git",
            worktree_gitdir,
            "common-dir/worktree indirection",
        )

        fifo_head = root / "git-fifo-head"
        shutil.copytree(fixture, fifo_head)
        (fifo_head / ".git/HEAD").unlink()
        os.mkfifo(fifo_head / ".git/HEAD")
        expect_pre_git_failure(
            "FIFO Git HEAD before repository-aware Git", fifo_head, "regular file"
        )

        oversized_index = root / "git-oversized-index"
        shutil.copytree(fixture, oversized_index)
        with (oversized_index / ".git/index").open("r+b") as stream:
            stream.truncate(256 * 1024 * 1024 + 1)
        expect_pre_git_failure(
            "oversized Git index before repository-aware Git",
            oversized_index,
            "pre-Git byte limit",
        )

        oversized_packed_refs = root / "git-oversized-packed-refs"
        shutil.copytree(fixture, oversized_packed_refs)
        with (oversized_packed_refs / ".git/packed-refs").open("wb") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        expect_pre_git_failure(
            "oversized Git packed-refs before repository-aware Git",
            oversized_packed_refs,
            "pre-Git byte limit",
        )

        hardlinked_head = root / "git-hardlinked-head"
        shutil.copytree(fixture, hardlinked_head)
        os.link(hardlinked_head / ".git/HEAD", hardlinked_head / ".git/HEAD.peer")
        expect_pre_git_failure(
            "hardlinked Git HEAD before repository-aware Git",
            hardlinked_head,
            "hardlinked critical Git storage",
        )
        shutil.rmtree(hardlinked_head)

        include_config = root / "git-config-external-include"
        shutil.copytree(fixture, include_config)
        external_config_fifo = root / "external-config-fifo"
        os.mkfifo(external_config_fifo)
        with (include_config / ".git/config").open("a", encoding="utf-8") as stream:
            stream.write(f"\n[include]\n\tpath = {external_config_fifo}\n")
        expect_failure(
            "external Git config include without opening its target",
            lambda: gen.repository_root(include_config),
            "configuration shaping",
        )

        core_shaping = root / "git-core-autocrlf"
        shutil.copytree(fixture, core_shaping)
        run("git", "config", "core.autocrlf", "true", cwd=core_shaping)
        expect_failure(
            "Git core byte-shaping configuration",
            lambda: gen.build_bundle_bytes(core_shaping, subject),
            "configuration shaping",
        )

        info_attributes = root / "git-info-attributes"
        shutil.copytree(fixture, info_attributes)
        put(info_attributes, ".git/info/attributes", "* ident\n")
        expect_failure(
            "Git info attributes",
            lambda: gen.build_bundle_bytes(info_attributes, subject),
            "Git info state",
        )

        info_symlink = root / "git-info-symlink"
        shutil.copytree(fixture, info_symlink)
        (info_symlink / ".git/info/exclude").unlink()
        (info_symlink / ".git/info/exclude").symlink_to("../config")
        expect_failure(
            "symlinked Git info state",
            lambda: gen.build_bundle_bytes(info_symlink, subject),
            "symlinked Git info",
        )

        special_git_storage = root / "git-object-fifo"
        shutil.copytree(fixture, special_git_storage)
        fifo_parent = special_git_storage / ".git/objects/zz"
        fifo_parent.mkdir()
        os.mkfifo(fifo_parent / "external-input")
        expect_failure(
            "special Git object storage type",
            lambda: gen.build_bundle_bytes(special_git_storage, subject),
            "special type",
        )

        hidden = root / "hidden-index-state"
        shutil.copytree(fixture, hidden)
        run("git", "update-index", "--assume-unchanged", "Cargo.toml", cwd=hidden)
        put(hidden, "Cargo.toml", (hidden / "Cargo.toml").read_text() + "# hidden\n")
        expect_failure("assume-unchanged subject mutation", lambda: gen.build_bundle_bytes(hidden, subject), "index flags")

        skipped = root / "skip-worktree-index-state"
        shutil.copytree(fixture, skipped)
        run("git", "update-index", "--skip-worktree", "Cargo.toml", cwd=skipped)
        expect_failure(
            "skip-worktree subject index state",
            lambda: gen.build_bundle_bytes(skipped, subject),
            "index flags",
        )

        ignored_dirty = root / "ignored-dirty-state"
        shutil.copytree(fixture, ignored_dirty)
        with (ignored_dirty / ".git/info/exclude").open("a", encoding="utf-8") as stream:
            stream.write("\nignored-dirty\n")
        put(ignored_dirty, "ignored-dirty", "must still fail\n")
        expect_failure(
            "ignored dirty worktree state",
            lambda: gen.build_bundle_bytes(ignored_dirty, subject),
            "strictly clean",
        )

        split_index = root / "split-index-state"
        shutil.copytree(fixture, split_index)
        run("git", "update-index", "--split-index", cwd=split_index)
        expect_failure(
            "split/shared Git index",
            lambda: gen.build_bundle_bytes(split_index, subject),
            "split/shared Git indexes",
        )

        semantic_cache = root / "git-semantic-cache"
        shutil.copytree(fixture, semantic_cache)
        for cache_label, relative in (
            ("commit-graph", ".git/objects/info/commit-graph"),
            ("pack bitmap", ".git/objects/pack/fixture.bitmap"),
            ("pack reverse index", ".git/objects/pack/fixture.rev"),
            ("multi-pack index", ".git/objects/pack/multi-pack-index"),
            ("split commit-graph directory", ".git/objects/info/commit-graphs/graph-fixture.graph"),
        ):
            put(semantic_cache, relative, b"unbound-cache")
            expect_failure(
                f"unbound Git semantic cache {cache_label}",
                lambda repo=semantic_cache: gen.build_bundle_bytes(repo, subject),
                "semantic cache",
            )
            (semantic_cache / relative).unlink()
            parent = (semantic_cache / relative).parent
            if parent.name == "commit-graphs":
                parent.rmdir()

        for state_name, relative, expected_message in (
            ("Git graft state", ".git/info/grafts", "graft/shallow/alternate"),
            ("Git object alternate", ".git/objects/info/alternates", "graft/shallow/alternate"),
            ("Git HTTP object alternate", ".git/objects/info/http-alternates", "graft/shallow/alternate"),
            ("Git promisor pack state", ".git/objects/pack/fixture.promisor", "promisor"),
            ("Git shallow state", ".git/shallow", "graft/shallow/alternate"),
        ):
            shaped = root / state_name.lower().replace(" ", "-")
            shutil.copytree(fixture, shaped)
            put(shaped, relative, "forbidden\n")
            expect_failure(
                state_name,
                lambda repo=shaped: gen.build_bundle_bytes(repo, subject),
                expected_message,
            )

        hardlinked_objects = root / "hardlinked-object-storage"
        run("git", "clone", "-q", str(fixture), str(hardlinked_objects), cwd=root)
        expect_failure(
            "hardlinked Git object storage",
            lambda: gen.build_bundle_bytes(hardlinked_objects, subject),
            "hardlinked Git storage",
        )
        # A local hardlink clone increments the source object's link count too;
        # remove the adversarial clone before any subsequent replay uses fixture.
        shutil.rmtree(hardlinked_objects)

        partial_history = root / "partial-history"
        shutil.copytree(fixture, partial_history)
        payloads = {
            "tag": gen._git(HERE.parent, "cat-file", "tag", gen.EXPECTED_RELEASE_SUBJECT["tag-object"]),
            "commit": gen._git(HERE.parent, "cat-file", "commit", gen.EXPECTED_RELEASE_SUBJECT["commit"]),
            "tree": gen._git(HERE.parent, "cat-file", "tree", gen.EXPECTED_RELEASE_SUBJECT["tree"]),
        }
        pack_dir = partial_history / ".git/objects/pack"
        for child in pack_dir.iterdir():
            child.unlink()
        for kind, payload in payloads.items():
            run("git", "hash-object", "-t", kind, "-w", "--stdin", cwd=partial_history, input_data=payload)
        expect_failure(
            "historical release missing descendant objects",
            lambda: gen.build_bundle_bytes(partial_history, subject),
            "missing descendant",
        )

        def oversized_blob(repo: Path) -> None:
            path = repo / "oversized-subject-blob"
            with path.open("wb") as stream:
                stream.truncate(64 * 1024 * 1024 + 1)

        subject_failure("oversized subject blob", oversized_blob, "64 MiB")

        # Evidence commits must be a one-parent, bundle-only delta over the exact subject.
        root_evidence = root / "root-evidence"
        root_evidence.mkdir()
        run("git", "init", "-q", cwd=root_evidence)
        run("git", "config", "user.name", "audit-freeze-selftest", cwd=root_evidence)
        run("git", "config", "user.email", "selftest@example.invalid", cwd=root_evidence)
        root_bundle = root_evidence / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID
        root_bundle.parent.mkdir(parents=True)
        gen.write_bundle(root_bundle, first)
        run("git", "add", "assurance/audit/freezes", cwd=root_evidence)
        run("git", "commit", "-q", "-m", "root evidence", cwd=root_evidence)
        expect_failure(
            "zero-parent evidence commit",
            lambda: verify._verify_bundle_internal(root_evidence, fixture, root_bundle, as_of=dt.date(2026, 8, 11)),
            "exactly one parent",
        )

        preexisting_repo = root / "preexisting-freeze-parent"
        clone_isolated(fixture, preexisting_repo, cwd=root)
        run("git", "config", "user.name", "audit-freeze-selftest", cwd=preexisting_repo)
        run("git", "config", "user.email", "selftest@example.invalid", cwd=preexisting_repo)
        preexisting_bundle = preexisting_repo / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID
        put(preexisting_repo, f"assurance/audit/freezes/{gen.PRODUCTION_FREEZE_ID}/freeze.json", "parent bytes\n")
        run("git", "add", "assurance/audit/freezes", cwd=preexisting_repo)
        run("git", "commit", "-q", "-m", "preexisting prefix", cwd=preexisting_repo)
        (preexisting_bundle / "freeze.json").unlink()
        for name, data in first.items():
            put(preexisting_repo, f"assurance/audit/freezes/{gen.PRODUCTION_FREEZE_ID}/{name}", data)
        run("git", "add", "assurance/audit/freezes", cwd=preexisting_repo)
        run("git", "commit", "-q", "-m", "invalid replacement evidence", cwd=preexisting_repo)
        expect_failure(
            "pre-existing parent freeze prefix",
            lambda: verify._verify_bundle_internal(preexisting_repo, fixture, preexisting_bundle, as_of=dt.date(2026, 8, 11)),
            "already exists in the subject parent",
        )

        wrong_parent_repo = root / "wrong-parent-evidence"
        clone_isolated(fixture, wrong_parent_repo, cwd=root)
        run("git", "config", "user.name", "audit-freeze-selftest", cwd=wrong_parent_repo)
        run("git", "config", "user.email", "selftest@example.invalid", cwd=wrong_parent_repo)
        put(wrong_parent_repo, "later", "later subject\n")
        run("git", "add", "later", cwd=wrong_parent_repo)
        run("git", "commit", "-q", "-m", "later subject", cwd=wrong_parent_repo)
        wrong_bundle = wrong_parent_repo / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID
        wrong_bundle.parent.mkdir(parents=True)
        gen.write_bundle(wrong_bundle, first)
        run("git", "add", "assurance/audit/freezes", cwd=wrong_parent_repo)
        run("git", "commit", "-q", "-m", "wrong parent evidence", cwd=wrong_parent_repo)
        expect_failure(
            "wrong evidence parent",
            lambda: verify._verify_bundle_internal(wrong_parent_repo, fixture, wrong_bundle, as_of=dt.date(2026, 8, 11)),
            "parent",
        )

        extra_repo = root / "extra-delta-evidence"
        clone_isolated(fixture, extra_repo, cwd=root)
        run("git", "config", "user.name", "audit-freeze-selftest", cwd=extra_repo)
        run("git", "config", "user.email", "selftest@example.invalid", cwd=extra_repo)
        extra_bundle = extra_repo / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID
        extra_bundle.parent.mkdir(parents=True)
        gen.write_bundle(extra_bundle, first)
        put(extra_repo, "unrelated-evidence-delta", "forbidden\n")
        run("git", "add", "assurance/audit/freezes", "unrelated-evidence-delta", cwd=extra_repo)
        run("git", "commit", "-q", "-m", "extra evidence delta", cwd=extra_repo)
        expect_failure(
            "unrelated evidence commit delta",
            lambda: verify._verify_bundle_internal(extra_repo, fixture, extra_bundle, as_of=dt.date(2026, 8, 11)),
            "delta",
        )

        dirty_evidence = root / "dirty-evidence"
        shutil.copytree(evidence_repo, dirty_evidence)
        put(dirty_evidence, "dirty-untracked", "forbidden\n")
        expect_failure(
            "dirty evidence checkout",
            lambda: verify._verify_bundle_internal(dirty_evidence, fixture, dirty_evidence / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID, as_of=dt.date(2026, 8, 11)),
            "strictly clean",
        )
        dirty_subject = root / "dirty-subject"
        shutil.copytree(fixture, dirty_subject)
        put(dirty_subject, "dirty-untracked", "forbidden\n")
        expect_failure(
            "dirty subject replay checkout",
            lambda: verify._verify_bundle_internal(evidence_repo, dirty_subject, bundle, as_of=dt.date(2026, 8, 11)),
            "strictly clean",
        )
        later_subject = root / "later-subject"
        shutil.copytree(fixture, later_subject)
        put(later_subject, "later-subject-file", "later\n")
        run("git", "add", "later-subject-file", cwd=later_subject)
        run("git", "commit", "-q", "-m", "later subject", cwd=later_subject)
        expect_failure(
            "old freeze with later subject HEAD",
            lambda: verify._verify_bundle_internal(evidence_repo, later_subject, bundle, as_of=dt.date(2026, 8, 11)),
            "does not equal subject",
        )
        expect_failure(
            "same evidence and subject checkout",
            lambda: verify._verify_bundle_internal(evidence_repo, evidence_repo, bundle, as_of=dt.date(2026, 8, 11)),
            "separate",
        )
        expect_failure(
            "external bundle path before read",
            lambda: verify._verify_bundle_internal(evidence_repo, fixture, root / "not-the-bundle", as_of=dt.date(2026, 8, 11)),
            "exact committed evidence path",
        )

        hidden_evidence = root / "hidden-evidence"
        shutil.copytree(evidence_repo, hidden_evidence)
        hidden_bundle = hidden_evidence / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID
        hidden_name = str((hidden_bundle / "freeze.json").relative_to(hidden_evidence))
        run("git", "update-index", "--assume-unchanged", hidden_name, cwd=hidden_evidence)
        (hidden_bundle / "freeze.json").write_bytes(b"{}\n")
        expect_failure(
            "assume-unchanged evidence mutation",
            lambda: verify._verify_bundle_internal(hidden_evidence, fixture, hidden_bundle, as_of=dt.date(2026, 8, 11)),
            "index flags",
        )

        skipped_evidence = root / "skip-worktree-evidence"
        shutil.copytree(evidence_repo, skipped_evidence)
        skipped_bundle = skipped_evidence / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID
        skipped_name = str((skipped_bundle / "freeze.json").relative_to(skipped_evidence))
        run("git", "update-index", "--skip-worktree", skipped_name, cwd=skipped_evidence)
        expect_failure(
            "skip-worktree evidence index state",
            lambda: verify._verify_bundle_internal(skipped_evidence, fixture, skipped_bundle, as_of=dt.date(2026, 8, 11)),
            "index flags",
        )

        ignored_evidence = root / "ignored-dirty-evidence"
        shutil.copytree(evidence_repo, ignored_evidence)
        ignored_bundle = ignored_evidence / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID
        with (ignored_evidence / ".git/info/exclude").open("a", encoding="utf-8") as stream:
            stream.write("\nignored-evidence-dirty\n")
        put(ignored_evidence, "ignored-evidence-dirty", "must fail\n")
        expect_failure(
            "ignored dirty evidence checkout",
            lambda: verify._verify_bundle_internal(ignored_evidence, fixture, ignored_bundle, as_of=dt.date(2026, 8, 11)),
            "strictly clean",
        )

        executable_repo = root / "executable-evidence"
        clone_isolated(fixture, executable_repo, cwd=root)
        run("git", "config", "user.name", "audit-freeze-selftest", cwd=executable_repo)
        run("git", "config", "user.email", "selftest@example.invalid", cwd=executable_repo)
        executable_bundle = executable_repo / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID
        executable_bundle.parent.mkdir(parents=True)
        gen.write_bundle(executable_bundle, first)
        (executable_bundle / "freeze.json").chmod(0o755)
        run("git", "add", "assurance/audit/freezes", cwd=executable_repo)
        run("git", "commit", "-q", "-m", "executable evidence", cwd=executable_repo)
        expect_failure(
            "executable committed evidence entry",
            lambda: verify._verify_bundle_internal(executable_repo, fixture, executable_bundle, as_of=dt.date(2026, 8, 11)),
            "100644",
        )

        symlink_repo = root / "symlink-evidence"
        clone_isolated(fixture, symlink_repo, cwd=root)
        run("git", "config", "user.name", "audit-freeze-selftest", cwd=symlink_repo)
        run("git", "config", "user.email", "selftest@example.invalid", cwd=symlink_repo)
        symlink_bundle = symlink_repo / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID
        symlink_bundle.parent.mkdir(parents=True)
        gen.write_bundle(symlink_bundle, first)
        symlink_bundle.chmod(0o700)
        (symlink_bundle / "freeze.json").unlink()
        (symlink_bundle / "freeze.json").symlink_to("artifact-manifest.json")
        run("git", "add", "assurance/audit/freezes", cwd=symlink_repo)
        run("git", "commit", "-q", "-m", "symlink evidence", cwd=symlink_repo)
        expect_failure(
            "committed symlink evidence entry",
            lambda: verify._verify_bundle_internal(symlink_repo, fixture, symlink_bundle, as_of=dt.date(2026, 8, 11)),
            "100644 regular blob",
        )

        original_total_limit = verify.MAX_BUNDLE_TOTAL_BYTES
        verify.MAX_BUNDLE_TOTAL_BYTES = 1
        try:
            expect_failure(
                "committed evidence aggregate byte limit",
                lambda: verify._verify_bundle_internal(evidence_repo, fixture, bundle, as_of=dt.date(2026, 8, 11)),
                "aggregate byte limit",
            )
        finally:
            verify.MAX_BUNDLE_TOTAL_BYTES = original_total_limit

        merge_repo = root / "merge-evidence"
        clone_isolated(fixture, merge_repo, cwd=root)
        run("git", "config", "user.name", "audit-freeze-selftest", cwd=merge_repo)
        run("git", "config", "user.email", "selftest@example.invalid", cwd=merge_repo)
        run("git", "checkout", "-q", "-b", "side", cwd=merge_repo)
        run("git", "commit", "-q", "--allow-empty", "-m", "side parent", cwd=merge_repo)
        run("git", "checkout", "-q", "-", cwd=merge_repo)
        merge_bundle = merge_repo / "assurance/audit/freezes" / gen.PRODUCTION_FREEZE_ID
        merge_bundle.parent.mkdir(parents=True)
        gen.write_bundle(merge_bundle, first)
        run("git", "add", "assurance/audit/freezes", cwd=merge_repo)
        run("git", "commit", "-q", "-m", "bundle parent", cwd=merge_repo)
        run("git", "merge", "-q", "--no-ff", "side", "-m", "merge evidence", cwd=merge_repo)
        expect_failure(
            "multiple-parent evidence commit",
            lambda: verify._verify_bundle_internal(merge_repo, fixture, merge_bundle, as_of=dt.date(2026, 8, 11)),
            "exactly one parent",
        )

        oversized_bundle = copy_bundle(bundle, root, "oversized-bundle")
        with (oversized_bundle / "environment.json").open("wb") as stream:
            stream.truncate(verify.MAX_BUNDLE_FILE_BYTES + 1)
        expect_failure(
            "oversized bundle entry before read",
            lambda: verify._verify_bundle_documents(oversized_bundle),
            "byte limit",
        )
        aggregate_bundle = copy_bundle(bundle, root, "aggregate-oversized-bundle")
        for name in ("actions-and-runners.json", "artifact-manifest.json", "assurance-inputs.json"):
            with (aggregate_bundle / name).open("wb") as stream:
                stream.truncate(90 * 1024 * 1024)
        expect_failure(
            "aggregate oversized bundle before read",
            lambda: verify._verify_bundle_documents(aggregate_bundle),
            "aggregate limit",
        )

        print("audit-freeze self-test: all adversarial checks passed")
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"audit-freeze self-test failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
