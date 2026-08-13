#!/usr/bin/env python3
"""Closed Package G policy model and future consumer record contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import stat
import sys
import tomllib
import unicodedata
import datetime as dt
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

FRAMEWORK = Path(__file__).resolve().parent
REPO = FRAMEWORK.parents[1]
POLICY = FRAMEWORK / "policy.toml"

G10_PATHS = (
    "assurance/release-acceptance/ARTIFACTS.json", "assurance/release-acceptance/README.md",
    "assurance/release-acceptance/fixtures/control.json", "assurance/release-acceptance/generate.py",
    "assurance/release-acceptance/model.py", "assurance/release-acceptance/package-g.json",
    "assurance/release-acceptance/policy.toml", "assurance/release-acceptance/schema.json",
    "assurance/release-acceptance/selftest.py", "assurance/release-acceptance/verify.py",
)
CONSUMER4_PATHS = (
    ".github/workflows/security-validation.yml", "tools/release-dcrypt.sh",
    "tools/verify-publish-ready.sh", "tools/verify-remote-release-ready.py",
)
EXACT14_PATHS = tuple(sorted((*G10_PATHS, *CONSUMER4_PATHS)))

PHASES = ("foundation", "prepublish", "registry-prefix", "postpublish")
ROLES = (
    "foundation", "prepublish-candidate", "registry-prefix-candidate",
    "postpublish-candidate", "acceptance",
)
PUBLISH_ORDER = (
    "dcrypt-internal", "dcrypt-params", "dcrypt-api", "dcrypt-common",
    "dcrypt-algorithms", "dcrypt-symmetric", "dcrypt-kem", "dcrypt-sign",
    "dcrypt-pke", "dcrypt-utils", "dcrypt-hybrid", "dcrypt",
)
SUBJECTS = (
    ("sbom-production", "sbom"),
    ("sbom-verification", "sbom"),
    ("sbom-fuzz", "sbom"),
    ("sbom-migration", "sbom"),
    ("sbom-bench", "sbom"),
    *((f"crate-{name}", "candidate-crate-archive") for name in PUBLISH_ORDER),
    ("canonical-source-archive", "source-archive"),
)
PRODUCERS = ("first-party", "administratively-independent")
HEX40 = set("0123456789abcdef")
HEX64 = HEX40


class PackageGError(ValueError):
    """Package G input is malformed or violates a closed invariant."""


class PackageGBlocker(PackageGError):
    """Well-formed but incomplete, deferred, or stale nonpromotion state."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def identical(left: Any, right: Any) -> bool:
    """Recursive equality that rejects Python's bool/int aliasing."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(identical(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(identical(a, b) for a, b in zip(left, right, strict=True))
    return left == right


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PackageGError(f"{label} field closure differs")
    return value


def _hex(value: Any, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length or any(c not in HEX40 for c in value):
        raise PackageGError(f"{label} must be lowercase hex{length}")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or unicodedata.normalize("NFC", value) != value:
        raise PackageGError(f"{label} must be nonempty NFC text")
    return value


def _date(value: Any, label: str) -> str:
    text = _text(value, label)
    try:
        if dt.date.fromisoformat(text).isoformat() != text:
            raise ValueError
    except ValueError as error:
        raise PackageGError(f"{label} must be an ISO date") from error
    return text


def _relative_artifact_path(value: Any, label: str) -> str:
    text = _text(value, label)
    if (
        text.startswith("/") or "\\" in text or "\x00" in text
        or re.match(r"^[A-Za-z]:", text) is not None
        or any(ord(character) < 0x20 or ord(character) == 0x7f for character in text)
        or any(part in {"", ".", ".."} for part in text.split("/"))
        or any(len(part) > 255 for part in text.split("/"))
        or text.startswith("assurance/release-acceptance/fixtures/")
    ):
        raise PackageGError(f"{label} must be a safe non-fixture relative path")
    return text


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _validate_nfc(value: Any, label: str) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise PackageGError(f"{label} contains a lone surrogate")
        if unicodedata.normalize("NFC", value) != value:
            raise PackageGError(f"{label} contains non-NFC text")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_nfc(item, f"{label}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_nfc(key, f"{label} key")
            _validate_nfc(item, f"{label}.{key}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PackageGError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_number(token: str) -> Any:
    raise PackageGError(f"JSON floating/nonfinite number forbidden: {token}")


def parse_json_strict(raw: bytes, *, label: str, require_canonical: bool = False) -> Any:
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(
            text, object_pairs_hook=_pairs, parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PackageGError(f"{label} is not strict JSON: {error}") from error
    _validate_nfc(value, label)
    if require_canonical and raw != canonical_json(value):
        raise PackageGError(f"{label} is not canonical JSON")
    return value


def read_regular_once(path: Path, *, label: str, maximum: int = 64 * 1024 * 1024) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum
            or stat.S_IMODE(before.st_mode) & 0o002 or before.st_uid != os.getuid()
            or before.st_gid != os.getgid()
        ):
            raise PackageGError(f"{label} must be a bounded singly-linked regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise PackageGError(f"short read for {label}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise PackageGError(f"{label} grew while read")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_nlink, before.st_uid, before.st_gid, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_uid, after.st_gid, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise PackageGError(f"{label} changed while read")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def load_policy() -> dict[str, Any]:
    raw, _metadata = read_regular_once(POLICY, label="Package G policy", maximum=256 * 1024)
    try:
        policy = tomllib.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise PackageGError(f"Package G policy is malformed: {error}") from error
    validate_policy(policy)
    return policy


def _git_object(oid: str, expected_type: str) -> bytes:
    _hex(oid, 40, "Git object ID")
    git_dir = REPO / ".git"
    if not git_dir.is_dir():
        raise PackageGError("Package G requires a normal checkout")
    replacements = git_dir / "refs" / "replace"
    if replacements.exists() and any(replacements.iterdir()):
        raise PackageGError("Git replacement objects are forbidden")
    environment = _git_environment()
    try:
        kind = _git_run(("cat-file", "-t", oid), timeout=10)
        content = _git_run(("cat-file", expected_type, oid), timeout=30)
    except PackageGError as error:
        raise PackageGError(f"Git object read failed: {oid}: {error}") from error
    if kind != f"{expected_type}\n".encode() or len(content) > 128 * 1024 * 1024:
        raise PackageGError(f"Git object content/type differs: {oid}")
    body = content
    if hashlib.sha1(f"{expected_type} {len(body)}\0".encode() + body, usedforsecurity=False).hexdigest() != oid:
        raise PackageGError(f"Git object digest differs: {oid}")
    return body


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.useReplaceRefs", "GIT_CONFIG_VALUE_0": "false",
        "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
    }


def _git_run(arguments: tuple[str, ...], *, timeout: int = 20, maximum: int = 128 * 1024 * 1024) -> bytes:
    try:
        result = subprocess.run(
            ["/usr/bin/git", *arguments], cwd=REPO, env=_git_environment(),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise PackageGError(f"Git command timed out: {arguments}") from error
    if result.returncode != 0 or result.stderr or len(result.stdout) > maximum:
        raise PackageGError(f"Git command failed: {arguments}")
    return result.stdout


def _tree_entries(body: bytes) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    offset = 0
    while offset < len(body):
        space = body.find(b" ", offset)
        nul = body.find(b"\x00", space + 1)
        if space < 0 or nul < 0 or nul + 21 > len(body):
            raise PackageGError("Git tree encoding is malformed")
        mode = body[offset:space].decode("ascii")
        name = body[space + 1:nul].decode("utf-8", "strict")
        oid = body[nul + 1:nul + 21].hex()
        if name in entries or "/" in name or not name:
            raise PackageGError("Git tree entry name closure differs")
        entries[name] = (mode, oid)
        offset = nul + 21
    return entries


def git_entry(commit: str, relative: str) -> tuple[str, str]:
    commit_body = _git_object(commit, "commit")
    lines = commit_body.splitlines()
    tree_lines = [line for line in lines if line.startswith(b"tree ")]
    if len(tree_lines) != 1:
        raise PackageGError("commit tree header closure differs")
    oid = tree_lines[0].split()[1].decode("ascii")
    mode = "40000"
    parts = relative.split("/")
    for offset, part in enumerate(parts):
        entries = _tree_entries(_git_object(oid, "tree"))
        if part not in entries:
            raise PackageGError(f"Git projection path absent: {relative}")
        mode, oid = entries[part]
        if offset < len(parts) - 1 and mode not in {"40000", "040000"}:
            raise PackageGError(f"Git projection path is not a tree: {relative}")
    return mode, oid


def git_blob(commit: str, relative: str) -> bytes:
    mode, oid = git_entry(commit, relative)
    if mode != "100644":
        raise PackageGError(f"immutable antecedent mode differs: {relative}")
    return _git_object(oid, "blob")


def validate_policy(policy: Any) -> None:
    expected_root = {
        "schema-version", "content-policy", "status", "release-gate", "release-exit-code",
        "workspace-version", "target-version", "version-preparation-authorized", "publish-eligible",
        "promotion-eligible", "acceptance-enabled", "scope", "topology", "protected-state",
        "immutable-projection", "release-contract", "threat-known-blocker", "deadlines",
        "publication", "phase", "producer-class", "artifact-subject", "record-contract", "antecedent",
    }
    p = _closed(policy, expected_root, "policy root")
    if (
        any(not identical(p[key], value) for key, value in {
            "schema-version": 1, "content-policy": "dcrypt-package-g-release-acceptance-foundation-v1",
            "status": "HOLD", "release-gate": "HOLD", "release-exit-code": 3,
            "workspace-version": "3.0.0", "target-version": "4.0.0",
        }.items())
        or any(p[k] is not False for k in (
            "version-preparation-authorized", "publish-eligible", "promotion-eligible", "acceptance-enabled"
        ))
    ):
        raise PackageGError("policy release identity differs")
    scope = _closed(p["scope"], {"path-count", "path-list-sha256", "mode-path-list-sha256", "regular-path-count", "executable-path-count"}, "scope")
    if not identical(scope, {
        "path-count": 14,
        "path-list-sha256": "31f865655ce1eda985d50d1e0ca46d578468eba0c4bdbc066800d91f190fcde0",
        "mode-path-list-sha256": "043175aa5d4c14c5c28243902fa7a4edb38d97a93a775a2502f70914d2aeacf2",
        "regular-path-count": 11,
        "executable-path-count": 3,
    }):
        raise PackageGError("policy path scope differs")
    topology = _closed(p["topology"], {
        "a-f-commit", "a-f-tree", "r-f-commit", "r-f-tree", "s-f-commit", "s-f-tree",
        "required-g-parent", "final-g-identity-claim", "construction-head", "construction-g-path-state",
        "final-parent-count", "final-diff-path-count", "final-diff-path-list-sha256",
    }, "topology")
    expected_topology = {
        "a-f-commit": "56d837d72467cd78d696218dabf016fb6dd6c457",
        "a-f-tree": "c1183ca6480655cd253e6e3527eef69b9d6607e8",
        "r-f-commit": "889cb8c4dc13a78679dc8a7677916484a9966f65",
        "r-f-tree": "0d44b68b186913de68844d09b7e498bcda14d109",
        "s-f-commit": "ac91913afee3b91c823a1448e6200de26fdd1c8a",
        "s-f-tree": "6952979606c28f739fca1aeb9bb14b1ca042d09d",
        "required-g-parent": "56d837d72467cd78d696218dabf016fb6dd6c457",
        "final-g-identity-claim": False,
        "construction-head": "56d837d72467cd78d696218dabf016fb6dd6c457",
        "construction-g-path-state": "untracked-g10-and-tracked-consumer4",
        "final-parent-count": 1,
        "final-diff-path-count": 14,
        "final-diff-path-list-sha256": "31f865655ce1eda985d50d1e0ca46d578468eba0c4bdbc066800d91f190fcde0",
    }
    if not identical(topology, expected_topology):
        raise PackageGError("policy topology differs")
    protected = _closed(p["protected-state"], {
        "path", "committed-sha256", "live-sha256", "live-size", "git-mode", "allowed-states", "clean-size",
    }, "protected state")
    if not identical(protected, {
        "path": ".gitignore", "committed-sha256": "f34512e77a7cf5fdfd465243dbb286d8e16bfd698cad264bdb1360f008915f26",
        "live-sha256": "e4887e3f444e25b7baad39bd6ff3da3ae770f8dc5b3f7cf2c87a117219a8fe2c",
        "live-size": 720, "git-mode": "100644", "allowed-states": ["clean-committed", "protected-preexisting-delta-unchanged"],
        "clean-size": 711,
    }):
        raise PackageGError("protected state differs")
    projection = _closed(p["immutable-projection"], {
        "commit", "tree", "parent", "replacement-objects-allowed", "subtree", "blob",
    }, "immutable projection")
    expected_subtrees = [
        ("assurance/interoperability", "c7c7858973631746a41c84264bf8088e7ff95f7f"),
        ("assurance/fuzzing", "19a8ee6506471d38f7ea3bd15c1d0bb562522b65"),
        ("assurance/side-channel", "d0c1544d0560e40a336265522869eb37d2f67fb0"),
        ("assurance/error-api-v4", "d57913804568c66114bc7e4a36dee1bf2d04c5b0"),
        ("assurance/supply-chain", "632f03f75141c0a59abbe243067288f05a3cf481"),
        ("assurance/threat-models", "1c50a55deaf424678e28f6dd881ad3d31399cdac"),
        ("assurance/audit", "a11f344fdd8e08ace083e62c14f2100c4c083ae7"),
    ]
    if not identical(projection["subtree"], [{"path": path, "git-object": oid} for path, oid in expected_subtrees]):
        raise PackageGError("immutable subtree closure differs")
    expected_blobs = [
        ("assurance/ledger.toml", "b6ba707f0c8cb74af4d90b25d2e465ad734982c5", "049d524b5cbea96a18bcf901f95e83fdf1f02093aef0542012e78882aba8d8dd"),
        ("assurance/atomic-operations.toml", "bf6f9afa7828de87b663ccb9a699762336202008", "8e745ab16086aa50e265ad79189375270c5906df8545f540d96426bc348ca11a"),
        ("assurance/public-api-snapshot.json", "22ff7a129184fe4187aad81538bf365ec5cf8ce2", "5fa59a0218c2be98ef653d85da35c616c75b1499cb376f2b12c99eb6813e553d"),
        ("assurance/subject-manifest.json", "15742ca9d33e21b2c4ba927bca71dfdf08fe7540", "95902d2ff4a2f99808ba5d404fbce3175b787b93fdc1538cb55ad350e69505c7"),
    ]
    if not identical(projection, {
        "commit": topology["a-f-commit"], "tree": topology["a-f-tree"], "parent": topology["r-f-commit"],
        "replacement-objects-allowed": False,
        "subtree": [{"path": path, "git-object": oid} for path, oid in expected_subtrees],
        "blob": [{"path": path, "git-object": oid, "sha256": digest} for path, oid, digest in expected_blobs],
    }):
        raise PackageGError("immutable projection differs")
    contract = p["release-contract"]
    _closed(contract, {
        "phase-order", "roles", "generation-command", "ci-command", "release-command-prefix",
        "release-cli-phases", "threat-model-release-command", "threat-model-current-exit-code",
        "threat-model-g-mapped-exit-code", "ci-foundation-exit-code", "release-hold-exit-code",
        "malformed-exit-code", "misuse-exit-code", "top-level-wiring-deferred",
    }, "release contract")
    if (
        not identical(contract["phase-order"], list(PHASES)) or not identical(contract["roles"], list(ROLES))
        or contract["threat-model-release-command"] != [
            "python3", "-B", "assurance/threat-models/verify-threat-models.py", "--mode", "release"
        ]
        or any(not identical(contract[key], value) for key, value in {
            "threat-model-current-exit-code": 1, "threat-model-g-mapped-exit-code": 3,
            "ci-foundation-exit-code": 0, "release-hold-exit-code": 3,
            "malformed-exit-code": 1, "misuse-exit-code": 2,
        }.items())
        or contract["generation-command"] != ["python3", "-B", "assurance/release-acceptance/generate.py", "--check"]
        or contract["ci-command"] != ["python3", "-B", "assurance/release-acceptance/verify.py", "--ci", "--phase", "foundation"]
        or contract["release-command-prefix"] != ["python3", "-B", "assurance/release-acceptance/verify.py", "--release", "--phase"]
        or contract["release-cli-phases"] != ["foundation", "prepublish", "postpublish"]
        or contract["top-level-wiring-deferred"] is not False
    ):
        raise PackageGError("release command contract differs")
    deadlines = _closed(p["deadlines"], {
        "dependency-exception-valid-before", "dependency-exception-reject-on-or-after",
        "historical-advisory-review-deadline", "historical-advisory-replay-required",
        "ledger-evidence-valid-through", "threat-model-valid-through", "evidence-reject-after",
    }, "deadline policy")
    if not identical(deadlines, {
        "dependency-exception-valid-before": "2026-09-10", "dependency-exception-reject-on-or-after": "2026-09-10",
        "historical-advisory-review-deadline": "2026-09-10", "historical-advisory-replay-required": True,
        "ledger-evidence-valid-through": "2026-11-09", "threat-model-valid-through": "2026-11-09",
        "evidence-reject-after": "2026-11-09",
    }):
        raise PackageGError("deadline policy differs")
    threat = _closed(p["threat-known-blocker"], {
        "threat-models-sha256", "coverage-sha256", "candidate-models", "independent-review-required",
        "critical-residual", "high-residual", "planned-mitigations", "implemented-unverified-mitigations",
        "verified-mitigations", "active-mitigations", "expected-upstream-release-exit-code", "mapped-g-release-exit-code",
    }, "threat known blocker")
    if not identical(threat, {
        "threat-models-sha256": "16b787d2eb100837b61b54f25f6e5ad96de696b4cd4274f09a3b5e511b41539e",
        "coverage-sha256": "253bf52dba0b5cecb149b9c6f5a282d9c3d37f0101ba2ff8a8b1c75794b9daf1",
        "candidate-models": 11, "independent-review-required": 11, "critical-residual": 10,
        "high-residual": 1, "planned-mitigations": 22, "implemented-unverified-mitigations": 9,
        "verified-mitigations": 0, "active-mitigations": 0, "expected-upstream-release-exit-code": 1,
        "mapped-g-release-exit-code": 3,
    }):
        raise PackageGError("threat known blocker tuple differs")
    if not identical(p["publication"], {"publish-order": list(PUBLISH_ORDER)}):
        raise PackageGError("publish order differs")
    phases = _closed(p["phase"], {"foundation", "prepublish", "registry-prefix", "postpublish", "acceptance"}, "phase policy")
    expected_phase_keys = {
        "foundation": {"role", "required-domains", "forbidden-domains", "registry-state", "trusted", "promotion-eligible"},
        "prepublish": {"role", "required-domains", "forbidden-domains", "registry-state", "registry-count", "trusted", "promotion-eligible"},
        "registry-prefix": {"role", "required-domains", "forbidden-domains", "registry-state", "registry-prefix-min", "registry-prefix-max", "trusted", "promotion-eligible"},
        "postpublish": {"role", "required-domains", "forbidden-domains", "registry-state", "registry-count", "require-downloaded-equals-candidate", "require-downloaded-equals-registry-checksum", "require-unyanked", "trusted", "promotion-eligible"},
        "acceptance": {"role", "enabled", "validation", "trusted", "promotion-eligible"},
    }
    expected_phases = {
        "foundation": {"role": "foundation", "required-domains": ["antecedents", "commands", "deadlines", "protected-state", "scope", "topology", "versions"], "forbidden-domains": ["candidate-artifacts", "downloaded-artifacts", "registry-artifacts", "review-decisions"], "registry-state": "absent", "trusted": False, "promotion-eligible": False},
        "prepublish": {"role": "prepublish-candidate", "required-domains": ["candidate-artifacts", "independent-comparisons", "producer-obligations", "review-decisions"], "forbidden-domains": ["downloaded-artifacts", "registry-artifacts"], "registry-state": "deferred-empty", "registry-count": 0, "trusted": False, "promotion-eligible": False},
        "registry-prefix": {"role": "registry-prefix-candidate", "required-domains": ["candidate-artifacts", "registry-artifacts", "review-decisions"], "forbidden-domains": ["downloaded-artifacts"], "registry-state": "exact-publish-order-prefix", "registry-prefix-min": 0, "registry-prefix-max": 12, "trusted": False, "promotion-eligible": False},
        "postpublish": {"role": "postpublish-candidate", "required-domains": ["candidate-artifacts", "downloaded-artifacts", "registry-artifacts", "review-decisions"], "forbidden-domains": [], "registry-state": "complete-12", "registry-count": 12, "require-downloaded-equals-candidate": True, "require-downloaded-equals-registry-checksum": True, "require-unyanked": True, "trusted": False, "promotion-eligible": False},
        "acceptance": {"role": "acceptance", "enabled": False, "validation": "always-reject", "trusted": False, "promotion-eligible": False},
    }
    for phase_name, keys in expected_phase_keys.items():
        _closed(phases[phase_name], keys, f"phase {phase_name}")
        if not identical(phases[phase_name], expected_phases[phase_name]):
            raise PackageGError(f"phase {phase_name} semantics differ")
    if not identical(p["artifact-subject"], [{"id": subject_id, "class": kind} for subject_id, kind in SUBJECTS]):
        raise PackageGError("artifact subject closure differs")
    if [r.get("id") for r in p["producer-class"]] != list(PRODUCERS):
        raise PackageGError("producer class closure differs")
    if any(not identical(r, {"id": r["id"], "required-subject-count": 18, "completed-subject-count": 0, "accepted": False}) for r in p["producer-class"]):
        raise PackageGError("producer obligation semantics differ")
    rc = p["record-contract"]
    _closed(rc, {
        "schema-version", "subject-count", "producer-class-count", "producer-obligation-count",
        "independent-comparison-count", "candidate-crate-count", "registry-crate-count",
        "downloaded-crate-count", "artifact-required-fields", "crate-artifact-extra-fields",
        "registry-required-fields", "download-required-fields", "review-required-fields",
        "lineage-required-fields", "producer-obligation-required-fields", "comparison-required-fields",
        "digest-equality-rules", "strict-json-rules",
    }, "record contract")
    if any(not identical(rc[k], v) for k, v in {
        "schema-version": 1, "subject-count": 18, "producer-class-count": 2,
        "producer-obligation-count": 36, "independent-comparison-count": 18,
        "candidate-crate-count": 12, "registry-crate-count": 12, "downloaded-crate-count": 12,
    }.items()):
        raise PackageGError("future record count contract differs")
    expected_record_lists = {
        "artifact-required-fields": ["acquisition_sha256", "artifact_class", "build_environment_sha256", "path", "producer_class", "producer_identity", "provenance_sha256", "role", "sha256", "signature_sha256", "size", "subject", "subject_id"],
        "crate-artifact-extra-fields": ["cargo_vcs_info_sha1", "name", "version"],
        "registry-required-fields": ["checksum", "name", "prefix_index", "registry_version_id", "subject", "unyanked", "version"],
        "download-required-fields": ["acquired_at", "acquisition_identity", "acquisition_provenance_sha256", "cargo_vcs_info_sha1", "name", "path", "sha256", "size", "subject", "subject_id", "version"],
        "review-required-fields": ["artifact_sha256", "decision", "independent", "review_evidence_sha256", "reviewed_at", "reviewer", "reviewed_producer_identities", "subject", "subject_id", "valid_through"],
        "lineage-required-fields": ["candidate_set_sha256", "prepublish_record_sha256", "prefix_predecessor_sha256", "final_prefix_record_sha256"],
        "producer-obligation-required-fields": ["accepted", "acquisition_sha256", "artifact_path", "artifact_sha256", "build_environment_sha256", "producer_class", "producer_identity", "provenance_sha256", "signature_sha256", "status", "subject", "subject_id"],
        "comparison-required-fields": ["accepted", "byte_equal", "first_party_producer_identity", "first_party_sha256", "independent_producer_identity", "independent_sha256", "review_evidence_sha256", "reviewer", "subject", "subject_id"],
        "digest-equality-rules": ["postpublish.local-candidate.sha256==postpublish.registry.checksum", "postpublish.local-candidate.sha256==postpublish.downloaded.sha256"],
        "strict-json-rules": ["canonical-utf8-nfc", "duplicate-keys-rejected", "floats-rejected", "nonfinite-rejected", "bool-not-integer", "unknown-fields-rejected", "exact-array-order"],
    }
    if any(not identical(rc[key], value) for key, value in expected_record_lists.items()):
        raise PackageGError("future record field/rule closure differs")
    if len(p["antecedent"]) != 8 or [r.get("id") for r in p["antecedent"]] != [
        "assurance-ledger", "package-b-interoperability", "package-c-fuzzing",
        "package-d-side-channel", "package-e-migration", "package-f-supply-chain",
        "threat-model-release", "historical-advisory-replay",
    ]:
        raise PackageGError("antecedent closure differs")
    antecedent_values = [
        ("assurance-ledger", "assurance/ledger.toml", "049d524b5cbea96a18bcf901f95e83fdf1f02093aef0542012e78882aba8d8dd", 2, "not-applicable", "informational-only", 9198, "2026-11-09", "valid-through-inclusive"),
        ("package-b-interoperability", "assurance/interoperability/matrix.json", "307e3ef67b596ba1ffe06cec0e58629f498d2ca4555458fbb8d6d313524fbadd", 1, "not-applicable", "blocked", 14816, "2026-11-09", "deadline-and-expiry-bound"),
        ("package-c-fuzzing", "assurance/fuzzing/row-mapping.json", "9feedae461b99e46cda1556a0eb13749fb65cfb53c495b77e1130e158835cc79", 1, "STABLE-final-subject-bound", "HOLD", 9198, "2026-11-09", "antecedent-evidence-bound"),
        ("package-d-side-channel", "assurance/side-channel/package-d.json", "59e9961813ac4fa0bc3ab186268889073cb89036b967f81619ab5e1f294ee22e", 1, "HOLD-structural-foundation-only", "HOLD", 9198, "2026-11-09", "antecedent-evidence-bound"),
        ("package-e-migration", "assurance/error-api-v4/package-e.json", "110cf0dc0c0993c59cf2b9b53a4985873a0e85914d544022e87caedccf1f8411", 1, "local-breaking-removal-complete", "HOLD", 9198, "2026-11-09", "antecedent-evidence-bound"),
        ("package-f-supply-chain", "assurance/supply-chain/package-f.json", "da052c4bad734d58e471ffe71db55009ba10ddf1d92423dbf28e3a02995f5e8c", 1, "local-foundation-complete-operational-evidence-absent", "HOLD", 9198, "2026-09-10", "dependency-exception-reject-on-or-after"),
        ("threat-model-release", "assurance/threat-models/threat-models.toml", "16b787d2eb100837b61b54f25f6e5ad96de696b4cd4274f09a3b5e511b41539e", 1, "11-candidate-models", "blocked-current-release-rc1", 9198, "2026-11-09", "valid-through-inclusive"),
        ("historical-advisory-replay", "assurance/audit/historical-advisory-regressions.toml", "ce6fa84b1a8de37d938e51b82806e67b8cc6c7dcb4d3234cdcd44c76cf96acc7", 1, "inventory-only-replay-required", "blocked-replay-required", 11, "2026-09-10", "review-deadline-metadata-no-expiry-invented"),
    ]
    keys = {"id", "path", "sha256", "schema-version", "document-status", "release-gate", "blocked-rows", "temporal-bound", "temporal-rule"}
    for observed, values in zip(p["antecedent"], antecedent_values, strict=True):
        _closed(observed, keys, f"antecedent {values[0]}")
        expected = dict(zip(("id", "path", "sha256", "schema-version", "document-status", "release-gate", "blocked-rows", "temporal-bound", "temporal-rule"), values, strict=True))
        if not identical(observed, expected):
            raise PackageGError(f"antecedent {values[0]} differs")


def verify_immutable_projection() -> dict[str, Any]:
    policy = load_policy()
    topology = policy["topology"]
    commit_body = _git_object(topology["a-f-commit"], "commit")
    headers = commit_body.split(b"\n\n", 1)[0].splitlines()
    if headers[0] != f"tree {topology['a-f-tree']}".encode() or [line for line in headers if line.startswith(b"parent ")] != [
        f"parent {topology['r-f-commit']}".encode()
    ]:
        raise PackageGError("A_F commit/tree/sole-parent topology differs")
    r_body = _git_object(topology["r-f-commit"], "commit")
    r_headers = r_body.split(b"\n\n", 1)[0].splitlines()
    if r_headers[0] != f"tree {topology['r-f-tree']}".encode() or [line for line in r_headers if line.startswith(b"parent ")] != [f"parent {topology['s-f-commit']}".encode()]:
        raise PackageGError("R_F tree/S_F parent topology differs")
    s_body = _git_object(topology["s-f-commit"], "commit")
    s_headers = s_body.split(b"\n\n", 1)[0].splitlines()
    if s_headers[0] != f"tree {topology['s-f-tree']}".encode() or len([line for line in s_headers if line.startswith(b"parent ")]) != 1:
        raise PackageGError("S_F tree topology differs")
    for row in policy["immutable-projection"]["subtree"]:
        mode, oid = git_entry(topology["a-f-commit"], row["path"])
        if mode not in {"40000", "040000"} or oid != row["git-object"]:
            raise PackageGError(f"A_F subtree projection differs: {row['path']}")
    for row in policy["immutable-projection"]["blob"]:
        mode, oid = git_entry(topology["a-f-commit"], row["path"])
        raw = _git_object(oid, "blob")
        if mode != "100644" or oid != row["git-object"] or sha256_bytes(raw) != row["sha256"]:
            raise PackageGError(f"A_F blob projection differs: {row['path']}")
    projections = _parse_antecedent_documents(topology["a-f-commit"])
    return {"commit": topology["a-f-commit"], "tree": topology["a-f-tree"], "antecedents": projections}


def verify_current_topology_scope() -> str:
    """Prove either the exact construction checkout or exact committed G child."""
    policy = load_policy()
    git_dir = REPO / ".git"
    forbidden = (
        git_dir / "shallow", git_dir / "info" / "grafts", git_dir / "objects" / "info" / "alternates",
    )
    if any(path.exists() for path in forbidden):
        raise PackageGError("shallow, grafted, or alternate Git object state is forbidden")
    config_raw, _metadata = read_regular_once(git_dir / "config", label="local Git config", maximum=1024 * 1024)
    lowered = config_raw.lower()
    if b"promisor" in lowered or b"partialclone" in lowered:
        raise PackageGError("promisor/partial-clone Git state is forbidden")
    if _git_run(("ls-files", "-u", "-z")):
        raise PackageGError("unmerged index entries are forbidden")
    tags = _git_run(("ls-files", "-v", "-z")).split(b"\x00")
    if any(row and (len(row) < 3 or row[:1] != b"H") for row in tags):
        raise PackageGError("index skip-worktree/assume-unchanged flags are forbidden")
    if _git_run(("diff", "--cached", "--name-only", "-z")):
        raise PackageGError("Package G requires an index identical to HEAD")
    head = _git_run(("rev-parse", "--verify", "HEAD")).decode("ascii").strip()
    status_raw = _git_run(("status", "--porcelain=v1", "-z", "--untracked-files=all"))
    status: dict[str, str] = {}
    for record in status_raw.split(b"\x00"):
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            raise PackageGError("Git porcelain status encoding differs")
        code = record[:2].decode("ascii")
        path = record[3:].decode("utf-8", "strict")
        if code[0] in {"R", "C"} or code[1] in {"R", "C"} or path in status:
            raise PackageGError("renames, copies, and duplicate status paths are forbidden")
        status[path] = code
    protected_raw, _metadata = read_regular_once(REPO / ".gitignore", label="protected .gitignore", maximum=4096)
    protected_digest = sha256_bytes(protected_raw)
    clean = protected_digest == policy["protected-state"]["committed-sha256"] and len(protected_raw) == policy["protected-state"]["clean-size"]
    local = protected_digest == policy["protected-state"]["live-sha256"] and len(protected_raw) == policy["protected-state"]["live-size"]
    if not (clean or local):
        raise PackageGError("protected .gitignore is in an unreviewed third state")
    a_f = policy["topology"]["a-f-commit"]
    if head == a_f:
        expected = {path: " M" for path in CONSUMER4_PATHS} | {path: "??" for path in G10_PATHS} | {".gitignore": " M"}
        if not local or status != expected:
            raise PackageGError("construction checkout closure differs")
        changed = set(_git_run(("diff", "--name-only", "-z", "HEAD")).decode("utf-8").strip("\x00").split("\x00"))
        if changed != set((*CONSUMER4_PATHS, ".gitignore")):
            raise PackageGError("construction tracked delta differs")
        for path in CONSUMER4_PATHS:
            metadata = (REPO / path).lstat()
            expected_exec = path.startswith("tools/")
            if (
                not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                or bool(metadata.st_mode & stat.S_IXUSR) is not expected_exec
                or metadata.st_mode & 0o7000
            ):
                raise PackageGError(f"construction consumer Git mode mapping differs: {path}")
        return "construction-exact14-plus-protected"
    commit_body = _git_object(head, "commit")
    parent_lines = [line for line in commit_body.split(b"\n\n", 1)[0].splitlines() if line.startswith(b"parent ")]
    if parent_lines != [f"parent {a_f}".encode()]:
        raise PackageGError("final Package G commit is not the sole child of A_F")
    diff_paths = _git_run(("diff-tree", "--no-commit-id", "--name-only", "-r", "-z", a_f, head)).decode("utf-8").strip("\x00").split("\x00")
    if tuple(sorted(diff_paths)) != EXACT14_PATHS:
        raise PackageGError("final Package G committed path closure differs")
    for path in EXACT14_PATHS:
        mode, _oid = git_entry(head, path)
        expected_mode = "100755" if path.startswith("tools/") else "100644"
        if mode != expected_mode:
            raise PackageGError(f"final Package G Git mode differs: {path}")
    expected_status = {} if clean else {".gitignore": " M"}
    if status != expected_status:
        raise PackageGError("final Package G worktree closure differs")
    return "final-sole-child-exact14" + ("-protected" if local else "-clean")


def _parse_antecedent_documents(commit: str) -> dict[str, Any]:
    b = parse_json_strict(git_blob(commit, "assurance/interoperability/matrix.json"), label="A_F Package B", require_canonical=False)
    c = parse_json_strict(git_blob(commit, "assurance/fuzzing/row-mapping.json"), label="A_F Package C", require_canonical=True)
    d = parse_json_strict(git_blob(commit, "assurance/side-channel/package-d.json"), label="A_F Package D", require_canonical=True)
    e = parse_json_strict(git_blob(commit, "assurance/error-api-v4/package-e.json"), label="A_F Package E", require_canonical=True)
    f = parse_json_strict(git_blob(commit, "assurance/supply-chain/package-f.json"), label="A_F Package F", require_canonical=True)
    checks = {
        "package-b": (
            b.get("content_policy") == "dcrypt-interoperability-matrix-v1" and b.get("schema_version") == 1
            and b.get("release_gate", {}).get("status") == "blocked"
            and b.get("release_gate", {}).get("evidence_promotion_enabled") is False
            and b.get("counts", {}).get("accepted_oracle_dossiers") == 0
            and b.get("counts", {}).get("passing_operation_atoms") == 0
            and b.get("counts", {}).get("interoperability_blockers") == 14816
        ),
        "package-c": (
            c.get("content_policy") == "dcrypt-fuzzing-row-mapping-v1" and c.get("schema_version") == 1
            and c.get("status") == "STABLE-final-subject-bound"
            and c.get("counts", {}).get("release_blocked_rows") == 9198
        ),
        "package-d": (
            d.get("content_policy") == "dcrypt-package-d-side-channel-foundation-v1" and d.get("schema_version") == 1
            and d.get("status") == "HOLD-structural-foundation-only"
            and identical(d.get("release_gate"), {"exit_code": 3, "status": "HOLD"})
            and d.get("promotion_eligible") is False and d.get("counts", {}).get("accepted_evidence_records") == 0
            and d.get("counts", {}).get("release_blocked_rows") == 9198
        ),
        "package-e": (
            e.get("content_policy") == "dcrypt-package-e-local-breaking-removal-v1" and e.get("schema_version") == 1
            and e.get("status") == "local-breaking-removal-complete"
            and identical(e.get("release_state"), {"promotion_eligible": False, "publish_eligible": False, "release_gate": "HOLD", "release_gate_exit_code": 3, "version_preparation_authorized": False})
            and e.get("workspace_version") == "3.0.0" and e.get("counts", {}).get("release_blocked_rows") == 9198
        ),
        "package-f": (
            f.get("content_policy") == "dcrypt-package-f-local-foundation-v1" and f.get("schema_version") == 1
            and f.get("status") == "local-foundation-complete-operational-evidence-absent"
            and identical(f.get("release_state"), {"promotion_eligible": False, "publish_eligible": False, "release_gate": "HOLD", "release_gate_exit_code": 3, "version_preparation_authorized": False})
            and f.get("workspace_version") == "3.0.0" and f.get("counts", {}).get("release_blocked_atomic_rows") == 9198
            and f.get("counts", {}).get("accepted_attestations") == 0 and f.get("counts", {}).get("accepted_independent_rebuilds") == 0
            and [row.get("name") for row in f.get("publish_order", [])] == list(PUBLISH_ORDER)
            and f.get("dependency_exception", {}).get("valid_through") == "2026-09-10"
        ),
    }
    if not all(checks.values()):
        raise PackageGError(f"immutable A_F antecedent nonpromotion tuple differs: {checks}")
    threat_raw = git_blob(commit, "assurance/threat-models/threat-models.toml")
    coverage_raw = git_blob(commit, "assurance/threat-models/coverage.json")
    try:
        threat = tomllib.loads(threat_raw.decode("utf-8", "strict"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise PackageGError(f"immutable threat model TOML malformed: {error}") from error
    coverage = parse_json_strict(coverage_raw, label="A_F threat coverage", require_canonical=True)
    models = threat.get("model")
    if not isinstance(models, list):
        raise PackageGError("immutable threat model closure differs")
    tuple_observed = {
        "active_mitigations": sum(1 for item in models for mitigation in item.get("mitigations", []) if mitigation.get("status") == "active"),
        "candidate_models": sum(1 for item in models if item.get("status") == "candidate"),
        "critical_residual": sum(1 for item in models if item.get("residual-risk", {}).get("rating") == "critical"),
        "high_residual": sum(1 for item in models if item.get("residual-risk", {}).get("rating") == "high"),
        "implemented_unverified_mitigations": sum(1 for item in models for mitigation in item.get("mitigations", []) if mitigation.get("status") == "implemented-unverified"),
        "independent_review_required": sum(1 for item in models if item.get("independent-review-status") == "required"),
        "planned_mitigations": sum(1 for item in models for mitigation in item.get("mitigations", []) if mitigation.get("status") == "planned"),
        "verified_mitigations": sum(1 for item in models for mitigation in item.get("mitigations", []) if mitigation.get("status") == "verified"),
    }
    expected_threat = {
        "active_mitigations": 0, "candidate_models": 11, "critical_residual": 10,
        "high_residual": 1, "implemented_unverified_mitigations": 9,
        "independent_review_required": 11, "planned_mitigations": 22, "verified_mitigations": 0,
    }
    if (
        sha256_bytes(threat_raw) != "16b787d2eb100837b61b54f25f6e5ad96de696b4cd4274f09a3b5e511b41539e"
        or sha256_bytes(coverage_raw) != "253bf52dba0b5cecb149b9c6f5a282d9c3d37f0101ba2ff8a8b1c75794b9daf1"
        or not identical(tuple_observed, expected_threat)
        or coverage.get("counts", {}).get("threat_models") != 11
        or coverage.get("counts", {}).get("release_blocked_rows") != 9198
    ):
        raise PackageGError("immutable known threat blocker tuple differs")
    return {name: "nonpromotable-exact-A_F" for name in checks} | {"threat-model": "known-exact-rc1-blocker-maps-to-G-rc3"}


def _subject_tuple(value: Any, label: str = "subject") -> dict[str, Any]:
    row = _closed(value, {"commit", "tree", "subject_manifest_sha256", "version"}, label)
    _hex(row["commit"], 40, f"{label}.commit")
    _hex(row["tree"], 40, f"{label}.tree")
    _hex(row["subject_manifest_sha256"], 64, f"{label}.subject_manifest_sha256")
    if row["version"] != "4.0.0":
        raise PackageGError(f"{label}.version must be 4.0.0")
    return row


def _artifact(value: Any, expected_subject_id: str, ag: dict[str, Any], *, crate: bool) -> dict[str, Any]:
    keys = {
        "acquisition_sha256", "artifact_class", "build_environment_sha256", "path",
        "producer_class", "producer_identity", "provenance_sha256", "role", "sha256",
        "signature_sha256", "size", "subject", "subject_id",
    }
    if crate:
        keys |= {"cargo_vcs_info_sha1", "name", "version"}
    row = _closed(value, keys, f"artifact {expected_subject_id}")
    if row["subject_id"] != expected_subject_id or not identical(row["subject"], ag):
        raise PackageGError(f"artifact {expected_subject_id} subject binding differs")
    _relative_artifact_path(row["path"], f"artifact {expected_subject_id} path")
    _hex(row["sha256"], 64, f"artifact {expected_subject_id} sha256")
    for key in ("acquisition_sha256", "build_environment_sha256", "signature_sha256", "provenance_sha256"):
        _hex(row[key], 64, f"artifact {expected_subject_id} {key}")
    _text(row["producer_identity"], f"artifact {expected_subject_id} producer identity")
    expected_class = dict(SUBJECTS)[expected_subject_id]
    if (
        row["artifact_class"] != expected_class or row["producer_class"] != "first-party"
        or row["role"] != "local-candidate" or not _is_int(row["size"])
        or row["size"] <= 0 or row["size"] > 1024 * 1024 * 1024
    ):
        raise PackageGError(f"artifact {expected_subject_id} size must be positive integer")
    if crate:
        name = expected_subject_id.removeprefix("crate-")
        if row["name"] != name or row["version"] != "4.0.0" or row["cargo_vcs_info_sha1"] != ag["commit"]:
            raise PackageGError(f"crate artifact {expected_subject_id} identity differs")
    return row


def _review(value: Any, ag: dict[str, Any], label: str) -> dict[str, Any]:
    row = _closed(value, {
        "artifact_sha256", "decision", "independent", "review_evidence_sha256", "reviewed_at",
        "reviewer", "reviewed_producer_identities", "subject", "subject_id", "valid_through",
    }, label)
    if row["decision"] != "candidate-unaccepted" or not identical(row["subject"], ag):
        raise PackageGError(f"{label} must remain candidate-unaccepted and exact-subject-bound")
    _text(row["reviewer"], f"{label}.reviewer")
    _date(row["reviewed_at"], f"{label}.reviewed_at")
    _date(row["valid_through"], f"{label}.valid_through")
    _hex(row["artifact_sha256"], 64, f"{label}.artifact_sha256")
    _hex(row["review_evidence_sha256"], 64, f"{label}.review_evidence_sha256")
    producer_identities = row["reviewed_producer_identities"]
    if (
        not isinstance(producer_identities, list) or len(producer_identities) != 2
        or len(set(producer_identities)) != 2
        or any(not isinstance(value, str) or not value for value in producer_identities)
        or row["reviewer"] in producer_identities
        or row["independent"] is not True or row["valid_through"] < row["reviewed_at"]
    ):
        raise PackageGError(f"{label} reviewer independence/date ordering differs")
    for offset, identity in enumerate(producer_identities):
        _text(identity, f"{label}.reviewed_producer_identities[{offset}]")
    return row


def _candidate_common(document: dict[str, Any], phase: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    expected_identity = {
        "content_policy": f"dcrypt-package-g-{phase}-candidate-v1",
        "phase": phase,
        "promotion_eligible": False,
        "role": f"{phase}-candidate",
        "schema_version": 1,
        "status": "candidate-unaccepted-HOLD",
        "trusted": False,
    }
    if any(not identical(document.get(k), v) for k, v in expected_identity.items()):
        raise PackageGError(f"{phase} identity must remain untrusted and nonpromotable")
    ag = _subject_tuple(document["subject"])
    artifacts = document["candidate_artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 18:
        raise PackageGError("candidate artifacts must close exact 18 subjects")
    mapped: dict[str, dict[str, Any]] = {}
    for row, (subject_id, kind) in zip(artifacts, SUBJECTS, strict=True):
        mapped[subject_id] = _artifact(row, subject_id, ag, crate=(kind == "candidate-crate-archive"))
    return ag, mapped


def validate_phase_document(
    document: Any, *, expected_phase: str | None = None,
    lineage_documents: dict[str, Any] | None = None, _skip_lineage: bool = False,
    evaluation_date: dt.date | None = None,
) -> dict[str, Any]:
    if evaluation_date is None:
        evaluation_date = dt.datetime.now(dt.UTC).date()
    if type(evaluation_date) is not dt.date:
        raise PackageGError("evaluation date must be a trusted date")
    if not isinstance(document, dict):
        raise PackageGError("phase document must be an object")
    phase = document.get("phase")
    if phase not in PHASES or (expected_phase is not None and phase != expected_phase):
        raise PackageGError("phase identity differs")
    if phase == "foundation":
        row = _closed(document, {"content_policy", "phase", "promotion_eligible", "role", "schema_version", "status", "trusted"}, "foundation record")
        if not identical(row, foundation_record()):
            raise PackageGError("foundation record differs")
        return row
    base = {
        "candidate_artifacts", "content_policy", "phase", "promotion_eligible", "review_decisions",
        "role", "schema_version", "status", "subject", "trusted", "candidate_set_sha256",
    }
    if phase == "prepublish":
        row = _closed(document, base | {"independent_comparisons", "producer_obligations", "registry"}, "prepublish record")
        if row["role"] != "prepublish-candidate" or not identical(row["registry"], {"artifacts": [], "state": "deferred-empty"}):
            raise PackageGError("prepublish registry must be explicitly deferred and empty")
        ag, artifacts = _candidate_common(row, phase)
        if row["candidate_set_sha256"] != semantic_sha256(row["candidate_artifacts"]):
            raise PackageGError("prepublish candidate-set lineage digest differs")
        obligations = row["producer_obligations"]
        expected_pairs = [(producer, subject_id) for producer in PRODUCERS for subject_id, _kind in SUBJECTS]
        if not isinstance(obligations, list) or len(obligations) != 36:
            raise PackageGError("producer obligations must close exact 36")
        for item, (producer, subject_id) in zip(obligations, expected_pairs, strict=True):
            exact = _closed(item, {
                "accepted", "acquisition_sha256", "artifact_path", "artifact_sha256",
                "build_environment_sha256", "producer_class", "producer_identity", "provenance_sha256",
                "signature_sha256", "status", "subject", "subject_id",
            }, "producer obligation")
            expected = {
                "accepted": False, "artifact_path": exact["artifact_path"], "artifact_sha256": exact["artifact_sha256"],
                "acquisition_sha256": exact["acquisition_sha256"],
                "build_environment_sha256": exact["build_environment_sha256"],
                "producer_class": producer, "producer_identity": exact["producer_identity"],
                "provenance_sha256": exact["provenance_sha256"],
                "signature_sha256": exact["signature_sha256"], "status": "candidate-unaccepted",
                "subject": ag, "subject_id": subject_id,
            }
            if not identical(exact, expected):
                raise PackageGError("producer obligation identity differs")
            _relative_artifact_path(exact["artifact_path"], "producer obligation artifact path")
            _text(exact["producer_identity"], "producer obligation identity")
            for key in ("acquisition_sha256", "artifact_sha256", "build_environment_sha256", "provenance_sha256", "signature_sha256"):
                _hex(exact[key], 64, f"producer obligation {key}")
            if producer == "first-party" and any(exact[left] != artifacts[subject_id][right] for left, right in {
                "acquisition_sha256": "acquisition_sha256", "artifact_sha256": "sha256",
                "artifact_path": "path",
                "build_environment_sha256": "build_environment_sha256", "producer_identity": "producer_identity",
                "provenance_sha256": "provenance_sha256", "signature_sha256": "signature_sha256",
            }.items()):
                raise PackageGError(f"first-party obligation differs from candidate artifact for {subject_id}")
        obligation_map = {(item["producer_class"], item["subject_id"]): item for item in obligations}
        comparisons = row["independent_comparisons"]
        if not isinstance(comparisons, list) or len(comparisons) != 18:
            raise PackageGError("independent comparisons must close exact 18")
        for item, (subject_id, _kind) in zip(comparisons, SUBJECTS, strict=True):
            exact = _closed(item, {
                "accepted", "byte_equal", "first_party_sha256", "independent_sha256",
                "first_party_producer_identity", "independent_producer_identity",
                "review_evidence_sha256", "reviewer", "subject", "subject_id",
            }, "independent comparison")
            if not identical(exact, {
                "accepted": False, "byte_equal": exact["byte_equal"],
                "first_party_sha256": exact["first_party_sha256"], "independent_sha256": exact["independent_sha256"],
                "first_party_producer_identity": exact["first_party_producer_identity"],
                "independent_producer_identity": exact["independent_producer_identity"],
                "review_evidence_sha256": exact["review_evidence_sha256"], "reviewer": exact["reviewer"],
                "subject": ag, "subject_id": subject_id,
            }):
                raise PackageGError("independent comparison identity differs")
            for key in ("first_party_sha256", "independent_sha256", "review_evidence_sha256"):
                _hex(exact[key], 64, f"comparison {subject_id} {key}")
            _text(exact["reviewer"], f"comparison {subject_id} reviewer")
            if (
                exact["first_party_sha256"] != obligation_map[("first-party", subject_id)]["artifact_sha256"]
                or exact["independent_sha256"] != obligation_map[("administratively-independent", subject_id)]["artifact_sha256"]
                or exact["first_party_sha256"] != artifacts[subject_id]["sha256"]
                or exact["first_party_producer_identity"] != obligation_map[("first-party", subject_id)]["producer_identity"]
                or exact["independent_producer_identity"] != obligation_map[("administratively-independent", subject_id)]["producer_identity"]
                or exact["reviewer"] in {exact["first_party_producer_identity"], exact["independent_producer_identity"]}
            ):
                raise PackageGError(f"comparison producer/candidate join differs for {subject_id}")
            if type(exact["byte_equal"]) is not bool or exact["byte_equal"] is not (exact["first_party_sha256"] == exact["independent_sha256"]):
                raise PackageGError(f"comparison {subject_id} factual equality differs")
            if exact["accepted"] is not False:
                raise PackageGError(f"comparison {subject_id} must remain unaccepted in v1")
        review_map = {review["subject_id"]: review for review in row["review_decisions"]}
        for comparison in comparisons:
            review = review_map.get(comparison["subject_id"])
            if review is None or comparison["reviewer"] != review["reviewer"] or comparison["review_evidence_sha256"] != review["review_evidence_sha256"]:
                raise PackageGError(f"comparison/review evidence join differs for {comparison['subject_id']}")
        producer_pairs = _producer_pairs(obligations)
        _validate_reviews(row["review_decisions"], ag, artifacts, evaluation_date=evaluation_date, producer_pairs=producer_pairs)
        return row
    if phase == "registry-prefix":
        row = _closed(document, base | {"prepublish_record_sha256", "prefix_predecessor_sha256", "registry_artifacts"}, "registry-prefix record")
        if row["role"] != "registry-prefix-candidate":
            raise PackageGError("registry-prefix role differs")
        ag, artifacts = _candidate_common(row, phase)
        _hex(row["prepublish_record_sha256"], 64, "registry prefix prepublish lineage")
        _hex(row["prefix_predecessor_sha256"], 64, "registry prefix predecessor lineage")
        if row["candidate_set_sha256"] != semantic_sha256(row["candidate_artifacts"]):
            raise PackageGError("registry prefix candidate-set lineage digest differs")
        _validate_registry(row["registry_artifacts"], ag, artifacts, complete=False)
        if not _skip_lineage:
            producer_pairs = _validate_prefix_lineage(row, lineage_documents, evaluation_date)
        else:
            producer_pairs = _review_pairs(row["review_decisions"])
        _validate_reviews(row["review_decisions"], ag, artifacts, evaluation_date=evaluation_date, producer_pairs=producer_pairs)
        return row
    row = _closed(document, base | {"final_prefix_record_sha256", "prepublish_record_sha256", "downloaded_artifacts", "registry_artifacts"}, "postpublish record")
    if row["role"] != "postpublish-candidate":
        raise PackageGError("postpublish role differs")
    ag, candidates = _candidate_common(row, phase)
    _hex(row["prepublish_record_sha256"], 64, "postpublish prepublish lineage")
    _hex(row["final_prefix_record_sha256"], 64, "postpublish final-prefix lineage")
    if row["candidate_set_sha256"] != semantic_sha256(row["candidate_artifacts"]):
        raise PackageGError("postpublish candidate-set lineage digest differs")
    registry = _validate_registry(row["registry_artifacts"], ag, candidates, complete=True)
    downloads = row["downloaded_artifacts"]
    if not isinstance(downloads, list) or len(downloads) != 12:
        raise PackageGError("postpublish downloaded archives must close exact 12")
    for item, name in zip(downloads, PUBLISH_ORDER, strict=True):
        subject_id = f"crate-{name}"
        downloaded = _downloaded_artifact(item, subject_id, ag, evaluation_date=evaluation_date)
        if downloaded["sha256"] != candidates[subject_id]["sha256"] or downloaded["sha256"] != registry[name]["checksum"]:
            raise PackageGError(f"postpublish three-way digest equality differs for {name}")
    if not _skip_lineage:
        producer_pairs, independent_obligations = _validate_postpublish_lineage(row, lineage_documents, evaluation_date)
    else:
        producer_pairs = _review_pairs(row["review_decisions"])
        independent_obligations = {}
    for item in downloads:
        subject_id = item["subject_id"]
        if subject_id in independent_obligations and (
            item["sha256"] != independent_obligations[subject_id]["artifact_sha256"]
            or item["acquisition_identity"] != independent_obligations[subject_id]["producer_identity"]
            or item["acquisition_provenance_sha256"] != independent_obligations[subject_id]["provenance_sha256"]
        ):
            raise PackageGError(f"downloaded archive does not bind independent producer output for {subject_id}")
    _validate_reviews(row["review_decisions"], ag, candidates, evaluation_date=evaluation_date, producer_pairs=producer_pairs)
    return row


def build_synthetic_records() -> dict[str, Any]:
    """Deterministic untrusted records for parser/schema adversarial tests only."""
    ag = {"commit": "1" * 40, "tree": "2" * 40, "subject_manifest_sha256": "3" * 64, "version": "4.0.0"}
    artifacts: list[dict[str, Any]] = []
    for offset, (subject_id, kind) in enumerate(SUBJECTS, 1):
        row: dict[str, Any] = {
            "acquisition_sha256": f"{offset:064x}", "artifact_class": kind,
            "build_environment_sha256": f"{offset + 100:064x}",
            "path": f"private/candidate/{subject_id}.bin", "producer_class": "first-party",
            "producer_identity": f"first-party-{subject_id}", "provenance_sha256": f"{offset + 200:064x}",
            "role": "local-candidate", "sha256": f"{offset + 300:064x}",
            "signature_sha256": f"{offset + 400:064x}", "size": offset,
            "subject": ag, "subject_id": subject_id,
        }
        if kind == "candidate-crate-archive":
            row |= {"cargo_vcs_info_sha1": ag["commit"], "name": subject_id.removeprefix("crate-"), "version": "4.0.0"}
        artifacts.append(row)
    obligations: list[dict[str, Any]] = []
    for producer in PRODUCERS:
        for offset, ((subject_id, _kind), artifact) in enumerate(zip(SUBJECTS, artifacts, strict=True), 1):
            first_party = producer == "first-party"
            obligations.append({
                "accepted": False,
                "acquisition_sha256": artifact["acquisition_sha256"] if first_party else f"{offset + 500:064x}",
                "artifact_path": artifact["path"] if first_party else f"private/independent/{subject_id}.bin",
                "artifact_sha256": artifact["sha256"],
                "build_environment_sha256": artifact["build_environment_sha256"] if first_party else f"{offset + 600:064x}",
                "producer_class": producer,
                "producer_identity": artifact["producer_identity"] if first_party else f"independent-{subject_id}",
                "provenance_sha256": artifact["provenance_sha256"] if first_party else f"{offset + 700:064x}",
                "signature_sha256": artifact["signature_sha256"] if first_party else f"{offset + 800:064x}",
                "status": "candidate-unaccepted", "subject": ag, "subject_id": subject_id,
            })
    obligation_map = {(row["producer_class"], row["subject_id"]): row for row in obligations}
    comparisons = []
    reviews = []
    for offset, ((subject_id, _kind), artifact) in enumerate(zip(SUBJECTS, artifacts, strict=True), 1):
        first = obligation_map[("first-party", subject_id)]
        independent = obligation_map[("administratively-independent", subject_id)]
        review_evidence = f"{offset + 1000:064x}"
        review_identity = f"subject-reviewer-{offset}"
        comparisons.append({
            "accepted": False, "byte_equal": True,
            "first_party_producer_identity": first["producer_identity"], "first_party_sha256": first["artifact_sha256"],
            "independent_producer_identity": independent["producer_identity"], "independent_sha256": independent["artifact_sha256"],
            "review_evidence_sha256": review_evidence, "reviewer": review_identity,
            "subject": ag, "subject_id": subject_id,
        })
        reviews.append({
            "artifact_sha256": artifact["sha256"], "decision": "candidate-unaccepted", "independent": True,
            "review_evidence_sha256": review_evidence, "reviewed_at": "2026-08-13",
            "reviewer": review_identity,
            "reviewed_producer_identities": [first["producer_identity"], independent["producer_identity"]],
            "subject": ag, "subject_id": subject_id, "valid_through": "2026-11-09",
        })
    prepublish = {
        "candidate_artifacts": artifacts, "candidate_set_sha256": semantic_sha256(artifacts),
        "content_policy": "dcrypt-package-g-prepublish-candidate-v1",
        "independent_comparisons": comparisons, "phase": "prepublish", "producer_obligations": obligations,
        "promotion_eligible": False, "registry": {"artifacts": [], "state": "deferred-empty"},
        "review_decisions": reviews, "role": "prepublish-candidate", "schema_version": 1,
        "status": "candidate-unaccepted-HOLD", "subject": ag, "trusted": False,
    }
    prefix0 = {
        "candidate_artifacts": artifacts, "candidate_set_sha256": semantic_sha256(artifacts),
        "content_policy": "dcrypt-package-g-registry-prefix-candidate-v1", "phase": "registry-prefix",
        "prepublish_record_sha256": semantic_sha256(prepublish), "prefix_predecessor_sha256": semantic_sha256(prepublish),
        "promotion_eligible": False, "registry_artifacts": [], "review_decisions": reviews,
        "role": "registry-prefix-candidate", "schema_version": 1, "status": "candidate-unaccepted-HOLD",
        "subject": ag, "trusted": False,
    }
    prefixes = [prefix0]
    registry_rows: list[dict[str, Any]] = []
    predecessor = semantic_sha256(prefix0)
    for index, name in enumerate(PUBLISH_ORDER, 1):
        registry_rows.append({
            "checksum": artifacts[5 + index - 1]["sha256"], "name": name,
            "prefix_index": index, "registry_version_id": 1000 + index,
            "subject": ag, "unyanked": True, "version": "4.0.0",
        })
        prefix = {
            "candidate_artifacts": artifacts, "candidate_set_sha256": semantic_sha256(artifacts),
            "content_policy": "dcrypt-package-g-registry-prefix-candidate-v1", "phase": "registry-prefix",
            "prepublish_record_sha256": semantic_sha256(prepublish), "prefix_predecessor_sha256": predecessor,
            "promotion_eligible": False, "registry_artifacts": list(registry_rows), "review_decisions": reviews,
            "role": "registry-prefix-candidate", "schema_version": 1, "status": "candidate-unaccepted-HOLD",
            "subject": ag, "trusted": False,
        }
        prefixes.append(prefix)
        predecessor = semantic_sha256(prefix)
    independent = {
        row["subject_id"]: row for row in obligations if row["producer_class"] == "administratively-independent"
    }
    downloads = []
    for index, name in enumerate(PUBLISH_ORDER, 1):
        subject_id = f"crate-{name}"
        obligation = independent[subject_id]
        candidate = artifacts[5 + index - 1]
        downloads.append({
            "acquired_at": "2026-08-13", "acquisition_identity": obligation["producer_identity"],
            "acquisition_provenance_sha256": obligation["provenance_sha256"],
            "cargo_vcs_info_sha1": ag["commit"], "name": name,
            "path": f"private/downloaded/{name}-4.0.0.crate", "sha256": candidate["sha256"],
            "size": candidate["size"], "subject": ag, "subject_id": subject_id, "version": "4.0.0",
        })
    postpublish = {
        "candidate_artifacts": artifacts, "candidate_set_sha256": semantic_sha256(artifacts),
        "content_policy": "dcrypt-package-g-postpublish-candidate-v1", "downloaded_artifacts": downloads,
        "final_prefix_record_sha256": semantic_sha256(prefixes[-1]), "phase": "postpublish",
        "prepublish_record_sha256": semantic_sha256(prepublish), "promotion_eligible": False,
        "registry_artifacts": prefixes[-1]["registry_artifacts"], "review_decisions": reviews,
        "role": "postpublish-candidate", "schema_version": 1, "status": "candidate-unaccepted-HOLD",
        "subject": ag, "trusted": False,
    }
    return {
        "foundation": foundation_record(), "prepublish": prepublish, "prefix0": prefix0,
        "prefixes": prefixes, "postpublish": postpublish,
    }


def _validate_prefix_lineage(row: dict[str, Any], lineage: dict[str, Any] | None, evaluation_date: dt.date | None = None) -> dict[str, tuple[str, str]]:
    if not isinstance(lineage, dict) or set(lineage) != {"prepublish", "prefix_chain"}:
        raise PackageGError("registry prefix requires exact prepublish and predecessor-chain lineage")
    prepublish = validate_phase_document(lineage["prepublish"], expected_phase="prepublish", evaluation_date=evaluation_date)
    if (
        row["prepublish_record_sha256"] != semantic_sha256(prepublish)
        or row["candidate_set_sha256"] != prepublish["candidate_set_sha256"]
        or not identical(row["candidate_artifacts"], prepublish["candidate_artifacts"])
        or not identical(row["review_decisions"], prepublish["review_decisions"])
        or not identical(row["subject"], prepublish["subject"])
    ):
        raise PackageGError("registry prefix prepublish lineage differs")
    chain = lineage["prefix_chain"]
    prefix_length = len(row["registry_artifacts"])
    if not isinstance(chain, list) or len(chain) != prefix_length:
        raise PackageGError("registry prefix predecessor chain length differs")
    predecessor_digest = semantic_sha256(prepublish)
    for expected_length, document in enumerate(chain):
        prior = validate_phase_document(document, expected_phase="registry-prefix", _skip_lineage=True, evaluation_date=evaluation_date)
        if (
            len(prior["registry_artifacts"]) != expected_length
            or prior["prepublish_record_sha256"] != semantic_sha256(prepublish)
            or prior["prefix_predecessor_sha256"] != predecessor_digest
            or prior["candidate_set_sha256"] != prepublish["candidate_set_sha256"]
            or not identical(prior["candidate_artifacts"], prepublish["candidate_artifacts"])
            or not identical(prior["registry_artifacts"], row["registry_artifacts"][:expected_length])
            or not identical(prior["review_decisions"], prepublish["review_decisions"])
            or not identical(prior["subject"], prepublish["subject"])
        ):
            raise PackageGError(f"registry prefix predecessor {expected_length} differs")
        predecessor_digest = semantic_sha256(prior)
    if row["prefix_predecessor_sha256"] != predecessor_digest:
        raise PackageGError("registry prefix immediate predecessor digest differs")
    return _producer_pairs(prepublish["producer_obligations"])


def _validate_postpublish_lineage(row: dict[str, Any], lineage: dict[str, Any] | None, evaluation_date: dt.date | None = None) -> tuple[dict[str, tuple[str, str]], dict[str, dict[str, Any]]]:
    if not isinstance(lineage, dict) or set(lineage) != {"prepublish", "final_prefix", "prefix_chain"}:
        raise PackageGError("postpublish requires exact prepublish and final-prefix lineage")
    prepublish = validate_phase_document(lineage["prepublish"], expected_phase="prepublish", evaluation_date=evaluation_date)
    final_prefix = validate_phase_document(
        lineage["final_prefix"], expected_phase="registry-prefix",
        lineage_documents={"prepublish": prepublish, "prefix_chain": lineage["prefix_chain"]},
        evaluation_date=evaluation_date,
    )
    if (
        len(final_prefix["registry_artifacts"]) != 12
        or row["prepublish_record_sha256"] != semantic_sha256(prepublish)
        or row["final_prefix_record_sha256"] != semantic_sha256(final_prefix)
        or row["candidate_set_sha256"] != prepublish["candidate_set_sha256"]
        or not identical(row["candidate_artifacts"], prepublish["candidate_artifacts"])
        or not identical(row["registry_artifacts"], final_prefix["registry_artifacts"])
        or not identical(row["subject"], prepublish["subject"])
    ):
        raise PackageGError("postpublish phase lineage differs")
    independent = {
        item["subject_id"]: item for item in prepublish["producer_obligations"]
        if item["producer_class"] == "administratively-independent"
    }
    return _producer_pairs(prepublish["producer_obligations"]), independent


def semantic_sha256(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def _downloaded_artifact(value: Any, subject_id: str, ag: dict[str, Any], *, evaluation_date: dt.date) -> dict[str, Any]:
    row = _closed(value, {
        "acquired_at", "acquisition_identity", "acquisition_provenance_sha256", "cargo_vcs_info_sha1",
        "name", "path", "sha256", "size", "subject", "subject_id", "version",
    }, f"downloaded artifact {subject_id}")
    name = subject_id.removeprefix("crate-")
    if (
        row["subject_id"] != subject_id or row["name"] != name or row["version"] != "4.0.0"
        or row["cargo_vcs_info_sha1"] != ag["commit"] or not identical(row["subject"], ag)
        or not _is_int(row["size"]) or row["size"] <= 0 or row["size"] > 1024 * 1024 * 1024
    ):
        raise PackageGError(f"downloaded artifact identity differs for {name}")
    _relative_artifact_path(row["path"], f"downloaded artifact {name} path")
    _hex(row["sha256"], 64, f"downloaded artifact {name} sha256")
    _hex(row["acquisition_provenance_sha256"], 64, f"downloaded artifact {name} provenance")
    _text(row["acquisition_identity"], f"downloaded artifact {name} acquisition identity")
    acquired = _date(row["acquired_at"], f"downloaded artifact {name} acquired_at")
    if acquired > evaluation_date.isoformat():
        raise PackageGError(f"downloaded artifact {name} is future-dated")
    return row


def _validate_registry(value: Any, ag: dict[str, Any], candidates: dict[str, dict[str, Any]], *, complete: bool) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 12 or (complete and len(value) != 12):
        raise PackageGError("registry artifacts must be exact prefix length 0..12")
    mapped: dict[str, dict[str, Any]] = {}
    for index, (row, name) in enumerate(zip(value, PUBLISH_ORDER, strict=False), 1):
        exact = _closed(row, {"checksum", "name", "prefix_index", "registry_version_id", "subject", "unyanked", "version"}, "registry artifact")
        if (
            exact["name"] != name or not _is_int(exact["prefix_index"]) or exact["prefix_index"] != index
            or not _is_int(exact["registry_version_id"]) or exact["registry_version_id"] <= 0
            or not identical(exact["subject"], ag) or exact["unyanked"] is not True or exact["version"] != "4.0.0"
        ):
            raise PackageGError(f"registry artifact identity differs at prefix index {index}")
        _hex(exact["checksum"], 64, f"registry artifact {name} checksum")
        if exact["checksum"] != candidates[f"crate-{name}"]["sha256"]:
            raise PackageGError(f"registry checksum differs from local candidate for {name}")
        if exact["registry_version_id"] in {r["registry_version_id"] for r in mapped.values()}:
            raise PackageGError("registry version IDs must be unique")
        mapped[name] = exact
    return mapped


def _producer_pairs(obligations: list[dict[str, Any]]) -> dict[str, tuple[str, str]]:
    mapped = {(row["producer_class"], row["subject_id"]): row["producer_identity"] for row in obligations}
    result: dict[str, tuple[str, str]] = {}
    for subject_id, _kind in SUBJECTS:
        pair = (mapped[("first-party", subject_id)], mapped[("administratively-independent", subject_id)])
        if pair[0] == pair[1]:
            raise PackageGError(f"producer identities are not independent for {subject_id}")
        result[subject_id] = pair
    return result


def _review_pairs(reviews: list[dict[str, Any]]) -> dict[str, tuple[str, str]]:
    return {row["subject_id"]: tuple(row["reviewed_producer_identities"]) for row in reviews}


def _validate_reviews(value: Any, ag: dict[str, Any], artifacts: dict[str, dict[str, Any]], *, evaluation_date: dt.date, producer_pairs: dict[str, tuple[str, str]]) -> None:
    as_of_date = evaluation_date.isoformat()
    if not isinstance(value, list) or len(value) != 18:
        raise PackageGError("review decisions must close exact 18")
    for row, (subject_id, _kind) in zip(value, SUBJECTS, strict=True):
        decision = _review(row, ag, f"review {subject_id}")
        if (
            decision["subject_id"] != subject_id or decision["artifact_sha256"] != artifacts[subject_id]["sha256"]
            or not identical(decision.get("subject"), ag)
        ):
            raise PackageGError(f"review {subject_id} subject differs")
        if decision["reviewed_at"] > as_of_date:
            raise PackageGError(f"review {subject_id} is future-dated")
        if decision["valid_through"] < as_of_date:
            raise PackageGBlocker(f"review {subject_id} is stale")
        if subject_id not in producer_pairs or tuple(decision["reviewed_producer_identities"]) != producer_pairs[subject_id]:
            raise PackageGError(f"review {subject_id} producer identity closure differs")
        if decision["reviewer"] in producer_pairs[subject_id]:
            raise PackageGError(f"review {subject_id} reviewer is not independent")
    reviewers = [row["reviewer"] for row in value]
    if len(set(reviewers)) != len(reviewers):
        raise PackageGError("reviewer identities must be unique across subject decisions")


def foundation_record() -> dict[str, Any]:
    return {
        "content_policy": "dcrypt-package-g-foundation-record-v1",
        "phase": "foundation", "promotion_eligible": False, "role": "foundation",
        "schema_version": 1, "status": "HOLD", "trusted": False,
    }


def evaluate_foundation_temporal_state(evaluation_date: dt.date | None = None) -> dict[str, Any]:
    """Evaluate pinned antecedent dates using only the verifier's trusted UTC date."""
    if evaluation_date is None:
        evaluation_date = dt.datetime.now(dt.UTC).date()
    if type(evaluation_date) is not dt.date:
        raise PackageGError("foundation evaluation date must be a trusted date")
    deadlines = load_policy()["deadlines"]
    dependency_boundary = dt.date.fromisoformat(deadlines["dependency-exception-reject-on-or-after"])
    ledger_boundary = dt.date.fromisoformat(deadlines["ledger-evidence-valid-through"])
    threat_boundary = dt.date.fromisoformat(deadlines["threat-model-valid-through"])
    historical_deadline = dt.date.fromisoformat(deadlines["historical-advisory-review-deadline"])
    dependency_expired = evaluation_date >= dependency_boundary
    ledger_stale = evaluation_date > ledger_boundary
    threat_stale = evaluation_date > threat_boundary
    blocker_ids = ["historical-advisory-replay-required"]
    if dependency_expired:
        blocker_ids.append("dependency-exception-expired")
    if ledger_stale:
        blocker_ids.append("ledger-evidence-stale")
    if threat_stale:
        blocker_ids.append("threat-model-evidence-stale")
    return {
        "blocker_ids": blocker_ids,
        "dependency_exception": {
            "boundary": dependency_boundary.isoformat(), "expired": dependency_expired,
            "rule": "reject-on-or-after",
        },
        "evaluation_date": evaluation_date.isoformat(),
        "historical_advisory": {
            "expiry_inferred": False, "replay_required": True,
            "review_deadline": historical_deadline.isoformat(),
            "rule": "review-deadline-metadata-no-expiry-invented",
        },
        "ledger_evidence": {
            "stale": ledger_stale, "valid_through": ledger_boundary.isoformat(),
            "rule": "valid-through-inclusive",
        },
        "release_gate": "HOLD",
        "threat_model": {
            "stale": threat_stale, "valid_through": threat_boundary.isoformat(),
            "rule": "valid-through-inclusive",
        },
    }


def build_package_document() -> dict[str, Any]:
    p = load_policy()
    return {
        "acceptance": {"enabled": False, "validation": "always-reject"},
        "artifact_role": "package-g-release-acceptance-foundation",
        "content_policy": p["content-policy"],
        "counts": {
            "antecedents": 8, "artifact_subjects": 18, "independent_comparisons": 18,
            "producer_classes": 2, "producer_obligations": 36, "publishable_packages": 12,
            "release_blocked_rows": 9198,
        },
        "immutable_antecedents": p["antecedent"],
        "immutable_projection": p["immutable-projection"],
        "deadlines": p["deadlines"],
        "phase_order": list(PHASES),
        "publish_order": list(PUBLISH_ORDER),
        "release_state": {
            "promotion_eligible": False, "publish_eligible": False, "release_gate": "HOLD",
            "release_gate_exit_code": 3, "version_preparation_authorized": False,
        },
        "schema_version": 1,
        "scope": p["scope"],
        "status": "pre-version-foundation-active-consumer-wiring",
        "subject_binding": p["topology"],
        "threat_model_dependency": {
            "command": p["release-contract"]["threat-model-release-command"],
            "current_exit_code": 1,
            "known_blocker": {
                "active_mitigations": 0, "candidate_models": 11, "critical_residual": 10,
                "high_residual": 1, "implemented_unverified_mitigations": 9,
                "independent_review_required": 11, "planned_mitigations": 22,
                "verified_mitigations": 0,
            },
            "mapped_release_exit_code": 3,
        },
        "top_level_wiring_deferred": False,
        "trusted": False,
        "versions": {"current": "3.0.0", "target": "4.0.0"},
    }


def build_schema() -> dict[str, Any]:
    """Full recursively closed schemas for every v1 record role."""
    ref_subject = {"$ref": "#/$defs/subject"}
    hex64 = {"$ref": "#/$defs/hex64"}
    safe_path = {"$ref": "#/$defs/safe_path"}
    text = {"type": "string", "minLength": 1, "maxLength": 512}

    def closed(properties: dict[str, Any]) -> dict[str, Any]:
        return {
            "additionalProperties": False, "properties": properties,
            "required": list(properties), "type": "object",
        }

    def tuple_array(items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "items": False, "maxItems": len(items), "minItems": len(items),
            "prefixItems": items, "type": "array",
        }

    def candidate_artifact(subject_id: str, artifact_class: str) -> dict[str, Any]:
        properties: dict[str, Any] = {
            "acquisition_sha256": hex64,
            "artifact_class": {"const": artifact_class},
            "build_environment_sha256": hex64,
            "path": safe_path,
            "producer_class": {"const": "first-party"},
            "producer_identity": text,
            "provenance_sha256": hex64,
            "role": {"const": "local-candidate"},
            "sha256": hex64,
            "signature_sha256": hex64,
            "size": {"type": "integer", "minimum": 1, "maximum": 1073741824},
            "subject": ref_subject,
            "subject_id": {"const": subject_id},
        }
        if artifact_class == "candidate-crate-archive":
            name = subject_id.removeprefix("crate-")
            properties |= {
                "cargo_vcs_info_sha1": {"$ref": "#/$defs/hex40"},
                "name": {"const": name}, "version": {"const": "4.0.0"},
            }
        return closed(properties)

    candidate_items = [candidate_artifact(subject_id, kind) for subject_id, kind in SUBJECTS]

    def obligation(producer: str, subject_id: str) -> dict[str, Any]:
        return closed({
            "accepted": {"const": False}, "acquisition_sha256": hex64,
            "artifact_path": safe_path, "artifact_sha256": hex64,
            "build_environment_sha256": hex64, "producer_class": {"const": producer},
            "producer_identity": text, "provenance_sha256": hex64,
            "signature_sha256": hex64, "status": {"const": "candidate-unaccepted"},
            "subject": ref_subject, "subject_id": {"const": subject_id},
        })

    obligation_items = [
        obligation(producer, subject_id)
        for producer in PRODUCERS for subject_id, _kind in SUBJECTS
    ]

    def comparison(subject_id: str) -> dict[str, Any]:
        return closed({
            "accepted": {"const": False}, "byte_equal": {"type": "boolean"},
            "first_party_sha256": hex64, "independent_sha256": hex64,
            "first_party_producer_identity": text, "independent_producer_identity": text,
            "review_evidence_sha256": hex64, "reviewer": text,
            "subject": ref_subject, "subject_id": {"const": subject_id},
        })

    def review(subject_id: str) -> dict[str, Any]:
        return closed({
            "artifact_sha256": hex64, "decision": {"const": "candidate-unaccepted"},
            "independent": {"const": True}, "review_evidence_sha256": hex64,
            "reviewed_at": {"$ref": "#/$defs/date"}, "reviewer": text,
            "reviewed_producer_identities": {
                "items": text, "maxItems": 2, "minItems": 2, "type": "array", "uniqueItems": True,
            },
            "subject": ref_subject, "subject_id": {"const": subject_id},
            "valid_through": {"$ref": "#/$defs/date"},
        })

    def registry(name: str, index: int) -> dict[str, Any]:
        return closed({
            "checksum": hex64, "name": {"const": name}, "prefix_index": {"const": index, "type": "integer"},
            "registry_version_id": {"type": "integer", "minimum": 1}, "subject": ref_subject,
            "unyanked": {"const": True}, "version": {"const": "4.0.0"},
        })

    def download(name: str) -> dict[str, Any]:
        return closed({
            "acquired_at": {"$ref": "#/$defs/date"}, "acquisition_identity": text,
            "acquisition_provenance_sha256": hex64, "cargo_vcs_info_sha1": {"$ref": "#/$defs/hex40"},
            "name": {"const": name}, "path": safe_path, "sha256": hex64,
            "size": {"type": "integer", "minimum": 1, "maximum": 1073741824},
            "subject": ref_subject, "subject_id": {"const": f"crate-{name}"},
            "version": {"const": "4.0.0"},
        })

    common = {
        "candidate_artifacts": tuple_array(candidate_items), "candidate_set_sha256": hex64,
        "promotion_eligible": {"const": False},
        "review_decisions": tuple_array([review(subject_id) for subject_id, _kind in SUBJECTS]),
        "schema_version": {"const": 1, "type": "integer"},
        "status": {"const": "candidate-unaccepted-HOLD"}, "subject": ref_subject,
        "trusted": {"const": False},
    }
    prepublish = closed(common | {
        "content_policy": {"const": "dcrypt-package-g-prepublish-candidate-v1"},
        "independent_comparisons": tuple_array([comparison(subject_id) for subject_id, _kind in SUBJECTS]),
        "phase": {"const": "prepublish"}, "producer_obligations": tuple_array(obligation_items),
        "registry": closed({"artifacts": tuple_array([]), "state": {"const": "deferred-empty"}}),
        "role": {"const": "prepublish-candidate"},
    })
    prefix = closed(common | {
        "content_policy": {"const": "dcrypt-package-g-registry-prefix-candidate-v1"},
        "phase": {"const": "registry-prefix"}, "prepublish_record_sha256": hex64,
        "prefix_predecessor_sha256": hex64,
        "registry_artifacts": {
            "items": False, "maxItems": 12, "minItems": 0,
            "prefixItems": [registry(name, index) for index, name in enumerate(PUBLISH_ORDER, 1)],
            "type": "array",
        },
        "role": {"const": "registry-prefix-candidate"},
    })
    postpublish = closed(common | {
        "content_policy": {"const": "dcrypt-package-g-postpublish-candidate-v1"},
        "downloaded_artifacts": tuple_array([download(name) for name in PUBLISH_ORDER]),
        "final_prefix_record_sha256": hex64, "phase": {"const": "postpublish"},
        "prepublish_record_sha256": hex64,
        "registry_artifacts": tuple_array([registry(name, index) for index, name in enumerate(PUBLISH_ORDER, 1)]),
        "role": {"const": "postpublish-candidate"},
    })
    foundation_properties = {key: {"const": value} for key, value in foundation_record().items()}
    foundation_properties["schema_version"] = {"const": 1, "type": "integer"}
    foundation_properties["promotion_eligible"] = {"const": False, "type": "boolean"}
    foundation_properties["trusted"] = {"const": False, "type": "boolean"}
    foundation = closed(foundation_properties)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://dcrypt.dev/assurance/release-acceptance/schema-v1.json",
        "$defs": {
            "date": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
            "hex40": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "safe_path": {
                "type": "string", "minLength": 1, "maxLength": 512,
                "pattern": "^(?!/)(?![A-Za-z]:)(?![^/]{256})(?!.*\\/[^/]{256})(?!.*(?:^|/)\\.\\.?(?:/|$))(?!.*\\\\)(?!.*[\\u0000-\\u001f\\u007f])[^/]+(?:/[^/]+)*$",
                "not": {"type": "string", "pattern": "^assurance/release-acceptance/fixtures/"},
            },
            "subject": closed({
                "commit": {"$ref": "#/$defs/hex40"}, "subject_manifest_sha256": {"$ref": "#/$defs/hex64"},
                "tree": {"$ref": "#/$defs/hex40"}, "version": {"const": "4.0.0"},
            }),
        },
        "oneOf": [foundation, prepublish, prefix, postpublish, {"not": {}, "title": "acceptance-disabled-v1"}],
        "title": "dcrypt Package G release-acceptance record",
    }


def artifact_source_files() -> tuple[tuple[str, str, str], ...]:
    """All thirteen non-self files in the exact14 authorized closure."""
    return (
        (".github/workflows/security-validation.yml", "100644", "reviewed-consumer"),
        ("assurance/release-acceptance/README.md", "100644", "reviewed-source"),
        ("assurance/release-acceptance/fixtures/control.json", "100644", "reviewed-source"),
        ("assurance/release-acceptance/generate.py", "100644", "reviewed-source"),
        ("assurance/release-acceptance/model.py", "100644", "reviewed-source"),
        ("assurance/release-acceptance/package-g.json", "100644", "generated"),
        ("assurance/release-acceptance/policy.toml", "100644", "reviewed-source"),
        ("assurance/release-acceptance/schema.json", "100644", "generated"),
        ("assurance/release-acceptance/selftest.py", "100644", "reviewed-source"),
        ("assurance/release-acceptance/verify.py", "100644", "reviewed-source"),
        ("tools/release-dcrypt.sh", "100755", "reviewed-consumer"),
        ("tools/verify-publish-ready.sh", "100755", "reviewed-consumer"),
        ("tools/verify-remote-release-ready.py", "100755", "reviewed-consumer"),
    )
