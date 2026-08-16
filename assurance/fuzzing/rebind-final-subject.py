#!/usr/bin/env python3
"""Review-gated Package C binding refresh and Package-C-era transition checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True


HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FRAMEWORK = Path(__file__).resolve().parent
REPO = FRAMEWORK.parent.parent
MODEL = FRAMEWORK / "fuzzing_lib.py"
MANIFEST = REPO / "assurance/subject-manifest.json"
FINAL_STATUS = "STABLE-final-subject-bound"
NORMALIZED_MODEL_SHA256 = "98a978c646d92588422767c21508684ae98341fb8d6676cab5e5c7246f765256"
ALLOWLISTED_ASSIGNMENTS = (
    "STATUS",
    "FRAMEWORK_SUBJECT_COMMIT",
    "FRAMEWORK_SUBJECT_TREE",
    "FRAMEWORK_SUBJECT_MANIFEST_SHA256",
    "EXPECTED_POLICY_SEMANTIC_SHA256",
    "EXPECTED_REGISTRY_SEMANTIC_SHA256",
)
SUBJECT_ROOT_KEYS = (
    "schema_version",
    "source_commit",
    "source_tree",
    "roots",
    "root_files",
    "absent_build_inputs",
    "include_policy",
    "files",
)
SUBJECT_ROOT_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "CONSTANT_TIME_POLICY.md",
    "README.md",
    "SECURITY.md",
    "deny.toml",
    "implementation-boundary.toml",
)
SUBJECT_ABSENT = (
    ".cargo/config",
    ".cargo/config.toml",
    "build.rs",
    "rust-toolchain",
    "rust-toolchain.toml",
)
SUBJECT_EXCLUDED = {
    ".gitignore",
    "tools/bench-processor/Cargo.lock",
    "tools/cargo_snapshot.sh",
    "tools/codebase_snapshot.sh",
    "tools/codebase_snapshot2.sh",
    "tools/tree.sh",
}

# Exact Package B evidence inventory reviewed in the prior R->A transition.
# Sixteen paths legitimately change when the evidence is refreshed or receives
# a reviewed assurance portability repair against a new R.  Four paths are
# generators/human documentation whose canonical bytes do not depend on the
# subject identity; those four must remain exact R blobs.
# The inventory is therefore deliberately broader than the R..A diff closure.
LEGACY_A_MODES = {
    "assurance/acvp-vector-manifest.json": "100644",
    "assurance/assurance-selftest.py": "100644",
    "assurance/atomic-operations.toml": "100644",
    "assurance/interoperability/matrix.json": "100644",
    "assurance/interoperability/policy.toml": "100644",
    "assurance/interoperability/protocol-specs/ARTIFACTS.sha256": "100644",
    "assurance/interoperability/protocol-specs/CURRENT-BEHAVIOR.md": "100644",
    "assurance/interoperability/protocol-specs/README.md": "100644",
    "assurance/interoperability/protocol-specs/current-behavior.json": "100644",
    "assurance/interoperability/protocol-specs/protocol-specs-selftest.py": "100755",
    "assurance/interoperability/protocol-specs/rebind-final-subject.py": "100755",
    "assurance/interoperability/protocol-specs/verify-protocol-specs.py": "100755",
    "assurance/ledger.toml": "100644",
    "assurance/public-api-snapshot.json": "100644",
    "assurance/subject-manifest.json": "100644",
    "assurance/threat-models/coverage.json": "100644",
    "assurance/threat-models/fixtures/mitigation-evidence-record.json": "100644",
    "assurance/threat-models/fixtures/review-evidence-record.json": "100644",
    "assurance/threat-models/threat-models.toml": "100644",
    "assurance/verify-assurance-ledger.py": "100644",
}
LEGACY_R_INVARIANTS = {
    "assurance/assurance-selftest.py": ("100644", "a162dd46408b9c9d81df0546d86d9bf8647f77f9c36affd153ad1303cd0694d8"),
    "assurance/atomic-operations.toml": ("100644", "1177eea6ff7fb48b8e3b7fc49f83da47d50949b724711331f4faf25311b56c3c"),
    "assurance/interoperability/protocol-specs/README.md": ("100644", "8b10fc6d61614dba0b95e4bb085324ac5bbc2ed63959822441ec3a4f34f407c8"),
    "assurance/verify-assurance-ledger.py": ("100644", "d6ece912e9ac62ded409a005d7ad5580cb40644cd0c8fff594e91ee3382f8dcd"),
}
LEGACY_CHANGED_A_MODES = {
    path: mode for path, mode in LEGACY_A_MODES.items() if path not in LEGACY_R_INVARIANTS
}
LEGACY_CHANGED_A_SHA256 = {
    "assurance/acvp-vector-manifest.json": "e24ee2f65e724c4c02fd03fbe9275223c0861dcc6e1cf2fba38a1a444c0685b6",
    "assurance/interoperability/matrix.json": "e8d8ff608404e58ddf1803cf632c7f561f1177cf2d684e543ba159da3ee5f1f7",
    "assurance/interoperability/policy.toml": "8c3930670d8e7ab959571c79ce82020bcd1e971650283c74b8d0aeec4ee5325a",
    "assurance/interoperability/protocol-specs/ARTIFACTS.sha256": "1addadc9add3a177c1b89a1e44856b55954de99b1b13d0130b6b11346c7b6153",
    "assurance/interoperability/protocol-specs/CURRENT-BEHAVIOR.md": "7f99c0e7e1a5c96ff72011ac67003192e53bd9ba357bd763f34d80fcc851b0ce",
    "assurance/interoperability/protocol-specs/current-behavior.json": "92d5e9e55fb432e56edf431a929bce52858a336d5a1678a2b488c2ceb6876233",
    "assurance/interoperability/protocol-specs/protocol-specs-selftest.py": "49a93cb150b45c34fdc1c808b8b1d5559c57ea74c3105e072a596d08053aeeed",
    "assurance/interoperability/protocol-specs/rebind-final-subject.py": "3cd6b84b34f7f7a2152ae83aa308729661fc1a4166795f9de0c9592bf95ab5d4",
    "assurance/interoperability/protocol-specs/verify-protocol-specs.py": "9178c8a3ec20c8edef3b13d93269efd8d0b2cdc9eeee154608b1ca94b5a58dde",
    "assurance/ledger.toml": "4938e362868be5fca790ed826fc23edb35172e0895292f557cb17a1e3b448e8e",
    "assurance/public-api-snapshot.json": "55143c0fd62d4e616cc32dfb7c4d2f94ac59521dabcabbbe7c178687d0465c14",
    "assurance/threat-models/coverage.json": "221c883a24fcddcef50fd5668a402008db0782ae61e73ccf50f5983e76c52fa6",
    "assurance/threat-models/fixtures/mitigation-evidence-record.json": "2dc7ce6ec57d8324b35186ec0bce7447903dd69b41de69b13e278cd85400c55c",
    "assurance/threat-models/fixtures/review-evidence-record.json": "1eedc1c1fb078e63432c9678372cf26478b11a95456e0e2769305ce2dbdd0a34",
    "assurance/threat-models/threat-models.toml": "21b2093d6e171da71a9cd799968147ef7f74e1ef4cabf1e545aeb8c6dca90082",
}
LEGACY_A_SHA256 = {
    path: (
        "VERIFIED-R-SUBJECT-MANIFEST"
        if path == "assurance/subject-manifest.json"
        else LEGACY_R_INVARIANTS[path][1]
        if path in LEGACY_R_INVARIANTS
        else LEGACY_CHANGED_A_SHA256[path]
    )
    for path in LEGACY_A_MODES
}
PACKAGE_C_RELATIVE_PATHS = (
    "ARTIFACTS.json",
    "README.md",
    "ROW-COVERAGE.md",
    "campaign-status.json",
    "compiler_probe.py",
    "corpus-manifest.json",
    "crash-bundle-template.json",
    "crash-lifecycle-status.json",
    "crash_lifecycle.py",
    "fuzzing_lib.py",
    "generate.py",
    "local-sanitizer-requirements.json",
    "policy.json",
    "rebind-final-subject.py",
    "row-mapping.json",
    "run-fuzz-smoke.py",
    "sanitizer-controls.json",
    "sanitizer_positive.py",
    "schemas.py",
    "schemas/artifacts.schema.json",
    "schemas/campaign-status.schema.json",
    "schemas/corpus-manifest.schema.json",
    "schemas/crash-bundle-template.schema.json",
    "schemas/crash-lifecycle-status.schema.json",
    "schemas/local-sanitizer-requirements.schema.json",
    "schemas/policy.schema.json",
    "schemas/row-mapping.schema.json",
    "schemas/sanitizer-controls.schema.json",
    "schemas/source-bindings.schema.json",
    "schemas/target-registry.schema.json",
    "select-fuzz-targets.py",
    "selftest.py",
    "source-bindings.json",
    "target-registry.json",
    "verify.py",
)
PACKAGE_C_MODES = {f"assurance/fuzzing/{path}": "100644" for path in PACKAGE_C_RELATIVE_PATHS}
PACKAGE_D_REFRESH_RELATIVE_PATHS = (
    "ARTIFACTS.json",
    "campaign-status.json",
    "corpus-manifest.json",
    "fuzzing_lib.py",
    "policy.json",
    "rebind-final-subject.py",
    "row-mapping.json",
    "source-bindings.json",
)
PACKAGE_D_REFRESH_MODES = {
    f"assurance/fuzzing/{path}": "100644"
    for path in PACKAGE_D_REFRESH_RELATIVE_PATHS
}
PACKAGE_D_REFRESH_PATHS = tuple(sorted(PACKAGE_D_REFRESH_MODES))
PACKAGE_D_INVARIANT_PATHS = tuple(
    sorted(set(PACKAGE_C_MODES) - set(PACKAGE_D_REFRESH_MODES))
)
PACKAGE_E_CHANGED_RELATIVE_PATHS = (
    "ARTIFACTS.json",
    "README.md",
    "ROW-COVERAGE.md",
    "campaign-status.json",
    "corpus-manifest.json",
    "fuzzing_lib.py",
    "policy.json",
    "rebind-final-subject.py",
    "row-mapping.json",
    "selftest.py",
    "source-bindings.json",
    "verify.py",
)
PACKAGE_E_CHANGED_PATHS = tuple(
    sorted(f"assurance/fuzzing/{path}" for path in PACKAGE_E_CHANGED_RELATIVE_PATHS)
)
PACKAGE_E_INVARIANT_PATHS = tuple(
    sorted(set(PACKAGE_C_MODES) - set(PACKAGE_E_CHANGED_PATHS))
)
PACKAGE_E_CONTROL_PATHS = (
    ".github/workflows/security-validation.yml",
    "tools/release-dcrypt.sh",
    "tools/verify-publish-ready.sh",
    "tools/verify-remote-release-ready.py",
)
PACKAGE_F_CHANGED_PATHS = tuple(sorted((
    *PACKAGE_D_REFRESH_PATHS,
    "assurance/fuzzing/selftest.py",
)))
PACKAGE_F_INVARIANT_PATHS = tuple(
    sorted(set(PACKAGE_C_MODES) - set(PACKAGE_F_CHANGED_PATHS))
)
PACKAGE_F_CONTROL_PATHS = PACKAGE_E_CONTROL_PATHS
PACKAGE_E_A_COMMIT = "86a907154c1f8211a1775c1da8186b71a704536f"
KNOWN_A_MODES = {**LEGACY_A_MODES, **PACKAGE_C_MODES}
KNOWN_A_PATHS = tuple(sorted(KNOWN_A_MODES))
EXPECTED_CHANGED_A_MODES = {**LEGACY_CHANGED_A_MODES, **PACKAGE_C_MODES}
EXPECTED_CHANGED_A_PATHS = tuple(sorted(EXPECTED_CHANGED_A_MODES))
LEGACY_R_INVARIANT_PATHS = tuple(sorted(LEGACY_R_INVARIANTS))
if (
    len(KNOWN_A_PATHS) != 55
    or len(EXPECTED_CHANGED_A_PATHS) != 51
    or len(LEGACY_R_INVARIANT_PATHS) != 4
    or set(EXPECTED_CHANGED_A_PATHS) | set(LEGACY_R_INVARIANT_PATHS) != set(KNOWN_A_PATHS)
    or set(EXPECTED_CHANGED_A_PATHS) & set(LEGACY_R_INVARIANT_PATHS)
    or set(LEGACY_CHANGED_A_SHA256)
    != set(LEGACY_CHANGED_A_MODES) - {"assurance/subject-manifest.json"}
    or len(LEGACY_A_SHA256) != 20
    or len(PACKAGE_D_REFRESH_PATHS) != 8
    or len(PACKAGE_D_INVARIANT_PATHS) != 27
    or not set(PACKAGE_D_REFRESH_PATHS).issubset(PACKAGE_C_MODES)
    or set(PACKAGE_D_REFRESH_PATHS) & set(PACKAGE_D_INVARIANT_PATHS)
    or len(PACKAGE_F_CHANGED_PATHS) != 9
    or len(PACKAGE_F_INVARIANT_PATHS) != 26
    or set(PACKAGE_F_CHANGED_PATHS) | set(PACKAGE_F_INVARIANT_PATHS)
    != set(PACKAGE_C_MODES)
    or set(PACKAGE_F_CHANGED_PATHS) & set(PACKAGE_F_INVARIANT_PATHS)
    or set(PACKAGE_D_REFRESH_PATHS) | set(PACKAGE_D_INVARIANT_PATHS)
    != set(PACKAGE_C_MODES)
    or len(PACKAGE_E_CHANGED_PATHS) != 12
    or len(PACKAGE_E_INVARIANT_PATHS) != 23
    or set(PACKAGE_E_CHANGED_PATHS) | set(PACKAGE_E_INVARIANT_PATHS)
    != set(PACKAGE_C_MODES)
    or set(PACKAGE_E_CHANGED_PATHS) & set(PACKAGE_E_INVARIANT_PATHS)
    or sum(value == "UNSTABLE" for value in LEGACY_A_SHA256.values()) != 0
):
    raise RuntimeError("reviewed A inventory/change/invariant partition differs")
PROTECTED_GITIGNORE = ".gitignore"
PROTECTED_GITIGNORE_WORKTREE_SHA256 = "cd5ef958d591174e93055245095fac5bd4c9f850367dc8960c6f7a6b022d96a9"
PROTECTED_GITIGNORE_DIFF_SHA256 = "47269b979e37e0dd4eaa655183ca1fefe6acb5a6b9c431eb28996cea6ff3fa57"
PROTECTED_GITIGNORE_COMMITTED_SHA256 = "da0952514f101a75710cb7a7dc9e7b060e386c9c587b7351f120104309e75564"


@dataclass(frozen=True)
class FileSnapshot:
    raw: bytes
    mode: int


class RebindError(RuntimeError):
    """A final-subject transition violated its exact reviewed contract."""


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_absolute_regular_once(path: Path, *, label: str) -> tuple[bytes, os.stat_result]:
    """Read one stable regular file exactly once through an O_NOFOLLOW descriptor."""

    try:
        before = path.lstat()
    except OSError as error:
        raise RebindError(f"cannot stat {label}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o002
        or before.st_mode & 0o7000
    ):
        raise RebindError(f"{label} is not a safe single-link regular file")
    identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != identity:
            raise RebindError(f"{label} changed before descriptor read")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != identity:
            raise RebindError(f"{label} changed during descriptor read")
        raw = b"".join(chunks)
        if len(raw) != before.st_size:
            raise RebindError(f"{label} size changed during descriptor read")
        return raw, before
    except OSError as error:
        raise RebindError(f"cannot safely read {label}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _git(arguments: list[str], *, binary: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", *arguments],
        cwd=REPO,
        capture_output=True,
        timeout=60,
        text=not binary,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
    )


def _subject_path(path: str) -> bool:
    return path not in SUBJECT_EXCLUDED and path != "assurance" and not path.startswith("assurance/")


def _safe_path(value: str) -> None:
    pure = PurePosixPath(value)
    if not value or pure.is_absolute() or ".." in pure.parts or "." in pure.parts or pure.as_posix() != value or "\\" in value:
        raise RebindError(f"noncanonical subject path: {value!r}")


def _strict_json_bytes(raw: bytes, *, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RebindError(f"{label} is not strict JSON") from error
    expected = (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=False) + "\n").encode("utf-8")
    if raw != expected:
        raise RebindError(f"{label} is not canonical generator-form JSON")
    return value


def _strict_json(path: Path) -> tuple[Any, bytes]:
    raw, _metadata = _read_absolute_regular_once(path, label="subject manifest")
    return _strict_json_bytes(raw, label="subject manifest"), raw


def _tree_entries(commit: str) -> dict[str, tuple[str, str]]:
    result = _git(["ls-tree", "-r", "-z", "--full-tree", commit], binary=True)
    if result.returncode != 0:
        raise RebindError("cannot enumerate exact R subject tree")
    entries: dict[str, tuple[str, str]] = {}
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            metadata, encoded_path = raw.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = encoded_path.decode("utf-8")
        except (UnicodeError, ValueError) as error:
            raise RebindError("R subject tree contains a malformed Git entry") from error
        _safe_path(path)
        if not _subject_path(path):
            continue
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise RebindError(f"R subject contains a non-regular entry: {path}")
        entries[path] = (mode, object_id)
    return entries


def _blob_sha256s(object_ids: list[str]) -> dict[str, str]:
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=REPO,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise RebindError("cannot open Git blob verification pipes")
    digests: dict[str, str] = {}
    try:
        for object_id in sorted(set(object_ids)):
            process.stdin.write((object_id + "\n").encode("ascii"))
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii", errors="strict").rstrip("\n").split(" ")
            if len(header) != 3 or header[:2] != [object_id, "blob"]:
                raise RebindError("unexpected Git blob header")
            remaining = int(header[2])
            digest = hashlib.sha256()
            while remaining:
                chunk = process.stdout.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise RebindError("truncated Git blob")
                digest.update(chunk)
                remaining -= len(chunk)
            if process.stdout.read(1) != b"\n":
                raise RebindError("invalid Git blob delimiter")
            digests[object_id] = digest.hexdigest()
        process.stdin.close()
        if process.stdout.read(1) != b"":
            raise RebindError("trailing Git blob output")
        stderr = process.stderr.read()
        if process.wait(timeout=30) != 0:
            raise RebindError(f"Git blob verification failed: {stderr.decode('utf-8', 'replace')}")
    except BaseException:
        process.kill()
        process.wait()
        raise
    return digests


def verify_subject_manifest_bytes(manifest_raw: bytes, commit: str, tree: str) -> str:
    manifest = _strict_json_bytes(manifest_raw, label="subject manifest")
    if not isinstance(manifest, dict) or tuple(manifest) != SUBJECT_ROOT_KEYS:
        raise RebindError("subject manifest root closure/order differs")
    if (
        manifest["schema_version"] != 1
        or manifest["source_commit"] != commit
        or manifest["source_tree"] != tree
        or manifest["roots"] != ["."]
        or manifest["root_files"] != list(SUBJECT_ROOT_FILES)
        or manifest["absent_build_inputs"] != list(SUBJECT_ABSENT)
        or manifest["include_policy"] != "production-and-evidence-v1"
    ):
        raise RebindError("subject manifest does not bind the exact reviewed R identity/scope")
    entries = _tree_entries(commit)
    rows = manifest["files"]
    if not isinstance(rows, list):
        raise RebindError("subject manifest files is not an array")
    declared: dict[str, tuple[str, str]] = {}
    order: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or tuple(row) != ("path", "sha256", "git_mode"):
            raise RebindError("subject manifest row closure/order differs")
        path, digest, mode = row["path"], row["sha256"], row["git_mode"]
        if not isinstance(path, str):
            raise RebindError("subject manifest path is not a string")
        _safe_path(path)
        if not _subject_path(path) or not isinstance(digest, str) or HEX64.fullmatch(digest) is None or mode not in {"100644", "100755"} or path in declared:
            raise RebindError("subject manifest row identity/type differs")
        declared[path] = (digest, mode)
        order.append(path)
    if order != sorted(order) or set(declared) != set(entries):
        raise RebindError("subject manifest is not the complete sorted R non-assurance closure")
    blobs = _blob_sha256s([object_id for _mode, object_id in entries.values()])
    for path, (digest, mode) in declared.items():
        actual_mode, object_id = entries[path]
        if mode != actual_mode or digest != blobs[object_id]:
            raise RebindError(f"subject manifest row differs from immutable R blob: {path}")
    return sha256_bytes(manifest_raw)


def verify_subject_manifest(commit: str, tree: str) -> str:
    _manifest, manifest_raw = _strict_json(MANIFEST)
    return verify_subject_manifest_bytes(manifest_raw, commit, tree)


def _assignment(source: str, name: str) -> str:
    match = re.search(rf'^{re.escape(name)} = "([^"\n]*)"$', source, re.MULTILINE)
    if match is None:
        raise RebindError(f"model assignment anchor is absent/nonunique: {name}")
    return match.group(1)


def _replace_assignment(source: str, name: str, value: str) -> str:
    result, count = re.subn(
        rf'^{re.escape(name)} = "[^"\n]*"$',
        f'{name} = "{value}"',
        source,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise RebindError(f"model assignment anchor is absent/nonunique: {name}")
    return result


def normalized_model_sha256(source: str) -> str:
    normalized = source
    for name in ALLOWLISTED_ASSIGNMENTS:
        normalized = _replace_assignment(normalized, name, "<FINAL-SUBJECT-BINDING>")
    return sha256_bytes(normalized.encode("utf-8"))


def _semantic_digests(source: str) -> tuple[str, str]:
    namespace: dict[str, Any] = {"__file__": str(MODEL), "__name__": "dcrypt_fuzzing_rebind_candidate"}
    exec(compile(source, str(MODEL), "exec"), namespace)
    return namespace["policy_semantic_sha256"](), namespace["registry_semantic_sha256"]()


def build_candidate_source(source: str, *, commit: str, tree: str, manifest_sha256: str) -> str:
    if NORMALIZED_MODEL_SHA256 == "UNSTABLE" or normalized_model_sha256(source) != NORMALIZED_MODEL_SHA256:
        raise RebindError("normative model differs outside the exact subject-binding allowlist")
    if HEX40.fullmatch(commit) is None or HEX40.fullmatch(tree) is None or HEX64.fullmatch(manifest_sha256) is None:
        raise RebindError("candidate subject identity is malformed")
    values = {name: _assignment(source, name) for name in ALLOWLISTED_ASSIGNMENTS}
    unstable = {
        "STATUS": "UNSTABLE-awaiting-final-subject-binding",
        "FRAMEWORK_SUBJECT_COMMIT": "UNSTABLE",
        "FRAMEWORK_SUBJECT_TREE": "UNSTABLE",
        "FRAMEWORK_SUBJECT_MANIFEST_SHA256": "UNSTABLE",
    }
    bound = {
        "STATUS": FINAL_STATUS,
        "FRAMEWORK_SUBJECT_COMMIT": commit,
        "FRAMEWORK_SUBJECT_TREE": tree,
        "FRAMEWORK_SUBJECT_MANIFEST_SHA256": manifest_sha256,
    }
    if {name: values[name] for name in unstable} not in (unstable, bound):
        raise RebindError("model contains a partial or differently bound subject state")
    candidate = source
    for name, value in bound.items():
        candidate = _replace_assignment(candidate, name, value)
    candidate = _replace_assignment(candidate, "EXPECTED_POLICY_SEMANTIC_SHA256", "0" * 64)
    candidate = _replace_assignment(candidate, "EXPECTED_REGISTRY_SEMANTIC_SHA256", "0" * 64)
    policy_digest, registry_digest = _semantic_digests(candidate)
    candidate = _replace_assignment(candidate, "EXPECTED_POLICY_SEMANTIC_SHA256", policy_digest)
    candidate = _replace_assignment(candidate, "EXPECTED_REGISTRY_SEMANTIC_SHA256", registry_digest)
    if _semantic_digests(candidate) != (policy_digest, registry_digest):
        raise RebindError("candidate semantic pin fixed point differs")
    if normalized_model_sha256(candidate) != NORMALIZED_MODEL_SHA256:
        raise RebindError("candidate changed model bytes outside the subject-binding allowlist")
    return candidate


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _decode_paths(raw: bytes, *, label: str) -> list[str]:
    try:
        values = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    except UnicodeError as error:
        raise RebindError(f"{label} contains a non-UTF-8 path") from error
    for value in values:
        _safe_path(value)
    if len(values) != len(set(values)):
        raise RebindError(f"{label} contains duplicate paths")
    return values


def _resolve_r_identity(commit: str, tree: str) -> None:
    resolved_commit = _git(["rev-parse", "--verify", f"{commit}^{{commit}}"])
    resolved_tree = _git(["rev-parse", "--verify", f"{commit}^{{tree}}"])
    if resolved_commit.returncode != 0 or resolved_commit.stdout.strip() != commit:
        raise RebindError("explicit R commit is absent or does not resolve exactly")
    if resolved_tree.returncode != 0 or resolved_tree.stdout.strip() != tree:
        raise RebindError("explicit R tree does not match the reviewed R commit")


def _head() -> str:
    result = _git(["rev-parse", "--verify", "HEAD"])
    value = result.stdout.strip() if result.returncode == 0 else ""
    if HEX40.fullmatch(value) is None:
        raise RebindError("cannot resolve one exact HEAD commit")
    return value


def _git_entry(revision: str, path: str) -> tuple[str, str] | None:
    _safe_path(path)
    result = _git(["ls-tree", "-z", "--full-tree", revision, "--", path], binary=True)
    if result.returncode != 0:
        raise RebindError(f"cannot inspect committed path: {path}")
    records = [record for record in result.stdout.split(b"\0") if record]
    if not records:
        return None
    if len(records) != 1:
        raise RebindError(f"committed path is ambiguous: {path}")
    try:
        metadata, encoded_path = records[0].split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        actual_path = encoded_path.decode("utf-8")
    except (UnicodeError, ValueError) as error:
        raise RebindError(f"malformed committed path record: {path}") from error
    if actual_path != path or object_type != "blob" or mode not in {"100644", "100755"}:
        raise RebindError(f"committed path is not an exact regular blob: {path}")
    return mode, object_id


def _git_blob(revision: str, path: str) -> tuple[str, bytes]:
    entry = _git_entry(revision, path)
    if entry is None:
        raise RebindError(f"required committed path is absent: {path}")
    mode, object_id = entry
    result = _git(["cat-file", "blob", object_id], binary=True)
    if result.returncode != 0:
        raise RebindError(f"cannot read committed blob: {path}")
    return mode, result.stdout


def _read_worktree_regular(path: str, expected_mode: str) -> tuple[bytes, int]:
    _safe_path(path)
    absolute = REPO / path
    try:
        before = absolute.lstat()
    except OSError as error:
        raise RebindError(f"cannot stat A candidate path {path}: {error}") from error
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_nlink != 1:
        raise RebindError(f"A candidate must be a single-link regular file: {path}")
    mode = stat.S_IMODE(before.st_mode)
    allowed_modes = (
        {0o600, 0o640, 0o644, 0o660, 0o664}
        if expected_mode == "100644"
        else {0o700, 0o750, 0o755, 0o770, 0o775}
    )
    if mode not in allowed_modes or mode & 0o002 or mode & 0o7000:
        raise RebindError(f"A candidate filesystem mode differs from Git {expected_mode}: {path}")
    descriptor = -1
    try:
        descriptor = os.open(absolute, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        identity = (
            before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
            before.st_size, before.st_mtime_ns, before.st_ctime_ns,
        )
        if (
            opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink,
            opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns,
        ) != identity:
            raise RebindError(f"A candidate path changed before descriptor read: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
            after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        ) != identity:
            raise RebindError(f"A candidate path changed while read: {path}")
        raw = b"".join(chunks)
        if len(raw) != before.st_size:
            raise RebindError(f"A candidate size changed while read: {path}")
        return raw, mode
    except OSError as error:
        raise RebindError(f"cannot safely read A candidate path {path}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def validate_legacy_r_invariant_rows(rows: list[dict[str, Any]]) -> None:
    """Validate the exact reviewed projection of the four immutable R files."""

    if [row.get("path") for row in rows] != list(LEGACY_R_INVARIANT_PATHS):
        raise RebindError("legacy R invariant path order/closure differs")
    for row in rows:
        if set(row) != {"git_mode", "path", "sha256", "size"}:
            raise RebindError("legacy R invariant row field closure differs")
        path = row["path"]
        expected_mode, expected_sha256 = LEGACY_R_INVARIANTS[path]
        if (
            row["git_mode"] != expected_mode
            or row["sha256"] != expected_sha256
            or not isinstance(row["size"], int)
            or isinstance(row["size"], bool)
            or row["size"] < 0
        ):
            raise RebindError(f"legacy R invariant identity differs: {path}")


def _verify_legacy_r_invariants(
    r_commit: str, *, candidate_revision: str | None = None
) -> list[dict[str, Any]]:
    """Prove invariant worktree/A bytes are the exact code-pinned R blobs."""

    rows: list[dict[str, Any]] = []
    for path in LEGACY_R_INVARIANT_PATHS:
        expected_mode, _expected_sha256 = LEGACY_R_INVARIANTS[path]
        r_mode, r_raw = _git_blob(r_commit, path)
        worktree_raw, _filesystem_mode = _read_worktree_regular(path, expected_mode)
        if r_mode != expected_mode or worktree_raw != r_raw:
            raise RebindError(f"legacy invariant differs from immutable R blob: {path}")
        if candidate_revision is not None:
            a_mode, a_raw = _git_blob(candidate_revision, path)
            if a_mode != r_mode or a_raw != r_raw:
                raise RebindError(f"legacy invariant was fabricated into R..A: {path}")
        rows.append(
            {
                "git_mode": r_mode,
                "path": path,
                "sha256": sha256_bytes(r_raw),
                "size": len(r_raw),
            }
        )
    validate_legacy_r_invariant_rows(rows)
    return rows


def validate_protected_gitignore_projection(
    *,
    current: bytes,
    committed: bytes,
    difference: bytes,
    committed_mode: str,
    staged: bool,
) -> None:
    if (
        not isinstance(current, bytes)
        or not isinstance(committed, bytes)
        or not isinstance(difference, bytes)
        or committed_mode != "100644"
        or sha256_bytes(current) != PROTECTED_GITIGNORE_WORKTREE_SHA256
        or current == committed
        or sha256_bytes(difference) != PROTECTED_GITIGNORE_DIFF_SHA256
        or staged
    ):
        raise RebindError("protected dirty .gitignore bytes/mode/diff/index state differ")


def validate_gitignore_topology_projection(
    *,
    current: bytes,
    committed: bytes,
    difference: bytes,
    committed_mode: str,
    staged: bool,
) -> str:
    if current == committed and difference == b"":
        if (
            committed_mode != "100644"
            or sha256_bytes(current) != PROTECTED_GITIGNORE_COMMITTED_SHA256
            or staged
        ):
            raise RebindError("clean replay .gitignore bytes/mode/index state differ")
        return "clean-replay"
    validate_protected_gitignore_projection(
        current=current,
        committed=committed,
        difference=difference,
        committed_mode=committed_mode,
        staged=staged,
    )
    return "protected-dirty-shared-workspace"


def validate_post_a_dirty_paths(paths: list[str]) -> str:
    if paths == []:
        return "clean-replay"
    if paths == [PROTECTED_GITIGNORE]:
        return "protected-dirty-shared-workspace"
    raise RebindError("post-A worktree must be clean or contain only the exact protected dirty .gitignore")


def _verify_gitignore_topology(revision: str) -> tuple[str, str]:
    mode, committed = _git_blob(revision, PROTECTED_GITIGNORE)
    current, _filesystem_mode = _read_worktree_regular(PROTECTED_GITIGNORE, "100644")
    difference = _git(["diff", "--binary", revision, "--", PROTECTED_GITIGNORE], binary=True)
    if difference.returncode != 0:
        raise RebindError("cannot inspect protected .gitignore diff")
    variant = validate_gitignore_topology_projection(
        current=current,
        committed=committed,
        difference=difference.stdout,
        committed_mode=mode,
        staged=PROTECTED_GITIGNORE in _staged_paths(),
    )
    return sha256_bytes(current), variant


def _verify_protected_gitignore(revision: str) -> str:
    digest, variant = _verify_gitignore_topology(revision)
    if variant != "protected-dirty-shared-workspace":
        raise RebindError("pre-A transaction requires the exact protected dirty .gitignore")
    return digest


def _assert_protected_gitignore_unchanged(
    revision: str, *, expected_sha256: str, expected_variant: str
) -> None:
    digest, variant = _verify_gitignore_topology(revision)
    if digest != expected_sha256 or variant != expected_variant:
        raise RebindError("protected .gitignore changed during framework execution")


def _staged_paths() -> list[str]:
    result = _git(["diff", "--cached", "--name-only", "-z", "--", "."], binary=True)
    if result.returncode != 0:
        raise RebindError("cannot inspect staged path closure")
    return _decode_paths(result.stdout, label="staged path closure")


def _working_a_paths() -> list[str]:
    changed = _git(["diff", "--name-only", "-z", "HEAD", "--", "."], binary=True)
    untracked = _git(["ls-files", "--others", "--exclude-standard", "-z", "--", "."], binary=True)
    ignored_assurance = _git(
        ["ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", "assurance"],
        binary=True,
    )
    if changed.returncode != 0 or untracked.returncode != 0 or ignored_assurance.returncode != 0:
        raise RebindError("cannot inspect working A closure")
    paths = _decode_paths(changed.stdout, label="tracked working A closure") + _decode_paths(
        untracked.stdout, label="untracked working A closure"
    ) + _decode_paths(
        ignored_assurance.stdout, label="ignored assurance working A closure"
    )
    if len(paths) != len(set(paths)):
        raise RebindError("working A closure contains overlapping tracked/untracked paths")
    return sorted(path for path in paths if path != PROTECTED_GITIGNORE)


def validate_exact_changed_a_paths(observed: list[str]) -> None:
    if observed != list(EXPECTED_CHANGED_A_PATHS):
        raise RebindError(
            "R..A changed path closure differs: "
            f"missing={sorted(set(EXPECTED_CHANGED_A_PATHS)-set(observed))}, "
            f"surplus={sorted(set(observed)-set(EXPECTED_CHANGED_A_PATHS))}"
        )


def validate_exact_package_d_refresh_paths(observed: list[str]) -> None:
    """Validate only Package C's reviewed eight-path Package D refresh slice."""

    if observed != list(PACKAGE_D_REFRESH_PATHS):
        raise RebindError(
            "Package D subordinate Package C refresh closure differs: "
            f"missing={sorted(set(PACKAGE_D_REFRESH_PATHS)-set(observed))}, "
            f"surplus={sorted(set(observed)-set(PACKAGE_D_REFRESH_PATHS))}"
        )


def package_d_refresh_projection(
    *,
    expected_r_commit: str,
    expected_r_tree: str,
    candidate_revision: str | None = None,
) -> dict[str, Any]:
    """Return the exact Package C sub-projection for Package D's topology authority.

    This intentionally does not make a claim about the other Package D A paths.
    The Package D rebind owns the full R_D..A_D closure and sole-parent check.
    """

    _resolve_r_identity(expected_r_commit, expected_r_tree)
    if candidate_revision is not None:
        manifest_mode, manifest_raw = _git_blob(
            candidate_revision, "assurance/subject-manifest.json"
        )
        if manifest_mode != "100644":
            raise RebindError("Package D subject manifest Git mode differs")
    else:
        manifest_raw = _read_worktree_regular(
            "assurance/subject-manifest.json", "100644"
        )[0]
    manifest_sha256 = verify_subject_manifest_bytes(
        manifest_raw, expected_r_commit, expected_r_tree
    )
    changed_rows: list[dict[str, Any]] = []
    changed_raw: dict[str, bytes] = {}
    revision = candidate_revision
    for path in PACKAGE_D_REFRESH_PATHS:
        expected_mode = PACKAGE_D_REFRESH_MODES[path]
        if revision is None:
            raw, _filesystem_mode = _read_worktree_regular(path, expected_mode)
            mode = expected_mode
        else:
            mode, raw = _git_blob(revision, path)
        r_mode, r_raw = _git_blob(expected_r_commit, path)
        if mode != expected_mode or r_mode != expected_mode or raw == r_raw:
            raise RebindError(f"Package D refreshed Package C path did not change: {path}")
        changed_rows.append(
            {
                "git_mode": mode,
                "path": path,
                "sha256": sha256_bytes(raw),
                "size": len(raw),
            }
        )
        changed_raw[path] = raw
    model_path = "assurance/fuzzing/fuzzing_lib.py"
    model_row = next(row for row in changed_rows if row["path"] == model_path)
    raw_model_bytes = changed_raw[model_path]
    if (
        model_row["sha256"] != sha256_bytes(raw_model_bytes)
        or model_row["size"] != len(raw_model_bytes)
    ):
        raise RebindError("Package D refreshed Package C model changed during projection")
    raw_model = raw_model_bytes.decode("utf-8", errors="strict")
    binding = {name: _assignment(raw_model, name) for name in ALLOWLISTED_ASSIGNMENTS}
    if (
        binding["STATUS"] != FINAL_STATUS
        or binding["FRAMEWORK_SUBJECT_COMMIT"] != expected_r_commit
        or binding["FRAMEWORK_SUBJECT_TREE"] != expected_r_tree
        or binding["FRAMEWORK_SUBJECT_MANIFEST_SHA256"] != manifest_sha256
    ):
        raise RebindError("Package D refreshed Package C subject binding differs")
    invariant_rows: list[dict[str, Any]] = []
    for path in PACKAGE_D_INVARIANT_PATHS:
        expected_mode = PACKAGE_C_MODES[path]
        r_mode, r_raw = _git_blob(expected_r_commit, path)
        if r_mode != expected_mode:
            raise RebindError(f"Package C R_D invariant mode differs: {path}")
        if revision is None:
            a_raw, _filesystem_mode = _read_worktree_regular(path, expected_mode)
            a_mode = expected_mode
        else:
            a_mode, a_raw = _git_blob(revision, path)
        if a_mode != r_mode or a_raw != r_raw:
            raise RebindError(f"Package C R_D invariant changed: {path}")
        invariant_rows.append(
            {
                "git_mode": r_mode,
                "path": path,
                "sha256": sha256_bytes(r_raw),
                "size": len(r_raw),
            }
        )
    body = {
        "binding_assignments": binding,
        "changed_files": changed_rows,
        "changed_paths": list(PACKAGE_D_REFRESH_PATHS),
        "content_policy": "dcrypt-package-c-package-d-subordinate-projection-v1",
        "invariant_files": invariant_rows,
        "r_commit": expected_r_commit,
        "r_tree": expected_r_tree,
        "schema_version": 1,
        "subject_manifest_sha256": manifest_sha256,
    }
    result = {**body, "projection_sha256": sha256_bytes(_canonical_json(body))}
    if (
        tuple(result)
        != (
            "binding_assignments",
            "changed_files",
            "changed_paths",
            "content_policy",
            "invariant_files",
            "r_commit",
            "r_tree",
            "schema_version",
            "subject_manifest_sha256",
            "projection_sha256",
        )
        or [row["path"] for row in result["changed_files"]]
        != list(PACKAGE_D_REFRESH_PATHS)
        or len(result["invariant_files"]) != len(PACKAGE_D_INVARIANT_PATHS)
        or [row["path"] for row in result["invariant_files"]]
        != list(PACKAGE_D_INVARIANT_PATHS)
        or any(tuple(row) != ("git_mode", "path", "sha256", "size") for row in [*result["changed_files"], *result["invariant_files"]])
    ):
        raise RebindError("Package D subordinate Package C projection closure differs")
    return result


def verify_package_d_refresh_commit(
    *, expected_r_commit: str, expected_r_tree: str, a_commit: str
) -> dict[str, Any]:
    """Verify C's eight changed paths and 27 invariant paths inside A_D."""

    _resolve_r_identity(expected_r_commit, expected_r_tree)
    resolved_a = _git(["rev-parse", "--verify", f"{a_commit}^{{commit}}"])
    if resolved_a.returncode != 0 or resolved_a.stdout.strip() != a_commit:
        raise RebindError("Package D A commit is absent or does not resolve exactly")
    for path, expected_mode in PACKAGE_C_MODES.items():
        r_mode, r_raw = _git_blob(expected_r_commit, path)
        a_mode, a_raw = _git_blob(a_commit, path)
        if r_mode != expected_mode or a_mode != expected_mode:
            raise RebindError(f"Package C path mode differs across Package D: {path}")
        changed = a_raw != r_raw
        if changed != (path in PACKAGE_D_REFRESH_MODES):
            disposition = "changed" if changed else "invariant"
            raise RebindError(
                f"Package C Package D {disposition} partition differs: {path}"
            )
    return package_d_refresh_projection(
        expected_r_commit=expected_r_commit,
        expected_r_tree=expected_r_tree,
        candidate_revision=a_commit,
    )


def _package_d_projection_main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--expected-r-commit", required=True)
    parser.add_argument("--expected-r-tree", required=True)
    parser.add_argument("--candidate-commit")
    args = parser.parse_args(arguments)
    if (
        HEX40.fullmatch(args.expected_r_commit) is None
        or HEX40.fullmatch(args.expected_r_tree) is None
        or (
            args.candidate_commit is not None
            and HEX40.fullmatch(args.candidate_commit) is None
        )
    ):
        raise RebindError("Package D projection identities must be lowercase 40-hex")
    projection = (
        verify_package_d_refresh_commit(
            expected_r_commit=args.expected_r_commit,
            expected_r_tree=args.expected_r_tree,
            a_commit=args.candidate_commit,
        )
        if args.candidate_commit is not None
        else package_d_refresh_projection(
            expected_r_commit=args.expected_r_commit,
            expected_r_tree=args.expected_r_tree,
        )
    )
    sys.stdout.buffer.write(_canonical_json(projection))
    return 0


def _projection_file_row(path: str, *, revision: str | None) -> dict[str, Any]:
    expected_mode = PACKAGE_C_MODES[path]
    if revision is None:
        raw, _filesystem_mode = _read_worktree_regular(path, expected_mode)
        mode = expected_mode
    else:
        mode, raw = _git_blob(revision, path)
    if mode != expected_mode:
        raise RebindError(f"Package E projection mode differs: {path}")
    return {
        "git_mode": mode,
        "path": path,
        "sha256": sha256_bytes(raw),
        "size": len(raw),
    }


def _package_projection(
    *,
    expected_r_commit: str,
    expected_r_tree: str,
    candidate_revision: str | None = None,
    read_revision: str | None = None,
    changed_paths: tuple[str, ...],
    invariant_paths: tuple[str, ...],
    control_paths: tuple[str, ...],
    content_policy: str,
    expected_public_sha256: str,
    package_label: str,
) -> dict[str, Any]:
    """Project Package C's complete owned subtree without global authority."""

    _resolve_r_identity(expected_r_commit, expected_r_tree)
    if candidate_revision is not None:
        resolved = _git(["rev-parse", "--verify", f"{candidate_revision}^{{commit}}"])
        if resolved.returncode != 0 or resolved.stdout.strip() != candidate_revision:
            raise RebindError("Package E candidate commit is absent or does not resolve exactly")
    data_revision = candidate_revision if candidate_revision is not None else read_revision
    if data_revision is not None:
        manifest_mode, manifest_raw = _git_blob(data_revision, "assurance/subject-manifest.json")
        if manifest_mode != "100644":
            raise RebindError(f"{package_label} subject manifest Git mode differs")
    else:
        manifest_raw = _read_worktree_regular("assurance/subject-manifest.json", "100644")[0]
    manifest_sha256 = verify_subject_manifest_bytes(
        manifest_raw, expected_r_commit, expected_r_tree
    )
    changed_files = [
        _projection_file_row(path, revision=data_revision)
        for path in changed_paths
    ]
    invariant_files = [
        _projection_file_row(path, revision=data_revision)
        for path in invariant_paths
    ]
    for changed, should_change in (
        *((row, True) for row in changed_files),
        *((row, False) for row in invariant_files),
    ):
        r_mode, r_raw = _git_blob(expected_r_commit, changed["path"])
        same = (
            r_mode == changed["git_mode"]
            and len(r_raw) == changed["size"]
            and sha256_bytes(r_raw) == changed["sha256"]
        )
        if same == should_change:
            disposition = "did not change" if should_change else "changed"
            raise RebindError(f"Package E Package C path {disposition}: {changed['path']}")
    model_row = next(
        row for row in changed_files if row["path"] == "assurance/fuzzing/fuzzing_lib.py"
    )
    model_raw = (
        _read_worktree_regular(model_row["path"], "100644")[0]
        if data_revision is None
        else _git_blob(data_revision, model_row["path"])[1]
    )
    model_source = model_raw.decode("utf-8", errors="strict")
    assignments = {
        name: _assignment(model_source, name)
        for name in (
            "EXPECTED_POLICY_SEMANTIC_SHA256",
            "EXPECTED_REGISTRY_SEMANTIC_SHA256",
            "CONTROL_INPUTS_SHA256",
            "FRAMEWORK_SUBJECT_COMMIT",
            "FRAMEWORK_SUBJECT_MANIFEST_SHA256",
            "FRAMEWORK_SUBJECT_TREE",
            "STATUS",
        )
    }
    if (
        assignments["STATUS"] != FINAL_STATUS
        or assignments["FRAMEWORK_SUBJECT_COMMIT"] != expected_r_commit
        or assignments["FRAMEWORK_SUBJECT_TREE"] != expected_r_tree
        or assignments["FRAMEWORK_SUBJECT_MANIFEST_SHA256"] != manifest_sha256
    ):
        raise RebindError("Package E Package C subject binding differs")
    atomic_raw = (
        _read_worktree_regular("assurance/atomic-operations.toml", "100644")[0]
        if data_revision is None
        else _git_blob(data_revision, "assurance/atomic-operations.toml")[1]
    )
    public_raw = (
        _read_worktree_regular("assurance/public-api-snapshot.json", "100644")[0]
        if data_revision is None
        else _git_blob(data_revision, "assurance/public-api-snapshot.json")[1]
    )
    source_bindings_raw = (
        _read_worktree_regular("assurance/fuzzing/source-bindings.json", "100644")[0]
        if data_revision is None
        else _git_blob(data_revision, "assurance/fuzzing/source-bindings.json")[1]
    )
    try:
        atomic = __import__("tomllib").loads(atomic_raw.decode("utf-8"))
        def unique_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate public API snapshot key")
                result[key] = value
            return result
        public = json.loads(public_raw.decode("utf-8"), object_pairs_hook=unique_pairs)
        source_bindings = json.loads(
            source_bindings_raw.decode("utf-8"), object_pairs_hook=unique_pairs
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RebindError("Package E Package C core inputs are malformed") from error
    if (
        sha256_bytes(atomic_raw) != "8e745ab16086aa50e265ad79189375270c5906df8545f540d96426bc348ca11a"
        or sha256_bytes(public_raw) != expected_public_sha256
        or len(atomic.get("operation", [])) != 566
        or len(atomic.get("unreviewed-gap", [])) != 8632
        or not isinstance(public, dict)
        or len(public.get("entries", [])) != 18891
        or not isinstance(source_bindings, dict)
        or not isinstance(source_bindings.get("files"), list)
    ):
        raise RebindError("Package E Package C core input binding/counts differ")
    control_rows = [
        row for row in source_bindings["files"]
        if isinstance(row, dict) and row.get("path") in control_paths
    ]
    if (
        [row.get("path") for row in control_rows] != list(control_paths)
        or any(set(row) != {"git_mode", "path", "sha256", "size"} for row in control_rows)
        or sha256_bytes(
            (json.dumps(control_rows, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        ) != assignments["CONTROL_INPUTS_SHA256"]
    ):
        raise RebindError("Package E Package C control-input binding rows differ")
    for row in control_rows:
        if data_revision is None:
            raw = _read_worktree_regular(row["path"], row["git_mode"])[0]
            mode = row["git_mode"]
        else:
            mode, raw = _git_blob(data_revision, row["path"])
        if (
            mode != row["git_mode"]
            or len(raw) != row["size"]
            or sha256_bytes(raw) != row["sha256"]
        ):
            raise RebindError(f"Package E Package C control input differs: {row['path']}")
    body = {
        "binding_assignments": {
            "atomic_operations_sha256": sha256_bytes(atomic_raw),
            "control_inputs_sha256": assignments["CONTROL_INPUTS_SHA256"],
            "policy_semantic_sha256": assignments["EXPECTED_POLICY_SEMANTIC_SHA256"],
            "public_api_snapshot_sha256": sha256_bytes(public_raw),
            "registry_semantic_sha256": assignments["EXPECTED_REGISTRY_SEMANTIC_SHA256"],
            "subject_commit": assignments["FRAMEWORK_SUBJECT_COMMIT"],
            "subject_manifest_sha256": assignments["FRAMEWORK_SUBJECT_MANIFEST_SHA256"],
            "subject_tree": assignments["FRAMEWORK_SUBJECT_TREE"],
        },
        "candidate_commit": candidate_revision,
        "changed_files": changed_files,
        "content_policy": content_policy,
        "counts": {
            "critical_family_rows": 372,
            "curated_rows": 566,
            "explicit_blocker_rows": 8826,
            "total_atomic_rows": 9198,
            "unreviewed_gap_rows": 8632,
        },
        "invariant_files": invariant_files,
        "r_commit": expected_r_commit,
        "r_tree": expected_r_tree,
        "schema_version": 1,
        "subject_manifest_sha256": manifest_sha256,
    }
    result = {**body, "projection_sha256": sha256_bytes(_canonical_json(body))}
    if (
        [row["path"] for row in [*changed_files, *invariant_files]]
        != [*changed_paths, *invariant_paths]
        or set(changed_paths) | set(invariant_paths)
        != set(PACKAGE_C_MODES)
        or any(tuple(row) != ("git_mode", "path", "sha256", "size") for row in [*changed_files, *invariant_files])
    ):
        raise RebindError(f"{package_label} Package C projection closure differs")
    return result


def package_e_projection(
    *,
    expected_r_commit: str,
    expected_r_tree: str,
    candidate_revision: str | None = None,
) -> dict[str, Any]:
    """Return the immutable completed Package E view of Package C."""

    return _package_projection(
        expected_r_commit=expected_r_commit,
        expected_r_tree=expected_r_tree,
        candidate_revision=candidate_revision,
        read_revision=None if candidate_revision is not None else PACKAGE_E_A_COMMIT,
        changed_paths=PACKAGE_E_CHANGED_PATHS,
        invariant_paths=PACKAGE_E_INVARIANT_PATHS,
        control_paths=PACKAGE_E_CONTROL_PATHS,
        content_policy="dcrypt-package-c-package-e-subordinate-projection-v1",
        expected_public_sha256="0a7c7d6585b6612f35e9dd5622018ca3c87c5fb51f8fa0e4652904d651c6215f",
        package_label="Package E",
    )


def package_f_projection(
    *,
    expected_r_commit: str,
    expected_r_tree: str,
    candidate_revision: str | None = None,
) -> dict[str, Any]:
    """Project Package C's current complete subtree for Package F."""

    return _package_projection(
        expected_r_commit=expected_r_commit,
        expected_r_tree=expected_r_tree,
        candidate_revision=candidate_revision,
        changed_paths=PACKAGE_F_CHANGED_PATHS,
        invariant_paths=PACKAGE_F_INVARIANT_PATHS,
        control_paths=PACKAGE_F_CONTROL_PATHS,
        content_policy="dcrypt-package-c-package-f-subordinate-projection-v1",
        expected_public_sha256="5fa59a0218c2be98ef653d85da35c616c75b1499cb376f2b12c99eb6813e553d",
        package_label="Package F",
    )


def _package_e_projection_main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--expected-r-commit", required=True)
    parser.add_argument("--expected-r-tree", required=True)
    parser.add_argument("--candidate-commit")
    args = parser.parse_args(arguments)
    if (
        HEX40.fullmatch(args.expected_r_commit) is None
        or HEX40.fullmatch(args.expected_r_tree) is None
        or (args.candidate_commit is not None and HEX40.fullmatch(args.candidate_commit) is None)
    ):
        raise RebindError("Package E projection identities must be lowercase 40-hex")
    sys.stdout.buffer.write(
        _canonical_json(
            package_e_projection(
                expected_r_commit=args.expected_r_commit,
                expected_r_tree=args.expected_r_tree,
                candidate_revision=args.candidate_commit,
            )
        )
    )
    return 0


def _package_f_projection_main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--expected-r-commit", required=True)
    parser.add_argument("--expected-r-tree", required=True)
    parser.add_argument("--candidate-commit")
    args = parser.parse_args(arguments)
    if (
        HEX40.fullmatch(args.expected_r_commit) is None
        or HEX40.fullmatch(args.expected_r_tree) is None
        or (args.candidate_commit is not None and HEX40.fullmatch(args.candidate_commit) is None)
    ):
        raise RebindError("Package F projection identities must be lowercase 40-hex")
    sys.stdout.buffer.write(
        _canonical_json(
            package_f_projection(
                expected_r_commit=args.expected_r_commit,
                expected_r_tree=args.expected_r_tree,
                candidate_revision=args.candidate_commit,
            )
        )
    )
    return 0


def _verify_absent_build_sentinels() -> None:
    present = [path for path in SUBJECT_ABSENT if os.path.lexists(REPO / path)]
    if present:
        raise RebindError(f"declared absent subject build inputs exist: {present}")


def _verify_pre_a(commit: str, tree: str) -> tuple[str, str]:
    _resolve_r_identity(commit, tree)
    if _head() != commit:
        raise RebindError("HEAD must equal the explicit reviewed R commit before A")
    if _staged_paths():
        raise RebindError("staged changes are forbidden during the A transaction")
    validate_exact_changed_a_paths(_working_a_paths())
    _verify_legacy_r_invariants(commit)
    _verify_absent_build_sentinels()
    gitignore_sha256 = _verify_protected_gitignore(commit)
    manifest_sha256 = verify_subject_manifest(commit, tree)
    return manifest_sha256, gitignore_sha256


def _verify_post_a(commit: str, tree: str) -> tuple[str, str, str, str]:
    _resolve_r_identity(commit, tree)
    head = _head()
    parents = _git(["rev-list", "--parents", "-n", "1", head])
    tokens = parents.stdout.strip().split() if parents.returncode == 0 else []
    if tokens != [head, commit]:
        raise RebindError("committed A must be a one-parent child of the exact reviewed R")
    if _staged_paths():
        raise RebindError("committed A check forbids every staged change")
    changed_worktree = _git(["diff", "--name-only", "-z", "HEAD", "--", "."], binary=True)
    untracked = _git(["ls-files", "--others", "--exclude-standard", "-z", "--", "."], binary=True)
    ignored_assurance = _git(
        ["ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", "assurance"],
        binary=True,
    )
    if changed_worktree.returncode != 0 or untracked.returncode != 0 or ignored_assurance.returncode != 0:
        raise RebindError("cannot inspect post-A protected worktree closure")
    observed_dirty = sorted(
        _decode_paths(changed_worktree.stdout, label="post-A dirty closure")
        + _decode_paths(untracked.stdout, label="post-A untracked closure")
        + _decode_paths(ignored_assurance.stdout, label="post-A ignored assurance closure")
    )
    worktree_variant = validate_post_a_dirty_paths(observed_dirty)
    changed = _git(["diff-tree", "--no-commit-id", "--name-only", "-r", "--no-renames", "-z", commit, head], binary=True)
    if changed.returncode != 0:
        raise RebindError("cannot inspect committed R..A path closure")
    validate_exact_changed_a_paths(sorted(_decode_paths(changed.stdout, label="committed R..A closure")))
    for path, expected_mode in KNOWN_A_MODES.items():
        entry = _git_entry(head, path)
        if entry is None or entry[0] != expected_mode:
            raise RebindError(f"committed A path mode/type differs: {path}")
        if path in PACKAGE_C_MODES and _git_entry(commit, path) is not None:
            raise RebindError(f"Package C path already existed in R: {path}")
    _verify_legacy_r_invariants(commit, candidate_revision=head)
    _verify_absent_build_sentinels()
    a_gitignore_mode, a_gitignore = _git_blob(head, PROTECTED_GITIGNORE)
    r_gitignore_mode, r_gitignore = _git_blob(commit, PROTECTED_GITIGNORE)
    if a_gitignore_mode != r_gitignore_mode or a_gitignore != r_gitignore:
        raise RebindError("committed A changed protected .gitignore")
    gitignore_sha256, observed_variant = _verify_gitignore_topology(commit)
    if observed_variant != worktree_variant:
        raise RebindError("post-A .gitignore topology differs from observed dirty-path closure")
    return verify_subject_manifest(commit, tree), gitignore_sha256, head, worktree_variant


def _run_framework(
    arguments: list[str],
    *,
    protected_revision: str,
    protected_sha256: str,
    protected_variant: str,
) -> None:
    primary: BaseException | None = None
    try:
        result = subprocess.run(
            [sys.executable, "-B", *arguments],
            cwd=REPO,
            capture_output=True,
            timeout=300,
            env={"HOME": os.environ.get("HOME", ""), "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
        )
        if result.returncode != 0:
            raise RebindError((result.stderr or result.stdout).decode("utf-8", "replace").strip())
    except BaseException as error:
        primary = error
    guard_failures: list[str] = []
    try:
        _assert_protected_gitignore_unchanged(
            protected_revision,
            expected_sha256=protected_sha256,
            expected_variant=protected_variant,
        )
    except BaseException as protected_error:
        guard_failures.append(f"protected file: {protected_error}")
    try:
        _verify_legacy_r_invariants(protected_revision)
    except BaseException as invariant_error:
        guard_failures.append(f"legacy R invariants: {invariant_error}")
    if guard_failures:
        failure = RebindError(
            "framework post-invocation guard failed: " + " | ".join(guard_failures)
        )
        if primary is not None:
            raise failure from primary
        raise failure
    if primary is not None:
        raise primary


def _run_framework_checks(
    *, protected_revision: str, protected_sha256: str, protected_variant: str
) -> None:
    parameters = {
        "protected_revision": protected_revision,
        "protected_sha256": protected_sha256,
        "protected_variant": protected_variant,
    }
    _run_framework(["assurance/fuzzing/generate.py", "--check"], **parameters)
    _run_framework(["assurance/fuzzing/selftest.py"], **parameters)
    _run_framework(["assurance/fuzzing/verify.py", "--ci"], **parameters)


def _atomic_write(path: Path, raw: bytes, mode: int) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def snapshot_regular_paths(root: Path, paths: list[str]) -> dict[str, FileSnapshot]:
    snapshots: dict[str, FileSnapshot] = {}
    for relative in paths:
        pure = PurePosixPath(relative)
        if not relative or pure.is_absolute() or ".." in pure.parts or "." in pure.parts or pure.as_posix() != relative:
            raise RebindError(f"unsafe rollback snapshot path: {relative!r}")
        path = root / relative
        raw, metadata = _read_absolute_regular_once(
            path, label=f"rollback snapshot {relative}"
        )
        snapshots[relative] = FileSnapshot(raw, stat.S_IMODE(metadata.st_mode))
    return snapshots


def restore_regular_paths(root: Path, snapshots: dict[str, FileSnapshot]) -> None:
    errors: list[str] = []
    for relative in sorted(snapshots):
        snapshot = snapshots[relative]
        path = root / relative
        try:
            if os.path.lexists(path) and (path.is_symlink() or not path.is_file()):
                raise RebindError(f"rollback target changed type: {relative}")
            if os.path.lexists(path):
                current, metadata = _read_absolute_regular_once(
                    path, label=f"rollback current path {relative}"
                )
                if current == snapshot.raw and stat.S_IMODE(metadata.st_mode) == snapshot.mode:
                    continue
            _atomic_write(path, snapshot.raw, snapshot.mode)
        except (OSError, RebindError) as error:
            errors.append(str(error))
    for relative, snapshot in snapshots.items():
        path = root / relative
        try:
            raw, metadata = _read_absolute_regular_once(
                path, label=f"restored rollback path {relative}"
            )
            if stat.S_IMODE(metadata.st_mode) != snapshot.mode or raw != snapshot.raw:
                raise RebindError(f"rollback did not restore exact bytes/mode/type: {relative}")
        except (OSError, RebindError) as error:
            errors.append(str(error))
    if errors:
        raise RebindError("rollback failures: " + " | ".join(errors))


def _framework_inventory(root_path: Path = FRAMEWORK) -> set[str]:
    result: set[str] = set()
    for root, directories, files in os.walk(root_path, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        for directory in directories:
            path = Path(root) / directory
            if path.is_symlink():
                raise RebindError(f"framework contains a symlink directory: {path}")
        for filename in files:
            path = Path(root) / filename
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise RebindError(f"framework contains a nonregular/hardlinked file: {path}")
            result.add(path.relative_to(root_path).as_posix())
    return result


def _assert_framework_inventory(
    baseline: set[str], *, root_path: Path = FRAMEWORK
) -> None:
    current = _framework_inventory(root_path)
    if current != baseline:
        raise RebindError(
            "framework inventory changed; unknown paths are preserved and require review: "
            f"missing={sorted(baseline-current)}, surplus={sorted(current-baseline)}"
        )


def _candidate_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in KNOWN_A_PATHS:
        raw, _mode = _read_worktree_regular(path, KNOWN_A_MODES[path])
        rows.append(
            {
                "disposition": (
                    "exact-r-invariant"
                    if path in LEGACY_R_INVARIANTS
                    else "changed-in-a"
                ),
                "git_mode": KNOWN_A_MODES[path],
                "path": path,
                "sha256": sha256_bytes(raw),
                "size": len(raw),
            }
        )
    return rows


def validate_candidate_rows(
    rows: list[dict[str, Any]],
    *,
    manifest_sha256: str,
    legacy_pins: dict[str, str] | None = None,
    allow_unstable_pins: bool = False,
) -> None:
    pins = LEGACY_A_SHA256 if legacy_pins is None else legacy_pins
    if [row.get("path") for row in rows] != list(KNOWN_A_PATHS):
        raise RebindError("candidate manifest path order/closure differs")
    if set(pins) != set(LEGACY_A_MODES):
        raise RebindError("legacy A digest pin closure differs")
    for row in rows:
        if set(row) != {"disposition", "git_mode", "path", "sha256", "size"}:
            raise RebindError("candidate manifest row field closure differs")
        path = row["path"]
        if (
            row["disposition"] != (
                "exact-r-invariant" if path in LEGACY_R_INVARIANTS else "changed-in-a"
            )
            or row["git_mode"] != KNOWN_A_MODES[path]
            or not isinstance(row["sha256"], str)
            or HEX64.fullmatch(row["sha256"]) is None
            or not isinstance(row["size"], int)
            or isinstance(row["size"], bool)
            or row["size"] < 0
        ):
            raise RebindError(f"candidate manifest row identity/mode/digest differs: {path}")
        if path in LEGACY_A_MODES:
            expected = pins[path]
            if path == "assurance/subject-manifest.json":
                if expected != "VERIFIED-R-SUBJECT-MANIFEST" or row["sha256"] != manifest_sha256:
                    raise RebindError("candidate subject-manifest digest differs from verified R manifest")
            elif expected == "UNSTABLE":
                if not allow_unstable_pins:
                    raise RebindError(f"legacy A byte pin remains UNSTABLE: {path}")
            elif HEX64.fullmatch(expected) is None or row["sha256"] != expected:
                raise RebindError(f"legacy A reviewed byte pin differs: {path}")


def _candidate_manifest(
    *,
    commit: str,
    tree: str,
    manifest_sha256: str,
    gitignore_sha256: str,
    a_commit: str | None,
    allow_unstable_pins: bool = False,
    worktree_variant: str = "protected-dirty-shared-workspace",
) -> dict[str, Any]:
    rows = _candidate_rows()
    validate_candidate_rows(
        rows,
        manifest_sha256=manifest_sha256,
        allow_unstable_pins=allow_unstable_pins,
    )
    source = _read_worktree_regular(
        "assurance/fuzzing/fuzzing_lib.py", "100644"
    )[0].decode("utf-8", errors="strict")
    binding = {name: _assignment(source, name) for name in ALLOWLISTED_ASSIGNMENTS}
    if binding["STATUS"] != FINAL_STATUS:
        raise RebindError("candidate manifest requires the final bound model")
    body = {
        "a_commit": a_commit,
        "allowed_assignment_names": list(ALLOWLISTED_ASSIGNMENTS),
        "binding_assignments": binding,
        "changed_paths": list(EXPECTED_CHANGED_A_PATHS),
        "content_policy": "dcrypt-package-c-full-a-candidate-manifest-v1",
        "files": rows,
        "known_inventory_paths": list(KNOWN_A_PATHS),
        "legacy_byte_pin_status": (
            "HOLD-unreviewed-legacy-hashes" if allow_unstable_pins else "reviewed-exact"
        ),
        "protected_gitignore_sha256": gitignore_sha256,
        "r_commit": commit,
        "r_invariant_paths": list(LEGACY_R_INVARIANT_PATHS),
        "r_tree": tree,
        "schema_version": 1,
        "subject_manifest_sha256": manifest_sha256,
        "worktree_variant": worktree_variant,
    }
    result = {**body, "candidate_manifest_sha256": sha256_bytes(_canonical_json(body))}
    validate_candidate_manifest(
        result,
        expected_r_commit=commit,
        expected_r_tree=tree,
        expected_manifest_sha256=manifest_sha256,
        allow_unstable_pins=allow_unstable_pins,
    )
    return result


def validate_candidate_manifest(
    document: dict[str, Any],
    *,
    expected_r_commit: str,
    expected_r_tree: str,
    expected_manifest_sha256: str,
    legacy_pins: dict[str, str] | None = None,
    allow_unstable_pins: bool = False,
) -> None:
    expected = {
        "a_commit", "allowed_assignment_names", "binding_assignments", "candidate_manifest_sha256",
        "changed_paths", "content_policy", "files", "known_inventory_paths", "legacy_byte_pin_status",
        "protected_gitignore_sha256", "r_commit", "r_invariant_paths", "r_tree", "schema_version",
        "subject_manifest_sha256", "worktree_variant",
    }
    if set(document) != expected:
        raise RebindError("candidate manifest root closure differs")
    if (
        document["content_policy"] != "dcrypt-package-c-full-a-candidate-manifest-v1"
        or document["schema_version"] != 1
        or document["allowed_assignment_names"] != list(ALLOWLISTED_ASSIGNMENTS)
        or document["changed_paths"] != list(EXPECTED_CHANGED_A_PATHS)
        or document["known_inventory_paths"] != list(KNOWN_A_PATHS)
        or document["r_invariant_paths"] != list(LEGACY_R_INVARIANT_PATHS)
        or document["legacy_byte_pin_status"] != (
            "HOLD-unreviewed-legacy-hashes" if allow_unstable_pins else "reviewed-exact"
        )
        or document["worktree_variant"] not in {
            "clean-replay", "protected-dirty-shared-workspace"
        }
        or document["r_commit"] != expected_r_commit
        or document["r_tree"] != expected_r_tree
        or document["subject_manifest_sha256"] != expected_manifest_sha256
        or HEX40.fullmatch(document["r_commit"] or "") is None
        or HEX40.fullmatch(document["r_tree"] or "") is None
        or (document["a_commit"] is not None and HEX40.fullmatch(document["a_commit"]) is None)
        or HEX64.fullmatch(document["subject_manifest_sha256"] or "") is None
        or HEX64.fullmatch(document["protected_gitignore_sha256"] or "") is None
        or set(document["binding_assignments"]) != set(ALLOWLISTED_ASSIGNMENTS)
    ):
        raise RebindError("candidate manifest identity/binding closure differs")
    expected_gitignore = (
        PROTECTED_GITIGNORE_COMMITTED_SHA256
        if document["worktree_variant"] == "clean-replay"
        else PROTECTED_GITIGNORE_WORKTREE_SHA256
    )
    if document["protected_gitignore_sha256"] != expected_gitignore:
        raise RebindError("candidate manifest protected .gitignore variant/digest differs")
    bindings = document["binding_assignments"]
    if (
        bindings["STATUS"] != FINAL_STATUS
        or bindings["FRAMEWORK_SUBJECT_COMMIT"] != document["r_commit"]
        or bindings["FRAMEWORK_SUBJECT_TREE"] != document["r_tree"]
        or bindings["FRAMEWORK_SUBJECT_MANIFEST_SHA256"] != document["subject_manifest_sha256"]
        or HEX64.fullmatch(bindings["EXPECTED_POLICY_SEMANTIC_SHA256"] or "") is None
        or HEX64.fullmatch(bindings["EXPECTED_REGISTRY_SEMANTIC_SHA256"] or "") is None
    ):
        raise RebindError("candidate manifest binding assignments are partial or rebound")
    validate_candidate_rows(
        document["files"],
        manifest_sha256=document["subject_manifest_sha256"],
        legacy_pins=legacy_pins,
        allow_unstable_pins=allow_unstable_pins,
    )
    body = {key: value for key, value in document.items() if key != "candidate_manifest_sha256"}
    if document["candidate_manifest_sha256"] != sha256_bytes(_canonical_json(body)):
        raise RebindError("candidate manifest digest differs")


def _restore_transaction(
    snapshots: dict[str, FileSnapshot],
    baseline_framework: set[str],
    *,
    protected_revision: str,
    protected_sha256: str,
    protected_variant: str,
) -> None:
    failures: list[str] = []
    try:
        restore_regular_paths(REPO, snapshots)
    except BaseException as error:
        failures.append(f"known-file restore: {error}")
    try:
        _assert_framework_inventory(baseline_framework)
    except BaseException as error:
        # Never delete a path that may have appeared concurrently. Preserve it
        # and force explicit review while still restoring every known file.
        failures.append(f"framework inventory: {error}")
    try:
        _verify_legacy_r_invariants(protected_revision)
    except BaseException as error:
        failures.append(f"legacy R invariants: {error}")
    try:
        _assert_protected_gitignore_unchanged(
            protected_revision,
            expected_sha256=protected_sha256,
            expected_variant=protected_variant,
        )
    except BaseException as error:
        failures.append(f"protected file: {error}")
    if failures:
        raise RebindError("transaction rollback incomplete: " + " | ".join(failures))


def _apply_or_preview(
    candidate: str,
    *,
    commit: str,
    tree: str,
    manifest_sha256: str,
    gitignore_sha256: str,
    keep: bool,
    inject_failure_after_model: bool = False,
    allow_unstable_pins: bool = False,
    protected_variant: str = "protected-dirty-shared-workspace",
) -> dict[str, Any]:
    snapshots = snapshot_regular_paths(REPO, list(KNOWN_A_PATHS))
    baseline_framework = _framework_inventory()
    expected_framework = set(PACKAGE_C_RELATIVE_PATHS)
    if baseline_framework != expected_framework:
        raise RebindError(
            "pre-transaction framework inventory differs; unknown paths are preserved: "
            f"missing={sorted(expected_framework-baseline_framework)}, "
            f"surplus={sorted(baseline_framework-expected_framework)}"
        )
    if protected_variant not in {"clean-replay", "protected-dirty-shared-workspace"}:
        raise RebindError("transaction protected-file topology is unknown")
    primary: BaseException | None = None
    result: dict[str, Any] | None = None
    try:
        _atomic_write(MODEL, candidate.encode("utf-8"), snapshots["assurance/fuzzing/fuzzing_lib.py"].mode)
        if inject_failure_after_model:
            raise RebindError("injected rebind failure after model write")
        protected_parameters = {
            "protected_revision": commit,
            "protected_sha256": gitignore_sha256,
            "protected_variant": protected_variant,
        }
        _run_framework(["assurance/fuzzing/generate.py"], **protected_parameters)
        _run_framework_checks(**protected_parameters)
        if _staged_paths():
            raise RebindError("A transaction unexpectedly modified the index")
        validate_exact_changed_a_paths(_working_a_paths())
        _verify_legacy_r_invariants(commit)
        _assert_framework_inventory(baseline_framework)
        result = _candidate_manifest(
            commit=commit,
            tree=tree,
            manifest_sha256=manifest_sha256,
            gitignore_sha256=gitignore_sha256,
            a_commit=None,
            allow_unstable_pins=allow_unstable_pins,
        )
        _assert_framework_inventory(baseline_framework)
        _assert_protected_gitignore_unchanged(
            commit,
            expected_sha256=gitignore_sha256,
            expected_variant=protected_variant,
        )
    except BaseException as error:
        primary = error
    if not keep or primary is not None:
        try:
            _restore_transaction(
                snapshots,
                baseline_framework,
                protected_revision=commit,
                protected_sha256=gitignore_sha256,
                protected_variant=protected_variant,
            )
        except BaseException as rollback_error:
            if primary is not None:
                raise RebindError(
                    f"A transaction failed and rollback also failed: {rollback_error}"
                ) from primary
            raise
    if primary is not None:
        raise primary
    if result is None:
        raise RebindError("A transaction produced no candidate manifest")
    return result


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--package-f-projection":
        try:
            return _package_f_projection_main(sys.argv[2:])
        except (RebindError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
            print(f"Package F subordinate projection HOLD: {error}", file=sys.stderr)
            return 3
    if len(sys.argv) >= 2 and sys.argv[1] == "--package-e-projection":
        try:
            return _package_e_projection_main(sys.argv[2:])
        except (RebindError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
            print(f"Package E subordinate projection HOLD: {error}", file=sys.stderr)
            return 3
    if len(sys.argv) >= 2 and sys.argv[1] == "--package-d-projection":
        try:
            return _package_d_projection_main(sys.argv[2:])
        except (RebindError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
            print(f"Package D subordinate projection HOLD: {error}", file=sys.stderr)
            return 3
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        if HEX40.fullmatch(args.expected_commit) is None or HEX40.fullmatch(args.expected_tree) is None:
            raise RebindError("expected R commit/tree must be lowercase 40-hex Git identities")
        head = _head()
        if args.check and head != args.expected_commit:
            manifest_sha256, gitignore_sha256, a_commit, worktree_variant = _verify_post_a(
                args.expected_commit, args.expected_tree
            )
            source = _read_worktree_regular(
                "assurance/fuzzing/fuzzing_lib.py", "100644"
            )[0].decode("utf-8", errors="strict")
            candidate = build_candidate_source(
                source,
                commit=args.expected_commit,
                tree=args.expected_tree,
                manifest_sha256=manifest_sha256,
            )
            if source != candidate:
                raise RebindError("committed A model is not the exact final-subject-bound candidate")
            _run_framework_checks(
                protected_revision=args.expected_commit,
                protected_sha256=gitignore_sha256,
                protected_variant=worktree_variant,
            )
            _assert_protected_gitignore_unchanged(
                args.expected_commit,
                expected_sha256=gitignore_sha256,
                expected_variant=worktree_variant,
            )
            document = _candidate_manifest(
                commit=args.expected_commit,
                tree=args.expected_tree,
                manifest_sha256=manifest_sha256,
                gitignore_sha256=gitignore_sha256,
                a_commit=a_commit,
                worktree_variant=worktree_variant,
            )
            _assert_protected_gitignore_unchanged(
                args.expected_commit,
                expected_sha256=gitignore_sha256,
                expected_variant=worktree_variant,
            )
            sys.stdout.buffer.write(_canonical_json(document))
            return 0
        manifest_sha256, gitignore_sha256 = _verify_pre_a(args.expected_commit, args.expected_tree)
        source = _read_worktree_regular(
            "assurance/fuzzing/fuzzing_lib.py", "100644"
        )[0].decode("utf-8", errors="strict")
        candidate = build_candidate_source(
            source,
            commit=args.expected_commit,
            tree=args.expected_tree,
            manifest_sha256=manifest_sha256,
        )
        if args.check:
            if source != candidate:
                raise RebindError("current model is not the exact final-subject-bound candidate")
            _run_framework_checks(
                protected_revision=args.expected_commit,
                protected_sha256=gitignore_sha256,
                protected_variant="protected-dirty-shared-workspace",
            )
            _assert_protected_gitignore_unchanged(
                args.expected_commit,
                expected_sha256=gitignore_sha256,
                expected_variant="protected-dirty-shared-workspace",
            )
            document = _candidate_manifest(
                commit=args.expected_commit,
                tree=args.expected_tree,
                manifest_sha256=manifest_sha256,
                gitignore_sha256=gitignore_sha256,
                a_commit=None,
            )
            _assert_protected_gitignore_unchanged(
                args.expected_commit,
                expected_sha256=gitignore_sha256,
                expected_variant="protected-dirty-shared-workspace",
            )
            sys.stdout.buffer.write(_canonical_json(document))
            return 0
        if source == candidate:
            raise RebindError("apply/dry-run requires the exact pre-bind UNSTABLE model")
        _run_framework_checks(
            protected_revision=args.expected_commit,
            protected_sha256=gitignore_sha256,
            protected_variant="protected-dirty-shared-workspace",
        )
        document = _apply_or_preview(
            candidate,
            commit=args.expected_commit,
            tree=args.expected_tree,
            manifest_sha256=manifest_sha256,
            gitignore_sha256=gitignore_sha256,
            keep=args.apply,
            allow_unstable_pins=args.dry_run,
        )
        sys.stdout.buffer.write(_canonical_json(document))
        return 0
    except (RebindError, OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        print(f"final-subject rebind HOLD: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
