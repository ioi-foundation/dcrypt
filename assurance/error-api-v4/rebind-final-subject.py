#!/usr/bin/env python3
"""Exact Package E topology, trust, and final-candidate transaction authority.

The literal global changed-file closure is intentionally a separately frozen
input. Until it is populated, pre/post-commit modes fail closed. Source and
rollback self-tests remain runnable while the global cascade reaches a fixed
point.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True

FRAMEWORK = Path(__file__).resolve().parent
REPO = FRAMEWORK.parent.parent
A_D_COMMIT = "39fed53adc1fa256812f6157396cd75a62b8fc8d"
A_D_TREE = "0ab8a595efbff7fb857e8573e3f138ad4a8d9cb1"
S_E_COMMIT = "219ee68040fa48ae1973ba5a16ccf7f32f73657a"
S_E_TREE = "4390012075501659de01e21b24432967b5aa0c23"
R_E_COMMIT = "276b78f9b3c2aed91d2548ab9add721c434ded06"
R_E_TREE = "c47c98062c43463818bb61bd3eed75ebaf189e1d"
R_E_SUBJECT_MANIFEST_SHA256 = (
    "d48d134daa383fb12c03e45aebe3bcf16f40e2c6930e17f209e0af95f1133eb4"
)
A_E_COMMIT = "86a907154c1f8211a1775c1da8186b71a704536f"
PROTECTED_GITIGNORE_SHA256 = (
    "e4887e3f444e25b7baad39bd6ff3da3ae770f8dc5b3f7cf2c87a117219a8fe2c"
)
PROTECTED_GITIGNORE_DIFF_SHA256 = (
    "caa005fda38ed3a65d8b92a5b788169ebba47e7106c1389bf4cd7bff980c6552"
)
PROTECTED_GITIGNORE_COMMITTED_SHA256 = (
    "f34512e77a7cf5fdfd465243dbb286d8e16bfd698cad264bdb1360f008915f26"
)

PACKAGE_F_R_COMMIT = "889cb8c4dc13a78679dc8a7677916484a9966f65"
PACKAGE_F_R_TREE = "0d44b68b186913de68844d09b7e498bcda14d109"
PACKAGE_F_SUBJECT_MANIFEST_SHA256 = (
    "95902d2ff4a2f99808ba5d404fbce3175b787b93fdc1538cb55ad350e69505c7"
)
PACKAGE_E_PATHS = tuple(sorted((
    "assurance/error-api-v4/ARTIFACTS.json",
    "assurance/error-api-v4/README.md",
    "assurance/error-api-v4/capture.py",
    "assurance/error-api-v4/fixtures/control.json",
    "assurance/error-api-v4/generate.py",
    "assurance/error-api-v4/model.py",
    "assurance/error-api-v4/package-e.json",
    "assurance/error-api-v4/rebind-final-subject.py",
    "assurance/error-api-v4/reviewed-inventory.toml",
    "assurance/error-api-v4/schema.json",
    "assurance/error-api-v4/selftest.py",
    "assurance/error-api-v4/verify.py",
)))
PACKAGE_F_CHANGED_PATHS = tuple(sorted((
    "assurance/error-api-v4/ARTIFACTS.json",
    "assurance/error-api-v4/model.py",
    "assurance/error-api-v4/package-e.json",
    "assurance/error-api-v4/rebind-final-subject.py",
    "assurance/error-api-v4/schema.json",
)))
PACKAGE_F_INVARIANT_PATHS = tuple(
    sorted(set(PACKAGE_E_PATHS) - set(PACKAGE_F_CHANGED_PATHS))
)
if (
    len(PACKAGE_E_PATHS) != 12
    or len(PACKAGE_F_CHANGED_PATHS) != 5
    or len(PACKAGE_F_INVARIANT_PATHS) != 7
    or set(PACKAGE_F_CHANGED_PATHS) | set(PACKAGE_F_INVARIANT_PATHS)
    != set(PACKAGE_E_PATHS)
    or set(PACKAGE_F_CHANGED_PATHS) & set(PACKAGE_F_INVARIANT_PATHS)
):
    raise RuntimeError("Package F Package E projection partition differs")

S_E_PATHS = tuple(sorted((
    ".github/workflows/security-validation.yml",
    "CHANGELOG.md",
    "CONSTANT_TIME_POLICY.md",
    "Cargo.lock",
    "VERSION_STRATEGY.md",
    "crates/algorithms/src/error/mod.rs",
    "crates/algorithms/src/error/tests.rs",
    "crates/algorithms/src/lib.rs",
    "crates/api/Cargo.toml",
    "crates/api/README.md",
    "crates/api/src/error/mod.rs",
    "crates/api/src/error/registry.rs",
    "crates/api/src/error/traits.rs",
    "crates/api/tests/error_registry_loom.rs",
    "crates/kem/src/error/mod.rs",
    "crates/symmetric/src/error/mod.rs",
    "crates/symmetric/src/lib.rs",
    "crates/symmetric/src/streaming/chacha20poly1305.rs",
    "crates/symmetric/src/streaming/framed.rs",
    "crates/symmetric/src/streaming/gcm.rs",
    "docs/api/error/README.md",
    "docs/migration/V4-ERROR-API.md",
    "docs/tests/README.md",
    "tests/tests/error_api_v4_migration.rs",
    "tools/release-dcrypt.sh",
    "tools/verify-publish-ready.sh",
    "tools/verify-remote-release-ready.py",
)))
R_E_PATHS = (
    "verification/oracle-provisioning/bundle_lib.py",
    "verification/oracle-provisioning/manifest.json",
    "verification/oracle-provisioning/subject-inputs.json",
)

# Literal global A_E closure, frozen only after deterministic generation and
# all subordinate projections reached a fixed point.
FINAL_CHANGED_FILES: dict[str, str] = {
    "assurance/SUPPORTED-ALGORITHMS.md": "100644",
    "assurance/acvp-vector-manifest.json": "100644",
    "assurance/atomic-operations.toml": "100644",
    "assurance/curated-operations.toml": "100644",
    "assurance/error-api-v4/ARTIFACTS.json": "100644",
    "assurance/error-api-v4/README.md": "100644",
    "assurance/error-api-v4/capture.py": "100644",
    "assurance/error-api-v4/fixtures/control.json": "100644",
    "assurance/error-api-v4/generate.py": "100644",
    "assurance/error-api-v4/model.py": "100644",
    "assurance/error-api-v4/package-e.json": "100644",
    "assurance/error-api-v4/rebind-final-subject.py": "100644",
    "assurance/error-api-v4/reviewed-inventory.toml": "100644",
    "assurance/error-api-v4/schema.json": "100644",
    "assurance/error-api-v4/selftest.py": "100644",
    "assurance/error-api-v4/verify.py": "100644",
    "assurance/fuzzing/ARTIFACTS.json": "100644",
    "assurance/fuzzing/README.md": "100644",
    "assurance/fuzzing/ROW-COVERAGE.md": "100644",
    "assurance/fuzzing/campaign-status.json": "100644",
    "assurance/fuzzing/corpus-manifest.json": "100644",
    "assurance/fuzzing/fuzzing_lib.py": "100644",
    "assurance/fuzzing/policy.json": "100644",
    "assurance/fuzzing/rebind-final-subject.py": "100644",
    "assurance/fuzzing/row-mapping.json": "100644",
    "assurance/fuzzing/selftest.py": "100644",
    "assurance/fuzzing/source-bindings.json": "100644",
    "assurance/fuzzing/verify.py": "100644",
    "assurance/interoperability/INTEROPERABILITY.md": "100644",
    "assurance/interoperability/README.md": "100644",
    "assurance/interoperability/interop_lib.py": "100644",
    "assurance/interoperability/matrix.json": "100644",
    "assurance/interoperability/matrix.schema.json": "100644",
    "assurance/interoperability/policy.toml": "100644",
    "assurance/interoperability/protocol-specs/ARTIFACTS.sha256": "100644",
    "assurance/interoperability/protocol-specs/CURRENT-BEHAVIOR.md": "100644",
    "assurance/interoperability/protocol-specs/current-behavior.json": "100644",
    "assurance/interoperability/protocol-specs/rebind-final-subject.py": "100755",
    "assurance/interoperability/protocol-specs/verify-protocol-specs.py": "100755",
    "assurance/ledger.toml": "100644",
    "assurance/public-api-snapshot.json": "100644",
    "assurance/side-channel/ARTIFACTS.json": "100644",
    "assurance/side-channel/README.md": "100644",
    "assurance/side-channel/model.py": "100644",
    "assurance/side-channel/package-d.json": "100644",
    "assurance/side-channel/rebind-final-subject.py": "100644",
    "assurance/side-channel/reviewed-inventory.toml": "100644",
    "assurance/side-channel/selftest.py": "100644",
    "assurance/side-channel/verify.py": "100644",
    "assurance/subject-manifest.json": "100644",
    "assurance/threat-models/README.md": "100644",
    "assurance/threat-models/THREAT-MODELS.md": "100644",
    "assurance/threat-models/coverage.json": "100644",
    "assurance/threat-models/fixtures/mitigation-evidence-record.json": "100644",
    "assurance/threat-models/fixtures/review-evidence-record.json": "100644",
    "assurance/threat-models/schema.toml": "100644",
    "assurance/threat-models/threat-model-selftest.py": "100644",
    "assurance/threat-models/threat-models.toml": "100644",
    "assurance/threat-models/threat_model_lib.py": "100644",
}
FINAL_CHANGED_PATHS_SHA256 = (
    "4fdf16d9060e2f36874c69ad78a36548133a1a950858e75117fdc4653b19d4ed"
)

NORMALIZED_REBIND_SHA256 = "668db7482f9d85e5604fa3e241e8ca4f94601fe3aba29c278c46823eac9b8702"
EXPECTED_REVIEWED_FILES: dict[str, tuple[str, int, str]] = {
    "assurance/error-api-v4/README.md": (
        "100644", 2226, "776c07813e09297a6225634f01d8cdbc5f6898e1e26cadb242aafa249fac060f",
    ),
    "assurance/error-api-v4/capture.py": (
        "100644", 40708, "19885ced169cdf025cb2f759ae08b4dea424c64b0051ea4c05734699503d5843",
    ),
    "assurance/error-api-v4/fixtures/control.json": (
        "100644", 1655, "c3b967c7a847003d5f719eed76fe349a1c1b2a4adcab205df600a1f945dfa6df",
    ),
    "assurance/error-api-v4/generate.py": (
        "100644", 4302, "dbde5bec04842e7c91ae78970f8492b784fd2d835b942da83902d3a619c75efe",
    ),
    "assurance/error-api-v4/model.py": (
        "100644", 50083, "65a1e50cb2aa679b414888284635789c2cc5867e132678e60e063007674c317a",
    ),
    "assurance/error-api-v4/reviewed-inventory.toml": (
        "100644", 79953, "5d2ae3900fd3517f3fb6b36d2c4fb7970e984bc8a27e919a7b99562ff601b071",
    ),
    "assurance/error-api-v4/selftest.py": (
        "100644", 19632, "770f06aedcbf6b7c11e64c9a89ddd510191a18b0c85612427cee28760a3604ec",
    ),
    "assurance/error-api-v4/verify.py": (
        "100644", 6660, "5636faa5b90e70640326592162599b0983e07c505be9119bdf13420485e9e5b1",
    ),
}
EXPECTED_PROVIDER_FILES: dict[str, tuple[str, int, str]] = {
    "assurance/fuzzing/rebind-final-subject.py": (
        "100644", 79946, "f2e7e5c0708922df89e3e336bf8fa0d3a640f368194e13876fb73ef04c334300",
    ),
    "assurance/side-channel/rebind-final-subject.py": (
        "100644", 41172, "20749115645db60b22b7a5b715a009a6ea7d3733d167a9459469c21e36cea818",
    ),
    "assurance/interoperability/protocol-specs/rebind-final-subject.py": (
        "100755", 69162, "7b859254d813decd1b5babd18d9def0ac56da40644143682ebeb2103f3cef630",
    ),
}
PROVIDER_MODES = {
    "assurance/fuzzing/rebind-final-subject.py": "--package-e-projection",
    "assurance/side-channel/rebind-final-subject.py": "--package-e-projection",
    "assurance/interoperability/protocol-specs/rebind-final-subject.py":
        "--package-e-projection",
}
PROJECTION_CONTRACTS: dict[str, dict[str, Any]] = {
    "assurance/fuzzing/rebind-final-subject.py": {
        "policy": "dcrypt-package-c-package-e-subordinate-projection-v1",
        "counts": {
            "critical_family_rows": 372,
            "curated_rows": 566,
            "explicit_blocker_rows": 8_826,
            "total_atomic_rows": 9_198,
            "unreviewed_gap_rows": 8_632,
        },
        "bindings": {
            "atomic_operations_sha256": "8e745ab16086aa50e265ad79189375270c5906df8545f540d96426bc348ca11a",
            "control_inputs_sha256": "1d6e478cf9fac07d2c938843099429f019d58976d5f742b503e62868bd863d58",
            "policy_semantic_sha256": "e34ca2a2e80add8731b544c6832f103cf873b321b0813fec229a7fe832a06a39",
            "public_api_snapshot_sha256": "0a7c7d6585b6612f35e9dd5622018ca3c87c5fb51f8fa0e4652904d651c6215f",
            "registry_semantic_sha256": "f9182aa95ff3e7d4db93f15c04a17f593273453d069df496dd2dd4bdeef1772b",
            "subject_commit": R_E_COMMIT,
            "subject_manifest_sha256": R_E_SUBJECT_MANIFEST_SHA256,
            "subject_tree": R_E_TREE,
        },
        "changed": {
            "assurance/fuzzing/ARTIFACTS.json": "100644",
            "assurance/fuzzing/README.md": "100644",
            "assurance/fuzzing/ROW-COVERAGE.md": "100644",
            "assurance/fuzzing/campaign-status.json": "100644",
            "assurance/fuzzing/corpus-manifest.json": "100644",
            "assurance/fuzzing/fuzzing_lib.py": "100644",
            "assurance/fuzzing/policy.json": "100644",
            "assurance/fuzzing/rebind-final-subject.py": "100644",
            "assurance/fuzzing/row-mapping.json": "100644",
            "assurance/fuzzing/selftest.py": "100644",
            "assurance/fuzzing/source-bindings.json": "100644",
            "assurance/fuzzing/verify.py": "100644",
        },
        "invariant": {
            path: "100644" for path in (
                "assurance/fuzzing/compiler_probe.py",
                "assurance/fuzzing/crash-bundle-template.json",
                "assurance/fuzzing/crash-lifecycle-status.json",
                "assurance/fuzzing/crash_lifecycle.py",
                "assurance/fuzzing/generate.py",
                "assurance/fuzzing/local-sanitizer-requirements.json",
                "assurance/fuzzing/run-fuzz-smoke.py",
                "assurance/fuzzing/sanitizer-controls.json",
                "assurance/fuzzing/sanitizer_positive.py",
                "assurance/fuzzing/schemas.py",
                "assurance/fuzzing/schemas/artifacts.schema.json",
                "assurance/fuzzing/schemas/campaign-status.schema.json",
                "assurance/fuzzing/schemas/corpus-manifest.schema.json",
                "assurance/fuzzing/schemas/crash-bundle-template.schema.json",
                "assurance/fuzzing/schemas/crash-lifecycle-status.schema.json",
                "assurance/fuzzing/schemas/local-sanitizer-requirements.schema.json",
                "assurance/fuzzing/schemas/policy.schema.json",
                "assurance/fuzzing/schemas/row-mapping.schema.json",
                "assurance/fuzzing/schemas/sanitizer-controls.schema.json",
                "assurance/fuzzing/schemas/source-bindings.schema.json",
                "assurance/fuzzing/schemas/target-registry.schema.json",
                "assurance/fuzzing/select-fuzz-targets.py",
                "assurance/fuzzing/target-registry.json",
            )
        },
    },
    "assurance/side-channel/rebind-final-subject.py": {
        "policy": "dcrypt-package-d-package-e-subordinate-projection-v1",
        "counts": {
            "curated_rows": 566,
            "production_rust_sources": 255,
            "public_api_units": 18_891,
            "release_blocked_rows": 9_198,
            "total_atomic_rows": 9_198,
            "unreviewed_gap_rows": 8_632,
        },
        "bindings": {
            "atomic_operations_sha256": "8e745ab16086aa50e265ad79189375270c5906df8545f540d96426bc348ca11a",
            "atomic_row_ids_sha256": "ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff",
            "production_source_paths_sha256": "5aae5258561c750a920b36be67c2652f28ea1c8536ad7527f73967633a62b804",
            "production_source_roots_sha256": "3bdf8ea3f968c18983d73ef3d4523e915e4b1c3fa4f7d8949e73d07b97ec298f",
            "production_source_rows_sha256": "e35cb1924e6f4480a557651db3fdebec3b9d1518d42160a8e7895c000f21f2f5",
            "public_api_snapshot_sha256": "0a7c7d6585b6612f35e9dd5622018ca3c87c5fb51f8fa0e4652904d651c6215f",
            "subject_commit": R_E_COMMIT,
            "subject_manifest_sha256": R_E_SUBJECT_MANIFEST_SHA256,
            "subject_tree": R_E_TREE,
        },
        "changed": {
            path: "100644" for path in (
                "assurance/side-channel/ARTIFACTS.json",
                "assurance/side-channel/README.md",
                "assurance/side-channel/model.py",
                "assurance/side-channel/package-d.json",
                "assurance/side-channel/rebind-final-subject.py",
                "assurance/side-channel/reviewed-inventory.toml",
                "assurance/side-channel/selftest.py",
                "assurance/side-channel/verify.py",
            )
        },
        "invariant": {
            path: "100644" for path in (
                "assurance/side-channel/capture.py",
                "assurance/side-channel/fixtures/control.rs",
                "assurance/side-channel/generate.py",
                "assurance/side-channel/schema.json",
            )
        },
    },
    "assurance/interoperability/protocol-specs/rebind-final-subject.py": {
        "policy": "dcrypt-protocol-specs-package-e-subordinate-projection-v1",
        "counts": {
            "changed_files": 5,
            "invariant_files": 3,
            "protocol_files": 8,
            "subject_files": 1_511,
        },
        "bindings": {
            "curated_operations_sha256": "082cc81db8f9fcd9222b195af43208040811ae5f2e5e4565c249fecf6e10dcc8",
            "semantic_registry_sha256": "37b0ecf19b57cf4c526af6bcfbbbf51a3f6bfe034dd19e50a0040fd8742c8eff",
            "subject_manifest_sha256": R_E_SUBJECT_MANIFEST_SHA256,
        },
        "changed": {
            "assurance/interoperability/protocol-specs/ARTIFACTS.sha256": "100644",
            "assurance/interoperability/protocol-specs/CURRENT-BEHAVIOR.md": "100644",
            "assurance/interoperability/protocol-specs/current-behavior.json": "100644",
            "assurance/interoperability/protocol-specs/rebind-final-subject.py": "100755",
            "assurance/interoperability/protocol-specs/verify-protocol-specs.py": "100755",
        },
        "invariant": {
            "assurance/interoperability/protocol-specs/README.md": "100644",
            "assurance/interoperability/protocol-specs/protocol-spec.schema.json": "100644",
            "assurance/interoperability/protocol-specs/protocol-specs-selftest.py": "100755",
        },
    },
}


class RebindError(RuntimeError):
    """Package E topology, trust, projection, or transaction differs."""


@dataclass(frozen=True)
class Snapshot:
    path: Path
    raw: bytes
    mode: int


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _normalized_rebind_sha256(raw: bytes) -> str:
    matches = list(re.finditer(
        rb'^NORMALIZED_REBIND_SHA256 = "([0-9a-f]{64})"$', raw, re.MULTILINE
    ))
    if len(matches) != 1:
        raise RebindError("normalized rebind anchor assignment closure differs")
    start, end = matches[0].span(1)
    return _sha(raw[:start] + b"0" * 64 + raw[end:])


def _git(arguments: list[str], *, binary: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", *arguments],
        cwd=REPO,
        capture_output=True,
        text=not binary,
        timeout=90,
        env={
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "TZ": "UTC",
        },
    )


def _decode_paths(raw: bytes, *, label: str) -> list[str]:
    try:
        result = [value.decode("utf-8") for value in raw.split(b"\0") if value]
    except UnicodeError as error:
        raise RebindError(f"{label} contains a non-UTF-8 path") from error
    if len(result) != len(set(result)):
        raise RebindError(f"{label} contains duplicate paths")
    return result


def _resolve(commit: str, suffix: str = "commit") -> str:
    result = _git(["rev-parse", "--verify", f"{commit}^{{{suffix}}}"])
    value = result.stdout.strip() if result.returncode == 0 else ""
    if re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise RebindError(f"cannot resolve exact Git {suffix}")
    return value


def _parents(commit: str) -> list[str]:
    result = _git(["rev-list", "--parents", "-n", "1", commit])
    values = result.stdout.strip().split() if result.returncode == 0 else []
    if not values or values[0] != commit:
        raise RebindError("cannot resolve exact Git parents")
    return values[1:]


def _diff_paths(parent: str, child: str) -> list[str]:
    result = _git([
        "diff-tree", "--no-commit-id", "--name-only", "-r", "--no-renames",
        "-z", parent, child,
    ], binary=True)
    if result.returncode != 0:
        raise RebindError("cannot inspect committed changed-path closure")
    return sorted(_decode_paths(result.stdout, label=f"{parent}..{child} closure"))


def validate_topology_observation(
    *, a_tree: str, s_tree: str, r_tree: str, s_parents: list[str],
    r_parents: list[str], s_paths: list[str], r_paths: list[str],
) -> None:
    if (
        a_tree != A_D_TREE
        or s_tree != S_E_TREE
        or r_tree != R_E_TREE
        or s_parents != [A_D_COMMIT]
        or r_parents != [S_E_COMMIT]
        or s_paths != list(S_E_PATHS)
        or r_paths != list(R_E_PATHS)
    ):
        raise RebindError("A_D -> S_E -> R_E sole-parent topology/path closure differs")


def verify_base_topology() -> None:
    validate_topology_observation(
        a_tree=_resolve(A_D_COMMIT, "tree"),
        s_tree=_resolve(S_E_COMMIT, "tree"),
        r_tree=_resolve(R_E_COMMIT, "tree"),
        s_parents=_parents(S_E_COMMIT),
        r_parents=_parents(R_E_COMMIT),
        s_paths=_diff_paths(A_D_COMMIT, S_E_COMMIT),
        r_paths=_diff_paths(S_E_COMMIT, R_E_COMMIT),
    )


def _read(path: Path, expected_mode: str = "100644") -> tuple[bytes, int]:
    try:
        before = path.lstat()
    except OSError as error:
        raise RebindError(f"cannot stat candidate path: {path}") from error
    allowed = (
        {0o600, 0o640, 0o644, 0o660, 0o664}
        if expected_mode == "100644"
        else {0o700, 0o750, 0o755, 0o770, 0o775}
    )
    mode = stat.S_IMODE(before.st_mode)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_mode & 0o7000
        or mode & 0o002
        or mode not in allowed
    ):
        raise RebindError(f"candidate path mode/type/link policy differs: {path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        identity = (
            before.st_dev, before.st_ino, before.st_uid, before.st_gid,
            before.st_mode, before.st_nlink, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        )
        if (
            opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid,
            opened.st_mode, opened.st_nlink, opened.st_size,
            opened.st_mtime_ns, opened.st_ctime_ns,
        ) != identity:
            raise RebindError(f"candidate path changed before read: {path}")
        raw = b""
        while len(raw) < before.st_size:
            chunk = os.read(descriptor, min(1 << 20, before.st_size - len(raw)))
            if not chunk:
                raise RebindError(f"candidate path truncated during read: {path}")
            raw += chunk
        if os.read(descriptor, 1) != b"":
            raise RebindError(f"candidate path grew during read: {path}")
        after = os.fstat(descriptor)
        if (
            after.st_dev, after.st_ino, after.st_uid, after.st_gid,
            after.st_mode, after.st_nlink, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        ) != identity:
            raise RebindError(f"candidate path changed during read: {path}")
        return raw, mode
    finally:
        os.close(descriptor)


def _git_blob(revision: str, path: str) -> tuple[str, bytes]:
    entry = _git(["ls-tree", "-z", "--full-tree", revision, "--", path], binary=True)
    records = [value for value in entry.stdout.split(b"\0") if value] if entry.returncode == 0 else []
    if len(records) != 1:
        raise RebindError(f"required committed blob differs: {path}")
    metadata, encoded = records[0].split(b"\t", 1)
    mode, kind, object_id = metadata.decode("ascii").split(" ")
    if encoded.decode("utf-8") != path or kind != "blob" or mode not in {"100644", "100755"}:
        raise RebindError(f"committed path mode/type differs: {path}")
    blob = _git(["cat-file", "blob", object_id], binary=True)
    if blob.returncode != 0:
        raise RebindError(f"cannot read committed blob: {path}")
    return mode, blob.stdout


def _validate_file_anchor(
    path: str, mode: str, raw: bytes, expected: tuple[str, int, str]
) -> None:
    if (mode, len(raw), _sha(raw)) != expected:
        raise RebindError(f"Package E trusted source/provider differs: {path}")


def verify_reviewed_anchors(revision: str | None = None) -> None:
    self_relative = "assurance/error-api-v4/rebind-final-subject.py"
    self_raw = (
        _read(REPO / self_relative)[0]
        if revision is None else _git_blob(revision, self_relative)[1]
    )
    expected_self_anchor = NORMALIZED_REBIND_SHA256
    if revision == A_E_COMMIT:
        embedded = re.search(
            rb'^NORMALIZED_REBIND_SHA256 = "([0-9a-f]{64})"$',
            self_raw,
            re.MULTILINE,
        )
        if embedded is None:
            raise RebindError("completed Package E self anchor is absent")
        expected_self_anchor = embedded.group(1).decode("ascii")
    if (
        expected_self_anchor == "0" * 64
        or _normalized_rebind_sha256(self_raw) != expected_self_anchor
    ):
        raise RebindError("Package E normalized rebind trust anchor is not finalized")
    if len(EXPECTED_REVIEWED_FILES) != 8 or len(EXPECTED_PROVIDER_FILES) != 3:
        raise RebindError("Package E reviewed/provider trust anchors are not finalized")
    for path, expected in {**EXPECTED_REVIEWED_FILES, **EXPECTED_PROVIDER_FILES}.items():
        if revision is None:
            raw, _filesystem_mode = _read(REPO / path, expected[0])
            mode = expected[0]
        else:
            mode, raw = _git_blob(revision, path)
        _validate_file_anchor(path, mode, raw, expected)


def _snapshot(paths: list[Path]) -> list[Snapshot]:
    result: list[Snapshot] = []
    for path in paths:
        raw, mode = _read(path)
        result.append(Snapshot(path=path, raw=raw, mode=mode))
    return result


def _atomic_restore(snapshot: Snapshot) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{snapshot.path.name}.rollback.", dir=snapshot.path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(snapshot.raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, snapshot.mode)
        os.replace(temporary, snapshot.path)
        directory = os.open(snapshot.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _verify_restored(snapshot: Snapshot) -> None:
    raw, mode = _read(snapshot.path, "100644")
    if raw != snapshot.raw or mode != snapshot.mode:
        raise RebindError(f"rollback byte/mode verification failed: {snapshot.path}")


def transactional_call(paths: list[Path], function: Callable[[], Any]) -> Any:
    """Run a bounded candidate action and restore every destination on failure."""

    snapshots = _snapshot(paths)
    try:
        return function()
    except BaseException:
        rollback_errors: list[str] = []
        for snapshot in reversed(snapshots):
            try:
                _atomic_restore(snapshot)
            except BaseException as error:  # pragma: no cover - catastrophic path
                rollback_errors.append(type(error).__name__)
        for snapshot in snapshots:
            try:
                _verify_restored(snapshot)
            except BaseException as error:
                rollback_errors.append(type(error).__name__)
        if rollback_errors:
            raise RebindError(f"rollback failed closed: {rollback_errors}")
        raise


def validate_changed_paths(paths: list[str]) -> None:
    expected = sorted(FINAL_CHANGED_FILES)
    if (
        not expected
        or FINAL_CHANGED_PATHS_SHA256 == "0" * 64
        or _sha(_canonical(expected)) != FINAL_CHANGED_PATHS_SHA256
    ):
        raise RebindError("Package E literal global changed-path freeze is not finalized")
    if paths != expected:
        raise RebindError(
            "Package E global changed-path closure differs: "
            f"missing={sorted(set(expected) - set(paths))}, "
            f"surplus={sorted(set(paths) - set(expected))}"
        )


def parse_projection(raw: bytes, *, provider: str, candidate_commit: str | None) -> dict[str, Any]:
    if provider not in PROJECTION_CONTRACTS:
        raise RebindError(f"unknown subordinate projection provider: {provider}")
    contract = PROJECTION_CONTRACTS[provider]
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RebindError(f"subordinate projection is malformed: {provider}") from error
    if raw != _canonical(document):
        raise RebindError(f"subordinate projection is not canonical: {provider}")
    expected = {
        "schema_version", "content_policy", "r_commit", "r_tree", "candidate_commit",
        "subject_manifest_sha256", "counts", "binding_assignments", "changed_files",
        "invariant_files", "projection_sha256",
    }
    body = {key: value for key, value in document.items() if key != "projection_sha256"}
    rows = [*document.get("changed_files", []), *document.get("invariant_files", [])]
    if (
        set(document) != expected
        or document["schema_version"] != 1
        or document["content_policy"] != contract["policy"]
        or document["r_commit"] != R_E_COMMIT
        or document["r_tree"] != R_E_TREE
        or document["candidate_commit"] != candidate_commit
        or document["subject_manifest_sha256"] != R_E_SUBJECT_MANIFEST_SHA256
        or document["projection_sha256"] != _sha(_canonical(body))
        or document["counts"] != contract["counts"]
        or document["binding_assignments"] != contract["bindings"]
        or not isinstance(document["changed_files"], list)
        or not isinstance(document["invariant_files"], list)
        or any(
            not isinstance(row, dict)
            or set(row) != {"path", "git_mode", "size", "sha256"}
            or row["git_mode"] not in {"100644", "100755"}
            or not isinstance(row["path"], str)
            or re.fullmatch(r"[0-9a-f]{64}", row["sha256"] or "") is None
            or not isinstance(row["size"], int)
            or isinstance(row["size"], bool)
            or row["size"] < 0
            for row in rows
        )
        or len({row["path"] for row in rows}) != len(rows)
        or [row["path"] for row in document["changed_files"]]
        != sorted(contract["changed"])
        or [row["path"] for row in document["invariant_files"]]
        != sorted(contract["invariant"])
        or any(
            row["git_mode"] != contract["changed"][row["path"]]
            for row in document["changed_files"]
        )
        or any(
            row["git_mode"] != contract["invariant"][row["path"]]
            for row in document["invariant_files"]
        )
    ):
        raise RebindError(f"subordinate projection schema/binding differs: {provider}")
    return document


def _projection_row_bytes(path: str, revision: str | None, expected_mode: str) -> bytes:
    if revision is None:
        raw, _filesystem_mode = _read(REPO / path, expected_mode)
        return raw
    mode, raw = _git_blob(revision, path)
    if mode != expected_mode:
        raise RebindError(f"subordinate projection committed mode differs: {path}")
    return raw


def verify_projection_rows(
    document: dict[str, Any], *, provider: str, candidate_commit: str | None
) -> None:
    contract = PROJECTION_CONTRACTS[provider]
    row_revision = candidate_commit
    if row_revision is None and _resolve("HEAD") != R_E_COMMIT:
        row_revision = A_E_COMMIT
    for category, require_change in (("changed_files", True), ("invariant_files", False)):
        modes = contract["changed" if require_change else "invariant"]
        for row in document[category]:
            path = row["path"]
            expected_mode = modes[path]
            raw = _projection_row_bytes(path, row_revision, expected_mode)
            r_mode, r_raw = _git_blob(R_E_COMMIT, path)
            if (
                r_mode != expected_mode
                or row["sha256"] != _sha(raw)
                or row["size"] != len(raw)
                or (require_change and raw == r_raw)
                or (not require_change and raw != r_raw)
            ):
                raise RebindError(f"subordinate projection row bytes differ: {path}")


def _projection(provider: str, candidate_commit: str | None) -> dict[str, Any]:
    arguments = [
        sys.executable, "-B", provider, PROVIDER_MODES[provider],
        "--expected-r-commit", R_E_COMMIT, "--expected-r-tree", R_E_TREE,
    ]
    if candidate_commit is not None:
        arguments.extend(["--candidate-commit", candidate_commit])
    result = subprocess.run(
        arguments,
        cwd=REPO,
        capture_output=True,
        timeout=300,
        env={
            "HOME": os.environ.get("HOME", ""),
            "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC",
        },
    )
    if result.returncode != 0 or result.stderr:
        raise RebindError(f"subordinate projection failed: {provider}")
    document = parse_projection(
        result.stdout, provider=provider, candidate_commit=candidate_commit
    )
    verify_projection_rows(
        document, provider=provider, candidate_commit=candidate_commit
    )
    return document


VALIDATION_GRAPH: tuple[tuple[tuple[str, ...], int, str | None], ...] = (
    (("assurance/error-api-v4/generate.py", "--check"), 0, None),
    (("assurance/error-api-v4/verify.py", "--ci"), 0, None),
    (("assurance/error-api-v4/selftest.py",), 0, None),
    (
        ("assurance/error-api-v4/verify.py", "--release"),
        3,
        "v4 version preparation and publication remain unauthorized",
    ),
    (("assurance/generate-assurance-ledger.py", "--check"), 0, None),
    (("assurance/verify-assurance-ledger.py", "--mode", "ci", "--snapshot-only"), 0, None),
    (("assurance/interoperability/generate-interoperability-matrix.py", "--check"), 0, None),
    (("assurance/interoperability/verify-interoperability.py", "--mode", "ci"), 0, None),
    (
        ("assurance/interoperability/verify-interoperability.py", "--mode", "release"),
        3,
        "total=14816",
    ),
    (("assurance/interoperability/interoperability-selftest.py",), 0, None),
    (("assurance/threat-models/generate-threat-models.py", "--check"), 0, None),
    (("assurance/threat-models/verify-threat-models.py", "--mode", "ci"), 0, None),
    (
        ("assurance/threat-models/verify-threat-models.py", "--mode", "release"),
        1,
        "has release-blocking high residual risk",
    ),
    (("assurance/threat-models/threat-model-selftest.py",), 0, None),
    (("assurance/fuzzing/generate.py", "--check"), 0, None),
    (("assurance/fuzzing/verify.py", "--ci"), 0, None),
    (("assurance/fuzzing/verify.py", "--release"), 3, '"release_gate": "HOLD"'),
    (("assurance/fuzzing/selftest.py",), 0, None),
    (("assurance/side-channel/generate.py", "--check"), 0, None),
    (("assurance/side-channel/verify.py", "--ci"), 0, None),
    (("assurance/side-channel/verify.py", "--release"), 3, "all 9,198 rows remain blocked"),
    (("assurance/side-channel/selftest.py",), 0, None),
    (
        (
            "assurance/interoperability/protocol-specs/verify-protocol-specs.py",
            "--require-final-subject",
            "--check-current-subject",
        ),
        0,
        None,
    ),
    (("assurance/interoperability/protocol-specs/protocol-specs-selftest.py",), 0, None),
)


def run_validation_graph() -> None:
    for arguments, expected_rc, required_fragment in VALIDATION_GRAPH:
        result = subprocess.run(
            [sys.executable, "-B", *arguments],
            cwd=REPO,
            capture_output=True,
            timeout=900,
            env={
                "HOME": os.environ.get("HOME", ""),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "TZ": "UTC",
            },
        )
        combined = result.stdout + result.stderr
        if result.returncode != expected_rc or (
            required_fragment is not None
            and required_fragment.encode("utf-8") not in combined
        ):
            raise RebindError(
                "anchored Package E validation graph failed: "
                f"command={list(arguments)} rc={result.returncode} expected={expected_rc}"
            )
    if any(path.name == "__pycache__" for path in FRAMEWORK.rglob("__pycache__")):
        raise RebindError("validation graph left forbidden Python bytecode cache residue")


def _worktree_paths() -> list[str]:
    tracked = _git(["diff", "--name-only", "-z", "HEAD", "--", "."], binary=True)
    untracked = _git(["ls-files", "--others", "--exclude-standard", "-z", "--", "."], binary=True)
    ignored = _git([
        "ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", "assurance"
    ], binary=True)
    if tracked.returncode != 0 or untracked.returncode != 0 or ignored.returncode != 0:
        raise RebindError("cannot inspect global worktree path closure")
    paths = (
        _decode_paths(tracked.stdout, label="tracked candidate")
        + _decode_paths(untracked.stdout, label="untracked candidate")
        + _decode_paths(ignored.stdout, label="ignored assurance candidate")
    )
    if len(paths) != len(set(paths)):
        raise RebindError("candidate worktree path classes overlap")
    return sorted(path for path in paths if path != ".gitignore")


def _staged_paths() -> list[str]:
    result = _git(["diff", "--cached", "--name-only", "-z", "--", "."], binary=True)
    if result.returncode != 0:
        raise RebindError("cannot inspect candidate index")
    return _decode_paths(result.stdout, label="staged candidate")


def classify_gitignore(
    *, committed_mode: str, committed: bytes, current: bytes,
    difference: bytes, staged_paths: list[str],
) -> tuple[str, str]:
    if committed_mode != "100644" or ".gitignore" in staged_paths:
        raise RebindError("cannot verify protected .gitignore")
    if current == committed and difference == b"" and _sha(current) == PROTECTED_GITIGNORE_COMMITTED_SHA256:
        return "clean-replay", _sha(current)
    if _sha(current) == PROTECTED_GITIGNORE_SHA256 and _sha(difference) == PROTECTED_GITIGNORE_DIFF_SHA256:
        return "protected-dirty-shared-workspace", _sha(current)
    raise RebindError("protected .gitignore bytes/diff differ")


def _gitignore_variant(revision: str) -> tuple[str, str]:
    committed_mode, committed = _git_blob(revision, ".gitignore")
    current, _filesystem_mode = _read(REPO / ".gitignore")
    difference = _git(["diff", "--binary", revision, "--", ".gitignore"], binary=True)
    if difference.returncode != 0:
        raise RebindError("cannot verify protected .gitignore")
    return classify_gitignore(
        committed_mode=committed_mode,
        committed=committed,
        current=current,
        difference=difference.stdout,
        staged_paths=_staged_paths(),
    )


def _candidate_rows(revision: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path, expected_mode in sorted(FINAL_CHANGED_FILES.items()):
        if revision is None:
            raw, _filesystem_mode = _read(REPO / path, expected_mode)
            mode = expected_mode
        else:
            mode, raw = _git_blob(revision, path)
        if mode != expected_mode:
            raise RebindError(f"Package E final Git mode differs: {path}")
        rows.append({
            "git_mode": mode, "path": path, "sha256": _sha(raw), "size": len(raw)
        })
    return rows


def _manifest(
    rows: list[dict[str, Any]], *, candidate_commit: str | None,
    gitignore_variant: str, gitignore_sha256: str, projections: list[dict[str, Any]],
) -> dict[str, Any]:
    body = {
        "candidate_commit": candidate_commit,
        "changed_paths": sorted(FINAL_CHANGED_FILES),
        "content_policy": "dcrypt-package-e-exact-global-candidate-v1",
        "files": rows,
        "projection_sha256": sorted(row["projection_sha256"] for row in projections),
        "protected_gitignore_sha256": gitignore_sha256,
        "r_commit": R_E_COMMIT,
        "r_tree": R_E_TREE,
        "schema_version": 1,
        "worktree_variant": gitignore_variant,
    }
    return {**body, "candidate_manifest_sha256": _sha(_canonical(body))}


def pre_commit_manifest() -> dict[str, Any]:
    verify_base_topology()
    if _resolve("HEAD") != R_E_COMMIT or _staged_paths():
        raise RebindError("pre-A_E requires exact R_E HEAD and an empty index")
    verify_reviewed_anchors()
    run_validation_graph()
    verify_reviewed_anchors()
    paths = _worktree_paths()
    validate_changed_paths(paths)
    variant, gitignore_sha = _gitignore_variant(R_E_COMMIT)
    rows = _candidate_rows(None)
    projections = [_projection(provider, None) for provider in sorted(PROVIDER_MODES)]
    verify_reviewed_anchors()
    if (
        _resolve("HEAD") != R_E_COMMIT
        or _staged_paths()
        or _worktree_paths() != paths
        or _gitignore_variant(R_E_COMMIT) != (variant, gitignore_sha)
        or _candidate_rows(None) != rows
    ):
        raise RebindError("pre-A_E candidate changed during anchored validation")
    return _manifest(
        rows, candidate_commit=None, gitignore_variant=variant,
        gitignore_sha256=gitignore_sha, projections=projections,
    )


def post_commit_manifest(candidate_commit: str) -> dict[str, Any]:
    verify_base_topology()
    if _resolve(candidate_commit) != candidate_commit or _parents(candidate_commit) != [R_E_COMMIT]:
        raise RebindError("A_E must be a sole-parent child of exact R_E")
    if _resolve("HEAD") != candidate_commit or _staged_paths() or _worktree_paths():
        raise RebindError("post-A_E requires exact candidate HEAD, empty index, and no residue")
    validate_changed_paths(_diff_paths(R_E_COMMIT, candidate_commit))
    verify_reviewed_anchors(candidate_commit)
    run_validation_graph()
    verify_reviewed_anchors(candidate_commit)
    variant, gitignore_sha = _gitignore_variant(candidate_commit)
    rows = _candidate_rows(candidate_commit)
    projections = [
        _projection(provider, candidate_commit) for provider in sorted(PROVIDER_MODES)
    ]
    if (
        _resolve("HEAD") != candidate_commit
        or _staged_paths()
        or _worktree_paths()
        or _gitignore_variant(candidate_commit) != (variant, gitignore_sha)
        or _candidate_rows(candidate_commit) != rows
    ):
        raise RebindError("post-A_E candidate changed during anchored validation")
    return _manifest(
        rows, candidate_commit=candidate_commit, gitignore_variant=variant,
        gitignore_sha256=gitignore_sha, projections=projections,
    )


def _package_f_bytes(path: str, revision: str | None, expected_mode: str = "100644") -> bytes:
    if revision is None:
        return _read(REPO / path, expected_mode)[0]
    mode, raw = _git_blob(revision, path)
    if mode != expected_mode:
        raise RebindError(f"Package F Package E projection mode differs: {path}")
    return raw


def _package_f_row(path: str, revision: str | None) -> dict[str, Any]:
    raw = _package_f_bytes(path, revision)
    return {
        "git_mode": "100644",
        "path": path,
        "sha256": _sha(raw),
        "size": len(raw),
    }


def package_f_projection(
    *, expected_r_commit: str, expected_r_tree: str,
    candidate_revision: str | None = None,
) -> dict[str, Any]:
    """Project Package E's current complete subtree without global F authority."""

    if (
        expected_r_commit != PACKAGE_F_R_COMMIT
        or expected_r_tree != PACKAGE_F_R_TREE
        or _resolve(expected_r_commit) != expected_r_commit
        or _resolve(expected_r_commit, "tree") != expected_r_tree
    ):
        raise RebindError("Package F expected R identity differs")
    if candidate_revision is not None and _resolve(candidate_revision) != candidate_revision:
        raise RebindError("Package F candidate commit does not resolve exactly")

    manifest_raw = _package_f_bytes(
        "assurance/subject-manifest.json", candidate_revision
    )
    if _sha(manifest_raw) != PACKAGE_F_SUBJECT_MANIFEST_SHA256:
        raise RebindError("Package F subject manifest digest differs")
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RebindError("Package F subject manifest is malformed") from error
    if (
        not isinstance(manifest, dict)
        or manifest.get("source_commit") != expected_r_commit
        or manifest.get("source_tree") != expected_r_tree
        or not isinstance(manifest.get("files"), list)
        or len(manifest["files"]) != 1511
    ):
        raise RebindError("Package F subject manifest binding/count differs")

    changed_files = [
        _package_f_row(path, candidate_revision) for path in PACKAGE_F_CHANGED_PATHS
    ]
    invariant_files = [
        _package_f_row(path, candidate_revision) for path in PACKAGE_F_INVARIANT_PATHS
    ]
    for row, should_change in (
        *((item, True) for item in changed_files),
        *((item, False) for item in invariant_files),
    ):
        r_mode, r_raw = _git_blob(expected_r_commit, row["path"])
        same = (
            r_mode == row["git_mode"]
            and len(r_raw) == row["size"]
            and _sha(r_raw) == row["sha256"]
        )
        if same == should_change:
            disposition = "did not change" if should_change else "changed"
            raise RebindError(
                f"Package F Package E path {disposition}: {row['path']}"
            )

    model_raw = _package_f_bytes("assurance/error-api-v4/model.py", candidate_revision)
    model_source = model_raw.decode("utf-8", errors="strict")
    assignments: dict[str, str] = {}
    for name in ("R_E_COMMIT", "R_E_TREE"):
        match = re.search(rf'^{name} = "([0-9a-f]{{40}})"$', model_source, re.MULTILINE)
        if match is None:
            raise RebindError(f"Package F Package E model anchor differs: {name}")
        assignments[name] = match.group(1)
    manifest_match = re.search(
        r'^R_E_SUBJECT_MANIFEST_SHA256 = \(\n    "([0-9a-f]{64})"\n\)$',
        model_source,
        re.MULTILINE,
    )
    inventory_match = re.search(
        r'^REVIEWED_INVENTORY_SHA256 = \(\n    "([0-9a-f]{64})"\n\)$',
        model_source,
        re.MULTILINE,
    )
    if manifest_match is None or inventory_match is None:
        raise RebindError("Package F Package E digest anchors differ")
    assignments["R_E_SUBJECT_MANIFEST_SHA256"] = manifest_match.group(1)
    assignments["REVIEWED_INVENTORY_SHA256"] = inventory_match.group(1)
    if (
        assignments["R_E_COMMIT"] != expected_r_commit
        or assignments["R_E_TREE"] != expected_r_tree
        or assignments["R_E_SUBJECT_MANIFEST_SHA256"]
        != PACKAGE_F_SUBJECT_MANIFEST_SHA256
    ):
        raise RebindError("Package F Package E subject model binding differs")

    package_raw = _package_f_bytes(
        "assurance/error-api-v4/package-e.json", candidate_revision
    )
    schema_raw = _package_f_bytes(
        "assurance/error-api-v4/schema.json", candidate_revision
    )
    artifacts_raw = _package_f_bytes(
        "assurance/error-api-v4/ARTIFACTS.json", candidate_revision
    )
    try:
        package = json.loads(package_raw.decode("utf-8"))
        schema = json.loads(schema_raw.decode("utf-8"))
        artifacts = json.loads(artifacts_raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RebindError("Package F Package E generated artifacts are malformed") from error
    if any(
        raw != _canonical(document)
        for raw, document in (
            (package_raw, package), (schema_raw, schema), (artifacts_raw, artifacts)
        )
    ):
        raise RebindError("Package F Package E generated artifact is not canonical")

    expected_counts = {
        "curated_source_rows": 283,
        "expanded_curated_atomic_rows": 566,
        "production_rust_sources": 255,
        "public_identities": 18891,
        "release_blocked_rows": 9198,
        "retained_other_transitional_public_identities": 124,
        "unreviewed_gap_rows": 8632,
    }
    expected_binding = {
        "a_d_commit": A_D_COMMIT,
        "a_d_tree": A_D_TREE,
        "r_e_commit": expected_r_commit,
        "r_e_subject_manifest_sha256": PACKAGE_F_SUBJECT_MANIFEST_SHA256,
        "r_e_tree": expected_r_tree,
        "s_e_commit": S_E_COMMIT,
        "s_e_tree": S_E_TREE,
    }
    if (
        not isinstance(package, dict)
        or package.get("counts") != expected_counts
        or package.get("subject_binding") != expected_binding
        or package.get("reviewed_inventory_sha256")
        != assignments["REVIEWED_INVENTORY_SHA256"]
        or package.get("release_state") != {
            "promotion_eligible": False,
            "publish_eligible": False,
            "release_gate": "HOLD",
            "release_gate_exit_code": 3,
            "version_preparation_authorized": False,
        }
    ):
        raise RebindError("Package F Package E package binding/counts differ")
    input_rows = package.get("input_bindings")
    if not isinstance(input_rows, list):
        raise RebindError("Package F Package E input binding closure differs")
    input_by_path = {
        row.get("path"): row for row in input_rows if isinstance(row, dict)
    }
    expected_input_digests = {
        "assurance/atomic-operations.toml":
            "8e745ab16086aa50e265ad79189375270c5906df8545f540d96426bc348ca11a",
        "assurance/curated-operations.toml":
            "082cc81db8f9fcd9222b195af43208040811ae5f2e5e4565c249fecf6e10dcc8",
        "assurance/public-api-snapshot.json":
            "5fa59a0218c2be98ef653d85da35c616c75b1499cb376f2b12c99eb6813e553d",
        "assurance/subject-manifest.json": PACKAGE_F_SUBJECT_MANIFEST_SHA256,
    }
    for path, digest in expected_input_digests.items():
        raw = _package_f_bytes(path, candidate_revision)
        row = input_by_path.get(path)
        if row != {
            "git_mode": "100644", "path": path, "sha256": digest, "size": len(raw)
        } or _sha(raw) != digest:
            raise RebindError(f"Package F Package E core input differs: {path}")

    subject_schemas: list[dict[str, Any]] = []
    def collect_subject_schemas(value: Any) -> None:
        if isinstance(value, dict):
            properties = value.get("properties")
            if isinstance(properties, dict) and set(properties) == {
                "r_commit", "r_tree", "subject_manifest_sha256"
            }:
                subject_schemas.append(properties)
            for child in value.values():
                collect_subject_schemas(child)
        elif isinstance(value, list):
            for child in value:
                collect_subject_schemas(child)
    collect_subject_schemas(schema)
    expected_subject_schema = {
        "r_commit": {"const": expected_r_commit},
        "r_tree": {"const": expected_r_tree},
        "subject_manifest_sha256": {"const": PACKAGE_F_SUBJECT_MANIFEST_SHA256},
    }
    if len(subject_schemas) != 4 or any(row != expected_subject_schema for row in subject_schemas):
        raise RebindError("Package F Package E evidence schema binding differs")

    artifact_rows = artifacts.get("files") if isinstance(artifacts, dict) else None
    if not isinstance(artifact_rows, list) or len(artifact_rows) != 11:
        raise RebindError("Package F Package E artifact manifest closure differs")
    artifact_by_path = {
        row.get("path"): row for row in artifact_rows if isinstance(row, dict)
    }
    for path in PACKAGE_E_PATHS:
        if path.endswith("/ARTIFACTS.json"):
            continue
        relative = path.removeprefix("assurance/error-api-v4/")
        raw = _package_f_bytes(path, candidate_revision)
        row = artifact_by_path.get(relative)
        if (
            not isinstance(row, dict)
            or row.get("git_mode") != "100644"
            or row.get("path") != relative
            or row.get("sha256") != _sha(raw)
            or row.get("size") != len(raw)
        ):
            raise RebindError(f"Package F Package E artifact row differs: {path}")

    body = {
        "binding_assignments": {
            "atomic_operations_sha256": expected_input_digests["assurance/atomic-operations.toml"],
            "curated_operations_sha256": expected_input_digests["assurance/curated-operations.toml"],
            "public_api_snapshot_sha256": expected_input_digests["assurance/public-api-snapshot.json"],
            "reviewed_inventory_sha256": assignments["REVIEWED_INVENTORY_SHA256"],
            "subject_commit": expected_r_commit,
            "subject_manifest_sha256": PACKAGE_F_SUBJECT_MANIFEST_SHA256,
            "subject_tree": expected_r_tree,
        },
        "candidate_commit": candidate_revision,
        "changed_files": changed_files,
        "content_policy": "dcrypt-package-e-package-f-subordinate-projection-v1",
        "counts": expected_counts,
        "invariant_files": invariant_files,
        "r_commit": expected_r_commit,
        "r_tree": expected_r_tree,
        "schema_version": 1,
        "subject_manifest_sha256": PACKAGE_F_SUBJECT_MANIFEST_SHA256,
    }
    result = {**body, "projection_sha256": _sha(_canonical(body))}
    if (
        [row["path"] for row in [*changed_files, *invariant_files]]
        != [*PACKAGE_F_CHANGED_PATHS, *PACKAGE_F_INVARIANT_PATHS]
        or any(
            tuple(row) != ("git_mode", "path", "sha256", "size")
            for row in [*changed_files, *invariant_files]
        )
        or set(result) != {
            "binding_assignments", "candidate_commit", "changed_files",
            "content_policy", "counts", "invariant_files", "projection_sha256",
            "r_commit", "r_tree", "schema_version", "subject_manifest_sha256",
        }
    ):
        raise RebindError("Package F Package E projection closure differs")
    return result


def _package_f_projection_main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--expected-r-commit", required=True)
    parser.add_argument("--expected-r-tree", required=True)
    parser.add_argument("--candidate-commit")
    args = parser.parse_args(arguments)
    if (
        re.fullmatch(r"[0-9a-f]{40}", args.expected_r_commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", args.expected_r_tree) is None
        or (
            args.candidate_commit is not None
            and re.fullmatch(r"[0-9a-f]{40}", args.candidate_commit) is None
        )
    ):
        raise RebindError("Package F projection identities must be lowercase 40-hex")
    sys.stdout.buffer.write(_canonical(package_f_projection(
        expected_r_commit=args.expected_r_commit,
        expected_r_tree=args.expected_r_tree,
        candidate_revision=args.candidate_commit,
    )))
    return 0


def self_test() -> int:
    controls = 0
    verify_base_topology()
    controls += 1
    observation = {
        "a_tree": A_D_TREE,
        "s_tree": S_E_TREE,
        "r_tree": R_E_TREE,
        "s_parents": [A_D_COMMIT],
        "r_parents": [S_E_COMMIT],
        "s_paths": list(S_E_PATHS),
        "r_paths": list(R_E_PATHS),
    }
    validate_topology_observation(**observation)
    for field in observation:
        changed = json.loads(json.dumps(observation))
        if field.endswith("tree"):
            changed[field] = "0" * 40
        elif field.endswith("parents"):
            changed[field].append(A_D_COMMIT)
        else:
            changed[field].append("surplus")
        try:
            validate_topology_observation(**changed)
        except RebindError:
            controls += 1
        else:
            raise RebindError(f"topology negative control passed: {field}")

    raw, _mode = _read(Path(__file__))
    normalized = _normalized_rebind_sha256(raw)
    if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
        raise RebindError("normalized self digest is malformed")
    if NORMALIZED_REBIND_SHA256 != "0" * 64 and normalized != NORMALIZED_REBIND_SHA256:
        raise RebindError("normalized self digest differs from finalized anchor")
    controls += 1

    for provider in sorted(PROVIDER_MODES):
        projection = _projection(provider, None)
        controls += 1
        mutations = (
            "digest", "commit", "tree", "subject", "policy", "counts", "binding",
            "changed-path", "invariant-path", "mode", "hash", "size", "surplus",
            "duplicate", "candidate",
        )
        for mutation in mutations:
            changed = json.loads(json.dumps(projection))
            if mutation == "digest":
                changed["projection_sha256"] = "0" * 64
            elif mutation == "commit":
                changed["r_commit"] = A_D_COMMIT
            elif mutation == "tree":
                changed["r_tree"] = A_D_TREE
            elif mutation == "subject":
                changed["subject_manifest_sha256"] = "0" * 64
            elif mutation == "policy":
                changed["content_policy"] += "-weakened"
            elif mutation == "counts":
                key = sorted(changed["counts"])[0]
                changed["counts"][key] += 1
            elif mutation == "binding":
                key = sorted(changed["binding_assignments"])[0]
                changed["binding_assignments"][key] = "0" * 64
            elif mutation == "changed-path":
                changed["changed_files"][0]["path"] += "-surplus"
            elif mutation == "invariant-path":
                changed["invariant_files"][0]["path"] += "-surplus"
            elif mutation == "mode":
                row = changed["changed_files"][0]
                row["git_mode"] = "100755" if row["git_mode"] == "100644" else "100644"
            elif mutation == "hash":
                changed["changed_files"][0]["sha256"] = "0" * 64
            elif mutation == "size":
                changed["changed_files"][0]["size"] += 1
            elif mutation == "surplus":
                changed["surplus"] = True
            elif mutation == "duplicate":
                changed["invariant_files"].append(copy.deepcopy(changed["changed_files"][0]))
            else:
                changed["candidate_commit"] = A_D_COMMIT
            if mutation != "digest":
                body = {key: value for key, value in changed.items() if key != "projection_sha256"}
                changed["projection_sha256"] = _sha(_canonical(body))
            try:
                parsed = parse_projection(
                    _canonical(changed), provider=provider, candidate_commit=None
                )
                verify_projection_rows(
                    parsed, provider=provider, candidate_commit=None
                )
            except (KeyError, RebindError):
                controls += 1
            else:
                raise RebindError(
                    f"projection negative control passed: {provider} {mutation}"
                )

    if _staged_paths():
        raise RebindError("self-test requires an empty index")
    controls += 1
    committed_mode, committed = _git_blob(R_E_COMMIT, ".gitignore")
    current, _filesystem_mode = _read(REPO / ".gitignore")
    difference = _git(["diff", "--binary", R_E_COMMIT, "--", ".gitignore"], binary=True)
    if difference.returncode != 0:
        raise RebindError("cannot obtain protected .gitignore self-test fixture")
    classify_gitignore(
        committed_mode=committed_mode, committed=committed, current=current,
        difference=difference.stdout, staged_paths=[],
    )
    controls += 1
    for mutation in ("mode", "current", "diff", "staged"):
        values: dict[str, Any] = {
            "committed_mode": committed_mode,
            "committed": committed,
            "current": current,
            "difference": difference.stdout,
            "staged_paths": [],
        }
        if mutation == "mode":
            values["committed_mode"] = "100755"
        elif mutation == "current":
            values["current"] = current + b"surplus"
        elif mutation == "diff":
            values["difference"] = difference.stdout + b"surplus"
        else:
            values["staged_paths"] = [".gitignore"]
        try:
            classify_gitignore(**values)
        except RebindError:
            controls += 1
        else:
            raise RebindError(f"protected-state negative control passed: {mutation}")

    if FINAL_CHANGED_FILES:
        validate_changed_paths(sorted(FINAL_CHANGED_FILES))
        for changed in (
            sorted(FINAL_CHANGED_FILES)[:-1],
            sorted((*FINAL_CHANGED_FILES, "surplus")),
        ):
            try:
                validate_changed_paths(changed)
            except RebindError:
                controls += 1
            else:
                raise RebindError("global changed-path negative control passed")
    else:
        try:
            validate_changed_paths([])
        except RebindError:
            controls += 1
        else:
            raise RebindError("unfinalized changed closure did not fail closed")

    if EXPECTED_REVIEWED_FILES and EXPECTED_PROVIDER_FILES:
        anchor_revision = None if _resolve("HEAD") == R_E_COMMIT else A_E_COMMIT
        verify_reviewed_anchors(anchor_revision)
        controls += 1
        for path, expected in {**EXPECTED_REVIEWED_FILES, **EXPECTED_PROVIDER_FILES}.items():
            if anchor_revision is None:
                raw_value, _filesystem_mode = _read(REPO / path, expected[0])
            else:
                committed_mode, raw_value = _git_blob(anchor_revision, path)
                if committed_mode != expected[0]:
                    raise RebindError(f"reviewed/provider committed mode differs: {path}")
            try:
                _validate_file_anchor(path, expected[0], raw_value + b"mutation", expected)
            except RebindError:
                controls += 1
            else:
                raise RebindError(f"reviewed/provider anchor mutation passed: {path}")
        mutated_self = raw + b"mutation"
        if _normalized_rebind_sha256(mutated_self) == normalized:
            raise RebindError("normalized self-anchor mutation was not detected")
        controls += 1

    with tempfile.TemporaryDirectory(prefix="dcrypt-package-e-rebind-") as temporary:
        first = Path(temporary) / "first"
        second = Path(temporary) / "second"
        first.write_bytes(b"before-first")
        second.write_bytes(b"before-second")
        os.chmod(first, 0o644)
        os.chmod(second, 0o644)

        def injected_failure() -> None:
            first.write_bytes(b"after-first")
            second.write_bytes(b"after-second")
            os.chmod(second, 0o600)
            raise KeyboardInterrupt("BaseException rollback control")

        try:
            transactional_call([first, second], injected_failure)
        except KeyboardInterrupt:
            pass
        else:
            raise RebindError("rollback control did not raise")
        if (
            first.read_bytes() != b"before-first"
            or second.read_bytes() != b"before-second"
            or stat.S_IMODE(first.stat().st_mode) != 0o644
            or stat.S_IMODE(second.stat().st_mode) != 0o644
        ):
            raise RebindError("BaseException rollback did not restore exact bytes/modes")
        controls += 1

        original_restore = globals()["_atomic_restore"]
        def failed_restore(_snapshot: Snapshot) -> None:
            raise OSError("injected rollback failure")
        globals()["_atomic_restore"] = failed_restore
        try:
            try:
                transactional_call([first], lambda: (_ for _ in ()).throw(ValueError("injected")))
            except RebindError:
                controls += 1
            else:
                raise RebindError("rollback-failure control was not reported")
        finally:
            globals()["_atomic_restore"] = original_restore

    if (
        len(VALIDATION_GRAPH) != 24
        or sum(expected_rc == 3 for _args, expected_rc, _fragment in VALIDATION_GRAPH) != 4
        or sum(expected_rc == 1 for _args, expected_rc, _fragment in VALIDATION_GRAPH) != 1
        or any(expected_rc not in {0, 1, 3} for _args, expected_rc, _fragment in VALIDATION_GRAPH)
    ):
        raise RebindError("anchored validation graph closure differs")
    controls += 1
    print(
        f"Package E rebind self-test passed: controls={controls} "
        f"final-global-closure={'frozen' if FINAL_CHANGED_FILES else 'HOLD-until-literal-freeze'}"
    )
    return controls

def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--package-f-projection":
        try:
            return _package_f_projection_main(sys.argv[2:])
        except (OSError, RebindError, UnicodeError, ValueError) as error:
            print(f"Package F subordinate projection HOLD: {error}", file=sys.stderr)
            return 3
    parser = argparse.ArgumentParser(allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pre-commit", action="store_true")
    mode.add_argument("--post-commit", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--candidate-commit")
    args = parser.parse_args()
    try:
        if args.self_test:
            if args.candidate_commit is not None:
                raise RebindError("self-test does not accept a candidate commit")
            self_test()
            return 0
        if args.pre_commit:
            if args.candidate_commit is not None:
                raise RebindError("pre-commit does not accept a candidate commit")
            document = pre_commit_manifest()
        else:
            if args.candidate_commit is None or re.fullmatch(r"[0-9a-f]{40}", args.candidate_commit) is None:
                raise RebindError("post-commit requires an exact lowercase 40-hex commit")
            document = post_commit_manifest(args.candidate_commit)
        sys.stdout.buffer.write(_canonical(document))
        return 0
    except (OSError, RebindError, UnicodeError, ValueError) as error:
        print(f"Package E rebind HOLD: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
