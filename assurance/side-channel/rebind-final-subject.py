#!/usr/bin/env python3
"""Package D's sole exact-34-path R_D to A_D topology authority."""

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
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True

FRAMEWORK = Path(__file__).resolve().parent
REPO = FRAMEWORK.parent.parent
R_COMMIT = "a79f1ac6b8cd2d853482f4a32a83f239611ba13e"
R_TREE = "28c04fffd98b76f447d55aa313fba13881604649"
S_COMMIT = "9c7d2941819ef0e268d5835a30afdf796f94297f"
S_TREE = "249c0cb9ac76569e8e8934d2ea42f01ef9814efa"
A_C_COMMIT = "7688120b3d3a7cdf870c5036b8bb6b094fd9ea5d"
ORACLE_REBIND_PATHS = (
    "verification/oracle-provisioning/bundle_lib.py",
    "verification/oracle-provisioning/manifest.json",
    "verification/oracle-provisioning/subject-inputs.json",
)
S_WIRING_PATHS = (
    ".github/workflows/security-validation.yml",
    "tools/release-dcrypt.sh",
    "tools/verify-publish-ready.sh",
    "tools/verify-remote-release-ready.py",
)
LEGACY_PATHS = (
    "assurance/acvp-vector-manifest.json",
    "assurance/interoperability/matrix.json",
    "assurance/interoperability/policy.toml",
    "assurance/interoperability/protocol-specs/ARTIFACTS.sha256",
    "assurance/interoperability/protocol-specs/CURRENT-BEHAVIOR.md",
    "assurance/interoperability/protocol-specs/current-behavior.json",
    "assurance/interoperability/protocol-specs/verify-protocol-specs.py",
    "assurance/ledger.toml",
    "assurance/public-api-snapshot.json",
    "assurance/subject-manifest.json",
    "assurance/threat-models/coverage.json",
    "assurance/threat-models/fixtures/mitigation-evidence-record.json",
    "assurance/threat-models/fixtures/review-evidence-record.json",
    "assurance/threat-models/threat-models.toml",
)
PACKAGE_C_PATHS = (
    "assurance/fuzzing/ARTIFACTS.json",
    "assurance/fuzzing/campaign-status.json",
    "assurance/fuzzing/corpus-manifest.json",
    "assurance/fuzzing/fuzzing_lib.py",
    "assurance/fuzzing/policy.json",
    "assurance/fuzzing/rebind-final-subject.py",
    "assurance/fuzzing/row-mapping.json",
    "assurance/fuzzing/source-bindings.json",
)
PACKAGE_D_PATHS = (
    "assurance/side-channel/ARTIFACTS.json",
    "assurance/side-channel/README.md",
    "assurance/side-channel/capture.py",
    "assurance/side-channel/fixtures/control.rs",
    "assurance/side-channel/generate.py",
    "assurance/side-channel/model.py",
    "assurance/side-channel/package-d.json",
    "assurance/side-channel/rebind-final-subject.py",
    "assurance/side-channel/reviewed-inventory.toml",
    "assurance/side-channel/schema.json",
    "assurance/side-channel/selftest.py",
    "assurance/side-channel/verify.py",
)
CHANGED_PATHS = tuple(sorted((*LEGACY_PATHS, *PACKAGE_C_PATHS, *PACKAGE_D_PATHS)))
CHANGED_MODES = {
    path: (
        "100755"
        if path == "assurance/interoperability/protocol-specs/verify-protocol-specs.py"
        else "100644"
    )
    for path in CHANGED_PATHS
}
PROTECTED_GITIGNORE_SHA256 = "e4887e3f444e25b7baad39bd6ff3da3ae770f8dc5b3f7cf2c87a117219a8fe2c"
PROTECTED_GITIGNORE_DIFF_SHA256 = "caa005fda38ed3a65d8b92a5b788169ebba47e7106c1389bf4cd7bff980c6552"
PROTECTED_GITIGNORE_COMMITTED_SHA256 = "f34512e77a7cf5fdfd465243dbb286d8e16bfd698cad264bdb1360f008915f26"
C_PROJECTION_POLICY = "dcrypt-package-c-package-d-subordinate-projection-v1"
NORMALIZED_REBIND_SHA256 = "186eb61d88af1492e6d5e45df0b9b17b88e7c17801453236627df45130c4168f"
EXPECTED_D_REVIEWED_FILES = {
    "assurance/side-channel/README.md": ("100644", 2185, "d590f2540a47fb8dbc1d0057f468ba1b0e13796299642ed8c907419d16e89824"),
    "assurance/side-channel/capture.py": ("100644", 41378, "5e6d5e7fac002620fcc1a973197f11e7bfe0899804ab38c67e625eb9d0c73599"),
    "assurance/side-channel/fixtures/control.rs": ("100644", 1189, "1aa7a7cf7e48354c2b2c444a8ce701273e427d413744c07504946c9ff6386a36"),
    "assurance/side-channel/generate.py": ("100644", 4287, "1084ef93a74e75125ff3586d82498cbfb89b70621a5dff921ab3be369c414e54"),
    "assurance/side-channel/model.py": ("100644", 57970, "289c85a5578709878be40a1f7b2dcb5e51d5575d02f1572bf6e0bfbffb6fde1a"),
    "assurance/side-channel/reviewed-inventory.toml": ("100644", 9028, "7e71bd2ad17f318643593307536d0c08e0f42ced5a34a6a61aeac748296de0d6"),
    "assurance/side-channel/selftest.py": ("100644", 27345, "76af9abc9e447acf35fab076e6cc27f1731898752a22af4e3988e9877f50bd7a"),
    "assurance/side-channel/verify.py": ("100644", 6993, "372e4c8aeeb7473bd61c0a5ada6ef3358524b13ea5125c49970e678cbd6ce389"),
}
EXPECTED_C_PROJECTION_PROVIDER = (
    "100644",
    69083,
    "2df5b85b651120e22f188abf622944d3e46b66fb5cbc5593cbee7e8a65a6f1bb",
)
PACKAGE_E_CHANGED_PATHS = tuple(sorted((
    "assurance/side-channel/ARTIFACTS.json",
    "assurance/side-channel/README.md",
    "assurance/side-channel/model.py",
    "assurance/side-channel/package-d.json",
    "assurance/side-channel/rebind-final-subject.py",
    "assurance/side-channel/reviewed-inventory.toml",
    "assurance/side-channel/selftest.py",
    "assurance/side-channel/verify.py",
)))
PACKAGE_E_INVARIANT_PATHS = tuple(sorted(set(PACKAGE_D_PATHS) - set(PACKAGE_E_CHANGED_PATHS)))
PACKAGE_F_CHANGED_PATHS = tuple(sorted((
    "assurance/side-channel/ARTIFACTS.json",
    "assurance/side-channel/model.py",
    "assurance/side-channel/package-d.json",
    "assurance/side-channel/rebind-final-subject.py",
    "assurance/side-channel/reviewed-inventory.toml",
)))
PACKAGE_F_INVARIANT_PATHS = tuple(sorted(set(PACKAGE_D_PATHS) - set(PACKAGE_F_CHANGED_PATHS)))
PACKAGE_E_A_COMMIT = "86a907154c1f8211a1775c1da8186b71a704536f"

if (
    len(LEGACY_PATHS) != 14
    or len(PACKAGE_C_PATHS) != 8
    or len(PACKAGE_D_PATHS) != 12
    or len(CHANGED_PATHS) != 34
    or len(set(CHANGED_PATHS)) != 34
    or len(PACKAGE_E_CHANGED_PATHS) != 8
    or len(PACKAGE_E_INVARIANT_PATHS) != 4
    or set(PACKAGE_E_CHANGED_PATHS) | set(PACKAGE_E_INVARIANT_PATHS) != set(PACKAGE_D_PATHS)
    or set(PACKAGE_E_CHANGED_PATHS) & set(PACKAGE_E_INVARIANT_PATHS)
    or len(PACKAGE_F_CHANGED_PATHS) != 5
    or len(PACKAGE_F_INVARIANT_PATHS) != 7
    or set(PACKAGE_F_CHANGED_PATHS) | set(PACKAGE_F_INVARIANT_PATHS) != set(PACKAGE_D_PATHS)
    or set(PACKAGE_F_CHANGED_PATHS) & set(PACKAGE_F_INVARIANT_PATHS)
):
    raise RuntimeError("Package D exact changed-path partition differs")


class RebindError(RuntimeError):
    """The Package D transaction or topology differs from reviewed intent."""


@dataclass(frozen=True)
class Snapshot:
    raw: bytes
    mode: int


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _normalized_rebind_sha256(raw: bytes) -> str:
    matches = list(re.finditer(
        rb'^NORMALIZED_REBIND_SHA256 = "([0-9a-f]{64})"$',
        raw,
        re.MULTILINE,
    ))
    if len(matches) != 1:
        raise RebindError("normalized rebind anchor assignment closure differs")
    start, end = matches[0].span(1)
    normalized = raw[:start] + (b"0" * 64) + raw[end:]
    return _sha(normalized)


def _reviewed_anchor_raw(path: str, revision: str | None) -> tuple[str, bytes]:
    if revision is None:
        raw, _filesystem_mode = _read_worktree(path, "100644")
        return "100644", raw
    return _git_blob(revision, path)


def _verify_reviewed_anchors(revision: str | None) -> None:
    self_path = "assurance/side-channel/rebind-final-subject.py"
    self_mode, self_raw = _reviewed_anchor_raw(self_path, revision)
    if (
        self_mode != "100644"
        or NORMALIZED_REBIND_SHA256 == "0" * 64
        or _normalized_rebind_sha256(self_raw) != NORMALIZED_REBIND_SHA256
    ):
        raise RebindError("Package D normalized rebind trust anchor differs")
    if set(EXPECTED_D_REVIEWED_FILES) != {
        "assurance/side-channel/README.md",
        "assurance/side-channel/capture.py",
        "assurance/side-channel/fixtures/control.rs",
        "assurance/side-channel/generate.py",
        "assurance/side-channel/model.py",
        "assurance/side-channel/reviewed-inventory.toml",
        "assurance/side-channel/selftest.py",
        "assurance/side-channel/verify.py",
    }:
        raise RebindError("Package D reviewed anchor path closure differs")
    for path, expected in EXPECTED_D_REVIEWED_FILES.items():
        mode, raw = _reviewed_anchor_raw(path, revision)
        if (mode, len(raw), _sha(raw)) != expected:
            raise RebindError(f"Package D reviewed source anchor differs: {path}")
    c_path = "assurance/fuzzing/rebind-final-subject.py"
    c_mode, c_raw = _reviewed_anchor_raw(c_path, revision)
    if (c_mode, len(c_raw), _sha(c_raw)) != EXPECTED_C_PROJECTION_PROVIDER:
        raise RebindError("Package C projection provider trust anchor differs")


def _git(arguments: list[str], *, binary: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", *arguments],
        cwd=REPO,
        capture_output=True,
        timeout=90,
        text=not binary,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
    )


def _head() -> str:
    result = _git(["rev-parse", "--verify", "HEAD^{commit}"])
    value = result.stdout.strip() if result.returncode == 0 else ""
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise RebindError("cannot resolve exact HEAD")
    return value


def _tree(commit: str) -> str:
    result = _git(["rev-parse", "--verify", f"{commit}^{{tree}}"])
    value = result.stdout.strip() if result.returncode == 0 else ""
    if len(value) != 40:
        raise RebindError("cannot resolve exact Git tree")
    return value


def _parents(commit: str) -> list[str]:
    result = _git(["rev-list", "--parents", "-n", "1", commit])
    tokens = result.stdout.strip().split() if result.returncode == 0 else []
    if not tokens or tokens[0] != commit:
        raise RebindError("cannot resolve exact Git parents")
    return tokens[1:]


def _decode_paths(raw: bytes, *, label: str) -> list[str]:
    try:
        paths = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    except UnicodeError as error:
        raise RebindError(f"{label} contains a non-UTF-8 path") from error
    if len(paths) != len(set(paths)):
        raise RebindError(f"{label} contains duplicate paths")
    return paths


def _git_entry(revision: str, path: str) -> tuple[str, str] | None:
    result = _git(["ls-tree", "-z", "--full-tree", revision, "--", path], binary=True)
    if result.returncode != 0:
        raise RebindError("cannot inspect committed path")
    records = [record for record in result.stdout.split(b"\0") if record]
    if not records:
        return None
    if len(records) != 1:
        raise RebindError("committed path is ambiguous")
    metadata, encoded = records[0].split(b"\t", 1)
    mode, kind, object_id = metadata.decode("ascii").split(" ")
    if encoded.decode("utf-8") != path or kind != "blob" or mode not in {"100644", "100755"}:
        raise RebindError("committed path type/mode differs")
    return mode, object_id


def _git_blob(revision: str, path: str) -> tuple[str, bytes]:
    entry = _git_entry(revision, path)
    if entry is None:
        raise RebindError(f"required committed path is absent: {path}")
    mode, object_id = entry
    result = _git(["cat-file", "blob", object_id], binary=True)
    if result.returncode != 0:
        raise RebindError("cannot read committed blob")
    return mode, result.stdout


def _read_worktree(path: str, expected_mode: str) -> tuple[bytes, int]:
    absolute = REPO / path
    try:
        before = absolute.lstat()
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
        or mode not in allowed
        or mode & 0o002
        or before.st_mode & 0o7000
    ):
        raise RebindError(f"candidate path mode/type differs: {path}")
    descriptor = os.open(absolute, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        identity = (
            before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode,
            before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns,
        )
        if (
            opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid, opened.st_mode,
            opened.st_nlink, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns,
        ) != identity:
            raise RebindError(f"candidate path changed before read: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode,
            after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        ) != identity:
            raise RebindError(f"candidate path changed during read: {path}")
        raw = b"".join(chunks)
        if len(raw) != before.st_size:
            raise RebindError(f"candidate path size differs: {path}")
        return raw, mode
    finally:
        os.close(descriptor)


def _changed_worktree_paths() -> list[str]:
    changed = _git(["diff", "--name-only", "-z", "HEAD", "--", "."], binary=True)
    untracked = _git(["ls-files", "--others", "--exclude-standard", "-z", "--", "."], binary=True)
    ignored = _git(["ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", "assurance"], binary=True)
    if changed.returncode != 0 or untracked.returncode != 0 or ignored.returncode != 0:
        raise RebindError("cannot inspect candidate path closure")
    paths = (
        _decode_paths(changed.stdout, label="tracked candidate")
        + _decode_paths(untracked.stdout, label="untracked candidate")
        + _decode_paths(ignored.stdout, label="ignored assurance candidate")
    )
    if len(paths) != len(set(paths)):
        raise RebindError("candidate path classes overlap")
    return sorted(path for path in paths if path != ".gitignore")


def validate_changed_paths(paths: list[str]) -> None:
    if paths != list(CHANGED_PATHS):
        raise RebindError(
            "Package D changed closure differs: "
            f"missing={sorted(set(CHANGED_PATHS)-set(paths))}, "
            f"surplus={sorted(set(paths)-set(CHANGED_PATHS))}"
        )


def _staged_paths() -> list[str]:
    result = _git(["diff", "--cached", "--name-only", "-z", "--", "."], binary=True)
    if result.returncode != 0:
        raise RebindError("cannot inspect index")
    return _decode_paths(result.stdout, label="staged paths")


def _verify_base_topology() -> None:
    if _tree(R_COMMIT) != R_TREE or _tree(S_COMMIT) != S_TREE or _parents(R_COMMIT) != [S_COMMIT] or _parents(S_COMMIT) != [A_C_COMMIT]:
        raise RebindError("A_C -> S_D -> R_D topology differs")
    wiring = _git(["diff-tree", "--no-commit-id", "--name-only", "-r", "--no-renames", "-z", A_C_COMMIT, S_COMMIT], binary=True)
    if wiring.returncode != 0 or sorted(_decode_paths(wiring.stdout, label="A_C..S_D closure")) != list(S_WIRING_PATHS):
        raise RebindError("A_C..S_D wiring closure differs")
    changed = _git(["diff-tree", "--no-commit-id", "--name-only", "-r", "--no-renames", "-z", S_COMMIT, R_COMMIT], binary=True)
    if changed.returncode != 0 or sorted(_decode_paths(changed.stdout, label="S_D..R_D closure")) != list(ORACLE_REBIND_PATHS):
        raise RebindError("S_D..R_D oracle-rebind closure differs")


def _gitignore_variant(revision: str) -> tuple[str, str]:
    mode, committed = _git_blob(revision, ".gitignore")
    current, _filesystem_mode = _read_worktree(".gitignore", "100644")
    difference = _git(["diff", "--binary", revision, "--", ".gitignore"], binary=True)
    if difference.returncode != 0 or mode != "100644" or ".gitignore" in _staged_paths():
        raise RebindError("cannot verify protected .gitignore")
    if current == committed and difference.stdout == b"" and _sha(current) == PROTECTED_GITIGNORE_COMMITTED_SHA256:
        return "clean-replay", _sha(current)
    if _sha(current) == PROTECTED_GITIGNORE_SHA256 and _sha(difference.stdout) == PROTECTED_GITIGNORE_DIFF_SHA256:
        return "protected-dirty-shared-workspace", _sha(current)
    raise RebindError("protected .gitignore bytes/diff differ")


def _candidate_rows(revision: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in CHANGED_PATHS:
        if revision is None:
            raw, _filesystem_mode = _read_worktree(path, CHANGED_MODES[path])
            mode = CHANGED_MODES[path]
        else:
            mode, raw = _git_blob(revision, path)
        if mode != CHANGED_MODES[path]:
            raise RebindError(f"Package D Git intent differs: {path}")
        rows.append({"git_mode": mode, "path": path, "sha256": _sha(raw), "size": len(raw)})
    return rows


def _package_e_file_row(path: str, *, revision: str | None) -> dict[str, Any]:
    if revision is None:
        raw, _filesystem_mode = _read_worktree(path, "100644")
        mode = "100644"
    else:
        mode, raw = _git_blob(revision, path)
    if mode != "100644":
        raise RebindError(f"Package E projection mode differs: {path}")
    return {"git_mode": mode, "path": path, "sha256": _sha(raw), "size": len(raw)}


def _package_subject_manifest(
    *, revision: str | None, commit: str, tree: str, expected_sha256: str,
    package_label: str,
) -> tuple[bytes, str]:
    if revision is None:
        raw, _filesystem_mode = _read_worktree("assurance/subject-manifest.json", "100644")
        mode = "100644"
    else:
        mode, raw = _git_blob(revision, "assurance/subject-manifest.json")
    if mode != "100644" or _sha(raw) != expected_sha256:
        raise RebindError(f"{package_label} subject manifest bytes/mode differ")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RebindError(f"{package_label} subject manifest is malformed") from error
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or document.get("source_commit") != commit
        or document.get("source_tree") != tree
        or not isinstance(document.get("files"), list)
    ):
        raise RebindError(f"{package_label} subject manifest binding differs")
    return raw, _sha(raw)


def _package_projection(
    *, expected_r_commit: str, expected_r_tree: str,
    candidate_revision: str | None = None, read_revision: str | None = None,
    changed_paths: tuple[str, ...], invariant_paths: tuple[str, ...],
    subject_manifest_sha256: str, content_policy: str, package_label: str,
) -> dict[str, Any]:
    """Project Package D's complete owned subtree without global authority."""

    resolved_commit = _git(["rev-parse", "--verify", f"{expected_r_commit}^{{commit}}"])
    resolved_tree = _git(["rev-parse", "--verify", f"{expected_r_commit}^{{tree}}"])
    if (
        resolved_commit.returncode != 0
        or resolved_commit.stdout.strip() != expected_r_commit
        or resolved_tree.returncode != 0
        or resolved_tree.stdout.strip() != expected_r_tree
    ):
        raise RebindError(f"{package_label} expected R identity does not resolve exactly")
    if candidate_revision is not None:
        candidate = _git(["rev-parse", "--verify", f"{candidate_revision}^{{commit}}"])
        if candidate.returncode != 0 or candidate.stdout.strip() != candidate_revision:
            raise RebindError(f"{package_label} candidate commit does not resolve exactly")
    data_revision = candidate_revision if candidate_revision is not None else read_revision
    _manifest_raw, manifest_sha256 = _package_subject_manifest(
        revision=data_revision, commit=expected_r_commit, tree=expected_r_tree,
        expected_sha256=subject_manifest_sha256, package_label=package_label,
    )
    changed_files = [_package_e_file_row(path, revision=data_revision) for path in changed_paths]
    invariant_files = [_package_e_file_row(path, revision=data_revision) for path in invariant_paths]
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
            raise RebindError(f"{package_label} Package D path {disposition}: {row['path']}")
    model_raw = (
        _read_worktree("assurance/side-channel/model.py", "100644")[0]
        if data_revision is None
        else _git_blob(data_revision, "assurance/side-channel/model.py")[1]
    )
    namespace: dict[str, Any] = {}
    for name in (
        "ATOMIC_SHA256", "EXPECTED_CURATED", "EXPECTED_GAPS", "EXPECTED_PUBLIC_API_UNITS",
        "EXPECTED_ROWS", "EXPECTED_ROW_IDS_SHA256", "EXPECTED_SOURCES",
        "EXPECTED_SOURCE_PATHS_SHA256", "EXPECTED_SOURCE_ROOTS_SHA256",
        "EXPECTED_SOURCE_ROWS_SHA256", "PUBLIC_SNAPSHOT_SHA256", "SUBJECT_COMMIT",
        "SUBJECT_MANIFEST_SHA256", "SUBJECT_TREE",
    ):
        match = re.search(rf'^{name} = (?P<value>.+)$', model_raw.decode("utf-8", errors="strict"), re.MULTILINE)
        if match is None:
            raise RebindError(f"Package E Package D model anchor is absent: {name}")
        try:
            namespace[name] = json.loads(match.group("value"))
        except json.JSONDecodeError:
            try:
                namespace[name] = int(match.group("value").replace("_", ""))
            except ValueError as error:
                raise RebindError(f"Package E Package D model anchor is malformed: {name}") from error
    if (
        namespace["SUBJECT_COMMIT"] != expected_r_commit
        or namespace["SUBJECT_TREE"] != expected_r_tree
        or namespace["SUBJECT_MANIFEST_SHA256"] != manifest_sha256
    ):
        raise RebindError("Package E Package D subject binding differs")
    if data_revision is None:
        atomic_raw = _read_worktree("assurance/atomic-operations.toml", "100644")[0]
        public_raw = _read_worktree("assurance/public-api-snapshot.json", "100644")[0]
    else:
        atomic_mode, atomic_raw = _git_blob(data_revision, "assurance/atomic-operations.toml")
        public_mode, public_raw = _git_blob(data_revision, "assurance/public-api-snapshot.json")
        if atomic_mode != "100644" or public_mode != "100644":
            raise RebindError("Package E Package D core input mode differs")
    try:
        atomic = tomllib.loads(atomic_raw.decode("utf-8"))
        public = json.loads(public_raw.decode("utf-8"))
    except (UnicodeError, ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError) as error:
        raise RebindError("Package E Package D core inputs are malformed") from error
    if (
        _sha(atomic_raw) != namespace["ATOMIC_SHA256"]
        or _sha(public_raw) != namespace["PUBLIC_SNAPSHOT_SHA256"]
        or len(atomic.get("operation", [])) != namespace["EXPECTED_CURATED"]
        or len(atomic.get("unreviewed-gap", [])) != namespace["EXPECTED_GAPS"]
        or not isinstance(public, dict)
        or len(public.get("entries", [])) != namespace["EXPECTED_PUBLIC_API_UNITS"]
    ):
        raise RebindError("Package E Package D core input binding/counts differ")
    body = {
        "binding_assignments": {
            "atomic_operations_sha256": namespace["ATOMIC_SHA256"],
            "atomic_row_ids_sha256": namespace["EXPECTED_ROW_IDS_SHA256"],
            "production_source_paths_sha256": namespace["EXPECTED_SOURCE_PATHS_SHA256"],
            "production_source_roots_sha256": namespace["EXPECTED_SOURCE_ROOTS_SHA256"],
            "production_source_rows_sha256": namespace["EXPECTED_SOURCE_ROWS_SHA256"],
            "public_api_snapshot_sha256": namespace["PUBLIC_SNAPSHOT_SHA256"],
            "subject_commit": namespace["SUBJECT_COMMIT"],
            "subject_manifest_sha256": namespace["SUBJECT_MANIFEST_SHA256"],
            "subject_tree": namespace["SUBJECT_TREE"],
        },
        "candidate_commit": candidate_revision,
        "changed_files": changed_files,
        "content_policy": content_policy,
        "counts": {
            "curated_rows": namespace["EXPECTED_CURATED"],
            "production_rust_sources": namespace["EXPECTED_SOURCES"],
            "public_api_units": namespace["EXPECTED_PUBLIC_API_UNITS"],
            "release_blocked_rows": namespace["EXPECTED_ROWS"],
            "total_atomic_rows": namespace["EXPECTED_ROWS"],
            "unreviewed_gap_rows": namespace["EXPECTED_GAPS"],
        },
        "invariant_files": invariant_files,
        "r_commit": expected_r_commit,
        "r_tree": expected_r_tree,
        "schema_version": 1,
        "subject_manifest_sha256": manifest_sha256,
    }
    result = {**body, "projection_sha256": _sha(_canonical(body))}
    if (
        [row["path"] for row in [*changed_files, *invariant_files]]
        != [*changed_paths, *invariant_paths]
        or set(changed_paths) | set(invariant_paths) != set(PACKAGE_D_PATHS)
        or set(changed_paths) & set(invariant_paths)
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
        raise RebindError(f"{package_label} Package D projection closure differs")
    return result


def package_e_projection(
    *, expected_r_commit: str, expected_r_tree: str, candidate_revision: str | None = None
) -> dict[str, Any]:
    """Return the immutable completed Package E view of Package D."""

    return _package_projection(
        expected_r_commit=expected_r_commit,
        expected_r_tree=expected_r_tree,
        candidate_revision=candidate_revision,
        read_revision=None if candidate_revision is not None else PACKAGE_E_A_COMMIT,
        changed_paths=PACKAGE_E_CHANGED_PATHS,
        invariant_paths=PACKAGE_E_INVARIANT_PATHS,
        subject_manifest_sha256="d48d134daa383fb12c03e45aebe3bcf16f40e2c6930e17f209e0af95f1133eb4",
        content_policy="dcrypt-package-d-package-e-subordinate-projection-v1",
        package_label="Package E",
    )


def package_f_projection(
    *, expected_r_commit: str, expected_r_tree: str, candidate_revision: str | None = None
) -> dict[str, Any]:
    """Project Package D's current complete subtree for Package F."""

    return _package_projection(
        expected_r_commit=expected_r_commit,
        expected_r_tree=expected_r_tree,
        candidate_revision=candidate_revision,
        changed_paths=PACKAGE_F_CHANGED_PATHS,
        invariant_paths=PACKAGE_F_INVARIANT_PATHS,
        subject_manifest_sha256="95902d2ff4a2f99808ba5d404fbce3175b787b93fdc1538cb55ad350e69505c7",
        content_policy="dcrypt-package-d-package-f-subordinate-projection-v1",
        package_label="Package F",
    )


def _package_e_projection_main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--expected-r-commit", required=True)
    parser.add_argument("--expected-r-tree", required=True)
    parser.add_argument("--candidate-commit")
    args = parser.parse_args(arguments)
    if (
        re.fullmatch(r"[0-9a-f]{40}", args.expected_r_commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", args.expected_r_tree) is None
        or (args.candidate_commit is not None and re.fullmatch(r"[0-9a-f]{40}", args.candidate_commit) is None)
    ):
        raise RebindError("Package E projection identities must be lowercase 40-hex")
    sys.stdout.buffer.write(_canonical(package_e_projection(
        expected_r_commit=args.expected_r_commit,
        expected_r_tree=args.expected_r_tree,
        candidate_revision=args.candidate_commit,
    )))
    return 0


def _package_f_projection_main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--expected-r-commit", required=True)
    parser.add_argument("--expected-r-tree", required=True)
    parser.add_argument("--candidate-commit")
    args = parser.parse_args(arguments)
    if (
        re.fullmatch(r"[0-9a-f]{40}", args.expected_r_commit) is None
        or re.fullmatch(r"[0-9a-f]{40}", args.expected_r_tree) is None
        or (args.candidate_commit is not None and re.fullmatch(r"[0-9a-f]{40}", args.candidate_commit) is None)
    ):
        raise RebindError("Package F projection identities must be lowercase 40-hex")
    sys.stdout.buffer.write(_canonical(package_f_projection(
        expected_r_commit=args.expected_r_commit,
        expected_r_tree=args.expected_r_tree,
        candidate_revision=args.candidate_commit,
    )))
    return 0


def _parse_c_projection(raw: bytes) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RebindError("Package C subordinate projection is malformed") from error
    if raw != _canonical(document):
        raise RebindError("Package C subordinate projection is not canonical")
    expected = {
        "binding_assignments", "changed_files", "changed_paths", "content_policy",
        "invariant_files", "projection_sha256", "r_commit", "r_tree", "schema_version",
        "subject_manifest_sha256",
    }
    if set(document) != expected or document["content_policy"] != C_PROJECTION_POLICY or document["schema_version"] != 1:
        raise RebindError("Package C subordinate projection root/policy differs")
    body = {key: value for key, value in document.items() if key != "projection_sha256"}
    if document["projection_sha256"] != _sha(_canonical(body)):
        raise RebindError("Package C subordinate projection digest differs")
    if (
        document["r_commit"] != R_COMMIT
        or document["r_tree"] != R_TREE
        or len(document["changed_files"]) != 8
        or document["subject_manifest_sha256"] != "12a8ddb037816e802640e921a7012e28a638943dba38eceed6f3ef0cf5465d5b"
        or len(document["invariant_files"]) != 27
        or document["changed_paths"] != list(PACKAGE_C_PATHS)
        or [row.get("path") for row in document["changed_files"]] != list(PACKAGE_C_PATHS)
        or any(
            set(row) != {"git_mode", "path", "sha256", "size"}
            or row["git_mode"] != "100644"
            or not isinstance(row["path"], str)
            or not isinstance(row["sha256"], str)
            or len(row["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in row["sha256"])
            or not isinstance(row["size"], int)
            or isinstance(row["size"], bool)
            or row["size"] < 0
            for row in [*document["changed_files"], *document["invariant_files"]]
        )
    ):
        raise RebindError("Package C subordinate projection partition differs")
    expected_invariants = sorted(
        {
            f"assurance/fuzzing/{path}"
            for path in (
                "README.md", "ROW-COVERAGE.md", "compiler_probe.py", "crash-bundle-template.json",
                "crash-lifecycle-status.json", "crash_lifecycle.py", "generate.py",
                "local-sanitizer-requirements.json", "run-fuzz-smoke.py", "sanitizer-controls.json",
                "sanitizer_positive.py", "schemas.py", "schemas/artifacts.schema.json",
                "schemas/campaign-status.schema.json", "schemas/corpus-manifest.schema.json",
                "schemas/crash-bundle-template.schema.json", "schemas/crash-lifecycle-status.schema.json",
                "schemas/local-sanitizer-requirements.schema.json", "schemas/policy.schema.json",
                "schemas/row-mapping.schema.json", "schemas/sanitizer-controls.schema.json",
                "schemas/source-bindings.schema.json", "schemas/target-registry.schema.json",
                "select-fuzz-targets.py", "selftest.py", "target-registry.json", "verify.py",
            )
        }
    )
    if [row["path"] for row in document["invariant_files"]] != expected_invariants:
        raise RebindError("Package C subordinate invariant path closure differs")
    bindings = document["binding_assignments"]
    if (
        not isinstance(bindings, dict)
        or set(bindings) != {
            "EXPECTED_POLICY_SEMANTIC_SHA256", "EXPECTED_REGISTRY_SEMANTIC_SHA256",
            "FRAMEWORK_SUBJECT_COMMIT", "FRAMEWORK_SUBJECT_MANIFEST_SHA256",
            "FRAMEWORK_SUBJECT_TREE", "STATUS",
        }
        or bindings["FRAMEWORK_SUBJECT_COMMIT"] != R_COMMIT
        or bindings["FRAMEWORK_SUBJECT_TREE"] != R_TREE
        or bindings["FRAMEWORK_SUBJECT_MANIFEST_SHA256"] != document["subject_manifest_sha256"]
        or bindings["STATUS"] != "STABLE-final-subject-bound"
    ):
        raise RebindError("Package C subordinate binding assignment closure differs")
    return document


def _verify_c_projection_rows(document: dict[str, Any], *, revision: str | None) -> None:
    for row in document["changed_files"]:
        if revision is None:
            raw, _filesystem_mode = _read_worktree(row["path"], "100644")
            mode = "100644"
        else:
            mode, raw = _git_blob(revision, row["path"])
        r_mode, r_raw = _git_blob(R_COMMIT, row["path"])
        if (
            mode != "100644"
            or r_mode != "100644"
            or raw == r_raw
            or row["sha256"] != _sha(raw)
            or row["size"] != len(raw)
        ):
            raise RebindError(f"Package C changed-row evidence differs: {row['path']}")
    for row in document["invariant_files"]:
        r_mode, r_raw = _git_blob(R_COMMIT, row["path"])
        if revision is None:
            raw, _filesystem_mode = _read_worktree(row["path"], "100644")
            mode = "100644"
        else:
            mode, raw = _git_blob(revision, row["path"])
        if (
            mode != r_mode
            or mode != "100644"
            or raw != r_raw
            or row["sha256"] != _sha(r_raw)
            or row["size"] != len(r_raw)
        ):
            raise RebindError(f"Package C invariant-row evidence differs: {row['path']}")


def _c_projection(candidate_commit: str | None = None) -> dict[str, Any]:
    arguments = [
        sys.executable,
        "-B",
        "assurance/fuzzing/rebind-final-subject.py",
        "--package-d-projection",
        "--expected-r-commit",
        R_COMMIT,
        "--expected-r-tree",
        R_TREE,
    ]
    if candidate_commit is not None:
        arguments.extend(["--candidate-commit", candidate_commit])
    result = subprocess.run(
        arguments,
        cwd=REPO,
        capture_output=True,
        timeout=300,
        env={"HOME": os.environ.get("HOME", ""), "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
    )
    if result.returncode != 0 or result.stderr:
        raise RebindError("Package C subordinate projection failed")
    document = _parse_c_projection(result.stdout)
    _verify_c_projection_rows(document, revision=candidate_commit)
    return document


def _run(arguments: list[str]) -> None:
    result = subprocess.run(
        [sys.executable, "-B", *arguments],
        cwd=REPO,
        capture_output=True,
        timeout=600,
        env={"HOME": os.environ.get("HOME", ""), "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
    )
    if result.returncode != 0:
        raise RebindError("Package D subordinate structural check failed")


def _run_structural_checks(*, anchor_revision: str | None) -> None:
    _verify_reviewed_anchors(anchor_revision)
    _run(["assurance/side-channel/generate.py", "--check"])
    _run(["assurance/side-channel/verify.py", "--ci"])
    _run(["assurance/side-channel/selftest.py"])
    _run(["assurance/fuzzing/generate.py", "--check"])
    _run(["assurance/fuzzing/verify.py", "--ci"])
    _run(["assurance/generate-assurance-ledger.py", "--check"])
    _run(["assurance/verify-assurance-ledger.py", "--mode", "ci", "--snapshot-only"])
    _run(["assurance/interoperability/generate-interoperability-matrix.py", "--check"])
    _run(["assurance/interoperability/verify-interoperability.py", "--mode", "ci"])
    _run(["assurance/threat-models/generate-threat-models.py", "--check"])
    _run(["assurance/threat-models/verify-threat-models.py", "--mode", "ci"])
    _run([
        "assurance/interoperability/protocol-specs/verify-protocol-specs.py",
        "--require-final-subject",
        "--check-current-subject",
    ])
    _verify_reviewed_anchors(anchor_revision)


def _manifest(rows: list[dict[str, Any]], *, a_commit: str | None, variant: str, gitignore_sha: str, c_projection: dict[str, Any]) -> dict[str, Any]:
    body = {
        "a_commit": a_commit,
        "changed_paths": list(CHANGED_PATHS),
        "content_policy": "dcrypt-package-d-exact-a-candidate-v1",
        "files": rows,
        "package_c_projection_sha256": c_projection["projection_sha256"],
        "protected_gitignore_sha256": gitignore_sha,
        "r_commit": R_COMMIT,
        "r_tree": R_TREE,
        "s_commit": S_COMMIT,
        "schema_version": 1,
        "worktree_variant": variant,
    }
    return {**body, "candidate_manifest_sha256": _sha(_canonical(body))}


def _verify_pre_a() -> tuple[str, str, list[dict[str, Any]], dict[str, Any]]:
    _verify_base_topology()
    if _head() != R_COMMIT or _tree(R_COMMIT) != R_TREE:
        raise RebindError("pre-A HEAD must be exact R_D")
    if _staged_paths():
        raise RebindError("pre-A index must be empty")
    _verify_reviewed_anchors(None)
    validate_changed_paths(_changed_worktree_paths())
    variant, digest = _gitignore_variant(R_COMMIT)
    rows = _candidate_rows()
    projection = _c_projection()
    return variant, digest, rows, projection


def _verify_post_a() -> tuple[str, str, str, list[dict[str, Any]], dict[str, Any]]:
    _verify_base_topology()
    head = _head()
    if _parents(head) != [R_COMMIT]:
        raise RebindError("A_D must be the sole-parent child of R_D")
    if _staged_paths():
        raise RebindError("post-A index must be empty")
    _verify_reviewed_anchors(head)
    changed = _git(["diff-tree", "--no-commit-id", "--name-only", "-r", "--no-renames", "-z", R_COMMIT, head], binary=True)
    if changed.returncode != 0:
        raise RebindError("cannot inspect R_D..A_D closure")
    validate_changed_paths(sorted(_decode_paths(changed.stdout, label="R_D..A_D closure")))
    dirty = _changed_worktree_paths()
    if dirty:
        raise RebindError("post-A worktree has non-protected dirty paths")
    variant, digest = _gitignore_variant(R_COMMIT)
    r_mode, r_ignore = _git_blob(R_COMMIT, ".gitignore")
    a_mode, a_ignore = _git_blob(head, ".gitignore")
    if r_mode != a_mode or r_ignore != a_ignore:
        raise RebindError("A_D changed protected .gitignore")
    rows = _candidate_rows(head)
    projection = _c_projection(head)
    return head, variant, digest, rows, projection


def _atomic_write(path: Path, raw: bytes, mode: int) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            view = memoryview(raw)
            while view:
                written = stream.write(view)
                if written is None or written <= 0:
                    raise RebindError("short transaction write")
                view = view[written:]
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _snapshots() -> dict[str, Snapshot]:
    return {
        path: Snapshot(*_read_worktree(path, CHANGED_MODES[path]))
        for path in CHANGED_PATHS
    }


def _restore(snapshots: dict[str, Snapshot]) -> None:
    failures: list[str] = []
    for path in CHANGED_PATHS:
        snapshot = snapshots[path]
        try:
            try:
                current, mode = _read_worktree(path, CHANGED_MODES[path])
            except (OSError, RebindError):
                absolute = REPO / path
                if os.path.lexists(absolute) and (
                    absolute.is_symlink() or not absolute.is_file()
                ):
                    raise RebindError(f"rollback target changed type: {path}")
                current, mode = b"", -1
            if current != snapshot.raw or mode != snapshot.mode:
                _atomic_write(REPO / path, snapshot.raw, snapshot.mode)
            restored, restored_mode = _read_worktree(path, CHANGED_MODES[path])
            if restored != snapshot.raw or restored_mode != snapshot.mode:
                raise RebindError(f"rollback did not restore exact path: {path}")
        except BaseException as error:
            failures.append(f"{path}: {error}")
    if failures:
        raise RebindError("Package D rollback failed: " + " | ".join(failures))


def _transaction(*, keep: bool) -> dict[str, Any]:
    variant, digest, _rows, _projection = _verify_pre_a()
    snapshots = _snapshots()
    initial_paths = _changed_worktree_paths()
    primary: BaseException | None = None
    result: dict[str, Any] | None = None
    try:
        _run(["assurance/side-channel/generate.py"])
        _run_structural_checks(anchor_revision=None)
        variant_after, digest_after, rows, projection = _verify_pre_a()
        if variant_after != variant or digest_after != digest or _changed_worktree_paths() != initial_paths:
            raise RebindError("Package D transaction changed protected/global closure")
        result = _manifest(
            rows,
            a_commit=None,
            variant=variant,
            gitignore_sha=digest,
            c_projection=projection,
        )
    except BaseException as error:
        primary = error
    if not keep or primary is not None:
        try:
            _restore(snapshots)
            if _changed_worktree_paths() != initial_paths:
                raise RebindError("Package D rollback path closure differs")
        except BaseException as rollback_error:
            if primary is not None:
                raise RebindError(f"transaction and rollback failed: {rollback_error}") from primary
            raise
    if primary is not None:
        raise primary
    if result is None:
        raise RebindError("Package D transaction produced no manifest")
    return result


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--package-f-projection":
        try:
            return _package_f_projection_main(sys.argv[2:])
        except (OSError, RebindError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
            print(f"Package F subordinate projection HOLD: {error}", file=sys.stderr)
            return 3
    if len(sys.argv) >= 2 and sys.argv[1] == "--package-e-projection":
        try:
            return _package_e_projection_main(sys.argv[2:])
        except (OSError, RebindError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
            print(f"Package E subordinate projection HOLD: {error}", file=sys.stderr)
            return 3
    parser = argparse.ArgumentParser(allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        if args.dry_run or args.apply:
            document = _transaction(keep=args.apply)
        elif _head() == R_COMMIT:
            variant, digest, rows, projection = _verify_pre_a()
            _run_structural_checks(anchor_revision=None)
            document = _manifest(rows, a_commit=None, variant=variant, gitignore_sha=digest, c_projection=projection)
        else:
            head, variant, digest, rows, projection = _verify_post_a()
            _run_structural_checks(anchor_revision=head)
            document = _manifest(rows, a_commit=head, variant=variant, gitignore_sha=digest, c_projection=projection)
        sys.stdout.buffer.write(_canonical(document))
        return 0
    except (OSError, RebindError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        print(f"Package D final-subject rebind HOLD: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
