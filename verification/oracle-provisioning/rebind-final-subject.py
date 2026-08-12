#!/usr/bin/env python3
"""Rebind the normative root to an exact, already committed subject tree."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

from bundle_lib import (  # noqa: E402
    BundleError,
    EXPECTED_NORMATIVE_MANIFEST_SHA256,
    _regular_unlinked_file,
    canonical_json,
    load_manifest,
    validate_manifest,
)
from subject_lib import (  # noqa: E402
    generate_subject_inputs,
    verify_rebind_worktree_scope,
    verify_subject_inputs,
)


PIN_PATTERN = re.compile(
    rb'EXPECTED_NORMATIVE_MANIFEST_SHA256 = "([0-9a-f]{64})"'
)


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _head(repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise BundleError(f"cannot resolve HEAD: {completed.stderr.strip()}")
    return completed.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--subject-commit", required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        repo_root = args.repo_root.resolve()
        provisioning = repo_root / "verification/oracle-provisioning"
        manifest_path = provisioning / "manifest.json"
        subject_path = provisioning / "subject-inputs.json"
        library_path = provisioning / "bundle_lib.py"
        if _head(repo_root) != args.subject_commit:
            raise BundleError(
                "final rebind requires --subject-commit to equal current HEAD; "
                "commit all reviewed subject changes first"
            )
        verify_rebind_worktree_scope(
            repo_root, allow_generated_binding_files=not args.write
        )
        _regular_unlinked_file(library_path, "binding library")
        _regular_unlinked_file(subject_path, "subject-input manifest")
        subject = generate_subject_inputs(repo_root, args.subject_commit)
        verify_subject_inputs(repo_root, subject)
        manifest = load_manifest(manifest_path)
        # Freeze every non-subject section before changing the prior-commit
        # binding. In particular this independently enforces the immutable test
        # semantics pin and the reviewed environment/package shapes.
        validate_manifest(manifest)
        file_digests = {record["path"]: record["sha256"] for record in subject["files"]}
        for key, path in (
            ("lockfile", "verification/Cargo.lock"),
            ("manifest", "verification/Cargo.toml"),
        ):
            if path not in file_digests:
                raise BundleError(f"subject closure omits {path}")
            expected_workspace = {"path": path, "sha256": file_digests[path]}
            if manifest["workspace"][key] != expected_workspace:
                raise BundleError(
                    f"frozen workspace {key} changed; acquire and review a new provisioning "
                    "root rather than silently rebinding it"
                )
        target_digests = {
            path.removeprefix("verification/"): digest
            for path, digest in file_digests.items()
            if path.startswith("verification/tests/")
        }
        for target in manifest["tests"]["targets"]:
            source = target["source"]
            if source not in target_digests:
                raise BundleError(f"subject closure omits exact target source {source}")
            if target["source_sha256"] != target_digests[source]:
                raise BundleError(
                    "frozen test source changed; preserve the discrepancy and obtain a separate "
                    f"semantic review before changing any pin: {source} expected "
                    f"{target['source_sha256']}, got {target_digests[source]}"
                )
        subject_bytes = canonical_json(subject)
        manifest["subject"] = {
            "binding_kind": "exact_prior_commit_and_tree_candidate_not_self_binding",
            "inputs": {
                "file_count": subject["file_count"],
                "path": "verification/oracle-provisioning/subject-inputs.json",
                "sha256": hashlib.sha256(subject_bytes).hexdigest(),
            },
            "rebind_policy": "rerun_after_every_subsequent_subject_change_before_replay",
            "source_commit": subject["source_commit"],
            "source_tree": subject["source_tree"],
            "subsequent_assurance_binding_required": True,
        }
        validate_manifest(manifest)
        manifest_bytes = canonical_json(manifest)
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        library_bytes = library_path.read_bytes()
        matches = list(PIN_PATTERN.finditer(library_bytes))
        if len(matches) != 1:
            raise BundleError("bundle_lib.py lacks one exact normative-manifest pin")
        current_pin = matches[0].group(1).decode("ascii")
        rewritten_library = PIN_PATTERN.sub(
            f'EXPECTED_NORMATIVE_MANIFEST_SHA256 = "{manifest_digest}"'.encode("ascii"),
            library_bytes,
            count=1,
        )
        if args.write:
            _atomic_write(subject_path, subject_bytes, 0o644)
            _atomic_write(manifest_path, manifest_bytes, 0o644)
            _atomic_write(library_path, rewritten_library, 0o644)
            if _head(repo_root) != args.subject_commit:
                raise BundleError("HEAD changed during final rebind; discard candidate outputs and rerun")
            verify_subject_inputs(repo_root, subject)
            if subject_path.read_bytes() != subject_bytes:
                raise BundleError("written subject-input bytes differ from the candidate")
            if manifest_path.read_bytes() != manifest_bytes:
                raise BundleError("written normative-manifest bytes differ from the candidate")
            written_library = library_path.read_bytes()
            written_matches = list(PIN_PATTERN.finditer(written_library))
            if (
                len(written_matches) != 1
                or written_matches[0].group(1).decode("ascii") != manifest_digest
            ):
                raise BundleError("written library does not contain the one exact candidate pin")
            verify_rebind_worktree_scope(
                repo_root, allow_generated_binding_files=True
            )
            print(
                "wrote candidate prior-commit binding: "
                f"commit={subject['source_commit']} tree={subject['source_tree']} "
                f"files={subject['file_count']} manifest_sha256={manifest_digest}"
            )
        else:
            differences = []
            if not subject_path.exists() or subject_path.read_bytes() != subject_bytes:
                differences.append("subject-inputs.json")
            if manifest_path.read_bytes() != manifest_bytes:
                differences.append("manifest.json")
            if current_pin != manifest_digest or EXPECTED_NORMATIVE_MANIFEST_SHA256 != manifest_digest:
                differences.append("bundle_lib.py manifest pin")
            if differences:
                raise BundleError(
                    "final subject rebind is stale; rerun with --write after review: "
                    + ", ".join(differences)
                )
            print(
                "verified candidate prior-commit binding: "
                f"commit={subject['source_commit']} tree={subject['source_tree']} "
                f"files={subject['file_count']} manifest_sha256={manifest_digest}"
            )
        return 0
    except (BundleError, OSError, KeyError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
