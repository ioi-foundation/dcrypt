#!/usr/bin/env python3
"""Safely materialize a Cargo directory source from a verified archive bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

from bundle_lib import (
    BundleError,
    cargo_config,
    compare_manifest_to_lock,
    extract_to_vendor,
    load_manifest,
    verify_bundle,
    verify_vendor,
)
from subject_lib import load_subject_inputs, materialize_subject, verify_subject_inputs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    args = parser.parse_args()
    stage: Path | None = None
    try:
        manifest = load_manifest(args.manifest)
        compare_manifest_to_lock(manifest, args.lock)
        verify_bundle(manifest, args.archives)
        repo_root = args.repo_root.resolve()
        expected_lock = repo_root / manifest["workspace"]["lockfile"]["path"]
        if args.lock.resolve() != expected_lock.resolve():
            raise BundleError("--lock is not the exact bound repository lockfile")
        subject_path = args.manifest.parent / Path(manifest["subject"]["inputs"]["path"]).name
        subject = load_subject_inputs(subject_path)
        subject_raw = subject_path.read_bytes()
        if manifest["subject"]["inputs"] != {
            "file_count": subject["file_count"],
            "path": "verification/oracle-provisioning/subject-inputs.json",
            "sha256": hashlib.sha256(subject_raw).hexdigest(),
        }:
            raise BundleError("normative manifest does not bind the exact subject-input manifest")
        if (
            manifest["subject"]["source_commit"] != subject["source_commit"]
            or manifest["subject"]["source_tree"] != subject["source_tree"]
        ):
            raise BundleError("normative manifest and subject-input Git bindings differ")
        verify_subject_inputs(repo_root, subject)
        if args.output.exists() or args.output.is_symlink():
            raise BundleError("materialization output must not already exist")
        args.output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        parent_mode = args.output.parent.lstat().st_mode
        if not stat.S_ISDIR(parent_mode) or stat.S_ISLNK(parent_mode):
            raise BundleError("materialization parent must be a real directory")
        stage = Path(tempfile.mkdtemp(prefix=f".{args.output.name}.stage-", dir=args.output.parent))
        cargo_home = stage / "cargo-home"
        vendor = stage / "vendor"
        subject_snapshot = stage / "subject"
        cargo_home.mkdir(mode=0o700)
        vendor.mkdir(mode=0o755)
        cargo_home.chmod(0o700)
        vendor.chmod(0o755)
        if any(cargo_home.iterdir()):
            raise BundleError("new CARGO_HOME was not empty")
        for package in manifest["packages"]:
            archive_path = args.archives / package["archive"]["file"]
            extract_to_vendor(archive_path, package, vendor)
        materialize_subject(repo_root, subject, subject_snapshot)
        config = cargo_config(Path("/provision/vendor"))
        config_path = stage / "cargo-config.toml"
        config_path.write_text(config, encoding="utf-8")
        config_path.chmod(0o644)
        record = {
            "cargo_home_initially_empty": True,
            "lockfile_sha256": manifest["workspace"]["lockfile"]["sha256"],
            "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
            "package_count": manifest["package_count"],
            "subject_commit": subject["source_commit"],
            "subject_inputs_sha256": hashlib.sha256(subject_raw).hexdigest(),
            "subject_tree": subject["source_tree"],
        }
        record_path = stage / "materialization.json"
        record_path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        record_path.chmod(0o644)
        verify_vendor(manifest, args.archives, vendor)
        os.rename(stage, args.output)
        stage = None
        print(f"materialized verified vendor source at {args.output}")
        return 0
    except (BundleError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
