#!/usr/bin/env python3
"""Build a review candidate manifest from a lockfile and a cold archive directory."""

from __future__ import annotations

import argparse
import copy
import hashlib
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from bundle_lib import (
    BundleError,
    canonical_json,
    load_manifest,
    lock_records,
    manifest_package,
    sha256_file,
    validate_manifest,
    verify_bundle,
)
from subject_lib import load_subject_inputs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--workspace-manifest", type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument(
        "--template", default=Path(__file__).with_name("manifest.json"), type=Path
    )
    parser.add_argument(
        "--subject-inputs",
        default=Path(__file__).with_name("subject-inputs.json"),
        type=Path,
    )
    args = parser.parse_args()
    try:
        workspace_manifest = args.workspace_manifest or args.lock.with_name("Cargo.toml")
        records = lock_records(args.lock)
        packages = []
        for record in records:
            path = args.archives / f"{record['name']}-{record['version']}.crate"
            packages.append(manifest_package(record, path))
        result = copy.deepcopy(load_manifest(args.template))
        subject = load_subject_inputs(args.subject_inputs)
        subject_bytes = args.subject_inputs.read_bytes()
        if result["subject"]["source_commit"] != subject["source_commit"]:
            raise BundleError("template and subject-input source commits differ")
        if result["subject"]["source_tree"] != subject["source_tree"]:
            raise BundleError("template and subject-input source trees differ")
        if result["subject"]["inputs"] != {
            "file_count": subject["file_count"],
            "path": "verification/oracle-provisioning/subject-inputs.json",
            "sha256": hashlib.sha256(subject_bytes).hexdigest(),
        }:
            raise BundleError("template does not bind the exact subject-input manifest")
        result["workspace"]["lockfile"]["sha256"] = sha256_file(args.lock)
        result["workspace"]["manifest"]["sha256"] = sha256_file(workspace_manifest)
        result["package_count"] = len(packages)
        result["packages"] = packages
        result["acquisition"]["aggregate_totals"] = {
            "archive_bytes": sum(package["archive"]["size"] for package in packages),
            "member_count": sum(package["archive"]["member_count"] for package in packages),
            "unpacked_bytes": sum(package["archive"]["unpacked_size"] for package in packages),
        }
        validate_manifest(result)
        verify_bundle(result, args.archives)
        sys.stdout.buffer.write(canonical_json(result))
        return 0
    except BundleError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
