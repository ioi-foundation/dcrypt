#!/usr/bin/env python3
"""Verify the manifest, lock binding, exact bundle contents, and publisher claims."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from bundle_lib import BundleError, compare_manifest_to_lock, load_manifest, verify_bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        compare_manifest_to_lock(manifest, args.lock)
        verify_bundle(manifest, args.archives)
        print(
            f"verified {manifest['package_count']} registry archives; "
            "provisioning does not change blocked oracle lineage status"
        )
        return 0
    except BundleError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
