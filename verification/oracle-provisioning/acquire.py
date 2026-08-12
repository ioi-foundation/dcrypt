#!/usr/bin/env python3
"""Acquire every pinned archive from its official static crates.io HTTPS URL."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import ssl
import stat
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.dont_write_bytecode = True

from bundle_lib import BundleError, compare_manifest_to_lock, load_manifest, verify_bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", default=60, type=int)
    args = parser.parse_args()
    stage: Path | None = None
    try:
        manifest = load_manifest(args.manifest)
        compare_manifest_to_lock(manifest, args.lock)
        if args.output.exists() or args.output.is_symlink():
            raise BundleError("acquisition output must not already exist")
        args.output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        parent_mode = args.output.parent.lstat().st_mode
        if not stat.S_ISDIR(parent_mode) or stat.S_ISLNK(parent_mode):
            raise BundleError("acquisition parent must be a real directory")
        stage = Path(tempfile.mkdtemp(prefix=f".{args.output.name}.cold-", dir=args.output.parent))
        context = ssl.create_default_context()
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        for index, package in enumerate(manifest["packages"], 1):
            archive = package["archive"]
            url = archive["url"]
            destination = stage / archive["file"]
            print(f"[{index}/{manifest['package_count']}] GET {url}", file=sys.stderr)
            request = urllib.request.Request(
                url,
                headers={
                    "Accept-Encoding": "identity",
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "User-Agent": "dcrypt-oracle-provisioning/2",
                },
                method="GET",
            )
            digest = hashlib.sha256()
            total = 0
            with opener.open(request, timeout=args.timeout) as response:
                if response.status != 200 or response.geturl() != url:
                    raise BundleError(
                        f"unexpected HTTP response for {url}: "
                        f"status={response.status} final_url={response.geturl()!r}"
                    )
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > archive["size"]:
                            raise BundleError(f"oversized response for {url}")
                        digest.update(chunk)
                        stream.write(chunk)
            if total != archive["size"] or digest.hexdigest() != archive["sha256"]:
                raise BundleError(
                    f"download differs for {url}: size={total} sha256={digest.hexdigest()}"
                )
        verify_bundle(manifest, stage)
        os.rename(stage, args.output)
        stage = None
        print(f"verified cold bundle: {args.output}")
        return 0
    except (BundleError, OSError, urllib.error.URLError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
