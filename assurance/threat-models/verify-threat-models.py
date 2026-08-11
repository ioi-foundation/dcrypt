#!/usr/bin/env python3
"""Fail-closed verifier for the candidate dcrypt threat-model control."""

from __future__ import annotations

import argparse
import datetime as dt
import subprocess
import sys

from threat_model_lib import HERE, format_errors, sha256_path, verify_generated_artifacts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("ci", "release"), default="ci")
    parser.add_argument("--as-of", type=dt.date.fromisoformat, default=dt.date.today())
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        result = subprocess.run(
            [sys.executable, "-B", str(HERE / "threat-model-selftest.py")],
            check=False,
        )
        if result.returncode != 0:
            return result.returncode
    coverage, errors = verify_generated_artifacts(mode=args.mode, as_of=args.as_of)
    if errors:
        print(format_errors(errors), file=sys.stderr)
        return 1
    print(
        "threat-model verification passed: "
        f"models={coverage['counts']['threat_models']}, "
        f"exact_rows={coverage['counts']['atomic_rows']}, "
        f"release_blocked={coverage['counts']['release_blocked_rows']}, "
        f"coverage_sha256={sha256_path(HERE / 'coverage.json')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
