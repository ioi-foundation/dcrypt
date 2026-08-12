#!/usr/bin/env python3
"""Verify the dcrypt interoperability framework and fail-closed release gate."""

from __future__ import annotations

import argparse
import sys

from interop_lib import ValidationError, full_validation, load_inputs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("ci", "release"), default="ci")
    args = parser.parse_args()
    try:
        matrix, errors = full_validation(load_inputs())
    except (OSError, ValidationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    counts = matrix["counts"]
    if args.mode == "release" and counts["interoperability_blockers"]:
        print(
            "RELEASE BLOCKED: interoperability completeness has "
            f"{counts['blocked_operation_atoms']} blocked exact operation atoms and "
            f"{counts['blocked_unreviewed_gaps']} blocked unreviewed atomic gaps; "
            f"total={counts['interoperability_blockers']}",
            file=sys.stderr,
        )
        return 3
    print(
        "interoperability verification passed: "
        f"mode={args.mode}, rows={counts['generated_matrix_rows']}, "
        f"passing={counts['passing_operation_atoms']}, "
        f"blocked={counts['interoperability_blockers']}, "
        f"ledger_blockers_unchanged={counts['ledger_atomic_release_blockers']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
