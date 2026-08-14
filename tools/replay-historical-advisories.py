#!/usr/bin/env python3
"""Replay the exact historical advisory regression inventory."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "assurance/audit/historical-advisory-regressions.toml"
EXPECTED_IDS = tuple(f"DCRYPT-2026-{index:04d}" for index in range(1, 12))


class ReplayError(RuntimeError):
    pass


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_inventory(raw: bytes | None = None) -> list[dict[str, str]]:
    if raw is None:
        raw = INVENTORY.read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))
    if set(data) != {"schema-version", "status", "owner", "review-deadline", "limitation", "regression"}:
        raise ReplayError("historical inventory top-level closure differs")
    if data["schema-version"] != 1 or data["status"] != "inventory-only-replay-required":
        raise ReplayError("historical inventory identity differs")
    rows = data["regression"]
    if not isinstance(rows, list) or tuple(row.get("id") for row in rows) != EXPECTED_IDS:
        raise ReplayError("historical inventory must contain the exact ordered eleven advisories")
    for row in rows:
        if set(row) != {"id", "name", "source", "command", "status"}:
            raise ReplayError(f"{row.get('id', '<unknown>')} row closure differs")
        if row["status"] != "source-bound-replay-required":
            raise ReplayError(f"{row['id']} is incorrectly promoted")
        source = ROOT / row["source"]
        if not source.exists() or source.is_symlink():
            raise ReplayError(f"{row['id']} source is absent or symlinked")
        argv = shlex.split(row["command"])
        if not argv or any("\x00" in item for item in argv):
            raise ReplayError(f"{row['id']} command is invalid")
    return rows


def git_value(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0:
        raise ReplayError(f"git {' '.join(args)} failed")
    return result.stdout.strip()


def run_replay(output: pathlib.Path) -> dict:
    inventory_raw = INVENTORY.read_bytes()
    rows = load_inventory(inventory_raw)
    environment = os.environ.copy()
    environment.update({
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
    })
    results = []
    for row in rows:
        argv = shlex.split(row["command"])
        completed = subprocess.run(
            argv, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        results.append({
            "argv": argv,
            "command_sha256": digest(row["command"].encode("utf-8")),
            "exit_code": completed.returncode,
            "id": row["id"],
            "output_sha256": digest(completed.stdout),
            "passed": completed.returncode == 0,
            "source": row["source"],
        })
        if completed.returncode != 0:
            sys.stderr.buffer.write(completed.stdout[-16384:])
            break
    head = git_value("rev-parse", "HEAD")
    report = {
        "classification": "first-party-reproducible-software-regression-replay",
        "content_policy": "dcrypt-historical-advisory-replay-v1",
        "environment": {
            "cargo": subprocess.run(["cargo", "--version"], cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True).stdout.strip(),
            "rustc": subprocess.run(["rustc", "--version", "--verbose"], cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True).stdout.strip().splitlines(),
            "variables": {key: environment[key] for key in ("CARGO_INCREMENTAL", "CARGO_NET_OFFLINE", "LANG", "LC_ALL", "TZ")},
        },
        "generated_at_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "independent_replay_claimed": False,
        "inventory_sha256": digest(inventory_raw),
        "passed": len(results) == len(rows) and all(row["passed"] for row in results),
        "results": results,
        "schema_version": 1,
        "subject": {"commit": head, "tree": git_value("rev-parse", "HEAD^{tree}")},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def self_test() -> None:
    rows = load_inventory()
    if len(rows) != 11:
        raise AssertionError("control inventory count differs")
    mutated = INVENTORY.read_text(encoding="utf-8").replace(
        'id = "DCRYPT-2026-0001"', 'id = "DCRYPT-2026-0099"', 1
    ).encode("utf-8")
    try:
        load_inventory(mutated)
    except ReplayError:
        pass
    else:
        raise AssertionError("mutated advisory id was accepted")


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--run", action="store_true")
    action.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("historical advisory replay self-test passed")
            return 0
        if args.check:
            if args.output is not None:
                parser.error("--output is valid only with --run")
            rows = load_inventory()
            print(f"historical advisory replay inventory passed: rows={len(rows)}")
            return 0
        if args.output is None:
            parser.error("--run requires --output")
        report = run_replay(args.output)
        if not report["passed"]:
            print("historical advisory replay failed", file=sys.stderr)
            return 1
        print(f"historical advisory replay passed: rows={len(report['results'])} report={args.output}")
        return 0
    except (OSError, UnicodeError, ValueError, ReplayError, subprocess.SubprocessError) as error:
        print(f"historical advisory replay invalid: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
