#!/usr/bin/env python3
"""Print exact code-pinned Package C target metadata for shell consumers."""

from __future__ import annotations

import argparse
import subprocess
import sys

sys.dont_write_bytecode = True

from fuzzing_lib import (
    FuzzingError,
    REPO_ROOT,
    assert_code_pins,
    build_registry,
    parse_canonical_lines,
    read_regular_file,
    select_changed_paths,
    select_changed_rows,
)


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    choices = parser.add_mutually_exclusive_group(required=True)
    choices.add_argument("--all-targets", action="store_true")
    choices.add_argument("--seed-dir-for", metavar="TARGET")
    choices.add_argument("--dictionary-for", metavar="TARGET")
    choices.add_argument("--input-cap-for", metavar="TARGET")
    choices.add_argument("--timeout-for", metavar="TARGET")
    choices.add_argument("--changed-paths-file", metavar="PATH")
    choices.add_argument("--changed-rows-file", metavar="PATH")
    choices.add_argument("--base", metavar="COMMIT")
    parser.add_argument("--head", metavar="COMMIT")
    args = parser.parse_args()
    try:
        assert_code_pins()
        records = {target["id"]: target for target in build_registry()["targets"]}
        if args.all_targets:
            print("\n".join(sorted(records)))
            return 0
        if args.base is not None:
            if args.head is None:
                raise FuzzingError("--base requires --head")
            for value, label in ((args.base, "base"), (args.head, "head")):
                if not value or value.startswith("-") or any(character.isspace() for character in value):
                    raise FuzzingError(f"invalid Git {label} revision")
            diff = subprocess.run(
                ["/usr/bin/git", "diff", "--name-status", "--find-renames", "--find-copies", "--no-ext-diff", f"{args.base}..{args.head}"],
                cwd=REPO_ROOT,
                capture_output=True,
                timeout=30,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
            )
            if diff.returncode != 0:
                raise FuzzingError("Git diff selection failed")
            paths: set[str] = set()
            for line in diff.stdout.decode("utf-8").splitlines():
                fields = line.split("\t")
                if len(fields) not in (2, 3) or not fields[0] or fields[0][0] not in "ACDMRTUXB":
                    raise FuzzingError("Git diff produced an unreviewed name-status row")
                for path in fields[1:]:
                    paths.add(path)
            selected = select_changed_paths(REPO_ROOT, sorted(paths))
            sys.stdout.buffer.write(__import__("fuzzing_lib").canonical_json(selected))
            return 3 if selected["status"] == "HOLD" else 0
        if args.head is not None:
            raise FuzzingError("--head requires --base")
        if args.changed_paths_file is not None or args.changed_rows_file is not None:
            path = args.changed_paths_file or args.changed_rows_file
            raw = read_regular_file(REPO_ROOT, path, label="selector input")
            values = parse_canonical_lines(raw, label="selector input", paths=args.changed_paths_file is not None)
            selected = (
                select_changed_paths(REPO_ROOT, values)
                if args.changed_paths_file is not None
                else select_changed_rows(REPO_ROOT, values)
            )
            sys.stdout.buffer.write(__import__("fuzzing_lib").canonical_json(selected))
            return 3 if selected["status"] == "HOLD" else 0
        requested = next(
            value
            for value in (
                args.seed_dir_for,
                args.dictionary_for,
                args.input_cap_for,
                args.timeout_for,
            )
            if value is not None
        )
        if requested not in records:
            raise FuzzingError(f"unknown fuzz target: {requested}")
        target = records[requested]
        if args.seed_dir_for is not None:
            print(target["seed_selector_path"] or "-")
        elif args.dictionary_for is not None:
            print(target["dictionary_selector_path"] or "-")
        elif args.input_cap_for is not None:
            print(target["runner_input_cap_bytes"])
        else:
            print(target["resource_limits"]["timeout_seconds"])
    except FuzzingError as error:
        print(f"selector HOLD: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
