#!/usr/bin/env python3
"""Validate or rewrite exact dcrypt path-dependency pins in isolated workspaces."""

from __future__ import annotations

import argparse
import os
import re
import stat
import tempfile
import tomllib
from pathlib import Path


DEPENDENCIES = ("dcrypt-algorithms", "dcrypt-internal")
SECTION = re.compile(r"^\s*\[([^]]+)]\s*(?:#.*)?$")
DEPENDENCY = re.compile(
    r'^(?P<prefix>\s*)(?P<name>[A-Za-z0-9_-]+)(?P<open>\s*=\s*\{)'
    r'(?P<body>.*)(?P<close>\}\s*(?:#.*)?(?:\r?\n)?)$'
)
VERSION = re.compile(r'(?P<prefix>\bversion\s*=\s*")=(?P<value>[^"]+)(?P<suffix>")')


def parsed_dependencies(text: str) -> dict[str, object]:
    document = tomllib.loads(text)
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, dict):
        raise ValueError("manifest has no [dependencies] table")
    return dependencies


def validate(text: str, expected: str) -> None:
    dependencies = parsed_dependencies(text)
    for name in DEPENDENCIES:
        value = dependencies.get(name)
        if not isinstance(value, dict):
            raise ValueError(f"{name} must use an inline dependency table")
        path = value.get("path")
        version = value.get("version")
        if not isinstance(path, str) or not path:
            raise ValueError(f"{name} must remain a local path dependency")
        if version != f"={expected}":
            raise ValueError(
                f"{name} must be pinned to ={expected}, found {version!r}"
            )


def rewritten(text: str, before: str, after: str) -> str:
    validate(text, before)
    section = ""
    changed: set[str] = set()
    output: list[str] = []

    for line in text.splitlines(keepends=True):
        header = SECTION.match(line.rstrip("\r\n"))
        if header:
            section = header.group(1)

        match = DEPENDENCY.match(line)
        if section != "dependencies" or match is None:
            output.append(line)
            continue

        name = match.group("name")
        if name not in DEPENDENCIES:
            output.append(line)
            continue

        body = match.group("body")
        versions = list(VERSION.finditer(body))
        if len(versions) != 1:
            raise ValueError(f"{name} must contain exactly one inline version field")
        if f'path = "' not in body:
            raise ValueError(f"{name} lost its inline path field")
        version = versions[0]
        if version.group("value") != before:
            raise ValueError(
                f"{name} expected ={before}, found ={version.group('value')}"
            )
        replacement = version.group("prefix") + f"={after}" + version.group("suffix")
        body = body[: version.start()] + replacement + body[version.end() :]
        output.append(
            match.group("prefix")
            + name
            + match.group("open")
            + body
            + match.group("close")
        )
        changed.add(name)

    missing = set(DEPENDENCIES) - changed
    if missing:
        raise ValueError(f"dependency line(s) were not rewritten: {sorted(missing)}")

    result = "".join(output)
    validate(result, after)
    return result


def atomic_write(path: Path, text: str) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def self_test() -> None:
    sample = """[package]
name = "fixture"
version = "0.0.0"
publish = false

[dependencies]
dcrypt-algorithms = { version = "=2.0.0", path = "../../crates/algorithms", default-features = false }
dcrypt-internal = { version = "=2.0.0", path = "../../crates/internal", default-features = false }
base64 = "=0.22.1"
"""
    result = rewritten(sample, "2.0.0", "3.0.0")
    validate(result, "3.0.0")
    if 'base64 = "=0.22.1"' not in result:
        raise AssertionError("unrelated dependency changed")
    try:
        rewritten(result, "2.0.0", "3.0.0")
    except ValueError:
        pass
    else:
        raise AssertionError("stale source version was accepted")
    print("isolated-workspace version updater self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--expect")
    parser.add_argument("--from-version")
    parser.add_argument("--to-version")
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()

    if arguments.self_test:
        self_test()
        return 0

    if arguments.manifest is None:
        parser.error("--manifest is required")
    path = arguments.manifest.resolve()
    text = path.read_text(encoding="utf-8")

    if arguments.expect is not None:
        if arguments.from_version is not None or arguments.to_version is not None:
            parser.error("--expect cannot be combined with rewrite options")
        validate(text, arguments.expect)
        return 0

    if arguments.from_version is None or arguments.to_version is None:
        parser.error("use --expect or both --from-version and --to-version")
    atomic_write(path, rewritten(text, arguments.from_version, arguments.to_version))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
