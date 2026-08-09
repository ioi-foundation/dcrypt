#!/usr/bin/env python3
"""Validate or rewrite exact path pins in every classified workspace."""

from __future__ import annotations

import argparse
import os
import re
import stat
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = PROJECT_ROOT / "implementation-boundary.toml"
EXACT_VERSION = re.compile(r"=[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
DEPENDENCY_LINE = re.compile(
    r"(?m)^(?P<prefix>\s*(?P<name>[A-Za-z0-9_-]+)\s*=\s*\{)"
    r"(?P<body>[^\n}]*)(?P<suffix>}\s*(?:#.*)?)$"
)
VERSION_FIELD = re.compile(r'\bversion\s*=\s*"(?P<value>[^"]*)"')


def classified_paths(policy: dict[str, Any]) -> list[Path]:
    values: list[str] = []
    for key in ("verification-workspace", "fuzz-workspace"):
        value = policy.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"policy {key} must be a non-empty string")
        values.append(value)
    configurations = policy.get("owned-excluded-workspaces", [])
    if not isinstance(configurations, list):
        raise ValueError("policy owned-excluded-workspaces must be an array")
    for configuration in configurations:
        if not isinstance(configuration, dict):
            raise ValueError("owned excluded workspace entries must be tables")
        value = configuration.get("path")
        if not isinstance(value, str) or not value:
            raise ValueError("owned excluded workspace path must be a non-empty string")
        values.append(value)

    paths = [Path(value) for value in values]
    if len(set(paths)) != len(paths):
        raise ValueError("classified workspace paths must be unique")
    for path in paths:
        root = (PROJECT_ROOT / path).resolve()
        if path.is_absolute() or root == PROJECT_ROOT or not root.is_relative_to(PROJECT_ROOT):
            raise ValueError(f"classified workspace path escapes repository: {path}")
    return paths


def validate_root_excludes(
    classified: Iterable[Path], declared: Iterable[str]
) -> None:
    classified_paths = {path.as_posix() for path in classified}
    declared_values = list(declared)
    if not all(isinstance(value, str) and value for value in declared_values):
        raise ValueError("root workspace.exclude must contain only non-empty strings")
    declared_paths = {Path(value).as_posix() for value in declared_values}
    if len(declared_paths) != len(declared_values):
        raise ValueError("root workspace.exclude contains duplicate paths")
    missing = sorted(classified_paths - declared_paths)
    extra = sorted(declared_paths - classified_paths)
    if missing or extra:
        raise ValueError(
            "root workspace.exclude classification mismatch: "
            f"missing={missing}, extra={extra}"
        )


def dependency_tables(manifest: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for name in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = manifest.get(name, {})
        if isinstance(table, dict):
            yield table
    for target in manifest.get("target", {}).values():
        if not isinstance(target, dict):
            continue
        for name in ("dependencies", "dev-dependencies", "build-dependencies"):
            table = target.get(name, {})
            if isinstance(table, dict):
                yield table


def exact_path_requirement(
    manifest_path: Path, dependency: str, specification: dict[str, Any]
) -> str:
    requirement = specification.get("version")
    if not isinstance(requirement, str) or not EXACT_VERSION.fullmatch(requirement):
        raise ValueError(
            f"{manifest_path}: path dependency {dependency} lacks an exact version"
        )
    return requirement


def dependency_package_name(dependency: str, specification: dict[str, Any]) -> str:
    package = specification.get("package", dependency)
    if not isinstance(package, str) or not package:
        raise ValueError(f"dependency {dependency} has an invalid package alias")
    return package


def validate_resolved_pin(
    manifest_path: Path, dependency: str, requirement: str, target_version: str
) -> None:
    if requirement != f"={target_version}":
        raise ValueError(
            f"{manifest_path}: {dependency} must be pinned to ={target_version}, "
            f"found {requirement!r}"
        )


def package_identity(manifest_path: Path) -> tuple[str, str]:
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    package = manifest.get("package", {})
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not name:
        raise ValueError(f"path dependency lacks package.name: {manifest_path}")
    if not isinstance(version, str):
        workspace_version = (
            tomllib.loads((PROJECT_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
            .get("workspace", {})
            .get("package", {})
            .get("version")
        )
        version = workspace_version
    if not isinstance(version, str) or not version:
        raise ValueError(f"cannot resolve package version: {manifest_path}")
    return name, version


def path_dependency_versions(manifest_path: Path) -> dict[str, str]:
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    expected: dict[str, str] = {}
    for table in dependency_tables(manifest):
        for dependency, specification in table.items():
            if not isinstance(specification, dict) or "path" not in specification:
                continue
            exact_path_requirement(manifest_path, dependency, specification)
            target_manifest = (
                manifest_path.parent / specification["path"] / "Cargo.toml"
            ).resolve()
            if not target_manifest.is_relative_to(PROJECT_ROOT):
                raise ValueError(
                    f"{manifest_path}: path dependency {dependency} escapes repository"
                )
            package_name, version = package_identity(target_manifest)
            renamed_package = dependency_package_name(dependency, specification)
            if renamed_package != package_name:
                raise ValueError(
                    f"{manifest_path}: dependency {dependency} resolves to {package_name}"
                )
            expected[dependency] = version
    return expected


def validate_manifest(manifest_path: Path, release_version: str) -> None:
    expected = path_dependency_versions(manifest_path)
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    actual: dict[str, str] = {}
    for table in dependency_tables(manifest):
        for dependency, specification in table.items():
            if isinstance(specification, dict) and "path" in specification:
                actual[dependency] = specification["version"]
    for dependency, target_version in expected.items():
        validate_resolved_pin(
            manifest_path, dependency, actual.get(dependency, ""), target_version
        )
        if target_version != "0.0.0" and target_version != release_version:
            raise ValueError(
                f"{manifest_path}: {dependency} resolves to {target_version}, "
                f"not release version {release_version}"
            )


def rewrite_manifest(
    manifest_path: Path, before: str, after: str
) -> str:
    original = manifest_path.read_text(encoding="utf-8")
    expected = path_dependency_versions(manifest_path)
    replacements: dict[str, str] = {
        dependency: version
        for dependency, version in expected.items()
        if version == after
    }
    seen: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        dependency = match.group("name")
        if dependency not in replacements:
            return match.group(0)
        versions = list(VERSION_FIELD.finditer(match.group("body")))
        if len(versions) != 1:
            raise ValueError(
                f"{manifest_path}: {dependency} must contain one inline version field"
            )
        version = versions[0]
        if version.group("value") != f"={before}":
            raise ValueError(
                f"{manifest_path}: {dependency} expected ={before}, "
                f"found {version.group('value')!r}"
            )
        body = match.group("body")
        body = (
            body[: version.start()]
            + f'version = "={after}"'
            + body[version.end() :]
        )
        seen.add(dependency)
        return match.group("prefix") + body + match.group("suffix")

    rewritten = DEPENDENCY_LINE.sub(replace, original)
    missing = set(replacements) - seen
    if missing:
        raise ValueError(
            f"{manifest_path}: dependency line(s) were not rewritten: {sorted(missing)}"
        )
    return rewritten


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


def manifests_from_policy() -> list[Path]:
    policy = tomllib.loads(POLICY_PATH.read_text(encoding="utf-8"))
    paths = classified_paths(policy)
    root_manifest = tomllib.loads(
        (PROJECT_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    )
    declared = root_manifest.get("workspace", {}).get("exclude", [])
    if not isinstance(declared, list):
        raise ValueError("root workspace.exclude must be an array")
    validate_root_excludes(paths, declared)
    manifests = [PROJECT_ROOT / path / "Cargo.toml" for path in paths]
    missing = [path for path in manifests if not path.is_file()]
    if missing:
        raise ValueError(f"classified workspace manifest is missing: {missing[0]}")
    return manifests


def self_test() -> None:
    sample = 'dcrypt-api = { version = "=2.0.0", path = "../crates/api" }\n'
    matches = list(DEPENDENCY_LINE.finditer(sample))
    if len(matches) != 1 or matches[0].group("name") != "dcrypt-api":
        raise AssertionError("inline dependency matcher failed")
    body = matches[0].group("body")
    version = VERSION_FIELD.search(body)
    if version is None or version.group("value") != "=2.0.0":
        raise AssertionError("exact version matcher failed")
    if EXACT_VERSION.fullmatch("2.0.0") or not EXACT_VERSION.fullmatch("=2.0.0"):
        raise AssertionError("exact-version policy failed")
    dependency_fixture = tomllib.loads(
        """
[dependencies]
normal = { version = "=2.0.0", path = "../normal" }
[dev-dependencies]
dev_alias = { package = "dev-real", version = "=2.0.0", path = "../dev" }
[build-dependencies]
build = { version = "=2.0.0", path = "../build" }
[target.'cfg(unix)'.dependencies]
target = { version = "=2.0.0", path = "../target" }
[target.'cfg(unix)'.dev-dependencies]
target_dev = { version = "=2.0.0", path = "../target-dev" }
[target.'cfg(unix)'.build-dependencies]
target_build = { version = "=2.0.0", path = "../target-build" }
"""
    )
    discovered = {
        name
        for table in dependency_tables(dependency_fixture)
        for name in table
    }
    if discovered != {
        "normal",
        "dev_alias",
        "build",
        "target",
        "target_dev",
        "target_build",
    }:
        raise AssertionError("not every dependency table was enumerated")
    alias = dependency_fixture["dev-dependencies"]["dev_alias"]
    if dependency_package_name("dev_alias", alias) != "dev-real":
        raise AssertionError("package alias was not honored")
    try:
        exact_path_requirement(Path("fixture/Cargo.toml"), "missing", {"path": "../x"})
    except ValueError:
        pass
    else:
        raise AssertionError("missing exact path pin was accepted")
    try:
        validate_resolved_pin(
            Path("fixture/Cargo.toml"), "stale", "=2.0.0", "3.0.0"
        )
    except ValueError:
        pass
    else:
        raise AssertionError("stale exact path pin was accepted")
    policy = {
        "verification-workspace": "verification",
        "fuzz-workspace": "fuzz",
        "owned-excluded-workspaces": [{"path": "migration/tool"}],
    }
    if classified_paths(policy) != [
        Path("verification"),
        Path("fuzz"),
        Path("migration/tool"),
    ]:
        raise AssertionError("classified workspace discovery failed")
    validate_root_excludes(
        [Path("verification"), Path("fuzz"), Path("migration/tool")],
        ["verification", "fuzz", "migration/tool"],
    )
    for invalid in (
        ["verification", "fuzz", "unknown"],
        ["verification", "fuzz"],
    ):
        try:
            validate_root_excludes(
                [Path("verification"), Path("fuzz"), Path("migration/tool")],
                invalid,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("inexact root workspace.exclude was accepted")
    policy["owned-excluded-workspaces"].append({"path": "fuzz"})
    try:
        classified_paths(policy)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate classified workspace was accepted")

    target_root = PROJECT_ROOT / "target"
    target_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="isolated-pin-updater-self-test-", dir=target_root
    ) as temporary_directory:
        fixture_root = Path(temporary_directory)
        packages = {
            "normal": "normal",
            "dev": "dev-real",
            "build": "build",
            "target": "target",
            "target-dev": "target-dev",
            "target-build": "target-build",
        }
        for directory, package_name in packages.items():
            package_root = fixture_root / directory
            package_root.mkdir()
            (package_root / "Cargo.toml").write_text(
                f'[package]\nname = "{package_name}"\nversion = "3.0.0"\n',
                encoding="utf-8",
            )

        manifest_path = fixture_root / "Cargo.toml"
        manifest_path.write_text(
            """[package]
name = "classified-fixture"
version = "0.0.0"
publish = false

[dependencies]
normal = { version = "=2.0.0", path = "normal" }
[dev-dependencies]
dev_alias = { package = "dev-real", version = "=2.0.0", path = "dev" }
[build-dependencies]
build = { version = "=2.0.0", path = "build" }
[target.'cfg(unix)'.dependencies]
target = { version = "=2.0.0", path = "target" }
[target.'cfg(unix)'.dev-dependencies]
target_dev = { package = "target-dev", version = "=2.0.0", path = "target-dev" }
[target.'cfg(unix)'.build-dependencies]
target_build = { package = "target-build", version = "=2.0.0", path = "target-build" }
""",
            encoding="utf-8",
        )
        manifest_path.chmod(0o640)
        rewritten = rewrite_manifest(manifest_path, "2.0.0", "3.0.0")
        if rewritten.count('version = "=3.0.0"') != len(packages):
            raise AssertionError("not every path-dependency table was rewritten")
        atomic_write(manifest_path, rewritten)
        if stat.S_IMODE(manifest_path.stat().st_mode) != 0o640:
            raise AssertionError("atomic rewrite did not preserve manifest mode")
        validate_manifest(manifest_path, "3.0.0")

        stale = rewritten.replace('version = "=3.0.0"', 'version = "=2.0.0"', 1)
        atomic_write(manifest_path, stale)
        try:
            validate_manifest(manifest_path, "3.0.0")
        except ValueError:
            pass
        else:
            raise AssertionError("stale path pin passed end-to-end validation")

        missing_exact = rewritten.replace(
            'version = "=3.0.0"', 'version = "3.0.0"', 1
        )
        atomic_write(manifest_path, missing_exact)
        try:
            validate_manifest(manifest_path, "3.0.0")
        except ValueError:
            pass
        else:
            raise AssertionError("non-exact path pin passed end-to-end validation")
    print("isolated-workspace version updater self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect")
    parser.add_argument("--from-version")
    parser.add_argument("--to-version")
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()

    if arguments.self_test:
        self_test()
        return 0
    if arguments.expect is not None:
        if arguments.from_version is not None or arguments.to_version is not None:
            parser.error("--expect cannot be combined with rewrite options")
        for manifest in manifests_from_policy():
            validate_manifest(manifest, arguments.expect)
        return 0
    if arguments.from_version is None or arguments.to_version is None:
        parser.error("use --expect or both --from-version and --to-version")

    for manifest in manifests_from_policy():
        rewritten = rewrite_manifest(
            manifest, arguments.from_version, arguments.to_version
        )
        if rewritten != manifest.read_text(encoding="utf-8"):
            atomic_write(manifest, rewritten)
    for manifest in manifests_from_policy():
        validate_manifest(manifest, arguments.to_version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
