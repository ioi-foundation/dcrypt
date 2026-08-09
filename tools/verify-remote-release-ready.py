#!/usr/bin/env python3
"""Fail-closed, read-only remote gate for a prepared dcrypt release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence
from urllib.parse import urlparse


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
OFFICIAL_REPOSITORY = "ioi-foundation/dcrypt"
RELEASE_BRANCH = "master"
GITHUB_API_VERSION = "2026-03-10"
GITHUB_ACTIONS_APP_ID = 15368
GITHUB_ACTIONS_APP_SLUG = "github-actions"
BOUNDARY_CHECK_CONTEXT = "Zero unsafe / zero FFI implementation boundary"
USER_AGENT = (
    "dcrypt-remote-release-gate/3.0 "
    "(+https://github.com/ioi-foundation/dcrypt)"
)

PUBLISH_ORDER = (
    "dcrypt-internal",
    "dcrypt-params",
    "dcrypt-api",
    "dcrypt-common",
    "dcrypt-algorithms",
    "dcrypt-symmetric",
    "dcrypt-kem",
    "dcrypt-sign",
    "dcrypt-pke",
    "dcrypt-utils",
    "dcrypt-hybrid",
    "dcrypt",
)

# These are the rendered job names in security-validation.yml. Keeping the
# reviewed list here makes a newly missing CI job fail closed instead of letting
# the single branch-ruleset context stand in for the complete release workflow.
EXPECTED_CHECK_CONTEXTS = (
    BOUNDARY_CHECK_CONTEXT,
    "Format and all-target workspace check",
    "Workspace crate tests",
    "Complete ACVP and AES-CBC property gates",
    "Excluded independent interoperability oracles",
    "Repository statistical timing regressions (not dudect or ctgrind)",
    "RustSec and workspace dependency policy",
    "Miri (dcrypt-api)",
    "Miri (dcrypt-common)",
    "Miri cryptographic parser and key boundaries",
    "Build and exercise externally controlled decoder fuzz targets",
)

SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?$")
OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BOUNDARY_REPORT = PROJECT_ROOT / "target" / "implementation-boundary" / "report.json"
BOUNDARY_POLICY = PROJECT_ROOT / "implementation-boundary.toml"
LOCK_FILE = PROJECT_ROOT / "Cargo.lock"


class GateError(RuntimeError):
    """A failed invariant or an unavailable source of release evidence."""


@dataclass(frozen=True)
class GitState:
    head: str
    origin_url: str
    local_tag_type: str
    local_tag_object: str
    local_tag_commit: str
    remote_tag_object: str | None
    remote_tag_commit: str | None
    remote_branch_commit: str | None


@dataclass(frozen=True)
class GitHubIdentity:
    login: str
    repository: str


@dataclass(frozen=True)
class RequiredCheck:
    context: str
    integration_id: int | None


@dataclass(frozen=True)
class BranchRules:
    checks: tuple[RequiredCheck, ...]
    strict: bool


@dataclass(frozen=True)
class CheckRun:
    identifier: int
    name: str
    head_sha: str
    status: str
    conclusion: str | None
    app_id: int | None
    app_slug: str | None


@dataclass(frozen=True)
class ReleaseState:
    identifier: int
    tag_name: str
    draft: bool


@dataclass(frozen=True)
class RegistryState:
    crate_name: str
    present: bool
    yanked: bool | None = None
    identifier: int | None = None
    checksum: str | None = None
    features: tuple[tuple[str, tuple[str, ...]], ...] | None = None
    expected_features: tuple[tuple[str, tuple[str, ...]], ...] | None = None
    dependencies: tuple[tuple[object, ...], ...] | None = None
    expected_dependencies: tuple[tuple[object, ...], ...] | None = None
    expected_checksum: str | None = None


class EvidenceProvider(Protocol):
    def git_state(self, tag: str) -> GitState: ...

    def github_identity(self) -> GitHubIdentity: ...

    def branch_rules(self, branch: str) -> BranchRules: ...

    def check_runs(self, commit: str) -> Sequence[CheckRun]: ...

    def release(self, tag: str) -> ReleaseState | None: ...

    def registry_states(self, version: str) -> Sequence[RegistryState]: ...


class CommandRunner:
    """Run read-only commands without exposing command output on failure."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "GH_PROMPT_DISABLED": "1",
                "GH_PAGER": "cat",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )

    def run(self, args: Sequence[str], label: str) -> str:
        try:
            completed = subprocess.run(
                list(args),
                cwd=self.root,
                env=self.environment,
                text=True,
                capture_output=True,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise GateError(f"{label} failed: {type(error).__name__}") from error
        if completed.returncode != 0:
            raise GateError(f"{label} failed with status {completed.returncode}")
        return completed.stdout

    def run_bytes(self, args: Sequence[str], label: str) -> bytes:
        try:
            completed = subprocess.run(
                list(args),
                cwd=self.root,
                env=self.environment,
                capture_output=True,
                check=False,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise GateError(f"{label} failed: {type(error).__name__}") from error
        if completed.returncode != 0:
            raise GateError(f"{label} failed with status {completed.returncode}")
        return completed.stdout


def _normalize_features(raw: object, label: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if not isinstance(raw, dict):
        raise GateError(f"{label} feature map is malformed")
    normalized: list[tuple[str, tuple[str, ...]]] = []
    for name, values in raw.items():
        if not isinstance(name, str) or not isinstance(values, list) or not all(
            isinstance(value, str) for value in values
        ):
            raise GateError(f"{label} feature map is malformed")
        if len(values) != len(set(values)):
            raise GateError(f"{label} feature map contains duplicate values")
        normalized.append((name, tuple(sorted(values))))
    return tuple(sorted(normalized))


def _registry_api_features(
    record: dict[str, Any], label: str
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if record.get("features2") is not None:
        raise GateError(f"{label} unexpectedly exposed index-only features2 data")
    return _normalize_features(record.get("features"), label)


def _normalize_dependencies(
    raw: object, label: str, *, registry: bool
) -> tuple[tuple[object, ...], ...]:
    if not isinstance(raw, list):
        raise GateError(f"{label} dependency list is malformed")
    normalized: list[tuple[object, ...]] = []
    for dependency in raw:
        if not isinstance(dependency, dict):
            raise GateError(f"{label} dependency list is malformed")
        name = dependency.get("crate_id" if registry else "name")
        requirement = dependency.get("req")
        kind = dependency.get("kind")
        if not registry and kind is None:
            kind = "normal"
        target = dependency.get("target")
        optional = dependency.get("optional")
        default_features = dependency.get(
            "default_features" if registry else "uses_default_features"
        )
        features = dependency.get("features")
        if (
            not isinstance(name, str)
            or not isinstance(requirement, str)
            or kind not in {"normal", "dev", "build"}
            or (target is not None and not isinstance(target, str))
            or not isinstance(optional, bool)
            or not isinstance(default_features, bool)
            or not isinstance(features, list)
            or not all(isinstance(feature, str) for feature in features)
        ):
            raise GateError(f"{label} dependency list is malformed")
        normalized.append(
            (
                name,
                requirement,
                kind,
                target,
                optional,
                default_features,
                tuple(sorted(features)),
            )
        )
    return tuple(sorted(normalized, key=repr))


def _sha256_file(path: Path, label: str) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise GateError(f"{label} is unavailable") from error
    return digest.hexdigest()


def _archive_hashes_from_report(
    report: object,
    version: str,
    *,
    current_head: str,
    lock_sha256: str,
    policy_sha256: str,
) -> dict[str, str]:
    if not isinstance(report, dict) or report.get("passed") is not True:
        raise GateError("implementation-boundary archive report did not pass")
    if report.get("head_sha") != current_head:
        raise GateError(
            "implementation-boundary archive report is not bound to exact HEAD"
        )
    if report.get("lock_sha256") != lock_sha256:
        raise GateError(
            "implementation-boundary archive report has a stale lockfile digest"
        )
    if report.get("policy_sha256") != policy_sha256:
        raise GateError(
            "implementation-boundary archive report has a stale policy digest"
        )
    if report.get("published_packages") != list(PUBLISH_ORDER):
        raise GateError(
            "implementation-boundary report package order differs from the release"
        )
    raw_hashes = report.get("archive_sha256")
    if not isinstance(raw_hashes, dict):
        raise GateError("implementation-boundary report omitted archive checksums")
    expected_labels = {f"{name}@{version}" for name in PUBLISH_ORDER}
    actual_labels = set(raw_hashes)
    if actual_labels != expected_labels:
        raise GateError(
            "implementation-boundary archive checksum set differs from the release: "
            f"missing={sorted(expected_labels - actual_labels)}, "
            f"extra={sorted(actual_labels - expected_labels)}"
        )
    archive_hashes: dict[str, str] = {}
    for label, checksum in raw_hashes.items():
        if not isinstance(label, str) or not isinstance(checksum, str):
            raise GateError("implementation-boundary archive checksum map is malformed")
        if not SHA256.fullmatch(checksum):
            raise GateError(f"local archive checksum is malformed: {label}")
        archive_hashes[label] = checksum
    return archive_hashes


class LiveEvidenceProvider:
    """Collect authenticated, read-only evidence from Git, GitHub, and crates.io."""

    def __init__(self, root: Path, *, require_local_archives: bool = False) -> None:
        self.root = root
        self.runner = CommandRunner(root)
        self.require_local_archives = require_local_archives

    def _git(self, args: Sequence[str], label: str) -> str:
        return self.runner.run(("git", *args), label).strip()

    def _gh_json(self, endpoint: str, label: str) -> Any:
        output = self.runner.run(
            (
                "gh",
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
                endpoint,
            ),
            label,
        )
        try:
            return json.loads(output)
        except json.JSONDecodeError as error:
            raise GateError(f"{label} returned malformed JSON") from error

    def _crates_json_or_absent(self, endpoint: str, label: str) -> Any | None:
        output = self.runner.run(
            (
                "curl",
                "--silent",
                "--show-error",
                "--location",
                "--connect-timeout",
                "15",
                "--max-time",
                "60",
                "--user-agent",
                USER_AGENT,
                "--write-out",
                "\n%{http_code}",
                f"https://crates.io/api/v1/{endpoint.lstrip('/')}",
            ),
            label,
        )
        try:
            body, status_text = output.rsplit("\n", 1)
            status = int(status_text)
        except (ValueError, TypeError) as error:
            raise GateError(f"{label} returned malformed HTTP status data") from error
        if status == 404:
            return None
        if status != 200:
            raise GateError(f"{label} returned HTTP {status}")
        try:
            return json.loads(body)
        except json.JSONDecodeError as error:
            raise GateError(f"{label} returned malformed JSON") from error

    def _downloaded_archive_checksum(self, crate_name: str, version: str) -> str:
        archive = self.runner.run_bytes(
            (
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--connect-timeout",
                "15",
                "--max-time",
                "120",
                "--user-agent",
                USER_AGENT,
                f"https://crates.io/api/v1/crates/{crate_name}/{version}/download",
            ),
            f"crates.io archive download for {crate_name}@{version}",
        )
        return hashlib.sha256(archive).hexdigest()

    @staticmethod
    def _parse_ls_remote(output: str, label: str) -> dict[str, str]:
        references: dict[str, str] = {}
        for line in output.splitlines():
            fields = line.split("\t")
            if len(fields) != 2 or not OBJECT_ID.fullmatch(fields[0]):
                raise GateError(f"{label} returned malformed Git reference data")
            if fields[1] in references:
                raise GateError(f"{label} returned a duplicate Git reference")
            references[fields[1]] = fields[0]
        return references

    def git_state(self, tag: str) -> GitState:
        head = self._git(("rev-parse", "--verify", "HEAD"), "local HEAD query")
        local_object = self._git(
            ("rev-parse", "--verify", f"refs/tags/{tag}"),
            f"local {tag} object query",
        )
        local_type = self._git(
            ("cat-file", "-t", local_object), f"local {tag} type query"
        )
        local_commit = self._git(
            ("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"),
            f"local {tag} peeled-commit query",
        )
        origin_url = self._git(("remote", "get-url", "origin"), "origin URL query")

        remote_tags = self._parse_ls_remote(
            self.runner.run(
                (
                    "git",
                    "ls-remote",
                    "--tags",
                    "origin",
                    f"refs/tags/{tag}",
                    f"refs/tags/{tag}^{{}}",
                ),
                f"origin {tag} query",
            ),
            f"origin {tag} query",
        )
        remote_branches = self._parse_ls_remote(
            self.runner.run(
                (
                    "git",
                    "ls-remote",
                    "--heads",
                    "origin",
                    f"refs/heads/{RELEASE_BRANCH}",
                ),
                f"origin/{RELEASE_BRANCH} query",
            ),
            f"origin/{RELEASE_BRANCH} query",
        )
        return GitState(
            head=head,
            origin_url=origin_url,
            local_tag_type=local_type,
            local_tag_object=local_object,
            local_tag_commit=local_commit,
            remote_tag_object=remote_tags.get(f"refs/tags/{tag}"),
            remote_tag_commit=remote_tags.get(f"refs/tags/{tag}^{{}}"),
            remote_branch_commit=remote_branches.get(
                f"refs/heads/{RELEASE_BRANCH}"
            ),
        )

    def github_identity(self) -> GitHubIdentity:
        self.runner.run(
            ("gh", "auth", "status", "--hostname", "github.com"),
            "GitHub authentication check",
        )
        user = self._gh_json("/user", "authenticated GitHub user query")
        repository = self._gh_json(
            f"/repos/{OFFICIAL_REPOSITORY}", "authenticated GitHub repository query"
        )
        if not isinstance(user, dict) or not isinstance(repository, dict):
            raise GateError("GitHub identity queries returned unexpected JSON")
        login = user.get("login")
        full_name = repository.get("full_name")
        if not isinstance(login, str) or not isinstance(full_name, str):
            raise GateError("GitHub identity queries omitted required fields")
        return GitHubIdentity(login=login, repository=full_name)

    def branch_rules(self, branch: str) -> BranchRules:
        document = self._gh_json(
            f"/repos/{OFFICIAL_REPOSITORY}/rules/branches/{branch}",
            f"GitHub rules for {branch}",
        )
        if not isinstance(document, list):
            raise GateError("GitHub branch-rules query returned unexpected JSON")

        checks: list[RequiredCheck] = []
        strict_values: list[bool] = []
        for rule in document:
            if (
                not isinstance(rule, dict)
                or rule.get("type") != "required_status_checks"
            ):
                continue
            parameters = rule.get("parameters")
            if not isinstance(parameters, dict):
                raise GateError("required-status-check rule omitted parameters")
            strict = parameters.get("strict_required_status_checks_policy")
            if not isinstance(strict, bool):
                raise GateError(
                    "required-status-check rule omitted strict policy state"
                )
            strict_values.append(strict)
            records = parameters.get("required_status_checks")
            if not isinstance(records, list):
                raise GateError("required-status-check rule omitted its check list")
            for record in records:
                if not isinstance(record, dict):
                    raise GateError(
                        "required-status-check rule contained malformed data"
                    )
                context = record.get("context")
                integration_id = record.get("integration_id")
                if not isinstance(context, str) or not context:
                    raise GateError("required-status-check rule omitted a context")
                if integration_id is not None and not isinstance(integration_id, int):
                    raise GateError(
                        "required-status-check rule has an invalid app identity"
                    )
                checks.append(RequiredCheck(context, integration_id))
        return BranchRules(tuple(checks), bool(strict_values) and all(strict_values))

    def check_runs(self, commit: str) -> Sequence[CheckRun]:
        per_page = 100
        page = 1
        expected_total: int | None = None
        records: list[dict[str, Any]] = []
        while True:
            document = self._gh_json(
                f"/repos/{OFFICIAL_REPOSITORY}/commits/{commit}/check-runs"
                f"?per_page={per_page}&page={page}",
                f"GitHub check-runs query page {page}",
            )
            if not isinstance(document, dict):
                raise GateError("GitHub check-runs query returned unexpected JSON")
            total = document.get("total_count")
            page_records = document.get("check_runs")
            if (
                not isinstance(total, int)
                or total < 0
                or not isinstance(page_records, list)
            ):
                raise GateError("GitHub check-runs query omitted pagination data")
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise GateError(
                    "GitHub check-runs changed while evidence was collected"
                )
            for record in page_records:
                if not isinstance(record, dict):
                    raise GateError("GitHub check-runs query contained malformed data")
                records.append(record)
            if len(records) >= total:
                break
            if not page_records or len(page_records) > per_page:
                raise GateError("GitHub check-runs pagination was incomplete")
            page += 1

        if expected_total is None or len(records) != expected_total:
            raise GateError("GitHub check-runs pagination count did not match")
        parsed: list[CheckRun] = []
        seen_identifiers: set[int] = set()
        for record in records:
            app = record.get("app")
            identifier = record.get("id")
            name = record.get("name")
            head_sha = record.get("head_sha")
            status = record.get("status")
            conclusion = record.get("conclusion")
            if (
                not isinstance(identifier, int)
                or not isinstance(name, str)
                or not isinstance(head_sha, str)
                or not isinstance(status, str)
                or (conclusion is not None and not isinstance(conclusion, str))
                or not isinstance(app, dict)
            ):
                raise GateError("GitHub check-runs query omitted required fields")
            if identifier in seen_identifiers:
                raise GateError(
                    "GitHub check-runs query returned a duplicate identifier"
                )
            seen_identifiers.add(identifier)
            app_id = app.get("id")
            app_slug = app.get("slug")
            if app_id is not None and not isinstance(app_id, int):
                raise GateError("GitHub check-run has an invalid app identifier")
            if app_slug is not None and not isinstance(app_slug, str):
                raise GateError("GitHub check-run has an invalid app slug")
            parsed.append(
                CheckRun(
                    identifier=identifier,
                    name=name,
                    head_sha=head_sha,
                    status=status,
                    conclusion=conclusion,
                    app_id=app_id,
                    app_slug=app_slug,
                )
            )
        return parsed

    def release(self, tag: str) -> ReleaseState | None:
        document = self._gh_json(
            f"/repos/{OFFICIAL_REPOSITORY}/releases/tags/{tag}",
            f"authenticated GitHub release query for {tag}",
        )
        if not isinstance(document, dict):
            raise GateError("GitHub release query returned unexpected JSON")
        identifier = document.get("id")
        tag_name = document.get("tag_name")
        draft = document.get("draft")
        if (
            not isinstance(identifier, int)
            or not isinstance(tag_name, str)
            or not isinstance(draft, bool)
        ):
            raise GateError("GitHub release query omitted required fields")
        return ReleaseState(identifier=identifier, tag_name=tag_name, draft=draft)

    def _local_registry_expectations(
        self, version: str
    ) -> dict[
        str,
        tuple[
            tuple[tuple[str, tuple[str, ...]], ...],
            tuple[tuple[object, ...], ...],
            str | None,
        ],
    ]:
        output = self.runner.run(
            (
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--no-deps",
            ),
            "locked local Cargo metadata query",
        )
        try:
            document = json.loads(output)
        except json.JSONDecodeError as error:
            raise GateError("local Cargo metadata returned malformed JSON") from error
        if not isinstance(document, dict) or not isinstance(
            document.get("packages"), list
        ):
            raise GateError("local Cargo metadata omitted package data")

        packages: dict[str, dict[str, Any]] = {}
        for package in document["packages"]:
            if not isinstance(package, dict):
                raise GateError("local Cargo metadata contained malformed package data")
            name = package.get("name")
            if name not in PUBLISH_ORDER:
                continue
            if not isinstance(name, str) or name in packages:
                raise GateError("local Cargo metadata contains duplicate release packages")
            if package.get("version") != version:
                raise GateError(f"local {name} package is not version {version}")
            packages[name] = package
        missing = sorted(set(PUBLISH_ORDER) - packages.keys())
        extra = sorted(packages.keys() - set(PUBLISH_ORDER))
        if missing or extra:
            raise GateError(
                "local Cargo release package set differs from the publish order: "
                f"missing={missing}, extra={extra}"
            )

        archive_hashes: dict[str, str] = {}
        if self.require_local_archives:
            try:
                report = json.loads(BOUNDARY_REPORT.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise GateError(
                    "implementation-boundary archive report is unavailable or malformed"
                ) from error
            current_head = self._git(
                ("rev-parse", "--verify", "HEAD"),
                "local HEAD query for archive report",
            )
            archive_hashes = _archive_hashes_from_report(
                report,
                version,
                current_head=current_head,
                lock_sha256=_sha256_file(LOCK_FILE, "tracked Cargo.lock"),
                policy_sha256=_sha256_file(
                    BOUNDARY_POLICY, "implementation-boundary policy"
                ),
            )

        expectations = {}
        for name in PUBLISH_ORDER:
            package = packages[name]
            expectations[name] = (
                _normalize_features(package.get("features"), f"local {name}@{version}"),
                _normalize_dependencies(
                    package.get("dependencies"),
                    f"local {name}@{version}",
                    registry=False,
                ),
                archive_hashes.get(f"{name}@{version}"),
            )
        return expectations

    def _registry_dependencies(
        self, crate_name: str, version: str, version_id: int
    ) -> tuple[tuple[object, ...], ...]:
        output = self.runner.run(
            (
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--connect-timeout",
                "15",
                "--max-time",
                "60",
                "--user-agent",
                USER_AGENT,
                f"https://crates.io/api/v1/crates/{crate_name}/{version}/dependencies",
            ),
            f"crates.io dependency query for {crate_name}@{version}",
        )
        try:
            document = json.loads(output)
        except json.JSONDecodeError as error:
            raise GateError(
                f"crates.io dependency query for {crate_name}@{version} returned malformed JSON"
            ) from error
        if not isinstance(document, dict) or not isinstance(
            document.get("dependencies"), list
        ):
            raise GateError(
                f"crates.io dependency query for {crate_name}@{version} omitted data"
            )
        for dependency in document["dependencies"]:
            if (
                not isinstance(dependency, dict)
                or isinstance(dependency.get("id"), bool)
                or not isinstance(dependency.get("id"), int)
                or dependency["id"] <= 0
                or dependency.get("version_id") != version_id
            ):
                raise GateError(
                    f"crates.io dependency query for {crate_name}@{version} "
                    "contained invalid identity data"
                )
        return _normalize_dependencies(
            document["dependencies"],
            f"crates.io {crate_name}@{version}",
            registry=True,
        )

    def registry_states(self, version: str) -> Sequence[RegistryState]:
        expectations = self._local_registry_expectations(version)
        states: list[RegistryState] = []
        for crate_name in PUBLISH_ORDER:
            expected_features, expected_dependencies, expected_checksum = expectations[
                crate_name
            ]
            document = self._crates_json_or_absent(
                f"crates/{crate_name}/{version}",
                f"crates.io exact-version query for {crate_name}@{version}",
            )
            if document is None:
                states.append(
                    RegistryState(
                        crate_name,
                        False,
                        expected_features=expected_features,
                        expected_dependencies=expected_dependencies,
                        expected_checksum=expected_checksum,
                    )
                )
                continue
            if not isinstance(document, dict) or not isinstance(
                document.get("version"), dict
            ):
                raise GateError(
                    f"crates.io exact-version query for {crate_name}@{version} "
                    "omitted version data"
                )
            record = document["version"]
            if record.get("num") != version:
                raise GateError(
                    f"crates.io returned another version for {crate_name}@{version}"
                )
            if record.get("crate") != crate_name:
                raise GateError(
                    f"crates.io returned another crate for {crate_name}@{version}"
                )
            identifier = record.get("id")
            checksum = record.get("checksum")
            yanked = record.get("yanked")
            if (
                isinstance(identifier, bool)
                or not isinstance(identifier, int)
                or identifier <= 0
            ):
                raise GateError(
                    f"crates.io omitted a valid version ID for {crate_name}@{version}"
                )
            if not isinstance(checksum, str) or not SHA256.fullmatch(checksum):
                raise GateError(
                    f"crates.io omitted a valid checksum for {crate_name}@{version}"
                )
            if not isinstance(yanked, bool):
                raise GateError(
                    f"crates.io omitted yank state for {crate_name}@{version}"
                )
            downloaded_checksum = self._downloaded_archive_checksum(
                crate_name, version
            )
            if downloaded_checksum != checksum:
                raise GateError(
                    f"downloaded archive checksum differs from crates.io API: "
                    f"{crate_name}@{version}"
                )
            states.append(
                RegistryState(
                    crate_name,
                    True,
                    yanked,
                    identifier,
                    checksum,
                    _registry_api_features(record, f"crates.io {crate_name}@{version}"),
                    expected_features,
                    self._registry_dependencies(crate_name, version, identifier),
                    expected_dependencies,
                    expected_checksum,
                )
            )
        return states


def _origin_repository(origin_url: str) -> str | None:
    scp_match = re.fullmatch(r"(?:[^@]+@)?github\.com:(.+?)(?:\.git)?", origin_url)
    if scp_match:
        return scp_match.group(1).removesuffix(".git")
    parsed = urlparse(origin_url)
    if parsed.hostname != "github.com":
        return None
    return parsed.path.strip("/").removesuffix(".git")


def _require_object_id(value: str, label: str) -> None:
    if not OBJECT_ID.fullmatch(value):
        raise GateError(f"{label} is not a complete Git object ID")


def validate_git_state(state: GitState) -> None:
    for value, label in (
        (state.head, "HEAD"),
        (state.local_tag_object, "local tag object"),
        (state.local_tag_commit, "local tag commit"),
    ):
        _require_object_id(value, label)
    if _origin_repository(state.origin_url) != OFFICIAL_REPOSITORY:
        raise GateError(f"origin is not the official {OFFICIAL_REPOSITORY} repository")
    if state.local_tag_type != "tag":
        raise GateError(
            "local release tag is lightweight; an annotated tag is required"
        )
    if state.local_tag_commit != state.head:
        raise GateError("local release tag does not peel to exact HEAD")
    if state.remote_tag_object is None or state.remote_tag_commit is None:
        raise GateError(
            "origin is missing the annotated tag object or its peeled commit"
        )
    _require_object_id(state.remote_tag_object, "remote tag object")
    _require_object_id(state.remote_tag_commit, "remote tag commit")
    if state.remote_tag_object != state.local_tag_object:
        raise GateError("origin tag object differs from the reviewed local tag object")
    if state.remote_tag_commit != state.local_tag_commit:
        raise GateError("origin tag peels to a different commit")
    if state.remote_branch_commit is None:
        raise GateError(f"origin/{RELEASE_BRANCH} is missing")
    _require_object_id(state.remote_branch_commit, f"origin/{RELEASE_BRANCH}")
    if state.remote_branch_commit != state.head:
        raise GateError(f"origin/{RELEASE_BRANCH} is not exact HEAD")


def validate_identity(identity: GitHubIdentity) -> None:
    if not identity.login:
        raise GateError("authenticated GitHub identity is unavailable")
    if identity.repository != OFFICIAL_REPOSITORY:
        raise GateError(
            "authenticated GitHub repository visibility is not authoritative"
        )


def validate_branch_rules(rules: BranchRules) -> None:
    if not rules.strict:
        raise GateError("required status checks are absent or not strict on master")
    if not rules.checks:
        raise GateError("master has no required status-check rules")
    unique = {(check.context, check.integration_id) for check in rules.checks}
    if len(unique) != len(rules.checks):
        raise GateError("master rules contain duplicate required status checks")
    if RequiredCheck(BOUNDARY_CHECK_CONTEXT, GITHUB_ACTIONS_APP_ID) not in rules.checks:
        raise GateError(
            "the zero-unsafe/zero-FFI context is not bound to trusted GitHub Actions"
        )
    untrusted = [
        check.context
        for check in rules.checks
        if check.integration_id != GITHUB_ACTIONS_APP_ID
    ]
    if untrusted:
        raise GateError(
            "required status checks are not all bound to trusted GitHub Actions: "
            + ", ".join(sorted(untrusted))
        )


def validate_check_runs(
    runs: Sequence[CheckRun], rules: BranchRules, commit: str
) -> None:
    if not runs:
        raise GateError("GitHub reported no check runs for exact HEAD")
    identifiers: set[int] = set()
    trusted_names: set[str] = set()
    incomplete_or_failed: list[str] = []
    for run in runs:
        if run.identifier in identifiers:
            raise GateError("GitHub check-run evidence contains duplicate identifiers")
        identifiers.add(run.identifier)
        if run.head_sha != commit:
            raise GateError("GitHub returned a check run for a different commit")
        if (
            run.app_id == GITHUB_ACTIONS_APP_ID
            and run.app_slug == GITHUB_ACTIONS_APP_SLUG
        ):
            trusted_names.add(run.name)
            if run.status != "completed" or run.conclusion != "success":
                incomplete_or_failed.append(
                    f"{run.name}#{run.identifier} "
                    f"({run.status}/{run.conclusion or 'none'})"
                )

    required_names = {check.context for check in rules.checks}
    expected_names = set(EXPECTED_CHECK_CONTEXTS) | required_names
    missing = sorted(expected_names - trusted_names)
    if missing:
        raise GateError(
            "trusted GitHub Actions check runs are missing: " + ", ".join(missing)
        )

    if incomplete_or_failed:
        raise GateError(
            "trusted GitHub Actions checks are not complete/success: "
            + ", ".join(sorted(incomplete_or_failed))
        )


def validate_release(release: ReleaseState | None, tag: str) -> None:
    if release is None:
        raise GateError(f"authenticated GitHub API cannot see a release for {tag}")
    if release.tag_name != tag:
        raise GateError("GitHub release is attached to a different tag")
    if not release.draft:
        raise GateError(
            "GitHub release is public; a private draft is required before upload"
        )


def validate_registry_state(
    states: Sequence[RegistryState],
    version: str,
    resume: str | None,
    *,
    allow_complete: bool = False,
    expected_prefix: int | None = None,
) -> int:
    names = tuple(state.crate_name for state in states)
    if names != PUBLISH_ORDER:
        raise GateError("crates.io evidence does not match the exact publish order")
    for state in states:
        label = f"{state.crate_name}@{version}"
        if state.expected_features is None or state.expected_dependencies is None:
            raise GateError(f"local registry expectations are incomplete: {label}")
        for dependency in state.expected_dependencies:
            dependency_name = dependency[0]
            dependency_requirement = dependency[1]
            if (
                dependency_name in PUBLISH_ORDER
                and dependency_requirement != f"={version}"
            ):
                raise GateError(
                    f"local {label} dependency {dependency_name} uses "
                    f"{dependency_requirement!r}, expected ={version}"
                )

        if state.present:
            if state.yanked is not False:
                raise GateError(f"existing {label} is yanked or has unknown state")
            if (
                isinstance(state.identifier, bool)
                or not isinstance(state.identifier, int)
                or state.identifier <= 0
            ):
                raise GateError(f"registry identity is missing or invalid: {label}")
            if not isinstance(state.checksum, str) or not SHA256.fullmatch(
                state.checksum
            ):
                raise GateError(f"registry checksum is missing or malformed: {label}")
            if state.features != state.expected_features:
                raise GateError(f"registry feature map differs from local package: {label}")
            if state.dependencies != state.expected_dependencies:
                raise GateError(
                    f"registry dependency metadata differs from local package: {label}"
                )
            if (
                state.expected_checksum is not None
                and state.checksum != state.expected_checksum
            ):
                raise GateError(
                    f"registry checksum differs from reviewed local archive: {label}"
                )
        elif any(
            value is not None
            for value in (
                state.yanked,
                state.identifier,
                state.checksum,
                state.features,
                state.dependencies,
            )
        ):
            raise GateError(f"absent {label} unexpectedly has registry metadata")

    present = [state.present for state in states]
    prefix_length = 0
    while prefix_length < len(present) and present[prefix_length]:
        prefix_length += 1
    if any(present[prefix_length:]):
        raise GateError(
            "target-version crates.io records are not a valid leaf-first prefix"
        )
    if expected_prefix is not None and prefix_length != expected_prefix:
        raise GateError(
            f"registry prefix length is {prefix_length}, expected {expected_prefix}"
        )
    if allow_complete and prefix_length != len(PUBLISH_ORDER):
        raise GateError(
            f"complete registry state required, found {prefix_length}/{len(PUBLISH_ORDER)}"
        )
    if prefix_length == len(PUBLISH_ORDER) and not allow_complete:
        raise GateError(f"all dcrypt crates already exist at {version}")
    if prefix_length == len(PUBLISH_ORDER):
        if resume not in (None, "auto"):
            raise GateError("a completed release cannot use a named resume target")
        return prefix_length
    if prefix_length and resume is None:
        raise GateError(
            "target-version crates already exist; an explicit --resume is required"
        )
    if resume is not None and resume != "auto":
        expected = PUBLISH_ORDER[prefix_length]
        if resume != expected:
            raise GateError(
                f"resume target is {resume}, but the first absent crate is {expected}"
            )
    return prefix_length


def verify_release_gate(
    provider: EvidenceProvider,
    version: str,
    resume: str | None = None,
    *,
    allow_complete: bool = False,
    expected_prefix: int | None = None,
    report: Callable[[str], None] | None = print,
) -> int:
    tag = f"v{version}"
    git_state = provider.git_state(tag)
    validate_git_state(git_state)
    if report:
        report(
            f"  ✓ local and origin {tag} annotated objects and peeled commit "
            "match HEAD"
        )
        report(f"  ✓ origin/{RELEASE_BRANCH} equals exact HEAD {git_state.head}")

    identity = provider.github_identity()
    validate_identity(identity)
    if report:
        report(f"  ✓ authenticated GitHub visibility as {identity.login}")

    rules = provider.branch_rules(RELEASE_BRANCH)
    validate_branch_rules(rules)
    runs = provider.check_runs(git_state.head)
    validate_check_runs(runs, rules, git_state.head)
    if report:
        expected_count = len(EXPECTED_CHECK_CONTEXTS)
        report(f"  ✓ {expected_count} expected trusted checks are complete/success")

    release = provider.release(tag)
    validate_release(release, tag)
    if report:
        assert release is not None
        report(
            f"  ✓ authenticated GitHub API sees draft release "
            f"{release.identifier} for {tag}"
        )

    states = provider.registry_states(version)
    prefix_length = validate_registry_state(
        states,
        version,
        resume,
        allow_complete=allow_complete,
        expected_prefix=expected_prefix,
    )
    if report:
        if prefix_length == len(PUBLISH_ORDER):
            report(
                f"  ✓ crates.io has the complete verified release "
                f"({prefix_length}/{len(PUBLISH_ORDER)})"
            )
        elif prefix_length:
            report(
                f"  ✓ crates.io has a valid explicit-resume prefix "
                f"({prefix_length}/{len(PUBLISH_ORDER)})"
            )
        else:
            report(f"  ✓ all {len(PUBLISH_ORDER)} {version} crate records are absent")
    return prefix_length


@dataclass
class MockProvider:
    git: GitState
    identity: GitHubIdentity
    rules: BranchRules
    runs: list[CheckRun]
    github_release: ReleaseState | None
    registry: list[RegistryState]
    fail_on: set[str] = field(default_factory=set)

    def _fail(self, operation: str) -> None:
        if operation in self.fail_on:
            raise GateError(f"mock {operation} network failure")

    def git_state(self, tag: str) -> GitState:
        self._fail("git")
        return self.git

    def github_identity(self) -> GitHubIdentity:
        self._fail("identity")
        return self.identity

    def branch_rules(self, branch: str) -> BranchRules:
        self._fail("rules")
        return self.rules

    def check_runs(self, commit: str) -> Sequence[CheckRun]:
        self._fail("checks")
        return self.runs

    def release(self, tag: str) -> ReleaseState | None:
        self._fail("release")
        return self.github_release

    def registry_states(self, version: str) -> Sequence[RegistryState]:
        self._fail("registry")
        return self.registry


def _mock_absent_registry(crate_name: str) -> RegistryState:
    return RegistryState(
        crate_name,
        False,
        expected_features=(),
        expected_dependencies=(),
    )


def _mock_present_registry(
    crate_name: str,
    *,
    yanked: bool = False,
    identifier: int = 1,
    checksum: str = "c" * 64,
    features: tuple[tuple[str, tuple[str, ...]], ...] = (),
    expected_features: tuple[tuple[str, tuple[str, ...]], ...] = (),
    dependencies: tuple[tuple[object, ...], ...] = (),
    expected_dependencies: tuple[tuple[object, ...], ...] = (),
    expected_checksum: str | None = None,
) -> RegistryState:
    return RegistryState(
        crate_name,
        True,
        yanked,
        identifier,
        checksum,
        features,
        expected_features,
        dependencies,
        expected_dependencies,
        expected_checksum,
    )


def _mock_boundary_report() -> dict[str, object]:
    return {
        "passed": True,
        "head_sha": "a" * 40,
        "lock_sha256": "b" * 64,
        "policy_sha256": "c" * 64,
        "published_packages": list(PUBLISH_ORDER),
        "archive_sha256": {
            f"{name}@3.0.0": "d" * 64 for name in PUBLISH_ORDER
        },
    }


def _mock_provider() -> MockProvider:
    head = "a" * 40
    tag_object = "b" * 40
    runs = [
        CheckRun(
            identifier=index,
            name=name,
            head_sha=head,
            status="completed",
            conclusion="success",
            app_id=GITHUB_ACTIONS_APP_ID,
            app_slug=GITHUB_ACTIONS_APP_SLUG,
        )
        for index, name in enumerate(EXPECTED_CHECK_CONTEXTS, start=1)
    ]
    return MockProvider(
        git=GitState(
            head=head,
            origin_url="git@github.com:ioi-foundation/dcrypt.git",
            local_tag_type="tag",
            local_tag_object=tag_object,
            local_tag_commit=head,
            remote_tag_object=tag_object,
            remote_tag_commit=head,
            remote_branch_commit=head,
        ),
        identity=GitHubIdentity("maintainer", OFFICIAL_REPOSITORY),
        rules=BranchRules(
            (RequiredCheck(BOUNDARY_CHECK_CONTEXT, GITHUB_ACTIONS_APP_ID),), True
        ),
        runs=runs,
        github_release=ReleaseState(42, "v3.0.0", True),
        registry=[_mock_absent_registry(name) for name in PUBLISH_ORDER],
    )


class GateSelfTests(unittest.TestCase):
    def assert_gate_fails(
        self, provider: MockProvider, pattern: str, resume: str | None = None
    ) -> None:
        with self.assertRaisesRegex(GateError, pattern):
            verify_release_gate(provider, "3.0.0", resume, report=None)

    def test_clean_absent_state_passes(self) -> None:
        verify_release_gate(_mock_provider(), "3.0.0", report=None)

    def test_api_feature_map_preserves_modern_feature_syntax(self) -> None:
        record = {
            "features": {
                "default": ["std"],
                "serde": ["dep:serde"],
                "weak": ["serde?/derive"],
            }
        }
        self.assertEqual(
            _registry_api_features(record, "fixture"),
            (
                ("default", ("std",)),
                ("serde", ("dep:serde",)),
                ("weak", ("serde?/derive",)),
            ),
        )

    def test_api_feature_map_rejects_index_features2(self) -> None:
        with self.assertRaisesRegex(GateError, "index-only features2"):
            _registry_api_features(
                {"features": {}, "features2": {"serde": ["dep:serde"]}},
                "fixture",
            )

    def test_api_feature_map_rejects_missing_or_duplicate_values(self) -> None:
        with self.assertRaisesRegex(GateError, "malformed"):
            _registry_api_features({}, "fixture")
        with self.assertRaisesRegex(GateError, "duplicate values"):
            _registry_api_features(
                {"features": {"default": ["std", "std"]}}, "fixture"
            )

    def test_dependency_normalization_maps_only_local_null_kind(self) -> None:
        local = {
            "name": "dcrypt-internal",
            "req": "=3.0.0",
            "kind": None,
            "target": None,
            "optional": False,
            "uses_default_features": False,
            "features": ["alloc"],
            "rename": "renamed-internal",
        }
        registry = {
            "crate_id": "dcrypt-internal",
            "req": "=3.0.0",
            "kind": "normal",
            "target": None,
            "optional": False,
            "default_features": False,
            "features": ["alloc"],
        }
        self.assertEqual(
            _normalize_dependencies([local], "local", registry=False),
            _normalize_dependencies([registry], "registry", registry=True),
        )
        registry["kind"] = None
        with self.assertRaisesRegex(GateError, "malformed"):
            _normalize_dependencies([registry], "registry", registry=True)

    def test_dependency_normalization_preserves_duplicate_package_rows(self) -> None:
        base = {
            "name": "hex",
            "req": "=0.4.3",
            "kind": None,
            "target": None,
            "optional": False,
            "uses_default_features": True,
            "features": [],
        }
        dev = dict(base, kind="dev", rename="hex-dev")
        rows = _normalize_dependencies([base, dev], "local", registry=False)
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0], rows[1])

    def test_archive_report_is_bound_to_head_lock_policy_and_exact_set(self) -> None:
        report = _mock_boundary_report()
        hashes = _archive_hashes_from_report(
            report,
            "3.0.0",
            current_head="a" * 40,
            lock_sha256="b" * 64,
            policy_sha256="c" * 64,
        )
        self.assertEqual(len(hashes), len(PUBLISH_ORDER))
        for field, pattern in (
            ("head_sha", "exact HEAD"),
            ("lock_sha256", "stale lockfile"),
            ("policy_sha256", "stale policy"),
        ):
            stale = dict(report)
            stale[field] = "e" * len(str(report[field]))
            with self.assertRaisesRegex(GateError, pattern):
                _archive_hashes_from_report(
                    stale,
                    "3.0.0",
                    current_head="a" * 40,
                    lock_sha256="b" * 64,
                    policy_sha256="c" * 64,
                )
        incomplete = dict(report)
        incomplete["archive_sha256"] = dict(report["archive_sha256"])
        del incomplete["archive_sha256"][f"{PUBLISH_ORDER[-1]}@3.0.0"]
        with self.assertRaisesRegex(GateError, "checksum set differs"):
            _archive_hashes_from_report(
                incomplete,
                "3.0.0",
                current_head="a" * 40,
                lock_sha256="b" * 64,
                policy_sha256="c" * 64,
            )

    def test_valid_partial_prefix_requires_and_accepts_explicit_resume(self) -> None:
        provider = _mock_provider()
        provider.registry[:3] = [
            _mock_present_registry(name) for name in PUBLISH_ORDER[:3]
        ]
        self.assert_gate_fails(provider, "explicit --resume")
        verify_release_gate(provider, "3.0.0", "auto", report=None)
        verify_release_gate(provider, "3.0.0", PUBLISH_ORDER[3], report=None)

    def test_lightweight_local_tag_fails(self) -> None:
        provider = _mock_provider()
        provider.git = replace(provider.git, local_tag_type="commit")
        self.assert_gate_fails(provider, "lightweight")

    def test_lightweight_remote_tag_fails(self) -> None:
        provider = _mock_provider()
        provider.git = replace(provider.git, remote_tag_commit=None)
        self.assert_gate_fails(provider, "missing the annotated tag object")

    def test_moved_remote_tag_object_fails(self) -> None:
        provider = _mock_provider()
        provider.git = replace(provider.git, remote_tag_object="c" * 40)
        self.assert_gate_fails(provider, "tag object differs")

    def test_moved_remote_tag_commit_fails(self) -> None:
        provider = _mock_provider()
        provider.git = replace(provider.git, remote_tag_commit="c" * 40)
        self.assert_gate_fails(provider, "peels to a different commit")

    def test_wrong_remote_master_fails(self) -> None:
        provider = _mock_provider()
        provider.git = replace(provider.git, remote_branch_commit="c" * 40)
        self.assert_gate_fails(provider, "origin/master is not exact HEAD")

    def test_missing_expected_check_fails(self) -> None:
        provider = _mock_provider()
        provider.runs = provider.runs[1:]
        self.assert_gate_fails(provider, "check runs are missing")

    def test_failing_expected_check_fails(self) -> None:
        provider = _mock_provider()
        provider.runs[0] = replace(provider.runs[0], conclusion="failure")
        self.assert_gate_fails(provider, "not complete/success")

    def test_pending_expected_check_fails(self) -> None:
        provider = _mock_provider()
        provider.runs[0] = replace(
            provider.runs[0], status="in_progress", conclusion=None
        )
        self.assert_gate_fails(provider, "not complete/success")

    def test_check_run_for_wrong_sha_fails(self) -> None:
        provider = _mock_provider()
        provider.runs[0] = replace(provider.runs[0], head_sha="c" * 40)
        self.assert_gate_fails(provider, "different commit")

    def test_older_failing_duplicate_check_still_fails(self) -> None:
        provider = _mock_provider()
        provider.runs.append(
            replace(
                provider.runs[0],
                identifier=1000,
                status="completed",
                conclusion="failure",
            )
        )
        self.assert_gate_fails(provider, "not complete/success")

    def test_untrusted_required_ruleset_context_fails(self) -> None:
        provider = _mock_provider()
        provider.rules = BranchRules(
            (RequiredCheck(BOUNDARY_CHECK_CONTEXT, 999),), True
        )
        self.assert_gate_fails(provider, "not bound to trusted")

    def test_untrusted_check_run_cannot_satisfy_expected_context(self) -> None:
        provider = _mock_provider()
        provider.runs[0] = replace(
            provider.runs[0], app_id=999, app_slug="other-app"
        )
        self.assert_gate_fails(provider, "check runs are missing")

    def test_missing_release_fails(self) -> None:
        provider = _mock_provider()
        provider.github_release = None
        self.assert_gate_fails(provider, "cannot see a release")

    def test_public_release_fails(self) -> None:
        provider = _mock_provider()
        assert provider.github_release is not None
        provider.github_release = replace(provider.github_release, draft=False)
        self.assert_gate_fails(provider, "private draft is required")

    def test_authenticated_draft_visibility_is_required(self) -> None:
        provider = _mock_provider()
        provider.identity = GitHubIdentity("", OFFICIAL_REPOSITORY)
        self.assert_gate_fails(provider, "identity is unavailable")

    def test_partial_non_prefix_fails(self) -> None:
        provider = _mock_provider()
        provider.registry[1] = _mock_present_registry(PUBLISH_ORDER[1])
        self.assert_gate_fails(provider, "not a valid leaf-first prefix", "auto")

    def test_yanked_prefix_record_fails(self) -> None:
        provider = _mock_provider()
        provider.registry[0] = _mock_present_registry(PUBLISH_ORDER[0], yanked=True)
        self.assert_gate_fails(provider, "yanked or has unknown state", "auto")

    def test_registry_order_mismatch_fails(self) -> None:
        provider = _mock_provider()
        provider.registry[0], provider.registry[1] = (
            provider.registry[1],
            provider.registry[0],
        )
        self.assert_gate_fails(provider, "exact publish order")

    def test_wrong_named_resume_target_fails(self) -> None:
        provider = _mock_provider()
        provider.registry[0] = _mock_present_registry(PUBLISH_ORDER[0])
        self.assert_gate_fails(provider, "first absent crate", PUBLISH_ORDER[4])

    def test_completed_registry_state_fails(self) -> None:
        provider = _mock_provider()
        provider.registry = [
            _mock_present_registry(name) for name in PUBLISH_ORDER
        ]
        self.assert_gate_fails(provider, "already exist", "auto")

    def test_completed_registry_state_passes_only_when_authorized(self) -> None:
        provider = _mock_provider()
        provider.registry = [
            _mock_present_registry(name) for name in PUBLISH_ORDER
        ]
        prefix = verify_release_gate(
            provider,
            "3.0.0",
            "auto",
            allow_complete=True,
            report=None,
        )
        self.assertEqual(prefix, len(PUBLISH_ORDER))

    def test_complete_mode_rejects_partial_state(self) -> None:
        provider = _mock_provider()
        provider.registry[0] = _mock_present_registry(PUBLISH_ORDER[0])
        with self.assertRaisesRegex(GateError, "complete registry state required"):
            verify_release_gate(
                provider,
                "3.0.0",
                "auto",
                allow_complete=True,
                report=None,
            )

    def test_expected_prefix_length_rejects_stale_registry_evidence(self) -> None:
        provider = _mock_provider()
        provider.registry[0] = _mock_present_registry(PUBLISH_ORDER[0])
        with self.assertRaisesRegex(GateError, "prefix length is 1, expected 2"):
            verify_release_gate(
                provider,
                "3.0.0",
                "auto",
                expected_prefix=2,
                report=None,
            )

    def test_registry_identifier_is_required(self) -> None:
        provider = _mock_provider()
        provider.registry[0] = _mock_present_registry(
            PUBLISH_ORDER[0], identifier=0
        )
        self.assert_gate_fails(provider, "identity is missing", "auto")

    def test_registry_checksum_is_required(self) -> None:
        provider = _mock_provider()
        provider.registry[0] = _mock_present_registry(
            PUBLISH_ORDER[0], checksum="not-a-checksum"
        )
        self.assert_gate_fails(provider, "checksum is missing", "auto")

    def test_registry_feature_mismatch_fails(self) -> None:
        provider = _mock_provider()
        provider.registry[0] = _mock_present_registry(
            PUBLISH_ORDER[0],
            features=(("default", ("std",)),),
            expected_features=(),
        )
        self.assert_gate_fails(provider, "feature map differs", "auto")

    def test_registry_dependency_mismatch_fails(self) -> None:
        provider = _mock_provider()
        dependency = (
            "dcrypt-internal",
            "=3.0.0",
            "normal",
            None,
            False,
            False,
            (),
        )
        provider.registry[0] = _mock_present_registry(
            PUBLISH_ORDER[0], dependencies=(dependency,), expected_dependencies=()
        )
        self.assert_gate_fails(provider, "dependency metadata differs", "auto")

    def test_local_internal_dependency_must_be_exact(self) -> None:
        provider = _mock_provider()
        dependency = (
            "dcrypt-internal",
            "^3.0",
            "normal",
            None,
            False,
            False,
            (),
        )
        provider.registry[0] = _mock_present_registry(
            PUBLISH_ORDER[0],
            dependencies=(dependency,),
            expected_dependencies=(dependency,),
        )
        self.assert_gate_fails(provider, "expected =3.0.0", "auto")

    def test_registry_checksum_must_match_reviewed_archive(self) -> None:
        provider = _mock_provider()
        provider.registry[0] = _mock_present_registry(
            PUBLISH_ORDER[0], expected_checksum="d" * 64
        )
        self.assert_gate_fails(provider, "reviewed local archive", "auto")

    def test_git_network_error_is_fatal(self) -> None:
        provider = _mock_provider()
        provider.fail_on.add("git")
        self.assert_gate_fails(provider, "network failure")

    def test_github_network_error_is_fatal(self) -> None:
        provider = _mock_provider()
        provider.fail_on.add("checks")
        self.assert_gate_fails(provider, "network failure")

    def test_release_network_error_is_fatal(self) -> None:
        provider = _mock_provider()
        provider.fail_on.add("release")
        self.assert_gate_fails(provider, "network failure")

    def test_registry_network_error_is_fatal(self) -> None:
        provider = _mock_provider()
        provider.fail_on.add("registry")
        self.assert_gate_fails(provider, "network failure")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", help="release version, for example 3.0.0")
    parser.add_argument(
        "--resume",
        choices=("auto", *PUBLISH_ORDER),
        help="explicitly authorize an existing proper publish-order prefix",
    )
    parser.add_argument(
        "--require-local-archives",
        action="store_true",
        help="require registry checksums to match the passed boundary report",
    )
    parser.add_argument(
        "--allow-complete",
        action="store_true",
        help="require and accept a fully published, verified 12-crate release",
    )
    parser.add_argument(
        "--expected-prefix",
        type=int,
        choices=range(len(PUBLISH_ORDER) + 1),
        help="require exactly this many leaf-first registry records",
    )
    parser.add_argument(
        "--self-test", action="store_true", help="run mock-only fail-closed tests"
    )
    args = parser.parse_args(argv)
    if args.self_test:
        if (
            args.version is not None
            or args.resume is not None
            or args.require_local_archives
            or args.allow_complete
            or args.expected_prefix is not None
        ):
            parser.error("--self-test cannot be combined with release options")
    elif args.version is None:
        parser.error("--version is required")
    elif not SEMVER.fullmatch(args.version):
        parser.error("--version must be a semantic version")
    elif args.allow_complete and not args.require_local_archives:
        parser.error("--allow-complete requires --require-local-archives")
    return args


def run_self_tests() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(GateSelfTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_tests()
    for command in ("git", "gh", "curl", "cargo"):
        if shutil.which(command) is None:
            print(f"error: required command is unavailable: {command}", file=sys.stderr)
            return 1
    assert args.version is not None
    print(
        f"=== Verifying remote release state for dcrypt {args.version} ===",
        flush=True,
    )
    try:
        verify_release_gate(
            LiveEvidenceProvider(
                PROJECT_ROOT,
                require_local_archives=args.require_local_archives,
            ),
            args.version,
            args.resume,
            allow_complete=args.allow_complete,
            expected_prefix=args.expected_prefix,
        )
    except GateError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("Remote release-state gate passed; no external state was changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
