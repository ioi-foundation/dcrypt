#!/usr/bin/env python3
"""Adversarial self-tests for the candidate protocol-specification gate."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterator


MANIFESTED_FILES = {
    "CURRENT-BEHAVIOR.md",
    "README.md",
    "current-behavior.json",
    "protocol-spec.schema.json",
    "protocol-specs-selftest.py",
    "rebind-final-subject.py",
    "verify-protocol-specs.py",
}
ALL_ARTIFACTS = MANIFESTED_FILES | {"ARTIFACTS.sha256"}
ARTIFACT_MODES = {
    "ARTIFACTS.sha256": 0o664,
    "CURRENT-BEHAVIOR.md": 0o664,
    "README.md": 0o664,
    "current-behavior.json": 0o664,
    "protocol-spec.schema.json": 0o664,
    "protocol-specs-selftest.py": 0o775,
    "rebind-final-subject.py": 0o775,
    "verify-protocol-specs.py": 0o775,
}


class SelfTestError(Exception):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_write(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def refresh_manifest(spec_dir: Path) -> None:
    """Simulate an attacker coherently rebinding the mutable package manifest."""
    lines = [f"{sha256(spec_dir / name)}  {name}" for name in sorted(MANIFESTED_FILES)]
    (spec_dir / "ARTIFACTS.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_verifier(
    verifier: Path,
    spec_dir: Path,
    repo_root: Path,
    *extra_arguments: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(verifier),
            "--spec-dir",
            str(spec_dir),
            "--repo-root",
            str(repo_root),
            *extra_arguments,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def require_rejection(
    result: subprocess.CompletedProcess[str],
    name: str,
    expected_fragment: str,
) -> None:
    if result.returncode == 0:
        raise SelfTestError(f"adversarial case unexpectedly passed: {name}")
    if "protocol-spec verification: FAIL:" not in result.stderr:
        raise SelfTestError(
            f"adversarial case did not fail through the gate: {name}:\n"
            + result.stdout
            + result.stderr
        )
    if expected_fragment not in result.stderr:
        raise SelfTestError(
            f"adversarial case failed for the wrong reason: {name}; "
            f"expected {expected_fragment!r}:\n{result.stderr}"
        )


def mutate_extra_property(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    data = load(path)
    data["unexpected"] = True
    canonical_write(path, data)


def mutate_promote_clean_room(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    data = load(path)
    data["clean_room_acceptance"]["status"] = "accepted"
    canonical_write(path, data)


def mutate_promote_oracle(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    data = load(path)
    data["assurance_effect"]["accepted_oracle_count"] = 1
    data["assurance_effect"]["counts_as_interoperability_evidence"] = True
    canonical_write(path, data)


def mutate_ecies_info(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    data = load(path)
    data["ecies"]["suites"][0]["info_ascii"] = "dcrypt-v3/ECIES-P224/rebound"
    canonical_write(path, data)


def mutate_hybrid_classical_info(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    data = load(path)
    data["hybrid_kem"]["suites"][0]["classical_kdf_info_ascii"] = (
        "dcrypt-v3/ECDH-K256-KEM/rebound"
    )
    canonical_write(path, data)


def mutate_error_outcome(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    data = load(path)
    data["ecies"]["error_behavior"][0]["outcome"] = "accepted interoperability evidence"
    canonical_write(path, data)


def mutate_source_role(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    data = load(path)
    data["source_bindings"][0]["role"] = "self-attested independent oracle"
    canonical_write(path, data)


def mutate_ecies_dimension(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    data = load(path)
    data["ecies"]["suites"][1]["point_length"] = 64
    canonical_write(path, data)


def mutate_remove_hybrid_suite(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    data = load(path)
    data["hybrid_kem"]["suites"].pop()
    canonical_write(path, data)


def mutate_source_traversal(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    data = load(path)
    data["source_bindings"][0]["path"] = "../outside.rs"
    canonical_write(path, data)


def mutate_source_digest(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    data = load(path)
    data["source_bindings"][0]["sha256"] = "0" * 64
    canonical_write(path, data)


def mutate_noncanonical_json(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    path.write_bytes(path.read_bytes() + b"\n")


def mutate_open_schema(spec_dir: Path) -> None:
    path = spec_dir / "protocol-spec.schema.json"
    data = load(path)
    data["additionalProperties"] = True
    canonical_write(path, data)


def mutate_duplicate_key(spec_dir: Path) -> None:
    path = spec_dir / "current-behavior.json"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace(
            "{\n",
            '{\n  "artifact_id": "duplicate-must-fail",\n',
            1,
        ),
        encoding="utf-8",
    )


def mutate_rendering_release_claim(spec_dir: Path) -> None:
    path = spec_dir / "CURRENT-BEHAVIOR.md"
    text = path.read_text(encoding="utf-8")
    old = "It accepts no oracle and clears no assurance blocker."
    new = "It accepts one oracle and clears one assurance blocker."
    if text.count(old) != 1:
        raise SelfTestError("release-claim mutation anchor is not unique")
    path.write_text(text.replace(old, new), encoding="utf-8")


def mutate_rendering_ecies_version(spec_dir: Path) -> None:
    path = spec_dir / "CURRENT-BEHAVIOR.md"
    text = path.read_text(encoding="utf-8")
    old = "The `dcrypt-v3` text exists only in HKDF literals."
    new = "The `dcrypt-v3` text is an in-band negotiated frame version."
    if text.count(old) != 1:
        raise SelfTestError("ECIES-version mutation anchor is not unique")
    path.write_text(text.replace(old, new), encoding="utf-8")


def mutate_readme_evidence_claim(spec_dir: Path) -> None:
    path = spec_dir / "README.md"
    text = path.read_text(encoding="utf-8")
    old = "This package does not change implementation behavior. It must not be cited as cross-implementation evidence or used to clear an atomic assurance row."
    new = "This package is passing cross-implementation evidence and clears atomic assurance rows."
    if text.count(old) != 1:
        raise SelfTestError("README evidence mutation anchor is not unique")
    path.write_text(text.replace(old, new), encoding="utf-8")


def mutate_symlink(spec_dir: Path) -> None:
    path = spec_dir / "README.md"
    path.unlink()
    path.symlink_to("CURRENT-BEHAVIOR.md")


def mutate_unexpected_file(spec_dir: Path) -> None:
    (spec_dir / "unreviewed.txt").write_text("must fail\n", encoding="utf-8")


def mutate_missing_file(spec_dir: Path) -> None:
    (spec_dir / "README.md").unlink()


def mutate_stale_manifest(spec_dir: Path) -> None:
    # The scripts are completeness-bound but not self-pinned. Altering one must
    # therefore exercise the independently useful mutable-manifest check.
    path = spec_dir / "protocol-specs-selftest.py"
    path.write_text(path.read_text(encoding="utf-8") + "\n# stale\n", encoding="utf-8")


REBIND_CASES: list[tuple[str, Callable[[Path], None], str]] = [
    ("closed-schema-extra-property", mutate_extra_property, "current-behavior.json"),
    ("clean-room-promotion", mutate_promote_clean_room, "current-behavior.json"),
    ("scaffold-oracle-promotion", mutate_promote_oracle, "current-behavior.json"),
    ("ecies-info-ascii-rebind", mutate_ecies_info, "current-behavior.json"),
    ("hybrid-classical-kdf-info-rebind", mutate_hybrid_classical_info, "current-behavior.json"),
    ("error-outcome-rebind", mutate_error_outcome, "current-behavior.json"),
    ("source-role-rebind", mutate_source_role, "current-behavior.json"),
    ("ecies-dimension-corruption", mutate_ecies_dimension, "current-behavior.json"),
    ("missing-hybrid-suite", mutate_remove_hybrid_suite, "current-behavior.json"),
    ("source-path-traversal", mutate_source_traversal, "current-behavior.json"),
    ("source-digest-corruption", mutate_source_digest, "current-behavior.json"),
    ("noncanonical-json", mutate_noncanonical_json, "current-behavior.json"),
    ("opened-schema", mutate_open_schema, "protocol-spec.schema.json"),
    ("duplicate-json-key", mutate_duplicate_key, "current-behavior.json"),
    ("rendering-release-evidence-claim", mutate_rendering_release_claim, "CURRENT-BEHAVIOR.md"),
    ("rendering-ecies-version-claim", mutate_rendering_ecies_version, "CURRENT-BEHAVIOR.md"),
    ("readme-evidence-claim", mutate_readme_evidence_claim, "README.md"),
]

STRUCTURAL_CASES: list[tuple[str, Callable[[Path], None], str]] = [
    ("symlink-artifact", mutate_symlink, "symlink is forbidden"),
    ("unexpected-artifact", mutate_unexpected_file, "artifact set mismatch"),
    ("missing-artifact", mutate_missing_file, "artifact set mismatch"),
    ("stale-artifact-manifest", mutate_stale_manifest, "ARTIFACTS.sha256 is stale"),
]


def iter_leaf_paths(value: Any, prefix: tuple[str | int, ...] = ()) -> Iterator[tuple[str | int, ...]]:
    if isinstance(value, dict):
        for key in sorted(value):
            yield from iter_leaf_paths(value[key], prefix + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_leaf_paths(item, prefix + (index,))
    else:
        yield prefix


def value_at(value: Any, path: tuple[str | int, ...]) -> Any:
    current = value
    for part in path:
        current = current[part]
    return current


def set_value(value: Any, path: tuple[str | int, ...], replacement: Any) -> None:
    current = value
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = replacement


def corrupted_leaf(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + " [adversarial rebind]"
    raise SelfTestError(f"unsupported normative leaf type: {type(value).__name__}")


def display_path(path: tuple[str | int, ...]) -> str:
    parts: list[str] = []
    for part in path:
        if isinstance(part, int):
            parts.append(f"[{part}]")
        elif parts:
            parts.append(f".{part}")
        else:
            parts.append(part)
    return "".join(parts)


def exercise_every_registry_leaf(
    pristine_dir: Path,
    temp_root: Path,
    verifier: Path,
    repo_root: Path,
) -> int:
    case_dir = temp_root / "every-registry-leaf"
    shutil.copytree(pristine_dir, case_dir, symlinks=True)
    registry_path = case_dir / "current-behavior.json"
    baseline = load(registry_path)
    paths = list(iter_leaf_paths(baseline))

    for path in paths:
        mutated = json.loads(json.dumps(baseline))
        set_value(mutated, path, corrupted_leaf(value_at(mutated, path)))
        canonical_write(registry_path, mutated)
        refresh_manifest(case_dir)
        result = run_verifier(verifier, case_dir, repo_root)
        require_rejection(
            result,
            f"normative-leaf-rebind:{display_path(path)}",
            "reviewed authoritative digest mismatch: current-behavior.json",
        )

    return len(paths)


def exercise_top_level_class_deletions(
    pristine_dir: Path,
    temp_root: Path,
    verifier: Path,
    repo_root: Path,
) -> int:
    case_dir = temp_root / "top-level-class-deletions"
    shutil.copytree(pristine_dir, case_dir, symlinks=True)
    registry_path = case_dir / "current-behavior.json"
    baseline = load(registry_path)

    for key in sorted(baseline):
        mutated = json.loads(json.dumps(baseline))
        del mutated[key]
        canonical_write(registry_path, mutated)
        refresh_manifest(case_dir)
        result = run_verifier(verifier, case_dir, repo_root)
        require_rejection(
            result,
            f"normative-class-deletion:{key}",
            "reviewed authoritative digest mismatch: current-behavior.json",
        )

    return len(baseline)


def exercise_rendering_crosscheck_beyond_pin(
    pristine_dir: Path,
    temp_root: Path,
    repo_root: Path,
) -> None:
    """Prove the registry/rendering cross-check still fails if its pin is updated."""
    case_dir = temp_root / "rendering-crosscheck-beyond-pin"
    shutil.copytree(pristine_dir, case_dir, symlinks=True)
    rendering_path = case_dir / "CURRENT-BEHAVIOR.md"
    verifier_path = case_dir / "verify-protocol-specs.py"
    old_digest = sha256(rendering_path)
    mutate_rendering_release_claim(case_dir)
    new_digest = sha256(rendering_path)
    verifier_text = verifier_path.read_text(encoding="utf-8")
    if verifier_text.count(old_digest) != 1:
        raise SelfTestError("authoritative rendering pin is not unique in copied verifier")
    verifier_path.write_text(verifier_text.replace(old_digest, new_digest), encoding="utf-8")
    refresh_manifest(case_dir)
    result = run_verifier(verifier_path, case_dir, repo_root)
    require_rejection(
        result,
        "rendering-crosscheck-beyond-pin",
        "authoritative rendering is missing non-evidentiary status",
    )


def require_command_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode != 0:
        raise SelfTestError(
            f"{label} failed with exit {result.returncode}:\n"
            + result.stdout
            + result.stderr
        )


def prepare_bound_checkout(
    repo_root: Path,
    spec_dir: Path,
    temp_root: Path,
) -> tuple[Path, dict[str, Any]]:
    registry = load(spec_dir / "current-behavior.json")
    binding = registry["subject_binding"]
    checkout = temp_root / "complete-bound-subject"
    clone = subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--shared",
            "--no-checkout",
            str(repo_root),
            str(checkout),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require_command_success(clone, "local shared clone for subject negatives")
    checkout_result = subprocess.run(
        ["git", "checkout", "--quiet", "--detach", binding["source_commit"]],
        cwd=checkout,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require_command_success(checkout_result, "bound subject checkout")
    for relative in [binding["subject_manifest_path"], binding["curated_operations_path"]]:
        destination = checkout / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo_root / relative, destination)
    return checkout, registry


def run_git_checked(repo: Path, arguments: list[str], label: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require_command_success(result, label)
    return result.stdout.strip()


def update_fixture_manifest_binding(
    fixture: Path,
    commit: str,
    tree: str,
) -> None:
    path = fixture / "assurance/subject-manifest.json"
    document = load(path)
    document["source_commit"] = commit
    document["source_tree"] = tree
    path.write_text(
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o664)


def current_fixture_binding(fixture: Path) -> tuple[str, str]:
    commit = run_git_checked(fixture, ["rev-parse", "HEAD"], "fixture HEAD")
    tree = run_git_checked(fixture, ["rev-parse", "HEAD^{tree}"], "fixture tree")
    update_fixture_manifest_binding(fixture, commit, tree)
    return commit, tree


def prepare_rebind_fixture(
    repo_root: Path,
    spec_dir: Path,
    temp_root: Path,
) -> tuple[Path, str, str]:
    registry = load(spec_dir / "current-behavior.json")
    fixture = temp_root / "transactional-rebind-repository"
    clone = subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--shared",
            "--no-checkout",
            str(repo_root),
            str(fixture),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require_command_success(clone, "transactional rebind fixture clone")
    checkout = subprocess.run(
        ["git", "checkout", "--quiet", "--detach", registry["subject_binding"]["source_commit"]],
        cwd=fixture,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require_command_success(checkout, "transactional rebind fixture checkout")
    run_git_checked(
        fixture,
        ["config", "user.name", "dcrypt protocol self-test"],
        "fixture user.name",
    )
    run_git_checked(
        fixture,
        ["config", "user.email", "protocol-selftest@dcrypt.invalid"],
        "fixture user.email",
    )

    fixture_spec = fixture / "assurance/interoperability/protocol-specs"
    fixture_spec.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(spec_dir, fixture_spec, dirs_exist_ok=True)
    for name, mode in ARTIFACT_MODES.items():
        (fixture_spec / name).chmod(mode)
    for relative in [
        "assurance/curated-operations.toml",
        "assurance/subject-manifest.json",
    ]:
        destination = fixture / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo_root / relative, destination)
        destination.chmod(0o664)

    run_git_checked(
        fixture,
        [
            "add",
            "--",
            "assurance/interoperability/protocol-specs",
            "assurance/curated-operations.toml",
        ],
        "stage reviewed rebind baseline",
    )
    run_git_checked(
        fixture,
        ["commit", "--quiet", "-m", "reviewed protocol rebind baseline"],
        "commit reviewed rebind baseline",
    )
    commit, tree = current_fixture_binding(fixture)
    return fixture, commit, tree


def run_rebind(
    fixture: Path,
    commit: str | None = None,
    tree: str | None = None,
    *extra: str,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        "-B",
        str(fixture / "assurance/interoperability/protocol-specs/rebind-final-subject.py"),
        "--repo-root",
        str(fixture),
    ]
    if commit is not None:
        command.extend(["--expected-commit", commit])
    if tree is not None:
        command.extend(["--expected-tree", tree])
    command.extend(extra)
    return subprocess.run(
        command,
        cwd=fixture,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def require_rebind_rejection(
    result: subprocess.CompletedProcess[str],
    name: str,
    expected_fragment: str,
) -> None:
    if result.returncode == 0:
        raise SelfTestError(f"rebind adversarial case unexpectedly passed: {name}")
    if "final-subject rebind: FAIL:" not in result.stderr:
        raise SelfTestError(
            f"rebind case did not fail through the transaction gate: {name}:\n"
            + result.stdout
            + result.stderr
        )
    if expected_fragment not in result.stderr:
        raise SelfTestError(
            f"rebind case failed for the wrong reason: {name}; "
            f"expected {expected_fragment!r}:\n{result.stderr}"
        )


def snapshot_artifacts(fixture: Path) -> dict[str, tuple[bytes, int]]:
    spec = fixture / "assurance/interoperability/protocol-specs"
    return {
        name: ((spec / name).read_bytes(), stat.S_IMODE((spec / name).stat().st_mode))
        for name in sorted(ALL_ARTIFACTS)
    }


def require_artifact_snapshot(
    fixture: Path,
    expected: dict[str, tuple[bytes, int]],
    label: str,
) -> None:
    spec = fixture / "assurance/interoperability/protocol-specs"
    actual_names = {path.name for path in spec.iterdir()}
    if actual_names != set(expected):
        raise SelfTestError(f"{label}: artifact set changed: {sorted(actual_names)}")
    for name, (value, mode) in expected.items():
        path = spec / name
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != mode
            or path.read_bytes() != value
        ):
            raise SelfTestError(f"{label}: artifact was not restored byte-exactly: {name}")


def exercise_rebind_hardlinks(
    fixture: Path,
    commit: str,
    tree: str,
    temp_root: Path,
) -> int:
    targets = [
        (f"artifact-{name}", f"assurance/interoperability/protocol-specs/{name}")
        for name in sorted(ALL_ARTIFACTS)
    ]
    targets.extend(
        [
            ("input-curated-operations", "assurance/curated-operations.toml"),
            ("input-subject-manifest", "assurance/subject-manifest.json"),
        ]
    )
    backing_root = temp_root / "hardlink-backing"
    backing_root.mkdir()
    for index, (name, relative) in enumerate(targets):
        path = fixture / relative
        backing = backing_root / f"{index}.backing"
        mode = stat.S_IMODE(path.stat().st_mode)
        path.rename(backing)
        os.link(backing, path)
        try:
            result = run_rebind(fixture, commit, tree, "--dry-run")
            require_rebind_rejection(result, name, "hardlink forbidden")
        finally:
            path.unlink()
            backing.rename(path)
            path.chmod(mode)
        print(f"rebind hardlink negative: PASS ({name} rejected)")
    return len(targets)


def commit_assurance_mutation(
    fixture: Path,
    relative: str,
    message: str,
) -> tuple[str, str]:
    run_git_checked(fixture, ["add", "--", relative], f"stage {message}")
    run_git_checked(
        fixture,
        ["commit", "--quiet", "-m", message],
        f"commit {message}",
    )
    return current_fixture_binding(fixture)


def exercise_rebind_semantic_attacks(
    fixture: Path,
) -> tuple[int, str, str]:
    cases: list[tuple[str, str, Callable[[Path], None], str]] = []

    def mutate_frame(path: Path) -> None:
        value = load(path)
        value["ecies"]["frame"]["fields"][0]["encoding"] = "u64"
        canonical_write(path, value)

    def mutate_false_evidence(path: Path) -> None:
        text = path.read_text(encoding="utf-8")
        old = "It accepts no oracle and clears no assurance blocker."
        if text.count(old) != 1:
            raise SelfTestError("false-evidence rebind anchor is not unique")
        path.write_text(
            text.replace(old, "It accepts one oracle and clears one assurance blocker."),
            encoding="utf-8",
        )

    def mutate_curated_support(path: Path) -> None:
        value = path.read_text(encoding="utf-8")
        old = 'support = "supported"'
        if value.count(old) < 1:
            raise SelfTestError("curated support mutation anchor is absent")
        path.write_text(value.replace(old, 'support = "transitional"', 1), encoding="utf-8")

    cases.extend(
        [
            (
                "committed-ecies-u8-to-u64",
                "assurance/interoperability/protocol-specs/current-behavior.json",
                mutate_frame,
                "registry contains a non-allowlisted semantic change",
            ),
            (
                "committed-false-evidence-rendering",
                "assurance/interoperability/protocol-specs/CURRENT-BEHAVIOR.md",
                mutate_false_evidence,
                "authoritative rendering contains a non-allowlisted semantic change",
            ),
            (
                "committed-curated-supported-to-transitional",
                "assurance/curated-operations.toml",
                mutate_curated_support,
                "curated operations differs from the immutable reviewed semantic baseline",
            ),
        ]
    )

    commit = tree = ""
    for name, relative, mutate, expected in cases:
        path = fixture / relative
        original = path.read_bytes()
        original_mode = stat.S_IMODE(path.stat().st_mode)
        mutate(path)
        path.chmod(original_mode)
        commit, tree = commit_assurance_mutation(fixture, relative, name)
        result = run_rebind(fixture, commit, tree, "--dry-run")
        require_rebind_rejection(result, name, expected)
        print(f"rebind semantic negative: PASS ({name} rejected after committed rebind)")
        path.write_bytes(original)
        path.chmod(original_mode)
        commit, tree = commit_assurance_mutation(fixture, relative, f"restore-{name}")
    return len(cases), commit, tree


def exercise_incomplete_synthetic_repo(
    pristine_dir: Path,
    repo_root: Path,
    temp_root: Path,
    verifier: Path,
) -> None:
    registry = load(pristine_dir / "current-behavior.json")
    synthetic = temp_root / "critical-only-repository"
    synthetic.mkdir()
    init = subprocess.run(
        ["git", "init", "--quiet"],
        cwd=synthetic,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require_command_success(init, "synthetic repository initialization")
    for entry in registry["source_bindings"]:
        relative = entry["path"]
        destination = synthetic / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo_root / relative, destination)
    for relative in [
        registry["subject_binding"]["subject_manifest_path"],
        registry["subject_binding"]["curated_operations_path"],
    ]:
        destination = synthetic / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo_root / relative, destination)
    for arguments in [
        ["config", "user.name", "dcrypt protocol self-test"],
        ["config", "user.email", "protocol-selftest@dcrypt.invalid"],
        ["add", "--all"],
        ["commit", "--quiet", "-m", "critical subset only"],
    ]:
        result = subprocess.run(
            ["git", *arguments],
            cwd=synthetic,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        require_command_success(result, f"synthetic git {' '.join(arguments)}")
    result = run_verifier(verifier, pristine_dir, synthetic)
    require_rejection(
        result,
        "critical-only-synthetic-repository",
        "subject source commit cannot be resolved in this repository",
    )


def replace_once(path: Path, old: bytes, new: bytes) -> None:
    value = path.read_bytes()
    if value.count(old) != 1:
        raise SelfTestError(f"source mutation anchor is not unique: {path}: {old!r}")
    path.write_bytes(value.replace(old, new, 1))


def exercise_complete_subject_mutations(
    checkout: Path,
    pristine_dir: Path,
    verifier: Path,
) -> int:
    cases: list[tuple[str, str, bytes | None, bytes | None, str]] = [
        (
            "remove-hybrid-kem-export-module",
            "crates/hybrid/src/kem/mod.rs",
            None,
            None,
            "cannot stat current subject crates/hybrid/src/kem/mod.rs",
        ),
        (
            "mutate-hybrid-feature-manifest",
            "crates/hybrid/Cargo.toml",
            b'default = ["std"]',
            b"default = []",
            "subject manifest current digest mismatch: crates/hybrid/Cargo.toml",
        ),
        (
            "mutate-ml-kem-parameter-alias",
            "crates/kem/src/ml_kem/mod.rs",
            b"pub type MlKem512 =",
            b"pub type MlKem512Wrong =",
            "subject manifest current digest mismatch: crates/kem/src/ml_kem/mod.rs",
        ),
        (
            "mutate-ml-kem-parameter-value",
            "crates/kem/src/ml_kem/params.rs",
            b"const K: usize = 2;",
            b"const K: usize = 3;",
            "subject manifest current digest mismatch: crates/kem/src/ml_kem/params.rs",
        ),
        (
            "mutate-ml-dsa-encoding-leaf",
            "crates/sign/src/dilithium/encoding.rs",
            b"pub fn pack_signature<P:",
            b"pub fn pack_signature_broken<P:",
            "subject manifest current digest mismatch: crates/sign/src/dilithium/encoding.rs",
        ),
        (
            "mutate-ml-dsa-sign-leaf",
            "crates/sign/src/dilithium/sign.rs",
            b"pub(crate) fn sign_internal<P>",
            b"pub(crate) fn sign_internal_broken<P>",
            "subject manifest current digest mismatch: crates/sign/src/dilithium/sign.rs",
        ),
    ]
    for name, relative, old, new, expected_fragment in cases:
        path = checkout / relative
        original = path.read_bytes()
        original_mode = path.stat().st_mode
        try:
            if old is None:
                path.unlink()
            else:
                assert new is not None
                replace_once(path, old, new)
            result = run_verifier(
                verifier,
                pristine_dir,
                checkout,
                "--check-current-subject",
            )
            require_rejection(result, name, expected_fragment)
        finally:
            path.write_bytes(original)
            path.chmod(stat.S_IMODE(original_mode))
        print(f"complete-subject negative: PASS ({name} rejected)")
    return len(cases)


def run() -> None:
    spec_dir = Path(__file__).absolute().parent
    repo_root = spec_dir.parents[2]
    verifier = spec_dir / "verify-protocol-specs.py"

    baseline = run_verifier(verifier, spec_dir, repo_root)
    if baseline.returncode != 0:
        raise SelfTestError(
            "baseline verifier failed before adversarial cases:\n"
            + baseline.stdout
            + baseline.stderr
        )

    interim_final_gate = run_verifier(
        verifier,
        spec_dir,
        repo_root,
        "--require-final-subject",
    )
    require_rejection(
        interim_final_gate,
        "interim-binding-cannot-pass-final-gate",
        "final subject binding is required but this freeze remains interim-rebind-required",
    )
    print("binding-stage negative: PASS (interim subject rejected by final gate)")

    with tempfile.TemporaryDirectory(prefix="dcrypt-protocol-spec-selftest-") as temp_text:
        temp_root = Path(temp_text)

        for name, mutate, artifact_name in REBIND_CASES:
            case_dir = temp_root / name
            shutil.copytree(spec_dir, case_dir, symlinks=True)
            mutate(case_dir)
            refresh_manifest(case_dir)
            result = run_verifier(verifier, case_dir, repo_root)
            require_rejection(
                result,
                name,
                f"reviewed authoritative digest mismatch: {artifact_name}",
            )
            print(f"coherently rehashed negative: PASS ({name} rejected)")

        leaf_count = exercise_every_registry_leaf(spec_dir, temp_root, verifier, repo_root)
        print(
            "coherently rehashed normative-leaf matrix: PASS "
            f"({leaf_count}/{leaf_count} leaf mutations rejected)"
        )

        class_count = exercise_top_level_class_deletions(
            spec_dir, temp_root, verifier, repo_root
        )
        print(
            "coherently rehashed normative-class matrix: PASS "
            f"({class_count}/{class_count} top-level deletions rejected)"
        )

        exercise_rendering_crosscheck_beyond_pin(spec_dir, temp_root, repo_root)
        print("rendering cross-check beyond digest pin: PASS (false evidence claim rejected)")

        exercise_incomplete_synthetic_repo(spec_dir, repo_root, temp_root, verifier)
        print(
            "subject-completeness negative: PASS "
            "(critical-bindings-only synthetic repository rejected)"
        )

        bound_checkout, registry = prepare_bound_checkout(repo_root, spec_dir, temp_root)
        bound_baseline = run_verifier(
            verifier,
            spec_dir,
            bound_checkout,
            "--check-current-subject",
        )
        if bound_baseline.returncode != 0:
            raise SelfTestError(
                "complete bound-subject baseline failed:\n"
                + bound_baseline.stdout
                + bound_baseline.stderr
            )
        print("complete-subject replay: PASS (all current paths/digests/modes match)")

        complete_subject_count = exercise_complete_subject_mutations(
            bound_checkout, spec_dir, verifier
        )

        for name, relative, expected_fragment in [
            (
                "mutate-complete-subject-manifest",
                registry["subject_binding"]["subject_manifest_path"],
                "subject manifest digest differs from the reviewed binding",
            ),
            (
                "mutate-curated-support-classification",
                registry["subject_binding"]["curated_operations_path"],
                "curated operations digest differs from the reviewed binding",
            ),
        ]:
            path = bound_checkout / relative
            original = path.read_bytes()
            try:
                path.write_bytes(original + b"\n# adversarial corruption\n")
                result = run_verifier(
                    verifier,
                    spec_dir,
                    bound_checkout,
                    "--check-current-subject",
                )
                require_rejection(result, name, expected_fragment)
            finally:
                path.write_bytes(original)
            print(f"external-binding negative: PASS ({name} rejected)")

        rebind_fixture, rebind_commit, rebind_tree = prepare_rebind_fixture(
            repo_root,
            spec_dir,
            temp_root,
        )
        hardlink_count = exercise_rebind_hardlinks(
            rebind_fixture,
            rebind_commit,
            rebind_tree,
            temp_root,
        )
        semantic_rebind_count, rebind_commit, rebind_tree = (
            exercise_rebind_semantic_attacks(rebind_fixture)
        )

        rebind_dry_run = run_rebind(
            rebind_fixture,
            rebind_commit,
            rebind_tree,
            "--dry-run",
        )
        require_command_success(rebind_dry_run, "explicit final-subject rebind dry-run")
        if "dry-run: no files changed" not in rebind_dry_run.stdout:
            raise SelfTestError("explicit rebind dry-run did not report nonmutation")
        print("explicit committed-baseline final-subject rebind dry-run: PASS")

        original_artifacts = snapshot_artifacts(rebind_fixture)
        abrupt = run_rebind(
            rebind_fixture,
            rebind_commit,
            rebind_tree,
            "--abrupt-after-replacements",
            "2",
        )
        if abrupt.returncode != 86:
            raise SelfTestError(
                "abrupt interruption did not stop at the injected boundary:\n"
                + abrupt.stdout
                + abrupt.stderr
            )
        if "final-subject rebind: PASS" in abrupt.stdout + abrupt.stderr:
            raise SelfTestError("abrupt partial transaction reported PASS")
        recovery = run_rebind(rebind_fixture, rebind_commit, rebind_tree)
        require_rebind_rejection(
            recovery,
            "abrupt-interruption-recovery",
            "recovered an interrupted transaction and restored originals; rerun required",
        )
        require_artifact_snapshot(
            rebind_fixture,
            original_artifacts,
            "abrupt interruption recovery",
        )
        print("abrupt partial transaction recovery: PASS (detected, restored, no PASS)")

        fault = run_rebind(
            rebind_fixture,
            rebind_commit,
            rebind_tree,
            "--fault-after-replacements",
            "2",
        )
        require_rebind_rejection(
            fault,
            "BaseException-rollback-fault",
            "injected after 2 destination replacement(s)",
        )
        require_artifact_snapshot(
            rebind_fixture,
            original_artifacts,
            "BaseException rollback",
        )
        transaction_path = Path(
            run_git_checked(
                rebind_fixture,
                ["rev-parse", "--path-format=absolute", "--git-path", "dcrypt-protocol-spec-rebind-v1"],
                "transaction path after rollback",
            )
        )
        if os.path.lexists(transaction_path):
            raise SelfTestError("rollback fault left a transaction marker behind")
        print("transaction rollback fault injection: PASS (all 8 artifacts byte-exact)")

        executed_rebind = run_rebind(
            rebind_fixture,
            rebind_commit,
            rebind_tree,
        )
        require_command_success(executed_rebind, "transactional final-subject rebind")
        if "final-subject rebind: PASS" not in executed_rebind.stdout:
            raise SelfTestError("transactional final-subject rebind did not report success")
        if not transaction_path.is_dir():
            raise SelfTestError("complete rebind did not retain its recovery transaction")
        fixture_spec = rebind_fixture / "assurance/interoperability/protocol-specs"
        rebound = run_verifier(
            fixture_spec / "verify-protocol-specs.py",
            fixture_spec,
            rebind_fixture,
            "--require-final-subject",
            "--check-current-subject",
        )
        if rebound.returncode != 0:
            raise SelfTestError(
                "transactional rebound final-subject verifier failed:\n"
                + rebound.stdout
                + rebound.stderr
            )
        finalize = run_rebind(
            rebind_fixture,
            None,
            None,
            "--finalize-transaction",
        )
        require_command_success(finalize, "completed rebind transaction finalization")
        if transaction_path.exists():
            raise SelfTestError("finalized transaction marker still exists")
        print("transactional final-subject rebind, final gate, and finalization: PASS")

        for name, mutate, expected_fragment in STRUCTURAL_CASES:
            case_dir = temp_root / name
            shutil.copytree(spec_dir, case_dir, symlinks=True)
            mutate(case_dir)
            result = run_verifier(verifier, case_dir, repo_root)
            require_rejection(result, name, expected_fragment)
            print(f"structural negative: PASS ({name} rejected)")

    total = (
        len(REBIND_CASES)
        + leaf_count
        + class_count
        + 1
        + len(STRUCTURAL_CASES)
        + 1
        + 1
        + complete_subject_count
        + 2
        + hardlink_count
        + semantic_rebind_count
        + 2
    )
    print(f"protocol-spec self-test: PASS ({total} adversarial cases rejected)")


if __name__ == "__main__":
    try:
        run()
    except SelfTestError as error:
        print(f"protocol-spec self-test: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
