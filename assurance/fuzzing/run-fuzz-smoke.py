#!/usr/bin/env python3
"""Run one exact Package C smoke group against private staged corpora."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True

from fuzzing_lib import (
    DICTIONARY_FOR_TARGET,
    FuzzingError,
    INTEGRATED_ASAN_OPTIONS,
    REPO_ROOT,
    REVIEWED_SEED_MEMBERS,
    SMOKE_GROUPS,
    assert_code_pins,
    build_corpus_manifest,
    build_registry,
    build_sanitizer_controls,
    canonical_fuzz_argv,
    canonical_json,
    parse_json,
    parse_target_listing,
    read_regular_file,
    require_private_contained_path,
    sha256_bytes,
    verify_fuzz_argv,
    verify_registry_against_sources,
)
from compiler_probe import (
    FUZZ_BUILD_LINKER_WRAPPER_SOURCE,
    pinned_cargo_tools,
    verify_binary_symbols,
    verify_fuzz_linker_log,
)


CARGO_WRAPPER_SOURCE = r'''#!/usr/bin/python3
import json, os, sys
real = os.environ["DCRYPT_REAL_CARGO"]
if len(sys.argv) < 2 or sys.argv[1] not in {"build", "metadata", "rustc"}:
    raise SystemExit(97)
argv = [real, "--locked", "--offline", *sys.argv[1:]]
record = (json.dumps(argv, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
fd = os.open(os.environ["DCRYPT_CARGO_ARGV_LOG"], os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
try:
    os.write(fd, record)
finally:
    os.close(fd)
child_env = {key: value for key, value in os.environ.items() if key not in {"DCRYPT_CARGO_ARGV_LOG", "DCRYPT_REAL_CARGO"}}
os.execve(real, argv, child_env)
'''


def required_smoke_binary_symbols(target_id: str) -> list[str]:
    """Return the exact policy-derived sanitizer plus harness marker closure."""

    controls = build_sanitizer_controls()["controls"]
    symbols: list[str] = []
    for control in controls:
        if target_id in control["assigned_target_ids"]:
            symbols.extend(control["target_binary_markers"])
    symbols.extend(
        [
            "__sanitizer_cov_pcs_init",
            "__sanitizer_cov_8bit_counters_init",
            "LLVMFuzzerTestOneInput",
        ]
    )
    if len(symbols) != len(set(symbols)) or target_id not in {
        target["id"] for target in build_registry()["targets"]
    }:
        raise FuzzingError("smoke binary marker assignment is unknown or duplicated")
    return symbols


def validate_instrumentation_proofs(target_id: str, proofs: list[dict[str, str]]) -> None:
    """Reject missing, reordered, duplicated, malformed, or policy-rebound proofs."""

    expected = required_smoke_binary_symbols(target_id)
    if [proof.get("symbol") for proof in proofs] != expected:
        raise FuzzingError("smoke binary instrumentation proof closure differs")
    for proof in proofs:
        if set(proof) != {
            "defined_function_row_sha256",
            "inspector_executable_sha256",
            "inspector_version_sha256",
            "symbol",
            "symbol_table_sha256",
        } or any(
            re.fullmatch(r"[0-9a-f]{64}", proof[key]) is None
            for key in (
                "defined_function_row_sha256",
                "inspector_executable_sha256",
                "inspector_version_sha256",
                "symbol_table_sha256",
            )
        ):
            raise FuzzingError("smoke binary instrumentation proof record differs")


def prove_target_instrumentation(
    target_id: str, binary: Path, *, tools: dict
) -> list[dict[str, str]]:
    """Produce a target/symbol-only diagnostic without exposing private paths or logs."""

    symbols = required_smoke_binary_symbols(target_id)
    try:
        proofs = verify_binary_symbols(binary, symbols, tools=tools)
    except FuzzingError as error:
        detail = str(error)
        symbol_match = re.search(r"symbol=(?:__[A-Za-z0-9_]+|LLVMFuzzerTestOneInput)", detail)
        class_match = re.search(r"class=[a-z-]+", detail)
        symbol = symbol_match.group(0) if symbol_match else "symbol=unknown"
        failure_class = class_match.group(0) if class_match else "class=inspector-rejected"
        raise FuzzingError(
            f"target instrumentation proof failed: target={target_id}, {symbol}, {failure_class}"
        ) from error
    validate_instrumentation_proofs(target_id, proofs)
    return proofs


def _child_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_STACK, (8 * 1024 * 1024, 8 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))


def _run_group_process(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    stdin: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=_child_limits,
        start_new_session=True,
    )
    caught: BaseException | None = None
    try:
        stdout, stderr = process.communicate(input=stdin, timeout=timeout)
    except BaseException as error:
        caught = error
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
    finally:
        # Kill any descendant that daemonized within the private group before
        # returning to the immutable-repository postcheck.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise FuzzingError(f"private process parent was not reaped: {argv[0]}") from error
        # A successful parent exit is not sufficient: no child may remain in
        # the private process group when repository immutability is checked.
        for _ in range(200):
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            raise FuzzingError(f"private process group survived forced teardown: {argv[0]}")
    if caught is not None:
        raise FuzzingError(f"private process group failed or timed out: {argv[0]}") from caught
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def _cargo_environment(private_root: Path) -> tuple[dict, dict[str, str]]:
    tools = pinned_cargo_tools(private_root)
    return tools, dict(tools["environment"])


MUTABLE_SURFACES = (
    "fuzz/Cargo.lock",
    "fuzz/artifacts",
    "fuzz/corpus",
    "fuzz/dictionaries",
    "fuzz/seeds",
)


def _inventory(manifest: dict) -> dict[str, dict]:
    return {
        item["path"]: {
            "git_mode": item["git_mode"],
            "sha256": item["sha256"],
            "size": item["size"],
        }
        for target in manifest["targets"]
        for item in [*target["seeds"], *target["dictionaries"]]
    }


def _mutable_surface_inventory() -> dict[str, dict]:
    result: dict[str, dict] = {}
    for relative in MUTABLE_SURFACES:
        root = REPO_ROOT / relative
        if not root.exists() and not root.is_symlink():
            result[relative] = {"type": "absent"}
            continue
        pending = [(relative, root)]
        while pending:
            name, path = pending.pop()
            metadata = path.lstat()
            mode = format(stat.S_IMODE(metadata.st_mode), "04o")
            if stat.S_ISLNK(metadata.st_mode):
                result[name] = {"mode_octal": mode, "target": os.readlink(path), "type": "symlink"}
            elif stat.S_ISDIR(metadata.st_mode):
                entries = sorted(path.iterdir(), key=lambda item: item.name)
                result[name] = {"entries": [item.name for item in entries], "mode_octal": mode, "type": "directory"}
                pending.extend((f"{name}/{item.name}", item) for item in reversed(entries))
            elif stat.S_ISREG(metadata.st_mode):
                hasher = hashlib.sha256()
                with path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        hasher.update(chunk)
                result[name] = {"mode_octal": mode, "sha256": hasher.hexdigest(), "size": metadata.st_size, "type": "file"}
            else:
                raise FuzzingError(f"unreviewed filesystem object in mutable surface: {name}")
    return dict(sorted(result.items()))


def _write_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


def _fuzz_failure_summary(identifier: str, returncode: int, raw_log: bytes) -> str:
    """Return a non-sensitive failure summary; raw input/log stays private."""

    if not isinstance(identifier, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", identifier):
        raise FuzzingError("failure summary target identity is invalid")
    if not isinstance(returncode, int) or isinstance(returncode, bool):
        raise FuzzingError("failure summary exit code is invalid")
    failure_class = "nonzero-fuzz-process"
    return (
        f"fuzz smoke failed: target={identifier} exit={returncode} "
        f"class={failure_class} private_log_sha256={sha256_bytes(raw_log)} "
        "raw_log_disposition=deleted-with-private-temp-no-durable-triage-store\n"
    )


def _verify_cargo_wrapper_log(path: Path, cargo_path: str) -> str:
    if not path.is_file() or path.is_symlink() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise FuzzingError("private cargo wrapper invocation log is missing or unsafe")
    raw = path.read_bytes()
    try:
        lines = raw.decode("ascii").splitlines()
        records = [json.loads(line) for line in lines]
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FuzzingError("private cargo wrapper invocation log is not canonical JSON lines") from error
    if not records or any(
        not isinstance(record, list)
        or len(record) < 4
        or record[:3] != [cargo_path, "--locked", "--offline"]
        or record[3] not in {"build", "metadata", "rustc"}
        or any(not isinstance(item, str) for item in record)
        for record in records
    ):
        raise FuzzingError("cargo wrapper did not enforce exact locked/offline arguments")
    canonical = b"".join(
        (json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        for record in records
    )
    if canonical != raw:
        raise FuzzingError("cargo wrapper invocation log is not canonical")
    return sha256_bytes(raw)


def _reject_cargo_config_overrides() -> None:
    """Cargo configuration is not part of the reviewed fuzz build contract."""

    home = Path(os.environ.get("HOME", ""))
    roots: set[Path] = {home}
    current = (REPO_ROOT / "fuzz").resolve(strict=True)
    while True:
        roots.add(current)
        if current.parent == current:
            break
        current = current.parent
    candidates = sorted(
        {
            root / ".cargo" / name
            for root in roots
            for name in ("config", "config.toml")
        },
        key=lambda path: str(path),
    )
    for path in candidates:
        if path.exists() or path.is_symlink():
            raise FuzzingError(f"unreviewed Cargo configuration could override the exact fuzz build: {path}")


def plan_group(group: str, private_root: Path) -> list[dict]:
    registry = build_registry()
    by_id = {target["id"]: target for target in registry["targets"]}
    manifest = build_corpus_manifest(REPO_ROOT)
    manifest_by_target = {target["target_id"]: target for target in manifest["targets"]}
    plan = []
    for identifier in SMOKE_GROUPS[group]:
        target = by_id[identifier]
        corpus = private_root / f"corpus-{identifier}"
        artifacts = private_root / f"artifacts-{identifier}"
        dictionary = private_root / f"dictionary-{identifier}.dict"
        plan.append(
            {
                "artifact_directory": str(artifacts),
                "corpus_directory": str(corpus),
                "dictionary_source": DICTIONARY_FOR_TARGET[identifier],
                "private_dictionary": str(dictionary),
                "fuzzer_arguments": canonical_fuzz_argv(
                    target,
                    artifact_prefix=f"{artifacts}/",
                    dictionary_path=str(dictionary),
                ),
                "reviewed_seed_paths": [item["path"] for item in manifest_by_target[identifier]["seeds"]],
                "target_id": identifier,
            }
        )
    return plan


def execute_groups(groups: list[str]) -> list[dict]:
    suite_started_ns = time.monotonic_ns()
    if not groups or groups != list(dict.fromkeys(groups)) or any(group not in SMOKE_GROUPS for group in groups):
        raise FuzzingError("smoke groups must be nonempty, reviewed, ordered, and duplicate-free")
    assert_code_pins()
    registry = build_registry()
    verify_registry_against_sources(REPO_ROOT, registry)
    expected_manifest = build_corpus_manifest(REPO_ROOT)
    stored = parse_json(
        read_regular_file(REPO_ROOT, "assurance/fuzzing/corpus-manifest.json", label="stored corpus manifest"),
        label="stored corpus manifest",
    )
    if stored != expected_manifest:
        raise FuzzingError("stored corpus manifest differs from the code-pinned exact inventory")
    before = _inventory(expected_manifest)
    mutable_before = _mutable_surface_inventory()
    results: list[dict] = []
    primary_error: BaseException | None = None
    try:
        by_id = {target["id"]: target for target in registry["targets"]}
        manifest_by_target = {target["target_id"]: target for target in expected_manifest["targets"]}
        with tempfile.TemporaryDirectory(prefix="dcrypt-private-fuzz-smoke-") as directory:
            private_root = Path(directory)
            os.chmod(private_root, 0o700)
            cargo_tools, cargo_env = _cargo_environment(private_root)
            _reject_cargo_config_overrides()
            cargo_fuzz = cargo_tools["cargo_fuzz_path"]
            probe_tools = cargo_tools["toolchain"]
            build_root = private_root / "shared-target"
            build_root.mkdir(mode=0o700)
            require_private_contained_path(private_root, build_root, label="shared private build directory")
            cargo_wrapper = private_root / "cargo"
            cargo_wrapper.write_text(CARGO_WRAPPER_SOURCE, encoding="utf-8")
            os.chmod(cargo_wrapper, 0o700)
            linker_wrapper = private_root / "cc"
            linker_wrapper.write_text(FUZZ_BUILD_LINKER_WRAPPER_SOURCE, encoding="utf-8")
            os.chmod(linker_wrapper, 0o700)
            linker_log = private_root / "linker-argv.jsonl"
            linker_descriptor = os.open(
                linker_log,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            os.close(linker_descriptor)
            wrapped_env = {
                **cargo_env,
                "CARGO": str(cargo_wrapper),
                "DCRYPT_CARGO_ARGV_LOG": str(private_root / "cargo-argv-unused.jsonl"),
                "DCRYPT_LINKER_ARGV_LOG": str(linker_log),
                "DCRYPT_REAL_CARGO": cargo_tools["cargo_path"],
                "DCRYPT_REAL_LINKER": probe_tools["linker_path"],
                "PATH": (
                    f"{private_root}:{Path(cargo_tools['cargo_fuzz_path']).parent}:"
                    f"{Path(cargo_tools['cargo_path']).parent}:/usr/bin:/bin"
                ),
                "RUSTFLAGS": f"-Clinker={linker_wrapper}",
            }
            metadata_log = private_root / "cargo-argv-metadata.jsonl"
            metadata_env = {
                **wrapped_env,
                "DCRYPT_CARGO_ARGV_LOG": str(metadata_log),
            }
            metadata = _run_group_process(
                [str(cargo_wrapper), "metadata", "--no-deps", "--format-version", "1"],
                cwd=REPO_ROOT / "fuzz",
                env=metadata_env,
                timeout=60,
            )
            if metadata.returncode != 0:
                raise FuzzingError("locked/offline Cargo metadata preflight failed")
            metadata_wrapper_hash = _verify_cargo_wrapper_log(metadata_log, cargo_tools["cargo_path"])
            listing = _run_group_process(
                [cargo_fuzz, "list"],
                cwd=REPO_ROOT / "fuzz",
                timeout=60,
                env=wrapped_env,
            )
            expected_ids = [target["id"] for target in registry["targets"]]
            listing_text = listing.stdout.decode("utf-8", errors="strict")
            parse_target_listing(listing_text, listing.returncode, set(expected_ids))
            if listing_text != "\n".join(expected_ids) + "\n":
                raise FuzzingError("cargo fuzz list differs in raw canonical order/cardinality")
            for group in groups:
                group_started_ns = time.monotonic_ns()
                executed: list[str] = []
                binary_hashes: dict[str, str] = {}
                instrumentation_proofs: dict[str, list[dict[str, str]]] = {}
                linker_proofs: dict[str, dict] = {}
                wrapper_log_hashes: dict[str, str] = {}
                target_results: list[dict] = []
                for identifier in SMOKE_GROUPS[group]:
                    target = by_id[identifier]
                    corpus = private_root / f"corpus-{identifier}"
                    artifacts = private_root / f"artifacts-{identifier}"
                    work = private_root / f"work-{identifier}"
                    log_path = private_root / f"log-{identifier}"
                    build_log_path = private_root / f"build-log-{identifier}"
                    cargo_argv_log = private_root / f"cargo-argv-{identifier}.jsonl"
                    dictionary_path = private_root / f"dictionary-{identifier}.dict"
                    corpus.mkdir(mode=0o700)
                    artifacts.mkdir(mode=0o700)
                    work.mkdir(mode=0o700)
                    require_private_contained_path(private_root, corpus, label="private corpus")
                    require_private_contained_path(private_root, artifacts, label="private artifact directory")
                    require_private_contained_path(private_root, work, label="private working directory")
                    seed_records = manifest_by_target[identifier]["seeds"]
                    if [Path(item["path"]).name for item in seed_records] != list(REVIEWED_SEED_MEMBERS[identifier]):
                        raise FuzzingError("manifest seed membership differs from the code-reviewed order")
                    for item in seed_records:
                        raw = read_regular_file(REPO_ROOT, item["path"], label=f"reviewed seed {item['path']}")
                        if sha256_bytes(raw) != item["sha256"]:
                            raise FuzzingError("reviewed seed digest changed before staging")
                        _write_private(corpus / Path(item["path"]).name, raw)
                    dictionary_record = manifest_by_target[identifier]["dictionaries"]
                    if len(dictionary_record) != 1:
                        raise FuzzingError("target must bind exactly one reviewed dictionary")
                    dictionary_raw = read_regular_file(
                        REPO_ROOT, dictionary_record[0]["path"], label=f"dictionary for {identifier}"
                    )
                    if sha256_bytes(dictionary_raw) != dictionary_record[0]["sha256"]:
                        raise FuzzingError("reviewed dictionary digest changed before staging")
                    _write_private(dictionary_path, dictionary_raw)
                    os.chmod(dictionary_path, 0o400)
                    arguments = canonical_fuzz_argv(
                        target,
                        artifact_prefix=f"{artifacts}/",
                        dictionary_path=str(dictionary_path),
                    )
                    verify_fuzz_argv(
                        arguments,
                        target=target,
                        artifact_prefix=f"{artifacts}/",
                        dictionary_path=str(dictionary_path),
                    )
                    build_env = {
                        **wrapped_env,
                        "DCRYPT_CARGO_ARGV_LOG": str(cargo_argv_log),
                    }
                    build_started_ns = time.monotonic_ns()
                    build = _run_group_process(
                        [
                            cargo_fuzz,
                            "build",
                            "--sanitizer",
                            "address",
                            "--target-dir",
                            str(build_root),
                            identifier,
                        ],
                        cwd=REPO_ROOT / "fuzz",
                        env=build_env,
                        timeout=900,
                    )
                    build_duration_ms = (time.monotonic_ns() - build_started_ns + 999_999) // 1_000_000
                    build_log = build.stdout + build.stderr
                    _write_private(build_log_path, build_log)
                    if build.returncode != 0:
                        raise FuzzingError(f"fuzz build failed for {identifier}")
                    wrapper_log_hashes[identifier] = _verify_cargo_wrapper_log(
                        cargo_argv_log, cargo_tools["cargo_path"]
                    )
                    binary = build_root / "x86_64-unknown-linux-gnu" / "release" / identifier
                    if not binary.is_file() or binary.is_symlink():
                        raise FuzzingError(f"exact built fuzz binary is missing for {identifier}")
                    linker_proofs[identifier] = verify_fuzz_linker_log(
                        linker_log,
                        wrapper=linker_wrapper,
                        binary=binary,
                        private_root=private_root,
                        tools=probe_tools,
                    )
                    instrumentation_proofs[identifier] = prove_target_instrumentation(
                        identifier, binary, tools=probe_tools
                    )
                    binary_hashes[identifier] = linker_proofs[identifier][
                        "materialized_final_binary_sha256"
                    ]
                    run_started_ns = time.monotonic_ns()
                    run = _run_group_process(
                        [str(binary), str(corpus), *arguments],
                        cwd=work,
                        env={
                            "ASAN_OPTIONS": INTEGRATED_ASAN_OPTIONS,
                            "LANG": "C",
                            "LC_ALL": "C",
                            "PATH": "/usr/bin:/bin",
                            "TZ": "UTC",
                        },
                        timeout=max(300, target["resource_limits"]["timeout_seconds"] * 30),
                    )
                    run_duration_ms = (time.monotonic_ns() - run_started_ns + 999_999) // 1_000_000
                    run_log_raw = run.stdout + run.stderr
                    _write_private(log_path, run_log_raw)
                    if run.returncode != 0:
                        raise FuzzingError(
                            _fuzz_failure_summary(identifier, run.returncode, run_log_raw).rstrip("\n")
                        )
                    run_log = run_log_raw.decode("utf-8", errors="strict")
                    if len(re.findall(r"(?m)^#1000\s+DONE\b", run_log)) != 1:
                        raise FuzzingError(f"fuzz smoke lacks exact 1000-execution completion for {identifier}")
                    terminal_stats = re.findall(r"(?m)^Done 1000 runs in ([0-9]+) second\(s\)$", run_log)
                    if len(terminal_stats) != 1:
                        raise FuzzingError(f"fuzz smoke lacks exact terminal execution count for {identifier}")
                    if "Dictionary:" not in run_log or "INFO: Seed: 424242" not in run_log:
                        raise FuzzingError(f"fuzz smoke lacks dictionary/seed confirmation for {identifier}")
                    if list(artifacts.iterdir()):
                        raise FuzzingError(f"fuzz smoke created a failure artifact for {identifier}")
                    for work_member in work.iterdir():
                        if not work_member.is_file() or work_member.is_symlink():
                            raise FuzzingError("private fuzz working directory contains an unreviewed object")
                        os.chmod(work_member, 0o600)
                    executed.append(identifier)
                    target_results.append(
                        {
                            "binary_sha256": binary_hashes[identifier],
                            "integrated_asan_options_sha256": sha256_bytes(
                                INTEGRATED_ASAN_OPTIONS.encode("ascii")
                            ),
                            "build_duration_ms": build_duration_ms,
                            "build_exit_code": build.returncode,
                            "build_log_sha256": sha256_bytes(build_log),
                            "executions_completed": 1000,
                            "libfuzzer_seconds": int(terminal_stats[0]),
                            "run_duration_ms": run_duration_ms,
                            "run_exit_code": run.returncode,
                            "run_log_sha256": sha256_bytes(run_log_raw),
                            "target_id": identifier,
                        }
                    )
                if executed != list(SMOKE_GROUPS[group]):
                    raise FuzzingError("smoke executed a missing, extra, filtered, reordered, or zero target set")
                results.append(
                    {
                        "binary_sha256": dict(sorted(binary_hashes.items())),
                        "cargo_wrapper_invocation_sha256": dict(sorted(wrapper_log_hashes.items())),
                        "cargo_wrapper_metadata_invocation_sha256": metadata_wrapper_hash,
                        "cargo_wrapper_source_sha256": sha256_bytes(CARGO_WRAPPER_SOURCE.encode()),
                        "evidence_classification": "deterministic-smoke-not-persistent-campaign-evidence",
                        "group_duration_ms": (time.monotonic_ns() - group_started_ns + 999_999) // 1_000_000,
                        "group_id": group,
                        "instrumentation_proofs": dict(sorted(instrumentation_proofs.items())),
                        "linker_proofs": dict(sorted(linker_proofs.items())),
                        "mutable_surface_inventory_sha256": sha256_bytes(canonical_json(mutable_before)),
                        "repository_inventory_sha256": sha256_bytes(canonical_json(before)),
                        "status": "passed",
                        "target_ids": executed,
                        "target_results": target_results,
                        "tool_identities": {
                            "cargo_fuzz_crate_sha256": cargo_tools["cargo_fuzz_crate_sha256"],
                            "cargo_fuzz_executable_sha256": cargo_tools["cargo_fuzz_executable_sha256"],
                            "cargo_fuzz_lock_sha256": cargo_tools["cargo_fuzz_lock_sha256"],
                            "cargo_fuzz_provenance_sha256": cargo_tools["cargo_fuzz_provenance_sha256"],
                            "cargo_fuzz_source_tree_sha256": cargo_tools["cargo_fuzz_source_tree_sha256"],
                            "cargo_fuzz_vcs_sha1": cargo_tools["cargo_fuzz_vcs_sha1"],
                            "cargo_fuzz_version_sha256": cargo_tools["cargo_fuzz_version_sha256"],
                            "cargo_sha256": cargo_tools["cargo_sha256"],
                            "cargo_version_sha256": cargo_tools["cargo_version_sha256"],
                            "rustc_sha256": cargo_tools["rustc_sha256"],
                            "rustc_version_sha256": cargo_tools["rustc_version_sha256"],
                            "host_linker_executable_sha256": probe_tools["linker_identity"]["executable_sha256"],
                            "host_linker_version_sha256": probe_tools["linker_identity"]["version_sha256"],
                            "readelf_executable_sha256": probe_tools["readelf_identity"]["executable_sha256"],
                            "readelf_version_sha256": probe_tools["readelf_identity"]["version_sha256"],
                        },
                    }
                )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        after_manifest = build_corpus_manifest(REPO_ROOT)
        mutable_after = _mutable_surface_inventory()
        if _inventory(after_manifest) != before or mutable_after != mutable_before:
            mutation_error = FuzzingError("repository mutable surface changed during private fuzz smoke")
            if primary_error is not None:
                raise mutation_error from primary_error
            raise mutation_error
    suite_duration_ms = (time.monotonic_ns() - suite_started_ns + 999_999) // 1_000_000
    for result in results:
        result["suite_duration_ms"] = suite_duration_ms
    return results


def execute_group(group: str) -> dict:
    return execute_groups([group])[0]


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--group", choices=sorted(SMOKE_GROUPS))
    choice.add_argument("--mode", choices=("pr",))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--print-plan", action="store_true")
    args = parser.parse_args()
    if args.execute and args.print_plan:
        parser.error("--execute and --print-plan are mutually exclusive")
    if args.group is not None and not (args.execute or args.print_plan):
        parser.error("a single --group requires --execute or --print-plan")
    if args.mode == "pr" and not args.print_plan:
        args.execute = True
    try:
        groups = sorted(SMOKE_GROUPS) if args.mode == "pr" else [args.group]
        if args.print_plan:
            with tempfile.TemporaryDirectory(prefix="dcrypt-private-fuzz-plan-") as directory:
                root = Path(directory)
                os.chmod(root, 0o700)
                sys.stdout.buffer.write(canonical_json([item for group in groups for item in plan_group(group, root)]))
        else:
            results = execute_groups(groups)
            sys.stdout.buffer.write(canonical_json({"mode": args.mode, "results": results}))
    except (FuzzingError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print(f"fuzz smoke HOLD: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
