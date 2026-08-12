#!/usr/bin/env python3
"""Execute temp-only safe-Rust sanitizer positive controls.

The output is ephemeral live control evidence only. It is never fuzz-target
campaign evidence, is not sealed into generated artifacts, and never upgrades
the Package C operational HOLD. No fixture source or binary is written to the
repository.
"""

from __future__ import annotations

import argparse
import os
import re
import resource
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from compiler_probe import (
    PINNED_RUSTC_SHA256,
    PINNED_SANITIZER_RUNTIME_SHA256,
    compile_fixture,
)
from fuzzing_lib import FuzzingError, INTEGRATED_ASAN_OPTIONS, canonical_json, sha256_bytes


STACK_LIMIT_KIB = 8192

ASAN_SOURCE = r'''#![forbid(unsafe_code)]
#[inline(never)]
fn consume(depth: usize) -> usize {
    let pad = [0x5au8; 4096];
    std::hint::black_box(&pad);
    if depth == 0 { 0 } else { consume(depth - 1) + usize::from(pad[0] == 0) }
}
fn main() { std::process::exit(consume(usize::MAX) as i32); }
'''

LSAN_SOURCE = r'''#![forbid(unsafe_code)]
fn main() {
    let leaked = Box::leak(Box::new([0x42u8; 4096]));
    std::hint::black_box(leaked);
}
'''


def build_control_requirements() -> dict[str, Any]:
    """Deterministic sealed predicates; host observations stay ephemeral."""

    controls = [
        {
            "control_id": "asan-stack-overflow",
            "evidence_role": "address-mode-memory-safety-positive",
            "host_dependent_fields": [
                "binary_sha256",
                "compiler_argv_sha256",
                "host_linker_identity",
                "host_symbol_inspector_identity",
                "linker_argv_sha256",
                "normalized_report_sha256",
                "symbol_table_sha256",
            ],
            "live_execution_observed": False,
            "required_report_patterns": [
                "ERROR: AddressSanitizer: stack-overflow",
                "SUMMARY: AddressSanitizer: stack-overflow",
            ],
            "required_runtime_sha256": PINNED_SANITIZER_RUNTIME_SHA256["address"],
            "required_sanitizer": "address",
            "required_symbol": "__asan_init",
            "required_runtime_options": {"ASAN_OPTIONS": INTEGRATED_ASAN_OPTIONS},
            "source_sha256": sha256_bytes(ASAN_SOURCE.encode("utf-8")),
            "status": "live-execution-required-not-sealed",
        },
        {
            "control_id": "asan-integrated-box-leak",
            "evidence_role": "integrated-address-mode-leak-detection-positive",
            "host_dependent_fields": [
                "binary_sha256",
                "compiler_argv_sha256",
                "host_linker_identity",
                "host_symbol_inspector_identity",
                "linker_argv_sha256",
                "normalized_report_sha256",
                "symbol_table_sha256",
            ],
            "live_execution_observed": False,
            "required_report_patterns": [
                "ERROR: LeakSanitizer: detected memory leaks",
                "SUMMARY: AddressSanitizer:",
            ],
            "required_runtime_sha256": PINNED_SANITIZER_RUNTIME_SHA256["address"],
            "required_sanitizer": "address",
            "required_symbol": "__asan_init",
            "required_runtime_options": {"ASAN_OPTIONS": INTEGRATED_ASAN_OPTIONS},
            "source_sha256": sha256_bytes(LSAN_SOURCE.encode("utf-8")),
            "status": "live-execution-required-not-sealed",
        },
        {
            "control_id": "lsan-box-leak",
            "evidence_role": "supplemental-standalone-leak-sanitizer-positive",
            "host_dependent_fields": [
                "binary_sha256",
                "compiler_argv_sha256",
                "host_linker_identity",
                "host_symbol_inspector_identity",
                "linker_argv_sha256",
                "normalized_report_sha256",
                "symbol_table_sha256",
            ],
            "live_execution_observed": False,
            "required_report_patterns": [
                "ERROR: LeakSanitizer: detected memory leaks",
                "SUMMARY: LeakSanitizer:",
            ],
            "required_runtime_sha256": PINNED_SANITIZER_RUNTIME_SHA256["leak"],
            "required_sanitizer": "leak",
            "required_symbol": "__lsan_init",
            "required_runtime_options": {
                "LSAN_OPTIONS": "exitcode=87:max_leaks=1:report_objects=1"
            },
            "source_sha256": sha256_bytes(LSAN_SOURCE.encode("utf-8")),
            "status": "live-execution-required-not-sealed",
        },
    ]
    return {
        "actual_positive_controls_observed": 0,
        "controls": controls,
        "operational_campaign_evidence": False,
        "pinned_rustc_executable_sha256": PINNED_RUSTC_SHA256,
        "promotion_authorized": False,
        "required_child_resource_limits": {
            "core_bytes": 0,
            "cpu_seconds": 20,
            "file_bytes": 8 * 1024 * 1024,
            "stack_kib": STACK_LIMIT_KIB,
        },
        "status": "live-execution-required-not-sealed",
    }


def validate_control_requirements(document: dict[str, Any]) -> None:
    if document != build_control_requirements():
        raise FuzzingError("sealed sanitizer requirements claimed or rebound host observations")


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_STACK, (STACK_LIMIT_KIB * 1024, STACK_LIMIT_KIB * 1024))


def _normalized_report(raw: bytes, private_root: Path) -> str:
    text = raw.decode("utf-8", errors="replace").replace(str(private_root), "<PRIVATE_TMP>")
    text = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", text)
    text = re.sub(r"==[0-9]+==", "==PID==", text)
    lines = [line.rstrip() for line in text.splitlines()]
    return "\n".join(lines[-1000:]) + "\n"


def _run_control(
    root: Path,
    *,
    identifier: str,
    sanitizer: str,
    source: str,
    options_name: str,
    options: str,
    required_patterns: tuple[str, ...],
) -> dict[str, Any]:
    source_path = root / f"{identifier}.rs"
    binary_path = root / identifier
    source_path.write_text(source, encoding="utf-8")
    os.chmod(source_path, 0o600)
    compile_record = compile_fixture(
        root, source=source_path, binary=binary_path, sanitizer=sanitizer
    )
    env = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
        options_name: options,
    }
    executed = subprocess.run(
        [str(binary_path)],
        capture_output=True,
        timeout=25,
        env=env,
        preexec_fn=_limits,
    )
    report = _normalized_report(executed.stdout + executed.stderr, root)
    if executed.returncode == 0 or not all(pattern in report for pattern in required_patterns):
        raise FuzzingError(
            f"{identifier} did not emit the exact real sanitizer report "
            f"(exit={executed.returncode}, report_tail={report[-1200:]!r})"
        )
    if "panicked at" in report and "Sanitizer:" not in report:
        raise FuzzingError("a panic cannot substitute for sanitizer positive proof")
    return {
        "binary_sha256": compile_record["binary_sha256"],
        "compiler_probe": compile_record,
        "control_id": identifier,
        "evidence_classification": "local-positive-control-not-campaign-evidence",
        "environment_sha256": sha256_bytes(canonical_json(env)),
        "exit_code": executed.returncode,
        "normalized_report_sha256": sha256_bytes(report.encode("utf-8")),
        "required_report_patterns": list(required_patterns),
        "resource_limits": build_control_requirements()["required_child_resource_limits"],
        "source_sha256": sha256_bytes(source.encode("utf-8")),
        "verified_real_report": True,
    }


def execute_controls() -> dict[str, Any]:
    private_root_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="dcrypt-sanitizer-controls-") as directory:
        root = Path(directory)
        private_root_path = root
        os.chmod(root, 0o700)
        controls = [
            _run_control(
                root,
                identifier="asan-stack-overflow",
                sanitizer="address",
                source=ASAN_SOURCE,
                options_name="ASAN_OPTIONS",
                options=INTEGRATED_ASAN_OPTIONS,
                required_patterns=("ERROR: AddressSanitizer: stack-overflow", "SUMMARY: AddressSanitizer: stack-overflow"),
            ),
            _run_control(
                root,
                identifier="asan-integrated-box-leak",
                sanitizer="address",
                source=LSAN_SOURCE,
                options_name="ASAN_OPTIONS",
                options=INTEGRATED_ASAN_OPTIONS,
                required_patterns=("ERROR: LeakSanitizer: detected memory leaks", "SUMMARY: AddressSanitizer:"),
            ),
            _run_control(
                root,
                identifier="lsan-box-leak",
                sanitizer="leak",
                source=LSAN_SOURCE,
                options_name="LSAN_OPTIONS",
                options="exitcode=87:max_leaks=1:report_objects=1",
                required_patterns=("ERROR: LeakSanitizer: detected memory leaks", "SUMMARY: LeakSanitizer:"),
            ),
        ]
    assert private_root_path is not None
    deleted = not private_root_path.exists()
    if not deleted:
        raise FuzzingError("private sanitizer control temporary tree survived cleanup")
    return {
        "controls": controls,
        "operational_campaign_evidence": False,
        "private_temporary_files_deleted": deleted,
        "status": "passed-local-positive-controls-only",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true", required=True)
    args = parser.parse_args()
    assert args.execute
    try:
        sys.stdout.buffer.write(canonical_json(execute_controls()))
    except (FuzzingError, OSError, subprocess.SubprocessError) as error:
        print(f"sanitizer positive controls BLOCKED: {error}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
