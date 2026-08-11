#!/usr/bin/env python3
"""Generate a deterministic, fail-closed dcrypt candidate audit freeze.

Only bytes reachable from an exact Git commit are inputs.  This tool does not
download dependencies, execute subject code, build artifacts, or promote a
missing evidence class.  Those absences are emitted as release blockers.
"""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import shutil
import secrets
import stat
import subprocess
import sys
import time
import tomllib
import unicodedata
from typing import Any, Iterable


SCHEMA_VERSION = 1
CONTENT_POLICY = "dcrypt-audit-freeze-v1"
PRODUCTION_FREEZE_ID = "dcrypt-v3.0.0-audit-candidate-001"
PROVISIONING_HANDOFF_ID = "dcrypt-audit-provisioning-v1"
PROVISIONING_HANDOFF_FILES = frozenset(("PROVISIONING-MANIFEST.json", "SHA256SUMS"))
EXPECTED_COUNTS = {
    "expected-public-api-units": 19021,
    "expected-atomic-operations": 9298,
    "expected-ledger-evidence-records": 17,
    "expected-action-occurrences": 22,
    "expected-unique-actions": 2,
    "expected-runner-occurrences": 11,
}
EXPECTED_RELEASE_SUBJECT = {
    "tag": "v3.0.0",
    "tag-object": "c3f1dc869df7e61a2c0d4a23833ea6accb5c8b33",
    "commit": "2ad99cae96efef1636cf5b75e40d5b1d3135b34d",
    "tree": "f869553e03b3854849f44f7df7b474a78d4d6c46",
    "classification": "published-v3.0.0-historical-subject",
}
EXPECTED_RELEASE_PAYLOAD_SHA256 = {
    "tag": "819f6a945952c052ac5458f687dc6cbe6aa03de5e67dcc3c7459a0cbaf474ec7",
    "commit": "d0a2a36003c315dcd94550fcb157fc049f5da6d429a693e045cc1126179cc515",
    "tree": "9e54917c2b2e29ca5ddbec6aeeb5dfb25056146411d937b0a96bc00a2c975635",
}
EXPECTED_WORKSPACES = {
    "Cargo.toml": ("published-root", "Cargo.lock", "published-and-test-workspace", True, "classified", None),
    "verification/Cargo.toml": (
        "verification", "verification/Cargo.lock", "isolated-non-published-oracle-workspace", True,
        "classified-with-transitive-review-blocker", "verification-transitive-closure-review-required",
    ),
    "fuzz/Cargo.toml": ("fuzz", "fuzz/Cargo.lock", "isolated-non-published-fuzz-workspace", True, "classified", None),
    "migration/legacy-xchacha20poly1305/Cargo.toml": (
        "legacy-xchacha-migration", "migration/legacy-xchacha20poly1305/Cargo.lock",
        "isolated-non-published-migration-workspace", True, "classified", None,
    ),
    "tools/bench-processor/Cargo.toml": (
        "bench-processor", "tools/bench-processor/Cargo.lock",
        "auxiliary-workspace-not-in-audit-command-graph", False, "blocked", "bench-processor-unclassified-lock",
    ),
}
EXPECTED_ROOT_MEMBERS = (
    "crates/api", "crates/common", "crates/internal", "crates/params",
    "crates/algorithms", "crates/symmetric", "crates/kem", "crates/sign",
    "crates/hybrid", "crates/pke", "crates/utils", "tests",
)
EXPECTED_ROOT_EXCLUDES = (
    "fuzz", "verification", "migration/legacy-xchacha20poly1305",
)
EXPECTED_PUBLISHED_PACKAGES = frozenset(
    ("dcrypt", "dcrypt-algorithms", "dcrypt-api", "dcrypt-common", "dcrypt-hybrid",
     "dcrypt-internal", "dcrypt-kem", "dcrypt-params", "dcrypt-pke", "dcrypt-sign",
     "dcrypt-symmetric", "dcrypt-utils")
)
EXPECTED_SOURCELESS_BY_LOCK = {
    "Cargo.lock": frozenset((name, "3.0.0") for name in (*EXPECTED_PUBLISHED_PACKAGES, "dcrypt-tests")),
    "verification/Cargo.lock": frozenset(
        (*((name, "3.0.0") for name in ("dcrypt-algorithms", "dcrypt-api", "dcrypt-common", "dcrypt-internal", "dcrypt-params", "dcrypt-sign")),
         ("dcrypt-legacy-xchacha20poly1305-migration", "0.0.0"), ("dcrypt-verification", "0.0.0"))
    ),
    "fuzz/Cargo.lock": frozenset(
        (*((name, "3.0.0") for name in ("dcrypt-algorithms", "dcrypt-api", "dcrypt-common", "dcrypt-hybrid", "dcrypt-internal", "dcrypt-kem", "dcrypt-params", "dcrypt-sign", "dcrypt-symmetric")),
         ("dcrypt-fuzz", "0.0.0"), ("dcrypt-legacy-xchacha20poly1305-migration", "0.0.0"))
    ),
    "migration/legacy-xchacha20poly1305/Cargo.lock": frozenset(
        (*((name, "3.0.0") for name in ("dcrypt-algorithms", "dcrypt-api", "dcrypt-common", "dcrypt-internal", "dcrypt-params")),
         ("dcrypt-legacy-xchacha20poly1305-migration", "0.0.0"))
    ),
}
EXPECTED_MANIFEST_IDENTITIES = {
    "Cargo.toml": ("dcrypt", "3.0.0", True),
    "crates/algorithms/Cargo.toml": ("dcrypt-algorithms", "3.0.0", True),
    "crates/api/Cargo.toml": ("dcrypt-api", "3.0.0", True),
    "crates/common/Cargo.toml": ("dcrypt-common", "3.0.0", True),
    "crates/hybrid/Cargo.toml": ("dcrypt-hybrid", "3.0.0", True),
    "crates/internal/Cargo.toml": ("dcrypt-internal", "3.0.0", True),
    "crates/kem/Cargo.toml": ("dcrypt-kem", "3.0.0", True),
    "crates/params/Cargo.toml": ("dcrypt-params", "3.0.0", True),
    "crates/pke/Cargo.toml": ("dcrypt-pke", "3.0.0", True),
    "crates/sign/Cargo.toml": ("dcrypt-sign", "3.0.0", True),
    "crates/symmetric/Cargo.toml": ("dcrypt-symmetric", "3.0.0", True),
    "crates/utils/Cargo.toml": ("dcrypt-utils", "3.0.0", True),
    "tests/Cargo.toml": ("dcrypt-tests", "3.0.0", False),
    "verification/Cargo.toml": ("dcrypt-verification", "0.0.0", False),
    "fuzz/Cargo.toml": ("dcrypt-fuzz", "0.0.0", False),
    "migration/legacy-xchacha20poly1305/Cargo.toml": (
        "dcrypt-legacy-xchacha20poly1305-migration", "0.0.0", False,
    ),
    "tools/bench-processor/Cargo.toml": ("bench-processor", "0.1.0", False),
}
EXPECTED_MANIFEST_PUBLISH_VALUES = {
    path: (None if path == "Cargo.toml" else expected[2])
    for path, expected in EXPECTED_MANIFEST_IDENTITIES.items()
}
EXPECTED_CARGO_INPUT_SHA256 = {
    "Cargo.lock": "350de8b632d80329a7020f49b8ba3c8df35611b61c12039c30b8c7745b4170bd",
    "Cargo.toml": "0dcf0e8826cd4f9e5aee6e120df981ead7a01923e3eb33aa36f4054da426baaf",
    "crates/algorithms/Cargo.toml": "1e87753eea388596316835b760f9c00ba0c83f47f4bd504cce7a0498990252d5",
    "crates/api/Cargo.toml": "7109f0ef85c0bc2b2e9b7832adb4feb78ec4e0e0740909a6b1f2325f0681071a",
    "crates/common/Cargo.toml": "44db31d3c11fedce6f90ec0452e412d6b5e30a56d5a4b9aeaff7c40efae0b30e",
    "crates/hybrid/Cargo.toml": "110faa0dc8b789b31a341ef21e4130420d54234984d11c26bef2e9c5358ff557",
    "crates/internal/Cargo.toml": "5fa8e1a1ac64cb069436a61909f11e4d383eea237821d1beb57d815a4780d33b",
    "crates/kem/Cargo.toml": "3ac85cb9b4919910b8986c1387151a36cc969ff3e78ec6288cb17e01e6ffb3ab",
    "crates/params/Cargo.toml": "39b80900976328d4eaf6f26f80081834994f7ef891b45a68a2db5042ba8ffdf8",
    "crates/pke/Cargo.toml": "49cd2c6525b984157d2f9b8a19e8b3c533b41c11c0f2f043fc5ecbeecdfbca6d",
    "crates/sign/Cargo.toml": "760225eeef22b43cc3a5036cf214bbb777b4322dfb8c3ab84387d64897820378",
    "crates/symmetric/Cargo.toml": "4887e0032a8ed591054e09cbbbe32e5854d8450170106f9c34d395788384956c",
    "crates/utils/Cargo.toml": "35f69a6f2c2891db74927bb456ee0a92f8ae83105710e81394255f97e5b30f32",
    "fuzz/Cargo.lock": "9202ac98e38d9a27d2f08b9e33bba0dfbe6a525fdfc84ae0679561dcd5ae37b8",
    "fuzz/Cargo.toml": "0f714dbfe0adfecc984981755789bc458c4a9edc5a2d92c2ce96d403831c8e19",
    "migration/legacy-xchacha20poly1305/Cargo.lock": "f16bbd9659f7942daa68ddafec9e1731105fe617d88b57d8dc5f788f2df14e11",
    "migration/legacy-xchacha20poly1305/Cargo.toml": "286c2ab4f1387fb00c0d61e3d02221582a5c4320b55355c9182338e1fdb6a431",
    "tests/Cargo.toml": "266300fe450bfd324afe029f39f49e51a8b499aedd973fb0b50c706b7273e511",
    "tools/bench-processor/Cargo.toml": "61a23776acce289c6a58fb1e8531d4c3ac25a482678e19478b83f2cf4c8f059d",
    "verification/Cargo.lock": "2f05e057dc06ea3e5634afc880fd01b401abdeab22627f05bb97b58acb2ba0d5",
    "verification/Cargo.toml": "e88738240a5f80a0232c0ca01e57710db23a15103ccd5f04a37a8faf43b024c8",
}
ROOT_TOOLCHAIN_CONFIGURATION_PATHS = ("rust-toolchain", "rust-toolchain.toml")
TOOLCHAIN_SELECTION_INPUT_PATHS = (
    ".github/workflows/security-validation.yml",
    "assurance/audit/provisioning-lock.toml",
    "assurance/ledger.toml",
)
PROVISIONING_SUBJECT_INPUT_PATHS = tuple(
    sorted(
        {
            *EXPECTED_CARGO_INPUT_SHA256,
            *TOOLCHAIN_SELECTION_INPUT_PATHS,
            "implementation-boundary.toml",
            "assurance/audit/README.md",
            "assurance/audit/audit-freeze.schema.json",
            "assurance/audit/freeze-envelope.schema.json",
            "assurance/audit/freeze-policy.toml",
            "assurance/audit/historical-advisory-regressions.toml",
            "assurance/audit/provisioning-lock.toml",
            "assurance/audit/provisioning.schema.json",
            "assurance/generate-audit-freeze.py",
            "assurance/verify-audit-freeze.py",
            "assurance/audit-freeze-selftest.py",
        }
    )
)
EXPECTED_ARTIFACTS = {
    "sbom-production": ("sbom", "audit-sbom-unavailable"),
    "sbom-verification": ("sbom", "audit-sbom-unavailable"),
    "sbom-fuzz": ("sbom", "audit-sbom-unavailable"),
    "sbom-migration": ("sbom", "audit-sbom-unavailable"),
    "sbom-bench-processor": ("sbom", "audit-sbom-unavailable"),
    "dependency-provision-bundle": ("offline-provisioning", "dependency-provision-bundle-unavailable"),
    "github-action-source-archives": ("action-source", "action-source-archives-unavailable"),
    "runner-image-manifest": ("runner-image", "runner-image-identity-unavailable"),
    "container-oci-layout": ("container-image", "container-image-unavailable"),
    "canonical-source-archive": ("source-archive", "source-archive-unavailable"),
    "candidate-crate-archives": ("package-archives", "candidate-package-archives-unavailable"),
    "published-v3-registry-archives": ("registry-archives", "registry-package-archives-unavailable"),
    "compiled-artifact-matrix": ("build-artifacts", "compiled-build-artifacts-unavailable"),
    "bls-complete-assembly-emissions": ("disassembly", "bls-disassembly-replay-unavailable"),
    "ghash-complete-assembly-emissions": ("disassembly", "ghash-binding-incomplete"),
    "historical-advisory-replay": ("advisory-regression", "historical-advisory-replay-unavailable"),
    "rustsec-database-snapshot": ("advisory-database", "rustsec-database-unbound"),
    "independent-replay-report": ("independent-replay", "independent-replay-unavailable"),
}
EXPECTED_CRATE_ARCHIVES = tuple(
    {
        "name": name,
        "version": "3.0.0",
        "archive": f"{name}-3.0.0.crate",
        "sha256": "blocked",
    }
    for name in (
        "dcrypt-internal", "dcrypt-params", "dcrypt-api", "dcrypt-common",
        "dcrypt-algorithms", "dcrypt-symmetric", "dcrypt-kem", "dcrypt-sign",
        "dcrypt-pke", "dcrypt-utils", "dcrypt-hybrid", "dcrypt",
    )
)
EXPECTED_LIMITATIONS = frozenset(
    (
        "audit-sbom-unavailable", "dependency-provision-bundle-unavailable",
        "action-source-archives-unavailable", "runner-image-identity-unavailable",
        "container-image-unavailable", "source-archive-unavailable",
        "candidate-package-archives-unavailable", "registry-package-archives-unavailable",
        "compiled-build-artifacts-unavailable", "bls-disassembly-replay-unavailable",
        "ghash-binding-incomplete", "historical-advisory-replay-unavailable",
        "bench-processor-unclassified-lock", "verification-transitive-closure-review-required",
        "toolchain-distribution-bundle-unavailable", "independent-replay-unavailable",
        "stable-toolchain-alias-in-workflows", "rustsec-database-unbound",
        "ledger-atomic-assurance-incomplete", "native-runtime-evidence-unavailable",
        "sandbox-kernel-assumptions-unbound",
    )
)
EXPECTED_LIMITATION_METADATA = {
    "audit-sbom-unavailable": ("supply-chain", "dcrypt release engineering", "2026-09-10"),
    "dependency-provision-bundle-unavailable": ("supply-chain", "dcrypt release engineering", "2026-09-10"),
    "action-source-archives-unavailable": ("supply-chain", "dcrypt CI security", "2026-09-10"),
    "runner-image-identity-unavailable": ("build-environment", "dcrypt CI security", "2026-09-10"),
    "container-image-unavailable": ("build-environment", "dcrypt release engineering", "2026-09-10"),
    "source-archive-unavailable": ("artifact", "dcrypt release engineering", "2026-09-10"),
    "candidate-package-archives-unavailable": ("artifact", "dcrypt release engineering", "2026-09-10"),
    "registry-package-archives-unavailable": ("artifact", "dcrypt release engineering", "2026-09-10"),
    "compiled-build-artifacts-unavailable": ("artifact", "dcrypt release engineering", "2026-09-10"),
    "bls-disassembly-replay-unavailable": ("side-channel", "dcrypt side-channel review", "2026-09-10"),
    "ghash-binding-incomplete": ("side-channel", "dcrypt side-channel review", "2026-09-10"),
    "historical-advisory-replay-unavailable": ("regression-evidence", "dcrypt security assurance", "2026-09-10"),
    "bench-processor-unclassified-lock": ("supply-chain", "dcrypt release engineering", "2026-09-10"),
    "verification-transitive-closure-review-required": ("oracle-isolation", "dcrypt interoperability review", "2026-09-10"),
    "toolchain-distribution-bundle-unavailable": ("build-environment", "dcrypt release engineering", "2026-09-10"),
    "independent-replay-unavailable": ("independence", "independent assurance reviewer", "2026-09-10"),
    "stable-toolchain-alias-in-workflows": ("build-environment", "dcrypt CI security", "2026-09-10"),
    "rustsec-database-unbound": ("supply-chain", "dcrypt dependency security", "2026-09-10"),
    "ledger-atomic-assurance-incomplete": ("assurance", "dcrypt security assurance", "2026-11-09"),
    "native-runtime-evidence-unavailable": ("platform", "dcrypt platform assurance", "2026-11-09"),
    "sandbox-kernel-assumptions-unbound": ("build-environment", "dcrypt release engineering", "2026-09-10"),
}
EXPECTED_HISTORICAL_REGRESSIONS = frozenset(f"DCRYPT-2026-{index:04d}" for index in range(1, 12))
EXPECTED_HISTORICAL_ROWS = {
    "DCRYPT-2026-0001": ("global-error-registry-cross-association", "crates/api/src/error/registry.rs", "cargo test --locked -p dcrypt-api --lib error::registry"),
    "DCRYPT-2026-0002": ("ed25519-identity-and-universal-forgery", "crates/sign/src/eddsa/ed25519/tests.rs", "cargo test --locked -p dcrypt-sign --lib rejects_identity_public_key_and_universal_forgery"),
    "DCRYPT-2026-0003": ("aes-gcm-operation-nonce-reuse", "crates/algorithms/src/aead/gcm/tests.rs", "cargo test --locked -p dcrypt-algorithms --lib operation_builder_uses_each_operation_nonce"),
    "DCRYPT-2026-0004": ("streaming-authentication-boundaries", "crates/symmetric/src/streaming", "cargo test --locked -p dcrypt-symmetric --lib streaming"),
    "DCRYPT-2026-0005": ("legacy-b283-arithmetic", "verification/tests/legacy_b283_advisory.rs", "cargo test --release --locked --offline --manifest-path verification/Cargo.toml --test legacy_b283_advisory"),
    "DCRYPT-2026-0006": ("bls12-381-subgroup-decoding", "crates/algorithms/src/ec/bls12_381", "cargo test --locked -p dcrypt-algorithms --lib checked_decoders_reject_on_curve_non_subgroup_point"),
    "DCRYPT-2026-0007": ("bls12-381-rfc9380-interoperability", "verification/tests/bls12_381_interop.rs", "cargo test --release --locked --offline --manifest-path verification/Cargo.toml --test bls12_381_interop"),
    "DCRYPT-2026-0008": ("ml-kem-acvp-regressions", "tests/src/suites/acvp/algorithms/ml_kem.rs", "cargo test --release --locked --offline -p dcrypt-tests --test acvp_tests test_ml_kem"),
    "DCRYPT-2026-0009": ("legacy-xchacha20poly1305-compatibility", "migration/legacy-xchacha20poly1305", "cargo test --release --locked --offline --manifest-path migration/legacy-xchacha20poly1305/Cargo.toml"),
    "DCRYPT-2026-0010": ("xchacha20poly1305-independent-vectors", "verification/tests/xchacha20poly1305.rs", "cargo test --release --locked --offline --manifest-path verification/Cargo.toml --test xchacha20poly1305"),
    "DCRYPT-2026-0011": ("ghash-compiler-emission-guards", "tools/verify-ghash-assembly.sh", "tools/verify-ghash-assembly.sh"),
}
EXPECTED_HOST_TOOLS = {
    "git": ("git version 2.43.0", "/usr/bin/git", "2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668", "locally-observed-unprovisioned", "toolchain-distribution-bundle-unavailable"),
    "python3": ("Python 3.12.3", "/usr/bin/python3.12", "e1efa562c2cc2e35521a5c9c9b9939921001ff8ca9708a13ef15ace68cc2ccd7", "locally-observed-unprovisioned", "toolchain-distribution-bundle-unavailable"),
    "bubblewrap": ("bubblewrap 0.11.0", "/usr/bin/bwrap", "a6203eb2d9ebc2e0e9549c55cda170df85a4e269d4369db3f58dc6c2413d1ba3", "locally-observed-unprovisioned", "sandbox-kernel-assumptions-unbound"),
    "linker-binutils": ("unbound", "blocked", "blocked", "blocked", "toolchain-distribution-bundle-unavailable"),
}
EXPECTED_ACQUISITION_TOOLS = {
    "cargo": ("blocked", "blocked", "unavailable", "toolchain-distribution-bundle-unavailable"),
    "rustup": ("blocked", "blocked", "unavailable", "toolchain-distribution-bundle-unavailable"),
}
EXPECTED_TOOLCHAINS = {
    "public-api-inventory": (
        "nightly-2026-08-07", "1a98b1e135b254f209c67d447b6d8bcd56a859e0",
        "c79e8f89441b3e73d6d65d125c0c745792808c74",
        "1a98b1e135b254f209c67d447b6d8bcd56a859e0", "23.1.0",
        "x86_64-unknown-linux-gnu",
        ("aarch64-unknown-linux-gnu", "thumbv7em-none-eabihf", "wasm32-unknown-unknown", "x86_64-unknown-linux-gnu"),
        "metadata-only-blocked", "toolchain-distribution-bundle-unavailable",
    ),
    "release-stable-reviewed": (
        "1.93.1", "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf",
        "083ac5135f967fd9dc906ab057a2315861c7a80d",
        "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf", "21.1.8",
        "x86_64-unknown-linux-gnu",
        ("aarch64-unknown-linux-gnu", "thumbv7em-none-eabihf", "wasm32-unknown-unknown", "x86_64-unknown-linux-gnu"),
        "metadata-only-blocked", "toolchain-distribution-bundle-unavailable",
    ),
    "assembly-reviewed-alternate": (
        "1.97.1", "8bab26f4f68e0e26f0bb7960be334d5b520ea452",
        "c980f4866141969fab6254a680546a277789d6f0",
        "8bab26f4f68e0e26f0bb7960be334d5b520ea452", "22.1.6",
        "x86_64-unknown-linux-gnu",
        ("aarch64-unknown-linux-gnu", "thumbv7em-none-eabihf", "wasm32-unknown-unknown", "x86_64-unknown-linux-gnu"),
        "metadata-only-blocked", "toolchain-distribution-bundle-unavailable",
    ),
}
EXPECTED_GITHUB_ACTIONS = {
    "actions-checkout": (
        "actions/checkout", "3d3c42e5aac5ba805825da76410c181273ba90b1", "blocked",
        "commit-pinned-source-unavailable", "action-source-archives-unavailable",
    ),
    "dtolnay-rust-toolchain": (
        "dtolnay/rust-toolchain", "6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772", "blocked",
        "commit-pinned-source-unavailable", "action-source-archives-unavailable",
    ),
}
EXPECTED_SECURITY_TOOLS = {
    "cargo-audit": ("0.22.2", "blocked", "version-pinned-binary-unavailable", "rustsec-database-unbound"),
    "cargo-deny": ("0.20.2", "blocked", "version-pinned-binary-unavailable", "rustsec-database-unbound"),
    "cargo-fuzz": ("0.13.2", "blocked", "version-pinned-binary-unavailable", "dependency-provision-bundle-unavailable"),
    "cargo-release": ("unbound", "blocked", "blocked", "toolchain-distribution-bundle-unavailable"),
}
EXPECTED_ADVISORY_DATABASES = {
    "rustsec-advisory-db": ("blocked", "blocked", "unavailable", "rustsec-database-unbound"),
}
EXPECTED_RUNNER_IMAGES = {
    "github-ubuntu-24.04": (
        "ubuntu-24.04", "blocked", "blocked", "mutable-label-only",
        "runner-image-identity-unavailable",
    ),
}
EXPECTED_CONTAINER_IMAGES = {
    "audit-build-environment": (
        "none", "blocked", "blocked", "unavailable", "container-image-unavailable",
    ),
}
EXPECTED_BOUND_CONTROL_SHA256 = {
    ".github/workflows/security-validation.yml": "1fb51314c1800679a2b4c3b7ac07318e2959a390eda6d7a80d421f9866ae7a69",
    "assurance/audit/README.md": "ac5316b0156b8a7f60ce141b44313a8c3f2c934b74d996ac99ebcdf2adf20e9f",
    "assurance/audit/audit-freeze.schema.json": "d7a1e7a4302a2cc87cc5bdefae382e4f2f1757e4fb5619a51743d036c20913ae",
    "assurance/audit/freeze-envelope.schema.json": "68d20098b24133aa13fc930f14d013245534098e30a786802adce2d5eec6a20f",
    "assurance/audit/provisioning.schema.json": "681f7688b9a581af6384cd36723dd1f12462a625718e9bf131220b69c55db600",
    "assurance/audit/freeze-policy.toml": "5a7d3683e266887aca6ac93b42ef11d3c9d912cf9c3fbbf00813272d2b6a89bc",
    "assurance/audit/provisioning-lock.toml": "3733ed23be2f93e6a756162bde9a841ab4a165037ccc1c0a22d3e23bd5030177",
    "assurance/audit/historical-advisory-regressions.toml": "ce6fa84b1a8de37d938e51b82806e67b8cc6c7dcb4d3234cdcd44c76cf96acc7",
}
GIT_EXECUTABLE = Path("/usr/bin/git")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REMOTE_ACTION = re.compile(r"^(?P<repository>[^/@\s]+/[^@\s]+)@(?P<ref>[^\s]+)$")
USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"#\s]+)")
RUNNER_LINE = re.compile(r"^\s*runs-on:\s*['\"]?([^'\"#\s]+)")
TOOLCHAIN_LINE = re.compile(r"^\s*toolchain:\s*['\"]?([^'\"#\s]+)")

SUBORDINATE_FILES = (
    "actions-and-runners.json",
    "artifact-manifest.json",
    "assurance-inputs.json",
    "environment.json",
    "limitations.json",
    "source-manifest.json",
    "toolchains.json",
    "workspace-dependencies.json",
)
JSON_FILES = tuple(
    sorted((*SUBORDINATE_FILES, "PROVISIONING-MANIFEST.json", "freeze-envelope.json", "freeze.json"))
)
ALLOWED_BUNDLE_FILES = frozenset((*JSON_FILES, "PROVISIONING-SHA256SUMS", "SHA256SUMS"))
MAX_BUNDLE_FILE_BYTES = 128 * 1024 * 1024
MAX_BUNDLE_TOTAL_BYTES = 256 * 1024 * 1024
SUBJECT_COMMAND_TARGETS = (
    "assurance/audit/sow/selftest.py",
    "assurance/audit/sow/verify-sow.py",
    "assurance/generate-assurance-ledger.py",
    "assurance/generate-audit-freeze.py",
    "assurance/threat-models/threat-model-selftest.py",
    "assurance/threat-models/verify-threat-models.py",
    "assurance/verify-assurance-ledger.py",
    "assurance/verify-audit-freeze.py",
)


def freeze_command_inventory(subject: str, freeze_id: str) -> tuple[list[str], list[dict[str, Any]]]:
    """Return exact sandbox-internal commands and honest execution semantics.

    Host checkout/output paths are deliberately not encoded as pseudo-argv.
    Commands 12--16 are executable only after the separately bound bubblewrap
    mount/environment contract maps their absolute virtual paths.
    """

    if not HEX40.fullmatch(subject):
        fail("freeze command inventory requires an exact subject commit")
    if freeze_id != PRODUCTION_FREEZE_ID:
        fail("freeze command inventory requires the reviewed candidate identifier")
    commands = [
        "/usr/bin/python3.12 -I -B -S assurance/generate-assurance-ledger.py --check",
        "/usr/bin/python3.12 -I -B -S assurance/verify-assurance-ledger.py --self-test",
        "/usr/bin/python3.12 -I -B -S assurance/verify-assurance-ledger.py --snapshot-only --mode ci",
        "/usr/bin/python3.12 -I -B -S assurance/verify-assurance-ledger.py --snapshot-only --mode release",
        "/usr/bin/python3.12 -I -B -S assurance/verify-assurance-ledger.py --mode ci",
        "/usr/bin/python3.12 -I -B -S assurance/verify-assurance-ledger.py --mode release",
        "/usr/bin/python3.12 -I -B -S -c 'import runpy,sys;sys.path.insert(0,\"assurance/threat-models\");runpy.run_path(\"assurance/threat-models/verify-threat-models.py\",run_name=\"__main__\")' --mode ci",
        "/usr/bin/python3.12 -I -B -S -c 'import runpy,sys;sys.path.insert(0,\"assurance/threat-models\");runpy.run_path(\"assurance/threat-models/verify-threat-models.py\",run_name=\"__main__\")' --mode release",
        "/usr/bin/python3.12 -I -B -S -c 'import runpy,sys;sys.path.insert(0,\"assurance/threat-models\");runpy.run_path(\"assurance/threat-models/threat-model-selftest.py\",run_name=\"__main__\")'",
        "/usr/bin/python3.12 -I -B -S assurance/audit/sow/verify-sow.py",
        "/usr/bin/python3.12 -I -B -S assurance/audit/sow/verify-sow.py --issuance",
        "/usr/bin/python3.12 -I -B -S assurance/audit/sow/selftest.py",
        "/usr/bin/python3.12 -I -B -S /dcrypt/assurance/verify-audit-freeze.py --self-test",
        (
            "/usr/bin/python3.12 -I -B -S /dcrypt/assurance/generate-audit-freeze.py "
            f"--materialize-provisioning --repo /dcrypt --subject {subject} "
            f"--output /output/{PROVISIONING_HANDOFF_ID}"
        ),
        (
            "/usr/bin/python3.12 -I -B -S /dcrypt/assurance/generate-audit-freeze.py "
            f"--repo /dcrypt --subject {subject} --provision /provision "
            f"--output /output/{freeze_id}"
        ),
        (
            "/usr/bin/python3.12 -I -B -S /dcrypt/assurance/verify-audit-freeze.py "
            f"--repo /evidence --subject-repo /dcrypt --provision /provision "
            f"--bundle /evidence/assurance/audit/freezes/{freeze_id} --mode structural"
        ),
        (
            "/usr/bin/python3.12 -I -B -S /dcrypt/assurance/verify-audit-freeze.py "
            f"--repo /evidence --subject-repo /dcrypt --provision /provision "
            f"--bundle /evidence/assurance/audit/freezes/{freeze_id} --mode release"
        ),
    ]
    expectations = [
        {"command_index": 0, "expected": "pass-reproducible-generator-check"},
        {"command_index": 1, "expected": "pass-offline-selftest"},
        {"command_index": 2, "expected": "pass-structural-snapshot-only"},
        {"command_index": 3, "expected": "fail-snapshot-not-release-evidence"},
        {"command_index": 4, "expected": "blocked-unprovisioned-do-not-run-as-structural-replay"},
        {"command_index": 5, "expected": "blocked-unprovisioned-and-atomic-release-blocked"},
        {"command_index": 6, "expected": "pass"},
        {"command_index": 7, "expected": "fail-release-controls-44-errors"},
        {"command_index": 8, "expected": "pass"},
        {"command_index": 9, "expected": "pass"},
        {"command_index": 10, "expected": "fail-uncommissioned-unreplayed"},
        {"command_index": 11, "expected": "pass"},
        {"command_index": 12, "expected": "not-executed-by-generator-requires-exact-selftest-sandbox"},
        {"command_index": 13, "expected": "not-executed-by-generator-requires-exact-provision-sandbox"},
        {"command_index": 14, "expected": "not-executed-by-generator-requires-exact-generation-sandbox"},
        {"command_index": 15, "expected": "not-executed-by-generator-structural-result-must-be-blocked"},
        {"command_index": 16, "expected": "not-executed-by-generator-release-result-must-fail-blocked"},
    ]
    referenced_targets = {
        match.removeprefix("/dcrypt/")
        for command in commands
        for match in re.findall(r"(?:/dcrypt/)?assurance/[A-Za-z0-9_./-]+\.py", command)
    }
    if referenced_targets != set(SUBJECT_COMMAND_TARGETS):
        fail(
            "freeze command target inventory drift: "
            f"expected {list(SUBJECT_COMMAND_TARGETS)}, got {sorted(referenced_targets)}"
        )
    return commands, expectations


class FreezeError(RuntimeError):
    """A fail-closed freeze validation error."""


def fail(message: str) -> None:
    raise FreezeError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reject_float(_: str) -> None:
    fail("floating-point JSON values are forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_strict(data: bytes, *, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label}: JSON is not UTF-8: {exc}")
    if unicodedata.normalize("NFC", text) != text:
        fail(f"{label}: JSON text is not NFC-normalized")
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except (json.JSONDecodeError, TypeError) as exc:
        fail(f"{label}: invalid JSON: {exc}")


def _walk_json(value: Any, path: str = "$") -> None:
    if isinstance(value, float):
        fail(f"{path}: floating-point values are forbidden")
    if isinstance(value, str) and unicodedata.normalize("NFC", value) != value:
        fail(f"{path}: string is not NFC-normalized")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                fail(f"{path}: non-string object key")
            if unicodedata.normalize("NFC", key) != key:
                fail(f"{path}: object key is not NFC-normalized: {key!r}")
            _walk_json(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_json(child, f"{path}[{index}]")
    elif value is not None and not isinstance(value, (str, int, bool)):
        fail(f"{path}: unsupported JSON value {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    _walk_json(value)
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    text = unicodedata.normalize("NFC", text)
    return (text + "\n").encode("utf-8")


def canonical_json_is_exact(data: bytes, *, label: str) -> Any:
    value = load_json_strict(data, label=label)
    if canonical_json(value) != data:
        fail(f"{label}: JSON is not in canonical byte form")
    return value


def validate_json_schema(instance: Any, schema: dict[str, Any], *, label: str = "$") -> None:
    """Evaluate the closed JSON-Schema subset used by the three bound schemas."""

    if "const" in schema and canonical_json(instance) != canonical_json(schema["const"]):
        fail(f"{label}: value differs from schema const")
    if "enum" in schema and not any(
        canonical_json(instance) == canonical_json(candidate) for candidate in schema["enum"]
    ):
        fail(f"{label}: value is outside schema enum")
    kind = schema.get("type")
    type_ok = {
        "object": lambda value: isinstance(value, dict),
        "array": lambda value: isinstance(value, list),
        "string": lambda value: isinstance(value, str),
        "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
        "boolean": lambda value: isinstance(value, bool),
    }
    if kind is not None:
        if kind not in type_ok or not type_ok[kind](instance):
            fail(f"{label}: value does not satisfy schema type {kind!r}")
    if isinstance(instance, dict):
        required = schema.get("required", [])
        missing = sorted(set(required) - set(instance))
        if missing:
            fail(f"{label}: schema-required keys are missing: {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unexpected = sorted(set(instance) - set(properties))
            if unexpected:
                fail(f"{label}: schema forbids additional keys: {unexpected}")
        for key, child in instance.items():
            if key in properties:
                validate_json_schema(child, properties[key], label=f"{label}.{key}")
    if isinstance(instance, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(instance) < minimum:
            fail(f"{label}: array is shorter than schema minItems")
        if isinstance(maximum, int) and len(instance) > maximum:
            fail(f"{label}: array is longer than schema maxItems")
        if schema.get("uniqueItems") is True:
            rendered = [canonical_json(child) for child in instance]
            if len(rendered) != len(set(rendered)):
                fail(f"{label}: schema uniqueItems violation")
        child_schema = schema.get("items")
        if isinstance(child_schema, dict):
            for index, child in enumerate(instance):
                validate_json_schema(child, child_schema, label=f"{label}[{index}]")
    if isinstance(instance, str):
        if isinstance(schema.get("minLength"), int) and len(instance) < schema["minLength"]:
            fail(f"{label}: string is shorter than schema minLength")
        if "pattern" in schema and re.fullmatch(schema["pattern"], instance) is None:
            fail(f"{label}: string does not match schema pattern")
    if isinstance(instance, int) and not isinstance(instance, bool):
        if isinstance(schema.get("minimum"), int) and instance < schema["minimum"]:
            fail(f"{label}: integer is below schema minimum")


def validate_schema_program(schema: dict[str, Any], *, label: str) -> None:
    allowed = {
        "$schema", "$id", "title", "type", "additionalProperties", "required", "properties",
        "const", "enum", "pattern", "minLength", "minItems", "maxItems", "uniqueItems",
        "items", "minimum", "$defs",
    }
    unexpected = sorted(set(schema) - allowed)
    if unexpected:
        fail(f"{label}: schema uses unsupported keywords: {unexpected}")
    if "properties" in schema:
        if not isinstance(schema["properties"], dict):
            fail(f"{label}: schema properties must be an object")
        for key, child in schema["properties"].items():
            if not isinstance(child, dict):
                fail(f"{label}.{key}: schema node must be an object")
            validate_schema_program(child, label=f"{label}.{key}")
    if "items" in schema:
        if not isinstance(schema["items"], dict):
            fail(f"{label}: schema items must be an object")
        validate_schema_program(schema["items"], label=f"{label}[]")
    if "$defs" in schema:
        if not isinstance(schema["$defs"], dict):
            fail(f"{label}: schema $defs must be an object")
        for key, child in schema["$defs"].items():
            if not isinstance(child, dict):
                fail(f"{label}.$defs.{key}: schema node must be an object")
            validate_schema_program(child, label=f"{label}.$defs.{key}")


def open_bound_git_executable() -> int:
    """Open and hash the exact Git inode before any Git subprocess executes."""

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(GIT_EXECUTABLE, flags)
    except OSError as exc:
        fail(f"cannot safely open the bound Git executable: {exc}")
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            fail("bound Git executable must be an exclusively linked regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        if digest.hexdigest() != EXPECTED_HOST_TOOLS["git"][2]:
            fail("Git executable bytes differ from the reviewed locally observed identity")
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            identity_result = subprocess.run(
                [f"/proc/self/fd/{descriptor}", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=closed_git_environment(),
                timeout=10,
                pass_fds=(descriptor,),
            )
        except subprocess.TimeoutExpired:
            fail("bound Git identity check exceeded the 10-second fail-closed timeout")
        identity = identity_result.stdout.decode("utf-8", "strict").strip()
        if identity_result.returncode != 0 or identity != EXPECTED_HOST_TOOLS["git"][0]:
            fail("Git executable version identity differs from the reviewed locally observed identity")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _git(repo: Path, *args: str, input_data: bytes | None = None) -> bytes:
    executable_fd = open_bound_git_executable()
    command = [f"/proc/self/fd/{executable_fd}", "-C", str(repo), *args]
    try:
        try:
            result = subprocess.run(
                command,
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=closed_git_environment(),
                timeout=30,
                pass_fds=(executable_fd,),
            )
        finally:
            os.close(executable_fd)
    except subprocess.TimeoutExpired:
        fail(f"command exceeded the 30-second fail-closed timeout: {' '.join(command)}")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        fail(f"command failed ({' '.join(command)}): {detail}")
    return result.stdout


def closed_git_environment() -> dict[str, str]:
    """Return the complete environment for every Git subprocess.

    No ambient Git/Python/Cargo/config/credential variables are inherited.
    Only local file transport is allowed, for clean-clone replay.
    """

    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_ASKPASS": "/bin/false",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "PAGER": "cat",
        "SSH_ASKPASS": "/bin/false",
    }


def require_isolated_python() -> None:
    executable = lexical_absolute(Path(sys.executable))
    if executable != Path("/usr/bin/python3.12"):
        fail(f"audit-freeze tooling requires /usr/bin/python3.12, found {executable}")
    if sys.flags.isolated != 1 or sys.flags.dont_write_bytecode != 1 or sys.flags.no_site != 1:
        fail("audit-freeze tooling must run with isolated Python flags -I -B -S")
    if sys.flags.optimize != 0:
        fail("audit-freeze tooling forbids Python optimization because self-test assertions must execute")
    if sha256(executable.read_bytes()) != EXPECTED_HOST_TOOLS["python3"][2]:
        fail("Python executable bytes differ from the reviewed locally observed identity")


def observed_host_tools(provisioning: dict[str, Any]) -> list[dict[str, Any]]:
    arguments = {
        "git": ["--version"],
        "python3": ["--version"],
        "bubblewrap": ["--version"],
    }
    observed: list[dict[str, Any]] = []
    rows = {row["id"]: row for row in provisioning["host-tool"]}
    for identifier in ("git", "python3", "bubblewrap"):
        row = rows[identifier]
        path = Path(row["path"])
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            fail(f"required host tool is unavailable or cannot be safely opened: {path}: {exc}")
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                fail(f"required host tool must be an exclusively linked regular file: {path}")
            digest_state = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest_state.update(chunk)
            digest = digest_state.hexdigest()
            if digest != row["binary-sha256"]:
                fail(f"host-tool binary digest drift: {identifier}")
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                result = subprocess.run(
                    [f"/proc/self/fd/{descriptor}", *arguments[identifier]],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"},
                    timeout=10,
                    pass_fds=(descriptor,),
                )
            except subprocess.TimeoutExpired:
                fail(f"host-tool identity check exceeded its timeout: {identifier}")
        finally:
            os.close(descriptor)
        identity = result.stdout.decode("utf-8", "strict").strip()
        if result.returncode != 0 or identity != row["identity"]:
            fail(f"host-tool version identity drift: {identifier}")
        observed.append(
            {
                "availability": row["availability"],
                "binary_sha256": digest,
                "id": identifier,
                "identity": identity,
                "limitation": row["limitation"],
                "path": row["path"],
            }
        )
    return observed


def parse_sandbox_mountinfo(text: str) -> dict[str, list[dict[str, Any]]]:
    mount_rows: dict[str, list[dict[str, Any]]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 7 or "-" not in fields:
            fail("sandbox mountinfo contains a malformed row")
        separator = fields.index("-")
        if separator + 3 >= len(fields):
            fail("sandbox mountinfo row lacks filesystem metadata")
        decode_mount = lambda value: value.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
        mount_point = decode_mount(fields[4])
        mount_rows.setdefault(mount_point, []).append(
            {
                "device": fields[2],
                "id": fields[0],
                "options": set(fields[5].split(",")),
                "root": decode_mount(fields[3]),
                "filesystem": fields[separator + 1],
                "source": decode_mount(fields[separator + 2]),
            }
        )
    return mount_rows


def validate_sandbox_mount_topology(
    mount_rows: dict[str, list[dict[str, Any]]], *, require_empty_output: bool,
    require_evidence: bool, require_provision: bool = False,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    required_mounts = {
        "/", "/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache", "/dcrypt",
        "/dev", "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
        "/dev/tty", "/dev/pts", "/proc", "/tmp", "/cargo",
    }
    operation_mounts = {
        *(('/output',) if require_empty_output else ()),
        *(('/evidence',) if require_evidence else ()),
        *(('/provision',) if require_provision else ()),
    }
    expected_mounts = required_mounts | operation_mounts
    observed_mounts = set(mount_rows)
    missing_mounts = sorted(expected_mounts - observed_mounts)
    unexpected_mounts = sorted(observed_mounts - expected_mounts)
    if missing_mounts or unexpected_mounts:
        fail(
            "sandbox mount set differs from the closed contract: "
            f"missing={missing_mounts} unexpected={unexpected_mounts}"
        )
    if any(len(rows) != 1 for rows in mount_rows.values()):
        fail("sandbox mount contract forbids stacked/duplicate mount points")
    readonly_runtime = ("/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache")
    for mount_point in readonly_runtime:
        row = mount_rows[mount_point][0]
        if "ro" not in row["options"] or "rw" in row["options"]:
            fail(f"sandbox runtime mount must be read-only: {mount_point}")
    root_mount = mount_rows["/"][0]
    if (
        "ro" not in root_mount["options"]
        or "rw" in root_mount["options"]
        or root_mount["filesystem"] != "tmpfs"
        or root_mount["source"] != "tmpfs"
        or root_mount["root"] != "/newroot"
    ):
        fail("sandbox root must be the reviewed read-only fresh tmpfs root")
    expected_fresh_mounts = {
        "/dev": ("tmpfs", "tmpfs", "/"),
        "/dev/pts": ("devpts", "devpts", "/"),
        "/proc": ("proc", "proc", "/"),
        "/tmp": ("tmpfs", "tmpfs", "/"),
        "/cargo": ("tmpfs", "tmpfs", "/"),
    }
    for mount_point, (filesystem, source, mount_root) in expected_fresh_mounts.items():
        row = mount_rows[mount_point][0]
        if (
            row["filesystem"] != filesystem
            or row["source"] != source
            or row["root"] != mount_root
            or "rw" not in row["options"]
            or "ro" in row["options"]
        ):
            fail(f"sandbox mount role/options drift: {mount_point}")
    for mount_point in ("/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty"):
        row = mount_rows[mount_point][0]
        if (
            row["filesystem"] != "devtmpfs"
            or row["source"] != "udev"
            or row["root"] != f"/{PurePosixPath(mount_point).name}"
            or "rw" not in row["options"]
        ):
            fail(f"sandbox device mount role/options drift: {mount_point}")
    nested_subject_mounts = sorted(
        mount_point for mount_point in mount_rows if mount_point.startswith("/dcrypt/")
    )
    if nested_subject_mounts:
        fail(f"sandbox contains forbidden descendant mounts under /dcrypt: {nested_subject_mounts}")
    if len(mount_rows.get("/dcrypt", [])) != 1:
        fail("sandbox must contain exactly one /dcrypt mount")
    dcrypt_mount = mount_rows["/dcrypt"][0]
    if "ro" not in dcrypt_mount["options"] or "rw" in dcrypt_mount["options"]:
        fail("sandbox /dcrypt must be an exact read-only mount")
    output_mount: dict[str, Any] | None = None
    if require_empty_output:
        if len(mount_rows.get("/output", [])) != 1:
            fail("generation sandbox must contain exactly one /output mount")
        output_mount = mount_rows["/output"][0]
        if "rw" not in output_mount["options"] or "ro" in output_mount["options"]:
            fail("generation sandbox /output must be an exact writable mount")
        if output_mount["id"] == dcrypt_mount["id"]:
            fail("generation sandbox /output must be a distinct mount from /dcrypt")
        if output_mount["device"] == dcrypt_mount["device"]:
            fail(
                "generation sandbox /output must use a different filesystem device from /dcrypt; "
                "same-device mounts permit hardlink aliases into the read-only subject"
            )
        if (
            output_mount["filesystem"] != "tmpfs"
            or output_mount["source"] != "tmpfs"
            or output_mount["root"] == "/"
        ):
            fail(
                "generation sandbox /output must be an externally persistent bind "
                "of a dedicated tmpfs subdirectory"
            )
    if require_evidence:
        nested_evidence_mounts = sorted(
            mount_point for mount_point in mount_rows if mount_point.startswith("/evidence/")
        )
        if nested_evidence_mounts:
            fail(f"sandbox contains forbidden descendant mounts under /evidence: {nested_evidence_mounts}")
        if len(mount_rows.get("/evidence", [])) != 1:
            fail("verification sandbox must contain exactly one /evidence mount")
        evidence_mount = mount_rows["/evidence"][0]
        if "ro" not in evidence_mount["options"] or "rw" in evidence_mount["options"]:
            fail("verification sandbox /evidence must be an exact read-only mount")
    if require_provision:
        provision_mount = mount_rows["/provision"][0]
        if (
            "ro" not in provision_mount["options"]
            or "rw" in provision_mount["options"]
            or provision_mount["filesystem"] != "tmpfs"
            or provision_mount["source"] != "tmpfs"
            or PurePosixPath(provision_mount["root"]).name != PROVISIONING_HANDOFF_ID
            or provision_mount["device"] == dcrypt_mount["device"]
        ):
            fail("sandbox /provision must be a read-only, subject-distinct tmpfs handoff")
    return dcrypt_mount, output_mount


def require_documented_sandbox_runtime(
    *, expected_source_date_epoch: int | None = None, require_empty_output: bool = False,
    require_evidence: bool = False, require_provision: bool = False,
) -> None:
    if os.environ.get("DCRYPT_AUDIT_SANDBOX") != "unshare-all-v1":
        fail("documented generation/replay requires the bound bubblewrap --unshare-all wrapper")
    required_environment = {
        "CARGO_HOME": "/cargo",
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "SOURCE_DATE_EPOCH": os.environ.get("SOURCE_DATE_EPOCH", ""),
        "TZ": "UTC",
        "DCRYPT_AUDIT_OPERATION": os.environ.get("DCRYPT_AUDIT_OPERATION", ""),
    }
    for key, expected in required_environment.items():
        if os.environ.get(key) != expected:
            fail(f"sandbox environment {key} must equal {expected!r}")
    source_date_epoch = required_environment["SOURCE_DATE_EPOCH"]
    if not source_date_epoch.isdigit() or str(int(source_date_epoch)) != source_date_epoch:
        fail("sandbox SOURCE_DATE_EPOCH must be a canonical non-negative integer")
    if expected_source_date_epoch is not None and int(source_date_epoch) != expected_source_date_epoch:
        fail(
            "sandbox SOURCE_DATE_EPOCH does not equal the exact subject commit timestamp: "
            f"expected {expected_source_date_epoch}, observed {source_date_epoch}"
        )
    operation = required_environment["DCRYPT_AUDIT_OPERATION"]
    contracts = {
        "selftest": (True, False, False),
        "provision": (True, False, False),
        "generation": (True, False, True),
        "verification": (False, True, True),
    }
    if operation not in contracts:
        fail("sandbox DCRYPT_AUDIT_OPERATION is not a reviewed operation contract")
    contract = contracts[operation]
    requested = (require_empty_output, require_evidence, require_provision)
    if any(requested) and requested != contract:
        fail(
            f"sandbox operation {operation} conflicts with requested mount contract: "
            f"expected={contract} requested={requested}"
        )
    require_empty_output, require_evidence, require_provision = contract
    if Path.cwd() != Path("/dcrypt"):
        fail(f"documented generation/replay must run at virtual repository root /dcrypt, found {Path.cwd()}")
    exact_environment = {
        **required_environment,
        "DCRYPT_AUDIT_SANDBOX": "unshare-all-v1",
        "PWD": "/dcrypt",
    }
    if dict(os.environ) != exact_environment:
        fail(
            "sandbox environment must equal the exact allowlist; unexpected/missing keys: "
            f"{sorted(set(os.environ) ^ set(exact_environment))}"
        )
    try:
        mount_lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        fail(f"cannot inspect sandbox mount namespace: {exc}")
    mount_rows = parse_sandbox_mountinfo("\n".join(mount_lines))
    validate_sandbox_mount_topology(
        mount_rows, require_empty_output=require_empty_output, require_evidence=require_evidence,
        require_provision=require_provision,
    )
    home_path = Path("/nonexistent")
    if home_path.exists() or home_path.is_symlink():
        fail("sandbox HOME must name an absent path")
    try:
        home_path.mkdir()
    except OSError as exc:
        if exc.errno not in {errno.EROFS, errno.EACCES, errno.EPERM}:
            fail(f"cannot prove absent HOME is non-creatable: {exc}")
    else:
        home_path.rmdir()
        fail("sandbox root permits creation of the nominally absent HOME path")
    for writable_root in (Path("/tmp"), Path("/cargo")):
        if not writable_root.is_dir() or writable_root.is_symlink():
            fail(f"sandbox writable root must be a real directory: {writable_root}")
        probe = writable_root / ".dcrypt-audit-write-probe"
        try:
            descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            probe.unlink()
        except OSError as exc:
            fail(f"sandbox writable root is not writable: {writable_root}: {exc}")
    for protected in (Path("/dcrypt/Cargo.toml"), Path("/dcrypt/.git/HEAD")):
        try:
            descriptor = os.open(protected, os.O_WRONLY | os.O_APPEND)
        except OSError as exc:
            if exc.errno not in {errno.EROFS, errno.EACCES, errno.EPERM}:
                fail(f"cannot prove read-only sandbox subject path {protected}: {exc}")
        else:
            os.close(descriptor)
            fail(f"sandbox subject path is writable: {protected}")
    if require_empty_output:
        output_root = Path("/output")
        if not output_root.is_dir() or output_root.is_symlink():
            fail("generation sandbox requires a real /output directory")
        if any(output_root.iterdir()):
            fail("generation sandbox /output must be empty before generation")
        probe = output_root / ".dcrypt-audit-write-probe"
        try:
            descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            probe.unlink()
        except OSError as exc:
            fail(f"generation sandbox /output is not writable: {exc}")
        hardlink_probe = output_root / ".dcrypt-audit-hardlink-probe"
        try:
            os.link("/dcrypt/Cargo.toml", hardlink_probe, follow_symlinks=False)
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                fail(
                    "generation sandbox cannot prove cross-device subject/output hardlink isolation: "
                    f"{exc}"
                )
        else:
            # Never write through the alias: doing so could mutate subject bytes.
            try:
                hardlink_probe.unlink()
            finally:
                fail("generation sandbox permitted a hardlink from /dcrypt into writable /output")
    if require_evidence:
        for protected in (Path("/evidence/Cargo.toml"), Path("/evidence/.git/HEAD")):
            try:
                descriptor = os.open(protected, os.O_WRONLY | os.O_APPEND)
            except OSError as exc:
                if exc.errno not in {errno.EROFS, errno.EACCES, errno.EPERM}:
                    fail(f"cannot prove read-only sandbox evidence path {protected}: {exc}")
            else:
                os.close(descriptor)
                fail(f"sandbox evidence path is writable: {protected}")
    if require_provision:
        for protected in (
            Path("/provision/PROVISIONING-MANIFEST.json"), Path("/provision/SHA256SUMS")
        ):
            try:
                descriptor = os.open(protected, os.O_WRONLY | os.O_APPEND)
            except OSError as exc:
                if exc.errno not in {errno.EROFS, errno.EACCES, errno.EPERM}:
                    fail(f"cannot prove read-only provisioning handoff path {protected}: {exc}")
            else:
                os.close(descriptor)
                fail(f"sandbox provisioning handoff path is writable: {protected}")
    old_umask = os.umask(0o022)
    os.umask(old_umask)
    if old_umask != 0o022:
        fail(f"sandbox umask must be 0022, observed {old_umask:04o}")
    try:
        network = Path("/proc/net/dev").read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        fail(f"cannot inspect sandbox network namespace: {exc}")
    interfaces = {
        line.split(":", 1)[0].strip()
        for line in network.splitlines()
        if ":" in line
    }
    if interfaces != {"lo"}:
        fail(f"sandbox network namespace exposes non-loopback interfaces: {sorted(interfaces)}")


def lexical_absolute(path: Path) -> Path:
    if any(part == ".." for part in path.parts):
        fail(f"parent traversal is forbidden in a user-supplied path: {path}")
    return Path(os.path.abspath(os.fspath(path)))


def reject_symlink_components(path: Path, *, allow_missing_tail: bool = False) -> Path:
    absolute = lexical_absolute(path)
    parts = absolute.parts
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if allow_missing_tail:
                return absolute
            fail(f"path component does not exist: {current}")
        if stat.S_ISLNK(mode):
            fail(f"symlinked path component is forbidden: {current}")
    return absolute


def open_directory_nofollow(path: Path) -> int:
    """Open an absolute directory path one component at a time without symlinks.

    The returned descriptor, rather than a later path lookup, is the authority
    for subsequent output operations.  This closes ancestor-swap races between
    a path preflight and the first descriptor-relative create.
    """

    absolute = lexical_absolute(path)
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_exact_directory_files(
    directory: Path,
    expected_files: frozenset[str],
    *,
    max_file_bytes: int = 16 * 1024 * 1024,
    max_total_bytes: int = 32 * 1024 * 1024,
) -> dict[str, bytes]:
    """Read a closed regular-file directory through held descriptors."""

    directory = reject_symlink_components(directory)
    path_status = directory.lstat()
    directory_fd = open_directory_nofollow(directory)
    descriptors: dict[str, tuple[int, os.stat_result]] = {}
    identity_fields = (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns",
    )
    try:
        opened_directory = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(opened_directory.st_mode)
            or (opened_directory.st_dev, opened_directory.st_ino)
            != (path_status.st_dev, path_status.st_ino)
            or stat.S_IMODE(opened_directory.st_mode) != 0o555
        ):
            fail("exact input directory must be the held non-writable 0555 directory inode")
        entries: dict[str, os.stat_result] = {}
        total = 0
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                name = validate_repo_path(entry.name, label="exact input filename")
                if name in entries:
                    fail(f"duplicate exact input entry: {name}")
                entry_status = entry.stat(follow_symlinks=False)
                if (
                    entry.is_symlink()
                    or not stat.S_ISREG(entry_status.st_mode)
                    or entry_status.st_nlink != 1
                    or stat.S_IMODE(entry_status.st_mode) != 0o644
                ):
                    fail(f"exact input must be a uniquely linked 0644 regular file: {name}")
                if entry_status.st_size > max_file_bytes:
                    fail(f"exact input exceeds the per-file byte limit: {name}")
                total += entry_status.st_size
                entries[name] = entry_status
        if set(entries) != set(expected_files):
            fail(
                "exact input file set mismatch: "
                f"missing={sorted(set(expected_files) - set(entries))} "
                f"unexpected={sorted(set(entries) - set(expected_files))}"
            )
        if total > max_total_bytes:
            fail("exact input exceeds the aggregate byte limit")
        contents: dict[str, bytes] = {}
        for name in sorted(entries):
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(name, flags, dir_fd=directory_fd)
            opened = os.fstat(descriptor)
            if any(
                getattr(opened, field) != getattr(entries[name], field)
                for field in identity_fields
            ):
                os.close(descriptor)
                fail(f"exact input changed between inventory and open: {name}")
            descriptors[name] = (descriptor, opened)
        for name in sorted(descriptors):
            descriptor, opened = descriptors[name]
            remaining = opened.st_size
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    fail(f"exact input was truncated while reading: {name}")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                fail(f"exact input grew while reading: {name}")
            contents[name] = b"".join(chunks)
        final_entries: dict[str, os.stat_result] = {}
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                if entry.name in final_entries:
                    fail(f"duplicate exact input entry during final inventory: {entry.name}")
                final_entries[entry.name] = entry.stat(follow_symlinks=False)
        if set(final_entries) != set(entries):
            fail("exact input inventory changed while reading")
        for name, (descriptor, opened) in descriptors.items():
            held_final = os.fstat(descriptor)
            path_final = final_entries[name]
            if any(
                getattr(held_final, field) != getattr(opened, field)
                or getattr(path_final, field) != getattr(opened, field)
                for field in identity_fields
            ):
                fail(f"exact input changed during complete read: {name}")
        comparison_fd = open_directory_nofollow(directory)
        try:
            comparison = os.fstat(comparison_fd)
            if (comparison.st_dev, comparison.st_ino) != (
                opened_directory.st_dev, opened_directory.st_ino
            ):
                fail("exact input directory path changed while reading")
        finally:
            os.close(comparison_fd)
        return contents
    except OSError as exc:
        fail(f"cannot safely read exact input directory: {exc}")
    finally:
        for descriptor, _status in descriptors.values():
            os.close(descriptor)
        os.close(directory_fd)


def repository_root(path: Path) -> Path:
    checked = reject_symlink_components(path)
    if not checked.is_dir() or not (checked / ".git").is_dir() or (checked / ".git").is_symlink():
        fail("repository argument must be the exact root with a real in-tree .git directory")
    # Inspect every byte/type/link/config source that Git could consume before
    # the first repository-aware Git invocation.  In particular, a FIFO config
    # or an external include must never be allowed to block or shape rev-parse.
    _filesystem_git_preflight(checked)
    root = _git(checked, "rev-parse", "--show-toplevel").decode().strip()
    result = reject_symlink_components(Path(root))
    if result != checked:
        fail("repository argument must be the exact repository root")
    if not (result / ".git").exists():
        fail("repository root does not contain .git")
    validate_repository_storage(result)
    return result


def _read_local_config_without_includes(config_path: Path) -> bytes:
    executable_fd = open_bound_git_executable()
    try:
        try:
            result = subprocess.run(
                [
                    f"/proc/self/fd/{executable_fd}", "config", "--file", str(config_path),
                    "--no-includes", "--null", "--list",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=closed_git_environment(),
                timeout=10,
                pass_fds=(executable_fd,),
            )
        finally:
            os.close(executable_fd)
    except subprocess.TimeoutExpired:
        fail("local Git configuration parsing exceeded the 10-second fail-closed timeout")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        fail(f"local Git configuration is malformed: {detail}")
    return result.stdout


def _validate_local_git_config(raw_config: bytes) -> None:
    exact_core_config = {
        "core.bare": "false",
        "core.filemode": "true",
        "core.logallrefupdates": "true",
        "core.repositoryformatversion": "0",
    }
    observed_core_config: dict[str, str] = {}
    seen_config: set[str] = set()
    for record in raw_config.split(b"\0"):
        if not record:
            continue
        try:
            key_bytes, value_bytes = record.split(b"\n", 1)
            key = key_bytes.decode("utf-8", "strict").lower()
            value = value_bytes.decode("utf-8", "strict")
        except (ValueError, UnicodeDecodeError) as exc:
            fail(f"local Git configuration is malformed: {exc}")
        if key in seen_config:
            fail(f"duplicate local Git configuration key is forbidden: {key}")
        seen_config.add(key)
        if key in exact_core_config:
            observed_core_config[key] = value
            continue
        allowed = (
            key in {"user.name", "user.email", "remote.origin.url", "remote.origin.fetch"}
            or (
                key.startswith("branch.")
                and (key.endswith(".remote") or key.endswith(".merge"))
            )
        )
        if not allowed or not value:
            fail(f"Git configuration shaping is forbidden: {key}")
    if observed_core_config != exact_core_config:
        fail(f"local Git core configuration must equal the reviewed safe values: {observed_core_config}")


def _filesystem_git_preflight(repo: Path) -> None:
    expected_git_dir = lexical_absolute(repo / ".git")
    if not expected_git_dir.is_dir() or expected_git_dir.is_symlink():
        fail("audit generation/replay requires a normal repository with a real in-tree .git directory")
    for indirection_name in ("commondir", "gitdir"):
        indirection = expected_git_dir / indirection_name
        try:
            indirection.lstat()
        except FileNotFoundError:
            continue
        fail(
            "Git common-dir/worktree indirection is forbidden before any repository-aware Git call: "
            f"{indirection_name}"
        )
    # Validate directory/file types before globbing, walking, or asking Git to
    # inspect any repository state.  This prevents FIFOs/devices and indirection
    # from becoming blocking or externally mutable inputs.
    critical_files = {
        "HEAD": 4 * 1024,
        "config": 1024 * 1024,
        "index": 256 * 1024 * 1024,
        "packed-refs": 16 * 1024 * 1024,
    }
    for critical in (
        expected_git_dir / "HEAD", expected_git_dir / "config", expected_git_dir / "index",
        expected_git_dir / "packed-refs", expected_git_dir / "objects", expected_git_dir / "refs",
        expected_git_dir / "info",
    ):
        try:
            critical_status = critical.lstat()
        except FileNotFoundError:
            if critical.name == "packed-refs":
                continue
            fail(f"required critical Git storage is absent: {critical.relative_to(expected_git_dir)}")
        expected_directory = critical.name in {"objects", "refs", "info"}
        if expected_directory and not stat.S_ISDIR(critical_status.st_mode):
            fail(f"critical Git storage must be a real directory: {critical.relative_to(expected_git_dir)}")
        if not expected_directory and not stat.S_ISREG(critical_status.st_mode):
            fail(f"critical Git storage must be a regular file: {critical.relative_to(expected_git_dir)}")
        if stat.S_ISREG(critical_status.st_mode) and critical_status.st_nlink != 1:
            fail(f"hardlinked critical Git storage is forbidden: {critical.relative_to(expected_git_dir)}")
        if (
            stat.S_ISREG(critical_status.st_mode)
            and critical.name in critical_files
            and critical_status.st_size > critical_files[critical.name]
        ):
            fail(
                "critical Git storage exceeds its pre-Git byte limit: "
                f"{critical.relative_to(expected_git_dir)}"
            )
    forbidden_files = (
        expected_git_dir / "shallow",
        expected_git_dir / "info" / "grafts",
        expected_git_dir / "objects" / "info" / "alternates",
        expected_git_dir / "objects" / "info" / "http-alternates",
        expected_git_dir / "info" / "sparse-checkout",
    )
    for path in forbidden_files:
        if path.exists() or path.is_symlink():
            fail(f"Git graft/shallow/alternate state is forbidden: {path.relative_to(expected_git_dir)}")
    promisor_packs = sorted((expected_git_dir / "objects" / "pack").glob("*.promisor"))
    if promisor_packs:
        fail("promisor/partial-clone packs are forbidden")
    semantic_caches = sorted(
        (
            *(expected_git_dir / "objects" / "pack").glob("*.bitmap"),
            *(expected_git_dir / "objects" / "pack").glob("*.rev"),
            *(expected_git_dir / "objects" / "pack").glob("multi-pack-index*"),
            expected_git_dir / "objects" / "info" / "commit-graph",
            expected_git_dir / "objects" / "info" / "commit-graphs",
        ),
        key=lambda item: item.as_posix(),
    )
    semantic_caches = [path for path in semantic_caches if path.exists() or path.is_symlink()]
    if semantic_caches:
        rendered = [path.relative_to(expected_git_dir).as_posix() for path in semantic_caches]
        fail(f"unbound Git semantic cache/index files are forbidden: {rendered}")
    shared_indexes = sorted(expected_git_dir.glob("sharedindex.*"))
    if shared_indexes:
        fail("split/shared Git indexes are forbidden")
    info_root = expected_git_dir / "info"
    if not info_root.is_dir() or info_root.is_symlink():
        fail(".git/info must be a real directory")
    info_entries: list[str] = []
    for walk_root, directories, filenames in os.walk(info_root, followlinks=False):
        base = Path(walk_root)
        for name in (*directories, *filenames):
            candidate = base / name
            relative = candidate.relative_to(info_root).as_posix()
            if candidate.is_symlink():
                fail(f"symlinked Git info state is forbidden: info/{relative}")
            info_entries.append(relative)
    exclude_path = info_root / "exclude"
    if sorted(info_entries) != ["exclude"] or not exclude_path.is_file():
        fail(f"Git info state must contain only the regular exclude template: {sorted(info_entries)}")
    exclude_status = exclude_path.lstat()
    if (
        not stat.S_ISREG(exclude_status.st_mode)
        or exclude_status.st_nlink != 1
        or exclude_status.st_size > 1024 * 1024
    ):
        fail("Git info/exclude must be a uniquely linked regular file within the 1 MiB pre-Git limit")
    for storage_root in (expected_git_dir / "objects", expected_git_dir / "refs", info_root):
        if not storage_root.is_dir():
            fail(f"required Git storage directory is absent: {storage_root.relative_to(expected_git_dir)}")
        for walk_root, directories, filenames in os.walk(storage_root, followlinks=False):
            base = Path(walk_root)
            for name in (*directories, *filenames):
                candidate = base / name
                candidate_mode = candidate.lstat().st_mode
                if stat.S_ISLNK(candidate_mode):
                    fail(f"symlinked Git object/ref storage is forbidden: {candidate.relative_to(expected_git_dir)}")
                if name in directories and not stat.S_ISDIR(candidate_mode):
                    fail(f"Git storage directory entry has a special type: {candidate.relative_to(expected_git_dir)}")
                if name in filenames and not stat.S_ISREG(candidate_mode):
                    fail(f"Git storage file entry has a special type: {candidate.relative_to(expected_git_dir)}")
                if stat.S_ISREG(candidate_mode) and candidate.stat().st_nlink != 1:
                    fail(
                        "hardlinked Git storage is forbidden: "
                        f"{repo}:{candidate.relative_to(expected_git_dir)}"
                    )
    config_path = expected_git_dir / "config"
    _validate_local_git_config(_read_local_config_without_includes(config_path))


def validate_repository_storage(repo: Path) -> None:
    # This filesystem-first pass is intentionally repeated when callers invoke
    # this function directly.  No repository-aware Git command may precede it.
    _filesystem_git_preflight(repo)
    expected_git_dir = lexical_absolute(repo / ".git")
    git_dir = lexical_absolute(Path(_git(repo, "rev-parse", "--absolute-git-dir").decode().strip()))
    common_dir_raw = _git(repo, "rev-parse", "--git-common-dir").decode().strip()
    common_dir = lexical_absolute(Path(common_dir_raw) if Path(common_dir_raw).is_absolute() else repo / common_dir_raw)
    if git_dir != expected_git_dir or common_dir != expected_git_dir:
        fail("external Git dir/common-dir/worktree indirection is forbidden")
    if _git(repo, "for-each-ref", "--format=%(refname)", "refs/replace").strip():
        fail("Git replace refs are forbidden")
    shallow = _git(repo, "rev-parse", "--is-shallow-repository").decode().strip()
    if shallow != "false":
        fail("shallow repositories are forbidden for audit freezes")


def parse_commit_identity(payload: bytes, *, label: str) -> tuple[str, tuple[str, ...], int]:
    """Extract tree, parents, and committer epoch from raw commit-object bytes."""

    header, separator, _message = payload.partition(b"\n\n")
    if not separator:
        fail(f"{label}: commit object lacks a header/message separator")
    tree_values: list[str] = []
    parents: list[str] = []
    committer_epochs: list[int] = []
    continuation = False
    for raw_line in header.splitlines():
        if raw_line.startswith(b" "):
            if not continuation:
                fail(f"{label}: malformed commit header continuation")
            continue
        continuation = True
        if raw_line.startswith(b"tree "):
            try:
                value = raw_line[5:].decode("ascii")
            except UnicodeDecodeError:
                fail(f"{label}: non-ASCII tree identity")
            tree_values.append(value)
        elif raw_line.startswith(b"parent "):
            try:
                value = raw_line[7:].decode("ascii")
            except UnicodeDecodeError:
                fail(f"{label}: non-ASCII parent identity")
            parents.append(value)
        elif raw_line.startswith(b"committer "):
            fields = raw_line.rsplit(b" ", 2)
            if len(fields) != 3:
                fail(f"{label}: malformed committer header")
            try:
                epoch = fields[-2].decode("ascii")
                zone = fields[-1].decode("ascii")
            except UnicodeDecodeError:
                fail(f"{label}: non-ASCII committer timestamp")
            if not epoch.isdigit() or re.fullmatch(r"[+-][0-9]{4}", zone) is None:
                fail(f"{label}: malformed committer timestamp")
            committer_epochs.append(int(epoch))
    if len(tree_values) != 1 or not HEX40.fullmatch(tree_values[0]):
        fail(f"{label}: commit must contain exactly one 40-hex tree header")
    if any(HEX40.fullmatch(parent) is None for parent in parents) or len(parents) != len(set(parents)):
        fail(f"{label}: commit contains an invalid or duplicate parent header")
    if len(committer_epochs) != 1:
        fail(f"{label}: commit must contain exactly one committer header")
    return tree_values[0], tuple(parents), committer_epochs[0]


def validate_exact_subject(repo: Path, subject: str) -> tuple[str, str]:
    if not HEX40.fullmatch(subject):
        fail("--subject must be a lowercase full 40-hex commit ID")
    if _git(repo, "cat-file", "-t", subject).decode().strip() != "commit":
        fail("--subject does not identify an exact commit object")
    tree, _parents, _epoch = parse_commit_identity(
        _git(repo, "cat-file", "commit", subject), label="subject"
    )
    return subject, tree


def exact_subject_timestamp(repo: Path, subject: str) -> int:
    _tree, _parents, timestamp = parse_commit_identity(
        _git(repo, "cat-file", "commit", subject), label="subject"
    )
    return timestamp


def validate_repo_path(path: str, *, label: str = "path") -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in path) or "\\" in path:
        fail(f"{label}: invalid repository path {path!r}")
    pure = PurePosixPath(path)
    if not path or pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        fail(f"{label}: path escapes repository or is non-canonical: {path!r}")
    normalized = unicodedata.normalize("NFC", path)
    if normalized != path:
        fail(f"{label}: path is not NFC-normalized: {path!r}")
    return path


def list_subject_tree(repo: Path, subject: str) -> list[dict[str, str]]:
    raw = _git(repo, "ls-tree", "-r", "-z", subject)
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            header, path_bytes = item.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ", 2)
            path = path_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            fail(f"malformed Git tree entry: {exc}")
        validate_repo_path(path, label="Git tree path")
        if path in seen:
            fail(f"duplicate Git tree path: {path}")
        seen.add(path)
        if kind != "blob" or mode not in ("100644", "100755"):
            fail(f"unsupported symlink, submodule, or special entry: {mode} {kind} {path}")
        if not HEX40.fullmatch(oid):
            fail(f"unexpected Git object ID for {path}")
        entries.append({"mode": mode, "oid": oid, "path": path})
    return sorted(entries, key=lambda row: row["path"])


def _retain_subject_bytes(path: str) -> bool:
    return (
        path.startswith("assurance/")
        or path.startswith(".github/workflows/")
        or path.startswith("tools/")
        or path == ".cargo/config"
        or path == ".cargo/config.toml"
        or path.endswith("/.cargo/config")
        or path.endswith("/.cargo/config.toml")
        or path == "Cargo.toml"
        or path.endswith("/Cargo.toml")
        or path == "Cargo.lock"
        or path.endswith("/Cargo.lock")
        or path in ("implementation-boundary.toml", "rust-toolchain", "rust-toolchain.toml")
        or path in (
            "CHANGELOG.md", "CONSTANT_TIME_POLICY.md", "RELEASE_NOTES.md",
            "SECURITY.md", "VERSION_STRATEGY.md", "deny.toml",
        )
    )


def subject_files(
    repo: Path, subject: str
) -> tuple[list[dict[str, Any]], dict[str, bytes], set[str]]:
    """Hash the full subject tree one bounded Git blob at a time.

    Non-control blobs are discarded immediately after hashing.  A 64 MiB
    per-blob ceiling bounds the implementation's actual in-memory read; this
    function intentionally makes no streaming claim.
    """

    entries = list_subject_tree(repo, subject)
    by_oid: dict[str, list[dict[str, str]]] = {}
    for row in entries:
        by_oid.setdefault(row["oid"], []).append(row)
    check_input = b"".join((oid + "\n").encode("ascii") for oid in sorted(by_oid))
    checked = _git(
        repo,
        "cat-file",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        input_data=check_input,
    )
    checked_sizes: dict[str, int] = {}
    for line in checked.decode("ascii", "strict").splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[1] != "blob" or not HEX40.fullmatch(fields[0]) or not fields[2].isdigit():
            fail(f"malformed Git blob size preflight row: {line!r}")
        size = int(fields[2])
        if size > 64 * 1024 * 1024:
            fail(f"Git blob {fields[0]} exceeds the reviewed 64 MiB per-object resource limit")
        checked_sizes[fields[0]] = size
    if set(checked_sizes) != set(by_oid):
        fail("Git blob size preflight inventory differs from subject tree")
    if sum(checked_sizes.values()) > 1024 * 1024 * 1024:
        fail("unique subject Git blob bytes exceed the reviewed 1 GiB aggregate limit")
    git_descriptor = open_bound_git_executable()
    try:
        process = subprocess.Popen(
            [f"/proc/self/fd/{git_descriptor}", "-C", str(repo), "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=closed_git_environment(),
            pass_fds=(git_descriptor,),
        )
    except OSError as exc:
        fail(f"cannot start bound git cat-file process: {exc}")
    finally:
        os.close(git_descriptor)
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        fail("bound git cat-file process lacks required pipes")
    metadata: dict[str, tuple[int, str]] = {}
    retained: dict[str, bytes] = {}
    deadline = time.monotonic() + 30.0
    stdout_buffer = bytearray()

    def remaining_time() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("bound git cat-file process exceeded its 30-second deadline")
        return remaining

    def read_more() -> None:
        ready, _, _ = select.select([process.stdout.fileno()], [], [], remaining_time())
        if not ready:
            fail("bound git cat-file process made no progress before its deadline")
        chunk = os.read(process.stdout.fileno(), 64 * 1024)
        if not chunk:
            fail("bound git cat-file process ended before completing its response")
        stdout_buffer.extend(chunk)

    def read_line() -> bytes:
        while b"\n" not in stdout_buffer:
            read_more()
        end = stdout_buffer.index(0x0A)
        line = bytes(stdout_buffer[:end])
        del stdout_buffer[: end + 1]
        return line

    def read_exact(count: int) -> bytes:
        while len(stdout_buffer) < count:
            read_more()
        data = bytes(stdout_buffer[:count])
        del stdout_buffer[:count]
        return data

    try:
        for oid in sorted(by_oid):
            try:
                process.stdin.write((oid + "\n").encode("ascii"))
                process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                fail(f"bound git cat-file request failed for {oid}: {exc}")
            header = read_line().decode("ascii", "strict").split()
            if len(header) != 3 or header[0] != oid or header[1] != "blob":
                fail(f"unexpected git cat-file response for {oid}: {' '.join(header)}")
            size = int(header[2])
            if size != checked_sizes[oid]:
                fail(f"Git blob {oid} size changed after resource preflight")
            data = read_exact(size)
            if read_exact(1) != b"\n":
                fail(f"truncated git cat-file response for {oid}")
            metadata[oid] = (size, sha256(data))
            for row in by_oid[oid]:
                if _retain_subject_bytes(row["path"]):
                    retained[row["path"]] = data
        process.stdin.close()
        try:
            code = process.wait(timeout=remaining_time())
        except subprocess.TimeoutExpired:
            fail("bound git cat-file process exceeded its 30-second deadline")
        if code != 0:
            fail(f"git cat-file --batch failed: {process.stderr.read().decode('utf-8', 'replace')}")
    finally:
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    manifest = []
    for row in entries:
        size, digest = metadata[row["oid"]]
        manifest.append(
            {
                "git_blob_oid": row["oid"],
                "mode": row["mode"],
                "path": row["path"],
                "sha256": digest,
                "size": size,
            }
        )
    return manifest, retained, {row["path"] for row in entries}


def parse_toml(files: dict[str, bytes], path: str) -> dict[str, Any]:
    validate_repo_path(path)
    if path not in files:
        fail(f"required subject input is missing: {path}")
    try:
        value = tomllib.loads(files[path].decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        fail(f"{path}: invalid TOML: {exc}")
    if not isinstance(value, dict):
        fail(f"{path}: TOML root must be a table")
    return value


def validate_bound_control_bytes(files: dict[str, bytes]) -> None:
    for path, expected in EXPECTED_BOUND_CONTROL_SHA256.items():
        if path not in files:
            fail(f"required versioned control is missing: {path}")
        actual = sha256(files[path])
        if actual != expected:
            fail(f"versioned control digest differs for {path}: expected {expected}, got {actual}")


def require_keys(value: dict[str, Any], keys: Iterable[str], *, label: str) -> None:
    missing = sorted(set(keys) - set(value))
    if missing:
        fail(f"{label}: missing required keys: {', '.join(missing)}")


def parse_bound_date(value: Any, *, label: str) -> dt.date:
    if isinstance(value, dt.datetime):
        fail(f"{label}: datetime is forbidden; an ISO calendar date is required")
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            pass
    fail(f"{label}: invalid ISO calendar date")


def toml_json_value(value: Any) -> Any:
    """Convert TOML's date values to canonical JSON strings without loss."""

    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: toml_json_value(child) for key, child in value.items()}
    if isinstance(value, list):
        return [toml_json_value(child) for child in value]
    return value


def validate_policy(policy: dict[str, Any]) -> None:
    expected_top_keys = {
            "schema-version", "freeze-id", "classification", "content-policy",
            "freeze-date", "valid-through", "release-subject", "commissioning-worktree",
            "canonical-json", "environment", "cargo-workspace", "required-artifact",
            "limitation", "expected-public-api-units", "expected-atomic-operations",
            "expected-ledger-evidence-records", "expected-action-occurrences",
            "expected-unique-actions", "expected-runner-occurrences",
    }
    require_keys(policy, expected_top_keys, label="freeze policy")
    if set(policy) != expected_top_keys:
        fail(f"freeze policy has unexpected top-level keys: {sorted(set(policy) - expected_top_keys)}")
    if policy["schema-version"] != 1 or policy["content-policy"] != CONTENT_POLICY:
        fail("unsupported freeze policy schema/content policy")
    if policy["freeze-id"] != PRODUCTION_FREEZE_ID:
        fail(f"freeze policy identifier must be {PRODUCTION_FREEZE_ID}")
    if policy["classification"] != "candidate-rehearsal":
        fail("only candidate-rehearsal freezes are supported by this commission")
    if policy["freeze-date"] != "2026-08-11" or policy["valid-through"] != "2026-09-10":
        fail("candidate freeze dates differ from the reviewed commission")
    for key, expected in EXPECTED_COUNTS.items():
        if policy[key] != expected:
            fail(f"freeze policy {key} must remain exactly {expected}")
    if policy["release-subject"] != EXPECTED_RELEASE_SUBJECT:
        fail("historical v3.0.0 release-subject identity drift")
    commissioning = policy["commissioning-worktree"]
    expected_commissioning = {
        "permitted-path": ".gitignore",
        "file-sha256": "e4887e3f444e25b7baad39bd6ff3da3ae770f8dc5b3f7cf2c87a117219a8fe2c",
        "binary-diff-sha256": "caa005fda38ed3a65d8b92a5b788169ebba47e7106c1389bf4cd7bff980c6552",
        "generation-checkout": "clean",
        "replay-checkout": "clean",
        "reason": (
            "Initial uncommitted .gitignore working-tree delta observation only; the delta never enters "
            "clean generation or replay, while the committed .gitignore blob remains a bound audit-subject "
            "source input."
        ),
    }
    if commissioning != expected_commissioning:
        fail("commissioning worktree exclusion identity drift")
    for key in ("freeze-date", "valid-through"):
        try:
            dt.date.fromisoformat(policy[key])
        except (TypeError, ValueError):
            fail(f"freeze policy {key} must be an ISO date")
    limitations = policy["limitation"]
    if not isinstance(limitations, list) or not limitations:
        fail("freeze policy must contain limitations")
    ids: set[str] = set()
    for row in limitations:
        require_keys(row, ("id", "class", "owner", "deadline", "release-blocking", "reason"), label="limitation")
        if set(row) != {"id", "class", "owner", "deadline", "release-blocking", "reason"}:
            fail(f"limitation {row.get('id')} has unexpected fields")
        if row["id"] in ids:
            fail(f"duplicate limitation id: {row['id']}")
        ids.add(row["id"])
        if not row["owner"] or not row["reason"] or row["release-blocking"] is not True:
            fail(f"limitation {row['id']} must have an owner, reason, and remain release-blocking")
        if EXPECTED_LIMITATION_METADATA.get(row["id"]) != (row["class"], row["owner"], row["deadline"]):
            fail(f"limitation classification/owner/deadline drift: {row['id']}")
        try:
            dt.date.fromisoformat(row["deadline"])
        except (TypeError, ValueError):
            fail(f"limitation {row['id']} has an invalid deadline")
    if ids != EXPECTED_LIMITATIONS:
        fail(f"limitation inventory drift: missing={sorted(EXPECTED_LIMITATIONS - ids)} unexpected={sorted(ids - EXPECTED_LIMITATIONS)}")
    artifacts = policy["required-artifact"]
    artifact_ids: set[str] = set()
    for row in artifacts:
        require_keys(row, ("id", "class", "status", "limitation"), label="required artifact")
        permitted_artifact_keys = {"id", "class", "status", "limitation"}
        if row["id"] in {"candidate-crate-archives", "published-v3-registry-archives"}:
            permitted_artifact_keys.add("expected-members")
        if set(row) != permitted_artifact_keys:
            fail(f"required artifact {row.get('id')} has unexpected fields")
        if row["id"] in artifact_ids:
            fail(f"duplicate required artifact id: {row['id']}")
        artifact_ids.add(row["id"])
        if row["status"] != "blocked" or row["limitation"] not in ids:
            fail(f"required artifact {row['id']} must map to a known blocker")
        if EXPECTED_ARTIFACTS.get(row["id"]) != (row["class"], row["limitation"]):
            fail(f"required artifact classification drift: {row['id']}")
        if row["id"] in {"candidate-crate-archives", "published-v3-registry-archives"}:
            if tuple(row["expected-members"]) != EXPECTED_CRATE_ARCHIVES:
                fail(f"required artifact expected twelve-crate member inventory drift: {row['id']}")
    if artifact_ids != set(EXPECTED_ARTIFACTS):
        fail(f"required artifact inventory drift: missing={sorted(set(EXPECTED_ARTIFACTS) - artifact_ids)} unexpected={sorted(artifact_ids - set(EXPECTED_ARTIFACTS))}")
    configured_workspaces: dict[str, tuple[Any, ...]] = {}
    for row in policy["cargo-workspace"]:
        require_keys(row, ("id", "manifest", "lockfile", "classification", "lock-required", "status"), label="cargo workspace")
        allowed_workspace_keys = {"id", "manifest", "lockfile", "classification", "lock-required", "status", "limitation"}
        if not set(row).issubset(allowed_workspace_keys):
            fail(f"cargo workspace {row.get('id')} has unexpected fields")
        if row["manifest"] in configured_workspaces:
            fail(f"duplicate configured workspace: {row['manifest']}")
        configured_workspaces[row["manifest"]] = (
            row["id"], row["lockfile"], row["classification"], row["lock-required"],
            row["status"], row.get("limitation"),
        )
    if configured_workspaces != EXPECTED_WORKSPACES:
        fail("Cargo workspace classifications/status/lock policies differ from the reviewed candidate policy")
    canonical = policy["canonical-json"]
    expected_canonical = {
        "encoding": "UTF-8", "normalization": "NFC", "key-order": "Unicode code-point ascending",
        "separators": "comma-and-colon-without-whitespace", "final-newline": True,
        "floats": "forbidden", "duplicate-keys": "forbidden",
    }
    if canonical != expected_canonical:
        fail("canonical JSON policy drift")
    expected_environment = {
        "network-during-generation": "forbidden",
        "network-during-replay": "forbidden",
        "ambient-cargo-config": "forbidden",
        "ambient-cache": "forbidden",
        "umask": "0022",
        "timezone": "UTC",
        "locale": "C.UTF-8",
        "source-date-epoch": "subject-commit-timestamp",
        "virtual-repository-root": "/dcrypt",
        "virtual-output-root": "/output",
        "virtual-cargo-home": "/cargo",
        "required": ["CARGO_INCREMENTAL=0", "CARGO_NET_OFFLINE=true", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"],
        "forbidden-exact": [
            "AR", "CC", "CFLAGS", "CXX", "CXXFLAGS", "LD", "LDFLAGS",
            "RUSTC", "RUSTDOC", "RUSTFLAGS", "RUSTDOCFLAGS",
            "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTDOC", "CARGO_BUILD_TARGET",
            "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTDOCFLAGS",
            "CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS",
        ],
        "forbidden-prefixes": ["CARGO_TARGET_", "PKG_CONFIG_"],
    }
    if policy["environment"] != expected_environment:
        fail("build-shaping environment/no-network policy drift")


def validate_provisioning(provisioning: dict[str, Any]) -> None:
    expected_top_keys = {
            "schema-version", "status", "limitation", "network-boundary",
            "cargo-package-source", "provisioning-procedure", "acquisition-tool", "toolchain", "github-action", "host-tool",
            "security-tool", "advisory-database", "runner-image", "container-image",
    }
    require_keys(provisioning, expected_top_keys, label="provisioning policy")
    if set(provisioning) != expected_top_keys:
        fail(f"provisioning policy has unexpected top-level keys: {sorted(set(provisioning) - expected_top_keys)}")
    if provisioning["schema-version"] != 1 or provisioning["status"] != "blocked":
        fail("provisioning policy must remain schema v1 and blocked")
    if provisioning["limitation"] != "dependency-provision-bundle-unavailable":
        fail("provisioning blocker identity drift")
    if provisioning["network-boundary"] != "Only an explicit provisioning phase may use the network; generation and replay must be network-disabled.":
        fail("provisioning network-boundary policy drift")
    if provisioning["cargo-package-source"] != "registry+https://github.com/rust-lang/crates.io-index":
        fail("Cargo registry source policy drift")
    if provisioning["provisioning-procedure"] != {
        "id": "dcrypt-audit-provisioning-v1",
        "status": "observed-structural-handoff-executable-full-provisioning-blocked",
        "authorization": "local-observed-handoff-authorized-network-acquisition-separate",
        "staging-root": "/provision",
        "manifest": "/provision/PROVISIONING-MANIFEST.json",
        "checksums": "/provision/SHA256SUMS",
        "network-cutoff": "unshare-all-loopback-only-for-handoff-generation-and-replay",
        "cold-cache-policy": "empty-host-caches-only-use-bound-provisioning-tree",
        "offline-replay-status": "source-structural-executable-live-cargo-and-build-blocked",
        "registry-archive-materialization": "not-executed-blocked",
        "vendor-tree-materialization": "not-executed-blocked",
        "action-archive-materialization": "not-executed-blocked",
        "toolchain-distribution-acquisition": "not-executed-blocked",
        "manifest-and-checksum-generation": "observed-structural-only-executable-full-bundle-blocked",
        "clean-host-transfer-and-offline-replay": "source-structural-executable-cold-cache-build-blocked",
        "limitation": "dependency-provision-bundle-unavailable",
    }:
        fail("pinned provisioning procedure contract drift")
    for kind in ("acquisition-tool", "toolchain", "github-action", "host-tool", "security-tool", "advisory-database", "runner-image", "container-image"):
        rows = provisioning[kind]
        if not isinstance(rows, list) or not rows:
            fail(f"provisioning policy {kind} must be a non-empty array")
        ids: set[str] = set()
        for row in rows:
            if not isinstance(row, dict) or not row.get("id") or row["id"] in ids:
                fail(f"provisioning policy {kind} has a missing or duplicate id")
            ids.add(row["id"])
            if "availability" not in row or "limitation" not in row:
                fail(f"provisioning policy {kind}/{row['id']} lacks availability or limitation")
            if row["limitation"] not in EXPECTED_LIMITATIONS:
                fail(f"provisioning policy {kind}/{row['id']} maps to an unknown limitation")
    expected_row_keys = {
        "acquisition-tool": {"id", "path", "binary-sha256", "availability", "limitation"},
        "toolchain": {"id", "requested", "rustc-commit", "cargo-commit", "rustdoc-commit", "llvm", "host", "targets", "availability", "limitation"},
        "github-action": {"id", "repository", "commit", "source-archive-sha256", "availability", "limitation"},
        "host-tool": {"id", "identity", "path", "binary-sha256", "availability", "limitation"},
        "security-tool": {"id", "version", "binary-sha256", "availability", "limitation"},
        "advisory-database": {"id", "commit", "archive-sha256", "availability", "limitation"},
        "runner-image": {"id", "requested", "manifest-digest", "platform-digest", "availability", "limitation"},
        "container-image": {"id", "requested", "manifest-digest", "platform-digest", "availability", "limitation"},
    }
    for kind, keys in expected_row_keys.items():
        for row in provisioning[kind]:
            if set(row) != keys:
                fail(f"provisioning policy {kind}/{row.get('id')} field set drift")
    acquisition_tools = {
        row["id"]: (row["path"], row["binary-sha256"], row["availability"], row["limitation"])
        for row in provisioning["acquisition-tool"]
    }
    if acquisition_tools != EXPECTED_ACQUISITION_TOOLS:
        fail("acquisition-tool blocker inventory drift")
    toolchains = {
        row["id"]: (
            row["requested"], row["rustc-commit"], row["cargo-commit"],
            row["rustdoc-commit"], row["llvm"], row["host"], tuple(row["targets"]),
            row["availability"], row["limitation"],
        )
        for row in provisioning["toolchain"]
    }
    if toolchains != EXPECTED_TOOLCHAINS:
        fail("toolchain row-by-row identity/status/limitation drift")
    actions = {
        row["id"]: (
            row["repository"], row["commit"], row["source-archive-sha256"],
            row["availability"], row["limitation"],
        )
        for row in provisioning["github-action"]
    }
    if actions != EXPECTED_GITHUB_ACTIONS:
        fail("GitHub Action row-by-row identity/status/limitation drift")
    host_tools = {
        row["id"]: (
            row["identity"], row["path"], row["binary-sha256"], row["availability"], row["limitation"]
        )
        for row in provisioning["host-tool"]
    }
    if host_tools != EXPECTED_HOST_TOOLS:
        fail("host-tool inventory or exact locally observed identity drift")
    security_tools = {
        row["id"]: (
            row["version"], row["binary-sha256"], row["availability"], row["limitation"]
        )
        for row in provisioning["security-tool"]
    }
    if security_tools != EXPECTED_SECURITY_TOOLS:
        fail("security-tool row-by-row identity/status/limitation drift")
    advisory_databases = {
        row["id"]: (
            row["commit"], row["archive-sha256"], row["availability"], row["limitation"]
        )
        for row in provisioning["advisory-database"]
    }
    if advisory_databases != EXPECTED_ADVISORY_DATABASES:
        fail("advisory-database row-by-row identity/status/limitation drift")
    runner_images = {
        row["id"]: (
            row["requested"], row["manifest-digest"], row["platform-digest"],
            row["availability"], row["limitation"],
        )
        for row in provisioning["runner-image"]
    }
    if runner_images != EXPECTED_RUNNER_IMAGES:
        fail("runner-image row-by-row identity/status/limitation drift")
    container_images = {
        row["id"]: (
            row["requested"], row["manifest-digest"], row["platform-digest"],
            row["availability"], row["limitation"],
        )
        for row in provisioning["container-image"]
    }
    if container_images != EXPECTED_CONTAINER_IMAGES:
        fail("container-image row-by-row identity/status/limitation drift")


def require_clean_checkout(repo: Path, subject: str, *, label: str = "subject") -> bytes:
    """Require the exact commit and no modified, untracked, or ignored paths."""

    current_head = _git(repo, "rev-parse", "HEAD").decode().strip()
    if current_head != subject:
        fail(f"{label} checkout HEAD {current_head} does not equal subject {subject}")
    status = _git(
        repo,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
    )
    if status:
        records = [item for item in status.split(b"\0") if item]
        rendered = b" | ".join(records[:20]).decode("utf-8", "backslashreplace")
        fail(f"{label} checkout is not strictly clean (modified/untracked/ignored): {rendered}")
    for option, forbidden in (("-v", lambda tag: tag.islower()), ("-t", lambda tag: tag == "S")):
        records = [item for item in _git(repo, "ls-files", option, "-z").split(b"\0") if item]
        for record in records:
            if len(record) < 3 or record[1:2] != b" ":
                fail(f"{label} checkout has malformed index inventory")
            tag = chr(record[0])
            if forbidden(tag):
                fail(f"{label} checkout uses assume-unchanged or skip-worktree index flags")
    return status


def source_manifest_document(
    repo: Path, subject: str, tree: str, entries: list[dict[str, Any]], policy: dict[str, Any]
) -> dict[str, Any]:
    commit_payload = _git(repo, "cat-file", "commit", subject)
    tree_payload = _git(repo, "cat-file", "tree", tree)
    freeze_root = f"assurance/audit/freezes/{policy['freeze-id']}"
    if any(
        row["path"] == freeze_root or row["path"].startswith(f"{freeze_root}/")
        for row in entries
    ):
        fail(f"subject contains its own freeze output path: {freeze_root}")
    gitignore_rows = [row for row in entries if row["path"] == ".gitignore"]
    if len(gitignore_rows) != 1 or gitignore_rows[0]["mode"] != "100644":
        fail("subject must bind exactly one regular committed .gitignore blob")
    gitignore_blob = _git(repo, "cat-file", "blob", gitignore_rows[0]["git_blob_oid"])
    return {
        "schema_version": 1,
        "subject": {
            "commit": subject,
            "commit_cat_file_payload_sha256": sha256(commit_payload),
            "tree": tree,
            "tree_cat_file_payload_sha256": sha256(tree_payload),
        },
        "entry_policy": "regular tracked blobs only; symlinks, submodules, and special modes rejected",
        "committed_gitignore_binding": {
            **gitignore_rows[0],
            "sha256": sha256(gitignore_blob),
            "size": len(gitignore_blob),
            "commissioning_dirty_delta_is_context_only": True,
        },
        "files": entries,
    }


def release_subject_document(repo: Path, policy: dict[str, Any]) -> dict[str, Any]:
    release = policy["release-subject"]
    tag_ref = _git(repo, "show-ref", "--verify", "--hash", f"refs/tags/{release['tag']}").decode().strip()
    if tag_ref != release["tag-object"]:
        fail("historical release tag ref does not identify the reviewed annotated tag object")
    if _git(repo, "cat-file", "-t", release["tag-object"]).decode().strip() != "tag":
        fail("historical release tag object is missing or not annotated")
    tag_payload = _git(repo, "cat-file", "tag", release["tag-object"])
    tag_header = tag_payload.split(b"\n\n", 1)[0].decode("utf-8", "strict").splitlines()
    expected_header = [f"object {release['commit']}", "type commit", f"tag {release['tag']}"]
    if tag_header[:3] != expected_header:
        fail("historical annotated tag target/type/name relationship drift")
    peeled = release["commit"]
    if _git(repo, "cat-file", "-t", release["commit"]).decode().strip() != "commit":
        fail("historical release commit object is missing or wrong type")
    commit_payload = _git(repo, "cat-file", "commit", release["commit"])
    commit_tree, _release_parents, _release_timestamp = parse_commit_identity(
        commit_payload, label="historical release commit"
    )
    if commit_tree != release["tree"]:
        fail("historical release commit does not identify the reviewed tree")
    if _git(repo, "cat-file", "-t", release["tree"]).decode().strip() != "tree":
        fail("historical release tree object is missing or wrong type")
    tree_payload = _git(repo, "cat-file", "tree", release["tree"])
    reachable = _git(
        repo, "-c", "pack.useBitmaps=false", "-c", "core.commitGraph=false",
        "rev-list", "--objects", "--missing=print", release["tree"],
    ).decode("utf-8", "strict").splitlines()
    missing = [line for line in reachable if line.startswith("?")]
    if missing:
        fail(f"historical release tree has missing descendant objects: {missing[:5]}")
    if not reachable or reachable[0].split(" ", 1)[0] != release["tree"]:
        fail("historical release tree connectivity traversal is incomplete")
    payload_hashes = {
        "tag": sha256(tag_payload),
        "commit": sha256(commit_payload),
        "tree": sha256(tree_payload),
    }
    if payload_hashes != EXPECTED_RELEASE_PAYLOAD_SHA256:
        fail("historical release tag/commit/tree payload digest drift")
    return {
        **release,
        "tag_payload_sha256": payload_hashes["tag"],
        "commit_payload_sha256": payload_hashes["commit"],
        "tree_payload_sha256": payload_hashes["tree"],
        "tag_peels_to_commit": peeled,
        "commit_tree": commit_tree,
        "reachable_tree_object_records": len(reachable),
        "object_replacement_policy": "GIT_NO_REPLACE_OBJECTS=1; replace/graft/alternate/promisor state rejected",
    }


def _resolve_manifest_dependency(manifest: str, dependency_path: str) -> str:
    if not isinstance(dependency_path, str) or not dependency_path or "\\" in dependency_path:
        fail(f"{manifest}: invalid path dependency {dependency_path!r}")
    dependency = PurePosixPath(dependency_path)
    if dependency.is_absolute():
        fail(f"{manifest}: absolute path dependency is forbidden: {dependency_path}")
    parts = list(PurePosixPath(manifest).parent.parts)
    if parts == ["."]:
        parts = []
    for part in dependency.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                fail(f"{manifest}: path dependency escapes repository: {dependency_path}")
            parts.pop()
        else:
            parts.append(part)
    return "/".join((*parts, "Cargo.toml"))


def _cargo_simple_requirement_matches(requirement: str | None, version: str) -> bool:
    """Evaluate the exact simple requirement grammar used by the frozen manifests."""

    if requirement is None:
        return True
    exact = requirement.startswith("=")
    raw = requirement[1:] if exact else requirement
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", raw) is None:
        fail(f"unsupported Cargo version requirement in reviewed manifest: {requirement!r}")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", version) is None:
        fail(f"unsupported locked semantic version: {version!r}")
    required_parts = tuple(int(part) for part in raw.split("."))
    locked = tuple(int(part) for part in version.split("-", 1)[0].split("+", 1)[0].split("."))
    if exact:
        return len(required_parts) == 3 and locked == required_parts
    lower = required_parts + (0,) * (3 - len(required_parts))
    major, minor, patch = lower
    if len(required_parts) == 1:
        upper = (major + 1, 0, 0)
    elif major > 0:
        upper = (major + 1, 0, 0)
    elif minor > 0:
        upper = (0, minor + 1, 0)
    else:
        upper = (0, 0, patch + 1)
    return lower <= locked < upper


def workspace_document(
    files: dict[str, bytes], all_paths: set[str], policy: dict[str, Any], provisioning: dict[str, Any]
) -> dict[str, Any]:
    configured = policy["cargo-workspace"]
    configured_by_manifest = {row["manifest"]: row for row in configured}
    if len(configured_by_manifest) != len(configured):
        fail("duplicate cargo workspace manifest in policy")
    manifests = sorted(path for path in files if path == "Cargo.toml" or path.endswith("/Cargo.toml"))
    expected_manifest_set = {
        "Cargo.toml", *(f"{member}/Cargo.toml" for member in EXPECTED_ROOT_MEMBERS),
        "verification/Cargo.toml", "fuzz/Cargo.toml",
        "migration/legacy-xchacha20poly1305/Cargo.toml", "tools/bench-processor/Cargo.toml",
    }
    if set(manifests) != expected_manifest_set or len(manifests) != 17:
        fail(f"tracked Cargo.toml inventory drift: {manifests}")
    cargo_config_paths = sorted(
        path for path in all_paths
        if path in {".cargo/config", ".cargo/config.toml"}
        or path.endswith("/.cargo/config")
        or path.endswith("/.cargo/config.toml")
    )
    if cargo_config_paths:
        fail(f"tracked Cargo configuration/source replacement is forbidden: {cargo_config_paths}")
    root_manifest = parse_toml(files, "Cargo.toml")
    root_workspace = root_manifest.get("workspace", {})
    if set(root_workspace) != {"members", "exclude", "resolver", "package", "dependencies", "metadata", "lints"}:
        fail("published-root workspace key set/default-members policy drift")
    if tuple(root_workspace.get("members", [])) != EXPECTED_ROOT_MEMBERS:
        fail("published-root workspace member inventory/order drift")
    if tuple(root_workspace.get("exclude", [])) != EXPECTED_ROOT_EXCLUDES:
        fail("published-root workspace exclusion inventory/order drift")
    if root_workspace.get("resolver") != "2" or "default-members" in root_workspace:
        fail("published-root workspace resolver/default-members policy drift")
    if root_workspace.get("package", {}).get("version") != "3.0.0":
        fail("published-root workspace version must remain 3.0.0")
    manifest_owners = {"Cargo.toml": "published-root"}
    manifest_owners.update({f"{member}/Cargo.toml": "published-root" for member in EXPECTED_ROOT_MEMBERS})
    manifest_owners.update(
        {
            "verification/Cargo.toml": "verification",
            "fuzz/Cargo.toml": "fuzz",
            "migration/legacy-xchacha20poly1305/Cargo.toml": "legacy-xchacha-migration",
            "tools/bench-processor/Cargo.toml": "bench-processor",
        }
    )
    manifest_inventory: list[dict[str, Any]] = []
    published_names: set[str] = set()
    for manifest_path in manifests:
        manifest_toml = parse_toml(files, manifest_path)
        if "patch" in manifest_toml or "replace" in manifest_toml:
            fail(f"{manifest_path}: [patch]/[replace] dependency reshaping is forbidden")
        package = manifest_toml.get("package")
        package_name = package.get("name") if isinstance(package, dict) else None
        package_version: Any = package.get("version") if isinstance(package, dict) else None
        if isinstance(package_version, dict) and package_version == {"workspace": True}:
            package_version = root_workspace["package"]["version"]
        raw_publish = package.get("publish") if isinstance(package, dict) else None
        if raw_publish is not EXPECTED_MANIFEST_PUBLISH_VALUES[manifest_path]:
            fail(f"manifest raw publish policy drift: {manifest_path}")
        publishable = raw_publish is not False
        if (package_name, package_version, publishable) != EXPECTED_MANIFEST_IDENTITIES[manifest_path]:
            fail(f"manifest path/package/version/publish identity drift: {manifest_path}")
        if manifest_owners[manifest_path] != "published-root" and publishable:
            fail(f"isolated/tool manifest must explicitly set publish = false: {manifest_path}")
        if manifest_path != "Cargo.toml" and isinstance(package, dict) and "workspace" in package:
            fail(f"package may not redirect workspace ownership: {manifest_path}")
        if manifest_path != "Cargo.toml" and manifest_owners[manifest_path] == "published-root":
            if "workspace" in manifest_toml:
                fail(f"published member may not establish a nested workspace: {manifest_path}")
        if manifest_owners[manifest_path] == "published-root" and publishable:
            if package_version != "3.0.0" or not isinstance(package_name, str):
                fail(f"published package name/version drift: {manifest_path}")
            published_names.add(package_name)
        manifest_inventory.append(
            {
                "owner": manifest_owners[manifest_path],
                "package": package_name,
                "path": manifest_path,
                "publishable": publishable,
                "sha256": sha256(files[manifest_path]),
                "version": package_version if isinstance(package_version, str) else None,
            }
        )
    if published_names != EXPECTED_PUBLISHED_PACKAGES:
        fail(f"published twelve-package inventory drift: {sorted(published_names)}")
    manifest_identities = {
        row["path"]: (row["package"], row["version"])
        for row in manifest_inventory
        if row["package"] is not None and row["version"] is not None
    }
    for isolated_path, label in (
        ("verification/Cargo.toml", "verification"),
        ("migration/legacy-xchacha20poly1305/Cargo.toml", "migration"),
    ):
        isolated_workspace = parse_toml(files, isolated_path).get("workspace")
        if isolated_workspace != {"members": ["."], "resolver": "2"}:
            fail(f"{label} workspace must contain exactly itself with resolver 2 and no excludes/default-members")
    bench_manifest = parse_toml(files, "tools/bench-processor/Cargo.toml")
    if "workspace" not in bench_manifest or bench_manifest["workspace"] != {}:
        fail("bench-processor must remain an explicit empty single-package workspace")
    if "workspace" in parse_toml(files, "fuzz/Cargo.toml"):
        fail("fuzz must remain a root-excluded single-package workspace without alternate members")
    locks = sorted(path for path in files if path == "Cargo.lock" or path.endswith("/Cargo.lock"))
    expected_tracked_locks = {
        "Cargo.lock", "verification/Cargo.lock", "fuzz/Cargo.lock",
        "migration/legacy-xchacha20poly1305/Cargo.lock",
    }
    if set(locks) != expected_tracked_locks:
        fail(f"tracked Cargo.lock inventory drift: {locks}")
    discovered: set[str] = {
        manifest for manifest, owner in manifest_owners.items()
        if manifest == "Cargo.toml" or owner != "published-root"
    }
    expected = set(configured_by_manifest)
    if discovered != expected:
        fail(
            "unclassified Cargo root(s): "
            f"missing_from_policy={sorted(discovered - expected)} "
            f"missing_from_subject={sorted(expected - discovered)}"
        )
    permitted_source = provisioning["cargo-package-source"]
    workspaces: list[dict[str, Any]] = []
    aggregate: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for manifest_path in sorted(expected):
        row = configured_by_manifest[manifest_path]
        require_keys(row, ("id", "manifest", "lockfile", "classification", "lock-required", "status"), label="cargo workspace")
        lock_path = row["lockfile"]
        manifest_data = files[manifest_path]
        owned_manifest_paths = sorted(path for path, owner in manifest_owners.items() if owner == row["id"])
        expected_lock_identities = EXPECTED_SOURCELESS_BY_LOCK.get(lock_path, set())
        semantic_manifest_paths = sorted(
            path for path, identity in manifest_identities.items()
            if identity in expected_lock_identities
        ) if expected_lock_identities else owned_manifest_paths
        declared_dependencies: dict[str, Any] = {}
        direct_requirements: list[dict[str, Any]] = []
        for owned_path in semantic_manifest_paths:
            manifest_toml = parse_toml(files, owned_path)
            dependency_tables = {
                key: manifest_toml.get(key, {})
                for key in ("dependencies", "dev-dependencies", "build-dependencies")
            }
            dependency_tables["workspace.dependencies"] = manifest_toml.get("workspace", {}).get("dependencies", {})
            target_dependencies: dict[str, Any] = {}
            for target_name, target_table in sorted(manifest_toml.get("target", {}).items()):
                if not isinstance(target_table, dict):
                    fail(f"{owned_path}: target dependency table {target_name} is invalid")
                target_dependencies[target_name] = {
                    key: target_table.get(key, {})
                    for key in ("dependencies", "dev-dependencies", "build-dependencies")
                }
            dependency_tables["target"] = target_dependencies
            declared_dependencies[owned_path] = dependency_tables
            for table_name, table in dependency_tables.items():
                if table_name == "target":
                    nested_tables = [
                        (nested_name, nested)
                        for target in table.values()
                        for nested_name, nested in target.items()
                    ]
                else:
                    nested_tables = [(table_name, table)]
                for dependency_kind, dependency_table in nested_tables:
                    if not isinstance(dependency_table, dict):
                        fail(f"{owned_path}: dependency table {table_name} is invalid")
                    for dependency_name, specification in dependency_table.items():
                        if not isinstance(specification, (str, dict)):
                            fail(f"{owned_path}: dependency {dependency_name} has an invalid specification")
                        resolved_specification: str | dict[str, Any] = specification
                        if isinstance(specification, dict) and "workspace" in specification:
                            if specification.get("workspace") is not True:
                                fail(f"{owned_path}: dependency {dependency_name} has invalid workspace inheritance")
                            inherited = root_workspace["dependencies"].get(dependency_name)
                            if inherited is None:
                                fail(f"{owned_path}: dependency {dependency_name} inherits an undeclared workspace dependency")
                            if isinstance(inherited, str):
                                resolved_specification = {"version": inherited}
                            elif isinstance(inherited, dict):
                                resolved_specification = dict(inherited)
                            else:
                                fail(f"{owned_path}: inherited dependency {dependency_name} has an invalid specification")
                            resolved_specification.update(
                                {key: value for key, value in specification.items() if key != "workspace"}
                            )
                        if isinstance(resolved_specification, dict):
                            if any(key in resolved_specification for key in ("git", "registry", "branch", "tag", "rev")):
                                fail(f"{owned_path}: dependency {dependency_name} uses an unbound Git/registry source")
                            supported_specification_keys = {
                                "default-features", "features", "optional", "package", "path", "version"
                            }
                            if not set(resolved_specification).issubset(supported_specification_keys):
                                fail(
                                    f"{owned_path}: dependency {dependency_name} uses unsupported specification keys"
                                )
                            declared_name = resolved_specification.get("package", dependency_name)
                            version_requirement = resolved_specification.get("version")
                            if not isinstance(declared_name, str) or not declared_name:
                                fail(f"{owned_path}: dependency {dependency_name} has an invalid package identity")
                            if version_requirement is not None and not isinstance(version_requirement, str):
                                fail(f"{owned_path}: dependency {dependency_name} has an invalid version requirement")
                            expected_source: str | None = permitted_source
                            exact_version = (
                                version_requirement[1:]
                                if isinstance(version_requirement, str) and version_requirement.startswith("=")
                                else None
                            )
                            if "path" in resolved_specification:
                                if not isinstance(resolved_specification["path"], str):
                                    fail(f"{owned_path}: dependency {dependency_name} has a non-string path")
                                target_manifest = _resolve_manifest_dependency(
                                    owned_path, resolved_specification["path"]
                                )
                                if target_manifest not in expected_manifest_set:
                                    fail(
                                        f"{owned_path}: path dependency {dependency_name} resolves to unbound "
                                        f"manifest {target_manifest}"
                                    )
                                target_name, target_version = manifest_identities[target_manifest]
                                if declared_name != target_name:
                                    fail(
                                        f"{owned_path}: path dependency alias/package {dependency_name} "
                                        f"does not name target package {target_name}"
                                    )
                                if version_requirement != f"={target_version}":
                                    fail(
                                        f"{owned_path}: path dependency {dependency_name} must pin exact "
                                        f"target version ={target_version}"
                                    )
                                expected_source = None
                                exact_version = target_version
                            elif not isinstance(version_requirement, str) or not version_requirement:
                                fail(
                                    f"{owned_path}: registry dependency {dependency_name} requires a supported version"
                                )
                            optional = resolved_specification.get("optional", False) is True
                        else:
                            declared_name = dependency_name
                            version_requirement = resolved_specification
                            expected_source = permitted_source
                            exact_version = (
                                version_requirement[1:] if version_requirement.startswith("=") else None
                            )
                            optional = False
                        if (
                            table_name != "workspace.dependencies"
                            and not (
                                dependency_kind == "dev-dependencies"
                                and owned_path not in owned_manifest_paths
                            )
                        ):
                            direct_requirements.append(
                                {
                                    "alias": dependency_name,
                                    "declaring_manifest": owned_path,
                                    "exact_version": exact_version,
                                    "version_requirement": version_requirement,
                                    "package": declared_name,
                                    "optional": optional,
                                    "source": expected_source,
                                }
                            )
        lock_present = lock_path in files
        if row["lock-required"] and not lock_present:
            fail(f"required lockfile is missing: {lock_path}")
        packages: list[dict[str, Any]] = []
        package_keys: set[tuple[str, str, str | None]] = set()
        if lock_present:
            lock = parse_toml(files, lock_path)
            if set(lock) != {"version", "package"}:
                fail(f"{lock_path}: unexpected Cargo.lock top-level fields")
            if lock.get("version") not in (3, 4):
                fail(f"{lock_path}: unsupported Cargo.lock format")
            for package in lock.get("package", []):
                require_keys(package, ("name", "version"), label=f"{lock_path} package")
                source = package.get("source")
                checksum = package.get("checksum", "")
                if source is not None:
                    if not set(package).issubset(
                        {"name", "version", "source", "checksum", "dependencies"}
                    ):
                        fail(f"{lock_path}: registry lock row has unexpected fields")
                    if source != permitted_source:
                        fail(f"{lock_path}: unapproved dependency source {source!r}")
                    if not isinstance(checksum, str) or not HEX64.fullmatch(checksum):
                        fail(f"{lock_path}: registry package lacks an exact SHA-256 checksum")
                elif set(package) not in (
                    {"name", "version"}, {"name", "version", "dependencies"}
                ):
                    fail(f"{lock_path}: source-less lock row may not contain source/checksum/extra fields")
                dependencies = package.get("dependencies", [])
                if not isinstance(dependencies, list) or not all(isinstance(item, str) for item in dependencies):
                    fail(f"{lock_path}: invalid dependency list")
                if len(dependencies) != len(set(dependencies)):
                    fail(f"{lock_path}: duplicate locked dependency edge for {package['name']}")
                item = {
                    "checksum": checksum or None,
                    "dependencies": sorted(dependencies),
                    "name": package["name"],
                    "source": source,
                    "version": package["version"],
                }
                packages.append(item)
                key = (item["name"], item["version"], source)
                if key in package_keys:
                    fail(f"{lock_path}: duplicate locked package {key}")
                package_keys.add(key)
                previous = aggregate.get(key)
                if previous and previous["checksum"] != item["checksum"]:
                    fail(f"conflicting checksums for locked package {key}")
                aggregate.setdefault(
                    key,
                    {
                        "checksum": item["checksum"],
                        "name": item["name"],
                        "source": source,
                        "version": item["version"],
                        "workspaces": [],
                    },
                )["workspaces"].append(row["id"])
            sourceless = {
                (item["name"], item["version"])
                for item in packages if item["source"] is None
            }
            if sourceless != EXPECTED_SOURCELESS_BY_LOCK[lock_path]:
                fail(
                    f"{lock_path}: source-less workspace/path package inventory drift: "
                    f"{sorted(sourceless)}"
                )
            mapped_source_less = {manifest_identities[path] for path in semantic_manifest_paths}
            if mapped_source_less != sourceless or len(semantic_manifest_paths) != len(sourceless):
                fail(f"{lock_path}: every source-less lock node must map to one tracked manifest")
            package_by_key = {
                (item["name"], item["version"], item["source"]): item for item in packages
            }
            adjacency: dict[tuple[str, str, str | None], list[tuple[str, str, str | None]]] = {}
            for item in packages:
                item_key = (item["name"], item["version"], item["source"])
                edges: list[tuple[str, str, str | None]] = []
                for dependency in item["dependencies"]:
                    fields = dependency.split(" ", 2)
                    referenced_name = fields[0]
                    candidates = [candidate for candidate in packages if candidate["name"] == referenced_name]
                    if len(fields) >= 2:
                        candidates = [candidate for candidate in candidates if candidate["version"] == fields[1]]
                    if len(fields) == 3:
                        source_field = fields[2]
                        if not (source_field.startswith("(") and source_field.endswith(")")):
                            fail(f"{lock_path}: malformed locked dependency reference {dependency!r}")
                        candidates = [candidate for candidate in candidates if candidate["source"] == source_field[1:-1]]
                    if len(candidates) != 1:
                        fail(
                            f"{lock_path}: locked dependency edge from {item['name']} has "
                            f"missing or ambiguous identity {dependency!r}"
                        )
                    candidate = candidates[0]
                    edges.append((candidate["name"], candidate["version"], candidate["source"]))
                if len(edges) != len(set(edges)):
                    fail(
                        f"{lock_path}: distinct dependency strings for {item['name']} "
                        "resolve to the same locked dependency identity"
                    )
                if item["source"] is not None and any(edge[2] is None for edge in edges):
                    fail(
                        f"{lock_path}: registry package {item['name']} has an impossible "
                        "reverse dependency on a source-less workspace/path package"
                    )
                adjacency[item_key] = edges
            root_keys: list[tuple[str, str, str | None]] = []
            for owned_path in owned_manifest_paths:
                package_name, package_version = manifest_identities[owned_path]
                root_key = (package_name, package_version, None)
                if root_key not in package_by_key:
                    fail(f"{lock_path}: workspace package is absent from lock graph: {owned_path}")
                root_keys.append(root_key)
            expected_direct_edges: dict[
                tuple[str, str, str | None], set[tuple[str, str, str | None]]
            ] = {
                (*manifest_identities[path], None): set() for path in semantic_manifest_paths
            }
            for requirement in direct_requirements:
                owner_name, owner_version = manifest_identities[requirement["declaring_manifest"]]
                owner_key = (owner_name, owner_version, None)
                candidates = [
                    dependency_key for dependency_key in adjacency[owner_key]
                    if dependency_key[0] == requirement["package"]
                    and dependency_key[2] == requirement["source"]
                    and _cargo_simple_requirement_matches(
                        requirement["version_requirement"], dependency_key[1]
                    )
                ]
                if len(candidates) != 1:
                    fail(
                        f"{lock_path}: manifest dependency edge {requirement['declaring_manifest']}/"
                        f"{requirement['alias']} is absent or ambiguous in the lock graph"
                    )
                expected_direct_edges[owner_key].add(candidates[0])
            for owner_key, expected_edges in expected_direct_edges.items():
                if set(adjacency[owner_key]) != expected_edges:
                    fail(
                        f"{lock_path}: lock edges for workspace package {owner_key[0]} do not "
                        "exactly match declared manifest dependencies"
                    )
            reachable: set[tuple[str, str, str | None]] = set()
            pending = list(root_keys)
            while pending:
                key = pending.pop()
                if key in reachable:
                    continue
                reachable.add(key)
                pending.extend(adjacency[key])
            if reachable != set(package_by_key):
                orphaned = sorted(
                    (name, version, source or "source-less")
                    for name, version, source in set(package_by_key) - reachable
                )
                fail(f"{lock_path}: orphan/unreachable locked packages: {orphaned[:20]}")
            visiting: set[tuple[str, str, str | None]] = set()
            visited: set[tuple[str, str, str | None]] = set()

            def visit(key: tuple[str, str, str | None]) -> None:
                if key in visiting:
                    fail(f"{lock_path}: dependency cycle includes {key[0]} {key[1]}")
                if key in visited:
                    return
                visiting.add(key)
                for dependency_key in adjacency[key]:
                    visit(dependency_key)
                visiting.remove(key)
                visited.add(key)

            for root_key in root_keys:
                visit(root_key)
            packages.sort(key=lambda item: (item["name"], item["version"], item["source"] or ""))
        workspaces.append(
            {
                "classification": row["classification"],
                "declared_dependencies": declared_dependencies,
                "id": row["id"],
                "limitation": row.get("limitation"),
                "lock_required": row["lock-required"],
                "lockfile": lock_path,
                "lockfile_present": lock_present,
                "lockfile_sha256": sha256(files[lock_path]) if lock_present else None,
                "manifest": manifest_path,
                "member_manifests": owned_manifest_paths,
                "semantically_reconciled_manifests": semantic_manifest_paths,
                "manifest_sha256": sha256(manifest_data),
                "package_count": len(packages),
                "packages": packages,
                "status": row["status"],
            }
        )
    aggregate_rows = []
    for key in sorted(aggregate, key=lambda item: (item[0], item[1], item[2] or "")):
        item = aggregate[key]
        item["workspaces"] = sorted(set(item["workspaces"]))
        aggregate_rows.append(item)
    registry_package_count = sum(1 for row in aggregate_rows if row["source"] == permitted_source)
    if len(aggregate_rows) != 239 or registry_package_count != 223:
        fail(
            "locked dependency baseline drift: expected 239 unique locked package identities "
            "including 223 registry packages"
        )
    observed_cargo_sha256 = {
        path: sha256(files[path]) for path in sorted(EXPECTED_CARGO_INPUT_SHA256)
    }
    if observed_cargo_sha256 != EXPECTED_CARGO_INPUT_SHA256:
        changed = sorted(
            path for path, expected_sha256 in EXPECTED_CARGO_INPUT_SHA256.items()
            if observed_cargo_sha256.get(path) != expected_sha256
        )
        fail(f"reviewed Cargo manifest/lock byte baseline differs: {changed}")
    return {
        "schema_version": 1,
        "discovery_policy": "Cargo.toml with [workspace] or a sibling tracked Cargo.lock",
        "workspace_count": len(workspaces),
        "tracked_manifest_count": len(manifest_inventory),
        "manifest_inventory": manifest_inventory,
        "published_package_names": sorted(published_names),
        "workspaces": workspaces,
        "unique_locked_package_count": len(aggregate_rows),
        "unique_registry_package_count": registry_package_count,
        "registry_transitive_edge_evidence": "structurally-lock-bound-not-source-archive-reconciled",
        "unique_locked_packages": aggregate_rows,
        "reviewed_cargo_input_sha256": observed_cargo_sha256,
        "provisioned_package_archives": [],
        "provisioning_status": "blocked",
    }


def workflow_document(files: dict[str, bytes], policy: dict[str, Any], provisioning: dict[str, Any]) -> dict[str, Any]:
    workflow_paths = sorted(path for path in files if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")))
    if workflow_paths != [".github/workflows/security-validation.yml"]:
        fail(f"GitHub workflow inventory drift: {workflow_paths}")
    configured_actions = {row["repository"]: row for row in provisioning["github-action"]}
    actions: list[dict[str, Any]] = []
    runners: list[dict[str, Any]] = []
    toolchain_requests: list[dict[str, Any]] = []
    for path in workflow_paths:
        try:
            lines = files[path].decode("utf-8").splitlines()
        except UnicodeDecodeError:
            fail(f"workflow is not UTF-8: {path}")
        for number, line in enumerate(lines, 1):
            match = USES_LINE.match(line)
            if match:
                value = match.group(1)
                if value.startswith("./"):
                    actions.append({"kind": "local", "line": number, "path": path, "value": value})
                else:
                    remote = REMOTE_ACTION.fullmatch(value)
                    if not remote:
                        fail(f"{path}:{number}: unclassified action use {value!r}")
                    repository, ref = remote.group("repository"), remote.group("ref")
                    if not HEX40.fullmatch(ref):
                        fail(f"{path}:{number}: action is not pinned to a full commit: {value}")
                    locked = configured_actions.get(repository)
                    if not locked or locked["commit"] != ref:
                        fail(f"{path}:{number}: action is absent from or disagrees with provisioning policy")
                    actions.append(
                        {
                            "archive_sha256": None,
                            "line": number,
                            "path": path,
                            "ref": ref,
                            "repository": repository,
                            "source_status": locked["availability"],
                        }
                    )
            match = RUNNER_LINE.match(line)
            if match:
                runners.append({"line": number, "path": path, "requested": match.group(1)})
            match = TOOLCHAIN_LINE.match(line)
            if match:
                toolchain_requests.append({"line": number, "path": path, "requested": match.group(1)})
    remote_repositories = sorted({row["repository"] for row in actions if row.get("repository")})
    if len(actions) != policy["expected-action-occurrences"]:
        fail(f"workflow action occurrence drift: {len(actions)} != {policy['expected-action-occurrences']}")
    if len(remote_repositories) != policy["expected-unique-actions"]:
        fail(f"workflow unique action drift: {len(remote_repositories)} != {policy['expected-unique-actions']}")
    if len(runners) != policy["expected-runner-occurrences"]:
        fail(f"workflow runner occurrence drift: {len(runners)} != {policy['expected-runner-occurrences']}")
    configured_runner_names = {row["requested"] for row in provisioning["runner-image"]}
    for row in runners:
        if row["requested"] not in configured_runner_names:
            fail(f"unclassified workflow runner: {row['requested']}")
    requested_toolchain_counts: dict[str, int] = {}
    for row in toolchain_requests:
        requested_toolchain_counts[row["requested"]] = requested_toolchain_counts.get(row["requested"], 0) + 1
    if requested_toolchain_counts != {"nightly-2026-08-07": 4, "stable": 7}:
        fail(f"workflow Rust toolchain request drift: {requested_toolchain_counts}")
    return {
        "schema_version": 1,
        "workflow_files": [{"path": path, "sha256": sha256(files[path])} for path in workflow_paths],
        "actions": actions,
        "action_occurrences": len(actions),
        "unique_remote_actions": remote_repositories,
        "runners": runners,
        "runner_occurrences": len(runners),
        "toolchain_requests": toolchain_requests,
        "action_source_archives": [],
        "runner_image_manifests": [],
    }


def validate_provisioning_subject_inputs(files: dict[str, bytes]) -> None:
    missing = sorted(set(PROVISIONING_SUBJECT_INPUT_PATHS) - set(files))
    if missing:
        fail(f"provisioning handoff subject inputs are missing: {missing}")
    unexpected_root_toolchain = sorted(set(ROOT_TOOLCHAIN_CONFIGURATION_PATHS) & set(files))
    if unexpected_root_toolchain:
        fail(
            "root toolchain configuration appeared without a reviewed provisioning-policy update: "
            f"{unexpected_root_toolchain}"
        )


def toolchain_document(files: dict[str, bytes], provisioning: dict[str, Any]) -> dict[str, Any]:
    validate_provisioning_subject_inputs(files)
    bound_paths = sorted(
        {
            "Cargo.toml", "implementation-boundary.toml", *TOOLCHAIN_SELECTION_INPUT_PATHS,
        }
    )
    return {
        "schema_version": 1,
        "bound_configuration": [{"path": path, "sha256": sha256(files[path])} for path in bound_paths],
        "root_toolchain_configuration": {
            "paths": [],
            "status": "absent-current-subject-workflow-ledger-policy-authoritative",
        },
        "toolchain_selection_inputs": [
            {"path": path, "sha256": sha256(files[path])}
            for path in TOOLCHAIN_SELECTION_INPUT_PATHS
        ],
        "acquisition_tools": sorted(provisioning["acquisition-tool"], key=lambda row: row["id"]),
        "toolchains": sorted(provisioning["toolchain"], key=lambda row: row["id"]),
        "host_tools": sorted(provisioning["host-tool"], key=lambda row: row["id"]),
        "security_tools": sorted(provisioning["security-tool"], key=lambda row: row["id"]),
        "advisory_databases": sorted(provisioning["advisory-database"], key=lambda row: row["id"]),
        "distribution_bytes_status": "blocked",
    }


def environment_document(repo: Path, subject: str, policy: dict[str, Any], provisioning: dict[str, Any]) -> dict[str, Any]:
    timestamp = str(exact_subject_timestamp(repo, subject))
    environment = policy["environment"]
    return {
        "schema_version": 1,
        "subject_commit_timestamp": int(timestamp),
        "source_date_epoch": int(timestamp),
        "generation_policy": environment,
        "provisioning_network_boundary": provisioning["network-boundary"],
        "provisioning_procedure": provisioning["provisioning-procedure"],
        "runner_images": sorted(provisioning["runner-image"], key=lambda row: row["id"]),
        "container_images": sorted(provisioning["container-image"], key=lambda row: row["id"]),
        "observed_host_tools": observed_host_tools(provisioning),
        "python_execution": {
            "argv_prefix": ["/usr/bin/python3.12", "-I", "-B", "-S"],
            "isolated": True,
            "bytecode_writes": "forbidden",
            "ambient_python_environment": "cleared by documented bubblewrap replay wrapper",
        },
        "structural_replay_sandbox": {
            "classification": "structured-mount-contract-not-complete-host-argv",
            "required_umask": "0022",
            "fixed_argv_without_role_sources": [
                "/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session",
                "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib",
                "--ro-bind", "/lib64", "/lib64", "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
                "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/cargo",
                "--remount-ro", "/",
                "--clearenv", "--setenv", "DCRYPT_AUDIT_SANDBOX", "unshare-all-v1",
                "--setenv", "DCRYPT_AUDIT_OPERATION", "verification",
                "--setenv", "CARGO_HOME", "/cargo", "--setenv", "CARGO_INCREMENTAL", "0",
                "--setenv", "CARGO_NET_OFFLINE", "true", "--setenv", "HOME", "/nonexistent",
                "--setenv", "LANG", "C.UTF-8", "--setenv", "LC_ALL", "C.UTF-8",
                "--setenv", "SOURCE_DATE_EPOCH", str(timestamp), "--setenv", "TZ", "UTC",
                "--chdir", "/dcrypt",
            ],
            "mount_roles": [
                {
                    "destination": "/evidence", "mode": "read-only",
                    "source_role": "separate-strictly-clean-evidence-checkout",
                },
                {
                    "destination": "/dcrypt", "mode": "read-only",
                    "source_role": "separate-strictly-clean-subject-checkout",
                },
                {
                    "destination": "/provision", "mode": "read-only",
                    "source_role": "verified-dcrypt-audit-provisioning-v1-tmpfs-directory",
                },
            ],
            "host_argv_status": "requires-reviewer-supplied-absolute-role-sources",
            "network_namespace": "unshare-all-required-for-documented-replay",
            "read_only_host_runtime_mounts": ["/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache"],
            "status": "locally-observed-unprovisioned",
            "limitation": "sandbox-kernel-assumptions-unbound",
        },
        "initial_commissioning_worktree_policy_record": policy["commissioning-worktree"],
        "runtime_environment_bytes_status": "blocked",
    }


def provisioning_manifest_document(
    repo: Path,
    subject: str,
    tree: str,
    files: dict[str, bytes],
    policy: dict[str, Any],
    provisioning: dict[str, Any],
) -> dict[str, Any]:
    """Describe the executable, networkless observed structural handoff.

    This deliberately materializes no dependency, toolchain distribution,
    action, runner/container, registry archive, vendor tree, or build output.
    Those byte classes remain typed blockers in the same manifest.
    """

    validate_provisioning_subject_inputs(files)
    limitation_rows = {row["id"]: row for row in policy["limitation"]}
    blocked_specs = (
        ("dependency-registry-archives", "dependency-provision-bundle-unavailable"),
        ("cargo-vendor-tree", "dependency-provision-bundle-unavailable"),
        ("github-action-source-archives", "action-source-archives-unavailable"),
        ("rust-toolchain-distributions", "toolchain-distribution-bundle-unavailable"),
        ("security-tool-binaries", "toolchain-distribution-bundle-unavailable"),
        ("rustsec-advisory-database", "rustsec-database-unbound"),
        ("runner-image", "runner-image-identity-unavailable"),
        ("container-image", "container-image-unavailable"),
        ("live-cargo-ledger-validation", "dependency-provision-bundle-unavailable"),
        ("cold-cache-artifact-rebuild", "dependency-provision-bundle-unavailable"),
    )
    blocked_operations = []
    for identifier, limitation_id in blocked_specs:
        limitation = limitation_rows[limitation_id]
        blocked_operations.append(
            {
                "deadline": str(limitation["deadline"]),
                "id": identifier,
                "limitation": limitation_id,
                "owner": limitation["owner"],
                "status": "blocked-not-materialized",
            }
        )
    timestamp = exact_subject_timestamp(repo, subject)
    sandbox_environment = {
        "CARGO_HOME": "/cargo",
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "DCRYPT_AUDIT_SANDBOX": "unshare-all-v1",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PWD": "/dcrypt",
        "SOURCE_DATE_EPOCH": str(timestamp),
        "TZ": "UTC",
    }
    commands = [
        {
            "argv": [
                "/usr/bin/git", "-c", "pack.writeReverseIndex=false", "clone", "--no-local",
                "--no-hardlinks", "--no-checkout", "/source", "/checkout",
            ],
            "id": "prepare-no-hardlink-checkout",
            "network": "forbidden-file-transport-only",
            "operation": "checkout-preparation",
            "status": "required-external-preparation",
        },
        {
            "argv": [
                "/usr/bin/git", "-C", "/checkout", "checkout", "--detach", subject,
            ],
            "id": "select-exact-subject",
            "network": "forbidden",
            "operation": "checkout-preparation",
            "status": "required-external-preparation",
        },
        {
            "argv": [
                "/usr/bin/python3.12", "-I", "-B", "-S",
                "/dcrypt/assurance/generate-audit-freeze.py", "--materialize-provisioning",
                "--repo", "/dcrypt", "--subject", subject, "--output",
                f"/output/{PROVISIONING_HANDOFF_ID}",
            ],
            "id": "materialize-observed-structural-handoff",
            "network": "forbidden-unshare-all",
            "operation": "provision",
            "status": "first-party-executable",
        },
        {
            "argv": [
                "/usr/bin/python3.12", "-I", "-B", "-S",
                "/dcrypt/assurance/generate-audit-freeze.py", "--repo", "/dcrypt",
                "--subject", subject, "--provision", "/provision", "--output",
                f"/output/{PRODUCTION_FREEZE_ID}",
            ],
            "id": "generate-candidate-from-read-only-handoff",
            "network": "forbidden-unshare-all",
            "operation": "generation",
            "status": "first-party-executable",
        },
        {
            "argv": [
                "/usr/bin/python3.12", "-I", "-B", "-S",
                "/dcrypt/assurance/verify-audit-freeze.py", "--repo", "/evidence",
                "--subject-repo", "/dcrypt", "--provision", "/provision", "--bundle",
                f"/evidence/assurance/audit/freezes/{PRODUCTION_FREEZE_ID}", "--mode", "structural",
            ],
            "id": "offline-two-checkout-structural-replay",
            "network": "forbidden-unshare-all",
            "operation": "verification",
            "status": "first-party-executable-after-evidence-commit",
        },
    ]
    return {
        "schema_version": 1,
        "id": PROVISIONING_HANDOFF_ID,
        "classification": "observed-structural-inputs-only",
        "status": "first-party-materializable-release-blocked",
        "subject": {"commit": subject, "tree": tree, "commit_timestamp": timestamp},
        "layout": {
            "checksums": "/provision/SHA256SUMS",
            "directory_mode": "0555",
            "manifest": "/provision/PROVISIONING-MANIFEST.json",
            "payload_root": "/provision/payload",
            "payload_status": "absent-blocked",
            "regular_file_mode": "0644",
            "root": "/provision",
        },
        "checksum_policy": {
            "algorithm": "SHA-256",
            "manifest_hashes": ["PROVISIONING-MANIFEST.json"],
            "self_reference": "forbidden",
        },
        "network": {
            "acquisition_authorized": False,
            "materialization_used_network": False,
            "offline_replay_required": True,
            "required_interfaces": ["lo"],
            "marker": "network-disabled-observed-loopback-only",
        },
        "checkout_environment": closed_git_environment(),
        "checkout_umask": "0022",
        "sandbox_environment": sandbox_environment,
        "commands": commands,
        "toolchain_selection": {
            "root_configuration_files": [],
            "root_configuration_status": "absent-current-subject",
            "selection_inputs": [
                {"path": path, "sha256": sha256(files[path]), "size": len(files[path])}
                for path in TOOLCHAIN_SELECTION_INPUT_PATHS
            ],
            "distribution_status": "blocked-not-materialized",
        },
        "subject_inputs": [
            {"path": path, "sha256": sha256(files[path]), "size": len(files[path])}
            for path in PROVISIONING_SUBJECT_INPUT_PATHS
        ],
        "observed_host_tools": observed_host_tools(provisioning),
        "provisioning_policy_binding": {
            "path": "assurance/audit/provisioning-lock.toml",
            "sha256": sha256(files["assurance/audit/provisioning-lock.toml"]),
            "status": provisioning["status"],
            "limitation": provisioning["limitation"],
        },
        "workspace_locks": [
            {"path": path, "sha256": sha256(files[path]), "status": "bytes-bound-no-archives"}
            for path in (
                "Cargo.lock", "fuzz/Cargo.lock",
                "migration/legacy-xchacha20poly1305/Cargo.lock", "verification/Cargo.lock",
            )
        ],
        "materialized_payloads": [],
        "blocked_operations": blocked_operations,
        "claim": (
            "This handoff binds locally observed structural runtime and subject inputs only; "
            "it is not a dependency bundle, cold-cache replay, artifact rebuild, or reproducible-build claim."
        ),
    }


def provisioning_handoff_bytes(
    repo: Path,
    subject: str,
    tree: str,
    files: dict[str, bytes],
    policy: dict[str, Any],
    provisioning: dict[str, Any],
    provisioning_schema: dict[str, Any],
) -> dict[str, bytes]:
    manifest = provisioning_manifest_document(repo, subject, tree, files, policy, provisioning)
    try:
        manifest_schema = provisioning_schema["$defs"]["provisioningManifest"]
    except (KeyError, TypeError):
        fail("provisioning schema lacks the closed provisioningManifest definition")
    validate_json_schema(manifest, manifest_schema, label="PROVISIONING-MANIFEST.json")
    manifest_bytes = canonical_json(manifest)
    return {
        "PROVISIONING-MANIFEST.json": manifest_bytes,
        "SHA256SUMS": (
            f"{sha256(manifest_bytes)}  PROVISIONING-MANIFEST.json\n"
        ).encode("ascii"),
    }


def validate_provisioning_handoff_contents(
    contents: dict[str, bytes], expected: dict[str, bytes]
) -> None:
    if set(contents) != set(PROVISIONING_HANDOFF_FILES):
        fail("provisioning handoff file set drift")
    if contents != expected:
        changed = sorted(name for name in expected if contents.get(name) != expected[name])
        fail(f"provisioning handoff differs from exact regenerated bytes: {changed}")
    checksum = contents["SHA256SUMS"]
    expected_checksum = (
        f"{sha256(contents['PROVISIONING-MANIFEST.json'])}  PROVISIONING-MANIFEST.json\n"
    ).encode("ascii")
    if checksum != expected_checksum:
        fail("provisioning handoff SHA256SUMS is noncanonical or mismatched")


def assurance_document(files: dict[str, bytes], all_paths: set[str], policy: dict[str, Any]) -> dict[str, Any]:
    required = (
        "assurance/ledger.toml",
        "assurance/atomic-operations.toml",
        "assurance/curated-operations.toml",
        "assurance/public-api-snapshot.json",
        "assurance/SUPPORTED-ALGORITHMS.md",
        "assurance/subject-manifest.json",
        "assurance/acvp-vector-manifest.json",
        "assurance/assurance-selftest.py",
        "assurance/audit/freeze-policy.toml",
        "assurance/audit/README.md",
        "assurance/audit/provisioning-lock.toml",
        "assurance/audit/audit-freeze.schema.json",
        "assurance/audit/freeze-envelope.schema.json",
        "assurance/audit/provisioning.schema.json",
        "assurance/audit/historical-advisory-regressions.toml",
        "assurance/audit-freeze-selftest.py",
        *SUBJECT_COMMAND_TARGETS,
        "implementation-boundary.toml",
        "CHANGELOG.md",
        "CONSTANT_TIME_POLICY.md",
        "RELEASE_NOTES.md",
        "SECURITY.md",
        "VERSION_STRATEGY.md",
        "deny.toml",
        "tools/release-dcrypt.sh",
        "tools/verify-publish-ready.sh",
        "tools/verify-remote-release-ready.py",
        "tools/verify-implementation-boundary.py",
        "tools/verify-implementation-boundary.sh",
        "tools/verify-bls-secret-assembly.py",
        "tools/verify-bls-secret-assembly.sh",
        "tools/verify-ghash-assembly.py",
        "tools/verify-ghash-assembly.sh",
        "tools/update-isolated-workspace-versions.py",
    )
    for path in required:
        if path not in files:
            fail(f"required assurance/audit input is missing: {path}")
    threat_paths = sorted(path for path in files if path.startswith("assurance/threat-models/") and not path.endswith("/"))
    sow_paths = sorted(path for path in files if path.startswith("assurance/audit/sow/") and not path.endswith("/"))
    if not threat_paths or not any(path.endswith(".md") for path in threat_paths) or not any(path.endswith((".toml", ".json")) for path in threat_paths):
        fail("subject lacks both machine-readable and human-readable threat-model artifacts")
    required_sow = {
        "assurance/audit/sow/RFP-SOW.md",
        "assurance/audit/sow/audit-policy.toml",
        "assurance/audit/sow/audit-scope.toml",
        "assurance/audit/sow/verify-sow.py",
    }
    if not required_sow.issubset(sow_paths):
        fail(f"subject lacks required SOW files: {sorted(required_sow - set(sow_paths))}")
    sow_bytes = files["assurance/audit/sow/RFP-SOW.md"]
    sow_text = sow_bytes.decode("utf-8", "strict")
    if re.search(r"(?im)^.*(?:manifest|freeze)[-_ ]?(?:sha|digest)[^\n]*\bPENDING\b", sow_text):
        fail("SOW contains a generated-digest PENDING placeholder; bind SOW bytes from the post-subject envelope instead")
    freeze_schema = load_json_strict(files["assurance/audit/audit-freeze.schema.json"], label="audit-freeze schema")
    envelope_schema = load_json_strict(files["assurance/audit/freeze-envelope.schema.json"], label="freeze-envelope schema")
    provisioning_schema = load_json_strict(files["assurance/audit/provisioning.schema.json"], label="provisioning schema")
    validate_schema_program(freeze_schema, label="audit-freeze schema")
    validate_schema_program(envelope_schema, label="freeze-envelope schema")
    validate_schema_program(provisioning_schema, label="provisioning schema")
    if freeze_schema.get("type") != "object" or not str(freeze_schema.get("$id", "")).endswith("audit-freeze-v1.json"):
        fail("audit-freeze schema identity/type drift")
    if provisioning_schema.get("type") != "object" or not str(provisioning_schema.get("$id", "")).endswith("audit-provisioning-v1.json"):
        fail("provisioning schema identity/type drift")
    if envelope_schema.get("type") != "object" or not str(envelope_schema.get("$id", "")).endswith("audit-freeze-envelope-v1.json"):
        fail("freeze-envelope schema identity/type drift")
    snapshot = load_json_strict(files["assurance/public-api-snapshot.json"], label="public API snapshot")
    public_count = len(snapshot.get("entries", []))
    atomic = parse_toml(files, "assurance/atomic-operations.toml")
    operations = atomic.get("operation", [])
    gaps = atomic.get("unreviewed-gap", [])
    defaults = atomic.get("unreviewed-gap-defaults", {})
    atomic_rows = [*operations, *gaps]
    ids: list[str] = []
    id_set: set[str] = set()
    for row in atomic_rows:
        identifier = row.get("id")
        if not identifier or identifier in id_set:
            fail("atomic assurance rows have a missing or duplicate id")
        ids.append(identifier)
        id_set.add(identifier)
        readiness = row.get("release-readiness", defaults.get("release-readiness"))
        if readiness != "blocked":
            fail(f"candidate freeze may not promote atomic row {identifier}: {readiness!r}")
    facade_aliases = sum(1 for row in operations if str(row.get("id", "")).startswith("alias."))
    authoritative_rows = len(operations) - facade_aliases
    if authoritative_rows != 314 or facade_aliases != 352 or len(gaps) != 8632:
        fail(
            "atomic row-kind baseline drift: expected 314 authoritative rows, "
            "352 facade aliases, and 8,632 explicit gaps"
        )
    ledger = parse_toml(files, "assurance/ledger.toml")
    evidence_rows = ledger.get("evidence", [])
    evidence_count = len(evidence_rows)
    ledger_freshness: list[dict[str, Any]] = []
    ledger_evidence_ids: set[str] = set()
    for row in evidence_rows:
        if not isinstance(row, dict):
            fail("ledger evidence row must be a table")
        require_keys(
            row,
            ("id", "required", "owner", "reviewer", "reviewed-at", "valid-through", "verdict"),
            label="ledger evidence",
        )
        identifier = row["id"]
        if not isinstance(identifier, str) or not identifier or identifier in ledger_evidence_ids:
            fail("ledger evidence has a missing or duplicate id")
        ledger_evidence_ids.add(identifier)
        reviewed_at = parse_bound_date(row["reviewed-at"], label=f"ledger evidence {identifier} reviewed-at")
        valid_through = parse_bound_date(row["valid-through"], label=f"ledger evidence {identifier} valid-through")
        if reviewed_at > parse_bound_date(policy["freeze-date"], label="freeze date"):
            fail(f"ledger evidence {identifier} review date is after the freeze date")
        if valid_through < reviewed_at:
            fail(f"ledger evidence {identifier} expires before its review date")
        ledger_freshness.append(
            {
                "id": identifier,
                "required": row["required"],
                "reviewed_at": reviewed_at.isoformat(),
                "valid_through": valid_through.isoformat(),
                "verdict": row["verdict"],
            }
        )
    boundary = parse_toml(files, "implementation-boundary.toml")
    if boundary.get("schema-version") != 2:
        fail("implementation-boundary.toml must remain schema v2")
    if set(boundary.get("published-packages", [])) != EXPECTED_PUBLISHED_PACKAGES or len(boundary.get("published-packages", [])) != 12:
        fail("implementation boundary published twelve-package inventory drift")
    if public_count != policy["expected-public-api-units"]:
        fail(f"public API count drift: {public_count} != {policy['expected-public-api-units']}")
    if len(atomic_rows) != policy["expected-atomic-operations"]:
        fail(f"atomic operation count drift: {len(atomic_rows)} != {policy['expected-atomic-operations']}")
    if evidence_count != policy["expected-ledger-evidence-records"]:
        fail(f"ledger evidence count drift: {evidence_count} != {policy['expected-ledger-evidence-records']}")
    historical = parse_toml(files, "assurance/audit/historical-advisory-regressions.toml")
    expected_historical_top = {
        "schema-version", "status", "owner", "review-deadline", "limitation", "regression"
    }
    if set(historical) != expected_historical_top:
        fail("historical advisory regression top-level policy drift")
    if (
        historical["schema-version"] != 1
        or historical["status"] != "inventory-only-replay-required"
        or historical["owner"] != "dcrypt security assurance"
        or historical["limitation"] != "historical-advisory-replay-unavailable"
    ):
        fail("historical advisory regression control metadata drift")
    historical_deadline = parse_bound_date(
        historical["review-deadline"], label="historical advisory review-deadline"
    )
    regressions = historical.get("regression", [])
    if not regressions or historical.get("status") != "inventory-only-replay-required":
        fail("historical-advisory inventory must be non-empty and replay-blocked")
    regression_ids = {row.get("id") for row in regressions if isinstance(row, dict)}
    if regression_ids != EXPECTED_HISTORICAL_REGRESSIONS or len(regressions) != len(EXPECTED_HISTORICAL_REGRESSIONS):
        fail("historical advisory regression inventory must contain exact IDs 0001 through 0011")
    for row in regressions:
        require_keys(row, ("id", "name", "source", "command", "status"), label="historical advisory regression")
        if set(row) != {"id", "name", "source", "command", "status"}:
            fail(f"historical advisory regression {row.get('id')} has unexpected fields")
        expected_row = EXPECTED_HISTORICAL_ROWS.get(row["id"])
        if expected_row != (row["name"], row["source"], row["command"]):
            fail(f"historical advisory regression row semantics drift: {row['id']}")
        source = row["source"]
        if source not in all_paths and not any(path.startswith(source.rstrip("/") + "/") for path in all_paths):
            fail(f"historical advisory source is absent: {source}")
        if row["status"] != "source-bound-replay-required":
            fail(f"historical advisory regression {row['id']} is incorrectly promoted")
    threat = parse_toml(files, "assurance/threat-models/threat-models.toml")
    threat_models = threat.get("model", [])
    if len(threat_models) != 11 or threat.get("expected-atomic-row-count") != 9298 or threat.get("expected-release-blocked-count") != 9298:
        fail("threat-model exact model/row baseline drift")
    threat_freshness: list[dict[str, Any]] = []
    threat_ids: set[str] = set()
    threat_release_errors = 0
    for model in threat_models:
        if not isinstance(model, dict):
            fail("threat model row must be a table")
        require_keys(
            model,
            (
                "id", "status", "owner", "reviewer", "independent-review-status",
                "reviewed-at", "valid-through", "mitigations", "residual-risk",
            ),
            label="threat model",
        )
        identifier = model["id"]
        if not isinstance(identifier, str) or not identifier or identifier in threat_ids:
            fail("threat model has a missing or duplicate id")
        threat_ids.add(identifier)
        reviewed_at = parse_bound_date(model["reviewed-at"], label=f"threat model {identifier} reviewed-at")
        valid_through = parse_bound_date(model["valid-through"], label=f"threat model {identifier} valid-through")
        if reviewed_at > parse_bound_date(policy["freeze-date"], label="freeze date"):
            fail(f"threat model {identifier} review date is after the freeze date")
        if valid_through < reviewed_at:
            fail(f"threat model {identifier} expires before its review date")
        residual = model["residual-risk"]
        mitigations = model["mitigations"]
        if not isinstance(residual, dict) or not isinstance(mitigations, list):
            fail(f"threat model {identifier} residual risk/mitigation structure is invalid")
        unclosed = [row.get("id") for row in mitigations if isinstance(row, dict) and row.get("status") != "verified"]
        row_release_errors = sum(
            (
                model["status"] != "active",
                model["independent-review-status"] != "complete",
                residual.get("rating") in {"high", "critical"},
                residual.get("disposition") == "mitigate" and bool(unclosed),
            )
        )
        threat_release_errors += row_release_errors
        threat_freshness.append(
            {
                "id": identifier,
                "independent_review_status": model["independent-review-status"],
                "release_control_errors": row_release_errors,
                "reviewed_at": reviewed_at.isoformat(),
                "status": model["status"],
                "valid_through": valid_through.isoformat(),
            }
        )
    if threat_release_errors != 44:
        fail(f"threat release-mode fail-closed baseline drift: {threat_release_errors} != 44")
    sow_policy = parse_toml(files, "assurance/audit/sow/audit-policy.toml")
    if (
        sow_policy.get("status") != "candidate-uncommissioned"
        or sow_policy.get("external-contact-authorized") is not False
        or sow_policy.get("audit-commissioned") is not False
    ):
        fail("SOW issuance fail-closed state drift")
    all_valid_through = [
        *(parse_bound_date(row["valid_through"], label="ledger freshness") for row in ledger_freshness),
        *(parse_bound_date(row["valid_through"], label="threat freshness") for row in threat_freshness),
        historical_deadline,
        *(parse_bound_date(row["deadline"], label="limitation deadline") for row in policy["limitation"]),
        parse_bound_date(policy["valid-through"], label="freeze valid-through"),
    ]
    effective_valid_through = min(all_valid_through)
    if effective_valid_through.isoformat() != policy["valid-through"]:
        fail("freeze valid-through is not the earliest bound review/evidence/limitation deadline")
    input_paths = sorted(set((*required, *threat_paths, *sow_paths)))
    blocker_ids = sorted(ids)
    return {
        "schema_version": 1,
        "inputs": [{"path": path, "sha256": sha256(files[path]), "size": len(files[path])} for path in input_paths],
        "public_api_units": public_count,
        "atomic_assurance_rows": len(atomic_rows),
        "atomic_release_blockers": len(blocker_ids),
        "atomic_release_blocker_ids_sha256": sha256(canonical_json(blocker_ids)),
        "authoritative_atomic_rows": authoritative_rows,
        "facade_alias_rows": facade_aliases,
        "explicit_unreviewed_gaps": len(gaps),
        "ledger_evidence_records": evidence_count,
        "feature_profile_count": len(ledger.get("profile", [])),
        "feature_profiles": toml_json_value(ledger.get("profile", [])),
        "feature_row_count": len(ledger.get("feature", [])),
        "feature_rows": toml_json_value(ledger.get("feature", [])),
        "published_packages": len(boundary.get("published-packages", [])),
        "implementation_boundary": toml_json_value(boundary),
        "implementation_boundary_sha256": sha256(files["implementation-boundary.toml"]),
        "threat_model_files": threat_paths,
        "sow_files": sow_paths,
        "sow_sha256": sha256(sow_bytes),
        "audit_policy_sha256": sha256(files["assurance/audit/sow/audit-policy.toml"]),
        "audit_scope_sha256": sha256(files["assurance/audit/sow/audit-scope.toml"]),
        "historical_advisory_regressions": len(regressions),
        "historical_advisory_replay_status": "blocked",
        "freshness": {
            "effective_valid_through": effective_valid_through.isoformat(),
            "historical_advisory_review_deadline": historical_deadline.isoformat(),
            "ledger_evidence": sorted(ledger_freshness, key=lambda row: row["id"]),
            "threat_models": sorted(threat_freshness, key=lambda row: row["id"]),
        },
        "control_status": [
            {"id": "ledger-generator-check", "command_index": 0, "expected_exit": 0, "status": "expected-pass-bound-inputs-not-executed"},
            {"id": "ledger-snapshot-ci", "command_index": 2, "expected_exit": 0, "status": "expected-pass-structural-bound-artifacts"},
            {"id": "ledger-snapshot-release", "command_index": 3, "expected_exit": 1, "status": "expected-reject-snapshot-not-release-evidence"},
            {"id": "ledger-live-ci", "command_index": 4, "expected_exit": None, "status": "blocked-unprovisioned-toolchain"},
            {"id": "ledger-live-release", "command_index": 5, "expected_exit": None, "atomic_blocked_rows": 9298, "status": "blocked-unprovisioned-and-atomic-release-blocked"},
            {"id": "threat-ci", "command_index": 6, "expected_exit": 0, "status": "expected-pass-bound-inputs-not-executed"},
            {"id": "threat-release", "command_index": 7, "expected_exit": 1, "expected_error_count": 44, "status": "expected-fail-release-controls"},
            {"id": "sow-base", "command_index": 9, "expected_exit": 0, "status": "expected-pass-bound-inputs-not-executed"},
            {"id": "sow-issuance", "command_index": 10, "expected_exit": 1, "status": "expected-fail-uncommissioned-unreplayed"},
        ],
        "release_boundary_and_assembly_tooling": [
            {"path": path, "sha256": sha256(files[path])}
            for path in required
            if path.startswith("tools/")
        ],
        "subject_validator_commands": [
            "/usr/bin/python3.12 -I -B -S assurance/verify-assurance-ledger.py --snapshot-only --mode ci",
            "/usr/bin/python3.12 -I -B -S assurance/verify-assurance-ledger.py --snapshot-only --mode release",
            "/usr/bin/python3.12 -I -B -S -c 'import runpy,sys;sys.path.insert(0,\"assurance/threat-models\");runpy.run_path(\"assurance/threat-models/verify-threat-models.py\",run_name=\"__main__\")' --mode ci",
            "/usr/bin/python3.12 -I -B -S -c 'import runpy,sys;sys.path.insert(0,\"assurance/threat-models\");runpy.run_path(\"assurance/threat-models/verify-threat-models.py\",run_name=\"__main__\")' --mode release",
            "/usr/bin/python3.12 -I -B -S assurance/audit/sow/verify-sow.py",
            "/usr/bin/python3.12 -I -B -S assurance/audit/sow/verify-sow.py --issuance",
        ],
        "subject_validator_execution": (
            "not executed by generator; exact inputs, freshness semantics, and expected fail-closed "
            "states are parsed here; command output/status still requires independent replay"
        ),
    }


def artifact_document(policy: dict[str, Any]) -> dict[str, Any]:
    records = []
    for row in sorted(policy["required-artifact"], key=lambda item: item["id"]):
        records.append(
            {
                "bytes_rebuilt": False,
                "class": row["class"],
                "evidence_files": [],
                "expected_members": row.get("expected-members", []),
                "id": row["id"],
                "independently_replayed": False,
                "limitation": row["limitation"],
                "status": row["status"],
            }
        )
    return {
        "schema_version": 1,
        "artifacts": records,
        "available_artifact_count": 0,
        "blocked_artifact_count": len(records),
        "rebuild_claim": "none",
        "reproducible_build_claim": False,
    }


def limitations_document(policy: dict[str, Any], assurance: dict[str, Any]) -> dict[str, Any]:
    rows = sorted(policy["limitation"], key=lambda row: row["id"])
    return {
        "schema_version": 1,
        "limitations": rows,
        "infrastructure_release_blockers": len(rows),
        "atomic_release_blockers": assurance["atomic_release_blockers"],
        "total_release_blockers": len(rows) + assurance["atomic_release_blockers"],
        "counting_semantics": (
            "Sum of atomic release-blocker rows and infrastructure limitation records. "
            "ledger-atomic-assurance-incomplete is retained as a separately owned summary limitation, "
            "so this is a blocking-record count, not a claim of statistically independent risks."
        ),
        "status": "blocked",
    }


def validate_generated_documents(documents: dict[str, Any]) -> None:
    if set(documents) != set(SUBORDINATE_FILES):
        fail("internal error: subordinate manifest set is incomplete")
    for name, document in documents.items():
        if not isinstance(document, dict) or document.get("schema_version") != 1:
            fail(f"{name}: generated document does not satisfy schema v1")
        canonical_json(document)
    limitations = documents["limitations.json"]
    if limitations["status"] != "blocked" or limitations["total_release_blockers"] <= 0:
        fail("candidate limitations must remain fail-closed")
    artifacts = documents["artifact-manifest.json"]
    if artifacts["available_artifact_count"] != 0 or artifacts["reproducible_build_claim"] is not False:
        fail("candidate artifact manifest makes an unsupported availability claim")


def build_bundle_bytes(repo: Path, subject: str) -> dict[str, bytes]:
    require_isolated_python()
    repo = repository_root(repo)
    subject, tree = validate_exact_subject(repo, subject)
    timestamp = str(exact_subject_timestamp(repo, subject))
    require_documented_sandbox_runtime(expected_source_date_epoch=int(timestamp))
    observed_status = require_clean_checkout(repo, subject, label="generation subject")
    entries, files, all_paths = subject_files(repo, subject)
    tracked_attributes = sorted(
        path for path in all_paths if PurePosixPath(path).name == ".gitattributes"
    )
    if tracked_attributes:
        fail(f"tracked .gitattributes files are forbidden for byte-exact replay: {tracked_attributes}")
    validate_bound_control_bytes(files)
    policy = parse_toml(files, "assurance/audit/freeze-policy.toml")
    provisioning = parse_toml(files, "assurance/audit/provisioning-lock.toml")
    validate_policy(policy)
    validate_provisioning(provisioning)
    freeze_schema = load_json_strict(files["assurance/audit/audit-freeze.schema.json"], label="audit-freeze schema")
    envelope_schema = load_json_strict(files["assurance/audit/freeze-envelope.schema.json"], label="freeze-envelope schema")
    provisioning_schema = load_json_strict(files["assurance/audit/provisioning.schema.json"], label="provisioning schema")
    for label, schema in (
        ("audit-freeze schema", freeze_schema),
        ("freeze-envelope schema", envelope_schema),
        ("provisioning schema", provisioning_schema),
    ):
        validate_schema_program(schema, label=label)
    validate_json_schema(toml_json_value(provisioning), provisioning_schema, label="provisioning-lock.toml")
    provisioning_handoff = provisioning_handoff_bytes(
        repo, subject, tree, files, policy, provisioning, provisioning_schema
    )
    source = source_manifest_document(repo, subject, tree, entries, policy)
    release_subject = release_subject_document(repo, policy)
    workspaces = workspace_document(files, all_paths, policy, provisioning)
    workflows = workflow_document(files, policy, provisioning)
    toolchains = toolchain_document(files, provisioning)
    environment = environment_document(repo, subject, policy, provisioning)
    environment["provisioning_handoff"] = {
        "classification": "observed-structural-inputs-only",
        "id": PROVISIONING_HANDOFF_ID,
        "manifest_sha256": sha256(provisioning_handoff["PROVISIONING-MANIFEST.json"]),
        "sha256sums_sha256": sha256(provisioning_handoff["SHA256SUMS"]),
        "status": "first-party-materializable-release-blocked",
    }
    environment["generation_checkout"] = {
        "head": subject,
        "status": "strictly-clean",
        "status_porcelain_v1_z_sha256": sha256(observed_status),
        "ignored_paths_included_in_check": True,
    }
    assurance = assurance_document(files, all_paths, policy)
    artifacts = artifact_document(policy)
    limitations = limitations_document(policy, assurance)
    docs: dict[str, Any] = {
        "actions-and-runners.json": workflows,
        "artifact-manifest.json": artifacts,
        "assurance-inputs.json": assurance,
        "environment.json": environment,
        "limitations.json": limitations,
        "source-manifest.json": source,
        "toolchains.json": toolchains,
        "workspace-dependencies.json": workspaces,
    }
    validate_generated_documents(docs)
    encoded = {name: canonical_json(value) for name, value in docs.items()}
    encoded["PROVISIONING-MANIFEST.json"] = provisioning_handoff["PROVISIONING-MANIFEST.json"]
    manifest_files = [
        {"path": name, "sha256": sha256(encoded[name])}
        for name in sorted(SUBORDINATE_FILES)
    ]
    freeze_commands, freeze_expectations = freeze_command_inventory(
        subject, policy["freeze-id"]
    )
    freeze = {
        "schema_version": SCHEMA_VERSION,
        "content_policy": CONTENT_POLICY,
        "freeze_id": policy["freeze-id"],
        "classification": policy["classification"],
        "freeze_date": policy["freeze-date"],
        "valid_through": policy["valid-through"],
        "subject": {
            "commit": subject,
            "tree": tree,
            "commit_payload_sha256": source["subject"]["commit_cat_file_payload_sha256"],
            "tree_payload_sha256": source["subject"]["tree_cat_file_payload_sha256"],
        },
        "release_subject": release_subject,
        "canonicalization": policy["canonical-json"],
        "manifest_files": manifest_files,
        "counts": {
            "authoritative_atomic_rows": assurance["authoritative_atomic_rows"],
            "atomic_assurance_rows": assurance["atomic_assurance_rows"],
            "atomic_release_blockers": assurance["atomic_release_blockers"],
            "blocked_artifacts": artifacts["blocked_artifact_count"],
            "infrastructure_release_blockers": limitations["infrastructure_release_blockers"],
            "ledger_evidence_records": assurance["ledger_evidence_records"],
            "facade_alias_rows": assurance["facade_alias_rows"],
            "locked_packages": workspaces["unique_locked_package_count"],
            "public_api_units": assurance["public_api_units"],
            "registry_packages": workspaces["unique_registry_package_count"],
            "source_files": len(entries),
            "unreviewed_atomic_gaps": assurance["explicit_unreviewed_gaps"],
            "workspaces": workspaces["workspace_count"],
        },
        "release_gate": {
            "status": "blocked",
            "total_blockers": limitations["total_release_blockers"],
            "counting_semantics": limitations["counting_semantics"],
            "structural_verification_may_pass_with_blockers": True,
            "release_verification_must_fail_with_blockers": True,
            "independent_replay_required": True,
        },
        "generated_evidence_status": "first-party-unreplayed",
        "commands": freeze_commands,
        "command_expectations": freeze_expectations,
    }
    validate_json_schema(freeze, freeze_schema, label="freeze.json")
    freeze_bytes = canonical_json(freeze)
    encoded["freeze.json"] = freeze_bytes
    envelope = {
        "schema_version": 1,
        "audit_policy_path": "assurance/audit/sow/audit-policy.toml",
        "audit_policy_sha256": assurance["audit_policy_sha256"],
        "audit_scope_path": "assurance/audit/sow/audit-scope.toml",
        "audit_scope_sha256": assurance["audit_scope_sha256"],
        "freeze_id": policy["freeze-id"],
        "freeze_json_sha256": sha256(freeze_bytes),
        "sow_path": "assurance/audit/sow/RFP-SOW.md",
        "sow_sha256": assurance["sow_sha256"],
        "subject_commit": subject,
        "subject_tree": tree,
        "status": "candidate-first-party-unreplayed",
    }
    validate_json_schema(envelope, envelope_schema, label="freeze-envelope.json")
    encoded["freeze-envelope.json"] = canonical_json(envelope)
    if set(encoded) != set(JSON_FILES):
        fail("internal error: canonical JSON file set drift")
    checksum_lines = [f"{sha256(encoded[name])}  {name}\n" for name in sorted(encoded)]
    encoded["PROVISIONING-SHA256SUMS"] = provisioning_handoff["SHA256SUMS"]
    encoded["SHA256SUMS"] = "".join(checksum_lines).encode("ascii")
    return encoded


def write_bundle(
    output: Path,
    encoded: dict[str, bytes],
    *,
    expected_files: frozenset[str] = ALLOWED_BUNDLE_FILES,
) -> None:
    """Atomically write one exact, descriptor-bound directory inventory."""

    output = lexical_absolute(output)
    if set(encoded) != set(expected_files):
        fail("generated output file set differs from the exact reviewed output set")
    if any(not isinstance(data, bytes) or len(data) > MAX_BUNDLE_FILE_BYTES for data in encoded.values()):
        fail("generated output contains a non-byte or oversized entry")
    if sum(len(data) for data in encoded.values()) > MAX_BUNDLE_TOTAL_BYTES:
        fail("generated output exceeds the reviewed aggregate byte limit")
    validate_repo_path(output.name, label="output directory name")
    parent = lexical_absolute(output.parent)
    production_parent = parent == Path("/output")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW

    parent_fd: int | None = None
    temporary_fd: int | None = None
    temporary_name: str | None = None
    renamed = False
    complete = False

    def directory_names(directory_fd: int) -> set[str]:
        names: set[str] = set()
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                name = validate_repo_path(entry.name, label="output parent entry")
                if name in names:
                    fail(f"duplicate output parent entry: {name}")
                names.add(name)
        return names

    def cleanup_held_output() -> None:
        if parent_fd is None or temporary_fd is None or temporary_name is None:
            return
        try:
            os.fchmod(temporary_fd, 0o700)
        except OSError:
            pass
        try:
            with os.scandir(temporary_fd) as iterator:
                cleanup_names = [entry.name for entry in iterator]
            for name in cleanup_names:
                try:
                    entry_status = os.stat(name, dir_fd=temporary_fd, follow_symlinks=False)
                    if stat.S_ISREG(entry_status.st_mode) or stat.S_ISLNK(entry_status.st_mode):
                        os.unlink(name, dir_fd=temporary_fd)
                except OSError:
                    pass
            held = os.fstat(temporary_fd)
            leaf = output.name if renamed else temporary_name
            leaf_status = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if (leaf_status.st_dev, leaf_status.st_ino) == (held.st_dev, held.st_ino):
                os.rmdir(leaf, dir_fd=parent_fd)
        except OSError:
            # Never fall back to path-recursive cleanup: preserving a suspicious
            # inode is safer than deleting through an attacker-swapped path.
            pass

    try:
        parent_fd = open_directory_nofollow(parent)
        parent_status = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_status.st_mode):
            fail("output parent descriptor is not a directory")
        if production_parent and directory_names(parent_fd):
            fail("production /output must be empty before the exact output is written")
        try:
            os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail(f"output already exists: {output}")

        for _attempt in range(128):
            candidate = f".{output.name}.{secrets.token_hex(16)}"
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if temporary_name is None:
            fail("cannot allocate an exclusive temporary output directory")
        temporary_fd = os.open(temporary_name, directory_flags, dir_fd=parent_fd)
        opened_temporary = os.fstat(temporary_fd)
        temporary_path_status = os.stat(
            temporary_name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISDIR(opened_temporary.st_mode)
            or (opened_temporary.st_dev, opened_temporary.st_ino)
            != (temporary_path_status.st_dev, temporary_path_status.st_ino)
        ):
            fail("temporary output directory identity changed before writing")

        for name in sorted(encoded):
            validate_repo_path(name, label="output filename")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=temporary_fd)
            except OSError as exc:
                fail(f"cannot exclusively create bounded output entry {name}: {exc}")
            try:
                initial = os.fstat(descriptor)
                if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1 or initial.st_size != 0:
                    fail(f"new output is not an exclusively linked empty regular file: {name}")
                view = memoryview(encoded[name])
                offset = 0
                while offset < len(view):
                    written = os.write(descriptor, view[offset:])
                    if written <= 0:
                        fail(f"short write while creating output entry: {name}")
                    offset += written
                os.fchmod(descriptor, 0o644)
                os.fsync(descriptor)
                final = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(final.st_mode)
                    or final.st_nlink != 1
                    or final.st_size != len(encoded[name])
                    or stat.S_IMODE(final.st_mode) != 0o644
                ):
                    fail(f"output entry changed or has an invalid final state: {name}")
            finally:
                os.close(descriptor)

        def verify_written_inventory(stage: str) -> None:
            if temporary_fd is None:
                fail("internal error: output directory descriptor is unavailable")
            observed: dict[str, os.stat_result] = {}
            with os.scandir(temporary_fd) as iterator:
                for entry in iterator:
                    entry_status = entry.stat(follow_symlinks=False)
                    if entry.name in observed:
                        fail(f"duplicate output entry during {stage}: {entry.name}")
                    if not stat.S_ISREG(entry_status.st_mode) or entry_status.st_nlink != 1:
                        fail(f"output contains a non-regular or externally linked entry during {stage}: {entry.name}")
                    observed[entry.name] = entry_status
            if set(observed) != set(expected_files):
                fail(f"output inventory differs from the exact reviewed file set during {stage}")
            identity_fields = (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                "st_mtime_ns", "st_ctime_ns",
            )
            descriptors: dict[str, tuple[int, os.stat_result]] = {}
            try:
                for name in sorted(observed):
                    entry_status = observed[name]
                    if (
                        entry_status.st_size != len(encoded[name])
                        or stat.S_IMODE(entry_status.st_mode) != 0o644
                    ):
                        fail(f"output final size/mode differs for {name} during {stage}")
                    flags = os.O_RDONLY
                    if hasattr(os, "O_CLOEXEC"):
                        flags |= os.O_CLOEXEC
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    descriptor = os.open(name, flags, dir_fd=temporary_fd)
                    opened = os.fstat(descriptor)
                    if any(
                        getattr(opened, field) != getattr(entry_status, field)
                        for field in identity_fields
                    ):
                        os.close(descriptor)
                        fail(f"output entry identity changed during {stage}: {name}")
                    descriptors[name] = (descriptor, opened)
                for name in sorted(descriptors):
                    descriptor, opened = descriptors[name]
                    digest = hashlib.sha256()
                    remaining = opened.st_size
                    while remaining:
                        chunk = os.read(descriptor, min(1024 * 1024, remaining))
                        if not chunk:
                            fail(f"output entry was truncated during {stage}: {name}")
                        digest.update(chunk)
                        remaining -= len(chunk)
                    if os.read(descriptor, 1):
                        fail(f"output entry grew during {stage}: {name}")
                    if digest.hexdigest() != sha256(encoded[name]):
                        fail(f"output entry bytes differ during {stage}: {name}")
                final_observed: dict[str, os.stat_result] = {}
                with os.scandir(temporary_fd) as iterator:
                    for entry in iterator:
                        if entry.name in final_observed:
                            fail(f"duplicate output entry during final {stage}: {entry.name}")
                        final_observed[entry.name] = entry.stat(follow_symlinks=False)
                if set(final_observed) != set(observed):
                    fail(f"output inventory differs after complete descriptor read during {stage}")
                for name, (descriptor, opened) in descriptors.items():
                    held_final = os.fstat(descriptor)
                    path_final = final_observed[name]
                    if any(
                        getattr(held_final, field) != getattr(opened, field)
                        or getattr(path_final, field) != getattr(opened, field)
                        for field in identity_fields
                    ):
                        fail(f"output entry changed during complete {stage}: {name}")
            finally:
                for descriptor, _opened in descriptors.values():
                    os.close(descriptor)

        verify_written_inventory("pre-rename verification")
        os.fchmod(temporary_fd, 0o555)
        os.fsync(temporary_fd)
        current_temporary = os.stat(
            temporary_name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            (current_temporary.st_dev, current_temporary.st_ino)
            != (opened_temporary.st_dev, opened_temporary.st_ino)
        ):
            fail("temporary output directory identity changed while writing")
        try:
            os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail("output appeared before atomic rename")
        os.rename(temporary_name, output.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        renamed = True
        os.fsync(parent_fd)
        output_status = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(output_status.st_mode)
            or (output_status.st_dev, output_status.st_ino)
            != (opened_temporary.st_dev, opened_temporary.st_ino)
        ):
            fail("renamed output does not identify the held temporary directory")
        verify_written_inventory("post-rename verification")
        final_parent = os.fstat(parent_fd)
        if (
            final_parent.st_dev,
            final_parent.st_ino,
            final_parent.st_mode,
        ) != (parent_status.st_dev, parent_status.st_ino, parent_status.st_mode):
            fail("output parent descriptor changed while writing")
        comparison_fd = open_directory_nofollow(parent)
        try:
            comparison = os.fstat(comparison_fd)
            if (comparison.st_dev, comparison.st_ino) != (
                parent_status.st_dev, parent_status.st_ino
            ):
                fail("output parent path changed while writing")
        finally:
            os.close(comparison_fd)
        if production_parent:
            final_names = directory_names(parent_fd)
            if final_names != {output.name}:
                fail(
                    "production /output inventory differs from the one exact generated directory: "
                    f"observed={sorted(final_names)}"
                )
            final_target = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
            if (final_target.st_dev, final_target.st_ino) != (
                opened_temporary.st_dev, opened_temporary.st_ino
            ):
                fail("production /output target identity changed during final inventory")
        complete = True
    except FreezeError:
        raise
    except Exception as exc:
        fail(f"cannot safely write exact output directory: {type(exc).__name__}: {exc}")
    finally:
        if not complete:
            cleanup_held_output()
        if temporary_fd is not None:
            try:
                os.close(temporary_fd)
            except OSError:
                pass
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def validate_generation_cli_paths(
    repo: Path, output: Path, freeze_id: str, *, provision: Path | None = None,
) -> None:
    if lexical_absolute(repo) != Path("/dcrypt"):
        fail("production generation --repo must be the exact sandbox mapping /dcrypt")
    expected_output = Path("/output") / freeze_id
    if lexical_absolute(output) != expected_output:
        fail(f"production generation --output must be exactly {expected_output}")
    if provision is not None and lexical_absolute(provision) != Path("/provision"):
        fail("production generation --provision must be the exact read-only mapping /provision")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--subject", required=True, help="exact lowercase 40-hex commit")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--provision", type=Path)
    parser.add_argument("--materialize-provisioning", action="store_true")
    args = parser.parse_args(argv)
    try:
        require_isolated_python()
        if args.materialize_provisioning:
            if args.provision is not None:
                fail("--provision is forbidden while materializing the provisioning handoff")
            require_documented_sandbox_runtime(require_empty_output=True)
            validate_generation_cli_paths(args.repo, args.output, PROVISIONING_HANDOFF_ID)
        else:
            if args.provision is None:
                fail("candidate generation requires --provision /provision")
            require_documented_sandbox_runtime(
                require_empty_output=True, require_provision=True
            )
            validate_generation_cli_paths(
                args.repo, args.output, PRODUCTION_FREEZE_ID, provision=args.provision
            )
        repo = repository_root(args.repo)
        subject, _ = validate_exact_subject(repo, args.subject)
        policy_bytes = _git(repo, "show", f"{subject}:assurance/audit/freeze-policy.toml")
        try:
            policy = tomllib.loads(policy_bytes.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            fail(f"assurance/audit/freeze-policy.toml: invalid TOML: {exc}")
        validate_policy(policy)
        require_clean_checkout(repo, subject, label="generation subject")
        requested_output = lexical_absolute(args.output)
        reject_symlink_components(requested_output.parent, allow_missing_tail=True)
        encoded = build_bundle_bytes(repo, subject)
        if args.materialize_provisioning:
            handoff = {
                "PROVISIONING-MANIFEST.json": encoded["PROVISIONING-MANIFEST.json"],
                "SHA256SUMS": encoded["PROVISIONING-SHA256SUMS"],
            }
            write_bundle(
                requested_output, handoff, expected_files=PROVISIONING_HANDOFF_FILES
            )
            print(
                f"materialized {PROVISIONING_HANDOFF_ID} "
                f"manifest sha256={sha256(handoff['PROVISIONING-MANIFEST.json'])}"
            )
            print("classification=observed-structural-inputs-only release_status=blocked")
            return 0
        external_handoff = read_exact_directory_files(
            lexical_absolute(args.provision), PROVISIONING_HANDOFF_FILES
        )
        expected_handoff = {
            "PROVISIONING-MANIFEST.json": encoded["PROVISIONING-MANIFEST.json"],
            "SHA256SUMS": encoded["PROVISIONING-SHA256SUMS"],
        }
        validate_provisioning_handoff_contents(external_handoff, expected_handoff)
        write_bundle(requested_output, encoded)
        freeze_hash = sha256(encoded["freeze.json"])
        freeze = canonical_json_is_exact(encoded["freeze.json"], label="freeze.json")
        print(f"generated {freeze['freeze_id']} freeze.json sha256={freeze_hash}")
        print(f"subject={freeze['subject']['commit']} tree={freeze['subject']['tree']}")
        print(f"release_status={freeze['release_gate']['status']} blockers={freeze['release_gate']['total_blockers']}")
        return 0
    except FreezeError as exc:
        print(f"audit-freeze generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
