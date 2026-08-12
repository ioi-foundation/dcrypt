#!/usr/bin/env python3
"""Deterministic adversarial self-tests for the dcrypt assurance ledger.

This module deliberately uses only the Python standard library.  It imports the
production verifier and generator by file path, then probes their fail-closed
boundaries with in-memory API ledgers and disposable Git repositories.  It does
not invoke Cargo, rustdoc, the network, or mutate the checkout.

Run with::

    python3 -B assurance/assurance-selftest.py

The assertions intentionally name the diagnostic that must be produced.  A
test only passes when the positive control is clean and its paired mutation is
rejected for the expected reason.
"""

from __future__ import annotations

import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Callable, Iterator


ASSURANCE_DIR = Path(__file__).resolve().parent
FIXED_DATE = dt.date(2030, 1, 2)
PROFILE = "fixture-profile"
TARGET = "fixture-target"
COMMIT = "1" * 40
TREE = "2" * 40
ZERO_SHA256 = "0" * 64


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


VERIFY = load_module("dcrypt_assurance_verifier", ASSURANCE_DIR / "verify-assurance-ledger.py")
GENERATE = load_module("dcrypt_assurance_generator", ASSURANCE_DIR / "generate-assurance-ledger.py")


class Checks:
    def __init__(self) -> None:
        self.count = 0
        self.failures: list[str] = []

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        self.count += 1
        if not condition:
            suffix = f": {detail}" if detail else ""
            self.failures.append(f"{name}{suffix}")

    def equal(self, name: str, actual: Any, expected: Any) -> None:
        self.check(name, actual == expected, f"expected {expected!r}; got {actual!r}")

    def includes(self, name: str, actual: list[str], expected: str) -> None:
        self.check(name, expected in actual, f"missing {expected!r}; got {actual!r}")

    def excludes(self, name: str, actual: list[str], forbidden: str) -> None:
        self.check(name, forbidden not in actual, f"unexpected {forbidden!r}; got {actual!r}")


ACVP_HARNESS_PATHS = sorted({
    "tests/src/suites/acvp/runner.rs",
    "tests/src/suites/acvp/model.rs",
    "tests/src/suites/acvp/loader.rs",
    "tests/src/suites/acvp/dispatcher.rs",
    "tests/src/suites/acvp/engine.rs",
    "tests/src/suites/acvp/error.rs",
    "tests/src/suites/acvp/mod.rs",
    "tests/src/suites/acvp/algorithms/mod.rs",
    "tests/tests/acvp_tests.rs",
    "assurance/acvp-vector-manifest.json",
})


def evidence(identifier: str, artifacts: list[str], *, expires: str = "2030-01-02") -> dict[str, Any]:
    return {
        "id": identifier,
        "kind": "deterministic self-test fixture",
        "required": True,
        "owner": "fixture-owner",
        "reviewer": "fixture-reviewer",
        "applicability": "fixture assurance row",
        "command": "python3 -B assurance/assurance-selftest.py --locked --offline",
        "verdict": "pass",
        "reviewed-at": "2029-01-01",
        "valid-through": expires,
        "source-commit": COMMIT,
        "source-tree": TREE,
        "artifacts": [{"path": path, "sha256": ZERO_SHA256} for path in artifacts],
    }


def operation(
    identifier: str,
    *,
    kind: str,
    selector: str,
    canonical: str,
    path: str,
    row_kind: str = "operation",
    support: str = "supported",
) -> dict[str, Any]:
    entry_bindings = [] if row_kind == "data-surface" else [f"{kind}:{selector}|{canonical}"]
    entrypoints = [] if row_kind == "data-surface" else [path]
    return {
        "id": identifier,
        "row-kind": row_kind,
        "crate": "fixture",
        "surface": "fixture-api",
        "entrypoint-bindings": entry_bindings,
        "public-bindings": [f"{kind}:{selector}|{canonical}"],
        "public-paths": [path],
        "entrypoints": entrypoints,
        "algorithm": "Fixture primitive",
        "standard": "Fixture Standard 1",
        "parameter-set": "fixture-128",
        "operation": selector,
        "action-selectors": [] if row_kind == "data-surface" else [selector],
        "encoding": "fixture-v1",
        "mode-profile": "exact-selector:fixture",
        "dst-context-prehash": "n/a",
        "feature-profile": "profile-bound: exact rustdoc presence",
        "profiles": [PROFILE],
        "platforms": [TARGET],
        "support": support,
        "vector-source": "fixture vectors",
        "independent-oracle": "fixture oracle",
        "oracle-provenance": "fixture oracle v1; sha256:fixture",
        "fuzz-target": "fixture fuzz target",
        "side-channel-claim": "no claim in fixture",
        "required-evidence-tier": "functional",
        "audit-coverage": "fixture-reviewed",
        "known-limitation": "none",
        "owner": "fixture-owner",
        "required-evidence": ["fixture-proof"],
        "release-readiness": "ready",
        "semantic-review": "curated",
        "semantic-review-deadline": "n/a-reviewed",
    }


def api_entry(
    *,
    path: str,
    kind: str,
    canonical: str,
    refs: list[str],
    classification: str = "supported-operation",
    unit: str = "export",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "package": "fixture",
        "path": path,
        "unit": unit,
        "kind": kind,
        "canonical": canonical,
        "declaration_sha256": {PROFILE: hashlib.sha256(path.encode()).hexdigest()},
        "profiles": [PROFILE],
        "surface": "fixture-api",
        "classification": classification,
        "operation_refs": sorted(refs),
    }
    if kind in VERIFY.CALLABLE_KINDS:
        result["callable_disposition"] = (
            "method-container" if kind == "trait_impl" else "operation-bearing"
        )
    if kind in VERIFY.DATA_KINDS:
        result["data_disposition"] = "security-or-protocol-data-review-required"
    return result


def baseline_documents() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    ledger: dict[str, Any] = {
        "schema-version": 2,
        "source-commit": COMMIT,
        "source-tree": TREE,
        "surface": [{
            "id": "fixture-api",
            "package": "fixture",
            "classification": "cryptographic-construction",
            "status": "supported",
        }],
        "profile": [{
            "id": PROFILE,
            "mode": "fixture",
            "target": TARGET,
            "support": "supported",
            "api-inventory": True,
        }],
        "evidence": [
            evidence("fixture-proof", ["fixture-proof.txt"]),
            evidence("acvp-harness-integrity", ACVP_HARNESS_PATHS),
        ],
    }

    specifications = [
        ("fixture.function", "function", "encrypt", "fixture::encrypt", "fixture::encrypt"),
        ("fixture.static", "static", "RANDOM_SEED", "fixture::RANDOM_SEED", "fixture::RANDOM_SEED"),
        ("fixture.constant", "constant", "TAG_SIZE", "fixture::TAG_SIZE", "fixture::TAG_SIZE"),
        ("fixture.assoc_const", "assoc_const", "BLOCK_SIZE", "fixture::Cipher::BLOCK_SIZE", "fixture::Cipher::BLOCK_SIZE"),
        ("fixture.macro", "macro", "encrypt_macro", "fixture::encrypt_macro", "fixture::encrypt_macro"),
        ("fixture.trait", "trait", "Operation", "fixture::Operation", "fixture::Operation"),
    ]
    rows = [
        operation(identifier, kind=kind, selector=selector, canonical=canonical, path=path)
        for identifier, kind, selector, canonical, path in specifications
    ]
    entries = [
        api_entry(path=path, kind=kind, canonical=canonical, refs=[identifier])
        for identifier, kind, _selector, canonical, path in specifications
    ]

    impl_digest = "a" * 64
    impl_path = f"fixture::Cipher::{{impl fixture::Operation#{impl_digest}}}"
    impl_canonical = f"fixture::Cipher::{{impl fixture::Operation}}#{impl_digest}"
    sign = operation(
        "fixture.trait.sign", kind="trait-method", selector="sign",
        canonical=impl_canonical, path=impl_path,
    )
    verify = operation(
        "fixture.trait.verify", kind="trait-method", selector="verify",
        canonical=impl_canonical, path=impl_path,
    )
    rows.extend([sign, verify])
    impl_entry = api_entry(
        path=impl_path, kind="trait_impl", canonical=impl_canonical,
        refs=[sign["id"], verify["id"]],
    )
    impl_entry.update({
        "impl_identity_sha256": impl_digest,
        "trait_methods": {PROFILE: ["sign", "verify"]},
        "trait_method_assurance": {
            "sign": {
                "profiles": [PROFILE],
                "operation_refs": [sign["id"]],
                "disposition": "operation-bearing",
                "classification": "supported-operation",
            },
            "verify": {
                "profiles": [PROFILE],
                "operation_refs": [verify["id"]],
                "disposition": "operation-bearing",
                "classification": "supported-operation",
            },
        },
    })
    entries.append(impl_entry)

    data_path = "fixture::Packet::bytes"
    data_row = operation(
        "fixture.data.bytes", kind="field", selector="bytes",
        canonical=data_path, path=data_path, row_kind="data-surface", support="low-level",
    )
    rows.append(data_row)
    entries.append(api_entry(
        path=data_path, kind="field", canonical=data_path,
        refs=[data_row["id"]], classification="internal-like-low-level", unit="member",
    ))

    operations = {"schema-version": 2, "operation": rows}
    snapshot = {
        "schema_version": 2,
        "source_commit": COMMIT,
        "source_tree": TREE,
        "profiles": [PROFILE],
        "entries": sorted(entries, key=VERIFY.entry_identity),
    }
    return ledger, operations, snapshot


def ledger_errors(
    mutate: Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], None] | None = None,
    *, mode: str = "ci",
) -> list[str]:
    ledger, operations, snapshot = baseline_documents()
    if mutate is not None:
        mutate(ledger, operations, snapshot)
    errors, _metrics = VERIFY.validate_ledger(
        ledger, operations, snapshot, repo=ASSURANCE_DIR,
        as_of=FIXED_DATE, mode=mode, check_paths=False,
    )
    return errors


def row(document: dict[str, Any], identifier: str) -> dict[str, Any]:
    return next(item for item in document["operation"] if item["id"] == identifier)


def entry(snapshot: dict[str, Any], path: str) -> dict[str, Any]:
    return next(item for item in snapshot["entries"] if item["path"] == path)


def ledger_validation_tests(checks: Checks) -> None:
    checks.equal("schema-positive", ledger_errors(), [])

    def exact_oracle_replay_records(
        ledger: dict[str, Any], _operations: dict[str, Any], _snapshot: dict[str, Any]
    ) -> None:
        artifacts = sorted(VERIFY.ORACLE_REPLAY_REQUIRED_ARTIFACTS)
        for identifier in sorted(VERIFY.ORACLE_REPLAY_EVIDENCE_IDS):
            record = evidence(identifier, artifacts)
            record["command"] = VERIFY.ORACLE_REPLAY_COMMAND
            record["verdict"] = "informational"
            ledger["evidence"].append(record)

    checks.equal(
        "exact-cold-oracle-replay-positive",
        ledger_errors(exact_oracle_replay_records),
        [],
    )

    def old_free_filter(
        ledger: dict[str, Any], operations: dict[str, Any], snapshot: dict[str, Any]
    ) -> None:
        exact_oracle_replay_records(ledger, operations, snapshot)
        target = next(
            item for item in ledger["evidence"] if item["id"] == "bls-interoperability"
        )
        target["command"] = (
            "cargo test --release --locked --offline "
            "--manifest-path verification/Cargo.toml bls"
        )

    checks.equal(
        "vacuous-oracle-filter-rejected",
        ledger_errors(old_free_filter),
        [
            "evidence bls-interoperability command differs from the exact cold "
            "oracle replay contract"
        ],
    )

    def direct_cargo_without_offline(
        ledger: dict[str, Any], operations: dict[str, Any], snapshot: dict[str, Any]
    ) -> None:
        exact_oracle_replay_records(ledger, operations, snapshot)
        target = next(
            item
            for item in ledger["evidence"]
            if item["id"] == "acvp-traditional-ec"
        )
        target["command"] = (
            "cargo test --release --locked --manifest-path verification/Cargo.toml "
            "--test traditional_ec_interop"
        )

    checks.equal(
        "nonoffline-oracle-command-rejected",
        ledger_errors(direct_cargo_without_offline),
        [
            "evidence acvp-traditional-ec command differs from the exact cold "
            "oracle replay contract"
        ],
    )

    def false_oracle_promotion(
        ledger: dict[str, Any], operations: dict[str, Any], snapshot: dict[str, Any]
    ) -> None:
        exact_oracle_replay_records(ledger, operations, snapshot)
        target = next(
            item
            for item in ledger["evidence"]
            if item["id"] == "acvp-post-quantum"
        )
        target["verdict"] = "pass"

    checks.equal(
        "candidate-oracle-evidence-promotion-rejected",
        ledger_errors(false_oracle_promotion),
        [
            "evidence acvp-post-quantum must remain informational until an oracle "
            "dossier and independent replay are accepted"
        ],
    )

    def missing_replay_subject_library(
        ledger: dict[str, Any], operations: dict[str, Any], snapshot: dict[str, Any]
    ) -> None:
        exact_oracle_replay_records(ledger, operations, snapshot)
        target = next(
            item
            for item in ledger["evidence"]
            if item["id"] == "xchacha-interoperability"
        )
        target["artifacts"] = [
            item
            for item in target["artifacts"]
            if item["path"] != "verification/oracle-provisioning/subject_lib.py"
        ]

    checks.equal(
        "cold-oracle-subject-library-required",
        ledger_errors(missing_replay_subject_library),
        [
            "evidence xchacha-interoperability cold replay artifact set differs "
            "from the exact contract: "
            "missing=['verification/oracle-provisioning/subject_lib.py'] unexpected=[]"
        ],
    )

    def unexpected_replay_artifact(
        ledger: dict[str, Any], operations: dict[str, Any], snapshot: dict[str, Any]
    ) -> None:
        exact_oracle_replay_records(ledger, operations, snapshot)
        target = next(
            item
            for item in ledger["evidence"]
            if item["id"] == "acvp-traditional-ec"
        )
        target["artifacts"].append(
            {"path": "tests/tests/acvp_tests.rs", "sha256": "0" * 64}
        )

    checks.equal(
        "cold-oracle-surplus-artifact-rejected",
        ledger_errors(unexpected_replay_artifact),
        [
            "evidence acvp-traditional-ec cold replay artifact set differs from "
            "the exact contract: missing=[] "
            "unexpected=['tests/tests/acvp_tests.rs']"
        ],
    )

    def unclassified(_l: Any, _o: Any, snapshot: Any) -> None:
        fresh = api_entry(
            path="fixture::new_secret", kind="function", canonical="fixture::new_secret", refs=[],
        )
        fresh.update({"surface": VERIFY.UNCLASSIFIED, "classification": VERIFY.UNCLASSIFIED})
        snapshot["entries"].append(fresh)

    errors = ledger_errors(unclassified)
    checks.includes("unclassified-export", errors, "unclassified public export: fixture::new_secret")
    checks.includes("unclassified-callable", errors, "operation-bearing callable has no atomic row: fixture::new_secret")

    def sixth_class(_l: Any, _o: Any, snapshot: Any) -> None:
        entry(snapshot, "fixture::encrypt")["classification"] = "conditionally-supported"

    checks.equal(
        "sixth-class-rejected",
        ledger_errors(sixth_class),
        ["invalid classification for public API entry: fixture::encrypt: 'conditionally-supported'"],
    )

    def expired(ledger: Any, _o: Any, _s: Any) -> None:
        next(item for item in ledger["evidence"] if item["id"] == "fixture-proof")["valid-through"] = "2030-01-01"

    checks.equal(
        "expired-evidence-release",
        ledger_errors(expired, mode="release"),
        ["expired required evidence: fixture-proof (valid through 2030-01-01, as of 2030-01-02)"],
    )

    def release_block(_l: Any, operations: Any, _s: Any) -> None:
        row(operations, "fixture.function")["release-readiness"] = "blocked"
        row(operations, "fixture.function")["known-limitation"] = "fixture blocker"

    checks.equal(
        "release-block-row",
        ledger_errors(release_block, mode="release"),
        ["release-blocked operation: fixture.function: fixture blocker"],
    )

    def missing_field(_l: Any, operations: Any, _s: Any) -> None:
        del row(operations, "fixture.function")["owner"]

    checks.equal(
        "missing-required-field",
        ledger_errors(missing_field),
        ["operation fixture.function has no owner"],
    )

    def support_mismatch(_l: Any, operations: Any, _s: Any) -> None:
        row(operations, "fixture.function")["support"] = "transitional"

    checks.equal(
        "support-classification-mismatch",
        ledger_errors(support_mismatch),
        [
            "public API classification/operation support mismatch: fixture::encrypt: "
            "supported-operation -> fixture.function/transitional"
        ],
    )

    # The positive fixture covers every executable binding grammar accepted by
    # the schema, including two independently mapped selectors on one impl.
    _, operations, _ = baseline_documents()
    witnessed = {
        value.split(":", 1)[0]
        for item in operations["operation"]
        for value in item["public-bindings"]
    }
    checks.equal(
        "all-exact-witness-kinds",
        witnessed,
        {"assoc_const", "constant", "field", "function", "macro", "static", "trait", "trait-method"},
    )

    for identifier in (
        "fixture.function", "fixture.static", "fixture.constant", "fixture.assoc_const",
        "fixture.macro", "fixture.trait", "fixture.trait.sign",
    ):
        def wrong_selector(_l: Any, operations: Any, _s: Any, identifier: str = identifier) -> None:
            target = row(operations, identifier)
            old = target["entrypoint-bindings"][0]
            kind, rest = old.split(":", 1)
            _selector, canonical = rest.split("|", 1)
            target["entrypoint-bindings"] = [f"{kind}:wrong_selector|{canonical}"]
            target["action-selectors"] = ["wrong_selector"]

        errors = ledger_errors(wrong_selector)
        checks.includes(
            f"exact-selector-{identifier}", errors,
            f"operation {identifier} did not expand every exact canonical alias",
        )

    def mixed_trait_refs(_l: Any, _o: Any, snapshot: Any) -> None:
        impl = next(item for item in snapshot["entries"] if item["kind"] == "trait_impl")
        impl["trait_method_assurance"]["verify"]["operation_refs"] = ["fixture.trait.sign"]

    errors = ledger_errors(mixed_trait_refs)
    impl_path = next(item["path"] for item in baseline_documents()[2]["entries"] if item["kind"] == "trait_impl")
    checks.includes(
        "mixed-trait-selector-exactness", errors,
        f"trait method refs differ from exact selector bindings: {impl_path}::verify",
    )
    checks.includes(
        "mixed-trait-selector-union", errors,
        f"trait impl refs differ from selector union: {impl_path}",
    )

    def unknown(kind: str, path: str, unit: str = "export") -> list[str]:
        def mutate(_l: Any, _o: Any, snapshot: Any) -> None:
            fresh = api_entry(path=path, kind=kind, canonical=path, refs=[], unit=unit)
            fresh.update({"surface": VERIFY.UNCLASSIFIED, "classification": VERIFY.UNCLASSIFIED})
            snapshot["entries"].append(fresh)
        return ledger_errors(mutate)

    for kind, path, disposition in (
        ("function", "fixture::transform_secret", "operation-bearing callable has no atomic row"),
        ("macro", "fixture::secret_macro", "operation-bearing callable has no atomic row"),
        ("assoc_const", "fixture::Secret::SIZE", "operation-bearing callable has no atomic row"),
        ("field", "fixture::Secret::bytes", "public data surface lacks an atomic row"),
    ):
        errors = unknown(kind, path, "member" if kind in {"assoc_const", "field"} else "export")
        noun = "public API member" if kind in {"assoc_const", "field"} else "public export"
        checks.includes(f"unknown-{kind}-classification", errors, f"unclassified {noun}: {path}")
        checks.includes(f"unknown-{kind}-atomic-row", errors, f"{disposition}: {path}")

    def bad_harness(ledger: Any, _o: Any, _s: Any) -> None:
        harness = next(item for item in ledger["evidence"] if item["id"] == "acvp-harness-integrity")
        harness["artifacts"] = harness["artifacts"][:-1]

    errors = ledger_errors(bad_harness)
    checks.includes(
        "acvp-harness-mutation", errors,
        "ACVP harness-integrity artifact set mismatch: missing=['tests/tests/acvp_tests.rs'], extra=[]",
    )

    def acvp_without_shared_harness(ledger: Any, operations: Any, _s: Any) -> None:
        ledger["evidence"].append(evidence("acvp-fixture-vectors", ["fixture-acvp.json"]))
        row(operations, "fixture.function")["required-evidence"] = ["acvp-fixture-vectors"]

    errors = ledger_errors(acvp_without_shared_harness)
    checks.includes(
        "acvp-row-requires-shared-harness", errors,
        "ACVP-backed operation lacks shared harness integrity: fixture.function",
    )

    vector_subject = {
        "files": [
            {"path": "tests/src/vectors/acvp_json/a.json", "sha256": "a" * 64},
            {"path": "tests/src/vectors/acvp_json/b.json", "sha256": "b" * 64},
        ],
    }
    vector_manifest = {
        "schema_version": 1,
        "source_commit": COMMIT,
        "source_tree": TREE,
        "root": "tests/src/vectors/acvp_json",
        "files": copy.deepcopy(vector_subject["files"]),
    }
    checks.equal(
        "acvp-vector-manifest-positive",
        VERIFY.validate_acvp_vector_manifest(
            vector_manifest, subject_manifest=vector_subject,
            source_commit=COMMIT, source_tree=TREE,
        ),
        [],
    )
    vector_manifest["files"][0]["sha256"] = "c" * 64
    checks.equal(
        "acvp-vector-byte-mutation",
        VERIFY.validate_acvp_vector_manifest(
            vector_manifest, subject_manifest=vector_subject,
            source_commit=COMMIT, source_tree=TREE,
        ),
        [
            "ACVP vector manifest differs from bound corpus: missing=[], stale=[], "
            "digest-mismatch=['tests/src/vectors/acvp_json/a.json']"
        ],
        )

    def unsupported_entry() -> dict[str, Any]:
        result = api_entry(
            path="fixture::X25519", kind="struct", canonical="fixture::X25519",
            refs=[], classification="intentionally-unsupported",
        )
        result.update({
            "unsupported_reason": "marker-only type; no public operation",
            "unsupported_owner": "fixture-owner",
            "unsupported_review_due": "2030-01-02",
        })
        return result

    def supported_unsupported_row(_l: Any, _o: Any, snapshot: Any) -> None:
        snapshot["entries"].append(unsupported_entry())

    checks.equal(
        "intentionally-unsupported-positive",
        ledger_errors(supported_unsupported_row),
        [],
    )
    for field, diagnostic in (
        (
            "unsupported_reason",
            "intentionally unsupported entry has no unsupported_reason: fixture::X25519",
        ),
        (
            "unsupported_owner",
            "intentionally unsupported entry has no unsupported_owner: fixture::X25519",
        ),
        (
            "unsupported_review_due",
            "intentionally unsupported entry fixture::X25519 review due must be an ISO 8601 date",
        ),
    ):
        def missing_unsupported(
            _l: Any, _o: Any, snapshot: Any, field: str = field,
        ) -> None:
            result = unsupported_entry()
            del result[field]
            snapshot["entries"].append(result)

        checks.equal(
            f"intentionally-unsupported-missing-{field}",
            ledger_errors(missing_unsupported),
            [diagnostic],
        )

    with tempfile.TemporaryDirectory(prefix="dcrypt-assurance-acvp-files-") as name:
        repo = Path(name)
        ledger, operations, snapshot = baseline_documents()
        for record in ledger["evidence"]:
            for artifact in record["artifacts"]:
                artifact_path = repo / artifact["path"]
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                artifact_path.write_text(f"fixture:{artifact['path']}\n", encoding="utf-8")
                artifact["sha256"] = VERIFY.sha256_file(artifact_path)
        errors, _metrics = VERIFY.validate_ledger(
            ledger, operations, snapshot, repo=repo,
            as_of=FIXED_DATE, mode="ci", check_paths=True,
        )
        checks.equal("acvp-harness-files-positive", errors, [])
        runner = repo / "tests/src/suites/acvp/runner.rs"
        runner.write_text("deliberately mutated harness\n", encoding="utf-8")
        errors, _metrics = VERIFY.validate_ledger(
            ledger, operations, snapshot, repo=repo,
            as_of=FIXED_DATE, mode="ci", check_paths=True,
        )
        checks.equal(
            "acvp-harness-byte-mutation",
            errors,
            [
                "evidence artifact digest mismatch: acvp-harness-integrity: "
                "tests/src/suites/acvp/runner.rs"
            ],
        )


def item(
    item_id: str,
    name: str | None,
    kind: str,
    data: Any,
    *,
    crate_id: int = 0,
    visibility: str = "public",
    attrs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": item_id,
        "crate_id": crate_id,
        "name": name,
        "visibility": visibility,
        "attrs": attrs or [],
        "docs": None,
        "inner": {kind: data},
    }


def projection_document(
    *, profile_variant: int = 1, alias_attr: str = "#[doc = \"alias\"]",
    hidden_attr: str = "#[doc(hidden)]",
) -> dict[str, Any]:
    index: dict[str, Any] = {}
    root_items = ["hidden", "cipher", "module_use", "enum_use", "trait_use", "type_use", "external_use"]
    index["0"] = item("0", "fixture", "module", {"is_crate": True, "items": root_items})
    index["hidden"] = item(
        "hidden", "hidden_secret", "function", {"sig": {"inputs": [], "output": None}},
        attrs=[hidden_attr],
    )

    impl_ids = ["impl-a", "impl-b", "impl-c"]
    index["cipher"] = item(
        "cipher", "Cipher", "struct",
        {"kind": {"plain": {"fields": [], "has_stripped_fields": False}}, "impls": impl_ids},
    )
    for offset, impl_id in enumerate(impl_ids):
        methods = [f"method-{offset}"]
        if offset == 0 and profile_variant == 2:
            methods.append("method-extra")
        for method_id in methods:
            method_name = "verify" if method_id == "method-extra" else f"op_{offset}"
            index[method_id] = item(method_id, method_name, "function", {"sig": {"inputs": [], "output": None}})
        index[impl_id] = item(
            impl_id, None, "impl",
            {
                "is_unsafe": False,
                "generics": {"params": [], "where_predicates": []},
                "provided_trait_methods": [],
                "trait": {"name": "Operation", "id": "operation-trait", "args": {"angle_bracketed": {"args": [{"type": {"primitive": str(offset)}}], "constraints": []}}, "path": "fixture::Operation"},
                "for": {"resolved_path": {"name": "Cipher", "id": "cipher", "args": {"angle_bracketed": {"args": [], "constraints": []}}}},
                "items": methods,
                "is_negative": False,
                "is_synthetic": False,
                "blanket_impl": None,
            },
        )

    index["module"] = item("module", "inner", "module", {"is_crate": False, "items": ["module_fn"]})
    index["module_fn"] = item("module_fn", "run", "function", {"sig": {"inputs": [], "output": None}})
    index["module_use"] = item("module_use", None, "use", {"source": "fixture::inner", "name": "module_alias", "id": "module", "is_glob": False}, attrs=[alias_attr])

    index["enum"] = item("enum", "Choice", "enum", {"generics": {}, "variants": ["variant"], "impls": []})
    index["variant"] = item("variant", "Some", "variant", {"kind": {"plain": {"fields": [], "has_stripped_fields": False}}, "discriminant": None})
    index["enum_use"] = item("enum_use", None, "use", {"source": "fixture::Choice", "name": "ChoiceAlias", "id": "enum", "is_glob": False}, attrs=[alias_attr])

    index["trait"] = item("trait", "Signer", "trait", {"items": ["trait_method"], "generics": {}, "bounds": [], "implementations": []})
    index["trait_method"] = item("trait_method", "sign", "function", {"sig": {"inputs": [], "output": None}})
    index["trait_use"] = item("trait_use", None, "use", {"source": "fixture::Signer", "name": "SignerAlias", "id": "trait", "is_glob": False}, attrs=[alias_attr])

    index["aliased_struct"] = item("aliased_struct", "Packet", "struct", {"kind": {"plain": {"fields": ["packet_field"], "has_stripped_fields": False}}, "impls": []})
    index["packet_field"] = item("packet_field", "bytes", "struct_field", {"type": {"slice": {"primitive": "u8"}}})
    index["type"] = item("type", "PacketType", "type_alias", {"type": {"resolved_path": {"name": "Packet", "id": "aliased_struct", "args": {"angle_bracketed": {"args": [], "constraints": []}}}}, "generics": {}})
    index["type_use"] = item("type_use", None, "use", {"source": "fixture::PacketType", "name": "PacketAlias", "id": "type", "is_glob": False}, attrs=[alias_attr])

    index["external"] = item("external", "Foreign", "struct", {"kind": {"plain": {"fields": [], "has_stripped_fields": False}}, "impls": []}, crate_id=1)
    index["external_use"] = item("external_use", None, "use", {"source": "foreign::Foreign", "name": "ForeignAlias", "id": "external", "is_glob": False}, attrs=[alias_attr])

    paths = {
        "cipher": {"path": ["fixture", "Cipher"], "kind": "struct"},
        "operation-trait": {"path": ["fixture", "Operation"], "kind": "trait"},
        "module": {"path": ["fixture", "inner"], "kind": "module"},
        "module_fn": {"path": ["fixture", "inner", "run"], "kind": "function"},
        "enum": {"path": ["fixture", "Choice"], "kind": "enum"},
        "variant": {"path": ["fixture", "Choice", "Some"], "kind": "variant"},
        "trait": {"path": ["fixture", "Signer"], "kind": "trait"},
        "trait_method": {"path": ["fixture", "Signer", "sign"], "kind": "function"},
        "type": {"path": ["fixture", "PacketType"], "kind": "type_alias"},
        "aliased_struct": {"path": ["fixture", "Packet"], "kind": "struct"},
        "packet_field": {"path": ["fixture", "Packet", "bytes"], "kind": "struct_field"},
        "external": {"path": ["foreign", "Foreign"], "kind": "struct"},
    }
    return {"root": "0", "crate_version": None, "includes_private": True, "index": index, "paths": paths}


def external_owner_document() -> dict[str, Any]:
    index = {
        "0": item("0", "crate_a", "module", {"is_crate": True, "items": ["module"]}),
        "module": item("module", "crypto", "module", {"is_crate": False, "items": ["thing"]}),
        "thing": item(
            "thing", "Thing", "struct",
            {"kind": {"plain": {"fields": ["field"], "has_stripped_fields": False}}, "impls": []},
        ),
        "field": item("field", "secret", "struct_field", {"type": {"primitive": "u8"}}),
    }
    paths = {
        "module": {"path": ["crate_a", "crypto"], "kind": "module"},
        "thing": {"path": ["crate_a", "crypto", "Thing"], "kind": "struct"},
        "field": {"path": ["crate_a", "crypto", "Thing", "secret"], "kind": "struct_field"},
    }
    return {
        "format_version": 99, "root": "0", "crate_version": None,
        "includes_private": True, "index": index, "paths": paths,
    }


def external_alias_document(
    crate_name: str, alias_name: str, source: str, *, alias_attr: str,
) -> dict[str, Any]:
    index = {
        "0": item("0", crate_name, "module", {"is_crate": True, "items": ["use"]}),
        "external": item(
            "external", "crypto", "module", {"is_crate": False, "items": []},
            crate_id=1,
        ),
        "use": item(
            "use", None, "use",
            {"source": source, "name": alias_name, "id": "external", "is_glob": False},
            attrs=[alias_attr],
        ),
    }
    return {
        "format_version": 99, "root": "0", "crate_version": None,
        "includes_private": True, "index": index,
        "paths": {"external": {"path": ["crate_a", "crypto"], "kind": "module"}},
    }


@contextlib.contextmanager
def fake_rustdoc_generation(
    documents: dict[str, dict[str, Any]],
    commands: list[list[str]] | None = None,
) -> Iterator[None]:
    saved_select = VERIFY.select_toolchain
    saved_run = VERIFY.run_command
    saved_load = VERIFY.load_json
    try:
        VERIFY.select_toolchain = lambda _repo, _ledger: "fixture"  # type: ignore[assignment]
        def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
            if commands is not None:
                commands.append(copy.deepcopy(command))
            is_text = kwargs.get("text", True)
            return subprocess.CompletedProcess(
                command, 0, "" if is_text else b"", "" if is_text else b"",
            )

        VERIFY.run_command = fake_run  # type: ignore[assignment]

        def fake_load(path: Path) -> dict[str, Any]:
            return copy.deepcopy(documents[path.stem])

        VERIFY.load_json = fake_load  # type: ignore[assignment]
        yield
    finally:
        VERIFY.select_toolchain = saved_select
        VERIFY.run_command = saved_run
        VERIFY.load_json = saved_load


def generate_external_chain(
    alias_attr: str, target_dir: Path,
    commands: list[list[str]] | None = None,
) -> list[dict[str, Any]]:
    documents = {
        "crate_a": external_owner_document(),
        "crate_b": external_alias_document(
            "crate_b", "mid", "crate_a::crypto", alias_attr=alias_attr,
        ),
        "crate_c": external_alias_document(
            "crate_c", "top", "crate_b::mid", alias_attr='#[doc = "outer"]',
        ),
    }
    policy = {
        "published-packages": ["crate-a", "crate-b", "crate-c"],
        "no-std-package-features": {"crate-a": [], "crate-b": [], "crate-c": []},
        "targets": {"native": "x86-fixture", "no-std": "thumb-fixture"},
    }
    with fake_rustdoc_generation(documents, commands):
        return VERIFY.generate_live_entries(
            ASSURANCE_DIR.parent,
            {"rustdoc-format-version": 99},
            policy,
            keep_target=target_dir,
        )


def projection_tests(checks: Checks) -> None:
    first = VERIFY.RustdocProjection(projection_document(profile_variant=1), "fixture", "p1").project()
    second = VERIFY.RustdocProjection(projection_document(profile_variant=2), "fixture", "p2").project()
    hidden = next(item for item in first if item["path"] == "fixture::hidden_secret")
    checks.equal("doc-hidden-export-inventory", hidden["kind"], "function")

    impls = [item for item in first if item["kind"] == "trait_impl"]
    checks.equal("three-trait-impls-retained", len(impls), 3)
    checks.equal("full-impl-digests-unique", len({item["impl_identity_sha256"] for item in impls}), 3)
    checks.check(
        "full-impl-digest-in-path",
        all(item["path"].endswith(item["impl_identity_sha256"] + "}") for item in impls),
    )

    # Reordering same-name impls cannot affect their complete-identity paths.
    reordered = projection_document(profile_variant=1)
    reordered["index"]["cipher"]["inner"]["struct"]["impls"].reverse()
    reordered_impls = [
        item for item in VERIFY.RustdocProjection(reordered, "fixture", "p1").project()
        if item["kind"] == "trait_impl"
    ]
    checks.equal(
        "trait-impl-order-independent",
        {(item["path"], item["canonical"]) for item in reordered_impls},
        {(item["path"], item["canonical"]) for item in impls},
    )

    p1_impl = next(item for item in impls if "op_0" in item["trait_methods"]["p1"])
    p2_impl = next(
        item for item in second
        if item["kind"] == "trait_impl" and item["impl_identity_sha256"] == p1_impl["impl_identity_sha256"]
    )
    checks.equal("cross-profile-impl-identity", p2_impl["path"], p1_impl["path"])
    checks.equal("cross-profile-method-p1", p1_impl["trait_methods"], {"p1": ["op_0"]})
    checks.equal("cross-profile-method-p2", p2_impl["trait_methods"], {"p2": ["op_0", "verify"]})

    by_path = {item["path"]: item for item in first}
    for path in (
        "fixture::module_alias::run",
        "fixture::ChoiceAlias::Some",
        "fixture::SignerAlias::sign",
        "fixture::PacketAlias::bytes",
        "fixture::ForeignAlias",
    ):
        checks.check(
            f"alias-metadata-{path}",
            bool(by_path[path].get("alias_binding_sha256", {}).get("p1")),
            f"entry lacks alias binding: {by_path[path]!r}",
        )
    checks.equal(
        "visible-canonical-reexport",
        (by_path["fixture::ForeignAlias"]["path"], by_path["fixture::ForeignAlias"]["canonical"]),
        ("fixture::ForeignAlias", "foreign::Foreign"),
    )

    changed = VERIFY.RustdocProjection(
        projection_document(profile_variant=1, alias_attr='#[deprecated = "changed"]'),
        "fixture", "p1",
    ).project()
    changed_by_path = {item["path"]: item for item in changed}
    checks.check(
        "alias-attribute-changes-binding",
        changed_by_path["fixture::ForeignAlias"]["alias_binding_sha256"]
        != by_path["fixture::ForeignAlias"]["alias_binding_sha256"],
    )

    projection = VERIFY.RustdocProjection(projection_document(), "fixture", "p1")
    projection.add("fixture::collision", "export", "function", "fixture::one", "hidden")
    try:
        projection.add("fixture::collision", "export", "function", "fixture::two", "module_fn")
    except VERIFY.AssuranceFailure as error:
        checks.equal(
            "projection-path-collision",
            str(error),
            "unresolved public path collision for fixture/p1: fixture::collision",
        )
    else:
        checks.check("projection-path-collision", False, "collision was accepted")

    # snapshot_document must discard a reviewed classification whenever the
    # declaration envelope (including attrs/deprecation/docs) changes.
    live = copy.deepcopy(hidden)
    old_snapshot = {
        "schema_version": 2,
        "source_commit": COMMIT,
        "source_tree": TREE,
        "profiles": ["p1"],
        "entries": [{
            **copy.deepcopy(live),
            "surface": "fixture-api",
            "classification": "supported-operation",
            "operation_refs": ["fixture.function"],
            "callable_disposition": "operation-bearing",
        }],
    }
    changed_hidden_projection = VERIFY.RustdocProjection(
        projection_document(hidden_attr='#[deprecated = "hidden changed"]'),
        "fixture", "p1",
    ).project()
    changed_live = next(
        item for item in changed_hidden_projection
        if item["path"] == "fixture::hidden_secret"
    )
    checks.check(
        "declaration-attribute-affects-hash",
        changed_live["declaration_sha256"] != live["declaration_sha256"],
    )
    refreshed = VERIFY.snapshot_document(
        repo=ASSURANCE_DIR.parent,
        ledger={"source-commit": COMMIT, "source-tree": TREE},
        policy_path=ASSURANCE_DIR / "IMPLEMENTATION-BASELINE.md",
        entries=[changed_live], old_snapshot=old_snapshot,
    )["entries"][0]
    checks.equal("declaration-change-resets-surface", refreshed["surface"], VERIFY.UNCLASSIFIED)
    checks.equal("declaration-change-resets-class", refreshed["classification"], VERIFY.UNCLASSIFIED)
    checks.equal("declaration-change-resets-refs", refreshed["operation_refs"], [])

    # Exercise the full external-alias closure (not merely the per-crate
    # projection): owner -> intermediate alias -> facade alias.  The facade's
    # visible spelling differs from its canonical owner and must bind both use
    # declarations, so changing the intermediate declaration changes the
    # facade descendant digest.
    with tempfile.TemporaryDirectory(prefix="dcrypt-assurance-rustdoc-chain-") as name:
        rustdoc_commands: list[list[str]] = []
        before = generate_external_chain(
            '#[doc = "middle-v1"]', Path(name) / "before", rustdoc_commands,
        )
        after = generate_external_chain('#[deprecated = "middle-v2"]', Path(name) / "after")
    before_entry = next(
        item for item in before
        if item["package"] == "crate-c" and item["path"] == "crate_c::top::Thing"
    )
    after_entry = next(
        item for item in after
        if item["package"] == "crate-c" and item["path"] == "crate_c::top::Thing"
    )
    checks.equal(
        "three-crate-visible-canonical",
        (before_entry["path"], before_entry["canonical"]),
        ("crate_c::top::Thing", "crate_a::crypto::Thing"),
    )
    checks.check(
        "three-crate-intermediate-binding",
        before_entry["alias_binding_sha256"] != after_entry["alias_binding_sha256"],
        "changing the intermediate public use did not invalidate the facade alias",
    )
    checks.equal("mocked-rustdoc-command-count", len(rustdoc_commands), 6)
    for offset, command in enumerate(rustdoc_commands):
        delimiter = command.index("--")
        checks.check(
            f"mocked-rustdoc-locked-offline-{offset}",
            command[0] == "cargo"
            and "rustdoc" in command[:delimiter]
            and "--locked" in command[:delimiter]
            and "--offline" in command[:delimiter],
            repr(command),
        )
        checks.check(
            f"mocked-rustdoc-hidden-items-{offset}",
            "--document-hidden-items" in command[delimiter + 1:],
            repr(command),
        )


def git(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *command], cwd=cwd, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        },
    )


@contextlib.contextmanager
def subject_repo() -> Iterator[tuple[Path, dict[str, Any], str, str]]:
    with tempfile.TemporaryDirectory(prefix="dcrypt-assurance-subject-") as name:
        repo = Path(name)
        (repo / "src").mkdir()
        (repo / ".gitignore").write_text("ignored.bin\n", encoding="utf-8")
        (repo / "Cargo.toml").write_text(
            "[package]\nname='fixture'\nversion='0.0.0'\nedition='2021'\n",
            encoding="utf-8",
        )
        (repo / "src" / "lib.rs").write_text("pub fn fixture() {}\n", encoding="utf-8")
        (repo / "src" / "one.inc").write_text("pub fn one() {}\n", encoding="utf-8")
        (repo / "src" / "two.rs").write_text("pub fn two() {}\n", encoding="utf-8")
        (repo / "src" / "blob.bin").write_bytes(b"fixture\x00bytes")
        (repo / "src" / "nonstandard.lib").write_text(
            "pub fn nonstandard_library_entry() {}\n", encoding="utf-8",
        )
        (repo / "src" / "build_payload.rs").write_text(
            "fn main() {}\n", encoding="utf-8",
        )
        if git(["init", "-q"], repo).returncode != 0:
            raise RuntimeError("cannot initialize subject self-test Git repository")
        git(["config", "user.name", "Assurance Fixture"], repo)
        git(["config", "user.email", "assurance@example.invalid"], repo)
        git(["config", "commit.gpgsign", "false"], repo)
        git(["config", "core.hooksPath", os.devnull], repo)
        git(["add", "."], repo)
        committed = git(["commit", "-q", "-m", "fixture"], repo)
        if committed.returncode != 0:
            raise RuntimeError(f"cannot commit subject fixture: {committed.stderr}")
        commit = git(["rev-parse", "HEAD"], repo).stdout.strip()
        tree = git(["rev-parse", "HEAD^{tree}"], repo).stdout.strip()
        manifest = VERIFY.subject_manifest_document(repo=repo, source_commit=commit, source_tree=tree)
        yield repo, manifest, commit, tree


def subject_errors_for_source(source: str) -> list[str]:
    with subject_repo() as (repo, manifest, _commit, _tree):
        (repo / "src" / "lib.rs").write_text(source, encoding="utf-8")
        return VERIFY.validate_source_policy(repo, manifest, metadata_target_paths={"src/lib.rs"})


def subject_tests(checks: Checks) -> None:
    with subject_repo() as (repo, manifest, commit, tree):
        checks.equal(
            "subject-positive",
            VERIFY.validate_subject_manifest(
                manifest, repo=repo, source_commit=commit, source_tree=tree,
            ),
            [],
        )
        checks.equal("source-policy-positive", VERIFY.validate_source_policy(repo, manifest), [])

        original = (repo / "src" / "lib.rs").read_bytes()
        (repo / "src" / "lib.rs").write_text("pub fn mutated() {}\n", encoding="utf-8")
        errors = VERIFY.validate_subject_manifest(
            manifest, repo=repo, source_commit=commit, source_tree=tree,
        )
        checks.includes("subject-current-blob-mutation", errors, "subject manifest current digest mismatch: src/lib.rs")
        (repo / "src" / "lib.rs").write_bytes(original)

        stale = copy.deepcopy(manifest)
        next(item for item in stale["files"] if item["path"] == "src/lib.rs")["sha256"] = "f" * 64
        errors = VERIFY.validate_subject_manifest(stale, repo=repo, source_commit=commit, source_tree=tree)
        checks.includes("subject-stale-bound-blob", errors, "subject manifest bound-commit digest mismatch: src/lib.rs")
        checks.includes("subject-stale-current-blob", errors, "subject manifest current digest mismatch: src/lib.rs")

        mode = (repo / "src" / "lib.rs").stat().st_mode
        os.chmod(repo / "src" / "lib.rs", mode | 0o111)
        errors = VERIFY.validate_subject_manifest(manifest, repo=repo, source_commit=commit, source_tree=tree)
        checks.includes("subject-mode-mutation", errors, "subject manifest current mode mismatch: src/lib.rs")
        os.chmod(repo / "src" / "lib.rs", mode)

        (repo / "ignored.bin").write_bytes(b"ignored but security relevant")
        errors = VERIFY.validate_source_policy(repo, manifest)
        checks.includes("ignored-input-rejected", errors, "ignored or untracked security-relevant input: ignored.bin")
        (repo / "ignored.bin").unlink()

        (repo / "src" / "link.rs").symlink_to("lib.rs")
        errors = VERIFY.validate_source_policy(repo, manifest)
        checks.includes("source-symlink-rejected", errors, "symlink is not permitted in assurance subject: src/link.rs")
        (repo / "src" / "link.rs").unlink()

        original_path = repo / "src" / "lib.rs"
        original_path.unlink()
        original_path.symlink_to("two.rs")
        path_errors: list[str] = []
        VERIFY.safe_repo_file(repo, "src/lib.rs", "fixture source", path_errors)
        checks.equal("final-component-symlink", path_errors, ["fixture source contains a symlink component: src/lib.rs"])

    with subject_repo() as (repo, manifest, commit, tree):
        (repo / "src" / "lib.rs").unlink()
        errors = VERIFY.validate_subject_manifest(
            manifest, repo=repo, source_commit=commit, source_tree=tree,
        )
        checks.equal(
            "subject-removed-file",
            errors,
            ["subject file src/lib.rs does not name a regular file: src/lib.rs"],
        )

    with subject_repo() as (repo, _manifest, _commit, _tree):
        (repo / "src").rename(repo / "real-src")
        (repo / "src").symlink_to("real-src", target_is_directory=True)
        path_errors = []
        VERIFY.safe_repo_file(repo, "src/lib.rs", "fixture source", path_errors)
        checks.equal(
            "parent-component-symlink",
            path_errors,
            ["fixture source contains a symlink component: src/lib.rs"],
        )

    with subject_repo() as (repo, manifest, commit, tree):
        (repo / "src" / "new.rs").write_text("pub fn new() {}\n", encoding="utf-8")
        git(["add", "src/new.rs"], repo)
        errors = VERIFY.validate_subject_manifest(manifest, repo=repo, source_commit=commit, source_tree=tree)
        checks.includes(
            "subject-added-index-path", errors,
            "subject manifest current/bound path set mismatch: new=['src/new.rs'], removed=[]",
        )

    with subject_repo() as (repo, manifest, _commit, _tree):
        metadata = {
            "workspace_members": ["fixture 0.0.0"],
            "packages": [{
                "id": "fixture 0.0.0",
                "manifest_path": str(repo / "Cargo.toml"),
                "targets": [{
                    "kind": ["custom-build"],
                    "src_path": str(repo / "target" / "generated.rs"),
                }],
            }],
        }
        (repo / "target").mkdir()
        (repo / "target" / "generated.rs").write_text("fn main() {}\n", encoding="utf-8")
        errors, _targets = VERIFY.validate_metadata_source_paths(metadata, repo=repo, manifest=manifest)
        checks.includes(
            "custom-build-target-rejected", errors,
            f"Cargo build scripts are not permitted by the Leg 2 inventory: {repo / 'target' / 'generated.rs'}",
        )
        checks.includes("custom-target-mutable-root", errors, "Cargo target source uses a mutable/output root: target/generated.rs")
        checks.includes("custom-target-unbound", errors, "Cargo target source is absent from the bound subject: target/generated.rs")

    with subject_repo() as (repo, manifest, _commit, _tree):
        package_id = "fixture 0.0.0"

        def metadata_for(source: Path, kind: str) -> dict[str, Any]:
            return {
                "workspace_members": [package_id],
                "packages": [{
                    "id": package_id,
                    "manifest_path": str(repo / "Cargo.toml"),
                    "targets": [{"kind": [kind], "src_path": str(source)}],
                }],
            }

        bound_nonstandard = repo / "src" / "nonstandard.lib"
        errors, targets = VERIFY.validate_metadata_source_paths(
            metadata_for(bound_nonstandard, "lib"), repo=repo, manifest=manifest,
        )
        checks.equal("tracked-nonstandard-lib-source", errors, [])
        checks.equal("tracked-nonstandard-lib-target", targets, {"src/nonstandard.lib"})

        unbound_nonstandard = repo / "src" / "unbound.payload"
        unbound_nonstandard.write_text(
            "pub fn post_freeze_library_entry() {}\n", encoding="utf-8",
        )
        git(["add", "src/unbound.payload"], repo)
        errors, targets = VERIFY.validate_metadata_source_paths(
            metadata_for(unbound_nonstandard, "lib"), repo=repo, manifest=manifest,
        )
        checks.equal(
            "tracked-but-unbound-lib-source",
            errors,
            ["Cargo target source is absent from the bound subject: src/unbound.payload"],
        )
        checks.equal("tracked-but-unbound-lib-target", targets, {"src/unbound.payload"})

        bound_build_payload = repo / "src" / "build_payload.rs"
        errors, targets = VERIFY.validate_metadata_source_paths(
            metadata_for(bound_build_payload, "custom-build"),
            repo=repo, manifest=manifest,
        )
        checks.equal(
            "bound-custom-build-payload-rejected",
            errors,
            [
                "Cargo build scripts are not permitted by the Leg 2 inventory: "
                f"{bound_build_payload}"
            ],
        )
        checks.equal("bound-custom-build-target", targets, {"src/build_payload.rs"})

    policy_cases = [
        (
            "negative-feature",
            '#[cfg(not(feature = "secret"))]\npub fn hidden() {}\n',
            "uncovered negative feature cfg in public-API subject: src/lib.rs:secret",
        ),
        (
            "nested-negative-feature",
            '#[cfg(all(unix, not(any(feature = "secret", feature = "std"))))]\npub fn hidden() {}\n',
            "uncovered negative feature cfg in public-API subject: src/lib.rs:secret",
        ),
        (
            "raw-negative-feature",
            '#[cfg(not(feature = r#"secret"#))]\npub fn hidden() {}\n',
            "raw-string feature cfg is not permitted: src/lib.rs",
        ),
        (
            "comment-obfuscated-cfg",
            '#[cfg(/* split */ not(feature = "secret"))]\npub fn hidden() {}\n',
            "comments are not permitted in cfg attributes: src/lib.rs",
        ),
        (
            "doc-cfg",
            '#[cfg(doc)]\npub fn hidden() {}\n',
            "unmodelled rustdoc-asymmetric cfg in public-API subject: src/lib.rs",
        ),
        (
            "target-cfg",
            '#[cfg(target_arch = "x86_64")]\npub fn hidden() {}\n',
            "unmodelled target-conditioned public API cfg: src/lib.rs",
        ),
        (
            "windows-target-cfg",
            '#[cfg(target_os = "windows")]\npub fn hidden() {}\n',
            "unmodelled target-conditioned public API cfg: src/lib.rs",
        ),
        (
            "macos-target-cfg",
            '#[cfg(target_os = "macos")]\npub fn hidden() {}\n',
            "unmodelled target-conditioned public API cfg: src/lib.rs",
        ),
        (
            "msvc-target-cfg",
            '#[cfg(target_env = "msvc")]\npub fn hidden() {}\n',
            "unmodelled target-conditioned public API cfg: src/lib.rs",
        ),
        (
            "debug-cfg",
            '#[cfg(not(debug_assertions))]\npub fn hidden() {}\n',
            "unmodelled release/debug cfg in public-API subject: src/lib.rs",
        ),
        (
            "absolute-include",
            'include!("/tmp/dcrypt-assurance-escape.rs");\n',
            "include! uses an absolute compiler input: src/lib.rs:/tmp/dcrypt-assurance-escape.rs",
        ),
        (
            "escaping-include",
            'include!("../../escape.rs");\n',
            "include! escapes the repository: src/lib.rs:../../escape.rs",
        ),
        (
            "missing-include",
            'include_str!("missing.txt");\n',
            "include_str! input is absent from the bound subject: src/lib.rs:src/missing.txt",
        ),
        (
            "excluded-include",
            'include_bytes!("../target/generated.bin");\n',
            "include_bytes! uses an excluded input: src/lib.rs:target/generated.bin",
        ),
        (
            "unapproved-env",
            'const TOKEN: &str = env!("DCRYPT_SECRET");\n',
            "unapproved compile-time environment input: src/lib.rs:DCRYPT_SECRET",
        ),
        (
            "dynamic-env",
            'const TOKEN: &str = option_env!(concat!("DCRYPT", "_SECRET"));\n',
            "unparseable compile-time environment lookup: src/lib.rs",
        ),
        (
            "comment-obfuscated-include",
            'include /* split */ !("one.inc");\n',
            "comments may not split compiler-input/cfg syntax: src/lib.rs",
        ),
        (
            "nested-path",
            '#[cfg_attr(feature = "std", path = "one.inc")]\nmod one;\n',
            "conditional/nested #[path] is not permitted: src/lib.rs",
        ),
        (
            "raw-path",
            '#[path = r#"one.inc"#]\nmod one;\n',
            "unparseable #[path] compiler input: src/lib.rs",
        ),
    ]
    for name, source, diagnostic in policy_cases:
        checks.includes(name, subject_errors_for_source(source), diagnostic)

    checks.equal(
        "allowed-negative-and-env",
        subject_errors_for_source(
            '#[cfg(not(any(feature = "std", feature = "alloc")))]\n'
            'const ROOT: &str = env!("CARGO_MANIFEST_DIR");\n'
            'pub fn fixture() {}\n'
        ),
        [],
    )

    with subject_repo() as (repo, manifest, _commit, _tree):
        (repo / "src" / "lib.rs").write_text('include!("one.inc");\n', encoding="utf-8")
        (repo / "src" / "one.inc").write_text('include!("two.rs");\n', encoding="utf-8")
        (repo / "src" / "two.rs").write_text('const X: &str = env!("TWO_HOP_SECRET");\n', encoding="utf-8")
        errors = VERIFY.validate_source_policy(repo, manifest, metadata_target_paths={"src/lib.rs"})
        checks.includes(
            "two-hop-include-scanned", errors,
            "unapproved compile-time environment input: src/two.rs:TWO_HOP_SECRET",
        )


@contextlib.contextmanager
def clean_build_environment() -> Iterator[None]:
    saved = os.environ.copy()
    try:
        for name in list(os.environ):
            if name in VERIFY.BUILD_SHAPING_ENV_EXACT or VERIFY.BUILD_SHAPING_ENV_PATTERN.fullmatch(name):
                os.environ.pop(name, None)
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def build_preflight_tests(checks: Checks) -> None:
    with tempfile.TemporaryDirectory(prefix="dcrypt-assurance-preflight-") as name:
        repo = Path(name) / "repo"
        repo.mkdir()
        cargo_home = Path(name) / "cargo-home"
        cargo_home.mkdir()
        with clean_build_environment():
            os.environ["CARGO_HOME"] = str(cargo_home)
            checks.equal("build-preflight-clean", VERIFY.build_environment_preflight(repo), [])
            os.environ["RUSTFLAGS"] = "--cfg injected"
            checks.equal(
                "build-preflight-env",
                VERIFY.build_environment_preflight(repo),
                ["build-shaping environment is not permitted: RUSTFLAGS"],
            )

            calls: list[list[str]] = []
            original = VERIFY.run_command
            VERIFY.run_command = lambda command, **_kwargs: calls.append(command)  # type: ignore[assignment]
            stderr = io.StringIO()
            try:
                with contextlib.redirect_stderr(stderr):
                    result = VERIFY.main(["--repo", str(repo), "--ledger", str(repo / "missing.toml")])
            finally:
                VERIFY.run_command = original
            checks.equal("preflight-main-fails", result, 1)
            checks.equal("preflight-command-spy", calls, [])
            checks.includes(
                "preflight-main-diagnostic", [stderr.getvalue().strip()],
                "error: build-shaping environment is not permitted: RUSTFLAGS",
            )
            os.environ.pop("RUSTFLAGS")

            for variable in (
                "CARGO_ENCODED_RUSTDOCFLAGS",
                "CARGO_BUILD_RUSTDOCFLAGS",
            ):
                os.environ[variable] = "--cfg\x1fassurance_injected"
                checks.equal(
                    f"build-preflight-{variable.lower()}",
                    VERIFY.build_environment_preflight(repo),
                    [f"build-shaping environment is not permitted: {variable}"],
                )
                os.environ.pop(variable)

            (repo / ".cargo").mkdir()
            config = repo / ".cargo" / "config.toml"
            config.write_text("[build]\nrustflags=['--cfg', 'injected']\n", encoding="utf-8")
            errors = VERIFY.build_environment_preflight(repo)
            checks.equal(
                "ambient-cargo-config",
                errors,
                [f"ambient Cargo configuration is not permitted: {config}"],
            )
            config.unlink()
            (repo / ".cargo").rmdir()

            external_cargo_home = Path(name) / "external-cargo-home"
            external_cargo_home.mkdir()
            external_config = external_cargo_home / "config.toml"
            external_config.write_text(
                "[build]\nrustdocflags=['--cfg', 'external_injected']\n",
                encoding="utf-8",
            )
            os.environ["CARGO_HOME"] = str(external_cargo_home)
            checks.equal(
                "external-cargo-home-config",
                VERIFY.build_environment_preflight(repo),
                [f"ambient Cargo configuration is not permitted: {external_config}"],
            )


def verifier_generator_order_tests(checks: Checks) -> None:
    """Prove normal verification checks generated state once, before inventory."""

    with tempfile.TemporaryDirectory(prefix="dcrypt-assurance-main-order-") as name:
        repo = Path(name) / "repo"
        ledger_dir = repo / "assurance"
        ledger_dir.mkdir(parents=True)
        ledger_path = ledger_dir / "ledger.toml"
        generator_path = ledger_dir / "generator.py"
        curated_path = ledger_dir / "curated.toml"
        generator_path.write_text("raise SystemExit(99)\n", encoding="utf-8")
        curated_path.write_text("schema-version = 2\n", encoding="utf-8")
        ledger_path.write_text(
            "schema-version = 2\n"
            'ledger-generator = "generator.py"\n'
            'curated-operations = "curated.toml"\n',
            encoding="utf-8",
        )
        cargo_home = Path(name) / "cargo-home"
        cargo_home.mkdir()

        commands: list[tuple[list[str], Path]] = []
        later_calls: list[str] = []
        saved = {
            "run_command": VERIFY.run_command,
            "select_toolchain": VERIFY.select_toolchain,
            "cargo_metadata": VERIFY.cargo_metadata,
            "generate_live_entries": VERIFY.generate_live_entries,
        }

        def fail_generator(
            command: list[str], *, cwd: Path, **_kwargs: Any,
        ) -> subprocess.CompletedProcess[str]:
            commands.append((copy.deepcopy(command), cwd))
            return subprocess.CompletedProcess(command, 1, "", "forced generator drift")

        def should_not_run(label: str) -> Callable[..., Any]:
            def spy(*_args: Any, **_kwargs: Any) -> Any:
                later_calls.append(label)
                raise AssertionError(f"{label} ran after failed generator check")
            return spy

        try:
            VERIFY.run_command = fail_generator
            VERIFY.select_toolchain = should_not_run("toolchain")
            VERIFY.cargo_metadata = should_not_run("metadata")
            VERIFY.generate_live_entries = should_not_run("live-inventory")
            stderr = io.StringIO()
            with clean_build_environment():
                os.environ["CARGO_HOME"] = str(cargo_home)
                with contextlib.redirect_stderr(stderr):
                    result = VERIFY.main([
                        "--repo", str(repo),
                        "--ledger", str(ledger_path),
                    ])
        finally:
            for key, value in saved.items():
                setattr(VERIFY, key, value)

        checks.equal("normal-generator-failure-return", result, 1)
        checks.equal(
            "normal-generator-check-exact-once",
            commands,
            [
                (
                    [sys.executable, "-B", str(generator_path), "--check"],
                    repo.resolve(),
                )
            ],
        )
        checks.equal("normal-generator-fail-before-inventory", later_calls, [])
        checks.equal(
            "normal-generator-failure-diagnostic",
            stderr.getvalue().strip(),
            "error: assurance generator reproducibility check failed: forced generator drift",
        )


@contextlib.contextmanager
def patched_generator_root(root: Path) -> Iterator[None]:
    names = (
        "ROOT", "CURATED_PATH", "OPS_PATH", "SNAPSHOT_PATH", "DOC_PATH",
        "ACVP_VECTOR_MANIFEST_PATH", "render_acvp_vector_manifest",
        "SURFACE_BY_PACKAGE",
    )
    saved = {name: getattr(GENERATE, name) for name in names}
    try:
        GENERATE.ROOT = root
        GENERATE.CURATED_PATH = root / "curated-operations.toml"
        GENERATE.OPS_PATH = root / "atomic-operations.toml"
        GENERATE.SNAPSHOT_PATH = root / "public-api-snapshot.json"
        GENERATE.DOC_PATH = root / "SUPPORTED-ALGORITHMS.md"
        GENERATE.ACVP_VECTOR_MANIFEST_PATH = root / "acvp-vector-manifest.json"
        GENERATE.render_acvp_vector_manifest = lambda: "{\"fixture\":true}\n"
        GENERATE.SURFACE_BY_PACKAGE = {
            **saved["SURFACE_BY_PACKAGE"],
            "fixture": "fixture-api",
        }
        yield
    finally:
        for name, value in saved.items():
            setattr(GENERATE, name, value)


def generator_drift_tests(checks: Checks) -> None:
    with tempfile.TemporaryDirectory(prefix="dcrypt-assurance-generator-") as name:
        root = Path(name)
        canonical = "fixture::encrypt"
        path = canonical
        curated = operation(
            "fixture.encrypt", kind="function", selector="encrypt",
            canonical=canonical, path=path,
        )
        for field in GENERATE.DERIVED_FIELDS:
            curated.pop(field)
        snapshot = {
            "schema_version": 2,
            "source_commit": COMMIT,
            "source_tree": TREE,
            "profiles": [PROFILE],
            "entries": [api_entry(
                path=path, kind="function", canonical=canonical,
                refs=["fixture.encrypt"],
            )],
        }
        with patched_generator_root(root):
            operations = [copy.deepcopy(curated)]
            for field in GENERATE.DERIVED_FIELDS:
                operations[0][field] = []
            GENERATE.initialize_snapshot_classifications(snapshot["entries"])
            GENERATE.expand(operations, snapshot["entries"])
            (root / "curated-operations.toml").write_text(
                GENERATE.render_curated_toml([curated]), encoding="utf-8",
            )
            (root / "atomic-operations.toml").write_text(
                GENERATE.render_toml(operations), encoding="utf-8",
            )
            (root / "public-api-snapshot.json").write_text(
                GENERATE.render_snapshot(snapshot), encoding="utf-8",
            )
            (root / "SUPPORTED-ALGORITHMS.md").write_text(
                GENERATE.render_doc(operations, snapshot["entries"]), encoding="utf-8",
            )
            (root / "acvp-vector-manifest.json").write_text(
                '{"fixture":true}\n', encoding="utf-8",
            )
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                clean = GENERATE.main(["--check"])
            checks.equal("generator-check-positive", clean, 0)
            checks.equal("generator-check-positive-stderr", stderr.getvalue(), "")

            with (root / "SUPPORTED-ALGORITHMS.md").open("a", encoding="utf-8") as target:
                target.write("deliberate drift\n")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                drift = GENERATE.main(["--check"])
            checks.equal("generator-drift-return", drift, 1)
            checks.equal(
                "generator-drift-diagnostic",
                stderr.getvalue().strip(),
                "assurance generation drift: SUPPORTED-ALGORITHMS.md",
            )


def main() -> int:
    checks = Checks()
    ledger_validation_tests(checks)
    projection_tests(checks)
    subject_tests(checks)
    build_preflight_tests(checks)
    verifier_generator_order_tests(checks)
    generator_drift_tests(checks)
    if checks.failures:
        for failure in checks.failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"assurance adversarial self-test failed ({len(checks.failures)}/{checks.count})", file=sys.stderr)
        return 1
    print(f"assurance adversarial self-test passed ({checks.count} deterministic checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
