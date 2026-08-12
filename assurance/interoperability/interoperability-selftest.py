#!/usr/bin/env python3
"""Adversarial negative fixtures for the interoperability completeness gate."""

from __future__ import annotations

import copy
import datetime as dt
from pathlib import Path
import tempfile

from interop_lib import (
    MATRIX_PATH,
    REPO_ROOT,
    ValidationError,
    build_matrix,
    discover_plain_tree_files,
    full_validation,
    load_toml,
    load_inputs,
    record_sha256,
    safe_repo_file,
    sha256_path,
    validate_dossiers,
    validate_isolation,
    validate_json_schema_instance,
    validate_matrix,
    validate_overrides,
    validate_policy,
    validate_source_graph,
)


AS_OF = dt.date(2026, 8, 11)


def main() -> int:
    inputs = load_inputs()
    expected, baseline_errors = full_validation(inputs)
    if baseline_errors:
        for error in baseline_errors:
            print(f"SELFTEST BASELINE ERROR: {error}")
        return 1
    failures: list[str] = []
    passed = 0

    def expect_error(name: str, errors: list[str], needle: str) -> None:
        nonlocal passed
        if not errors:
            failures.append(f"{name}: mutation passed unexpectedly")
        elif not any(needle in error for error in errors):
            failures.append(f"{name}: expected {needle!r}, got {errors[:5]!r}")
        else:
            passed += 1

    def expect_exception(name: str, action, needle: str) -> None:
        nonlocal passed
        try:
            action()
        except ValidationError as exc:
            if needle in str(exc):
                passed += 1
            else:
                failures.append(f"{name}: expected {needle!r}, got {str(exc)!r}")
        else:
            failures.append(f"{name}: mutation passed unexpectedly")

    def matrix_case(name: str, mutate, needle: str) -> None:
        candidate = copy.deepcopy(expected)
        mutate(candidate)
        expect_error(name, validate_matrix(candidate, expected, as_of=AS_OF), needle)

    matrix_case("missing matrix row", lambda d: d["rows"].pop(), "differs from deterministic regeneration")
    matrix_case(
        "duplicate matrix row",
        lambda d: d["rows"].append(copy.deepcopy(d["rows"][0])),
        "duplicate matrix row id",
    )

    def add_extra_row(candidate):
        row = copy.deepcopy(candidate["rows"][0])
        row["key"]["case_id"] = "unexpected-extra-case"
        row["row_id"] = "interop." + record_sha256({"row_kind": row["row_kind"], "key": row["key"]})
        candidate["rows"].append(row)

    matrix_case("unexpected extra matrix row", add_extra_row, "differs from deterministic regeneration")
    matrix_case(
        "stale row expiry",
        lambda d: d["rows"][0].__setitem__("expiry", "2026-08-10"),
        "expiry is stale",
    )
    expect_error(
        "matrix rows expire against current UTC date rather than static policy as-of",
        validate_matrix(expected, expected, as_of=dt.date(2026, 11, 10)),
        "matrix.rows[0].expiry is stale",
    )
    stale_gap_errors = validate_matrix(expected, expected, as_of=dt.date(2026, 11, 10))
    expect_error(
        "matrix gaps expire against current UTC date rather than static policy as-of",
        stale_gap_errors,
        "unreviewed_gaps.items[0].expiry is stale",
    )
    matrix_case(
        "missing row owner",
        lambda d: d["rows"][0].pop("owner"),
        "missing required keys",
    )
    matrix_case(
        "missing row reviewer",
        lambda d: d["rows"][0].pop("reviewer"),
        "missing required keys",
    )
    matrix_case(
        "missing row deadline",
        lambda d: d["rows"][0].pop("deadline"),
        "missing required keys",
    )
    matrix_case(
        "corrupt matrix expected output",
        lambda d: d["counts"].__setitem__("passing_operation_atoms", 1),
        "differs from deterministic regeneration",
    )
    matrix_case(
        "corrupt gap digest",
        lambda d: d["unreviewed_gaps"].__setitem__("set_sha256", "0" * 64),
        "gap set digest mismatch",
    )
    matrix_case(
        "missing unreviewed gap",
        lambda d: d["unreviewed_gaps"]["items"].pop(),
        "gap set digest mismatch",
    )
    matrix_case(
        "corrupt vector or corpus identifier",
        lambda d: d["rows"][0]["corpus_test_identifiers"].append("mutated-vector-id"),
        "differs from deterministic regeneration",
    )
    matrix_case(
        "corrupt oracle provenance summary",
        lambda d: d["oracle_dossiers"][0].__setitem__("record_sha256", "0" * 64),
        "differs from deterministic regeneration",
    )
    matrix_case(
        "missing verification closure package",
        lambda d: d["verification_external_closure"]["packages"].pop(),
        "closure package count mismatch",
    )
    matrix_case(
        "corrupt verification closure digest",
        lambda d: d["verification_external_closure"].__setitem__("set_sha256", "0" * 64),
        "closure digest mismatch",
    )
    missing_direction = copy.deepcopy(expected)
    missing_direction["rows"][0]["key"].pop("direction")
    expect_error(
        "matrix schema requires direction in every canonical key",
        validate_json_schema_instance(
            missing_direction,
            inputs["matrix_schema"],
            label="matrix-schema-fixture",
        ),
        "missing JSON Schema required properties",
    )
    schema_with_unknown_keyword = copy.deepcopy(inputs["matrix_schema"])
    schema_with_unknown_keyword["x-unreviewed-validation"] = True
    expect_error(
        "unsupported schema validation keyword fails closed",
        validate_json_schema_instance(
            expected,
            schema_with_unknown_keyword,
            label="matrix-schema-fixture",
        ),
        "unsupported validation keywords",
    )

    new_operation = copy.deepcopy(inputs)
    operation = copy.deepcopy(new_operation["atomic"]["operation"][0])
    operation["id"] = "selftest.new-public-operation"
    operation["public-paths"] = ["selftest::new_public_operation"]
    operation["entrypoints"] = ["selftest::new_public_operation"]
    new_operation["atomic"]["operation"].append(operation)
    entry = copy.deepcopy(new_operation["snapshot"]["entries"][0])
    entry.update(
        {
            "package": operation["crate"],
            "path": "selftest::new_public_operation",
            "canonical": "selftest::new_public_operation",
            "operation_refs": [operation["id"]],
            "profiles": [new_operation["snapshot"]["profiles"][0]],
        }
    )
    new_operation["snapshot"]["entries"].append(entry)
    expect_error("new public operation requires matrix review", validate_source_graph(new_operation), "count drift")

    family_removed = copy.deepcopy(inputs["policy"])
    family_removed["required-family"] = family_removed["required-family"][1:]
    family_removed["expected"]["curated-operation-atoms"] = inputs["policy"]["expected"]["curated-operation-atoms"]
    expect_error(
        "mandatory family cannot be removed while rebasing aggregates",
        validate_policy(family_removed),
        "mandatory interoperability family mapping mismatch",
    )
    promotion_enabled = copy.deepcopy(inputs["policy"])
    promotion_enabled["evidence-promotion-enabled"] = True
    expect_error(
        "policy cannot enable evidence promotion in schema v1",
        validate_policy(promotion_enabled),
        "evidence-promotion-enabled must remain false",
    )

    dossiers = inputs["dossiers"]

    def dossier_errors(candidate):
        return validate_dossiers(
            candidate,
            policy=inputs["policy"],
            verification_manifest=inputs["verification_manifest"],
            verification_lock=inputs["verification_lock"],
            root=REPO_ROOT,
        )

    duplicate = copy.deepcopy(dossiers)
    duplicate["oracle"].append(copy.deepcopy(duplicate["oracle"][0]))
    expect_error("duplicate dossier", dossier_errors(duplicate), "duplicate oracle dossier id")

    missing_owner = copy.deepcopy(dossiers)
    missing_owner["oracle"][0].pop("owner")
    expect_error("missing dossier owner", dossier_errors(missing_owner), "missing required keys")
    expect_error(
        "dossier schema semantically requires owner",
        validate_json_schema_instance(
            missing_owner,
            inputs["dossier_schema"],
            label="dossier-schema-fixture",
        ),
        "missing JSON Schema required properties",
    )

    missing_expiry = copy.deepcopy(dossiers)
    missing_expiry["oracle"][0].pop("expiry")
    expect_error("missing dossier expiry", dossier_errors(missing_expiry), "missing required keys")
    expect_error(
        "dossiers expire against current UTC date rather than static policy as-of",
        validate_dossiers(
            dossiers,
            policy=inputs["policy"],
            verification_manifest=inputs["verification_manifest"],
            verification_lock=inputs["verification_lock"],
            root=REPO_ROOT,
            validation_date=dt.date(2026, 11, 10),
        ),
        "expiry is stale",
    )

    unknown_field = copy.deepcopy(dossiers)
    unknown_field["oracle"][0]["unexpected"] = "forbidden"
    expect_error("unexpected dossier field", dossier_errors(unknown_field), "unexpected keys")

    unpinned_manifest = copy.deepcopy(inputs["verification_manifest"])
    unpinned_manifest["dev-dependencies"]["bls12_381"]["version"] = "^0.8.0"
    expect_error(
        "unpinned oracle dependency",
        validate_dossiers(
            dossiers,
            policy=inputs["policy"],
            verification_manifest=unpinned_manifest,
            verification_lock=inputs["verification_lock"],
            root=REPO_ROOT,
        ),
        "not exactly pinned",
    )

    checksum = copy.deepcopy(dossiers)
    checksum["oracle"][0]["archive-sha256"] = "0" * 64
    expect_error("oracle archive checksum drift", dossier_errors(checksum), "drifts from verification/Cargo.lock")

    def coherent_self_attested_bls_promotion() -> dict:
        candidate = copy.deepcopy(dossiers)
        record = candidate["oracle"][0]
        record.update(
            {
                "status": "accepted",
                "provenance-status": "complete",
                "source-commit-provenance": "independently-verified",
                "acquisition-record": "assurance/interoperability/README.md",
                "license-file-sha256": [
                    "README.md:" + sha256_path(REPO_ROOT / "assurance/interoperability/README.md")
                ],
                "offline-artifact-path": "assurance/interoperability/README.md",
                "offline-artifact-sha256": sha256_path(REPO_ROOT / "assurance/interoperability/README.md"),
                "offline-replay-command": "python3 -B assurance/interoperability/verify-interoperability.py --mode ci --offline",
                "implementation-lineage": "independent",
                "independence-review-status": "complete",
                "reviewer": "synthetic independent self-test reviewer",
                "review-date": "2026-08-11",
            }
        )
        return candidate

    forged_dossiers = coherent_self_attested_bls_promotion()
    expect_error(
        "coherent self-attested BLS dossier using README cannot become accepted",
        dossier_errors(forged_dossiers),
        "status is not allowed",
    )
    expect_error(
        "dossier schema forbids accepted status",
        validate_json_schema_instance(
            forged_dossiers, inputs["dossier_schema"], label="forged-bls-dossier"
        ),
        "outside allowed enum",
    )

    first_operation_row = next(row for row in expected["rows"] if row["row_kind"] == "operation")

    def override_fixture(case_id: str = "executed-case") -> dict:
        key = first_operation_row["key"]
        return {
            "schema-version": 1,
            "override": [
                {
                    "atomic-row-id": key["atomic_row_id"],
                    "public-path": key["public_path"],
                    "feature-profile": key["feature_profile"],
                    "platform": key["platform"],
                    "direction": "bidirectional",
                    "oracle-id": dossiers["oracle"][0]["id"],
                    "case-id": case_id,
                    "corpus-test-identifiers": ["selftest-case"],
                    "evidence-path": "assurance/interoperability/README.md",
                    "evidence-sha256": sha256_path(REPO_ROOT / "assurance/interoperability/README.md"),
                    "evidence-generated-at": "2026-08-11",
                    "evidence-valid-through": "2026-11-09",
                    "execution-status": "complete",
                    "independent-replay-status": "complete",
                    "status": "pass",
                    "owner": "synthetic self-test owner",
                    "reviewer": "synthetic independent self-test reviewer",
                    "deadline": "2026-11-09",
                    "expiry": "2026-11-09",
                }
            ],
        }

    coherent_readme_override = override_fixture()
    expect_error(
        "coherent BLS promotion using README cannot produce pass",
        validate_overrides(
            coherent_readme_override,
            dossiers=forged_dossiers,
            policy=inputs["policy"],
            root=REPO_ROOT,
        ),
        "evidence overrides are forbidden",
    )
    expect_error(
        "override schema requires zero promotion records",
        validate_json_schema_instance(
            coherent_readme_override,
            inputs["overrides_schema"],
            label="forged-readme-override",
        ),
        "more than maxItems",
    )
    forged_pass_matrix = copy.deepcopy(expected)
    next(row for row in forged_pass_matrix["rows"] if row["row_kind"] == "operation")[
        "status"
    ] = "pass"
    expect_error(
        "matrix schema forbids passing operation rows",
        validate_json_schema_instance(
            forged_pass_matrix,
            inputs["matrix_schema"],
            label="forged-pass-matrix",
        ),
        "outside allowed enum",
    )

    scaffold_override = override_fixture("scaffold-only")
    expect_error(
        "scaffold cannot be promoted",
        validate_overrides(scaffold_override, dossiers=dossiers, policy=inputs["policy"], root=REPO_ROOT),
        "evidence overrides are forbidden",
    )

    corrupt_evidence = override_fixture()
    corrupt_evidence["override"][0]["evidence-sha256"] = "0" * 64
    expect_error(
        "corrupt oracle evidence result",
        validate_overrides(corrupt_evidence, dossiers=dossiers, policy=inputs["policy"], root=REPO_ROOT),
        "evidence overrides are forbidden",
    )

    leaked_root = copy.deepcopy(inputs["root_manifest"])
    leaked_root.setdefault("dependencies", {})["bls12_381"] = "=0.8.0"
    expect_error(
        "oracle dependency leak into published package",
        validate_isolation(
            policy=inputs["policy"],
            boundary=inputs["boundary"],
            root_manifest=leaked_root,
            verification_manifest=inputs["verification_manifest"],
            verification_lock=inputs["verification_lock"],
            dossiers=dossiers,
            root=REPO_ROOT,
            published_manifest_documents={"Cargo.toml": leaked_root},
        ),
        "leaked into published manifest",
    )

    leaked_dev = copy.deepcopy(inputs["root_manifest"])
    leaked_dev.setdefault("dev-dependencies", {})["subtle"] = "=2.6.1"
    expect_error(
        "verification transitive dependency leak into published dev dependencies",
        validate_isolation(
            policy=inputs["policy"],
            boundary=inputs["boundary"],
            root_manifest=leaked_dev,
            verification_manifest=inputs["verification_manifest"],
            verification_lock=inputs["verification_lock"],
            dossiers=dossiers,
            root=REPO_ROOT,
            published_manifest_documents={"Cargo.toml": leaked_dev},
        ),
        "verification-only closure dependency subtle leaked",
    )

    leaked_target_build = copy.deepcopy(inputs["root_manifest"])
    leaked_target_build.setdefault("target", {}).setdefault(
        "cfg(target_os = 'linux')", {}
    ).setdefault("build-dependencies", {})["crypto-bigint"] = "=0.5.5"
    expect_error(
        "verification transitive dependency leak into target build dependencies",
        validate_isolation(
            policy=inputs["policy"],
            boundary=inputs["boundary"],
            root_manifest=leaked_target_build,
            verification_manifest=inputs["verification_manifest"],
            verification_lock=inputs["verification_lock"],
            dossiers=dossiers,
            root=REPO_ROOT,
            published_manifest_documents={"Cargo.toml": leaked_target_build},
        ),
        "verification-only closure dependency crypto-bigint leaked",
    )

    expanded_boundary = copy.deepcopy(inputs["boundary"])
    expanded_boundary["allowed-normal-build-packages"].append("subtle@2.6.1")
    expect_error(
        "published baseline cannot expand to admit verification transitive dependency",
        validate_isolation(
            policy=inputs["policy"],
            boundary=expanded_boundary,
            root_manifest=inputs["root_manifest"],
            verification_manifest=inputs["verification_manifest"],
            verification_lock=inputs["verification_lock"],
            dossiers=dossiers,
            root=REPO_ROOT,
        ),
        "baseline must remain exactly",
    )

    drifted_baseline_manifest = copy.deepcopy(inputs["root_manifest"])
    drifted_baseline_manifest.setdefault("dependencies", {})["base64"] = "=0.22.0"
    expect_error(
        "allowed production baseline version cannot drift",
        validate_isolation(
            policy=inputs["policy"],
            boundary=inputs["boundary"],
            root_manifest=drifted_baseline_manifest,
            verification_manifest=inputs["verification_manifest"],
            verification_lock=inputs["verification_lock"],
            dossiers=dossiers,
            root=REPO_ROOT,
            published_manifest_documents={"Cargo.toml": drifted_baseline_manifest},
        ),
        "must remain exactly =0.22.1",
    )

    published_documents = {
        path: load_toml(safe_repo_file(REPO_ROOT, path, "selftest published manifest"))
        for path in inputs["policy"]["published"]["manifests"]
    }
    arbitrary_external = copy.deepcopy(published_documents["Cargo.toml"])
    arbitrary_external.setdefault("dependencies", {})["semantic-bypass-oracle"] = {
        "version": "=1.0.0"
    }
    arbitrary_documents = copy.deepcopy(published_documents)
    arbitrary_documents["Cargo.toml"] = arbitrary_external
    expect_error(
        "arbitrary new external dependency outside verification closure cannot bypass isolation",
        validate_isolation(
            policy=inputs["policy"],
            boundary=inputs["boundary"],
            root_manifest=arbitrary_external,
            verification_manifest=inputs["verification_manifest"],
            verification_lock=inputs["verification_lock"],
            dossiers=dossiers,
            root=REPO_ROOT,
            published_manifest_documents=arbitrary_documents,
        ),
        "canonical record drifts from the code-bound baseline",
    )
    substituted_manifest_policy = copy.deepcopy(inputs["policy"])
    substituted_manifest_policy["published"]["manifests"][-2] = (
        "assurance/interoperability/dcrypt-pke-reviewed-manifest.toml"
    )
    expect_error(
        "assurance-owned manifest copy cannot replace a published manifest",
        validate_policy(substituted_manifest_policy),
        "paths/order drift from the code-bound baseline",
    )
    rebound_manifest_hash = copy.deepcopy(inputs["policy"])
    rebound_manifest_hash["published"]["manifest-record-sha256"]["Cargo.toml"] = "0" * 64
    expect_error(
        "published manifest baseline cannot be coherently rebound in policy",
        validate_policy(rebound_manifest_hash),
        "record hashes drift from the code-bound baseline",
    )

    with tempfile.TemporaryDirectory(prefix="dcrypt-interop-selftest-") as temporary:
        root = Path(temporary)
        (root / "plain.txt").write_text("fixture\n", encoding="utf-8")
        (root / "link.txt").symlink_to(root / "plain.txt")
        expect_exception(
            "missing input",
            lambda: safe_repo_file(root, "missing.txt", "selftest input"),
            "is missing",
        )
        expect_exception(
            "symlinked input",
            lambda: safe_repo_file(root, "link.txt", "selftest input"),
            "must not traverse a symlink",
        )
        expect_exception(
            "path-escaping input",
            lambda: safe_repo_file(root, "../escape.txt", "selftest input"),
            "path escape",
        )
        expect_exception(
            "absolute external input",
            lambda: safe_repo_file(root, "/etc/passwd", "selftest input"),
            "must be relative",
        )
        (root / "tree").mkdir()
        (root / "tree" / "plain.txt").write_text("fixture\n", encoding="utf-8")
        (root / "tree" / "linked.txt").symlink_to(root / "plain.txt")
        expect_exception(
            "symlinked preservation-tree input",
            lambda: discover_plain_tree_files(root, "tree", "selftest tree"),
            "must not traverse a symlink",
        )

    if failures:
        for failure in failures:
            print(f"SELFTEST FAILURE: {failure}")
        return 1
    print(f"interoperability adversarial self-tests passed: {passed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
