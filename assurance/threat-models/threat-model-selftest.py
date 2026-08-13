#!/usr/bin/env python3
"""Adversarial negative fixtures for the threat-model control."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable

from threat_model_lib import (
    ASSURANCE_DIR,
    HERE,
    MANDATORY_MODEL_IDS,
    MITIGATION_EVIDENCE_ARTIFACT_ROLE,
    MITIGATION_EVIDENCE_KIND,
    MITIGATION_EVIDENCE_PURPOSE,
    REPO_ROOT,
    REVIEW_EVIDENCE_ARTIFACT_ROLE,
    REVIEW_EVIDENCE_KIND,
    REVIEW_EVIDENCE_PURPOSE,
    ValidationError,
    build_coverage,
    evidence_applicability,
    expand_atomic_rows,
    load_inputs,
    safe_fixed_input_path,
    safe_generated_path,
    safe_source_path,
    sha256_path,
    threat_model_record_sha256,
    validate_coverage,
    validate_models as _validate_models,
    validate_schema,
)


AS_OF = dt.date(2026, 8, 11)
REVIEW_FIXTURE_ID = "selftest-threat-model-independent-review"
MITIGATION_FIXTURE_ID = "selftest-threat-model-mitigation-verification"


def validate_models(*args: Any, **kwargs: Any) -> list[str]:
    """Exercise synthetic evidence records only inside this offline self-test."""
    kwargs["allow_synthetic_fixtures"] = True
    return _validate_models(*args, **kwargs)


def main() -> int:
    schema, models, ledger, operations, snapshot = load_inputs()
    rows, row_errors = expand_atomic_rows(operations)
    baseline_errors = row_errors + validate_models(
        schema, models, ledger, rows, snapshot, mode="ci", as_of=AS_OF
    )
    if baseline_errors:
        for error in baseline_errors:
            print(f"SELFTEST BASELINE ERROR: {error}", file=sys.stderr)
        return 1
    expected_coverage = build_coverage(schema, models, ledger, rows, snapshot)
    failures: list[str] = []
    passed = 0

    def expect_error(name: str, errors: list[str], needle: str) -> None:
        nonlocal passed
        if not errors:
            failures.append(f"{name}: mutation passed unexpectedly")
        elif not any(needle in error for error in errors):
            failures.append(f"{name}: expected {needle!r}, got {errors[:3]!r}")
        else:
            passed += 1

    def expect_validation_error(name: str, action: Callable[[], Any], needle: str) -> None:
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

    def expect_no_errors(name: str, errors: list[str]) -> None:
        nonlocal passed
        if errors:
            failures.append(f"{name}: valid fixture failed: {errors[:5]!r}")
        else:
            passed += 1

    def model_case(
        name: str,
        mutate: Callable[[dict[str, Any]], None],
        needle: str,
    ) -> None:
        candidate = copy.deepcopy(models)
        mutate(candidate)
        errors = validate_models(
            schema, candidate, ledger, rows, snapshot, mode="ci", as_of=AS_OF
        )
        expect_error(name, errors, needle)

    def bind_evidence(
        candidate_ledger: dict[str, Any],
        model: dict[str, Any],
        *,
        purpose: str,
        mitigation_id: str | None = None,
    ) -> dict[str, Any]:
        if purpose == "review":
            evidence_id = REVIEW_FIXTURE_ID
            kind = REVIEW_EVIDENCE_KIND
            bound_purpose = REVIEW_EVIDENCE_PURPOSE
            artifact_role = REVIEW_EVIDENCE_ARTIFACT_ROLE
            artifact_path = HERE / "fixtures" / "review-evidence-record.json"
            reviewer = model["reviewer"]
        elif purpose == "mitigation":
            evidence_id = MITIGATION_FIXTURE_ID
            kind = MITIGATION_EVIDENCE_KIND
            bound_purpose = MITIGATION_EVIDENCE_PURPOSE
            artifact_role = MITIGATION_EVIDENCE_ARTIFACT_ROLE
            artifact_path = HERE / "fixtures" / "mitigation-evidence-record.json"
            reviewer = "independent mitigation evidence reviewer"
        else:
            raise AssertionError(f"unknown fixture evidence purpose: {purpose}")
        record: dict[str, Any] = {
            "id": evidence_id,
            "kind": kind,
            "purpose": bound_purpose,
            "owner": "threat-model evidence custodian",
            "reviewer": reviewer,
            "verdict": "pass",
            "threat-model-id": model["id"],
            "threat-model-set-version": models["model-set-version"],
            "threat-model-record-sha256": threat_model_record_sha256(model),
            "applicability": evidence_applicability(
                model_id=model["id"],
                model_set_version=models["model-set-version"],
                purpose=bound_purpose,
                mitigation_id=mitigation_id,
            ),
            "reviewed-at": model["reviewed-at"],
            "valid-through": model["valid-through"],
            "independent-replay-status": "complete",
            "independent-replay-reviewer": "independent replay reviewer",
            "independent-replay-reviewed-at": AS_OF,
            "synthetic-fixture-only": True,
            "source-commit": candidate_ledger["source-commit"],
            "source-tree": candidate_ledger["source-tree"],
            "artifacts": [
                {
                    "path": artifact_path.relative_to(REPO_ROOT).as_posix(),
                    "sha256": sha256_path(artifact_path),
                    "role": artifact_role,
                }
            ],
        }
        if purpose == "mitigation":
            record["verified-mitigation-id"] = mitigation_id
        candidate_ledger["evidence"].append(record)
        return record

    # Every mandatory class is independently protected, not count-only checked.
    for model_id in MANDATORY_MODEL_IDS:
        model_case(
            f"missing mandatory class {model_id}",
            lambda candidate, target=model_id: candidate.__setitem__(
                "model", [item for item in candidate["model"] if item["id"] != target]
            ),
            "mandatory threat-model set mismatch",
        )

    model_case("duplicate model id", lambda d: d["model"].append(copy.deepcopy(d["model"][0])), "ids must be unique")
    model_case("missing owner", lambda d: d["model"][0].pop("owner"), ".owner must be a non-empty string")
    model_case("missing reviewer", lambda d: d["model"][0].pop("reviewer"), ".reviewer must be a non-empty string")
    model_case("same owner and reviewer", lambda d: d["model"][0].__setitem__("reviewer", d["model"][0]["owner"]), "owner and reviewer must be distinct")
    model_case("missing independent review evidence", lambda d: d["model"][0].pop("independent-review-evidence"), ".independent-review-evidence must be an array")
    model_case(
        "self-attested complete review",
        lambda d: (
            d["model"][0].__setitem__("status", "active"),
            d["model"][0].__setitem__("independent-review-status", "complete"),
        ),
        "self-attested complete review has no independent-review evidence",
    )
    model_case(
        "informational evidence cannot complete review",
        lambda d: (
            d["model"][0].__setitem__("status", "active"),
            d["model"][0].__setitem__("independent-review-status", "complete"),
            d["model"][0].__setitem__("independent-review-evidence", ["assurance-ledger-control"]),
        ),
        "is not passing",
    )
    completed_models = copy.deepcopy(models)
    completed_models["model"][0]["status"] = "active"
    completed_models["model"][0]["independent-review-status"] = "complete"
    completed_models["model"][0]["reviewer"] = (
        "Independent External Review Organization / Reviewer 001"
    )
    completed_models["model"][0]["independent-review-evidence"] = [REVIEW_FIXTURE_ID]
    forged_ledger = copy.deepcopy(ledger)
    review_record = bind_evidence(
        forged_ledger,
        completed_models["model"][0],
        purpose="review",
    )
    errors = validate_models(
        schema, completed_models, forged_ledger, rows, snapshot, mode="ci", as_of=AS_OF
    )
    expect_no_errors("exact review evidence can complete active model review", errors)

    normal_errors = _validate_models(
        schema,
        completed_models,
        forged_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "normal verification rejects synthetic review evidence",
        normal_errors,
        "uses a synthetic fixture identity forbidden in normal verification",
    )

    pending_reviewer_models = copy.deepcopy(completed_models)
    pending_reviewer_models["model"][0]["reviewer"] = (
        "dcrypt release assurance review (independent review pending)"
    )
    errors = validate_models(
        schema,
        pending_reviewer_models,
        forged_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "active completed model rejects pending project reviewer",
        errors,
        "requires a concrete non-project independent reviewer identity",
    )

    review_model_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        (
            "residual rationale",
            lambda model: model["residual-risk"].__setitem__(
                "rationale", "mutated without changing model-set version"
            ),
        ),
        (
            "residual rating",
            lambda model: model["residual-risk"].__setitem__("rating", "high"),
        ),
        (
            "residual disposition",
            lambda model: model["residual-risk"].__setitem__("disposition", "avoid"),
        ),
        (
            "known limitation",
            lambda model: model["known-limitations"].append(
                "mutated without changing model-set version"
            ),
        ),
    ]
    for mutation_name, mutate_model in review_model_mutations:
        mutated_review_models = copy.deepcopy(completed_models)
        mutate_model(mutated_review_models["model"][0])
        errors = validate_models(
            schema,
            mutated_review_models,
            forged_ledger,
            rows,
            snapshot,
            mode="ci",
            as_of=AS_OF,
        )
        expect_error(
            f"review evidence rejects changed {mutation_name}",
            errors,
            ".threat-model-record-sha256 does not bind the exact model table",
        )

    unrelated_review_ledger = copy.deepcopy(forged_ledger)
    unrelated_review = next(
        item
        for item in unrelated_review_ledger["evidence"]
        if item["id"] == REVIEW_FIXTURE_ID
    )
    unrelated_review["kind"] = MITIGATION_EVIDENCE_KIND
    unrelated_review["purpose"] = MITIGATION_EVIDENCE_PURPOSE
    errors = validate_models(
        schema,
        completed_models,
        unrelated_review_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "unrelated evidence cannot complete model review",
        errors,
        f".kind must be exactly {REVIEW_EVIDENCE_KIND}",
    )

    wrong_review_model_ledger = copy.deepcopy(forged_ledger)
    wrong_review_model = next(
        item
        for item in wrong_review_model_ledger["evidence"]
        if item["id"] == REVIEW_FIXTURE_ID
    )
    wrong_review_model["threat-model-id"] = "TM-UNRELATED"
    errors = validate_models(
        schema,
        completed_models,
        wrong_review_model_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "review evidence must bind exact model id",
        errors,
        "does not bind exact threat-model-id",
    )

    wrong_review_version_ledger = copy.deepcopy(forged_ledger)
    wrong_review_version = next(
        item
        for item in wrong_review_version_ledger["evidence"]
        if item["id"] == REVIEW_FIXTURE_ID
    )
    wrong_review_version["threat-model-set-version"] = "unrelated-set"
    errors = validate_models(
        schema,
        completed_models,
        wrong_review_version_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "review evidence must bind exact model-set version",
        errors,
        "does not bind exact threat-model-set-version",
    )

    wrong_review_applicability_ledger = copy.deepcopy(forged_ledger)
    wrong_review_applicability = next(
        item
        for item in wrong_review_applicability_ledger["evidence"]
        if item["id"] == REVIEW_FIXTURE_ID
    )
    wrong_review_applicability["applicability"] = "unrelated"
    errors = validate_models(
        schema,
        completed_models,
        wrong_review_applicability_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "review evidence must bind exact applicability",
        errors,
        ".applicability does not exactly bind its purpose",
    )

    wrong_review_reviewer_ledger = copy.deepcopy(forged_ledger)
    wrong_review_reviewer = next(
        item
        for item in wrong_review_reviewer_ledger["evidence"]
        if item["id"] == REVIEW_FIXTURE_ID
    )
    wrong_review_reviewer["reviewer"] = "unrelated reviewer"
    errors = validate_models(
        schema,
        completed_models,
        wrong_review_reviewer_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "review evidence must bind exact model reviewer",
        errors,
        ".reviewer does not bind the model reviewer",
    )

    wrong_review_date_ledger = copy.deepcopy(forged_ledger)
    wrong_review_date = next(
        item
        for item in wrong_review_date_ledger["evidence"]
        if item["id"] == REVIEW_FIXTURE_ID
    )
    wrong_review_date["reviewed-at"] = dt.date(2026, 8, 10)
    errors = validate_models(
        schema,
        completed_models,
        wrong_review_date_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "review evidence must bind exact model review date",
        errors,
        ".reviewed-at does not bind the model review date",
    )

    wrong_replay_reviewer_ledger = copy.deepcopy(forged_ledger)
    wrong_replay_reviewer = next(
        item
        for item in wrong_replay_reviewer_ledger["evidence"]
        if item["id"] == REVIEW_FIXTURE_ID
    )
    wrong_replay_reviewer["independent-replay-reviewer"] = wrong_replay_reviewer[
        "reviewer"
    ]
    errors = validate_models(
        schema,
        completed_models,
        wrong_replay_reviewer_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "review replay reviewer must be distinct",
        errors,
        "lacks a distinct independent-replay reviewer",
    )

    forged_ledger = copy.deepcopy(forged_ledger)
    review_record = next(
        item for item in forged_ledger["evidence"] if item["id"] == REVIEW_FIXTURE_ID
    )
    review_record["source-commit"] = "0" * 40
    errors = validate_models(
        schema, completed_models, forged_ledger, rows, snapshot, mode="ci", as_of=AS_OF
    )
    expect_error("review evidence must bind exact source", errors, "does not bind the ledger subject")
    forged_ledger = copy.deepcopy(ledger)
    bind_evidence(forged_ledger, completed_models["model"][0], purpose="review")
    review_record = next(
        item for item in forged_ledger["evidence"] if item["id"] == REVIEW_FIXTURE_ID
    )
    review_record["artifacts"][0]["sha256"] = "0" * 64
    errors = validate_models(
        schema, completed_models, forged_ledger, rows, snapshot, mode="ci", as_of=AS_OF
    )
    expect_error("review evidence must bind exact artifact", errors, "does not bind current artifact bytes")
    model_case("missing review date", lambda d: d["model"][0].pop("reviewed-at"), ".reviewed-at must be a TOML local date")
    model_case("missing expiry", lambda d: d["model"][0].pop("valid-through"), ".valid-through must be a TOML local date")
    model_case("expired record", lambda d: d["model"][0].__setitem__("valid-through", dt.date(2026, 8, 10)), "expired on")
    model_case("future review", lambda d: d["model"][0].__setitem__("reviewed-at", dt.date(2026, 8, 12)), "reviewed-at is in the future")
    model_case("overlong validity", lambda d: d["model"][0].__setitem__("valid-through", dt.date(2027, 8, 11)), "validity exceeds")
    model_case("missing entrypoint scope", lambda d: d["model"][0].pop("public-entrypoint-scope"), ".public-entrypoint-scope must be a non-empty string")
    model_case("missing row selector", lambda d: d["model"][0].pop("atomic-row-selector"), ".atomic-row-selector must be a non-empty string")
    model_case("missing exact row set", lambda d: d["model"][0].pop("affected-row-set"), ".affected-row-set must be a non-empty string")
    for field in ("affected-algorithms", "affected-operations", "affected-profiles", "affected-platforms"):
        model_case(
            f"missing {field}",
            lambda d, target=field: d["model"][0].pop(target),
            f".{field} must be a non-empty array",
        )
    model_case("wrong algorithm dimension", lambda d: d["model"][0].__setitem__("affected-algorithms", ["all"]), "must bind the exact coverage dimension")
    model_case("missing assets", lambda d: d["model"][0].pop("assets"), ".assets must be a non-empty array")
    model_case("missing asset id", lambda d: d["model"][0]["assets"][0].pop("id"), ".assets[0].id must be a non-empty string")
    model_case("missing asset security property", lambda d: d["model"][0]["assets"][0].pop("security-properties"), ".security-properties must be a non-empty array")
    for field in (
        "trust-boundaries",
        "attacker-capabilities",
        "preconditions",
        "excluded-capabilities",
        "assumptions",
        "known-limitations",
        "required-evidence-tiers",
        "claim-invalidation-conditions",
    ):
        model_case(
            f"missing {field}",
            lambda d, target=field: d["model"][0].pop(target),
            f".{field} must be a non-empty array",
        )
    model_case("unknown evidence tier", lambda d: d["model"][0]["required-evidence-tiers"].append("wishful-thinking"), "unknown values")
    model_case("missing mitigations", lambda d: d["model"][0].pop("mitigations"), ".mitigations must be a non-empty array")
    model_case("unknown evidence id", lambda d: d["model"][0]["mitigations"][0]["evidence"].append("not-in-ledger"), "references unknown evidence")
    model_case("verified mitigation claim", lambda d: d["model"][0]["mitigations"][0].__setitem__("status", "verified"), "requires independently replayed passing evidence")

    verified_models = copy.deepcopy(models)
    verified_model = verified_models["model"][0]
    verified_mitigation = verified_model["mitigations"][0]
    verified_mitigation["status"] = "verified"
    verified_mitigation["evidence"] = [MITIGATION_FIXTURE_ID]
    verified_ledger = copy.deepcopy(ledger)
    bind_evidence(
        verified_ledger,
        verified_model,
        purpose="mitigation",
        mitigation_id=verified_mitigation["id"],
    )
    errors = validate_models(
        schema, verified_models, verified_ledger, rows, snapshot, mode="ci", as_of=AS_OF
    )
    expect_no_errors("fully bound mitigation evidence can support verified status", errors)

    normal_mitigation_errors = _validate_models(
        schema,
        verified_models,
        verified_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "normal verification rejects synthetic mitigation identity",
        normal_mitigation_errors,
        "uses a synthetic fixture identity forbidden in normal verification",
    )
    expect_error(
        "normal verification rejects fixture artifact path",
        normal_mitigation_errors,
        ".path uses a synthetic fixture location forbidden in normal verification",
    )

    wrong_artifact_role_ledger = copy.deepcopy(verified_ledger)
    wrong_artifact_role_record = next(
        item
        for item in wrong_artifact_role_ledger["evidence"]
        if item["id"] == MITIGATION_FIXTURE_ID
    )
    wrong_artifact_role_record["artifacts"][0]["role"] = (
        REVIEW_EVIDENCE_ARTIFACT_ROLE
    )
    errors = validate_models(
        schema,
        verified_models,
        wrong_artifact_role_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "verified mitigation rejects unrelated artifact role",
        errors,
        f".role must be exactly {MITIGATION_EVIDENCE_ARTIFACT_ROLE}",
    )

    generic_artifacts_ledger = copy.deepcopy(verified_ledger)
    generic_artifacts_record = next(
        item
        for item in generic_artifacts_ledger["evidence"]
        if item["id"] == MITIGATION_FIXTURE_ID
    )
    generic_artifacts_record["artifacts"] = copy.deepcopy(
        ledger["evidence"][0]["artifacts"]
    )
    errors = validate_models(
        schema,
        verified_models,
        generic_artifacts_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "verified mitigation rejects relabeled generic artifact list",
        errors,
        "must have exactly one dedicated",
    )

    mutated_description_models = copy.deepcopy(verified_models)
    mutated_description_models["model"][0]["mitigations"][0]["description"] += (
        " mutated"
    )
    errors = validate_models(
        schema,
        mutated_description_models,
        verified_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "verified mitigation rejects changed description",
        errors,
        ".threat-model-record-sha256 does not bind the exact model table",
    )

    mutated_status_models = copy.deepcopy(verified_models)
    mutated_status_models["model"][0]["mitigations"][0][
        "status"
    ] = "implemented-unverified"
    errors = validate_models(
        schema,
        mutated_status_models,
        verified_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "verified mitigation rejects changed status",
        errors,
        "cites dedicated verification evidence but status is not verified",
    )

    mutated_refs_models = copy.deepcopy(verified_models)
    mutated_refs_models["model"][0]["mitigations"][0]["evidence"].append(
        "assurance-ledger-control"
    )
    errors = validate_models(
        schema,
        mutated_refs_models,
        verified_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "verified mitigation rejects changed evidence references",
        errors,
        ".threat-model-record-sha256 does not bind the exact model table",
    )

    bad_source_ledger = copy.deepcopy(verified_ledger)
    bad_source_record = next(
        item
        for item in bad_source_ledger["evidence"]
        if item["id"] == MITIGATION_FIXTURE_ID
    )
    bad_source_record["source-tree"] = "0" * 40
    errors = validate_models(
        schema,
        verified_models,
        bad_source_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "verified mitigation rejects bad source binding",
        errors,
        "does not bind the ledger subject",
    )

    bad_artifact_ledger = copy.deepcopy(verified_ledger)
    bad_artifact_record = next(
        item
        for item in bad_artifact_ledger["evidence"]
        if item["id"] == MITIGATION_FIXTURE_ID
    )
    bad_artifact_record["artifacts"][0]["sha256"] = "0" * 64
    errors = validate_models(
        schema,
        verified_models,
        bad_artifact_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "verified mitigation rejects bad artifact binding",
        errors,
        "does not bind current artifact bytes",
    )

    wrong_mitigation_ledger = copy.deepcopy(verified_ledger)
    wrong_mitigation_record = next(
        item
        for item in wrong_mitigation_ledger["evidence"]
        if item["id"] == MITIGATION_FIXTURE_ID
    )
    wrong_mitigation_record["verified-mitigation-id"] = "unrelated-mitigation"
    errors = validate_models(
        schema,
        verified_models,
        wrong_mitigation_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "verified mitigation rejects unrelated mitigation evidence",
        errors,
        "does not bind exact verified-mitigation-id",
    )

    wrong_applicability_ledger = copy.deepcopy(verified_ledger)
    wrong_applicability_record = next(
        item
        for item in wrong_applicability_ledger["evidence"]
        if item["id"] == MITIGATION_FIXTURE_ID
    )
    wrong_applicability_record["applicability"] = "unrelated"
    errors = validate_models(
        schema,
        verified_models,
        wrong_applicability_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "verified mitigation rejects unrelated applicability",
        errors,
        ".applicability does not exactly bind its purpose",
    )

    unrelated_mitigation_ledger = copy.deepcopy(verified_ledger)
    unrelated_mitigation_record = next(
        item
        for item in unrelated_mitigation_ledger["evidence"]
        if item["id"] == MITIGATION_FIXTURE_ID
    )
    unrelated_mitigation_record["kind"] = REVIEW_EVIDENCE_KIND
    unrelated_mitigation_record["purpose"] = REVIEW_EVIDENCE_PURPOSE
    errors = validate_models(
        schema,
        verified_models,
        unrelated_mitigation_ledger,
        rows,
        snapshot,
        mode="ci",
        as_of=AS_OF,
    )
    expect_error(
        "verified mitigation rejects unrelated evidence purpose",
        errors,
        f".kind must be exactly {MITIGATION_EVIDENCE_KIND}",
    )
    model_case("implemented without evidence", lambda d: d["model"][0]["mitigations"][0].__setitem__("evidence", []), "needs bounded evidence")
    model_case("planned cites evidence", lambda d: d["model"][0]["mitigations"][0].__setitem__("status", "planned"), "planned mitigation must not cite")
    model_case("missing residual risk", lambda d: d["model"][0].pop("residual-risk"), ".residual-risk must be a table")
    for field in ("likelihood", "impact", "rating", "disposition", "rationale", "acceptance-authority"):
        model_case(
            f"missing residual {field}",
            lambda d, target=field: d["model"][0]["residual-risk"].pop(target),
            f".residual-risk.{field} must be a non-empty string",
        )
    model_case("invalid residual rating", lambda d: d["model"][0]["residual-risk"].__setitem__("rating", "unknown"), ".residual-risk.rating is not an allowed risk level")
    model_case("source digest drift", lambda d: d.__setitem__("source-operations-sha256", "0" * 64), "does not bind the current source-operations bytes")
    release_errors = _validate_models(
        schema, models, ledger, rows, snapshot, mode="release", as_of=AS_OF
    )
    expect_error("release rejects candidate models", release_errors, "is not active in release mode")
    expect_error("release rejects pending independent review", release_errors, "lacks completed independent review")
    expect_error("release rejects high or critical residual risk", release_errors, "has release-blocking")
    expect_error("release rejects unresolved mitigate disposition", release_errors, "has unresolved mitigate disposition")

    # The schema itself cannot delete or weaken mandatory classes or field lists.
    candidate_schema = copy.deepcopy(schema)
    candidate_schema["required-model-ids"].pop()
    expect_error("schema cannot drop model class", validate_schema(candidate_schema), "required-model-ids differs")
    candidate_schema = copy.deepcopy(schema)
    candidate_schema["required-list-fields"].remove("affected-operations")
    expect_error("schema cannot drop affected operations", validate_schema(candidate_schema), "required-list-fields differs")
    candidate_schema = copy.deepcopy(schema)
    candidate_schema["allowed-evidence-tiers"].append("unchecked")
    expect_error("schema cannot expand evidence tiers", validate_schema(candidate_schema), "allowed-evidence-tiers differs")
    candidate_schema = copy.deepcopy(schema)
    candidate_schema.pop("conditional-list-fields")
    expect_error("schema cannot drop review evidence binding", validate_schema(candidate_schema), "conditional-list-fields differs")
    candidate_schema = copy.deepcopy(schema)
    candidate_schema["review-evidence-kind"] = "generic-review"
    expect_error(
        "schema cannot broaden review evidence kind",
        validate_schema(candidate_schema),
        "review-evidence-kind differs",
    )
    candidate_schema = copy.deepcopy(schema)
    candidate_schema["mitigation-evidence-purpose"] = "generic-pass"
    expect_error(
        "schema cannot broaden mitigation evidence purpose",
        validate_schema(candidate_schema),
        "mitigation-evidence-purpose differs",
    )
    candidate_schema = copy.deepcopy(schema)
    candidate_schema["review-evidence-artifact-role"] = "generic-artifact"
    expect_error(
        "schema cannot broaden review artifact role",
        validate_schema(candidate_schema),
        "review-evidence-artifact-role differs",
    )

    # Exact operation mapping fixtures: missing, duplicate, extra, and altered rows fail.
    candidate = copy.deepcopy(expected_coverage)
    candidate["rows"].pop()
    expect_error("coverage missing exact row", validate_coverage(candidate, expected_coverage), "missing exact atomic row ids")
    candidate = copy.deepcopy(expected_coverage)
    candidate["rows"].append(copy.deepcopy(candidate["rows"][0]))
    expect_error("coverage duplicate exact row", validate_coverage(candidate, expected_coverage), "duplicate atomic row ids")
    candidate = copy.deepcopy(expected_coverage)
    extra = copy.deepcopy(candidate["rows"][0])
    extra["id"] = "selftest.unexpected-row"
    candidate["rows"].append(extra)
    expect_error("coverage unexpected exact row", validate_coverage(candidate, expected_coverage), "unexpected atomic row ids")
    candidate = copy.deepcopy(expected_coverage)
    candidate["rows"][0]["threat_models"].pop()
    expect_error("coverage altered threat-class mapping", validate_coverage(candidate, expected_coverage), "row differs from bound atomic row mapping")
    candidate = copy.deepcopy(expected_coverage)
    candidate["rows"][0]["public_bindings"].pop()
    expect_error("coverage altered public binding mapping", validate_coverage(candidate, expected_coverage), "row differs from bound atomic row mapping")
    candidate = copy.deepcopy(expected_coverage)
    first_model_id = sorted(candidate["models"])[0]
    candidate["models"][first_model_id]["atomic_row_count"] -= 1
    expect_error("coverage altered model summary", validate_coverage(candidate, expected_coverage), "model summaries differ")

    # Atomic source changes fail before a generated map could hide them.
    candidate_operations = copy.deepcopy(operations)
    added = copy.deepcopy(candidate_operations["operation"][0])
    added["id"] = "selftest.new-unclassified-export"
    candidate_operations["operation"].append(added)
    added_rows, added_errors = expand_atomic_rows(candidate_operations)
    added_errors.extend(validate_models(schema, models, ledger, added_rows, snapshot, mode="ci", as_of=AS_OF))
    expect_error("new atomic row changes baseline", added_errors, "effective atomic row count must remain 9198")
    candidate_operations = copy.deepcopy(operations)
    candidate_operations["operation"][0]["release-readiness"] = "ready"
    _, readiness_errors = expand_atomic_rows(candidate_operations)
    expect_error("ready row cannot clear blocker", readiness_errors, "is not release-blocked")

    # Original unresolved path components are inspected before any resolve().
    fixture_dir = Path(tempfile.mkdtemp(prefix=".threat-model-selftest-", dir=HERE))
    try:
        source_link = fixture_dir / "source-link.toml"
        source_link.symlink_to(ASSURANCE_DIR / "ledger.toml")
        relative_source = str(source_link.relative_to(HERE))
        expect_validation_error(
            "source symlink rejected before resolution",
            lambda: safe_source_path(relative_source, label="selftest-source"),
            "must not traverse a symlink",
        )
        generated_link = fixture_dir / "generated-link.json"
        generated_link.symlink_to(HERE / "coverage.json")
        relative_generated = str(generated_link.relative_to(HERE))
        expect_validation_error(
            "generated symlink rejected before resolution",
            lambda: safe_generated_path(relative_generated, label="selftest-generated"),
            "must not traverse a symlink",
        )

        fixed_inputs = fixture_dir / "fixed-inputs"
        fixed_inputs.mkdir()
        schema_link = fixed_inputs / "schema.toml"
        schema_link.symlink_to(HERE / "schema.toml")
        relative_schema = str(schema_link.relative_to(HERE))
        expect_validation_error(
            "fixed schema direct symlink rejected before resolution",
            lambda: safe_fixed_input_path(
                relative_schema,
                label="selftest fixed schema",
            ),
            "must not traverse a symlink",
        )

        real_parent = fixture_dir / "real-control-parent"
        real_parent.mkdir()
        shutil.copyfile(HERE / "threat-models.toml", real_parent / "threat-models.toml")
        linked_parent = fixture_dir / "linked-control-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        relative_model = str((linked_parent / "threat-models.toml").relative_to(HERE))
        expect_validation_error(
            "fixed threat-model parent symlink rejected before resolution",
            lambda: safe_fixed_input_path(
                relative_model,
                label="selftest fixed threat-model document",
            ),
            "must not traverse a symlink",
        )
        expect_validation_error(
            "fixed-input base parent symlink rejected before resolution",
            lambda: safe_fixed_input_path(
                "threat-models.toml",
                label="selftest symlinked fixed-input base",
                base=linked_parent,
            ),
            "base must not traverse a symlink",
        )
    finally:
        shutil.rmtree(fixture_dir)

    # argparse rejects unknown options before generation and --check performs no writes.
    generator = HERE / "generate-threat-models.py"
    before = {
        name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        for name in ("coverage.json", "THREAT-MODELS.md")
    }
    unknown = subprocess.run(
        [sys.executable, "-B", str(generator), "--unknown-selftest-option"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    expect_error(
        "generator rejects unknown CLI option",
        [] if unknown.returncode == 0 else [unknown.stderr],
        "unrecognized arguments",
    )
    checked = subprocess.run(
        [sys.executable, "-B", str(generator), "--check"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    expect_error(
        "generator --check succeeds without writes",
        [checked.stderr] if checked.returncode != 0 else [checked.stdout],
        "checked generated threat-model artifacts without writes",
    )
    coverage_path = HERE / "coverage.json"
    original_coverage = coverage_path.read_bytes()
    try:
        coverage_path.write_bytes(original_coverage + b" ")
        drifted = subprocess.run(
            [sys.executable, "-B", str(generator), "--check"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        expect_error(
            "generator --check rejects drift without rewriting",
            [] if drifted.returncode == 0 else [drifted.stderr],
            "generated threat-model artifact drift",
        )
        if coverage_path.read_bytes() != original_coverage + b" ":
            failures.append("generator --check rewrote the drift fixture")
        else:
            passed += 1
    finally:
        coverage_path.write_bytes(original_coverage)
    after = {
        name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        for name in ("coverage.json", "THREAT-MODELS.md")
    }
    expect_error(
        "generator --check leaves bytes unchanged",
        ["unchanged"] if before == after else [],
        "unchanged",
    )

    if failures:
        for failure in failures:
            print(f"SELFTEST FAILURE: {failure}", file=sys.stderr)
        return 1
    print(f"threat-model self-test passed: {passed} adversarial fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
