#!/usr/bin/env python3
"""Deterministic validation and rendering for dcrypt threat models.

This module intentionally uses only the Python standard library.  Threat models
describe risk and required evidence; they never promote ledger evidence or make
an assurance verdict pass.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import stat
import tomllib
from typing import Any, Iterable


HERE = Path(__file__).absolute().parent
ASSURANCE_DIR = HERE.parent
REPO_ROOT = ASSURANCE_DIR.parent
MODEL_PATH = HERE / "threat-models.toml"

MANDATORY_MODEL_IDS = (
    "TM-DEPENDENCY-ORACLE-COMMON-MODE",
    "TM-DOS-RESOURCE-BOUNDS",
    "TM-EMBEDDED-PHYSICAL-ACCESS",
    "TM-FAULT-INJECTION",
    "TM-LOCAL-CORESIDENT-CACHE",
    "TM-POWER-EM",
    "TM-PROTOCOL-MISUSE",
    "TM-REMOTE-MALICIOUS-INPUT",
    "TM-RNG-FAILURE",
    "TM-SECRET-LIFECYCLE",
    "TM-SUPPLY-CHAIN-TOOLCHAIN",
)

REQUIRED_STRING_FIELDS = (
    "id",
    "title",
    "status",
    "owner",
    "reviewer",
    "independent-review-status",
    "public-entrypoint-scope",
    "atomic-row-selector",
    "affected-row-set",
)

REQUIRED_LIST_FIELDS = (
    "affected-algorithms",
    "affected-operations",
    "affected-profiles",
    "affected-platforms",
    "trust-boundaries",
    "attacker-capabilities",
    "preconditions",
    "excluded-capabilities",
    "assumptions",
    "known-limitations",
    "required-evidence-tiers",
    "claim-invalidation-conditions",
)

REQUIRED_RESIDUAL_FIELDS = (
    "likelihood",
    "impact",
    "rating",
    "disposition",
    "rationale",
    "acceptance-authority",
)

CONDITIONAL_LIST_FIELDS = ("independent-review-evidence",)

ALLOWED_STATUSES = {"active", "candidate", "retired"}
ALLOWED_REVIEW_STATUSES = {"complete", "required"}
ALLOWED_MITIGATION_STATUSES = {"implemented-unverified", "planned", "verified"}
ALLOWED_RISK_LEVELS = {"low", "moderate", "high", "critical"}
ALLOWED_RISK_DISPOSITIONS = {"accept", "avoid", "mitigate", "transfer"}
ALLOWED_EVIDENCE_TIERS = {
    "dedicated-side-channel",
    "deterministic-regression",
    "external-audit",
    "fault-analysis",
    "independent-interoperability",
    "persistent-fuzz",
    "physical-validation",
    "platform-runtime",
    "resource-bound-analysis",
    "source-policy",
    "supply-chain-reproducibility",
}
FORBIDDEN_COMPLETED_REVIEWER_MARKERS = (
    "pending",
    "tbd",
    "unknown",
    "selftest",
    "fixture",
    "self-review",
    "self review",
    "project owner",
)
REVIEW_EVIDENCE_KIND = "threat-model-independent-review"
REVIEW_EVIDENCE_PURPOSE = "threat-model-independent-review"
MITIGATION_EVIDENCE_KIND = "threat-model-mitigation-verification"
MITIGATION_EVIDENCE_PURPOSE = "threat-model-mitigation-verification"
REVIEW_EVIDENCE_ARTIFACT_ROLE = "threat-model-independent-review-record"
MITIGATION_EVIDENCE_ARTIFACT_ROLE = "threat-model-mitigation-verification-record"


class ValidationError(RuntimeError):
    """Raised for a fail-closed threat-model validation error."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def pretty_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def canonical_value_hash(values: Iterable[str]) -> str:
    return sha256_bytes(canonical_json_bytes(sorted(set(values))))


def _canonical_toml_json(value: Any) -> Any:
    if isinstance(value, dt.date) and not isinstance(value, dt.datetime):
        return {"$toml-local-date": value.isoformat()}
    if isinstance(value, dict):
        return {str(key): _canonical_toml_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_canonical_toml_json(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise ValidationError(
        f"model table contains unsupported canonical value type: {type(value).__name__}"
    )


def threat_model_record_sha256(model: dict[str, Any]) -> str:
    """Bind one parsed [[model]] table without hashing the containing file."""
    return sha256_bytes(canonical_json_bytes(_canonical_toml_json(model)))


def evidence_applicability(
    *, model_id: str, model_set_version: str, purpose: str, mitigation_id: str | None
) -> str:
    fields = [
        f"threat-model-id={model_id}",
        f"model-set-version={model_set_version}",
        f"purpose={purpose}",
    ]
    if mitigation_id is not None:
        fields.append(f"verified-mitigation-id={mitigation_id}")
    return ";".join(fields)


def _walk_unresolved_path(
    relative: Path,
    *,
    base: Path,
    allowed_root: Path,
    label: str,
    allow_parent: bool,
) -> Path:
    """Walk lexical components before resolving, rejecting every symlink hop."""
    if relative.is_absolute():
        raise ValidationError(f"{label} must be relative: {relative}")
    current = base
    root = allowed_root
    for part in relative.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not allow_parent:
                raise ValidationError(f"{label} must remain within {base}: {relative}")
            current = current.parent
        else:
            current = current / part
        try:
            current.relative_to(root)
        except ValueError as exc:
            raise ValidationError(f"{label} escapes allowed root {root}: {relative}") from exc
        if current.is_symlink():
            raise ValidationError(f"{label} must not traverse a symlink: {current}")
    return current


def _require_plain_file(path: Path, *, label: str) -> Path:
    if not path.exists():
        raise ValidationError(f"{label} is missing: {path}")
    if path.is_symlink():
        raise ValidationError(f"{label} must not be a symlink: {path}")
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise ValidationError(f"{label} is not a regular file: {path}")
    return path


def _require_unresolved_plain_directory(path: Path, *, label: str) -> Path:
    absolute = path.absolute()
    for component in list(reversed(absolute.parents)) + [absolute]:
        try:
            mode = component.lstat().st_mode
        except OSError as exc:
            raise ValidationError(f"cannot inspect {label} component {component}: {exc}") from exc
        if stat.S_ISLNK(mode):
            raise ValidationError(f"{label} must not traverse a symlink: {component}")
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise ValidationError(f"cannot resolve {label} {absolute}: {exc}") from exc
    if resolved != absolute:
        raise ValidationError(
            f"{label} has an unsafe resolved path: lexical={absolute}, resolved={resolved}"
        )
    if not stat.S_ISDIR(absolute.lstat().st_mode):
        raise ValidationError(f"{label} is not a directory: {absolute}")
    return absolute


def safe_source_path(relative: str, *, label: str) -> Path:
    if not isinstance(relative, str) or not relative.strip():
        raise ValidationError(f"{label} must be a non-empty relative path")
    raw = Path(relative)
    candidate = _walk_unresolved_path(
        raw,
        base=HERE,
        allowed_root=ASSURANCE_DIR,
        label=label,
        allow_parent=True,
    )
    return _require_plain_file(candidate, label=label)


def safe_fixed_input_path(
    relative: str,
    *,
    label: str,
    base: Path = HERE,
) -> Path:
    """Validate a fixed control input using unresolved lexical components."""
    if not isinstance(relative, str) or not relative.strip():
        raise ValidationError(f"{label} must be a non-empty relative path")
    checked_base = _require_unresolved_plain_directory(base, label=f"{label} base")
    candidate = _walk_unresolved_path(
        Path(relative),
        base=checked_base,
        allowed_root=checked_base,
        label=label,
        allow_parent=False,
    )
    return _require_plain_file(candidate, label=label)


def safe_generated_path(relative: str, *, label: str, require_exists: bool = True) -> Path:
    if not isinstance(relative, str) or not relative.strip():
        raise ValidationError(f"{label} must be a non-empty relative path")
    raw = Path(relative)
    resolved = _walk_unresolved_path(
        raw,
        base=HERE,
        allowed_root=HERE,
        label=label,
        allow_parent=False,
    )
    if require_exists:
        return _require_plain_file(resolved, label=label)
    if resolved.exists() and resolved.is_symlink():
        raise ValidationError(f"{label} must not be a symlink: {resolved}")
    return resolved


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            document = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError(f"cannot load TOML {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ValidationError(f"TOML root must be a table: {path}")
    return document


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as source:
            return json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot load JSON {path}: {exc}") from exc


def load_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    schema = load_toml(safe_fixed_input_path("schema.toml", label="threat-model schema"))
    models = load_model_document()
    ledger_path = safe_source_path(models.get("source-ledger", ""), label="source-ledger")
    operations_path = safe_source_path(models.get("source-operations", ""), label="source-operations")
    snapshot_path = safe_source_path(models.get("source-api-snapshot", ""), label="source-api-snapshot")
    return schema, models, load_toml(ledger_path), load_toml(operations_path), load_json(snapshot_path)


def load_model_document() -> dict[str, Any]:
    return load_toml(
        safe_fixed_input_path("threat-models.toml", label="threat-model document")
    )


def _as_nonempty_string(value: Any, label: str, errors: list[str]) -> str:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{label} must be a non-empty string")
        return ""
    return value


def _as_nonempty_string_list(value: Any, label: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{label} must be a non-empty array")
        return []
    result: list[str] = []
    for offset, item in enumerate(value):
        text = _as_nonempty_string(item, f"{label}[{offset}]", errors)
        if text:
            result.append(text)
    if len(result) != len(set(result)):
        errors.append(f"{label} contains duplicate values")
    return result


def validate_schema(schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if schema.get("schema-version") != 1:
        errors.append("schema-version must be 1")
    if schema.get("document-schema-version") != 1:
        errors.append("document-schema-version must be 1")
    if schema.get("coverage-schema-version") != 1:
        errors.append("coverage-schema-version must be 1")
    if schema.get("coverage-policy") != "conservative-all-atomic-rows-v1":
        errors.append("coverage-policy must remain conservative-all-atomic-rows-v1")
    hardcoded = {
        "required-model-ids": MANDATORY_MODEL_IDS,
        "required-string-fields": REQUIRED_STRING_FIELDS,
        "required-list-fields": REQUIRED_LIST_FIELDS,
        "required-residual-risk-fields": REQUIRED_RESIDUAL_FIELDS,
        "conditional-list-fields": CONDITIONAL_LIST_FIELDS,
    }
    for field, expected in hardcoded.items():
        actual = schema.get(field)
        if not isinstance(actual, list) or tuple(actual) != expected:
            errors.append(f"{field} differs from the verifier's fail-closed requirement")
    enum_checks = {
        "allowed-statuses": ALLOWED_STATUSES,
        "allowed-independent-review-statuses": ALLOWED_REVIEW_STATUSES,
        "allowed-mitigation-statuses": ALLOWED_MITIGATION_STATUSES,
        "allowed-risk-levels": ALLOWED_RISK_LEVELS,
        "allowed-risk-dispositions": ALLOWED_RISK_DISPOSITIONS,
        "allowed-evidence-tiers": ALLOWED_EVIDENCE_TIERS,
    }
    for field, expected in enum_checks.items():
        actual = schema.get(field)
        if not isinstance(actual, list) or set(actual) != expected or len(actual) != len(expected):
            errors.append(f"{field} differs from the verifier's fail-closed enum")
    closed_evidence_contract = {
        "review-evidence-kind": REVIEW_EVIDENCE_KIND,
        "review-evidence-purpose": REVIEW_EVIDENCE_PURPOSE,
        "mitigation-evidence-kind": MITIGATION_EVIDENCE_KIND,
        "mitigation-evidence-purpose": MITIGATION_EVIDENCE_PURPOSE,
        "review-evidence-artifact-role": REVIEW_EVIDENCE_ARTIFACT_ROLE,
        "mitigation-evidence-artifact-role": MITIGATION_EVIDENCE_ARTIFACT_ROLE,
    }
    for field, expected in closed_evidence_contract.items():
        if schema.get(field) != expected:
            errors.append(f"{field} differs from the verifier's closed evidence contract")
    for field in ("expected-atomic-row-count", "expected-release-blocked-count"):
        if schema.get(field) != 9198:
            errors.append(f"{field} must be exactly 9198 for this candidate baseline")
    validity = schema.get("maximum-validity-days")
    if not isinstance(validity, int) or isinstance(validity, bool) or not 1 <= validity <= 180:
        errors.append("maximum-validity-days must be an integer from 1 through 180")
    return errors


def expand_atomic_rows(document: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    explicit = document.get("operation", [])
    gaps = document.get("unreviewed-gap", [])
    defaults = document.get("unreviewed-gap-defaults", {})
    if not isinstance(explicit, list):
        errors.append("atomic operation must be an array of tables")
        explicit = []
    if not isinstance(gaps, list):
        errors.append("atomic unreviewed-gap must be an array of tables")
        gaps = []
    if gaps and not isinstance(defaults, dict):
        errors.append("atomic unreviewed-gap-defaults must be a table")
        defaults = {}
    rows: list[dict[str, Any]] = []
    for offset, row in enumerate(explicit):
        if not isinstance(row, dict):
            errors.append(f"operation[{offset}] must be a table")
            continue
        rows.append(copy.deepcopy(row))
    for offset, gap in enumerate(gaps):
        if not isinstance(gap, dict):
            errors.append(f"unreviewed-gap[{offset}] must be a table")
            continue
        overlap = sorted(set(defaults) & set(gap))
        if overlap:
            errors.append(f"unreviewed-gap[{offset}] overrides fail-closed defaults: {', '.join(overlap)}")
        merged = copy.deepcopy(defaults)
        merged.update(copy.deepcopy(gap))
        rows.append(merged)
    identifiers: set[str] = set()
    for offset, row in enumerate(rows):
        identifier = row.get("id")
        if not isinstance(identifier, str) or not identifier.strip():
            errors.append(f"effective atomic row[{offset}] has no non-empty id")
            continue
        if identifier in identifiers:
            errors.append(f"duplicate effective atomic row id: {identifier}")
        identifiers.add(identifier)
        bindings = row.get("public-bindings")
        if not isinstance(bindings, list) or not bindings or any(not isinstance(x, str) or not x for x in bindings):
            errors.append(f"atomic row {identifier} must have non-empty public-bindings")
        if row.get("release-readiness") != "blocked":
            errors.append(f"atomic row {identifier} is not release-blocked")
    return sorted(rows, key=lambda item: str(item.get("id", ""))), errors


def _validate_date(value: Any, label: str, errors: list[str]) -> dt.date | None:
    if not isinstance(value, dt.date) or isinstance(value, dt.datetime):
        errors.append(f"{label} must be a TOML local date")
        return None
    return value


def validate_models(
    schema: dict[str, Any],
    document: dict[str, Any],
    ledger: dict[str, Any],
    rows: list[dict[str, Any]],
    snapshot: dict[str, Any],
    *,
    mode: str,
    as_of: dt.date,
    allow_synthetic_fixtures: bool = False,
) -> list[str]:
    errors = validate_schema(schema)
    if mode not in {"ci", "release"}:
        errors.append(f"unknown verification mode: {mode}")
    if allow_synthetic_fixtures and mode != "ci":
        errors.append("synthetic evidence fixtures are restricted to CI self-tests")
    if document.get("schema-version") != schema.get("document-schema-version"):
        errors.append("threat-model document schema-version mismatch")
    _as_nonempty_string(
        document.get("model-set-version"),
        "threat-model document.model-set-version",
        errors,
    )
    if document.get("coverage-policy") != schema.get("coverage-policy"):
        errors.append("threat-model coverage-policy mismatch")
    for field, hash_field in (
        ("source-ledger", "source-ledger-sha256"),
        ("source-operations", "source-operations-sha256"),
        ("source-api-snapshot", "source-api-snapshot-sha256"),
    ):
        try:
            path = safe_source_path(document.get(field, ""), label=field)
            expected = document.get(hash_field)
            if not isinstance(expected, str) or len(expected) != 64:
                errors.append(f"{hash_field} must be a SHA-256 digest")
            elif sha256_path(path) != expected:
                errors.append(f"{hash_field} does not bind the current {field} bytes")
        except ValidationError as exc:
            errors.append(str(exc))
    expected_rows = schema.get("expected-atomic-row-count")
    blocked = sum(row.get("release-readiness") == "blocked" for row in rows)
    if len(rows) != expected_rows or document.get("expected-atomic-row-count") != expected_rows:
        errors.append(f"effective atomic row count must remain {expected_rows}, found {len(rows)}")
    expected_blocked = schema.get("expected-release-blocked-count")
    if blocked != expected_blocked or document.get("expected-release-blocked-count") != expected_blocked:
        errors.append(f"release-blocked row count must remain {expected_blocked}, found {blocked}")
    entries = snapshot.get("entries") if isinstance(snapshot, dict) else None
    if not isinstance(entries, list) or len(entries) != 18891:
        errors.append("bound public API snapshot must contain exactly 18,891 classified units")
    evidence_records = ledger.get("evidence", [])
    if not isinstance(evidence_records, list):
        errors.append("ledger evidence must be an array of tables")
        evidence_records = []
    evidence: dict[str, dict[str, Any]] = {}
    for offset, record in enumerate(evidence_records):
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            errors.append(f"ledger evidence[{offset}] must have a string id")
            continue
        identifier = record["id"]
        if identifier in evidence:
            errors.append(f"duplicate ledger evidence id: {identifier}")
        evidence[identifier] = record

    def independently_replayed_and_bound(
        evidence_id: str,
        label: str,
        model: dict[str, Any],
        *,
        purpose: str,
        mitigation_id: str | None = None,
    ) -> bool:
        record = evidence.get(evidence_id)
        if not isinstance(record, dict):
            errors.append(f"{label} references unknown independent-review evidence {evidence_id}")
            return False
        valid = True
        identity_values = (
            evidence_id,
            record.get("owner"),
            record.get("reviewer"),
            record.get("independent-replay-reviewer"),
        )
        has_fixture_identity = any(
            isinstance(value, str)
            and any(marker in value.casefold() for marker in ("selftest", "fixture", "synthetic"))
            for value in identity_values
        ) or "synthetic-fixture-only" in record
        if has_fixture_identity and not allow_synthetic_fixtures:
            errors.append(
                f"{label} evidence {evidence_id} uses a synthetic fixture identity forbidden in normal verification"
            )
            valid = False
        model_id = model.get("id")
        model_set_version = document.get("model-set-version")
        if purpose == "review":
            expected_kind = REVIEW_EVIDENCE_KIND
            expected_purpose = REVIEW_EVIDENCE_PURPOSE
            expected_artifact_role = REVIEW_EVIDENCE_ARTIFACT_ROLE
        elif purpose == "mitigation":
            expected_kind = MITIGATION_EVIDENCE_KIND
            expected_purpose = MITIGATION_EVIDENCE_PURPOSE
            expected_artifact_role = MITIGATION_EVIDENCE_ARTIFACT_ROLE
        else:
            errors.append(f"{label} requests unknown evidence purpose {purpose}")
            return False
        if record.get("kind") != expected_kind:
            errors.append(
                f"{label} evidence {evidence_id}.kind must be exactly {expected_kind}"
            )
            valid = False
        if record.get("purpose") != expected_purpose:
            errors.append(
                f"{label} evidence {evidence_id}.purpose must be exactly {expected_purpose}"
            )
            valid = False
        if record.get("threat-model-id") != model_id:
            errors.append(
                f"{label} evidence {evidence_id} does not bind exact threat-model-id {model_id}"
            )
            valid = False
        if record.get("threat-model-set-version") != model_set_version:
            errors.append(
                f"{label} evidence {evidence_id} does not bind exact threat-model-set-version {model_set_version}"
            )
            valid = False
        try:
            expected_model_record_sha256 = threat_model_record_sha256(model)
        except ValidationError as exc:
            errors.append(f"{label} cannot canonicalize exact model table: {exc}")
            return False
        record_model_sha256 = record.get("threat-model-record-sha256")
        if record_model_sha256 != expected_model_record_sha256:
            errors.append(
                f"{label} evidence {evidence_id}.threat-model-record-sha256 does not bind the exact model table"
            )
            valid = False
        expected_applicability = evidence_applicability(
            model_id=str(model_id),
            model_set_version=str(model_set_version),
            purpose=expected_purpose,
            mitigation_id=mitigation_id,
        )
        if record.get("applicability") != expected_applicability:
            errors.append(
                f"{label} evidence {evidence_id}.applicability does not exactly bind its purpose"
            )
            valid = False
        if purpose == "mitigation":
            if record.get("verified-mitigation-id") != mitigation_id:
                errors.append(
                    f"{label} evidence {evidence_id} does not bind exact verified-mitigation-id {mitigation_id}"
                )
                valid = False
        elif "verified-mitigation-id" in record:
            errors.append(
                f"{label} review evidence {evidence_id} must not claim a verified mitigation"
            )
            valid = False
        if record.get("verdict") != "pass":
            errors.append(f"{label} evidence {evidence_id} is not passing")
            valid = False
        if record.get("independent-replay-status") != "complete":
            errors.append(f"{label} evidence {evidence_id} lacks completed independent replay")
            valid = False
        record_owner = record.get("owner")
        record_reviewer = record.get("reviewer")
        if not isinstance(record_owner, str) or not record_owner.strip():
            errors.append(f"{label} evidence {evidence_id} lacks an evidence owner")
            valid = False
        if (
            not isinstance(record_reviewer, str)
            or not record_reviewer.strip()
            or record_reviewer == record_owner
            or record_reviewer == model.get("owner")
        ):
            errors.append(f"{label} evidence {evidence_id} lacks a distinct evidence reviewer")
            valid = False
        if purpose == "review" and record_reviewer != model.get("reviewer"):
            errors.append(
                f"{label} evidence {evidence_id}.reviewer does not bind the model reviewer"
            )
            valid = False
        replay_reviewer = record.get("independent-replay-reviewer")
        if (
            not isinstance(replay_reviewer, str)
            or not replay_reviewer.strip()
            or any(
                replay_reviewer == candidate
                for candidate in (
                    record_owner,
                    record_reviewer,
                    model.get("owner"),
                    model.get("reviewer"),
                )
            )
        ):
            errors.append(
                f"{label} evidence {evidence_id} lacks a distinct independent-replay reviewer"
            )
            valid = False
        replay_date = record.get("independent-replay-reviewed-at")
        if not isinstance(replay_date, dt.date) or isinstance(replay_date, dt.datetime):
            errors.append(
                f"{label} evidence {evidence_id} lacks an independent-replay review date"
            )
            valid = False
        elif replay_date > as_of:
            errors.append(f"{label} evidence {evidence_id} independent replay is future-dated")
            valid = False
        reviewed_at = record.get("reviewed-at")
        valid_through = record.get("valid-through")
        if not isinstance(reviewed_at, dt.date) or isinstance(reviewed_at, dt.datetime):
            errors.append(f"{label} evidence {evidence_id} lacks an evidence review date")
            valid = False
        else:
            if reviewed_at > as_of:
                errors.append(f"{label} evidence {evidence_id} review is future-dated")
                valid = False
            if (
                isinstance(replay_date, dt.date)
                and not isinstance(replay_date, dt.datetime)
                and replay_date < reviewed_at
            ):
                errors.append(
                    f"{label} evidence {evidence_id} independent replay predates evidence review"
                )
                valid = False
        if not isinstance(valid_through, dt.date) or isinstance(valid_through, dt.datetime):
            errors.append(f"{label} evidence {evidence_id} lacks an evidence validity date")
            valid = False
        elif valid_through < as_of:
            errors.append(f"{label} evidence {evidence_id} is expired")
            valid = False
        if purpose == "review":
            if reviewed_at != model.get("reviewed-at"):
                errors.append(
                    f"{label} evidence {evidence_id}.reviewed-at does not bind the model review date"
                )
                valid = False
            if valid_through != model.get("valid-through"):
                errors.append(
                    f"{label} evidence {evidence_id}.valid-through does not bind the model validity date"
                )
                valid = False
        for field in ("source-commit", "source-tree"):
            value = record.get(field)
            if not isinstance(value, str) or len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
                errors.append(f"{label} evidence {evidence_id}.{field} is not an exact Git object id")
                valid = False
            elif value != ledger.get(field):
                errors.append(f"{label} evidence {evidence_id}.{field} does not bind the ledger subject")
                valid = False
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, list) or len(artifacts) != 1:
            errors.append(
                f"{label} evidence {evidence_id} must have exactly one dedicated {expected_artifact_role} artifact"
            )
            return False
        for artifact_offset, artifact in enumerate(artifacts):
            artifact_label = f"{label} evidence {evidence_id}.artifacts[{artifact_offset}]"
            if not isinstance(artifact, dict):
                errors.append(f"{artifact_label} must be a table")
                valid = False
                continue
            if set(artifact) != {"path", "sha256", "role"}:
                errors.append(
                    f"{artifact_label} must contain exactly path, sha256, and role"
                )
                valid = False
            if artifact.get("role") != expected_artifact_role:
                errors.append(
                    f"{artifact_label}.role must be exactly {expected_artifact_role}"
                )
                valid = False
            path_value = artifact.get("path")
            expected_digest = artifact.get("sha256")
            if not isinstance(path_value, str) or not path_value:
                errors.append(f"{artifact_label}.path must be a non-empty string")
                valid = False
                continue
            path_markers = {part.casefold() for part in Path(path_value).parts}
            if (
                any(marker in part for part in path_markers for marker in ("fixture", "selftest", "synthetic"))
                and not allow_synthetic_fixtures
            ):
                errors.append(
                    f"{artifact_label}.path uses a synthetic fixture location forbidden in normal verification"
                )
                valid = False
            try:
                artifact_path = _walk_unresolved_path(
                    Path(path_value),
                    base=REPO_ROOT,
                    allowed_root=REPO_ROOT,
                    label=f"{artifact_label}.path",
                    allow_parent=False,
                )
                artifact_path = _require_plain_file(artifact_path, label=f"{artifact_label}.path")
            except ValidationError as exc:
                errors.append(str(exc))
                valid = False
                continue
            if (
                not isinstance(expected_digest, str)
                or len(expected_digest) != 64
                or any(ch not in "0123456789abcdef" for ch in expected_digest)
            ):
                errors.append(f"{artifact_label}.sha256 must be an exact SHA-256 digest")
                valid = False
            elif sha256_path(artifact_path) != expected_digest:
                errors.append(f"{artifact_label}.sha256 does not bind current artifact bytes")
                valid = False
            try:
                artifact_record = load_json(artifact_path)
            except ValidationError as exc:
                errors.append(str(exc))
                valid = False
                continue
            expected_artifact_record = {
                "schema-version": 1,
                "artifact-role": expected_artifact_role,
                "evidence-id": evidence_id,
                "kind": expected_kind,
                "purpose": expected_purpose,
                "threat-model-id": model_id,
                "threat-model-set-version": model_set_version,
                "threat-model-record-sha256": expected_model_record_sha256,
                "applicability": expected_applicability,
                "owner": record_owner,
                "reviewer": record_reviewer,
                "reviewed-at": reviewed_at.isoformat()
                if isinstance(reviewed_at, dt.date)
                and not isinstance(reviewed_at, dt.datetime)
                else None,
                "valid-through": valid_through.isoformat()
                if isinstance(valid_through, dt.date)
                and not isinstance(valid_through, dt.datetime)
                else None,
                "verdict": record.get("verdict"),
                "independent-replay-status": record.get("independent-replay-status"),
                "independent-replay-reviewer": replay_reviewer,
                "independent-replay-reviewed-at": replay_date.isoformat()
                if isinstance(replay_date, dt.date)
                and not isinstance(replay_date, dt.datetime)
                else None,
                "source-commit": record.get("source-commit"),
                "source-tree": record.get("source-tree"),
            }
            if purpose == "mitigation":
                expected_artifact_record["verified-mitigation-id"] = mitigation_id
            if has_fixture_identity and allow_synthetic_fixtures:
                expected_artifact_record["fixture-only"] = True
            if artifact_record != expected_artifact_record:
                errors.append(
                    f"{artifact_label} is not the exact dedicated {expected_artifact_role} record"
                )
                valid = False
        return valid
    model_records = document.get("model", [])
    if not isinstance(model_records, list):
        errors.append("model must be an array of tables")
        return errors
    ids = [item.get("id") if isinstance(item, dict) else None for item in model_records]
    string_ids = [item for item in ids if isinstance(item, str)]
    if len(string_ids) != len(set(string_ids)):
        errors.append("threat model ids must be unique")
    if set(string_ids) != set(MANDATORY_MODEL_IDS) or len(string_ids) != len(MANDATORY_MODEL_IDS):
        missing = sorted(set(MANDATORY_MODEL_IDS) - set(string_ids))
        extra = sorted(set(string_ids) - set(MANDATORY_MODEL_IDS))
        errors.append(f"mandatory threat-model set mismatch; missing={missing}, extra={extra}")
    maximum_days = schema.get("maximum-validity-days", 180)
    for offset, model in enumerate(model_records):
        label = f"model[{offset}]"
        if not isinstance(model, dict):
            errors.append(f"{label} must be a table")
            continue
        identifier = str(model.get("id", f"index-{offset}"))
        label = f"model {identifier}"
        for field in REQUIRED_STRING_FIELDS:
            _as_nonempty_string(model.get(field), f"{label}.{field}", errors)
        for field in REQUIRED_LIST_FIELDS:
            _as_nonempty_string_list(model.get(field), f"{label}.{field}", errors)
        if model.get("status") not in ALLOWED_STATUSES:
            errors.append(f"{label}.status is not allowed")
        if model.get("independent-review-status") not in ALLOWED_REVIEW_STATUSES:
            errors.append(f"{label}.independent-review-status is not allowed")
        review_evidence = model.get("independent-review-evidence")
        if not isinstance(review_evidence, list) or any(
            not isinstance(item, str) or not item for item in review_evidence
        ):
            errors.append(f"{label}.independent-review-evidence must be an array of evidence ids")
            review_evidence = []
        elif len(review_evidence) != len(set(review_evidence)):
            errors.append(f"{label}.independent-review-evidence contains duplicates")
        for evidence_id in review_evidence:
            if evidence_id not in evidence:
                errors.append(f"{label} references unknown independent-review evidence {evidence_id}")
        if model.get("independent-review-status") == "required" and review_evidence:
            errors.append(f"{label} pending independent review must not cite completion evidence")
        if model.get("independent-review-status") == "complete":
            if not review_evidence:
                errors.append(f"{label} self-attested complete review has no independent-review evidence")
            for evidence_id in review_evidence:
                independently_replayed_and_bound(
                    evidence_id,
                    label,
                    model,
                    purpose="review",
                )
        if model.get("status") == "active" and model.get("independent-review-status") != "complete":
            errors.append(f"{label} cannot be active without completed independent review")
        if model.get("status") == "active" or model.get("independent-review-status") == "complete":
            reviewer_identity = model.get("reviewer")
            normalized_reviewer = (
                reviewer_identity.casefold()
                if isinstance(reviewer_identity, str)
                else ""
            )
            if (
                not normalized_reviewer.strip()
                or "dcrypt" in normalized_reviewer
                or any(
                    marker in normalized_reviewer
                    for marker in FORBIDDEN_COMPLETED_REVIEWER_MARKERS
                )
            ):
                errors.append(
                    f"{label} active/completed review requires a concrete non-project independent reviewer identity"
                )
        if model.get("owner") == model.get("reviewer"):
            errors.append(f"{label} owner and reviewer must be distinct")
        reviewed = _validate_date(model.get("reviewed-at"), f"{label}.reviewed-at", errors)
        expires = _validate_date(model.get("valid-through"), f"{label}.valid-through", errors)
        if reviewed and expires:
            if reviewed > as_of:
                errors.append(f"{label}.reviewed-at is in the future")
            if expires < reviewed:
                errors.append(f"{label}.valid-through precedes reviewed-at")
            if (expires - reviewed).days > maximum_days:
                errors.append(f"{label} validity exceeds {maximum_days} days")
            if expires < as_of:
                errors.append(f"{label} expired on {expires.isoformat()}")
        if model.get("atomic-row-selector") != "all-atomic-rows":
            errors.append(f"{label}.atomic-row-selector must remain all-atomic-rows")
        if model.get("affected-row-set") != f"coverage.json#/models/{identifier}":
            errors.append(f"{label}.affected-row-set does not bind its exact coverage summary")
        dimension_references = {
            "affected-algorithms": ["coverage.json#/dimensions/algorithms/values"],
            "affected-operations": ["coverage.json#/dimensions/operations/values"],
            "affected-profiles": ["coverage.json#/dimensions/feature_profiles/values"],
            "affected-platforms": ["coverage.json#/dimensions/platforms/values"],
        }
        for field, expected_reference in dimension_references.items():
            if model.get(field) != expected_reference:
                errors.append(f"{label}.{field} must bind the exact coverage dimension {expected_reference[0]}")
        assets = model.get("assets")
        if not isinstance(assets, list) or not assets:
            errors.append(f"{label}.assets must be a non-empty array")
        else:
            asset_ids: list[str] = []
            for asset_offset, asset in enumerate(assets):
                asset_label = f"{label}.assets[{asset_offset}]"
                if not isinstance(asset, dict):
                    errors.append(f"{asset_label} must be a table")
                    continue
                asset_id = _as_nonempty_string(asset.get("id"), f"{asset_label}.id", errors)
                if asset_id:
                    asset_ids.append(asset_id)
                _as_nonempty_string_list(asset.get("security-properties"), f"{asset_label}.security-properties", errors)
            if len(asset_ids) != len(set(asset_ids)):
                errors.append(f"{label}.assets contains duplicate ids")
        tiers = model.get("required-evidence-tiers", [])
        if isinstance(tiers, list):
            unknown = sorted(set(tiers) - ALLOWED_EVIDENCE_TIERS)
            if unknown:
                errors.append(f"{label}.required-evidence-tiers has unknown values: {unknown}")
        mitigations = model.get("mitigations")
        if not isinstance(mitigations, list) or not mitigations:
            errors.append(f"{label}.mitigations must be a non-empty array")
        else:
            mitigation_ids: list[str] = []
            for mitigation_offset, mitigation in enumerate(mitigations):
                mitigation_label = f"{label}.mitigations[{mitigation_offset}]"
                if not isinstance(mitigation, dict):
                    errors.append(f"{mitigation_label} must be a table")
                    continue
                mid = _as_nonempty_string(mitigation.get("id"), f"{mitigation_label}.id", errors)
                if mid:
                    mitigation_ids.append(mid)
                _as_nonempty_string(mitigation.get("description"), f"{mitigation_label}.description", errors)
                status_value = mitigation.get("status")
                if status_value not in ALLOWED_MITIGATION_STATUSES:
                    errors.append(f"{mitigation_label}.status is not allowed")
                evidence_ids = mitigation.get("evidence")
                if not isinstance(evidence_ids, list) or any(not isinstance(item, str) or not item for item in evidence_ids):
                    errors.append(f"{mitigation_label}.evidence must be an array of evidence ids")
                    evidence_ids = []
                elif len(evidence_ids) != len(set(evidence_ids)):
                    errors.append(f"{mitigation_label}.evidence contains duplicates")
                for evidence_id in evidence_ids:
                    if evidence_id not in evidence:
                        errors.append(f"{mitigation_label} references unknown evidence {evidence_id}")
                if status_value == "planned" and evidence_ids:
                    errors.append(f"{mitigation_label} planned mitigation must not cite implementation evidence")
                if status_value == "implemented-unverified" and not evidence_ids:
                    errors.append(f"{mitigation_label} implemented-unverified mitigation needs bounded evidence")
                if status_value == "verified":
                    binding_results = [
                        independently_replayed_and_bound(
                            evidence_id,
                            mitigation_label,
                            model,
                            purpose="mitigation",
                            mitigation_id=mid,
                        )
                        for evidence_id in evidence_ids
                    ]
                    independently_replayed = bool(evidence_ids) and all(binding_results)
                    if not independently_replayed:
                        errors.append(
                            f"{mitigation_label} verified status requires independently replayed passing evidence"
                        )
                else:
                    for evidence_id in evidence_ids:
                        cited = evidence.get(evidence_id)
                        if isinstance(cited, dict) and (
                            cited.get("kind") == MITIGATION_EVIDENCE_KIND
                            or cited.get("purpose") == MITIGATION_EVIDENCE_PURPOSE
                        ):
                            errors.append(
                                f"{mitigation_label} cites dedicated verification evidence but status is not verified"
                            )
                            independently_replayed_and_bound(
                                evidence_id,
                                mitigation_label,
                                model,
                                purpose="mitigation",
                                mitigation_id=mid,
                            )
            if len(mitigation_ids) != len(set(mitigation_ids)):
                errors.append(f"{label}.mitigations contains duplicate ids")
        residual = model.get("residual-risk")
        if not isinstance(residual, dict):
            errors.append(f"{label}.residual-risk must be a table")
        else:
            for field in REQUIRED_RESIDUAL_FIELDS:
                _as_nonempty_string(residual.get(field), f"{label}.residual-risk.{field}", errors)
            for field in ("likelihood", "impact", "rating"):
                if residual.get(field) not in ALLOWED_RISK_LEVELS:
                    errors.append(f"{label}.residual-risk.{field} is not an allowed risk level")
            if residual.get("disposition") not in ALLOWED_RISK_DISPOSITIONS:
                errors.append(f"{label}.residual-risk.disposition is not allowed")
        if mode == "release":
            if model.get("status") != "active":
                errors.append(f"{label} is not active in release mode")
            if model.get("independent-review-status") != "complete":
                errors.append(f"{label} lacks completed independent review in release mode")
            if isinstance(residual, dict) and residual.get("rating") in {"high", "critical"}:
                errors.append(f"{label} has release-blocking {residual.get('rating')} residual risk")
            unclosed = [
                mitigation.get("id", "<unknown>")
                for mitigation in mitigations or []
                if isinstance(mitigation, dict) and mitigation.get("status") != "verified"
            ]
            if (
                isinstance(residual, dict)
                and residual.get("disposition") == "mitigate"
                and unclosed
            ):
                errors.append(f"{label} has unresolved mitigate disposition: {unclosed}")
    return errors


def _atomic_dimensions(rows: list[dict[str, Any]], ledger: dict[str, Any]) -> dict[str, Any]:
    profile_records = ledger.get("profile", []) if isinstance(ledger.get("profile", []), list) else []
    ledger_profiles = sorted(
        record["id"]
        for record in profile_records
        if isinstance(record, dict)
        and record.get("api-inventory") is True
        and record.get("support") == "supported"
        and isinstance(record.get("id"), str)
    )
    ledger_platforms = sorted(
        {
            record["target"]
            for record in profile_records
            if isinstance(record, dict)
            and record.get("api-inventory") is True
            and record.get("support") == "supported"
            and isinstance(record.get("target"), str)
        }
    )
    fields = {
        "algorithms": sorted({str(row.get("algorithm", "")) for row in rows if row.get("algorithm")}),
        "operations": sorted({str(row.get("operation", "")) for row in rows if row.get("operation")}),
        "parameter_sets": sorted({str(row.get("parameter-set", "")) for row in rows if row.get("parameter-set")}),
        "encodings": sorted({str(row.get("encoding", "")) for row in rows if row.get("encoding")}),
        "modes_profiles": sorted({str(row.get("mode-profile", "")) for row in rows if row.get("mode-profile")}),
        "feature_profiles": ledger_profiles,
        "platforms": ledger_platforms,
    }
    return {
        name: {
            "count": len(values),
            "values": values,
            "values_sha256": canonical_value_hash(values),
        }
        for name, values in fields.items()
    }


def build_coverage(
    schema: dict[str, Any],
    document: dict[str, Any],
    ledger: dict[str, Any],
    rows: list[dict[str, Any]],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    model_ids = sorted(MANDATORY_MODEL_IDS)
    operation_ids = [str(row["id"]) for row in rows]
    all_bindings = sorted({binding for row in rows for binding in row.get("public-bindings", [])})
    mappings = []
    for row in rows:
        mappings.append(
            {
                "algorithm": row.get("algorithm", ""),
                "id": row["id"],
                "operation": row.get("operation", ""),
                "public_bindings": sorted(set(row.get("public-bindings", []))),
                "row_kind": row.get("row-kind", ""),
                "semantic_review": row.get("semantic-review", ""),
                "support": row.get("support", ""),
                "threat_models": model_ids,
            }
        )
    dimensions = _atomic_dimensions(rows, ledger)
    dimension_hash = sha256_bytes(canonical_json_bytes(dimensions))
    row_hash = canonical_value_hash(operation_ids)
    binding_hash = canonical_value_hash(all_bindings)
    summaries: dict[str, dict[str, Any]] = {}
    for model_id in model_ids:
        summaries[model_id] = {
            "atomic_row_count": len(rows),
            "atomic_row_ids_sha256": row_hash,
            "public_binding_count": len(all_bindings),
            "public_bindings_sha256": binding_hash,
            "row_membership_field": "rows[].threat_models",
            "dimension_set_sha256": dimension_hash,
        }
    entries = snapshot.get("entries", []) if isinstance(snapshot, dict) else []
    return {
        "schema_version": schema["coverage-schema-version"],
        "coverage_policy": schema["coverage-policy"],
        "model_set_version": document["model-set-version"],
        "sources": {
            "ledger": {"path": document["source-ledger"], "sha256": document["source-ledger-sha256"]},
            "operations": {"path": document["source-operations"], "sha256": document["source-operations-sha256"]},
            "public_api_snapshot": {"path": document["source-api-snapshot"], "sha256": document["source-api-snapshot-sha256"]},
            "threat_models": {
                "path": "threat-models.toml",
                "sha256": sha256_path(
                    safe_fixed_input_path(
                        "threat-models.toml", label="threat-model document"
                    )
                ),
            },
            "schema": {
                "path": "schema.toml",
                "sha256": sha256_path(
                    safe_fixed_input_path("schema.toml", label="threat-model schema")
                ),
            },
        },
        "counts": {
            "atomic_rows": len(rows),
            "release_blocked_rows": sum(row.get("release-readiness") == "blocked" for row in rows),
            "curated_rows": sum(row.get("semantic-review") == "curated" for row in rows),
            "unreviewed_rows": sum(row.get("semantic-review") == "required" for row in rows),
            "public_api_units": len(entries) if isinstance(entries, list) else 0,
            "threat_models": len(model_ids),
        },
        "atomic_row_ids_sha256": row_hash,
        "public_bindings_sha256": binding_hash,
        "dimensions": dimensions,
        "models": summaries,
        "rows": mappings,
    }


def validate_coverage(actual: Any, expected: dict[str, Any]) -> list[str]:
    """Validate the exact generated mapping, with useful fail-closed diagnostics."""
    errors: list[str] = []
    if not isinstance(actual, dict):
        return ["coverage root must be an object"]
    actual_rows = actual.get("rows")
    expected_rows = expected.get("rows", [])
    if not isinstance(actual_rows, list):
        return ["coverage rows must be an array"]
    actual_ids = [row.get("id") if isinstance(row, dict) else None for row in actual_rows]
    expected_ids = [row["id"] for row in expected_rows]
    string_ids = [item for item in actual_ids if isinstance(item, str)]
    duplicate_ids = sorted({item for item in string_ids if string_ids.count(item) > 1})
    if duplicate_ids:
        errors.append(f"coverage contains duplicate atomic row ids: {duplicate_ids[:5]}")
    missing = sorted(set(expected_ids) - set(string_ids))
    extra = sorted(set(string_ids) - set(expected_ids))
    if missing:
        errors.append(f"coverage is missing exact atomic row ids: {missing[:5]}")
    if extra:
        errors.append(f"coverage contains unexpected atomic row ids: {extra[:5]}")
    expected_by_id = {row["id"]: row for row in expected_rows}
    for offset, row in enumerate(actual_rows):
        if not isinstance(row, dict):
            errors.append(f"coverage rows[{offset}] must be an object")
            continue
        identifier = row.get("id")
        if identifier in expected_by_id and row != expected_by_id[identifier]:
            errors.append(f"coverage row differs from bound atomic row mapping: {identifier}")
    expected_without_rows = {key: value for key, value in expected.items() if key != "rows"}
    actual_without_rows = {key: value for key, value in actual.items() if key != "rows"}
    if actual_without_rows != expected_without_rows:
        errors.append("coverage metadata, dimension inventory, or model summaries differ from expected values")
    if len(actual_rows) != len(expected_rows):
        errors.append(f"coverage row count mismatch: expected {len(expected_rows)}, found {len(actual_rows)}")
    return errors


def _md_list(lines: list[str], title: str, values: list[str]) -> None:
    lines.extend([f"### {title}", ""])
    for value in values:
        lines.append(f"- {value}")
    lines.append("")


def render_markdown(document: dict[str, Any], coverage: dict[str, Any]) -> bytes:
    counts = coverage["counts"]
    lines = [
        "# dcrypt candidate threat models",
        "",
        "> Status: candidate and independently unreviewed. This document records scope,",
        "> residual risk, and required evidence. It is not a passing assurance verdict.",
        "",
        "## Bound inventory",
        "",
        f"- Model set: `{document['model-set-version']}`",
        f"- Coverage policy: `{coverage['coverage_policy']}`",
        f"- Public API units: {counts['public_api_units']:,}",
        f"- Exact atomic rows: {counts['atomic_rows']:,}",
        f"- Curated rows: {counts['curated_rows']:,}",
        f"- Semantically unreviewed rows: {counts['unreviewed_rows']:,}",
        f"- Release-blocked rows: {counts['release_blocked_rows']:,}",
        f"- Atomic row ID set SHA-256: `{coverage['atomic_row_ids_sha256']}`",
        f"- Public binding set SHA-256: `{coverage['public_bindings_sha256']}`",
        "",
        "Every exact row in `coverage.json` names all eleven applicable threat models.",
        "This deliberately conservative mapping remains in force while low-level rows await",
        "semantic review. It does not clear or reduce any release blocker.",
        "",
        "## Model summary",
        "",
        "| ID | Status | Independent review | Residual rating | Valid through | Exact rows |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    models_by_id = {model["id"]: model for model in document["model"]}
    summary_by_id = coverage["models"]
    for model_id in sorted(models_by_id):
        model = models_by_id[model_id]
        summary = summary_by_id[model_id]
        lines.append(
            f"| `{model_id}` | {model['status']} | {model['independent-review-status']} | "
            f"{model['residual-risk']['rating']} | {model['valid-through'].isoformat()} | "
            f"{summary['atomic_row_count']:,} |"
        )
    lines.append("")
    for model_id in sorted(models_by_id):
        model = models_by_id[model_id]
        summary = summary_by_id[model_id]
        lines.extend(
            [
                f"## {model_id}: {model['title']}",
                "",
                f"- Owner: {model['owner']}",
                f"- Reviewer: {model['reviewer']}",
                f"- Review state: `{model['independent-review-status']}`",
                f"- Independent review evidence: {', '.join(f'`{item}`' for item in model['independent-review-evidence']) or 'none'}",
                f"- Review date: {model['reviewed-at'].isoformat()}",
                f"- Expiry: {model['valid-through'].isoformat()}",
                f"- Public scope: {model['public-entrypoint-scope']}",
                f"- Exact atomic rows: {summary['atomic_row_count']:,}",
                f"- Atomic row ID set SHA-256: `{summary['atomic_row_ids_sha256']}`",
                f"- Exact mapping: `{model['affected-row-set']}`",
                f"- Affected algorithms: `{model['affected-algorithms'][0]}`",
                f"- Affected operations: `{model['affected-operations'][0]}`",
                f"- Affected profiles: `{model['affected-profiles'][0]}`",
                f"- Affected platforms: `{model['affected-platforms'][0]}`",
                "",
                "### Assets and security properties",
                "",
            ]
        )
        for asset in model["assets"]:
            lines.append(f"- `{asset['id']}`: {', '.join(asset['security-properties'])}")
        lines.append("")
        titled_lists = (
            ("Trust boundaries", "trust-boundaries"),
            ("Attacker capabilities", "attacker-capabilities"),
            ("Preconditions", "preconditions"),
            ("Explicitly excluded capabilities", "excluded-capabilities"),
            ("Assumptions", "assumptions"),
            ("Known limitations", "known-limitations"),
            ("Required evidence tiers", "required-evidence-tiers"),
            ("Claim-invalidation conditions", "claim-invalidation-conditions"),
        )
        for title, field in titled_lists:
            _md_list(lines, title, model[field])
        lines.extend(["### Mitigations", ""])
        for mitigation in model["mitigations"]:
            evidence = ", ".join(f"`{item}`" for item in mitigation["evidence"]) or "none"
            lines.append(
                f"- `{mitigation['id']}` — **{mitigation['status']}**; evidence: {evidence}. "
                f"{mitigation['description']}"
            )
        risk = model["residual-risk"]
        lines.extend(
            [
                "",
                "### Residual risk",
                "",
                f"- Likelihood: `{risk['likelihood']}`",
                f"- Impact: `{risk['impact']}`",
                f"- Rating: `{risk['rating']}`",
                f"- Disposition: `{risk['disposition']}`",
                f"- Rationale: {risk['rationale']}",
                f"- Acceptance authority: {risk['acceptance-authority']}",
                "",
            ]
        )
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def expected_artifacts(*, mode: str = "ci", as_of: dt.date | None = None) -> tuple[dict[str, Any], bytes, list[str]]:
    as_of = as_of or dt.date.today()
    schema, models, ledger, operations, snapshot = load_inputs()
    rows, row_errors = expand_atomic_rows(operations)
    errors = row_errors + validate_models(schema, models, ledger, rows, snapshot, mode=mode, as_of=as_of)
    if errors:
        return {}, b"", errors
    coverage = build_coverage(schema, models, ledger, rows, snapshot)
    return coverage, render_markdown(models, coverage), []


def verify_generated_artifacts(*, mode: str, as_of: dt.date | None = None) -> tuple[dict[str, Any], list[str]]:
    coverage, markdown, errors = expected_artifacts(mode=mode, as_of=as_of)
    if errors:
        return {}, errors
    models = load_model_document()
    try:
        coverage_path = safe_generated_path(models.get("generated-coverage", ""), label="generated-coverage")
        document_path = safe_generated_path(models.get("generated-document", ""), label="generated-document")
    except ValidationError as exc:
        return coverage, [str(exc)]
    expected_coverage = pretty_json_bytes(coverage)
    try:
        actual_coverage = load_json(coverage_path)
        errors.extend(validate_coverage(actual_coverage, coverage))
    except ValidationError as exc:
        errors.append(str(exc))
    if coverage_path.read_bytes() != expected_coverage:
        errors.append(f"generated coverage drift: run generate-threat-models.py ({coverage_path})")
    if document_path.read_bytes() != markdown:
        errors.append(f"generated threat-model document drift: run generate-threat-models.py ({document_path})")
    return coverage, errors


def format_errors(errors: list[str]) -> str:
    return "\n".join(f"ERROR: {error}" for error in errors)
