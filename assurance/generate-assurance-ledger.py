#!/usr/bin/env python3
"""Deterministically materialize dcrypt's curated atomic API bindings.

The concise curated TOML is the review-authoritative semantic source: each
operation names exact ``kind:selector|canonical`` witnesses. This tool performs
no prefix/ranking guess. It expands those bindings to visible rustdoc aliases,
derives exact target/profile presence and fail-closed unreviewed gap rows,
writes back-references into the classified snapshot, and renders the derived
atomic map and supported-algorithm document.

`curated-operations.toml` is the concise, review-authoritative semantic input.
This tool deterministically derives cross-crate aliases and explicit blocked
rows for every otherwise unreviewed callable/data surface. Normal CI uses
``--check`` only; no command infers a supported claim.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any


ROOT = Path(__file__).resolve().parent
CURATED_PATH = ROOT / "curated-operations.toml"
OPS_PATH = ROOT / "atomic-operations.toml"
SNAPSHOT_PATH = ROOT / "public-api-snapshot.json"
DOC_PATH = ROOT / "SUPPORTED-ALGORITHMS.md"
ACVP_VECTOR_MANIFEST_PATH = ROOT / "acvp-vector-manifest.json"
UNCLASSIFIED = "UNCLASSIFIED"
CALLABLE_KINDS = {
    "assoc_const", "constant", "function", "macro", "static", "trait", "trait_impl"
}
DATA_KINDS = {"field", "variant"}
SURFACE_BY_PACKAGE = {
    "dcrypt": "facade-surface",
    "dcrypt-algorithms": "algorithm-primitives",
    "dcrypt-api": "api-contracts",
    "dcrypt-common": "common-support",
    "dcrypt-hybrid": "hybrid-constructions",
    "dcrypt-internal": "internal-support",
    "dcrypt-kem": "kem-constructions",
    "dcrypt-params": "parameter-data",
    "dcrypt-pke": "pke-constructions",
    "dcrypt-sign": "signature-constructions",
    "dcrypt-symmetric": "symmetric-constructions",
    "dcrypt-utils": "utility-surface",
}
FIELDS = [
    "id", "row-kind", "crate", "surface", "entrypoint-bindings", "public-bindings",
    "public-paths", "entrypoints", "algorithm", "standard", "parameter-set",
    "operation", "action-selectors", "encoding", "mode-profile", "dst-context-prehash",
    "feature-profile", "profiles", "platforms", "support", "vector-source",
    "independent-oracle", "oracle-provenance", "fuzz-target",
    "side-channel-claim", "required-evidence-tier", "audit-coverage",
    "known-limitation", "owner", "required-evidence", "release-readiness",
    "semantic-review", "semantic-review-deadline",
]
DERIVED_FIELDS = {"public-paths", "entrypoints", "profiles", "platforms"}
CURATED_FIELDS = [field for field in FIELDS if field not in DERIVED_FIELDS]
GAP_RECORD_FIELDS = [
    "id", "row-kind", "crate", "surface", "entrypoint-bindings",
    "public-bindings", "algorithm", "operation", "action-selectors",
]
GAP_DEFAULT_FIELDS = [
    field for field in FIELDS
    if field not in GAP_RECORD_FIELDS and field not in DERIVED_FIELDS
]


def parse_binding(value: str) -> tuple[str, str, str]:
    witness, canonical = value.split("|", 1)
    kind, selector = witness.split(":", 1)
    return kind, selector, canonical


def binding(kind: str, selector: str, canonical: str) -> str:
    return f"{kind}:{selector}|{canonical}"


def all_trait_methods(entry: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for names in entry.get("trait_methods", {}).values():
        result.update(str(name) for name in names)
    return result


def witness_profiles(entry: dict[str, Any], kind: str, selector: str) -> set[str]:
    if kind != "trait-method":
        return set(entry["profiles"])
    return {
        profile
        for profile, names in entry.get("trait_methods", {}).items()
        if selector in names
    }


def operation_template(
    *, identifier: str, package: str, surface: str, canonical: str,
    kind: str, selector: str, action: str, support: str,
) -> dict[str, Any]:
    algorithm = (
        canonical.split("::{impl ", 1)[0]
        if "::{impl " in canonical
        else canonical.rsplit("::", 1)[0]
    )
    return {
        "id": identifier,
        "row-kind": "operation",
        "crate": package,
        "surface": surface,
        "entrypoint-bindings": [binding(kind, selector, canonical)],
        "public-bindings": [binding(kind, selector, canonical)],
        "public-paths": [],
        "entrypoints": [],
        "algorithm": algorithm,
        "standard": "unclassified low-level/public helper; standards mapping pending",
        "parameter-set": "unclassified type-bound-generic",
        "operation": action,
        "action-selectors": [selector],
        "encoding": "exact public declaration; format classification pending",
        "mode-profile": "exact-callable",
        "dst-context-prehash": "n/a or not yet classified",
        "feature-profile": "profile-bound: exact rustdoc presence",
        "profiles": [],
        "platforms": [],
        "support": support,
        "vector-source": "blocked: no accepted atomic vector row",
        "independent-oracle": "blocked: no accepted independent atomic oracle",
        "oracle-provenance": "not yet accepted",
        "fuzz-target": "blocked: no semantic differential target",
        "side-channel-claim": "no claim until the low-level callable is classified",
        "required-evidence-tier": "classification + audit + oracle + fuzz + side-channel disposition",
        "audit-coverage": "not independently audited",
        "known-limitation": (
            "Public callable or data surface is explicitly inventoried but awaits "
            "standards/parameter/encoding classification and the required independent "
            "evidence."
        ),
        "owner": "dcrypt security assurance",
        "required-evidence": ["public-api-inventory-integrity"],
        "release-readiness": "blocked",
        "semantic-review": "required",
        "semantic-review-deadline": "2026-11-09",
    }


def binding_is_present(
    value: str, *, package: str, entries: list[dict[str, Any]]
) -> bool:
    kind, selector, canonical = parse_binding(value)
    for entry in entries:
        if entry["package"] != package or entry["canonical"] != canonical:
            continue
        if kind == "trait-method":
            if entry["kind"] == "trait_impl" and witness_profiles(entry, kind, selector):
                return True
        elif entry["kind"] == kind:
            return True
    return False


def clone_curated_cross_package_aliases(
    operations: list[dict[str, Any]], entries: list[dict[str, Any]]
) -> None:
    """Carry reviewed semantics across exact cross-crate public aliases.

    Rustdoc reports a facade alias with the owning crate's canonical identity.
    Atomic rows remain crate-scoped, so each importing published crate receives
    a separate row whose witnesses are the exact canonical bindings actually
    reachable through that crate.  No semantic fields are inferred.
    """

    packages = sorted(SURFACE_BY_PACKAGE)
    existing_ids = {operation["id"] for operation in operations}
    additions: list[dict[str, Any]] = []
    for operation in list(operations):
        if operation.get("semantic-review") != "curated":
            continue
        for package in packages:
            if package == operation["crate"]:
                continue
            alias_id = f"alias.{package}.{operation['id']}"
            if alias_id in existing_ids:
                continue
            available_entrypoints = sorted(
                value
                for value in operation.get("entrypoint-bindings", [])
                if binding_is_present(value, package=package, entries=entries)
            )
            available_public = sorted(
                value
                for value in operation.get("public-bindings", [])
                if binding_is_present(value, package=package, entries=entries)
            )
            available_public = sorted(set(available_public) | set(available_entrypoints))
            if not available_entrypoints and not (
                operation.get("row-kind") == "data-surface" and available_public
            ):
                continue
            alias = copy.deepcopy(operation)
            existing_ids.add(alias_id)
            alias["id"] = alias_id
            alias["crate"] = package
            alias["surface"] = SURFACE_BY_PACKAGE[package]
            alias["feature-profile"] = (
                "profile-bound: exact cross-crate alias presence"
            )
            alias["entrypoint-bindings"] = available_entrypoints
            alias["public-bindings"] = available_public
            alias["known-limitation"] = (
                f"Cross-crate alias of {operation['id']}. "
                + str(operation["known-limitation"])
            )
            alias["public-paths"] = []
            alias["entrypoints"] = []
            alias["profiles"] = []
            alias["platforms"] = []
            additions.append(alias)
    operations.extend(additions)


def add_callable_gap_rows(
    operations: list[dict[str, Any]], entries: list[dict[str, Any]]
) -> None:
    covered: set[tuple[str, str, str]] = set()
    for operation in operations:
        binding_values = list(operation.get("entrypoint-bindings", []))
        if operation.get("row-kind") == "data-surface" and operation.get("semantic-review") == "curated":
            binding_values.extend(operation.get("public-bindings", []))
        for value in binding_values:
            kind, selector, canonical = parse_binding(value)
            covered.add((operation["crate"], canonical, selector))
    identifiers = {operation["id"] for operation in operations}
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in entries:
        if entry.get("surface") == UNCLASSIFIED:
            continue
        if entry["kind"] in {"assoc_const", "constant", "function", "macro", "static"}:
            selector = str(entry["canonical"]).rsplit("::", 1)[-1]
            unique[(entry["package"], entry["canonical"], selector)] = entry
        elif entry["kind"] == "trait_impl":
            for selector in sorted(all_trait_methods(entry)):
                unique[(entry["package"], entry["canonical"], selector)] = entry
    for key, entry in sorted(unique.items()):
        package, canonical, selector = key
        if key in covered:
            continue
        witness_kind = (
            "trait-method" if entry["kind"] == "trait_impl" else entry["kind"]
        )
        digest = hashlib.sha256(f"{package}\0{canonical}\0{selector}".encode()).hexdigest()
        action = selector.replace("/", "-").replace(",", "-")
        identifier = f"callable.{package}.{action}.{digest}"
        if identifier in identifiers:
            raise RuntimeError(f"callable row id collision: {identifier}")
        identifiers.add(identifier)
        operations.append(operation_template(
            identifier=identifier,
            package=package,
            surface=SURFACE_BY_PACKAGE[package],
            canonical=canonical,
            kind=witness_kind,
            selector=selector,
            action=action,
            support="low-level",
        ))


def add_data_gap_rows(
    operations: list[dict[str, Any]], entries: list[dict[str, Any]]
) -> None:
    """Give every public field/variant a fail-closed, exact data-surface row."""

    covered = {
        (operation["crate"], value)
        for operation in operations
        for value in operation.get("public-bindings", [])
    }
    identifiers = {operation["id"] for operation in operations}
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in entries:
        if entry["kind"] not in DATA_KINDS:
            continue
        selector = str(entry["canonical"]).rsplit("::", 1)[-1]
        unique[(entry["package"], entry["canonical"], selector)] = entry
    for (package, canonical, selector), entry in sorted(unique.items()):
        value = binding(entry["kind"], selector, canonical)
        if (package, value) in covered:
            continue
        digest = hashlib.sha256(
            f"data\0{package}\0{canonical}\0{selector}".encode()
        ).hexdigest()
        identifier = f"data.{package}.{entry['kind']}.{digest}"
        if identifier in identifiers:
            raise RuntimeError(f"data row id collision: {identifier}")
        identifiers.add(identifier)
        row = operation_template(
            identifier=identifier,
            package=package,
            surface=SURFACE_BY_PACKAGE[package],
            canonical=canonical,
            kind=entry["kind"],
            selector=selector,
            action=f"classify-public-{entry['kind']}",
            support="low-level",
        )
        row["row-kind"] = "data-surface"
        row["action-selectors"] = []
        row["entrypoint-bindings"] = []
        row["public-bindings"] = [value]
        operations.append(row)


def initialize_snapshot_classifications(entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        package = entry["package"]
        entry["surface"] = SURFACE_BY_PACKAGE[package]
        entry["operation_refs"] = []
        entry.pop("callable_disposition", None)
        entry.pop("non_operation_reason", None)
        entry.pop("unsupported_reason", None)
        entry.pop("unsupported_owner", None)
        entry.pop("unsupported_review_due", None)
        canonical = str(entry["canonical"])
        if "X25519" in canonical:
            entry["classification"] = "intentionally-unsupported"
            entry["unsupported_reason"] = (
                "Marker-only X25519 types are exported, but dcrypt exposes no "
                "X25519 cryptographic operation in v3."
            )
            entry["unsupported_owner"] = "dcrypt security assurance"
            entry["unsupported_review_due"] = "2026-11-09"
        elif package in {"dcrypt-algorithms", "dcrypt-common", "dcrypt-internal"}:
            entry["classification"] = "internal-like-low-level"
        else:
            entry["classification"] = "metadata-only"


def expand(operations: list[dict[str, Any]], entries: list[dict[str, Any]]) -> None:
    by_package_canonical: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for entry in entries:
        by_package_canonical.setdefault((entry["package"], entry["canonical"]), []).append(entry)
        entry["operation_refs"] = []
        entry.pop("trait_method_assurance", None)
    support_classes = {
        "supported": "supported-operation",
        "transitional": "transitional-legacy",
        "low-level": "internal-like-low-level",
        "unsupported": "intentionally-unsupported",
    }
    for operation in operations:
        row_kind = operation.get("row-kind", "operation")
        entrypoints: set[str] = set()
        public_paths: set[str] = set()
        exact_profiles: set[str] = set()
        for value in operation["entrypoint-bindings"]:
            kind, selector, canonical = parse_binding(value)
            candidates = by_package_canonical.get((operation["crate"], canonical), [])
            if not candidates:
                raise RuntimeError(f"{operation['id']} has no exact witness for {value}")
            for entry in candidates:
                if kind == "trait-method":
                    if entry["kind"] != "trait_impl":
                        continue
                elif entry["kind"] != kind:
                    continue
                profiles = witness_profiles(entry, kind, selector)
                if not profiles:
                    continue
                entrypoints.add(entry["path"])
                exact_profiles.update(profiles)
        if row_kind == "operation" and not entrypoints:
            raise RuntimeError(f"{operation['id']} has no action-bearing visible entrypoint")
        for value in operation.get("public-bindings", operation["entrypoint-bindings"]):
            kind, selector, canonical = parse_binding(value)
            candidates = by_package_canonical.get((operation["crate"], canonical), [])
            for entry in candidates:
                if kind == "trait-method":
                    if entry["kind"] != "trait_impl" or not witness_profiles(entry, kind, selector):
                        continue
                elif entry["kind"] != kind:
                    continue
                public_paths.add(entry["path"])
                entry["operation_refs"].append(operation["id"])
                if kind == "trait-method":
                    assurance = entry.setdefault("trait_method_assurance", {})
                    record = assurance.setdefault(
                        selector,
                        {
                            "profiles": sorted(witness_profiles(entry, kind, selector)),
                            "operation_refs": [],
                        },
                    )
                    record["operation_refs"].append(operation["id"])
        if not entrypoints.issubset(public_paths):
            raise RuntimeError(f"{operation['id']} witnesses are absent from public bindings")
        operation["entrypoints"] = sorted(entrypoints)
        operation["public-paths"] = sorted(public_paths)
        if row_kind == "data-surface":
            exact_profiles = {
                profile
                for value in operation.get("public-bindings", [])
                for kind, selector, canonical in [parse_binding(value)]
                for entry in by_package_canonical.get((operation["crate"], canonical), [])
                if entry["kind"] == kind
                for profile in entry.get("profiles", [])
            }
        declared_profiles = {
            f"boundary-no-std/{operation['crate']}"
            if profile.startswith("boundary-no-std/") else profile
            for profile in exact_profiles
        }
        operation["profiles"] = sorted(declared_profiles)
        operation["platforms"] = sorted(
            {profile.rsplit("/", 1)[-1] for profile in exact_profiles}
        )

    by_id = {operation["id"]: operation for operation in operations}
    for entry in entries:
        entry["operation_refs"] = sorted(set(entry.get("operation_refs", [])))
        if entry["kind"] == "trait_impl":
            assurance = entry.setdefault("trait_method_assurance", {})
            all_methods = all_trait_methods(entry)
            for selector in sorted(all_methods):
                record = assurance.setdefault(
                    selector,
                    {
                        "profiles": sorted(
                            profile
                            for profile, names in entry.get("trait_methods", {}).items()
                            if selector in names
                        ),
                        "operation_refs": [],
                    },
                )
                refs = sorted(set(record.get("operation_refs", [])))
                record["operation_refs"] = refs
                if refs:
                    classes = {
                        support_classes[by_id[identifier]["support"]]
                        for identifier in refs
                    }
                    record["classification"] = (
                        "internal-like-low-level"
                        if "internal-like-low-level" in classes or len(classes) != 1
                        else next(iter(classes))
                    )
                    record["disposition"] = "operation-bearing"
                else:
                    raise RuntimeError(
                        f"trait method lacks atomic row: {entry['package']}:"
                        f"{entry['path']}::{selector}"
                    )
            stale = set(assurance) - all_methods
            if stale:
                raise RuntimeError(
                    f"trait method assurance is stale for {entry['path']}: {sorted(stale)}"
                )
            entry["trait_method_assurance"] = {
                selector: assurance[selector] for selector in sorted(assurance)
            }
        if entry["kind"] in DATA_KINDS:
            if not entry["operation_refs"]:
                raise RuntimeError(
                    f"public data surface lacks an atomic row: {entry['package']}:{entry['path']}"
                )
            entry["data_disposition"] = "security-or-protocol-data-review-required"
        if entry["kind"] in CALLABLE_KINDS:
            if entry["kind"] == "trait_impl":
                entry["callable_disposition"] = "method-container"
                entry.pop("non_operation_reason", None)
            elif entry["kind"] == "trait" and not entry["operation_refs"]:
                entry["callable_disposition"] = "method-contract"
                entry.pop("non_operation_reason", None)
            elif entry["operation_refs"]:
                entry["callable_disposition"] = "operation-bearing"
                entry.pop("non_operation_reason", None)
            else:
                raise RuntimeError(
                    f"callable lacks atomic row: {entry['package']}:{entry['path']}"
                )
        if entry["kind"] == "trait_impl":
            classes = {
                record["classification"]
                for record in entry.get("trait_method_assurance", {}).values()
                if record.get("disposition") == "operation-bearing"
            }
            if "internal-like-low-level" in classes or len(classes) != 1:
                entry["classification"] = "internal-like-low-level"
            elif classes:
                entry["classification"] = next(iter(classes))
            else:
                entry["classification"] = "metadata-only"
        elif entry["operation_refs"]:
            classes = {
                support_classes[by_id[identifier]["support"]]
                for identifier in entry["operation_refs"]
            }
            if "internal-like-low-level" in classes:
                entry["classification"] = "internal-like-low-level"
            elif len(classes) != 1:
                raise RuntimeError(
                    f"mixed support classes on one API identity: {entry['path']}: {sorted(classes)}"
                )
            else:
                entry["classification"] = classes.pop()
        if entry.get("classification") != "intentionally-unsupported":
            entry.pop("unsupported_reason", None)
            entry.pop("unsupported_owner", None)
            entry.pop("unsupported_review_due", None)


def render_toml(operations: list[dict[str, Any]]) -> str:
    def value(item: Any) -> str:
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=False)
        if isinstance(item, list):
            return "[" + ", ".join(value(child) for child in item) + "]"
        raise TypeError(type(item))

    lines = [
        "# Curated atomic assurance rows with exact rustdoc action bindings.",
        "# Derived aliases/profiles and compact blocked gaps are reproduced by",
        "# generate-assurance-ledger.py from curated-operations.toml + the snapshot.",
        "schema-version = 2",
    ]
    curated = sorted(
        (row for row in operations if row.get("semantic-review") == "curated"),
        key=lambda item: item["id"],
    )
    gaps = sorted(
        (row for row in operations if row.get("semantic-review") == "required"),
        key=lambda item: item["id"],
    )
    for operation in curated:
        extras = set(operation) - set(FIELDS)
        missing = set(FIELDS) - set(operation)
        if extras or missing:
            raise RuntimeError(
                f"operation {operation['id']} field mismatch: extra={sorted(extras)}, missing={sorted(missing)}"
            )
        lines.extend(["", "[[operation]]"])
        lines.extend(f"{field} = {value(operation[field])}" for field in FIELDS)
    if gaps:
        defaults = {field: gaps[0][field] for field in GAP_DEFAULT_FIELDS}
        for operation in gaps:
            extras = set(operation) - set(FIELDS)
            missing = set(FIELDS) - set(operation)
            if extras or missing:
                raise RuntimeError(
                    f"operation {operation['id']} field mismatch: "
                    f"extra={sorted(extras)}, missing={sorted(missing)}"
                )
            differing = {
                field for field in GAP_DEFAULT_FIELDS
                if operation[field] != defaults[field]
            }
            if differing:
                raise RuntimeError(
                    f"unreviewed gap {operation['id']} differs from the fail-closed "
                    f"template: {sorted(differing)}"
                )
        lines.extend(["", "[unreviewed-gap-defaults]"])
        lines.extend(
            f"{field} = {value(defaults[field])}" for field in GAP_DEFAULT_FIELDS
        )
        for operation in gaps:
            lines.extend(["", "[[unreviewed-gap]]"])
            lines.extend(
                f"{field} = {value(operation[field])}" for field in GAP_RECORD_FIELDS
            )
    return "\n".join(lines) + "\n"


def render_curated_toml(operations: list[dict[str, Any]]) -> str:
    def value(item: Any) -> str:
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=False)
        if isinstance(item, list):
            return "[" + ", ".join(value(child) for child in item) + "]"
        raise TypeError(type(item))

    lines = [
        "# Independently curated semantic rows. Derived aliases, profiles, public",
        "# paths, and unreviewed blocked gaps are generated; never edit those outputs.",
        "schema-version = 2",
    ]
    for operation in sorted(operations, key=lambda item: item["id"]):
        missing = set(CURATED_FIELDS) - set(operation)
        if missing:
            raise RuntimeError(
                f"curated operation {operation['id']} missing fields: {sorted(missing)}"
            )
        lines.extend(["", "[[operation]]"])
        lines.extend(
            f"{field} = {value(operation[field])}" for field in CURATED_FIELDS
        )
    return "\n".join(lines) + "\n"


def render_doc(
    operations: list[dict[str, Any]], entries: list[dict[str, Any]]
) -> str:
    curated_all = sorted(
        (
            operation for operation in operations
            if operation.get("semantic-review") == "curated"
        ),
        key=lambda item: item["id"],
    )
    curated = [
        operation for operation in curated_all
        if not str(operation["id"]).startswith("alias.")
    ]
    pending = [
        operation for operation in operations
        if operation.get("semantic-review") == "required"
    ]
    lines = [
        "# dcrypt assurance-ledger algorithm inventory", "",
        "This file is generated from `atomic-operations.toml`. Do not edit it by hand.",
        "`Ready` is the machine-enforced future-release disposition; `blocked` records",
        "an assurance gap and is never presented as completed evidence.",
        "Only independently curated standardized/transitional rows are expanded below;",
        "unreviewed low-level callables remain exact, release-blocking rows in the TOML",
        "and are summarized here so this document stays human-reviewable.", "",
        "| ID | Algorithm | Parameter set | Operation | Support | Ready | Gap / limitation |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for operation in curated:
        cells = [
            operation["id"], operation["algorithm"], operation["parameter-set"],
            operation["operation"], operation["support"], operation["release-readiness"],
            operation["known-limitation"],
        ]
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells) + " |")
    pending_counts: dict[tuple[str, str], int] = {}
    for operation in pending:
        key = (str(operation["crate"]), str(operation["surface"]))
        pending_counts[key] = pending_counts.get(key, 0) + 1
    lines.extend([
        "", "## Unreviewed low-level callable backlog", "",
        "These rows are classified `internal-like-low-level`, carry no supported",
        "algorithm claim, and block release until their atomic semantics and evidence",
        "are reviewed. Exact IDs and bindings are in `atomic-operations.toml`.", "",
        "| Crate | Surface | Pending rows |",
        "| --- | --- | ---: |",
    ])
    for (package, surface), count in sorted(pending_counts.items()):
        lines.append(f"| {package} | {surface} | {count} |")
    unsupported = sorted(
        (
            entry for entry in entries
            if entry.get("classification") == "intentionally-unsupported"
        ),
        key=lambda entry: (str(entry.get("package", "")), str(entry.get("path", ""))),
    )
    lines.extend([
        "", "## Intentionally unsupported public markers", "",
        "These exports are inventoried but make no cryptographic operation claim.", "",
        "| Crate | Public path | Reason | Owner | Review due |",
        "| --- | --- | --- | --- | --- |",
    ])
    for entry in unsupported:
        cells = [
            entry.get("package", ""), entry.get("path", ""),
            entry.get("unsupported_reason", ""), entry.get("unsupported_owner", ""),
            entry.get("unsupported_review_due", ""),
        ]
        lines.append(
            "| " + " | ".join(
                str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells
            ) + " |"
        )
    lines.extend([
        "",
        f"Authoritative curated atomic rows: {len(curated)}",
        f"Derived cross-crate curated alias rows: {len(curated_all) - len(curated)}",
        f"Unreviewed release-blocking low-level rows: {len(pending)}",
        f"Total atomic rows: {len(operations)}",
        "",
    ])
    return "\n".join(lines)


def render_snapshot(snapshot: dict[str, Any]) -> str:
    """Render stable, reviewable JSON with one public API unit per line."""

    header = {key: value for key, value in snapshot.items() if key != "entries"}
    lines = ["{"]
    header_items = sorted(header.items())
    for key, value in header_items:
        lines.append(
            "  " + json.dumps(key) + ": "
            + json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            + ","
        )
    lines.append('  "entries": [')
    entries = sorted(
        snapshot.get("entries", []),
        key=lambda item: (
            str(item.get("package", "")), str(item.get("path", "")),
            str(item.get("kind", "")), str(item.get("canonical", "")),
        ),
    )
    for index, entry in enumerate(entries):
        suffix = "," if index + 1 < len(entries) else ""
        lines.append(
            "    "
            + json.dumps(entry, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            + suffix
        )
    lines.extend(["  ]", "}"])
    return "\n".join(lines) + "\n"


def render_acvp_vector_manifest() -> str:
    """Content-address the complete tracked ACVP vector corpus."""

    repo = ROOT.parent
    ledger = tomllib.loads((ROOT / "ledger.toml").read_text(encoding="utf-8"))
    root = "tests/src/vectors/acvp_json"
    result = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", ledger["source-commit"], "--", root],
        cwd=repo, check=False, stdout=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError("cannot enumerate the bound ACVP vector corpus")
    bound: list[tuple[str, str]] = []
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        path = raw_path.decode("utf-8")
        if object_type != "blob" or mode == "120000":
            raise RuntimeError(f"non-regular ACVP vector input: {path}")
        bound.append((path, object_id))
    object_ids = sorted({object_id for _path, object_id in bound})
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"], cwd=repo,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    stdout, stderr = process.communicate(
        ("\n".join(object_ids) + "\n").encode("ascii")
    )
    if process.returncode != 0:
        raise RuntimeError(
            "cannot read bound ACVP vectors: "
            + stderr.decode("utf-8", "replace").strip()
        )
    digests: dict[str, str] = {}
    cursor = 0
    for expected in object_ids:
        newline = stdout.find(b"\n", cursor)
        if newline < 0:
            raise RuntimeError("truncated ACVP vector cat-file header")
        header = stdout[cursor:newline].decode("ascii")
        cursor = newline + 1
        object_id, object_type, size_value = header.split(" ")
        if object_id != expected or object_type != "blob":
            raise RuntimeError(f"unexpected ACVP vector object: {header}")
        size = int(size_value)
        end = cursor + size
        if end >= len(stdout) or stdout[end:end + 1] != b"\n":
            raise RuntimeError(f"truncated ACVP vector blob: {expected}")
        digests[expected] = hashlib.sha256(stdout[cursor:end]).hexdigest()
        cursor = end + 1
    if cursor != len(stdout):
        raise RuntimeError("unexpected trailing ACVP vector cat-file output")
    rows = [
        {"path": path, "sha256": digests[object_id]}
        for path, object_id in bound
    ]
    lines = [
        "{",
        '  "schema_version": 1,',
        f'  "source_commit": {json.dumps(ledger["source-commit"])},',
        f'  "source_tree": {json.dumps(ledger["source-tree"])},',
        f'  "root": {json.dumps(root)},',
        '  "files": [',
    ]
    for offset, row in enumerate(sorted(rows, key=lambda value: value["path"])):
        suffix = "," if offset + 1 < len(rows) else ""
        lines.append(
            "    " + json.dumps(row, sort_keys=True, separators=(",", ":")) + suffix
        )
    lines.extend(["  ]", "}"])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    operations_document = tomllib.loads(CURATED_PATH.read_text(encoding="utf-8"))
    operations = copy.deepcopy(operations_document["operation"])
    snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
    entries = snapshot["entries"]
    for operation in operations:
        for field in DERIVED_FIELDS:
            operation[field] = []
        if operation.get("semantic-review") != "curated":
            raise RuntimeError(
                f"authoritative semantic row is not curated: {operation.get('id')}"
            )
        required = operation.get("required-evidence", [])
        if (
            any(str(item).startswith("acvp-") for item in required)
            and "acvp-harness-integrity" not in required
        ):
            raise RuntimeError(
                f"ACVP-backed semantic row lacks shared harness integrity: "
                f"{operation.get('id')}"
            )
    initialize_snapshot_classifications(entries)
    clone_curated_cross_package_aliases(operations, entries)
    add_callable_gap_rows(operations, entries)
    add_data_gap_rows(operations, entries)
    expand(operations, entries)
    operations_text = render_toml(operations)
    snapshot_text = render_snapshot(snapshot)
    doc_text = render_doc(operations, entries)
    vector_manifest_text = render_acvp_vector_manifest()

    current = {
        CURATED_PATH: CURATED_PATH.read_text(encoding="utf-8"),
        OPS_PATH: OPS_PATH.read_text(encoding="utf-8"),
        SNAPSHOT_PATH: SNAPSHOT_PATH.read_text(encoding="utf-8"),
        DOC_PATH: DOC_PATH.read_text(encoding="utf-8"),
        ACVP_VECTOR_MANIFEST_PATH: (
            ACVP_VECTOR_MANIFEST_PATH.read_text(encoding="utf-8")
            if ACVP_VECTOR_MANIFEST_PATH.exists() else ""
        ),
    }
    desired = {
        CURATED_PATH: render_curated_toml(operations_document["operation"]),
        OPS_PATH: operations_text,
        SNAPSHOT_PATH: snapshot_text,
        DOC_PATH: doc_text,
        ACVP_VECTOR_MANIFEST_PATH: vector_manifest_text,
    }
    if args.check or not args.write:
        drift = [path.name for path in desired if desired[path] != current[path]]
        if drift:
            print(f"assurance generation drift: {', '.join(drift)}", file=sys.stderr)
            return 1
        print(f"assurance generation is reproducible ({len(operations)} rows, {len(entries)} API units)")
        return 0
    for path, content in desired.items():
        path.write_text(content, encoding="utf-8")
    print(f"wrote {len(operations)} rows and {len(entries)} classified API units")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
