#!/usr/bin/env python3
"""Adversarial, offline Package F structural, schema, and capture self-tests."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True


def _audit_capture_source(raw: str) -> None:
    tree = ast.parse(raw, filename="capture")
    rename_functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_rename_noreplace"
    ]
    if len(rename_functions) != 1:
        raise AssertionError("capture renameat2 wrapper closure differs")
    rename = rename_functions[0]
    rename_dump = ast.dump(rename, annotate_fields=True, include_attributes=False)
    if hashlib.sha256(rename_dump.encode("utf-8")).hexdigest() != (
        "e7a9cb6976fae70b477233df829254cb13d38ac10fc6f3830d5d0ebadd288f54"
    ):
        raise AssertionError("capture ctypes renameat2 normalized AST differs")
    ctypes_imports = [
        node for node in tree.body
        if isinstance(node, ast.Import)
        and any(alias.name == "ctypes" for alias in node.names)
    ]
    ctypes_from_imports = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "ctypes"
    ]
    if (
        len(ctypes_imports) != 1
        or len(ctypes_imports[0].names) != 1
        or ctypes_imports[0].names[0].name != "ctypes"
        or ctypes_imports[0].names[0].asname is not None
        or ctypes_from_imports
    ):
        raise AssertionError("capture ctypes import closure differs")
    all_ctypes_names = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == "ctypes"
    ]
    local_ctypes_names = [
        node for node in ast.walk(rename)
        if isinstance(node, ast.Name) and node.id == "ctypes"
    ]
    if {id(node) for node in all_ctypes_names} != {
        id(node) for node in local_ctypes_names
    }:
        raise AssertionError("capture ctypes name-use closure differs")
    all_getattr = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == "getattr"
    ]
    local_getattr = [
        node for node in ast.walk(rename)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == "getattr"
    ]
    if len(all_getattr) != 1 or all_getattr != local_getattr:
        raise AssertionError("capture ctypes getattr closure differs")
    all_ctypes = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name) and node.value.id == "ctypes"
    ]
    local_ctypes = [
        node for node in ast.walk(rename)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name) and node.value.id == "ctypes"
    ]
    observed = [node.attr for node in all_ctypes]
    if (
        len(all_ctypes) != len(local_ctypes)
        or sorted(observed) != sorted((
            "CDLL", "c_int", "c_int", "c_int", "c_char_p", "c_char_p",
            "c_uint", "get_errno",
        ))
    ):
        raise AssertionError("capture ctypes reference allowlist differs")
    cdll_calls = [
        node for node in ast.walk(rename)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name) and node.func.value.id == "ctypes"
        and node.func.attr == "CDLL"
    ]
    if (
        len(cdll_calls) != 1
        or len(cdll_calls[0].args) != 1
        or not isinstance(cdll_calls[0].args[0], ast.Constant)
        or cdll_calls[0].args[0].value is not None
        or len(cdll_calls[0].keywords) != 1
        or cdll_calls[0].keywords[0].arg != "use_errno"
        or not isinstance(cdll_calls[0].keywords[0].value, ast.Constant)
        or cdll_calls[0].keywords[0].value.value is not True
    ):
        raise AssertionError("capture ctypes CDLL construction differs")
    getattr_calls = [
        node for node in ast.walk(rename)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
    ]
    if (
        len(getattr_calls) != 1 or len(getattr_calls[0].args) != 3
        or not isinstance(getattr_calls[0].args[0], ast.Name)
        or getattr_calls[0].args[0].id != "library"
        or not isinstance(getattr_calls[0].args[1], ast.Constant)
        or getattr_calls[0].args[1].value != "renameat2"
        or not isinstance(getattr_calls[0].args[2], ast.Constant)
        or getattr_calls[0].args[2].value is not None
    ):
        raise AssertionError("capture ctypes symbol lookup differs")
    function_calls = [
        node for node in ast.walk(rename)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "function"
    ]
    if len(function_calls) != 1 or len(function_calls[0].args) != 5:
        raise AssertionError("capture renameat2 invocation closure differs")


def _bootstrap_source_audit() -> None:
    """Prove capture has no local/transitive process or network capability."""
    framework = Path(__file__).resolve().parent
    raw = (framework / "capture.py").read_text(encoding="utf-8")
    _audit_capture_source(raw)
    tree = ast.parse(raw, filename="capture")
    forbidden_modules = {
        "asyncio", "ftplib", "http", "model", "requests", "shlex", "smtplib",
        "socket", "ssl", "subprocess", "telnetlib", "urllib", "webbrowser",
    }
    forbidden_names = {
        "__import__", "breakpoint", "compile", "eval", "exec", "help", "input",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots = {alias.name.split(".")[0] for alias in node.names}
            if roots & forbidden_modules:
                raise AssertionError(
                    f"capture imports a forbidden capability: {roots & forbidden_modules}"
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in forbidden_modules:
                raise AssertionError(f"capture imports a forbidden capability: {root}")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_names:
                raise AssertionError(f"capture calls forbidden builtin: {node.func.id}")
            if isinstance(node.func, ast.Attribute):
                base = node.func.value
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name):
                    if base.id in forbidden_modules:
                        raise AssertionError(
                            f"capture calls forbidden module: {base.id}"
                        )
                    if base.id == "os" and (
                        node.func.attr in {"system", "popen"}
                        or node.func.attr.startswith(("exec", "spawn"))
                    ):
                        raise AssertionError(
                            f"capture calls forbidden OS primitive: {node.func.attr}"
                        )


_bootstrap_source_audit()

import capture  # noqa: E402  (deliberately imported only after the source audit)
import model  # noqa: E402
import verify  # noqa: E402


def _expect_failure(
    label: str,
    function: Callable[[], Any],
    contains: str | None = None,
) -> None:
    try:
        function()
    except (capture.PackageFError, model.PackageFError, OSError, ValueError) as error:
        if contains is not None and contains not in str(error):
            raise AssertionError(f"{label}: wrong failure: {error}") from error
        return
    raise AssertionError(f"{label}: unexpectedly succeeded")


def _artifact(path: str, raw: bytes, artifact_class: str, subject_id: str) -> dict[str, Any]:
    return {
        "artifact_class": artifact_class,
        "file_mode": "0600",
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "subject_id": subject_id,
    }


def _candidate(role: str) -> tuple[dict[str, Any], dict[str, bytes]]:
    artifacts: list[dict[str, Any]] = []
    files: dict[str, bytes] = {}
    if role == "first-party-build-candidate":
        specs = model.ARTIFACT_SUBJECTS
        for subject_id, artifact_class in specs:
            path = f"artifacts/{subject_id}.{'json' if artifact_class == 'sbom' else 'bin'}"
            raw = (subject_id + "\n").encode()
            files[path] = raw
            artifacts.append(_artifact(path, raw, artifact_class, subject_id))
        role_data = {
            "accepted_subjects": 0,
            "artifact_subject_count": 18,
            "artifact_subject_set_sha256": model.ARTIFACT_SUBJECT_SET_SHA256,
            "cache_policy": "cold-bound-provisioning-only",
            "command_target_profile_sha256": "1" * 64,
            "crate_archive_count": 12,
            "dsse_envelope_sha256": "2" * 64,
            "environment_sha256": "3" * 64,
            "in_toto_statement_sha256": "4" * 64,
            "in_toto_statement_type": "https://in-toto.io/Statement/v1",
            "invocation_sha256": "5" * 64,
            "materials_sha256": "6" * 64,
            "network_policy": "offline",
            "producer_class": "first-party",
            "producer_identity_sha256": "7" * 64,
            "sbom_count": 5,
            "sbom_format": "CycloneDX",
            "sbom_spec_version": "1.6",
            "slsa_predicate_sha256": "8" * 64,
            "slsa_predicate_type": "https://slsa.dev/provenance/v1",
            "source_and_lock_input_set_sha256": "9" * 64,
            "source_archive_count": 1,
            "toolchain_bundle_sha256": "a" * 64,
            "toolchain_distribution_verified": False,
            "workspace_ids": list(model.SBOM_IDS),
        }
    elif role == "signature-transparency-candidate":
        specs = (
            ("attestation", "attestation"),
            ("certificate-chain", "certificate-chain"),
            ("signature-envelope", "signature-envelope"),
            ("transparency-proof", "transparency-proof"),
            ("trust-root", "trust-root"),
        )
        for subject_id, artifact_class in specs:
            path = f"signing/{subject_id}.bin"
            raw = (subject_id + "\n").encode()
            files[path] = raw
            artifacts.append(_artifact(path, raw, artifact_class, subject_id))
        by_subject = {row["subject_id"]: row for row in artifacts}
        role_data = {
            "accepted_attestations": 0,
            "cryptographic_verification_completed": False,
            "dsse_payload_type": "application/vnd.in-toto+json",
            "envelope_sha256": by_subject["signature-envelope"]["sha256"],
            "first_party_artifact_set_sha256": "2" * 64,
            "identity_verified": False,
            "in_toto_statement_type": "https://in-toto.io/Statement/v1",
            "signature_count": 18,
            "signed_subject_set_sha256": model.ARTIFACT_SUBJECT_SET_SHA256,
            "signer_identity_sha256": "3" * 64,
            "slsa_predicate_type": "https://slsa.dev/provenance/v1",
            "subject_count": 18,
            "timestamp_binding_sha256": "4" * 64,
            "transparency_verified": False,
            "trust_root_sha256": by_subject["trust-root"]["sha256"],
            "trust_root_verified": False,
        }
    elif role == "independent-rebuild-candidate":
        specs = (
            *model.ARTIFACT_SUBJECTS,
            ("independent-build-manifest", "build-manifest"),
            ("rebuild-comparison-report", "rebuild-report"),
        )
        for subject_id, artifact_class in specs:
            path = f"rebuild/{subject_id}.bin"
            raw = (subject_id + "\n").encode()
            files[path] = raw
            artifacts.append(_artifact(path, raw, artifact_class, subject_id))
        by_subject = {row["subject_id"]: row for row in artifacts}
        role_data = {
            "accepted_rebuilds": 0,
            "administrative_independence_claimed": True,
            "administrative_independence_verified": False,
            "artifact_subject_count": 18,
            "artifact_subject_set_sha256": model.ARTIFACT_SUBJECT_SET_SHA256,
            "byte_comparison_report_sha256": by_subject["rebuild-comparison-report"]["sha256"],
            "cache_policy": "cold-bound-provisioning-only",
            "command_target_profile_sha256": "2" * 64,
            "environment_sha256": "3" * 64,
            "first_party_artifact_set_sha256": "4" * 64,
            "invocation_sha256": "5" * 64,
            "matching_subjects": 0,
            "materials_sha256": "6" * 64,
            "mismatching_subjects": 18,
            "network_policy": "offline",
            "producer_identity_sha256": "7" * 64,
            "replayer_identity_sha256": "8" * 64,
            "source_and_lock_input_set_sha256": "9" * 64,
            "toolchain_bundle_sha256": "a" * 64,
        }
    else:
        raise AssertionError(role)
    artifacts.sort(key=lambda row: row["path"])
    value = {
        "artifact_role": role,
        "artifacts": artifacts,
        "content_policy": model.ROLE_POLICIES[role],
        "promotion_eligible": False,
        "raw_artifact_set_sha256": model.artifact_set_sha256(artifacts),
        "role_data": role_data,
        "schema_version": 1,
        "status": model.ROLE_STATUSES[role],
        "subject_binding": {
            "r_commit": model.R_F_COMMIT,
            "r_tree": model.R_F_TREE,
            "subject_manifest_sha256": model.R_F_SUBJECT_MANIFEST_SHA256,
        },
        "trusted": False,
    }
    model.validate_evidence_candidate(value, capture=True)
    return value, files


def _write_bundle(root: Path, candidate: dict[str, Any], files: dict[str, bytes]) -> None:
    root.mkdir(mode=0o700)
    for relative, raw in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(0o600)
    candidate_path = root / "candidate.json"
    candidate_path.write_bytes(model.canonical_json(candidate))
    candidate_path.chmod(0o600)
    for directory in sorted((item for item in root.rglob("*") if item.is_dir()), reverse=True):
        directory.chmod(0o700)


def _rewrite_candidate(root: Path, candidate: dict[str, Any]) -> None:
    path = root / "candidate.json"
    path.write_bytes(model.canonical_json(candidate))
    path.chmod(0o600)


def _static_capture_policy() -> None:
    raw = Path(capture.__file__).read_text(encoding="utf-8")
    _audit_capture_source(raw)
    tree = ast.parse(raw)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {
            "system", "popen", "spawn", "run", "call", "check_call", "check_output",
        }:
            raise AssertionError("capture contains a forbidden command-execution call")
    forbidden = {
        "asyncio", "ftplib", "http", "model", "requests", "shlex", "smtplib",
        "socket", "ssl", "subprocess", "telnetlib", "urllib", "webbrowser",
    }
    if imports & forbidden:
        raise AssertionError(f"capture imports forbidden capabilities: {imports & forbidden}")
    for token in (
        "O_NONBLOCK", "O_NOFOLLOW", "RENAME_NOREPLACE", "os.fsync",
        "validate_evidence_candidate", ".dcrypt-package-f-capture-",
    ):
        if token not in raw:
            raise AssertionError(f"capture safety token absent: {token}")
    ctypes_mutations = {
        "ctypes system call": raw.replace(
            "value = ctypes.get_errno()",
            'value = ctypes.CDLL(None).system(b"true")', 1,
        ),
        "ctypes import alias": raw.replace(
            "import ctypes", "from ctypes import CDLL as ctypes", 1,
        ),
        "ctypes library method": raw.replace(
            "library = ctypes.CDLL(None, use_errno=True)",
            'library = ctypes.CDLL(None, use_errno=True)\n    library.system(b"true")', 1,
        ),
        "dynamic ctypes lookup": raw.replace(
            "import ctypes", "import ctypes\nDYNAMIC_CDLL = getattr(ctypes, 'CDLL')", 1,
        ),
    }
    for label, ctypes_mutation in ctypes_mutations.items():
        if ctypes_mutation == raw:
            raise AssertionError(f"{label}: negative control is ineffective")
        try:
            _audit_capture_source(ctypes_mutation)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"{label}: ctypes FFI mutation passed")


def _capture_contract_parity() -> None:
    """Cross-check the capability-free copier's frozen contract with the model."""

    scalar_pairs = (
        (capture.REPO, model.REPO),
        (capture.R_F_COMMIT, model.R_F_COMMIT),
        (capture.R_F_TREE, model.R_F_TREE),
        (capture.R_F_SUBJECT_MANIFEST_SHA256, model.R_F_SUBJECT_MANIFEST_SHA256),
        (capture.SBOM_IDS, model.SBOM_IDS),
        (capture.PUBLISH_ORDER, model.PUBLISH_ORDER),
        (capture.ARTIFACT_SUBJECTS, model.ARTIFACT_SUBJECTS),
        (capture.ARTIFACT_SUBJECT_SET_SHA256, model.ARTIFACT_SUBJECT_SET_SHA256),
        (capture.ROLE_CAPS, model.ROLE_CAPS),
        (
            capture.CAPTURE_ADMISSIBLE_ROLES,
            frozenset(model.CAPTURE_ADMISSIBLE_ROLES),
        ),
    )
    if any(left != right for left, right in scalar_pairs):
        raise AssertionError("capture/model frozen scalar contract differs")
    for role in sorted(capture.CAPTURE_ADMISSIBLE_ROLES):
        if (
            capture.ROLE_POLICIES[role] != model.ROLE_POLICIES[role]
            or capture.ROLE_STATUSES[role] != model.ROLE_STATUSES[role]
            or capture._expected_role_cap(role) != model.ROLE_CAPS[role]
            or capture._role_schema(role) != model._role_schema(role)
        ):
            raise AssertionError(f"capture/model role contract differs: {role}")
        candidate, _files = _candidate(role)
        if (
            capture.canonical_json(candidate) != model.canonical_json(candidate)
            or capture.artifact_set_sha256(candidate["artifacts"])
            != model.artifact_set_sha256(candidate["artifacts"])
            or capture.validate_evidence_candidate(candidate, capture=True) != role
        ):
            raise AssertionError(f"capture/model candidate validation differs: {role}")


def _inventory_controls(inventory: dict[str, Any]) -> int:
    mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("surplus top-level", lambda value: value.update(surplus=True)),
        ("tracked manifest count", lambda value: value.update(**{"tracked-cargo-manifests": 16})),
        ("lock occurrence count", lambda value: value.update(**{"lock-package-occurrences": 341})),
        ("external direct count", lambda value: value.update(**{"external-direct-dependency-occurrences": 4})),
        ("subject count", lambda value: value.update(**{"artifact-subjects": 17})),
        ("producer obligations", lambda value: value.update(**{"producer-subject-obligations": 35})),
        ("accepted signature", lambda value: value.update(**{"accepted-signatures": 1})),
        ("release gate", lambda value: value.update(**{"release-gate": "PASS"})),
        ("subject files", lambda value: value.update(**{"r-f-subject-manifest-files": 1510})),
        ("subject size", lambda value: value.update(**{"r-f-subject-manifest-size": 296232})),
        ("lock row source", lambda value: value["workspace-lock"][0].update(**{"registry-occurrences": 114})),
        ("SBOM lock join", lambda value: value["sbom-slot"][0].update(**{"workspace-lock": "bench"})),
        ("artifact mapping", lambda value: value["artifact-subject"][0].update(**{"class": "source-archive"})),
        ("producer duplicate", lambda value: value["producer-class"].__setitem__(1, copy.deepcopy(value["producer-class"][0]))),
        ("blocked mapping", lambda value: value["blocked-slot"][0].update(**{"expected-members": 11})),
        ("antecedent duplicate", lambda value: value["antecedent"].__setitem__(1, copy.deepcopy(value["antecedent"][0]))),
        ("toolchain selector", lambda value: value["toolchain-selector"][0].update(selector="stable")),
        ("exception owner", lambda value: value["dependency-exception"][0].update(owner="unknown")),
        ("exception reviewer", lambda value: value["dependency-exception"][0].update(reviewer="")),
        ("exception expiry boundary", lambda value: value["dependency-exception"][0].update(**{"valid-through": model.dt.date(2026, 9, 9)})),
        ("exception deny digest", lambda value: value["dependency-exception"][0].update(**{"deny-file-sha256": "0" * 64})),
        ("exception node checksum", lambda value: value["dependency-exception"][0]["node"][0].update(checksum="0" * 64)),
        ("publish order edge", lambda value: value["publish-package"][2].update(**{"internal-dependencies": []})),
    ]
    for label, mutation in mutations:
        changed = copy.deepcopy(inventory)
        mutation(changed)
        _expect_failure(label, lambda changed=changed: model.validate_inventory(changed))
    return len(mutations)


def _candidate_controls() -> int:
    controls = 0
    for role in sorted(model.CAPTURE_ADMISSIBLE_ROLES):
        candidate, _files = _candidate(role)
        for label, mutation in (
            ("trusted", lambda value: value.update(trusted=True)),
            ("promotion", lambda value: value.update(promotion_eligible=True)),
            ("surplus root", lambda value: value.update(surplus=True)),
            ("wrong subject", lambda value: value["subject_binding"].update(r_commit="0" * 40)),
            ("unsorted paths", lambda value: value["artifacts"].reverse()),
            ("artifact-set digest", lambda value: value.update(raw_artifact_set_sha256="0" * 64)),
            ("missing artifact", lambda value: value["artifacts"].pop()),
            ("duplicate artifact", lambda value: value["artifacts"].__setitem__(1, copy.deepcopy(value["artifacts"][0]))),
            ("wrong class", lambda value: value["artifacts"][0].update(
                artifact_class=("crate-archive" if value["artifacts"][0]["artifact_class"] != "crate-archive" else "attestation")
            )),
            ("wrong file mode", lambda value: value["artifacts"][0].update(file_mode="0644")),
            ("zero size", lambda value: value["artifacts"][0].update(size=0)),
            ("per-file cap plus one", lambda value, role=role: value["artifacts"][0].update(size=model.ROLE_CAPS[role]["per_file"] + 1)),
            ("traversal", lambda value: value["artifacts"][0].update(path="../escape")),
        ):
            changed = copy.deepcopy(candidate)
            mutation(changed)
            if label not in {"artifact-set digest", "unsorted paths"}:
                changed["raw_artifact_set_sha256"] = model.artifact_set_sha256(changed["artifacts"])
            _expect_failure(f"{role}: {label}", lambda changed=changed: model.validate_evidence_candidate(changed, capture=True))
            controls += 1
        role_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = []
        if role == "first-party-build-candidate":
            role_mutations = [
                ("accepted count boolean alias", lambda value: value["role_data"].update(accepted_subjects=False)),
                ("verification boolean integer alias", lambda value: value["role_data"].update(toolchain_distribution_verified=0)),
                ("SBOM format", lambda value: value["role_data"].update(sbom_spec_version="1.5")),
                ("toolchain context", lambda value: value["role_data"].pop("toolchain_bundle_sha256")),
                ("subject-set join", lambda value: value["role_data"].update(artifact_subject_set_sha256="0" * 64)),
            ]
        elif role == "signature-transparency-candidate":
            role_mutations = [
                ("accepted count boolean alias", lambda value: value["role_data"].update(accepted_attestations=False)),
                ("verification boolean integer alias", lambda value: value["role_data"].update(cryptographic_verification_completed=0)),
                ("signature count minus one", lambda value: value["role_data"].update(signature_count=17)),
                ("signature count plus one", lambda value: value["role_data"].update(signature_count=19)),
                ("envelope digest join", lambda value: value["role_data"].update(envelope_sha256="0" * 64)),
                ("trust-root digest join", lambda value: value["role_data"].update(trust_root_sha256="0" * 64)),
            ]
        else:
            role_mutations = [
                ("accepted count boolean alias", lambda value: value["role_data"].update(accepted_rebuilds=False)),
                ("verification boolean integer alias", lambda value: value["role_data"].update(administrative_independence_verified=0)),
                ("independence claim", lambda value: value["role_data"].update(administrative_independence_claimed=False)),
                ("identity separation", lambda value: value["role_data"].update(replayer_identity_sha256=value["role_data"]["producer_identity_sha256"])),
                ("comparison total", lambda value: value["role_data"].update(mismatching_subjects=17)),
                ("comparison digest join", lambda value: value["role_data"].update(byte_comparison_report_sha256="0" * 64)),
            ]
        for label, mutation in role_mutations:
            changed = copy.deepcopy(candidate)
            mutation(changed)
            _expect_failure(f"{role}: {label}", lambda changed=changed: model.validate_evidence_candidate(changed, capture=True))
            controls += 1
    return controls


def _schema_export_controls() -> int:
    """Attribute representative exact-closure failures to the exported schema layer."""
    candidate, _files = _candidate("signature-transparency-candidate")
    mutations: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
        ("wrong artifact mode", lambda value: value["artifacts"][0].update(file_mode="0644")),
        ("empty artifact", lambda value: value["artifacts"][0].update(size=0)),
        (
            "per-role cap plus one",
            lambda value: value["artifacts"][0].update(
                size=model.ROLE_CAPS["signature-transparency-candidate"]["per_file"] + 1
            ),
        ),
        ("missing exact artifact", lambda value: value["artifacts"].pop()),
        (
            "duplicate exact artifact",
            lambda value: value["artifacts"].__setitem__(1, copy.deepcopy(value["artifacts"][0])),
        ),
        ("wrong exact class", lambda value: value["artifacts"][0].update(artifact_class="crate-archive")),
        ("artifact traversal", lambda value: value["artifacts"][0].update(path="../escape")),
        ("artifact double slash", lambda value: value["artifacts"][0].update(path="artifacts//escape")),
        ("artifact absolute path", lambda value: value["artifacts"][0].update(path="/absolute")),
    )
    for label, mutation in mutations:
        changed = copy.deepcopy(candidate)
        mutation(changed)
        changed["raw_artifact_set_sha256"] = model.artifact_set_sha256(changed["artifacts"])
        _expect_failure(
            f"exported schema: {label}",
            lambda changed=changed: model.validate_schema_value(changed),
        )
    return len(mutations)


def _live_semantic_drift_controls(inventory: dict[str, Any]) -> int:
    controls = 0
    original_rows = model._lock_rows
    for label, mutate in (
        ("lock occurrence", lambda rows: rows.pop()),
        ("lock source", lambda rows: rows[0].__setitem__(2, "local" if rows[0][2] != "local" else "registry+drift")),
        ("lock checksum", lambda rows: rows[0].__setitem__(3, "0" * 64)),
    ):
        def drifting_rows(raw: bytes, *, label: str, mutate: Callable[[list[list[Any]]], None] = mutate) -> list[list[Any]]:
            rows = original_rows(raw, label=label)
            if label == "Package F production lock":
                mutate(rows)
            return rows
        model._lock_rows = drifting_rows
        try:
            _expect_failure(label, lambda: model.validate_locks(inventory))
        finally:
            model._lock_rows = original_rows
        controls += 1

    original_manifests = model.TRACKED_CARGO_MANIFESTS
    model.TRACKED_CARGO_MANIFESTS = original_manifests[:-1]
    try:
        _expect_failure("tracked Cargo manifest closure", model.validate_tracked_manifest_closure)
    finally:
        model.TRACKED_CARGO_MANIFESTS = original_manifests
    controls += 1
    reviewed_tracked = tuple(sorted((
        *model.TRACKED_CARGO_MANIFESTS,
        *(path for _workspace, path in model.LOCK_PATHS),
    )))
    _expect_failure(
        "live tracked Cargo manifest surplus",
        lambda: model.validate_tracked_manifest_closure(
            tuple(sorted((*reviewed_tracked, "surplus/Cargo.toml")))
        ),
    )
    controls += 1

    original_read = model.read_regular_once
    for label, target, transform, validator in (
        (
            "publish=false package",
            model.REPO / "Cargo.toml",
            lambda raw: raw.replace(b'name = "dcrypt"\n', b'name = "dcrypt"\npublish = false\n', 1),
            lambda: model.validate_publish_order(inventory),
        ),
        (
            "external direct dependency drift",
            model.REPO / "crates/algorithms/Cargo.toml",
            lambda raw: raw.replace(b'"=0.22.1"', b'"=0.22.2"', 1),
            lambda: model.validate_publish_order(inventory),
        ),
        (
            "root workspace version drift",
            model.REPO / "Cargo.toml",
            lambda raw: raw.replace(b'version     = "3.0.0"', b'version     = "3.0.1"', 1),
            lambda: model.validate_publish_order(inventory),
        ),
        (
            "package version inheritance drift",
            model.REPO / "crates/api/Cargo.toml",
            lambda raw: raw.replace(b"version.workspace = true", b'version = "3.0.0"', 1),
            lambda: model.validate_publish_order(inventory),
        ),
        (
            "package version inheritance type alias",
            model.REPO / "crates/api/Cargo.toml",
            lambda raw: raw.replace(b"version.workspace = true", b"version.workspace = 1", 1),
            lambda: model.validate_publish_order(inventory),
        ),
        (
            "internal dependency version drift",
            model.REPO / "crates/api/Cargo.toml",
            lambda raw: raw.replace(b'version = "=3.0.0"', b'version = "=3.0.1"', 1),
            lambda: model.validate_publish_order(inventory),
        ),
        (
            "internal dependency path drift",
            model.REPO / "crates/api/Cargo.toml",
            lambda raw: raw.replace(b'path = "../internal"', b'path = "../common"', 1),
            lambda: model.validate_publish_order(inventory),
        ),
        (
            "primary tests publish drift",
            model.REPO / "tests/Cargo.toml",
            lambda raw: raw.replace(b"publish = false", b"publish = true", 1),
            model.validate_workspace_classifications,
        ),
    ):
        def drifting_read(path: Path, **kwargs: Any) -> tuple[bytes, os.stat_result]:
            raw, metadata = original_read(path, **kwargs)
            return (transform(raw), metadata) if path == target else (raw, metadata)
        model.read_regular_once = drifting_read
        try:
            _expect_failure(label, validator)
        finally:
            model.read_regular_once = original_read
        controls += 1

    original_rows = model._lock_rows
    def unconstrained_rows(raw: bytes, *, label: str) -> list[list[Any]]:
        rows = original_rows(raw, label=label)
        if label == "exception confinement production":
            rows.extend([
                ["libcrux-ml-dsa", "0.0.10", "registry+drift", "0" * 64],
                ["hax-lib", "0.3.7", "registry+drift", "0" * 64],
                ["hax-lib-macros", "0.3.7", "registry+drift", "0" * 64],
                ["proc-macro-error2", "2.0.1", "registry+drift", "0" * 64],
            ])
        return rows
    model._lock_rows = unconstrained_rows
    try:
        _expect_failure(
            "dependency exception production reachability",
            lambda: model.validate_dependency_exception(inventory),
        )
    finally:
        model._lock_rows = original_rows
    controls += 1

    original_blob = model._git_blob
    for label, target, old, new in (
        (
            "S_F stable selector drift",
            ".github/workflows/security-validation.yml",
            b"toolchain: 1.93.1",
            b"toolchain: stable",
        ),
        (
            "S_F bench pin drift",
            "tools/bench-processor/Cargo.toml",
            b'=1.0.228',
            b'=1.0.227',
        ),
        (
            "S_F Package F HOLD wiring drift",
            "tools/verify-publish-ready.sh",
            b'assurance/supply-chain/verify.py" --release',
            b'assurance/supply-chain/verify.py" --ci',
        ),
    ):
        def drifting_blob(commit: str, path: str) -> tuple[str, bytes]:
            mode, raw = original_blob(commit, path)
            if commit == model.S_F_COMMIT and path == target:
                raw = raw.replace(old, new, 1)
            return mode, raw
        model._git_blob = drifting_blob
        try:
            _expect_failure(label, model.validate_s_f_semantics)
        finally:
            model._git_blob = original_blob
        controls += 1
    return controls


def _workspace_classification_controls() -> int:
    paths = (
        "Cargo.toml", "implementation-boundary.toml",
        "verification/Cargo.toml", "fuzz/Cargo.toml",
        "migration/legacy-xchacha20poly1305/Cargo.toml",
        "tools/bench-processor/Cargo.toml",
    )
    documents: dict[str, dict[str, Any]] = {}
    for path in paths:
        raw, _metadata = model.read_regular_once(
            model.REPO / path, label=f"workspace control {path}"
        )
        documents[path] = model.parse_toml_strict(
            raw, label=f"workspace control {path}"
        )
    model.validate_workspace_classifications(documents)
    controls = 1
    mutations: tuple[tuple[str, Callable[[dict[str, dict[str, Any]]], None]], ...] = (
        (
            "primary member missing",
            lambda value: value["Cargo.toml"]["workspace"]["members"].pop(),
        ),
        (
            "primary exclude surplus",
            lambda value: value["Cargo.toml"]["workspace"]["exclude"].append(
                "tools/bench-processor"
            ),
        ),
        (
            "published classification missing",
            lambda value: value["implementation-boundary.toml"][
                "published-packages"
            ].pop(),
        ),
        (
            "verification classification drift",
            lambda value: value["implementation-boundary.toml"].update(
                **{"verification-workspace": "fuzz"}
            ),
        ),
        (
            "owned excluded classification drift",
            lambda value: value["implementation-boundary.toml"][
                "owned-excluded-workspaces"
            ][0].update(path="tools/bench-processor"),
        ),
        (
            "auxiliary publish drift",
            lambda value: value["tools/bench-processor/Cargo.toml"][
                "package"
            ].update(publish=True),
        ),
        (
            "primary workspace member surplus",
            lambda value: value["Cargo.toml"]["workspace"]["members"].append(
                "tests-surplus"
            ),
        ),
        (
            "auxiliary workspace shape drift",
            lambda value: value["verification/Cargo.toml"]["workspace"].update(
                resolver="3"
            ),
        ),
    )
    for label, mutation in mutations:
        changed = copy.deepcopy(documents)
        mutation(changed)
        _expect_failure(
            label,
            lambda changed=changed: model.validate_workspace_classifications(changed),
        )
        controls += 1
    return controls


def _private_layout(prefix: str) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
    context = tempfile.TemporaryDirectory(prefix=prefix)
    parent = Path(context.name)
    parent.chmod(0o700)
    source_parent = parent / "source-parent"
    destination_parent = parent / "destination-parent"
    source_parent.mkdir(mode=0o700)
    destination_parent.mkdir(mode=0o700)
    return context, source_parent / "source", destination_parent, destination_parent / "captured"


def _capture_controls() -> int:
    controls = 0
    context, source, _destination_parent, destination = _private_layout("dcrypt-package-f-positive-")
    try:
        candidate, files = _candidate("signature-transparency-candidate")
        _write_bundle(source, candidate, files)
        forbidden_calls: list[str] = []
        original_run, original_popen = subprocess.run, subprocess.Popen
        original_socket, original_system = socket.socket, os.system
        original_execve, original_spawnve = os.execve, os.spawnve
        def forbidden(name: str) -> Callable[..., Any]:
            def reject(*_args: Any, **_kwargs: Any) -> Any:
                forbidden_calls.append(name)
                raise AssertionError(f"capture reached forbidden runtime capability: {name}")
            return reject
        subprocess.run = forbidden("subprocess.run")  # type: ignore[assignment]
        subprocess.Popen = forbidden("subprocess.Popen")  # type: ignore[assignment,misc]
        socket.socket = forbidden("socket.socket")  # type: ignore[assignment]
        os.system = forbidden("os.system")  # type: ignore[assignment]
        os.execve = forbidden("os.execve")  # type: ignore[assignment]
        os.spawnve = forbidden("os.spawnve")  # type: ignore[assignment]
        try:
            result = capture.capture(source, destination)
        finally:
            subprocess.run, subprocess.Popen = original_run, original_popen
            socket.socket, os.system = original_socket, original_system
            os.execve, os.spawnve = original_execve, original_spawnve
        if forbidden_calls:
            raise AssertionError(f"positive capture used forbidden runtime capabilities: {forbidden_calls}")
        if result != {
            "artifact_count": 5,
            "candidate_sha256": model.sha256_bytes(model.canonical_json(candidate)),
            "artifact_role": "signature-transparency-candidate",
            "promotion_eligible": False,
            "status": "captured-unreviewed-not-accepted",
            "trusted": False,
            "total_bytes": len(model.canonical_json(candidate)) + sum(map(len, files.values())),
        }:
            raise AssertionError("positive capture summary differs")
        expected_output = {
            "candidate.json": model.canonical_json(candidate),
            **files,
        }
        observed_output = {
            path.relative_to(destination).as_posix(): path
            for path in destination.rglob("*")
            if path.is_file()
        }
        if set(observed_output) != set(expected_output):
            raise AssertionError("positive capture file closure differs")
        for relative, raw in expected_output.items():
            path = observed_output[relative]
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != len(raw)
                or path.read_bytes() != raw
                or hashlib.sha256(path.read_bytes()).hexdigest()
                != hashlib.sha256(raw).hexdigest()
            ):
                raise AssertionError(f"positive capture bytes/mode differ: {relative}")
        directories = [destination, *(path for path in destination.rglob("*") if path.is_dir())]
        if any(
            not stat.S_ISDIR(path.lstat().st_mode)
            or stat.S_IMODE(path.lstat().st_mode) != 0o700
            for path in directories
        ):
            raise AssertionError("positive capture directory mode differs")
        controls += 1
    finally:
        context.cleanup()

    def bundle_control(label: str, mutate: Callable[[Path, Path, dict[str, Any], dict[str, bytes]], None]) -> None:
        nonlocal controls
        context, source, destination_parent, destination = _private_layout(f"dcrypt-package-f-{label}-")
        try:
            candidate, files = _candidate("signature-transparency-candidate")
            _write_bundle(source, candidate, files)
            mutate(source, destination, candidate, files)
            _expect_failure(label, lambda: capture.capture(source, destination))
            if (label != "existing-output" and destination.exists()) or any(
                item.name.startswith(".dcrypt-package-f-capture-")
                for item in destination_parent.iterdir()
            ):
                raise AssertionError(f"{label}: capture failure left residue")
            controls += 1
        finally:
            context.cleanup()

    def artifact_path(candidate: dict[str, Any]) -> Path:
        return Path(candidate["artifacts"][0]["path"])

    bundle_control("existing-output", lambda _s, d, _c, _f: d.mkdir(mode=0o700))
    bundle_control("surplus", lambda s, _d, _c, _f: (s / "surplus").write_bytes(b"x"))
    bundle_control("world-readable-source", lambda s, _d, _c, _f: s.chmod(0o755))
    bundle_control("world-readable-candidate", lambda s, _d, _c, _f: (s / "candidate.json").chmod(0o644))
    bundle_control("executable-candidate", lambda s, _d, _c, _f: (s / "candidate.json").chmod(0o700))
    bundle_control("artifact-symlink", lambda s, _d, c, _f: (s / artifact_path(c)).unlink() or (s / artifact_path(c)).symlink_to("../../candidate.json"))
    bundle_control("artifact-hardlink", lambda s, _d, c, _f: os.link(s / artifact_path(c), s.parent / "outside-hardlink"))
    bundle_control("executable-artifact", lambda s, _d, c, _f: (s / artifact_path(c)).chmod(0o700))
    bundle_control("artifact-fifo", lambda s, _d, c, _f: (s / artifact_path(c)).unlink() or os.mkfifo(s / artifact_path(c), 0o600))
    def change_size(source: Path, _destination: Path, candidate: dict[str, Any], _files: dict[str, bytes]) -> None:
        candidate["artifacts"][0]["size"] += 1
        candidate["raw_artifact_set_sha256"] = model.artifact_set_sha256(candidate["artifacts"])
        _rewrite_candidate(source, candidate)
    bundle_control("artifact-size", change_size)
    bundle_control("artifact-digest", lambda s, _d, c, _f: c["artifacts"][0].update(sha256="0" * 64) or c.update(raw_artifact_set_sha256=model.artifact_set_sha256(c["artifacts"])) or _rewrite_candidate(s, c))

    def cap_control(
        label: str, mutate: Callable[[dict[str, Any]], None]
    ) -> None:
        nonlocal controls
        context, source, destination_parent, destination = _private_layout(
            f"dcrypt-package-f-{label}-"
        )
        try:
            candidate, files = _candidate("signature-transparency-candidate")
            _write_bundle(source, candidate, files)
            mutate(candidate)
            candidate["raw_artifact_set_sha256"] = model.artifact_set_sha256(
                candidate["artifacts"]
            )
            _rewrite_candidate(source, candidate)
            _expect_failure(label, lambda: capture.capture(source, destination))
            if destination.exists() or any(destination_parent.iterdir()):
                raise AssertionError(f"{label}: cap failure left residue")
            controls += 1
        finally:
            context.cleanup()

    cap_control(
        "artifact per-file cap plus one",
        lambda candidate: candidate["artifacts"][0].update(
            size=capture.ROLE_CAPS[candidate["artifact_role"]]["per_file"] + 1
        ),
    )
    cap_control(
        "aggregate cap plus one",
        lambda candidate: [
            row.update(size=capture.ROLE_CAPS[candidate["artifact_role"]]["per_file"])
            for row in candidate["artifacts"]
        ],
    )

    context, source, destination_parent, destination = _private_layout(
        "dcrypt-package-f-role-cap-integrity-"
    )
    try:
        candidate, files = _candidate("signature-transparency-candidate")
        _write_bundle(source, candidate, files)
        original = copy.deepcopy(capture.ROLE_CAPS[candidate["artifact_role"]])
        try:
            capture.ROLE_CAPS[candidate["artifact_role"]]["files"] = 4
            _expect_failure(
                "role cap integrity", lambda: capture.capture(source, destination)
            )
        finally:
            capture.ROLE_CAPS[candidate["artifact_role"]] = original
        if destination.exists() or any(destination_parent.iterdir()):
            raise AssertionError("role cap integrity failure left residue")
        controls += 1
    finally:
        context.cleanup()

    for label, raw in (
        ("candidate duplicate key", b'{"a":1,"a":2}\n'),
        ("candidate float", b'{"schema_version":1.0}\n'),
        ("candidate non-NFC", '{"name":"e\u0301"}\n'.encode()),
        ("candidate noncanonical", b'{"b":1,"a":2}\n'),
    ):
        context, source, destination_parent, destination = _private_layout(f"dcrypt-package-f-{label}-")
        try:
            source.mkdir(mode=0o700)
            (source / "candidate.json").write_bytes(raw)
            (source / "candidate.json").chmod(0o600)
            _expect_failure(label, lambda: capture.capture(source, destination))
            if destination.exists() or any(destination_parent.iterdir()):
                raise AssertionError(f"{label}: malformed candidate left residue")
            controls += 1
        finally:
            context.cleanup()

    context, source, destination_parent, destination = _private_layout(
        "dcrypt-package-f-candidate-cap-"
    )
    try:
        source.mkdir(mode=0o700)
        candidate_path = source / "candidate.json"
        candidate_path.write_bytes(b" " * (capture.MAX_CANDIDATE_BYTES + 1))
        candidate_path.chmod(0o600)
        _expect_failure(
            "candidate cap plus one", lambda: capture.capture(source, destination)
        )
        if destination.exists() or any(destination_parent.iterdir()):
            raise AssertionError("candidate cap failure left residue")
        controls += 1
    finally:
        context.cleanup()

    context, source, _destination_parent, destination = _private_layout("dcrypt-package-f-candidate-fifo-")
    try:
        source.mkdir(mode=0o700)
        os.mkfifo(source / "candidate.json", 0o600)
        _expect_failure("candidate FIFO", lambda: capture.capture(source, destination))
        controls += 1
    finally:
        context.cleanup()

    context, source, destination_parent, destination = _private_layout(
        "dcrypt-package-f-candidate-hardlink-"
    )
    try:
        candidate, files = _candidate("signature-transparency-candidate")
        _write_bundle(source, candidate, files)
        os.link(source / "candidate.json", source.parent / "candidate-outside-link")
        _expect_failure(
            "candidate hardlink", lambda: capture.capture(source, destination)
        )
        if destination.exists() or any(destination_parent.iterdir()):
            raise AssertionError("candidate hardlink failure left residue")
        controls += 1
    finally:
        context.cleanup()

    with tempfile.TemporaryDirectory(prefix="dcrypt-package-f-roots-") as temporary:
        parent = Path(temporary); parent.chmod(0o700)
        source_parent = parent / "source-parent"; source_parent.mkdir(mode=0o700)
        destination_parent = parent / "destination-parent"; destination_parent.mkdir(mode=0o700)
        source = source_parent / "source"; candidate, files = _candidate("signature-transparency-candidate"); _write_bundle(source, candidate, files)
        link = parent / "source-link"; link.symlink_to(source_parent, target_is_directory=True)
        _expect_failure("source symlink component", lambda: capture.capture(link / "source", destination_parent / "out")); controls += 1
        destination_link = parent / "destination-link"; destination_link.symlink_to(destination_parent, target_is_directory=True)
        _expect_failure("destination symlink component", lambda: capture.capture(source, destination_link / "out")); controls += 1
        destination_parent.chmod(0o755)
        _expect_failure("nonprivate destination parent", lambda: capture.capture(source, destination_parent / "out")); controls += 1
        destination_parent.chmod(0o700)
        _expect_failure("source destination overlap", lambda: capture.capture(source, source / "out")); controls += 1
        _expect_failure("double slash", lambda: capture.capture(Path("//") / source.relative_to("/"), destination_parent / "out")); controls += 1

    context, source, destination_parent, destination = _private_layout("dcrypt-package-f-rollback-")
    try:
        candidate, files = _candidate("signature-transparency-candidate")
        _write_bundle(source, candidate, files)
        original_verify = capture._verify_destination_tree
        calls = 0
        def fail_after_publication(*args: Any, **kwargs: Any) -> None:
            nonlocal calls
            calls += 1
            original_verify(*args, **kwargs)
            if calls == 2:
                raise model.PackageFError("injected post-publication failure")
        capture._verify_destination_tree = fail_after_publication
        try:
            _expect_failure("post-publication rollback", lambda: capture.capture(source, destination))
        finally:
            capture._verify_destination_tree = original_verify
        if calls != 2 or destination.exists() or any(destination_parent.iterdir()):
            raise AssertionError("post-publication rollback left residue")
        controls += 1
    finally:
        context.cleanup()

    for label, attribute in (("zero-progress-write", "write"), ("fsync-failure", "fsync")):
        context, source, destination_parent, destination = _private_layout(f"dcrypt-package-f-{label}-")
        try:
            candidate, files = _candidate("signature-transparency-candidate")
            _write_bundle(source, candidate, files)
            original = getattr(os, attribute)
            injected = False
            def fail_once(*args: Any, **kwargs: Any) -> Any:
                nonlocal injected
                if not injected:
                    injected = True
                    if attribute == "write":
                        return 0
                    raise OSError(5, "injected fsync failure")
                return original(*args, **kwargs)
            setattr(os, attribute, fail_once)
            try:
                _expect_failure(label, lambda: capture.capture(source, destination))
            finally:
                setattr(os, attribute, original)
            if not injected or destination.exists() or any(destination_parent.iterdir()):
                raise AssertionError(f"{label}: failure cleanup differs")
            controls += 1
        finally:
            context.cleanup()
    return controls


def main() -> int:
    controls = 0
    package = model.build_package_document()
    model.validate_package_document(package)
    controls += 1
    inventory, _raw = model.load_reviewed_inventory()
    model.validate_inventory(inventory)
    controls += 1
    schema = model.build_schema()
    if set(schema) != {"$schema", "oneOf", "title"} or len(schema["oneOf"]) != 5:
        raise AssertionError("closed five-role schema differs")
    controls += 1
    local = model.build_local_foundation_proof()
    if model.validate_evidence_candidate(local) != "local-foundation-proof":
        raise AssertionError("local foundation proof differs")
    controls += 1
    _expect_failure("local proof capture", lambda: model.validate_evidence_candidate(local, capture=True)); controls += 1
    acceptance = {
        "artifact_role": "acceptance",
        "artifacts": [_artifact("acceptance.json", b"{}\n", "attestation", "attestation")],
        "content_policy": model.ROLE_POLICIES["acceptance"],
        "promotion_eligible": False,
        "role_data": {"accepted": False, "decision": "disabled", "reason": "v1 disabled"},
        "schema_version": 1,
        "status": model.ROLE_STATUSES["acceptance"],
        "subject_binding": {"r_commit": model.R_F_COMMIT, "r_tree": model.R_F_TREE, "subject_manifest_sha256": model.R_F_SUBJECT_MANIFEST_SHA256},
        "trusted": False,
    }
    acceptance["raw_artifact_set_sha256"] = model.artifact_set_sha256(acceptance["artifacts"])
    model.validate_schema_value(acceptance); controls += 1
    _expect_failure("acceptance disabled", lambda: model.validate_evidence_candidate(acceptance)); controls += 1
    _static_capture_policy(); controls += 1
    _capture_contract_parity(); controls += 1

    fixture = model.validate_control_fixture()
    controls += 1
    for field in fixture:
        changed = copy.deepcopy(fixture)
        if field == "controls":
            changed[field].pop()
        elif isinstance(changed[field], bool):
            changed[field] = not changed[field]
        elif isinstance(changed[field], int):
            changed[field] += 1
        else:
            changed[field] += "-drift"
        _expect_failure(
            f"parser-smoke fixture {field}",
            lambda changed=changed: model.validate_control_fixture(changed),
        )
        controls += 1

    controls += _inventory_controls(inventory)
    controls += _candidate_controls()
    controls += _schema_export_controls()
    controls += _live_semantic_drift_controls(inventory)
    controls += _workspace_classification_controls()
    model.validate_exception_dates(
        model.dt.date(2026, 8, 13), model.dt.date(2026, 9, 10),
        observed_date=model.dt.date(2026, 9, 9),
    )
    controls += 1
    for observed in (model.dt.date(2026, 9, 10), model.dt.date(2026, 9, 11)):
        _expect_failure(
            f"dependency exception UTC boundary {observed.isoformat()}",
            lambda observed=observed: model.validate_exception_dates(
                model.dt.date(2026, 8, 13), model.dt.date(2026, 9, 10),
                observed_date=observed,
            ),
        )
        controls += 1
    for path in (
        "counts", "input_bindings", "subject_binding", "lock_graph", "publish_order", "dependency_exception",
    ):
        changed = copy.deepcopy(package)
        if isinstance(changed[path], list):
            changed[path].pop()
        elif isinstance(changed[path], dict):
            changed[path][next(iter(changed[path]))] = "mutated"
        _expect_failure(f"package nested {path}", lambda changed=changed: model.validate_package_document(changed))
        controls += 1
    changed = copy.deepcopy(package); changed["release_state"]["publish_eligible"] = True
    _expect_failure("package promotion", lambda: model.validate_package_document(changed)); controls += 1
    for label, mutation in (
        ("package schema boolean alias", lambda value: value.update(schema_version=True)),
        ("package release boolean alias", lambda value: value["release_state"].update(publish_eligible=0)),
        ("package evidence boolean alias", lambda value: value["evidence_state"].update(trusted=0)),
        ("package count boolean alias", lambda value: value["counts"].update(dependency_exceptions=True)),
    ):
        changed = copy.deepcopy(package)
        mutation(changed)
        _expect_failure(
            label, lambda changed=changed: model.validate_package_document(changed)
        )
        controls += 1

    original_read = model.read_regular_once
    def executable_core(path: Path, **kwargs: Any) -> tuple[bytes, os.stat_result]:
        raw, metadata = original_read(path, **kwargs)
        if path == model.REPO / "assurance/subject-manifest.json":
            values = list(metadata); values[0] |= stat.S_IXUSR
            metadata = os.stat_result(values)
        return raw, metadata
    model.read_regular_once = executable_core
    try:
        _expect_failure("core executable mode", model.validate_core_inputs)
    finally:
        model.read_regular_once = original_read
    controls += 1

    for core_relative in (
        "assurance/subject-manifest.json",
        "assurance/atomic-operations.toml",
        "assurance/public-api-snapshot.json",
    ):
        def drifting_core(path: Path, **kwargs: Any) -> tuple[bytes, os.stat_result]:
            raw, metadata = original_read(path, **kwargs)
            if path == model.REPO / core_relative:
                return raw + b"drift", metadata
            return raw, metadata
        model.read_regular_once = drifting_core
        try:
            _expect_failure(
                f"core digest drift {core_relative}", model.validate_core_inputs
            )
        finally:
            model.read_regular_once = original_read
        controls += 1

    controls += _capture_controls()
    verify.verify_structural(); controls += 1
    print(f"Package F self-test passed: adversarial-controls={controls} release=HOLD")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
