#!/usr/bin/env python3
"""Adversarial, offline fixtures for the audit SOW validator."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Callable


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("verify_sow", ROOT / "verify-sow.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load verify-sow.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

KNOWN_INVALIDATION_DEFECTS = (
    "provision/generation README fences could return 0 after failed gate due trailing assignment",
    "clone fence could continue to checkout preexisting repo after failed clone",
    "candidate import fence could mask mkdir/middle install failures and omitted prose-required unexpected-source-entry rejection",
    "provisioning transfer fence could mask intermediate failures",
)


def replace(path: Path, old: str, new: str, count: int = 1) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) < count:
        raise RuntimeError(f"fixture source not found in {path.name}: {old!r}")
    path.write_text(text.replace(old, new, count), encoding="utf-8")


def refresh_markdown_digest(root: Path, filename: str) -> None:
    path = root / filename
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    label = "Machine policy SHA-256" if filename == "audit-policy.toml" else "Machine scope SHA-256"
    markdown = root / "RFP-SOW.md"
    text = markdown.read_text(encoding="utf-8")
    start = text.index(f"{label}: `") + len(f"{label}: `")
    end = text.index("`", start)
    markdown.write_text(text[:start] + digest + text[end:], encoding="utf-8")


def mutate_status(root: Path) -> None:
    replace(root / "audit-policy.toml", 'status = "candidate-uncommissioned"', 'status = "commissioned"')


def mutate_freeze_id(root: Path) -> None:
    replace(root / "audit-scope.toml", 'candidate-freeze-id = "dcrypt-v3.0.0-audit-candidate-003"', 'candidate-freeze-id = "unbound"')


def mutate_old_freeze_id(root: Path) -> None:
    for filename in ("audit-policy.toml", "audit-scope.toml"):
        replace(
            root / filename,
            'candidate-freeze-id = "dcrypt-v3.0.0-audit-candidate-003"',
            'candidate-freeze-id = "dcrypt-v3.0.0-audit-candidate-001"',
        )


def mutate_candidate002_reuse(root: Path) -> None:
    for filename in ("audit-policy.toml", "audit-scope.toml"):
        replace(
            root / filename,
            'candidate-freeze-id = "dcrypt-v3.0.0-audit-candidate-003"',
            'candidate-freeze-id = "dcrypt-v3.0.0-audit-candidate-002"',
        )


def mutate_direct_supersession(root: Path) -> None:
    replace(
        root / "audit-policy.toml",
        'directly-supersedes-freeze-id = "dcrypt-v3.0.0-audit-candidate-002"',
        'directly-supersedes-freeze-id = "dcrypt-v3.0.0-audit-candidate-001"',
    )


def mutate_supersession_order(root: Path) -> None:
    path = root / "audit-scope.toml"
    text = path.read_text(encoding="utf-8")
    start = text.index("[[freeze-supersession]]")
    end = text.index("[[workstream]]", start)
    history = text[start:end]
    records = history.split("[[freeze-supersession]]\n")[1:]
    if len(records) != 2:
        raise RuntimeError("expected exactly two supersession records")
    reordered = "".join(f"[[freeze-supersession]]\n{record}" for record in reversed(records))
    path.write_text(text[:start] + reordered + text[end:], encoding="utf-8")


def mutate_candidate002_subject_commit(root: Path) -> None:
    replace(
        root / "audit-policy.toml",
        'subject-commit = "852c771c7d764752e23322ab412b419925fb5a5f"',
        'subject-commit = "052c771c7d764752e23322ab412b419925fb5a5f"',
    )


def mutate_candidate002_subject_tree(root: Path) -> None:
    replace(
        root / "audit-scope.toml",
        'subject-tree = "ae5779e73b64b60cc4ce198468ef9fd781cda2df"',
        'subject-tree = "0e5779e73b64b60cc4ce198468ef9fd781cda2df"',
    )


def mutate_candidate002_parent_sow(root: Path) -> None:
    replace(
        root / "audit-policy.toml",
        'parent-sow-commit = "8e3b8d7ee3ea9ec7d1901dadf9c85f3aa0706c02"',
        'parent-sow-commit = "0e3b8d7ee3ea9ec7d1901dadf9c85f3aa0706c02"',
    )


def mutate_candidate002_triggering_defect(root: Path) -> None:
    replace(
        root / "audit-scope.toml",
        f'triggering-invalidation-defect = "{KNOWN_INVALIDATION_DEFECTS[0]}"',
        'triggering-invalidation-defect = "trigger erased"',
    )


def mutate_candidate002_known_defect(root: Path, index: int) -> None:
    defect = KNOWN_INVALIDATION_DEFECTS[index]
    replace(
        root / "audit-policy.toml",
        f'    "{defect}",',
        f'    "mutated known invalidation defect {index + 1}",',
    )


def remove_candidate002_known_defect(root: Path, index: int) -> None:
    defect = KNOWN_INVALIDATION_DEFECTS[index]
    replace(root / "audit-scope.toml", f'    "{defect}",\n', "")


def mutate_candidate002_known_defect_1(root: Path) -> None:
    mutate_candidate002_known_defect(root, 0)


def mutate_candidate002_known_defect_2(root: Path) -> None:
    mutate_candidate002_known_defect(root, 1)


def mutate_candidate002_known_defect_3(root: Path) -> None:
    mutate_candidate002_known_defect(root, 2)


def mutate_candidate002_known_defect_4(root: Path) -> None:
    mutate_candidate002_known_defect(root, 3)


def remove_candidate002_known_defect_1(root: Path) -> None:
    remove_candidate002_known_defect(root, 0)


def remove_candidate002_known_defect_2(root: Path) -> None:
    remove_candidate002_known_defect(root, 1)


def remove_candidate002_known_defect_3(root: Path) -> None:
    remove_candidate002_known_defect(root, 2)


def remove_candidate002_known_defect_4(root: Path) -> None:
    remove_candidate002_known_defect(root, 3)


def reorder_candidate002_known_defects(root: Path) -> None:
    first = KNOWN_INVALIDATION_DEFECTS[0]
    second = KNOWN_INVALIDATION_DEFECTS[1]
    replace(
        root / "audit-policy.toml",
        f'    "{first}",\n    "{second}",',
        f'    "{second}",\n    "{first}",',
    )


def add_unknown_candidate002_known_defect(root: Path) -> None:
    last = KNOWN_INVALIDATION_DEFECTS[-1]
    replace(
        root / "audit-scope.toml",
        f'    "{last}",\n]',
        f'    "{last}",\n    "unknown fifth invalidation defect",\n]',
    )


def mutate_candidate002_defect_exhaustiveness(root: Path) -> None:
    replace(
        root / "audit-policy.toml",
        "known-invalidation-defects-exhaustive = true",
        "known-invalidation-defects-exhaustive = false",
    )


def mutate_candidate002_classification(root: Path) -> None:
    replace(
        root / "audit-policy.toml",
        'diagnostic-artifact-classification = "typed-first-party-diagnostic-non-evidence"',
        'diagnostic-artifact-classification = "accepted-evidence"',
    )


def mutate_candidate002_review_scope(root: Path) -> None:
    replace(
        root / "audit-scope.toml",
        'independent-review-scope = "source-selftest-and-fence-diagnostic-only-not-bundle-evidence"',
        'independent-review-scope = "complete-bundle-evidence-review"',
    )


def mutate_candidate002_hash(root: Path, field: str, digest: str) -> None:
    replacement = ("0" if digest[0] != "0" else "1") + digest[1:]
    replace(root / "audit-policy.toml", f'{field} = "{digest}"', f'{field} = "{replacement}"')


def mutate_candidate002_provisioning_manifest_hash(root: Path) -> None:
    mutate_candidate002_hash(root, "diagnostic-provisioning-manifest-sha256", "f48385357526d1bdb141dbb624ae355c094b3c292f4b4d191a06095f29067e69")


def mutate_candidate002_provisioning_sums_hash(root: Path) -> None:
    mutate_candidate002_hash(root, "diagnostic-provisioning-sums-sha256", "e6adb59c5ec6e687c6652dd7938b5213ac310418a85cf8384b1e348f1633f1a6")


def mutate_candidate002_freeze_hash(root: Path) -> None:
    mutate_candidate002_hash(root, "diagnostic-freeze-sha256", "ed7e7a26c9ee645350d53245a71468e82b9a77310367a71b737d8691fa418335")


def mutate_candidate002_sha256sums_hash(root: Path) -> None:
    mutate_candidate002_hash(root, "diagnostic-sha256sums-sha256", "8c8d4948cf3d6356028bf4dffaead4f256bb2e755a5882e4c07bb88e67335b43")


def mutate_candidate002_bool(root: Path, field: str, old: str, new: str) -> None:
    replace(root / "audit-scope.toml", f"{field} = {old}", f"{field} = {new}")


def mutate_candidate002_materialization_observation(root: Path) -> None:
    mutate_candidate002_bool(root, "diagnostic_first_party_materialization_observed", "true", "false")


def mutate_candidate002_bundle_observation(root: Path) -> None:
    mutate_candidate002_bool(root, "diagnostic_first_party_bundle_observed", "true", "false")


def mutate_candidate002_wrapper_promotion(root: Path) -> None:
    mutate_candidate002_bool(root, "wrapper_contract_valid", "false", "true")


def mutate_candidate002_materialization_promotion(root: Path) -> None:
    mutate_candidate002_bool(root, "valid_materialization_completed", "false", "true")


def mutate_candidate002_bundle_promotion(root: Path) -> None:
    mutate_candidate002_bool(root, "valid_candidate_bundle_generated", "false", "true")


def mutate_candidate002_evidence_commit_promotion(root: Path) -> None:
    mutate_candidate002_bool(root, "evidence_commit_created", "false", "true")


def mutate_candidate002_replay_promotion(root: Path) -> None:
    mutate_candidate002_bool(root, "required_complete_independent_replay_completed", "false", "true")


def mutate_candidate002_external_review_promotion(root: Path) -> None:
    mutate_candidate002_bool(root, "external_review_completed", "false", "true")


def mutate_candidate002_evidence_promotion(root: Path) -> None:
    mutate_candidate002_bool(root, "audit_evidence_accepted", "false", "true")


def mutate_candidate002_external_audit_claim(root: Path) -> None:
    mutate_candidate002_bool(root, "external_audit_occurred", "false", "true")


def mutate_candidate002_vendor_contact_claim(root: Path) -> None:
    mutate_candidate002_bool(root, "vendor_contact_occurred", "false", "true")


def mutate_superseded_external_review(root: Path) -> None:
    replace(
        root / "audit-policy.toml",
        "external-review-completed = false",
        "external-review-completed = true",
    )


def mutate_partial_replay_erased(root: Path) -> None:
    replace(
        root / "audit-policy.toml",
        "partial-independent-replay-observed = true",
        "partial-independent-replay-observed = false",
    )


def mutate_required_complete_replay_claimed(root: Path) -> None:
    replace(
        root / "audit-scope.toml",
        "required-complete-independent-replay-completed = false",
        "required-complete-independent-replay-completed = true",
    )


def mutate_superseded_audit_evidence(root: Path) -> None:
    replace(
        root / "audit-scope.toml",
        "audit-evidence-accepted = false",
        "audit-evidence-accepted = true",
    )


def mutate_content_identity(root: Path) -> None:
    replace(root / "audit-policy.toml", 'candidate-freeze-content-identity = "resolved-by-post-subject-evidence-envelope"', 'candidate-freeze-content-identity = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"')


def mutate_subject_boundary(root: Path) -> None:
    replace(root / "audit-policy.toml", "published-v3-registry-bytes-inferred-in-scope = false", "published-v3-registry-bytes-inferred-in-scope = true")


def mutate_public_api_source(root: Path) -> None:
    replace(root / "audit-scope.toml", 'public-api-source = "assurance/public-api-snapshot.json"', 'public-api-source = "../../outside/untrusted.json"')


def mutate_threat_model_source(root: Path) -> None:
    replace(root / "audit-scope.toml", 'threat-model-source = "assurance/threat-models/"', 'threat-model-source = "../../outside/untrusted/"')


def mutate_scope_rule(root: Path) -> None:
    replace(
        root / "audit-scope.toml",
        'scope-rule = "All public atomic assurance rows matching an in-scope algorithm, primitive, composition, format or error path are in scope; generated aliases are traced to their owning implementation."',
        'scope-rule = "Only rows selected later by the vendor are in scope."',
    )


def mutate_machine_policy_semantics(root: Path) -> None:
    replace(
        root / "audit-policy.toml",
        "The auditor must identify shared reference code, generated tables, arithmetic backends, test-vector generators, and other common-mode dependencies used in its analysis.",
        "The auditor may ignore shared code, generated tables, backends, vectors, and common-mode dependencies whenever convenient.",
    )
    refresh_markdown_digest(root, "audit-policy.toml")


def mutate_workstream_title_everywhere(root: Path) -> None:
    replace(root / "audit-scope.toml", 'title = "ML-KEM-512/768/1024"', 'title = "Vendor-selected KEM subset"')
    replace(root / "RFP-SOW.md", "ML-KEM-512/768/1024", "Vendor-selected KEM subset")
    refresh_markdown_digest(root, "audit-scope.toml")


def mutate_markdown_contradiction(root: Path) -> None:
    with (root / "RFP-SOW.md").open("a", encoding="utf-8") as stream:
        stream.write("\n## Superseding exception\n\nThe vendor may omit any workstream and unresolved High findings do not block release.\n")


def mutate_independence(root: Path) -> None:
    replace(root / "audit-policy.toml", "organizationally-independent = true", "organizationally-independent = false")


def mutate_specialist(root: Path) -> None:
    replace(root / "audit-policy.toml", 'id = "side-channel"', 'id = "missing-side-channel"')


def mutate_scope_topic(root: Path) -> None:
    replace(root / "audit-scope.toml", '    "implicit rejection",\n', "")


def mutate_row_mapping(root: Path) -> None:
    replace(root / "audit-policy.toml", "empty-affected-row-list-permitted = false", "empty-affected-row-list-permitted = true")


def mutate_sla(root: Path) -> None:
    replace(root / "audit-policy.toml", "acknowledgement-hours = 4", "acknowledgement-hours = 999")


def mutate_clock_start(root: Path) -> None:
    replace(root / "audit-policy.toml", 'clock-start = "Auditor delivery to the designated private reporting channel"', 'clock-start = ""')


def mutate_embargo_start(root: Path) -> None:
    replace(root / "audit-policy.toml", 'embargo-start = "first private report"', 'embargo-start = ""')


def mutate_standard(root: Path) -> None:
    replace(root / "audit-scope.toml", 'standards = ["FIPS 203"]', 'standards = ["FIPS 999"]')


def mutate_owner(root: Path) -> None:
    replace(root / "audit-policy.toml", 'owner = "dcrypt security assurance lead"', 'owner = ""')


def mutate_approver(root: Path) -> None:
    replace(root / "audit-policy.toml", 'approver = "independent dcrypt security reviewer"', 'approver = ""')


def mutate_independent_replay_issuance(root: Path) -> None:
    replace(root / "audit-policy.toml", '    "candidate-003 freeze is independently regenerated and replayed",\n', "")


def mutate_envelope_issuance(root: Path) -> None:
    replace(root / "audit-policy.toml", '    "a post-subject evidence envelope maps the stable candidate freeze ID to a lowercase 64-character canonical freeze.json SHA-256 digest and the policy, scope, and SOW SHA-256 digests",\n', "")


def mutate_blocker(root: Path) -> None:
    replace(root / "audit-policy.toml", '    "nonce",\n', "")


def mutate_closure(root: Path) -> None:
    replace(root / "audit-policy.toml", '    "regression-test",\n', "")


def mutate_public_report(root: Path) -> None:
    replace(root / "audit-policy.toml", "public-report-required = true", "public-report-required = false")


def mutate_markdown_digest(root: Path) -> None:
    replace(root / "RFP-SOW.md", "Machine policy SHA-256: `", "Machine policy SHA-256: `0")


def mutate_markdown_critical_ack(root: Path) -> None:
    replace(root / "RFP-SOW.md", "| 4 hours | 24 hours |", "| 999 hours | 24 hours |")


def mutate_markdown_embargo(root: Path) -> None:
    replace(root / "RFP-SOW.md", "- Embargo starts: first private report", "- Embargo starts: erased")


def mutate_malformed_toml(root: Path) -> None:
    with (root / "audit-scope.toml").open("a", encoding="utf-8") as stream:
        stream.write("\n[[unterminated\n")


def mutate_symlink(root: Path) -> None:
    target = root / "RFP-SOW.md"
    target.unlink()
    target.symlink_to(ROOT / "RFP-SOW.md")


def mutate_unexpected(root: Path) -> None:
    (root / "unreviewed.txt").write_text("not allowed\n", encoding="utf-8")


FIXTURES: list[tuple[str, Callable[[Path], None], str]] = [
    ("commissioned-state", mutate_status, "must remain candidate-uncommissioned"),
    ("policy-scope-freeze-id-mismatch", mutate_freeze_id, "scope candidate freeze ID differs"),
    ("candidate001-reuse", mutate_old_freeze_id, "policy candidate freeze ID differs"),
    ("candidate002-reuse", mutate_candidate002_reuse, "policy candidate freeze ID differs"),
    ("direct-supersession-rewritten", mutate_direct_supersession, "policy direct supersession differs"),
    ("supersession-history-reordered", mutate_supersession_order, "scope freeze supersession history differs"),
    ("candidate001-partial-independent-replay-erased", mutate_partial_replay_erased, "policy freeze supersession history differs"),
    ("candidate001-required-complete-replay-falsely-claimed", mutate_required_complete_replay_claimed, "scope freeze supersession history differs"),
    ("candidate001-external-review-claimed", mutate_superseded_external_review, "policy freeze supersession history differs"),
    ("candidate001-audit-evidence-accepted", mutate_superseded_audit_evidence, "scope freeze supersession history differs"),
    ("candidate002-subject-commit-drift", mutate_candidate002_subject_commit, "policy freeze supersession history differs"),
    ("candidate002-subject-tree-drift", mutate_candidate002_subject_tree, "scope freeze supersession history differs"),
    ("candidate002-parent-sow-drift", mutate_candidate002_parent_sow, "policy freeze supersession history differs"),
    ("candidate002-triggering-defect-erased", mutate_candidate002_triggering_defect, "scope freeze supersession history differs"),
    ("candidate002-known-defect-1-mutated", mutate_candidate002_known_defect_1, "policy freeze supersession history differs"),
    ("candidate002-known-defect-2-mutated", mutate_candidate002_known_defect_2, "policy freeze supersession history differs"),
    ("candidate002-known-defect-3-mutated", mutate_candidate002_known_defect_3, "policy freeze supersession history differs"),
    ("candidate002-known-defect-4-mutated", mutate_candidate002_known_defect_4, "policy freeze supersession history differs"),
    ("candidate002-known-defect-1-removed", remove_candidate002_known_defect_1, "scope freeze supersession history differs"),
    ("candidate002-known-defect-2-removed", remove_candidate002_known_defect_2, "scope freeze supersession history differs"),
    ("candidate002-known-defect-3-removed", remove_candidate002_known_defect_3, "scope freeze supersession history differs"),
    ("candidate002-known-defect-4-removed", remove_candidate002_known_defect_4, "scope freeze supersession history differs"),
    ("candidate002-known-defects-reordered", reorder_candidate002_known_defects, "policy freeze supersession history differs"),
    ("candidate002-unknown-defect-added", add_unknown_candidate002_known_defect, "scope freeze supersession history differs"),
    ("candidate002-defect-set-not-exhaustive", mutate_candidate002_defect_exhaustiveness, "policy freeze supersession history differs"),
    ("candidate002-diagnostic-promoted", mutate_candidate002_classification, "policy freeze supersession history differs"),
    ("candidate002-review-scope-promoted", mutate_candidate002_review_scope, "scope freeze supersession history differs"),
    ("candidate002-provisioning-manifest-hash-drift", mutate_candidate002_provisioning_manifest_hash, "policy freeze supersession history differs"),
    ("candidate002-provisioning-sums-hash-drift", mutate_candidate002_provisioning_sums_hash, "policy freeze supersession history differs"),
    ("candidate002-freeze-hash-drift", mutate_candidate002_freeze_hash, "policy freeze supersession history differs"),
    ("candidate002-sha256sums-hash-drift", mutate_candidate002_sha256sums_hash, "policy freeze supersession history differs"),
    ("candidate002-materialization-observation-erased", mutate_candidate002_materialization_observation, "scope freeze supersession history differs"),
    ("candidate002-bundle-observation-erased", mutate_candidate002_bundle_observation, "scope freeze supersession history differs"),
    ("candidate002-wrapper-promoted", mutate_candidate002_wrapper_promotion, "scope freeze supersession history differs"),
    ("candidate002-materialization-promoted", mutate_candidate002_materialization_promotion, "scope freeze supersession history differs"),
    ("candidate002-bundle-promoted", mutate_candidate002_bundle_promotion, "scope freeze supersession history differs"),
    ("candidate002-evidence-commit-promoted", mutate_candidate002_evidence_commit_promotion, "scope freeze supersession history differs"),
    ("candidate002-replay-promoted", mutate_candidate002_replay_promotion, "scope freeze supersession history differs"),
    ("candidate002-external-review-promoted", mutate_candidate002_external_review_promotion, "scope freeze supersession history differs"),
    ("candidate002-audit-evidence-promoted", mutate_candidate002_evidence_promotion, "scope freeze supersession history differs"),
    ("candidate002-external-audit-claimed", mutate_candidate002_external_audit_claim, "scope freeze supersession history differs"),
    ("candidate002-vendor-contact-claimed", mutate_candidate002_vendor_contact_claim, "scope freeze supersession history differs"),
    ("embedded-later-freeze-digest", mutate_content_identity, "defer content identity"),
    ("published-v3-inferred", mutate_subject_boundary, "subject-boundary differs from the exact candidate-versus-published-byte contract"),
    ("public-api-source-escape", mutate_public_api_source, "scope public-api-source differs from the exact versioned contract"),
    ("threat-model-source-escape", mutate_threat_model_source, "scope threat-model-source differs from the exact versioned contract"),
    ("vendor-selected-scope", mutate_scope_rule, "scope scope-rule differs from the exact versioned contract"),
    ("machine-policy-semantics-drift", mutate_machine_policy_semantics, "versioned document digest differs for audit-policy.toml"),
    ("workstream-title-drift", mutate_workstream_title_everywhere, "workstream ml-kem title differs from the exact contract"),
    ("markdown-contradiction", mutate_markdown_contradiction, "versioned document digest differs for RFP-SOW.md"),
    ("independence-disabled", mutate_independence, "every independence control must be true"),
    ("specialist-missing", mutate_specialist, "specialist coverage differs"),
    ("scope-topic-missing", mutate_scope_topic, "workstream ml-kem.topics differs"),
    ("row-mapping-optional", mutate_row_mapping, "empty finding row mappings must be forbidden"),
    ("sla-critical-4-to-999", mutate_sla, "severity critical contract differs"),
    ("sla-clock-start-erased", mutate_clock_start, "sla-policy semantics differ"),
    ("embargo-start-erased", mutate_embargo_start, "coordinated-disclosure.embargo-start differs"),
    ("ml-kem-standard-bogus", mutate_standard, "workstream ml-kem.standards differs"),
    ("owner-erased", mutate_owner, "policy owner differs from the exact versioned contract"),
    ("approver-erased", mutate_approver, "policy approver differs from the exact versioned contract"),
    ("independent-replay-issuance-removed", mutate_independent_replay_issuance, "issuance requirements differ"),
    ("evidence-envelope-issuance-removed", mutate_envelope_issuance, "issuance requirements differ"),
    ("release-blocker-missing", mutate_blocker, "release-blocking defect classes differ"),
    ("closure-record-missing", mutate_closure, "finding closure records differ"),
    ("public-report-disabled", mutate_public_report, "coordinated-disclosure.public-report-required differs"),
    ("markdown-digest-drift", mutate_markdown_digest, "SOW missing or stale binding line"),
    ("markdown-critical-ack-drift", mutate_markdown_critical_ack, "SOW SLA table does not exactly reconcile"),
    ("markdown-embargo-drift", mutate_markdown_embargo, "SOW coordinated-disclosure section does not exactly reconcile"),
    ("malformed-toml", mutate_malformed_toml, "cannot parse audit-scope.toml"),
    ("symlinked-input", mutate_symlink, "symlinked input forbidden"),
    ("unexpected-file", mutate_unexpected, "SOW package files differ"),
]


def run_fixture(name: str, mutation: Callable[[Path], None], expected: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"dcrypt-sow-{name}-") as temporary:
        candidate = Path(temporary) / "sow"
        shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        mutation(candidate)
        try:
            VERIFY.validate_bundle(candidate)
        except VERIFY.ValidationError as exc:
            if expected not in str(exc):
                raise AssertionError(f"{name}: rejected for wrong reason: {exc}") from exc
            return
        raise AssertionError(f"{name}: invalid fixture passed")


def run_parent_symlink_root_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="dcrypt-sow-parent-symlink-") as temporary:
        temporary_root = Path(temporary)
        real_parent = temporary_root / "real-parent"
        candidate = real_parent / "sow"
        shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        alias_parent = temporary_root / "alias-parent"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = VERIFY.main(["--root", str(alias_parent / "sow")])
        require_message = "symlinked SOW root or ancestor forbidden"
        if result != 1 or require_message not in stderr.getvalue():
            raise AssertionError(
                "parent-symlink-root: --root did not fail closed for the expected reason: "
                f"exit={result}, stderr={stderr.getvalue()!r}"
            )


def run_unsafe_root_fixture() -> None:
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        result = VERIFY.main(["--root", "/"])
    require_message = "filesystem root forbidden"
    if result != 1 or require_message not in stderr.getvalue():
        raise AssertionError(
            "unsafe-root: --root / did not fail closed for the expected reason: "
            f"exit={result}, stderr={stderr.getvalue()!r}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    try:
        VERIFY.validate_bundle(ROOT)
        for name, mutation, expected in FIXTURES:
            run_fixture(name, mutation, expected)
            if args.verbose:
                print(f"PASS negative fixture: {name}")
        run_parent_symlink_root_fixture()
        if args.verbose:
            print("PASS negative fixture: parent-symlink-root")
        run_unsafe_root_fixture()
        if args.verbose:
            print("PASS negative fixture: unsafe-root")
        try:
            VERIFY.validate_bundle(ROOT, issuance=True)
        except VERIFY.ValidationError as exc:
            if "issuance blocked" not in str(exc):
                raise AssertionError(f"issuance gate rejected for wrong reason: {exc}") from exc
        else:
            raise AssertionError("issuance gate unexpectedly passed")
    except (AssertionError, RuntimeError, VERIFY.ValidationError) as exc:
        print(f"audit SOW self-test failed: {exc}", file=sys.stderr)
        return 1

    print(f"audit SOW self-test passed: valid=1, negative={len(FIXTURES) + 2}, issuance-blocked=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
