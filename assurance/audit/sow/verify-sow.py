#!/usr/bin/env python3
"""Fail-closed validator for the candidate external-audit policy and SOW."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import stat
import sys
import tomllib
from typing import Any


FREEZE_ID = "dcrypt-v3.0.0-audit-candidate-003"
DIRECTLY_SUPERSEDED_FREEZE_ID = "dcrypt-v3.0.0-audit-candidate-002"
VERSIONED_DOCUMENT_SHA256 = {
    "audit-policy.toml": "eda28392c5e52b6242a7b796562afeb5c4af342ae17a31f1115b83e3463b4a99",
    "audit-scope.toml": "066f83e994f0a3fa15b6c8180048290b65d68a856f3cd8cfac476db0efef2a58",
    "RFP-SOW.md": "e7332306b6f956a1684c3f2ec7eebbc8c32f50cc7877131bdefb1d57b38bc868",
}
FREEZE_SUPERSESSION_HISTORY = [
    {
        "superseded-freeze-id": "dcrypt-v3.0.0-audit-candidate-001",
        "status": "invalidated-after-partial-independent-replay-before-acceptance",
        "reason": "Candidate-002 supersedes candidate-001 because a documented PTY wrapper mismatch invalidated candidate-001 after partial independent replay observations but before completion and acceptance under the full required replay contract.",
        "partial-independent-replay-observed": True,
        "required-complete-independent-replay-completed": False,
        "external-review-completed": False,
        "audit-evidence-accepted": False,
    },
    {
        "superseded-freeze-id": DIRECTLY_SUPERSEDED_FREEZE_ID,
        "status": "invalidated-after-first-party-diagnostic-before-valid-wrapper-compliant-generation",
        "reason": "Candidate-003 directly supersedes candidate-002 because the provision and generation README fences could return exit status 0 after a failed gate due to a trailing assignment; candidate-002 was invalidated after first-party diagnostic temporary materialization and diagnostic bundle creation but before valid wrapper-compliant materialization, valid candidate generation, an evidence commit, complete independent replay, or acceptance.",
        "subject-commit": "852c771c7d764752e23322ab412b419925fb5a5f",
        "subject-tree": "ae5779e73b64b60cc4ce198468ef9fd781cda2df",
        "parent-sow-commit": "8e3b8d7ee3ea9ec7d1901dadf9c85f3aa0706c02",
        "triggering-invalidation-defect": "provision/generation README fences could return 0 after failed gate due trailing assignment",
        "known-invalidation-defects": [
            "provision/generation README fences could return 0 after failed gate due trailing assignment",
            "clone fence could continue to checkout preexisting repo after failed clone",
            "candidate import fence could mask mkdir/middle install failures and omitted prose-required unexpected-source-entry rejection",
            "provisioning transfer fence could mask intermediate failures",
        ],
        "known-invalidation-defects-exhaustive": True,
        "diagnostic-artifact-classification": "typed-first-party-diagnostic-non-evidence",
        "independent-review-scope": "source-selftest-and-fence-diagnostic-only-not-bundle-evidence",
        "diagnostic-provisioning-manifest-sha256": "f48385357526d1bdb141dbb624ae355c094b3c292f4b4d191a06095f29067e69",
        "diagnostic-provisioning-sums-sha256": "e6adb59c5ec6e687c6652dd7938b5213ac310418a85cf8384b1e348f1633f1a6",
        "diagnostic-freeze-sha256": "ed7e7a26c9ee645350d53245a71468e82b9a77310367a71b737d8691fa418335",
        "diagnostic-sha256sums-sha256": "8c8d4948cf3d6356028bf4dffaead4f256bb2e755a5882e4c07bb88e67335b43",
        "diagnostic_first_party_materialization_observed": True,
        "diagnostic_first_party_bundle_observed": True,
        "wrapper_contract_valid": False,
        "valid_materialization_completed": False,
        "valid_candidate_bundle_generated": False,
        "evidence_commit_created": False,
        "required_complete_independent_replay_completed": False,
        "external_review_completed": False,
        "audit_evidence_accepted": False,
        "external_audit_occurred": False,
        "vendor_contact_occurred": False,
    },
]
POLICY_SCALARS = {
    "document-id": "dcrypt-external-cryptographic-audit-policy-v3",
    "content-identity-policy": "The immutable in-subject SOW binds the stable candidate freeze ID. A later post-subject evidence envelope maps that ID to the canonical freeze.json SHA-256 and the policy, scope, and SOW SHA-256 digests without mutating these subject documents.",
    "owner": "dcrypt security assurance lead",
    "approver": "independent dcrypt security reviewer",
    "external-contact-authorized": False,
    "audit-commissioned": False,
}
SUBJECT_BOUNDARY = {
    "subject": "post-v3.0.0 assurance-branch candidate bytes identified by the candidate freeze",
    "published-v3-registry-bytes-inferred-in-scope": False,
    "rule": "Audit work and conclusions apply only to bytes bound by the candidate freeze. They do not apply to the published v3.0.0 tag or registry archives unless the auditor verifies an explicit byte-for-byte comparison and the final report names that extension.",
}
SCOPE_SCALARS = {
    "document-id": "dcrypt-v3-external-cryptographic-audit-scope-v3",
    "subject-version-label": "post-v3.0.0 assurance-branch candidate",
    "atomic-row-source": "assurance/atomic-operations.toml",
    "public-api-source": "assurance/public-api-snapshot.json",
    "threat-model-source": "assurance/threat-models/",
    "scope-rule": "All public atomic assurance rows matching an in-scope algorithm, primitive, composition, format or error path are in scope; generated aliases are traced to their owning implementation.",
    "finding-mapping-rule": "Every finding must map to one or more exact assurance row IDs, or create an explicit new row when the affected behavior was absent from the inventory.",
    "exclusion-rule": "No scope exclusion is effective unless listed in the candidate freeze, justified by the auditor, approved by the release authority, and retained as a release-blocking limitation for affected rows.",
}
EXPECTED_FILES = {
    "RFP-SOW.md",
    "audit-policy.toml",
    "audit-scope.toml",
    "fixtures/README.md",
    "selftest.py",
    "verify-sow.py",
}
POLICY_TOP_KEYS = {
    "schema-version",
    "document-id",
    "status",
    "candidate-freeze-id",
    "candidate-freeze-content-identity",
    "directly-supersedes-freeze-id",
    "content-identity-policy",
    "owner",
    "approver",
    "external-contact-authorized",
    "audit-commissioned",
    "freeze-supersession",
    "subject-boundary",
    "independence",
    "specialist",
    "methodology",
    "artifact-access",
    "finding-format",
    "severity",
    "sla-policy",
    "coordinated-disclosure",
    "deliverables",
    "release-acceptance",
    "issuance-gate",
}
SCOPE_TOP_KEYS = {
    "schema-version",
    "document-id",
    "status",
    "candidate-freeze-id",
    "candidate-freeze-content-identity",
    "directly-supersedes-freeze-id",
    "freeze-supersession",
    "subject-version-label",
    "atomic-row-source",
    "public-api-source",
    "threat-model-source",
    "scope-rule",
    "finding-mapping-rule",
    "exclusion-rule",
    "workstream",
    "cross-cutting",
    "out-of-scope-policy",
}
SPECIALISTS = {
    "pqc",
    "pairing-ecc",
    "symmetric",
    "side-channel",
    "protocols",
    "supply-chain",
}
WORKSTREAMS: dict[str, dict[str, set[str]]] = {
    "ml-kem": {
        "standards": {"FIPS 203"},
        "parameter-sets": {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"},
        "topics": {
            "key generation", "encapsulation", "decapsulation",
            "implicit rejection", "parsing", "canonical encoding",
            "NTT arithmetic", "sampling", "randomness behavior",
            "failure behavior",
        },
        "required-specialists": {"pqc", "side-channel", "protocols"},
    },
    "ml-dsa": {
        "standards": {"FIPS 204"},
        "parameter-sets": {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"},
        "topics": {
            "key generation", "deterministic signing", "hedged signing",
            "verification", "contexts", "prehash modes", "rejection sampling",
            "canonical encoding", "malformed signatures",
            "randomness and failure behavior",
        },
        "required-specialists": {"pqc", "side-channel", "protocols"},
    },
    "bls12-381": {
        "standards": {"RFC 9380", "IETF BLS signatures", "Ethereum consensus BLS profile"},
        "parameter-sets": {"BLS12-381", "BLS12-381-G2"},
        "topics": {
            "field arithmetic", "group arithmetic", "pairing arithmetic",
            "subgroup arithmetic and validation", "hash-to-curve",
            "domain separation", "KeyGen", "Basic profile",
            "Augmented profile", "Proof-of-Possession profile",
            "Ethereum profile", "aggregation", "duplicate-message attacks",
            "rogue-key attacks", "invalid-point attacks",
        },
        "required-specialists": {"pairing-ecc", "side-channel", "protocols"},
    },
    "ed25519": {
        "standards": {"RFC 8032"},
        "parameter-sets": {"Ed25519"},
        "topics": {
            "key generation", "signing", "strict verification",
            "canonical encoding", "small-order points", "identity points",
            "signature malleability", "malformed keys and signatures",
        },
        "required-specialists": {"pairing-ecc", "side-channel", "protocols"},
    },
    "weierstrass-curves": {
        "standards": {"FIPS 186-5", "RFC 6979", "SEC 1"},
        "parameter-sets": {"P-224", "P-256", "P-384", "P-521", "secp256k1"},
        "topics": {
            "field and scalar arithmetic", "point arithmetic", "ECDSA signing",
            "ECDSA strict verification", "RFC6979 deterministic nonce generation",
            "DER encoding and parsing", "low-S rules", "ECDH",
            "point validation", "invalid-point attacks", "ECIES protocols",
            "ECIES transcripts",
        },
        "required-specialists": {"pairing-ecc", "side-channel", "protocols"},
    },
    "aes-gcm-ghash": {
        "standards": {"FIPS 197", "SP 800-38D"},
        "parameter-sets": {"AES-128-GCM", "AES-256-GCM", "GHASH"},
        "topics": {
            "AES field and round arithmetic", "GHASH field arithmetic",
            "encryption and decryption", "authentication behavior",
            "nonce handling", "tag generation", "tag verification",
            "tampering and truncation behavior", "compiler output",
            "platform-specific implementations",
        },
        "required-specialists": {"symmetric", "side-channel", "protocols"},
    },
    "chacha-poly1305": {
        "standards": {"RFC 8439", "XChaCha draft construction"},
        "parameter-sets": {
            "ChaCha20", "HChaCha20", "Poly1305", "ChaCha20-Poly1305",
            "XChaCha20-Poly1305",
        },
        "topics": {
            "ChaCha20 core and stream generation", "HChaCha20 subkey derivation",
            "Poly1305 arithmetic", "ChaCha20-Poly1305 seal and open",
            "XChaCha20-Poly1305 seal and open", "nonce handling",
            "AAD and transcript construction", "tag verification",
            "canonical framing", "tampering and truncation behavior",
        },
        "required-specialists": {"symmetric", "side-channel", "protocols"},
    },
    "kdfs-passwords": {
        "standards": {"RFC 5869", "RFC 8018", "SP 800-132", "RFC 9106"},
        "parameter-sets": {
            "HKDF", "PBKDF2", "Argon2d", "Argon2i", "Argon2id",
            "dcrypt key-derivation profiles",
        },
        "topics": {
            "extract and expand semantics", "salt and context handling",
            "domain separation", "password and secret lifecycle",
            "parameter validation", "resource bounds", "random salt generation",
            "RNG failure propagation",
        },
        "required-specialists": {"symmetric", "side-channel", "protocols"},
    },
    "hybrids-ecies-framing": {
        "standards": {"dcrypt v3 wire and transcript specifications"},
        "parameter-sets": {
            "ECDH+ML-KEM hybrid KEMs", "ECDSA+ML-DSA hybrid signatures",
            "dcrypt ECIES", "streaming formats", "migration formats",
        },
        "topics": {
            "wire encoding", "framing", "transcript construction",
            "domain separation", "KDF inputs", "key confirmation",
            "component failure composition", "downgrade and version negotiation",
            "tampering and truncation behavior", "migration compatibility",
        },
        "required-specialists": {"pqc", "pairing-ecc", "symmetric", "protocols"},
    },
    "rng-errors-lifecycle": {
        "standards": {"caller-owned CryptoRng contract", "dcrypt v3 compatibility contract"},
        "parameter-sets": {"all secret-generating and randomized operations"},
        "topics": {
            "entropy acquisition assumptions", "entropy degradation",
            "RNG failure propagation", "partial-output behavior",
            "operation-scoped errors", "deprecated global error registry behavior",
            "secret creation and ownership", "secret copying and exposure",
            "zeroization behavior", "documented zeroization limitations",
            "panic and fault behavior",
        },
        "required-specialists": {
            "pqc", "pairing-ecc", "symmetric", "protocols", "supply-chain",
        },
    },
    "historical-regressions": {
        "standards": {"dcrypt security advisory records"},
        "parameter-sets": {"DCRYPT-2026-0001 through DCRYPT-2026-0011"},
        "topics": {
            "error-registry memory unsafety", "Ed25519 universal forgery",
            "GCM ignored operation nonce", "unauthenticated streaming framing",
            "predictable legacy ECDH-KEM secret",
            "BLS subgroup-validation bypass",
            "BLS hash-to-curve incompatibility",
            "pre-final ML-KEM incompatibility", "XChaCha zero-nonce reuse",
            "nonstandard XChaCha construction",
            "GHASH secret-dependent compiled branches",
            "variant analysis for shared root causes",
        },
        "required-specialists": SPECIALISTS,
    },
    "build-supply-chain": {
        "standards": {"dcrypt implementation-boundary and release policies"},
        "parameter-sets": {"all twelve published crates and isolated assurance workspaces"},
        "topics": {
            "dependency closure and lockfiles", "published package contents",
            "unsafe-code boundary", "native-code and FFI boundary",
            "isolated oracle and fuzz workspaces", "toolchain and target binding",
            "action and container pinning", "SBOM completeness",
            "registry archive correspondence", "reproducible build claims",
            "clean-room replay",
        },
        "required-specialists": {"supply-chain", "side-channel"},
    },
}
WORKSTREAM_TITLES = {
    "ml-kem": "ML-KEM-512/768/1024",
    "ml-dsa": "ML-DSA-44/65/87",
    "bls12-381": "BLS12-381 arithmetic and signatures",
    "ed25519": "Ed25519",
    "weierstrass-curves": "P-curves and secp256k1",
    "aes-gcm-ghash": "AES-128/256-GCM and GHASH",
    "chacha-poly1305": "ChaCha-family and Poly1305 constructions",
    "kdfs-passwords": "KDFs and password-derived operations",
    "hybrids-ecies-framing": "Hybrid constructions, ECIES and framing",
    "rng-errors-lifecycle": "RNG, errors and secret lifecycle",
    "historical-regressions": "Historical-advisory regression and variant analysis",
    "build-supply-chain": "Build, dependency and supply-chain assurance",
}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
SEVERITY_CONTRACT: dict[str, dict[str, Any]] = {
    "critical": {
        "definition": "Practical or broadly exploitable key recovery, signature or authentication forgery, remote code execution or memory unsafety across a common/default use, catastrophic systemic protocol break, or equivalent impact.",
        "acknowledgement-hours": 4,
        "containment-plan-hours": 24,
        "remediation-calendar-days": 3,
        "independent-retest-business-days": 5,
        "coordinated-disclosure-calendar-days": 30,
        "release-blocking": True,
    },
    "high": {
        "definition": "Key recovery, forgery, authentication bypass, material confidentiality/integrity loss, exploitable side channel, or standards/correctness failure under realistic preconditions.",
        "acknowledgement-hours": 24,
        "containment-plan-hours": 72,
        "remediation-calendar-days": 14,
        "independent-retest-business-days": 10,
        "coordinated-disclosure-calendar-days": 60,
        "release-blocking": True,
    },
    "medium": {
        "definition": "Security weakness requiring restrictive conditions, meaningful denial of service, defense-in-depth failure, or correctness defect with limited security reach.",
        "acknowledgement-hours": 72,
        "containment-plan-hours": 240,
        "remediation-calendar-days": 45,
        "independent-retest-business-days": 15,
        "coordinated-disclosure-calendar-days": 90,
        "release-blocking": False,
    },
    "low": {
        "definition": "Limited-impact hardening, misuse-resistance, diagnostic, documentation or non-default weakness without a demonstrated material compromise.",
        "acknowledgement-hours": 120,
        "containment-plan-hours": 720,
        "remediation-calendar-days": 90,
        "independent-retest-business-days": 20,
        "coordinated-disclosure-calendar-days": 120,
        "release-blocking": False,
    },
    "informational": {
        "definition": "Observation with no current security impact that records an assumption, limitation, quality improvement or future risk.",
        "acknowledgement-hours": 120,
        "containment-plan-hours": 1440,
        "remediation-calendar-days": 180,
        "independent-retest-business-days": 20,
        "coordinated-disclosure-calendar-days": 180,
        "release-blocking": False,
    },
}
SLA_POLICY = {
    "clock-start": "Auditor delivery to the designated private reporting channel",
    "business-day-definition": "One business day in the project security lead's published timezone, excluding published local holidays",
    "calendar-day-definition": "Continuous 24-hour periods",
    "missed-sla": "Escalate to the security lead and release authority; a missed Critical or High remediation or retest SLA blocks release unless a documented risk decision withdraws the affected functionality.",
    "extensions": "Require written agreement from the security lead and auditor, a reason, a replacement date, affected assurance rows, and an explicit release disposition. Critical and High findings cannot be risk-accepted for release.",
}
DISCLOSURE_SCALARS: dict[str, Any] = {
    "private-reporting-required": True,
    "need-to-know-access-required": True,
    "embargo-start": "first private report",
    "embargo-end": "the earliest coordinated publication date agreed by dcrypt and the auditor, or the applicable disclosure SLA",
    "vendor-and-downstream-notice": "Notify affected dependencies and downstreams privately when their action is required, using least disclosure necessary during embargo.",
    "credential-handling": "No secrets, signing credentials, registry tokens or production keys may enter audit artifacts; suspected credential exposure triggers the incident-response procedure immediately.",
    "public-report-required": True,
    "public-report-timing": "after remediation and independent retest, or at the coordinated-disclosure deadline when remediation is incomplete",
}
PERMITTED_REDACTIONS = (
    "active exploit details during an agreed embargo",
    "personal data",
    "third-party confidential material not needed to understand risk or remediation",
    "credentials and infrastructure secrets",
)
FORBIDDEN_REDACTIONS = (
    "finding existence",
    "final severity",
    "affected algorithms and assurance rows",
    "security impact",
    "remediation status",
    "whether independent retesting passed",
    "material scope limitations or conflicts",
)
ISSUANCE_REQUIREMENTS = {
    "a post-subject evidence envelope maps the stable candidate freeze ID to a lowercase 64-character canonical freeze.json SHA-256 digest and the policy, scope, and SOW SHA-256 digests",
    "candidate-003 freeze is independently regenerated and replayed",
    "the ordered candidate-001 and candidate-002 supersession records remain exact, candidate-003 directly supersedes candidate-002, and neither superseded candidate may be reused, promoted, issued, or treated as audit or assurance evidence",
    "the issued SOW identifies the post-v3.0.0 candidate as its subject and does not imply that published v3.0.0 registry bytes were audited",
    "all required audit artifacts are present or explicitly recorded as release-blocking limitations",
    "policy, scope and SOW digest binding passes assurance/audit/sow/verify-sow.py",
    "security lead separately authorizes vendor contact and commissioning",
}
BLOCKER_CLASSES = {
    "correctness",
    "forgery",
    "key-recovery",
    "nonce",
    "domain-separation",
    "secret-dependent-control-flow",
    "secret-dependent-memory-address",
}
CLOSURE_RECORDS = {"regression-test", "remediation-record", "independent-retest"}
CROSS_CUTTING = {
    "canonical parsing and encoding",
    "malformed and noncanonical inputs",
    "empty, boundary and maximum inputs",
    "denial of service and resource bounds",
    "secret-dependent control flow",
    "secret-dependent memory access",
    "compiler and platform variance",
    "fault injection and partial computation",
    "public API and feature-profile drift",
    "oracle and dependency common-mode failure",
}


class ValidationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    require(actual == expected, f"{context} keys differ: missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}")


def unique_strings(value: Any, context: str) -> set[str]:
    require(isinstance(value, list) and value, f"{context} must be a non-empty array")
    require(all(isinstance(item, str) and item.strip() for item in value), f"{context} must contain non-empty strings")
    result = set(value)
    require(len(result) == len(value), f"{context} contains duplicates")
    return result


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_toml(path: Path) -> dict[str, Any]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError(f"cannot parse {path.name}: {exc}") from exc
    require(isinstance(data, dict), f"{path.name} root must be a table")
    return data


def safe_root(root: Path) -> Path:
    """Resolve a bundle root without accepting any symlinked path component."""
    absolute = root.absolute()
    components = list(reversed(absolute.parents)) + [absolute]
    for component in components:
        try:
            mode = component.lstat().st_mode
        except OSError as exc:
            raise ValidationError(f"cannot inspect SOW root component {component}: {exc}") from exc
        require(not stat.S_ISLNK(mode), f"symlinked SOW root or ancestor forbidden: {component}")
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise ValidationError(f"cannot resolve SOW root: {exc}") from exc
    require(resolved == absolute, f"unsafe resolved SOW root: lexical={absolute}, resolved={resolved}")
    require(resolved != Path(resolved.anchor), "unsafe resolved SOW root: filesystem root forbidden")
    require(resolved.parent != resolved, "unsafe resolved SOW root: parent cycle")
    return resolved


def verify_files(root: Path) -> None:
    require(root.is_dir() and not root.is_symlink(), "SOW root must be a real directory")
    actual: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValidationError(f"symlinked input forbidden: {relative}")
        if path.is_file():
            actual.add(relative)
    require(actual == EXPECTED_FILES, f"SOW package files differ: missing={sorted(EXPECTED_FILES - actual)}, unexpected={sorted(actual - EXPECTED_FILES)}")
    for relative in EXPECTED_FILES:
        path = root / relative
        require(path.is_file() and not path.is_symlink(), f"required regular file missing: {relative}")


def verify_common_identity(policy: dict[str, Any], scope: dict[str, Any]) -> None:
    for name, doc in (("policy", policy), ("scope", scope)):
        require(doc.get("schema-version") == 3, f"{name} schema-version must be 3")
        require(doc.get("status") == "candidate-uncommissioned", f"{name} must remain candidate-uncommissioned")
        require(doc.get("candidate-freeze-id") == FREEZE_ID, f"{name} candidate freeze ID differs")
        require(doc.get("candidate-freeze-content-identity") == "resolved-by-post-subject-evidence-envelope", f"{name} must defer content identity to the post-subject evidence envelope")
        require(doc.get("directly-supersedes-freeze-id") == DIRECTLY_SUPERSEDED_FREEZE_ID, f"{name} direct supersession differs")
        require(isinstance(doc.get("freeze-supersession"), list), f"{name} freeze supersession history must be an ordered array")
        require(doc.get("freeze-supersession") == FREEZE_SUPERSESSION_HISTORY, f"{name} freeze supersession history differs from the exact ordered candidate-001 and candidate-002 dispositions")
    require(policy["external-contact-authorized"] is False, "external contact must remain unauthorized")
    require(policy["audit-commissioned"] is False, "audit must remain uncommissioned")


def verify_policy(policy: dict[str, Any]) -> None:
    exact_keys(policy, POLICY_TOP_KEYS, "policy")
    for key, expected in POLICY_SCALARS.items():
        require(policy[key] == expected, f"policy {key} differs from the exact versioned contract")
    require(policy["owner"] != policy["approver"], "policy owner and approver must be distinct")

    boundary = policy["subject-boundary"]
    exact_keys(boundary, {"subject", "published-v3-registry-bytes-inferred-in-scope", "rule"}, "subject-boundary")
    require(boundary == SUBJECT_BOUNDARY, "subject-boundary differs from the exact candidate-versus-published-byte contract")

    independence = policy["independence"]
    independence_bools = {
        "organizationally-independent",
        "conflict-disclosure-required",
        "prior-material-contributors-prohibited",
        "subcontractor-disclosure-required",
        "financial-interest-disclosure-required",
        "shared-tooling-and-lineage-disclosure-required",
        "retest-independent-from-remediation",
    }
    require(all(independence.get(key) is True for key in independence_bools), "every independence control must be true")
    require(independence.get("prior-material-contribution-window-months", 0) >= 24, "prior-contribution exclusion must cover at least 24 months")
    require(len(unique_strings(independence.get("minimum-rules"), "independence.minimum-rules")) >= 5, "at least five independence rules required")

    specialists = policy["specialist"]
    require(isinstance(specialists, list), "specialist must be an array of tables")
    seen: set[str] = set()
    for specialist in specialists:
        exact_keys(specialist, {"id", "role", "minimum-competence", "required"}, "specialist")
        specialist_id = specialist["id"]
        require(specialist_id not in seen, f"duplicate specialist: {specialist_id}")
        seen.add(specialist_id)
        require(specialist["required"] is True, f"specialist {specialist_id} must be required")
        require(len(specialist["minimum-competence"].strip()) >= 20, f"specialist {specialist_id} competence is not concrete")
    require(seen == SPECIALISTS, f"specialist coverage differs: missing={sorted(SPECIALISTS - seen)}, unexpected={sorted(seen - SPECIALISTS)}")

    methods = policy["methodology"]
    require(len(unique_strings(methods.get("required-methods"), "methodology.required-methods")) >= 6, "six audit methods required")
    for key in ("generated-evidence-trusted-by-default", "scaffolding-counts-as-evidence", "inconclusive-counts-as-pass"):
        require(methods.get(key) is False, f"methodology.{key} must be false")

    access = policy["artifact-access"]
    require(len(unique_strings(access.get("required"), "artifact-access.required")) >= 12, "artifact access inventory is incomplete")
    require("release blocker" in access.get("missing-artifact-disposition", ""), "missing artifacts must remain release blockers")

    finding = policy["finding-format"]
    required_finding_fields = {
        "finding-id", "title", "severity", "defect-class", "status",
        "affected-assurance-row-ids", "affected-public-paths",
        "affected-commit-and-tree", "affected-features-targets-and-toolchains",
        "threat-model-and-attacker-preconditions", "security-impact",
        "reproduction-steps", "evidence-and-artifact-hashes", "root-cause",
        "variant-analysis", "recommended-remediation", "regression-test-id",
        "remediation-record-id", "retest-record-id", "disclosure-state",
    }
    require(unique_strings(finding.get("required-fields"), "finding-format.required-fields") == required_finding_fields, "finding fields differ from the required exact set")
    require(finding.get("assurance-row-source") == "assurance/atomic-operations.toml", "finding row source differs")
    require(finding.get("empty-affected-row-list-permitted") is False, "empty finding row mappings must be forbidden")
    require(finding.get("new-row-required-when-no-existing-row-matches") is True, "new row must be required when no row matches")

    severities = policy["severity"]
    require(isinstance(severities, list), "severity must be an array of tables")
    seen_severities: set[str] = set()
    severity_fields = {
        "id", "definition", "acknowledgement-hours", "containment-plan-hours",
        "remediation-calendar-days", "independent-retest-business-days",
        "coordinated-disclosure-calendar-days", "release-blocking",
    }
    for severity in severities:
        exact_keys(severity, severity_fields, "severity")
        severity_id = severity["id"]
        require(severity_id not in seen_severities, f"duplicate severity: {severity_id}")
        seen_severities.add(severity_id)
        require(severity_id in SEVERITY_CONTRACT, f"unexpected severity: {severity_id}")
        expected = {"id": severity_id, **SEVERITY_CONTRACT[severity_id]}
        require(severity == expected, f"severity {severity_id} contract differs from the exact taxonomy and SLA")
    expected_severities = set(SEVERITY_CONTRACT)
    require(seen_severities == expected_severities, f"severity taxonomy differs: missing={sorted(expected_severities - seen_severities)}, unexpected={sorted(seen_severities - expected_severities)}")

    sla_policy = policy["sla-policy"]
    exact_keys(sla_policy, set(SLA_POLICY), "sla-policy")
    require(sla_policy == SLA_POLICY, "sla-policy semantics differ from the exact clock, calendar, escalation, or extension contract")

    disclosure = policy["coordinated-disclosure"]
    disclosure_keys = set(DISCLOSURE_SCALARS) | {"permitted-redactions", "forbidden-redactions"}
    exact_keys(disclosure, disclosure_keys, "coordinated-disclosure")
    for key, expected in DISCLOSURE_SCALARS.items():
        require(disclosure[key] == expected, f"coordinated-disclosure.{key} differs from the exact policy")
    require(disclosure["permitted-redactions"] == list(PERMITTED_REDACTIONS), "permitted-redactions differ from the exact policy")
    require(disclosure["forbidden-redactions"] == list(FORBIDDEN_REDACTIONS), "forbidden-redactions differ from the exact policy")

    deliverables = unique_strings(policy["deliverables"].get("required"), "deliverables.required")
    for phrase in ("public report", "independent retest letter", "finding-to-regression-test"):
        require(any(phrase in item for item in deliverables), f"deliverable missing: {phrase}")

    acceptance = policy["release-acceptance"]
    require(unique_strings(acceptance.get("unresolved-severities-forbidden"), "release-acceptance.unresolved-severities-forbidden") == {"critical", "high"}, "Critical and High must both block release")
    require(unique_strings(acceptance.get("unresolved-defect-classes-forbidden"), "release-acceptance.unresolved-defect-classes-forbidden") == BLOCKER_CLASSES, "release-blocking defect classes differ")
    require(unique_strings(acceptance.get("required-closure-records"), "release-acceptance.required-closure-records") == CLOSURE_RECORDS, "finding closure records differ")
    for key in ("confirmed-finding-must-have-regression", "auditor-mandatory-independent-retest"):
        require(acceptance.get(key) is True, f"release-acceptance.{key} must be true")
    for key in ("inconclusive-is-accepted", "unreplayed-generated-evidence-is-accepted", "scaffolded-evidence-is-accepted", "scope-limitation-clears-row"):
        require(acceptance.get(key) is False, f"release-acceptance.{key} must be false")

    issuance = policy["issuance-gate"]
    exact_keys(issuance, {"requirements"}, "issuance-gate")
    issuance_requirements = unique_strings(issuance["requirements"], "issuance-gate.requirements")
    require(issuance_requirements == ISSUANCE_REQUIREMENTS, "issuance requirements differ from the exact evidence-envelope, independent-replay, subject, artifact, digest, and authorization gates")


def verify_scope(scope: dict[str, Any]) -> None:
    exact_keys(scope, SCOPE_TOP_KEYS, "scope")
    for key, expected in SCOPE_SCALARS.items():
        require(scope[key] == expected, f"scope {key} differs from the exact versioned contract")

    workstreams = scope["workstream"]
    require(isinstance(workstreams, list), "workstream must be an array of tables")
    seen: set[str] = set()
    fields = {"id", "title", "standards", "parameter-sets", "topics", "required-specialists"}
    for workstream in workstreams:
        exact_keys(workstream, fields, "workstream")
        workstream_id = workstream["id"]
        require(workstream_id not in seen, f"duplicate workstream: {workstream_id}")
        seen.add(workstream_id)
        require(workstream_id in WORKSTREAMS, f"unexpected workstream: {workstream_id}")
        require(workstream["title"] == WORKSTREAM_TITLES[workstream_id], f"workstream {workstream_id} title differs from the exact contract")
        for key in ("standards", "parameter-sets", "topics", "required-specialists"):
            actual = unique_strings(workstream[key], f"workstream {workstream_id}.{key}")
            expected = WORKSTREAMS[workstream_id][key]
            require(actual == expected, f"workstream {workstream_id}.{key} differs: missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}")
        require(set(workstream["required-specialists"]).issubset(SPECIALISTS), f"workstream {workstream_id} names unknown specialist")
    require(seen == set(WORKSTREAMS), f"workstream coverage differs: missing={sorted(set(WORKSTREAMS) - seen)}, unexpected={sorted(seen - set(WORKSTREAMS))}")

    cross_cutting = unique_strings(scope["cross-cutting"].get("topics"), "cross-cutting.topics")
    require(cross_cutting == CROSS_CUTTING, f"cross-cutting topics differ: missing={sorted(CROSS_CUTTING - cross_cutting)}, unexpected={sorted(cross_cutting - CROSS_CUTTING)}")
    out = scope["out-of-scope-policy"]
    require(out.get("permitted") is False, "pre-authorized scope exclusions must be forbidden")
    require("release-blocking" in out.get("statement", ""), "excluded rows must remain release-blocking")


def render_sla_block(policy: dict[str, Any]) -> str:
    by_id = {severity["id"]: severity for severity in policy["severity"]}
    lines = [
        "<!-- BEGIN GENERATED SLA TABLE -->",
        "| Severity | Exact characterization | Acknowledge | Containment plan | Remediate | Independent retest | Coordinated disclosure | Release blocking |",
        "|---|---|---:|---:|---:|---:|---:|:---:|",
    ]
    for severity_id in SEVERITY_ORDER:
        severity = by_id[severity_id]
        lines.append(
            "| "
            + " | ".join(
                [
                    severity_id.title(),
                    severity["definition"],
                    f"{severity['acknowledgement-hours']:,} hours",
                    f"{severity['containment-plan-hours']:,} hours",
                    f"{severity['remediation-calendar-days']:,} calendar days",
                    f"{severity['independent-retest-business-days']:,} business days",
                    f"{severity['coordinated-disclosure-calendar-days']:,} calendar days",
                    "yes" if severity["release-blocking"] else "no",
                ]
            )
            + " |"
        )
    sla = policy["sla-policy"]
    lines.extend(
        [
            "",
            f"- Clock starts: {sla['clock-start']}",
            f"- Business day: {sla['business-day-definition']}",
            f"- Calendar day: {sla['calendar-day-definition']}",
            f"- Missed SLA: {sla['missed-sla']}",
            f"- Extensions: {sla['extensions']}",
            "<!-- END GENERATED SLA TABLE -->",
        ]
    )
    return "\n".join(lines)


def render_disclosure_block(policy: dict[str, Any]) -> str:
    disclosure = policy["coordinated-disclosure"]
    lines = [
        "<!-- BEGIN GENERATED COORDINATED DISCLOSURE -->",
        f"- Private reporting required: `{str(disclosure['private-reporting-required']).lower()}`",
        f"- Need-to-know access required: `{str(disclosure['need-to-know-access-required']).lower()}`",
        f"- Embargo starts: {disclosure['embargo-start']}",
        f"- Embargo ends: {disclosure['embargo-end']}",
        f"- Vendor and downstream notice: {disclosure['vendor-and-downstream-notice']}",
        f"- Credential handling: {disclosure['credential-handling']}",
        f"- Public report required: `{str(disclosure['public-report-required']).lower()}`",
        f"- Public report timing: {disclosure['public-report-timing']}",
        "- Permitted redactions:",
    ]
    lines.extend(f"  - {item}" for item in disclosure["permitted-redactions"])
    lines.append("- Forbidden redactions:")
    lines.extend(f"  - {item}" for item in disclosure["forbidden-redactions"])
    lines.append("<!-- END GENERATED COORDINATED DISCLOSURE -->")
    return "\n".join(lines)


def verify_markdown(root: Path, policy: dict[str, Any], scope: dict[str, Any]) -> None:
    markdown = (root / "RFP-SOW.md").read_text(encoding="utf-8")
    normalized = " ".join(markdown.split())
    required_exact = {
        "Status: **candidate / uncommissioned — do not issue**",
        f"Candidate freeze ID: `{FREEZE_ID}`",
        "Candidate freeze content identity: `resolved-by-post-subject-evidence-envelope`",
        f"Directly supersedes freeze ID: `{DIRECTLY_SUPERSEDED_FREEZE_ID}`",
        "Ordered supersession history: `dcrypt-v3.0.0-audit-candidate-001`, then `dcrypt-v3.0.0-audit-candidate-002`",
        "Candidate-001 superseded state: `invalidated-after-partial-independent-replay-before-acceptance`",
        "Candidate-002 superseded state: `invalidated-after-first-party-diagnostic-before-valid-wrapper-compliant-generation`",
        f"Machine policy SHA-256: `{sha256(root / 'audit-policy.toml')}`",
        f"Machine scope SHA-256: `{sha256(root / 'audit-scope.toml')}`",
    }
    for line in required_exact:
        require(line in markdown, f"SOW missing or stale binding line: {line}")
    for workstream in scope["workstream"]:
        require(workstream["title"] in markdown, f"SOW does not name workstream title: {workstream['title']}")
    required_phrases = [
        "No vendor contact is authorized",
        "Candidate-003 directly supersedes candidate-002",
        "Candidate-002 supersedes candidate-001 because a documented PTY wrapper mismatch invalidated candidate-001 after partial independent replay observations but before completion and acceptance under the full required replay contract",
        "non-PTY self-test, materialization, 13-file regeneration",
        "documented PTY wrapper mismatch",
        "not a completed required independent replay, acceptance, completed external review, external audit, or accepted audit or assurance evidence for candidate-001",
        "852c771c7d764752e23322ab412b419925fb5a5f",
        "ae5779e73b64b60cc4ce198468ef9fd781cda2df",
        "8e3b8d7ee3ea9ec7d1901dadf9c85f3aa0706c02",
        "provision/generation README fences could return 0 after failed gate due trailing assignment",
        "exact ordered, exhaustive set of all four known candidate-002 invalidation defects",
        "clone fence could continue to checkout preexisting repo after failed clone",
        "candidate import fence could mask mkdir/middle install failures and omitted prose-required unexpected-source-entry rejection",
        "provisioning transfer fence could mask intermediate failures",
        "first-party diagnostic temporary materialization and diagnostic bundle creation",
        "before valid wrapper-compliant materialization, valid candidate generation, an evidence commit, complete independent replay, or acceptance",
        "source, self-test, and fence diagnostics only, not candidate-002 bundle evidence",
        "typed first-party diagnostic non-evidence only",
        "f48385357526d1bdb141dbb624ae355c094b3c292f4b4d191a06095f29067e69",
        "e6adb59c5ec6e687c6652dd7938b5213ac310418a85cf8384b1e348f1633f1a6",
        "ed7e7a26c9ee645350d53245a71468e82b9a77310367a71b737d8691fa418335",
        "8c8d4948cf3d6356028bf4dffaead4f256bb2e755a5882e4c07bb88e67335b43",
        "Candidate-002 is non-evidence and must not be reused, promoted, or issued",
        "No external audit occurred and no vendor was contacted for either superseded candidate",
        "do **not** apply to the published v3.0.0 Git tag or registry archives",
        "Every confirmed finding requires a regression test, remediation record, and",
        "mandatory independent retest",
        "unresolved Critical",
        "secret-dependent-memory-address",
        "public report",
        "9,298 assurance rows",
    ]
    for phrase in required_phrases:
        require(phrase in normalized, f"SOW missing required statement: {phrase}")
    require(render_sla_block(policy) in markdown, "SOW SLA table does not exactly reconcile with machine policy")
    require(render_disclosure_block(policy) in markdown, "SOW coordinated-disclosure section does not exactly reconcile with machine policy")
    require(markdown.count("## ") >= 11, "SOW lacks required vendor-ready sections")
    require(policy["candidate-freeze-id"] == scope["candidate-freeze-id"], "policy/scope freeze ID mismatch")


def verify_versioned_document_bytes(root: Path) -> None:
    """Bind every authoritative machine and human SOW byte.

    Semantic checks above provide actionable diagnostics.  This final exact-byte
    check prevents an unchecked or contradictory policy/prose field from being
    accepted merely because a weaker semantic predicate overlooked it.  Any
    deliberate wording change therefore requires a separately reviewed version
    update to this validator and its fixtures.
    """
    for relative, expected in VERSIONED_DOCUMENT_SHA256.items():
        actual = sha256(root / relative)
        require(actual == expected, f"versioned document digest differs for {relative}: expected {expected}, got {actual}")


def validate_bundle(root: Path, issuance: bool = False) -> None:
    root = safe_root(root)
    verify_files(root)
    policy = load_toml(root / "audit-policy.toml")
    scope = load_toml(root / "audit-scope.toml")
    verify_common_identity(policy, scope)
    verify_policy(policy)
    verify_scope(scope)
    verify_markdown(root, policy, scope)
    verify_versioned_document_bytes(root)
    if issuance:
        raise ValidationError("issuance blocked: no verified post-subject evidence envelope was supplied, vendor contact is unauthorized, and audit is uncommissioned")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).absolute().parent)
    parser.add_argument("--issuance", action="store_true", help="apply vendor-issuance gate (expected to fail for this candidate)")
    args = parser.parse_args(argv)
    try:
        validate_bundle(args.root, issuance=args.issuance)
    except ValidationError as exc:
        print(f"audit SOW verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"audit SOW verification passed: freeze={FREEZE_ID}, status=candidate-uncommissioned, workstreams={len(WORKSTREAMS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
