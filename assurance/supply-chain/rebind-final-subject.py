#!/usr/bin/env python3
"""Exact Package F topology, projection, and final-candidate authority."""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True

FRAMEWORK = Path(__file__).resolve().parent
REPO = FRAMEWORK.parent.parent

A_E_COMMIT = "86a907154c1f8211a1775c1da8186b71a704536f"
A_E_TREE = "d9bd9b791038fc92c4581468708e9cf39cd6234f"
S_F_COMMIT = "ac91913afee3b91c823a1448e6200de26fdd1c8a"
S_F_TREE = "6952979606c28f739fca1aeb9bb14b1ca042d09d"
R_F_COMMIT = "889cb8c4dc13a78679dc8a7677916484a9966f65"
R_F_TREE = "0d44b68b186913de68844d09b7e498bcda14d109"
R_F_SUBJECT_MANIFEST_SHA256 = (
    "95902d2ff4a2f99808ba5d404fbce3175b787b93fdc1538cb55ad350e69505c7"
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

S_F_PATHS = tuple(sorted((
    ".github/workflows/security-validation.yml",
    "tools/bench-processor/Cargo.lock",
    "tools/bench-processor/Cargo.toml",
    "tools/release-dcrypt.sh",
    "tools/verify-publish-ready.sh",
    "tools/verify-remote-release-ready.py",
)))
R_F_PATHS = tuple(sorted((
    "verification/oracle-provisioning/bundle_lib.py",
    "verification/oracle-provisioning/manifest.json",
    "verification/oracle-provisioning/subject-inputs.json",
)))

F12_RELATIVE_PATHS = (
    "ARTIFACTS.json",
    "README.md",
    "capture.py",
    "fixtures/control.json",
    "generate.py",
    "model.py",
    "package-f.json",
    "rebind-final-subject.py",
    "reviewed-inventory.toml",
    "schema.json",
    "selftest.py",
    "verify.py",
)
F12_PATHS = tuple(sorted(f"assurance/supply-chain/{path}" for path in F12_RELATIVE_PATHS))

# Independent cascade/repair evidence, frozen before the repaired Package F
# fixed point. The two digests bind the canonical sorted path array and
# path->Git-mode object.
OUTSIDE_PATH_LIST_SHA256 = "fe92c8a3980faa877556a7a8ed6c4b62c4df2fd558fccf68c617b08c2121bab3"
OUTSIDE_PATH_MODE_MAP_SHA256 = "7d68b2a27ec32dff57294597a79c2cda4d230e5afb482a40a5eb7d2412c64a5d"
OUTSIDE_CONTENT_BYTES = 78_947_918
OUTSIDE_ROWS_TSV = """\
100644\t128298\t4c713ba7b85a6f27504544b44eba2a899cd6622343be7a15a390ece1432b49ab\tassurance/acvp-vector-manifest.json
100644\t2535\td801038d49170e3916d3dc9e57054b272508ff59837816f3d6e4056975529ddd\tassurance/error-api-v4/ARTIFACTS.json
100644\t50532\t0a52f93cc51e97e34e56a87924d1c28d158d3265b1c5d887fbb27de8c15229dd\tassurance/error-api-v4/model.py
100644\t5148\t110cf0dc0c0993c59cf2b9b53a4985873a0e85914d544022e87caedccf1f8411\tassurance/error-api-v4/package-e.json
100644\t66411\t7b91813b502010d158045655af4fd0f6958ee2aa63b08dd1f6deb39fd05c488d\tassurance/error-api-v4/rebind-final-subject.py
100644\t13031\tb648b5a2f951caff2614bc50b8470d4cb8bc6bb76b385e2f7aaf42d545e83566\tassurance/error-api-v4/schema.json
100644\t6546\ta98ea22604879106a94f7529ffbdcc34e1c981610529e3f25e2cde195fa726a7\tassurance/fuzzing/ARTIFACTS.json
100644\t54842\t234375fd4ed9bf24aa06444c0312678d1988672415e23f447c704ee051a1a965\tassurance/fuzzing/campaign-status.json
100644\t172485\t5cc64302bbfcac55259b4354af5b5f16dec60e0711bf27b7d02583d1331b574c\tassurance/fuzzing/corpus-manifest.json
100644\t118755\t6636d2cd2a53a4500aa3b70338c845268e8547cb6726a5748d270db61cc8d3fd\tassurance/fuzzing/fuzzing_lib.py
100644\t3844\tcf47804939a121888d95781641fea9995e941c7fbf4186713af95058caf26a78\tassurance/fuzzing/policy.json
100644\t83549\tbab2d71a3d63db2bd79f8c93b3a8609e9a705c2d2d1a459376bee4df37b14f5e\tassurance/fuzzing/rebind-final-subject.py
100644\t7422246\t9feedae461b99e46cda1556a0eb13749fb65cfb53c495b77e1130e158835cc79\tassurance/fuzzing/row-mapping.json
100644\t80544\t3f09c3e0d891e3fbe13c41f5fc949d73bca7209ab600a2f6e4d312bcb9eec7c6\tassurance/fuzzing/selftest.py
100644\t5200\taee8ecfaab95d09ef193089b7ce00ce5e6e4077d4414ea0a92169c34d29269fb\tassurance/fuzzing/source-bindings.json
100644\t17147979\t307e3ef67b596ba1ffe06cec0e58629f498d2ca4555458fbb8d6d313524fbadd\tassurance/interoperability/matrix.json
100644\t11722\td05cf0485a30accb94d909d784ee4dc8d99554ac9cc81137e14e2671a7cc4731\tassurance/interoperability/policy.toml
100644\t616\te3d7eaaf985268e82e0f7020f2212fcf6af0eb3e6209c34e8d1712bd7de06925\tassurance/interoperability/protocol-specs/ARTIFACTS.sha256
100644\t17245\t4438f5d21a3231111240ed7bc8af4589733ff7a103511ce76a3eb0d70563fa3f\tassurance/interoperability/protocol-specs/CURRENT-BEHAVIOR.md
100644\t33625\tc504a07379055335d455bc9eb46b0acc9f81172d6eb0d2424e76ea5f9e18540e\tassurance/interoperability/protocol-specs/current-behavior.json
100755\t72305\tc289a5d0c3d8840608a56be5262e497ca8f85f4d0c00bf8bb5fc8471326f286d\tassurance/interoperability/protocol-specs/rebind-final-subject.py
100755\t46723\tf81ab65adc4602a088d701fb14ad4e94dab789de082d6a6e5e02418e170ffcc4\tassurance/interoperability/protocol-specs/verify-protocol-specs.py
100644\t41707\t049d524b5cbea96a18bcf901f95e83fdf1f02093aef0542012e78882aba8d8dd\tassurance/ledger.toml
100644\t37066613\t5fa59a0218c2be98ef653d85da35c616c75b1499cb376f2b12c99eb6813e553d\tassurance/public-api-snapshot.json
100644\t2505\t3db5c2a3b3de8b927184b61dd8c37069933b0ea0e4dc9ff4815e0f695c2f35dc\tassurance/side-channel/ARTIFACTS.json
100644\t58776\t9ab5051a07c760e5072cedfddc05819bb51d733d418d5e0b1fe29c8f02a8b244\tassurance/side-channel/model.py
100644\t7545201\t59e9961813ac4fa0bc3ab186268889073cb89036b967f81619ab5e1f294ee22e\tassurance/side-channel/package-d.json
100644\t45669\t2b8afb09840811b5a3ff8b7a665c4e9a584305c266ec51d623e626c10be175b4\tassurance/side-channel/rebind-final-subject.py
100644\t9062\t62e857cf1b18c03a708d926a123668c87dd5a0880d17c0fa1771fd68c2f61850\tassurance/side-channel/reviewed-inventory.toml
100644\t296233\t95902d2ff4a2f99808ba5d404fbce3175b787b93fdc1538cb55ad350e69505c7\tassurance/subject-manifest.json
100644\t8291936\t253bf52dba0b5cecb149b9c6f5a282d9c3d37f0101ba2ff8a8b1c75794b9daf1\tassurance/threat-models/coverage.json
100644\t1217\t5e52e839db7d456620dd9f0f2d8fd81cfcdbadbe902495038dc6c07510bce48a\tassurance/threat-models/fixtures/mitigation-evidence-record.json
100644\t1101\t4fc2f74ea6361c2b753fe7a9d971ca9e7c7b4ebe766339b648e34ae7d42f6064\tassurance/threat-models/fixtures/review-evidence-record.json
100644\t43717\t16b787d2eb100837b61b54f25f6e5ad96de696b4cd4274f09a3b5e511b41539e\tassurance/threat-models/threat-models.toml
"""


def _outside_rows() -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for line in OUTSIDE_ROWS_TSV.splitlines():
        mode, size, digest, path = line.split("\t")
        rows.append({"git_mode": mode, "path": path, "sha256": digest, "size": int(size)})
    return tuple(rows)


OUTSIDE_ROWS = _outside_rows()
OUTSIDE_PATHS = tuple(row["path"] for row in OUTSIDE_ROWS)
FINAL_PATHS = tuple(sorted((*OUTSIDE_PATHS, *F12_PATHS)))
FINAL_MODES = {
    **{row["path"]: row["git_mode"] for row in OUTSIDE_ROWS},
    **{path: "100644" for path in F12_PATHS},
}
DIRECT_OUTSIDE_PATHS = tuple(sorted((
    "assurance/acvp-vector-manifest.json",
    "assurance/interoperability/matrix.json",
    "assurance/interoperability/policy.toml",
    "assurance/ledger.toml",
    "assurance/public-api-snapshot.json",
    "assurance/subject-manifest.json",
    "assurance/threat-models/coverage.json",
    "assurance/threat-models/fixtures/mitigation-evidence-record.json",
    "assurance/threat-models/fixtures/review-evidence-record.json",
    "assurance/threat-models/threat-models.toml",
)))

# Replaced after all twelve Package F members have reached their reviewed fixed
# point.  Zero is an intentional fail-closed construction sentinel.
FINAL_CHANGED_PATHS_SHA256 = "a0374d9e187e3bb45f2e8309a92ad3ab86711bb11dfdc6f1e7dd810063c263a8"
NORMALIZED_REBIND_SHA256 = "4b57be6450604712236b03f95b3df951be33ac8373d33fc6c0207a626aec73c0"
EXPECTED_REVIEWED_FILES: dict[str, tuple[str, int, str]] = {
    "assurance/supply-chain/README.md": (
        "100644", 4625,
        "311c9256f94e3a6abdbe81b6065fb118381c6a524611ffd1fbf8c27145b85280",
    ),
    "assurance/supply-chain/capture.py": (
        "100644", 61320,
        "235376707674d20a930ff31089fe6b021286c571f97bb165c9cf1fa6657b4d67",
    ),
    "assurance/supply-chain/fixtures/control.json": (
        "100644", 412,
        "1dd84bbd4b630abaa07a180e4fd8e120be18427896e3e070f8b5a794b6326ef3",
    ),
    "assurance/supply-chain/generate.py": (
        "100644", 4009,
        "49aa9119d6fc6891f190a1e7a2852514a5ac669db863134fed011f7ca61ebf1e",
    ),
    "assurance/supply-chain/model.py": (
        "100644", 75898,
        "c0d839f8844b1db3c6773587d54d9a6833a0dfa2085bcb0fff56eab6ea776f5c",
    ),
    "assurance/supply-chain/reviewed-inventory.toml": (
        "100644", 15753,
        "6786b8d5e312ab6ebe736db57289dfb552bae6b956fedec81a78232eaf7b77ca",
    ),
    "assurance/supply-chain/selftest.py": (
        "100644", 57892,
        "bdc2cc65a5a74296edae21d99e0c174b45abd88992a860226a309ba78212f48f",
    ),
    "assurance/supply-chain/verify.py": (
        "100644", 6238,
        "26b739de3ecabbe285384090b4f8d14bcac814e51c1e6daf06876275af1a16fe",
    ),
}

PROVIDER_MODES = {
    "assurance/fuzzing/rebind-final-subject.py": "--package-f-projection",
    "assurance/side-channel/rebind-final-subject.py": "--package-f-projection",
    "assurance/error-api-v4/rebind-final-subject.py": "--package-f-projection",
    "assurance/interoperability/protocol-specs/rebind-final-subject.py":
        "--package-f-projection",
}
EXPECTED_PROVIDER_FILES: dict[str, tuple[str, int, str]] = {
    "assurance/error-api-v4/rebind-final-subject.py": (
        "100644", 66411,
        "7b91813b502010d158045655af4fd0f6958ee2aa63b08dd1f6deb39fd05c488d",
    ),
    "assurance/fuzzing/rebind-final-subject.py": (
        "100644", 83549,
        "bab2d71a3d63db2bd79f8c93b3a8609e9a705c2d2d1a459376bee4df37b14f5e",
    ),
    "assurance/interoperability/protocol-specs/rebind-final-subject.py": (
        "100755", 72305,
        "c289a5d0c3d8840608a56be5262e497ca8f85f4d0c00bf8bb5fc8471326f286d",
    ),
    "assurance/side-channel/rebind-final-subject.py": (
        "100644", 45669,
        "2b8afb09840811b5a3ff8b7a665c4e9a584305c266ec51d623e626c10be175b4",
    ),
}


def _mode_map(paths: tuple[str, ...], executable: tuple[str, ...] = ()) -> dict[str, str]:
    executable_set = set(executable)
    return {path: "100755" if path in executable_set else "100644" for path in paths}


PROJECTION_CONTRACTS: dict[str, dict[str, Any]] = {
    "assurance/fuzzing/rebind-final-subject.py": {
        "policy": "dcrypt-package-c-package-f-subordinate-projection-v1",
        "counts": {
            "critical_family_rows": 372, "curated_rows": 566,
            "explicit_blocker_rows": 8826, "total_atomic_rows": 9198,
            "unreviewed_gap_rows": 8632,
        },
        "bindings": {
            "atomic_operations_sha256": "8e745ab16086aa50e265ad79189375270c5906df8545f540d96426bc348ca11a",
            "control_inputs_sha256": "e37be66d9bdd6c90b571f4a690247b641fd2e6fe835d7804e462d2f81c5a19c1",
            "policy_semantic_sha256": "cf47804939a121888d95781641fea9995e941c7fbf4186713af95058caf26a78",
            "public_api_snapshot_sha256": "5fa59a0218c2be98ef653d85da35c616c75b1499cb376f2b12c99eb6813e553d",
            "registry_semantic_sha256": "f9182aa95ff3e7d4db93f15c04a17f593273453d069df496dd2dd4bdeef1772b",
            "subject_commit": R_F_COMMIT,
            "subject_manifest_sha256": R_F_SUBJECT_MANIFEST_SHA256,
            "subject_tree": R_F_TREE,
        },
        "changed": _mode_map(tuple(sorted((
            "assurance/fuzzing/ARTIFACTS.json",
            "assurance/fuzzing/campaign-status.json",
            "assurance/fuzzing/corpus-manifest.json",
            "assurance/fuzzing/fuzzing_lib.py",
            "assurance/fuzzing/policy.json",
            "assurance/fuzzing/rebind-final-subject.py",
            "assurance/fuzzing/row-mapping.json",
            "assurance/fuzzing/selftest.py",
            "assurance/fuzzing/source-bindings.json",
        )))),
        "invariant": _mode_map(tuple(sorted((
            "assurance/fuzzing/README.md", "assurance/fuzzing/ROW-COVERAGE.md",
            "assurance/fuzzing/compiler_probe.py", "assurance/fuzzing/crash-bundle-template.json",
            "assurance/fuzzing/crash-lifecycle-status.json", "assurance/fuzzing/crash_lifecycle.py",
            "assurance/fuzzing/generate.py", "assurance/fuzzing/local-sanitizer-requirements.json",
            "assurance/fuzzing/run-fuzz-smoke.py", "assurance/fuzzing/sanitizer-controls.json",
            "assurance/fuzzing/sanitizer_positive.py", "assurance/fuzzing/schemas.py",
            "assurance/fuzzing/schemas/artifacts.schema.json",
            "assurance/fuzzing/schemas/campaign-status.schema.json",
            "assurance/fuzzing/schemas/corpus-manifest.schema.json",
            "assurance/fuzzing/schemas/crash-bundle-template.schema.json",
            "assurance/fuzzing/schemas/crash-lifecycle-status.schema.json",
            "assurance/fuzzing/schemas/local-sanitizer-requirements.schema.json",
            "assurance/fuzzing/schemas/policy.schema.json",
            "assurance/fuzzing/schemas/row-mapping.schema.json",
            "assurance/fuzzing/schemas/sanitizer-controls.schema.json",
            "assurance/fuzzing/schemas/source-bindings.schema.json",
            "assurance/fuzzing/schemas/target-registry.schema.json",
            "assurance/fuzzing/select-fuzz-targets.py",
            "assurance/fuzzing/target-registry.json", "assurance/fuzzing/verify.py",
        )))),
    },
    "assurance/side-channel/rebind-final-subject.py": {
        "policy": "dcrypt-package-d-package-f-subordinate-projection-v1",
        "counts": {
            "curated_rows": 566, "production_rust_sources": 255,
            "public_api_units": 18891, "release_blocked_rows": 9198,
            "total_atomic_rows": 9198, "unreviewed_gap_rows": 8632,
        },
        "bindings": {
            "atomic_operations_sha256": "8e745ab16086aa50e265ad79189375270c5906df8545f540d96426bc348ca11a",
            "atomic_row_ids_sha256": "ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff",
            "production_source_paths_sha256": "5aae5258561c750a920b36be67c2652f28ea1c8536ad7527f73967633a62b804",
            "production_source_roots_sha256": "3bdf8ea3f968c18983d73ef3d4523e915e4b1c3fa4f7d8949e73d07b97ec298f",
            "production_source_rows_sha256": "e35cb1924e6f4480a557651db3fdebec3b9d1518d42160a8e7895c000f21f2f5",
            "public_api_snapshot_sha256": "5fa59a0218c2be98ef653d85da35c616c75b1499cb376f2b12c99eb6813e553d",
            "subject_commit": R_F_COMMIT,
            "subject_manifest_sha256": R_F_SUBJECT_MANIFEST_SHA256,
            "subject_tree": R_F_TREE,
        },
        "changed": _mode_map(tuple(sorted((
            "assurance/side-channel/ARTIFACTS.json", "assurance/side-channel/model.py",
            "assurance/side-channel/package-d.json", "assurance/side-channel/rebind-final-subject.py",
            "assurance/side-channel/reviewed-inventory.toml",
        )))),
        "invariant": _mode_map(tuple(sorted((
            "assurance/side-channel/README.md", "assurance/side-channel/capture.py",
            "assurance/side-channel/fixtures/control.rs", "assurance/side-channel/generate.py",
            "assurance/side-channel/schema.json", "assurance/side-channel/selftest.py",
            "assurance/side-channel/verify.py",
        )))),
    },
    "assurance/error-api-v4/rebind-final-subject.py": {
        "policy": "dcrypt-package-e-package-f-subordinate-projection-v1",
        "counts": {
            "curated_source_rows": 283, "expanded_curated_atomic_rows": 566,
            "production_rust_sources": 255, "public_identities": 18891,
            "release_blocked_rows": 9198,
            "retained_other_transitional_public_identities": 124,
            "unreviewed_gap_rows": 8632,
        },
        "bindings": {
            "atomic_operations_sha256": "8e745ab16086aa50e265ad79189375270c5906df8545f540d96426bc348ca11a",
            "curated_operations_sha256": "082cc81db8f9fcd9222b195af43208040811ae5f2e5e4565c249fecf6e10dcc8",
            "public_api_snapshot_sha256": "5fa59a0218c2be98ef653d85da35c616c75b1499cb376f2b12c99eb6813e553d",
            "reviewed_inventory_sha256": "5d2ae3900fd3517f3fb6b36d2c4fb7970e984bc8a27e919a7b99562ff601b071",
            "subject_commit": R_F_COMMIT,
            "subject_manifest_sha256": R_F_SUBJECT_MANIFEST_SHA256,
            "subject_tree": R_F_TREE,
        },
        "changed": _mode_map(tuple(sorted((
            "assurance/error-api-v4/ARTIFACTS.json", "assurance/error-api-v4/model.py",
            "assurance/error-api-v4/package-e.json", "assurance/error-api-v4/rebind-final-subject.py",
            "assurance/error-api-v4/schema.json",
        )))),
        "invariant": _mode_map(tuple(sorted((
            "assurance/error-api-v4/README.md", "assurance/error-api-v4/capture.py",
            "assurance/error-api-v4/fixtures/control.json", "assurance/error-api-v4/generate.py",
            "assurance/error-api-v4/reviewed-inventory.toml", "assurance/error-api-v4/selftest.py",
            "assurance/error-api-v4/verify.py",
        )))),
    },
    "assurance/interoperability/protocol-specs/rebind-final-subject.py": {
        "policy": "dcrypt-protocol-specs-package-f-subordinate-projection-v1",
        "counts": {"changed_files": 5, "invariant_files": 3, "protocol_files": 8, "subject_files": 1511},
        "bindings": {
            "curated_operations_sha256": "082cc81db8f9fcd9222b195af43208040811ae5f2e5e4565c249fecf6e10dcc8",
            "semantic_registry_sha256": "37b0ecf19b57cf4c526af6bcfbbbf51a3f6bfe034dd19e50a0040fd8742c8eff",
            "subject_manifest_sha256": R_F_SUBJECT_MANIFEST_SHA256,
        },
        "changed": _mode_map(
            tuple(sorted((
                "assurance/interoperability/protocol-specs/ARTIFACTS.sha256",
                "assurance/interoperability/protocol-specs/CURRENT-BEHAVIOR.md",
                "assurance/interoperability/protocol-specs/current-behavior.json",
                "assurance/interoperability/protocol-specs/rebind-final-subject.py",
                "assurance/interoperability/protocol-specs/verify-protocol-specs.py",
            ))),
            (
                "assurance/interoperability/protocol-specs/rebind-final-subject.py",
                "assurance/interoperability/protocol-specs/verify-protocol-specs.py",
            ),
        ),
        "invariant": _mode_map(
            tuple(sorted((
                "assurance/interoperability/protocol-specs/README.md",
                "assurance/interoperability/protocol-specs/protocol-spec.schema.json",
                "assurance/interoperability/protocol-specs/protocol-specs-selftest.py",
            ))),
            ("assurance/interoperability/protocol-specs/protocol-specs-selftest.py",),
        ),
    },
}

PROTECTED_GITIGNORE = ".gitignore"
PROTECTED_GITIGNORE_WORKTREE_SHA256 = (
    "e4887e3f444e25b7baad39bd6ff3da3ae770f8dc5b3f7cf2c87a117219a8fe2c"
)
PROTECTED_GITIGNORE_DIFF_SHA256 = (
    "caa005fda38ed3a65d8b92a5b788169ebba47e7106c1389bf4cd7bff980c6552"
)
PROTECTED_GITIGNORE_COMMITTED_SHA256 = (
    "f34512e77a7cf5fdfd465243dbb286d8e16bfd698cad264bdb1360f008915f26"
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_float(_value: str) -> float:
    raise ValueError("JSON floats are forbidden")


def _reject_constant(_value: str) -> None:
    raise ValueError("nonfinite JSON values are forbidden")


def _assert_nfc(value: Any, *, label: str) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise RebindError(f"{label} contains a non-NFC string")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_nfc(item, label=f"{label}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _assert_nfc(key, label=f"{label} key")
            _assert_nfc(item, label=f"{label}.{key}")


def _parse_json_strict(raw: bytes, *, label: str) -> Any:
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_float=_reject_float, parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RebindError(f"{label} is not strict JSON") from error
    _assert_nfc(value, label=label)
    return value


def _same_json_value(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _same_json_value(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same_json_value(a, b) for a, b in zip(left, right, strict=True)
        )
    return bool(left == right)


class RebindError(RuntimeError):
    """Package F topology, trust, projection, or transaction differs."""


@dataclass(frozen=True)
class Snapshot:
    path: Path
    raw: bytes
    mode: int
    identity: tuple[int, ...]


def _git(arguments: list[str], *, binary: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", *arguments], cwd=REPO, capture_output=True,
        text=not binary, timeout=120,
        env={
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0",
            "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin", "TZ": "UTC",
        },
    )


def _resolve(revision: str, suffix: str = "commit") -> str:
    result = _git(["rev-parse", "--verify", f"{revision}^{{{suffix}}}"])
    if result.returncode != 0 or HEX40.fullmatch(result.stdout.strip()) is None:
        raise RebindError(f"cannot resolve exact Git {suffix}: {revision}")
    return result.stdout.strip()


def _parents(revision: str) -> list[str]:
    result = _git(["show", "-s", "--format=%P", revision])
    if result.returncode != 0:
        raise RebindError("cannot inspect Git parents")
    return result.stdout.strip().split() if result.stdout.strip() else []


def _decode_paths(raw: bytes, *, label: str) -> list[str]:
    try:
        paths = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    except UnicodeError as error:
        raise RebindError(f"{label} contains a non-UTF-8 path") from error
    if len(paths) != len(set(paths)) or any(
        not path or path.startswith("/") or "//" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        for path in paths
    ):
        raise RebindError(f"{label} is not a canonical unique path list")
    return sorted(paths)


def _diff_paths(parent: str, child: str) -> list[str]:
    result = _git([
        "diff-tree", "--no-commit-id", "--name-only", "--no-renames",
        "-r", "-z", parent, child,
    ], binary=True)
    if result.returncode != 0:
        raise RebindError("cannot inspect exact Git path delta")
    return _decode_paths(result.stdout, label="Git path delta")


def verify_base_topology() -> None:
    if (
        _resolve(A_E_COMMIT, "tree") != A_E_TREE
        or _resolve(S_F_COMMIT, "tree") != S_F_TREE
        or _resolve(R_F_COMMIT, "tree") != R_F_TREE
        or _parents(S_F_COMMIT) != [A_E_COMMIT]
        or _parents(R_F_COMMIT) != [S_F_COMMIT]
        or _diff_paths(A_E_COMMIT, S_F_COMMIT) != list(S_F_PATHS)
        or _diff_paths(S_F_COMMIT, R_F_COMMIT) != list(R_F_PATHS)
    ):
        raise RebindError("A_E -> S_F -> R_F topology/path closure differs")


def validate_literal_tables() -> None:
    outside_paths = sorted(OUTSIDE_PATHS)
    outside_modes = {path: FINAL_MODES[path] for path in outside_paths}
    provider_changed = set().union(*(
        set(contract["changed"]) for contract in PROJECTION_CONTRACTS.values()
    ))
    if (
        len(OUTSIDE_ROWS) != 34 or len(set(OUTSIDE_PATHS)) != 34
        or tuple(OUTSIDE_PATHS) != tuple(sorted(OUTSIDE_PATHS))
        or sum(row["size"] for row in OUTSIDE_ROWS) != OUTSIDE_CONTENT_BYTES
        or _sha(_canonical(outside_paths)) != OUTSIDE_PATH_LIST_SHA256
        or _sha(_canonical(outside_modes)) != OUTSIDE_PATH_MODE_MAP_SHA256
        or len(F12_PATHS) != 12 or len(FINAL_PATHS) != 46
        or len(set(FINAL_PATHS)) != 46
        or any(row["git_mode"] not in {"100644", "100755"} for row in OUTSIDE_ROWS)
        or any(HEX64.fullmatch(row["sha256"]) is None for row in OUTSIDE_ROWS)
        or set(PROVIDER_MODES) != set(PROJECTION_CONTRACTS)
        or len(provider_changed) != 24
        or provider_changed != set(OUTSIDE_PATHS) - set(DIRECT_OUTSIDE_PATHS)
        or any(
            set(contract) != {"policy", "counts", "bindings", "changed", "invariant"}
            or set(contract["changed"]) & set(contract["invariant"])
            or not contract["counts"] or not contract["bindings"]
            for contract in PROJECTION_CONTRACTS.values()
        )
    ):
        raise RebindError("Package F exact 34+12 literal table differs")


def _normalized_rebind_sha256(raw: bytes) -> str:
    normalized, count = re.subn(
        rb'^NORMALIZED_REBIND_SHA256 = "(?:[0-9a-f]{64}|0" \* 64)"$',
        b'NORMALIZED_REBIND_SHA256 = "<normalized-self>"',
        raw,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        # Construction sentinel has Python expression syntax rather than a quoted digest.
        normalized, count = re.subn(
            rb'^NORMALIZED_REBIND_SHA256 = "0" \* 64$',
            b'NORMALIZED_REBIND_SHA256 = "<normalized-self>"',
            raw,
            count=1,
            flags=re.MULTILINE,
        )
    if count != 1:
        raise RebindError("normalized self-anchor assignment differs")
    return _sha(normalized)


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
        metadata.st_mode, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _read_state(path: Path) -> tuple[bytes, int, tuple[int, ...]]:
    try:
        before = path.lstat()
    except OSError as error:
        raise RebindError(f"cannot stat candidate path: {path}") from error
    mode = stat.S_IMODE(before.st_mode)
    if (
        not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1 or before.st_mode & 0o7000 or mode & 0o002
        or before.st_size < 0
    ):
        raise RebindError(f"candidate path type/mode/link policy differs: {path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        expected = _identity(before)
        if _identity(opened) != expected:
            raise RebindError(f"candidate path changed before descriptor read: {path}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                raise RebindError(f"candidate path truncated during read: {path}")
            chunks.append(chunk); remaining -= len(chunk)
        if os.read(descriptor, 1) != b"":
            raise RebindError(f"candidate path grew during read: {path}")
        after = os.fstat(descriptor)
        if _identity(after) != expected:
            raise RebindError(f"candidate path changed during descriptor read: {path}")
        return b"".join(chunks), mode, expected
    finally:
        os.close(descriptor)


def _read(path: Path) -> tuple[bytes, int]:
    raw, mode, _state = _read_state(path)
    return raw, mode


def _git_mode_from_filesystem(mode: int) -> str:
    if mode & 0o7000 or mode & 0o002:
        raise RebindError("filesystem mode has unsafe special/world-write bits")
    return "100755" if mode & 0o111 else "100644"


def _git_blob(revision: str, path: str) -> tuple[str, bytes]:
    result = _git(["ls-tree", "-z", "--full-tree", revision, "--", path], binary=True)
    records = [row for row in result.stdout.split(b"\0") if row] if result.returncode == 0 else []
    if len(records) != 1:
        raise RebindError(f"required committed path differs: {path}")
    metadata, encoded = records[0].split(b"\t", 1)
    mode, kind, object_id = metadata.decode("ascii").split(" ")
    if encoded.decode("utf-8") != path or kind != "blob" or mode not in {"100644", "100755"}:
        raise RebindError(f"committed path type/mode differs: {path}")
    blob = _git(["cat-file", "blob", object_id], binary=True)
    if blob.returncode != 0:
        raise RebindError(f"cannot read committed blob: {path}")
    return mode, blob.stdout


def _path_bytes(path: str, revision: str | None, expected_mode: str) -> bytes:
    if revision is None:
        raw, filesystem_mode = _read(REPO / path)
        mode = _git_mode_from_filesystem(filesystem_mode)
    else:
        mode, raw = _git_blob(revision, path)
    if mode != expected_mode:
        raise RebindError(f"candidate Git mode differs: {path}")
    return raw


def _validate_file_anchor(
    path: str, mode: str, raw: bytes, expected: tuple[str, int, str]
) -> None:
    if (mode, len(raw), _sha(raw)) != expected:
        raise RebindError(f"reviewed/provider trust anchor differs: {path}")


def verify_reviewed_anchors(revision: str | None = None) -> None:
    if len(EXPECTED_REVIEWED_FILES) != 8 or len(EXPECTED_PROVIDER_FILES) != 4:
        raise RebindError("reviewed/provider trust-anchor closure is not frozen")
    for path, expected in {**EXPECTED_REVIEWED_FILES, **EXPECTED_PROVIDER_FILES}.items():
        if revision is None:
            raw, filesystem_mode = _read(REPO / path)
            mode = _git_mode_from_filesystem(filesystem_mode)
        else:
            mode, raw = _git_blob(revision, path)
        _validate_file_anchor(path, mode, raw, expected)
    if revision is None:
        self_raw, self_mode = _read(Path(__file__))
        if _git_mode_from_filesystem(self_mode) != "100644":
            raise RebindError("Package F rebind source mode differs")
    else:
        self_mode, self_raw = _git_blob(revision, "assurance/supply-chain/rebind-final-subject.py")
        if self_mode != "100644":
            raise RebindError("Package F committed rebind source mode differs")
    if NORMALIZED_REBIND_SHA256 == "0" * 64 or _normalized_rebind_sha256(self_raw) != NORMALIZED_REBIND_SHA256:
        raise RebindError("normalized Package F rebind self anchor differs")


def parse_projection(
    raw: bytes, *, provider: str, candidate_commit: str | None
) -> dict[str, Any]:
    contract = PROJECTION_CONTRACTS.get(provider)
    if contract is None:
        raise RebindError(f"unknown Package F projection provider: {provider}")
    document = _parse_json_strict(raw, label=f"projection {provider}")
    if not isinstance(document, dict):
        raise RebindError(f"projection root is not an object: {provider}")
    if raw != _canonical(document):
        raise RebindError(f"projection is not canonical: {provider}")
    keys = {
        "binding_assignments", "candidate_commit", "changed_files", "content_policy",
        "counts", "invariant_files", "projection_sha256", "r_commit", "r_tree",
        "schema_version", "subject_manifest_sha256",
    }
    body = {key: value for key, value in document.items() if key != "projection_sha256"}
    changed = document.get("changed_files")
    invariant = document.get("invariant_files")
    rows = [
        *(changed if isinstance(changed, list) else []),
        *(invariant if isinstance(invariant, list) else []),
    ]
    def valid_row(row: Any) -> bool:
        return (
            isinstance(row, dict)
            and set(row) == {"git_mode", "path", "sha256", "size"}
            and isinstance(row.get("path"), str)
            and isinstance(row.get("git_mode"), str)
            and row["git_mode"] in {"100644", "100755"}
            and isinstance(row.get("sha256"), str)
            and HEX64.fullmatch(row["sha256"]) is not None
            and isinstance(row.get("size"), int)
            and not isinstance(row["size"], bool)
            and row["size"] >= 0
        )
    row_shapes_valid = (
        isinstance(changed, list) and isinstance(invariant, list)
        and all(valid_row(row) for row in rows)
    )
    if (
        set(document) != keys
        or not _same_json_value(document.get("schema_version"), 1)
        or document.get("content_policy") != contract["policy"]
        or document.get("r_commit") != R_F_COMMIT or document.get("r_tree") != R_F_TREE
        or document.get("candidate_commit") != candidate_commit
        or document.get("subject_manifest_sha256") != R_F_SUBJECT_MANIFEST_SHA256
        or not _same_json_value(document.get("counts"), contract["counts"])
        or not _same_json_value(document.get("binding_assignments"), contract["bindings"])
        or document.get("projection_sha256") != _sha(_canonical(body))
        or not row_shapes_valid
    ):
        raise RebindError(f"projection schema/policy/binding differs: {provider}")
    assert isinstance(changed, list) and isinstance(invariant, list)
    if (
        [row["path"] for row in changed] != sorted(contract["changed"])
        or [row.get("path") for row in invariant] != sorted(contract["invariant"])
        or len({row.get("path") for row in rows}) != len(rows)
        or any(row["git_mode"] != contract["changed"][row["path"]] for row in changed)
        or any(row["git_mode"] != contract["invariant"][row["path"]] for row in invariant)
    ):
        raise RebindError(f"projection schema/policy/binding differs: {provider}")
    return document


def verify_projection_rows(
    document: dict[str, Any], *, provider: str, candidate_commit: str | None
) -> None:
    contract = PROJECTION_CONTRACTS[provider]
    for category, changed in (("changed_files", True), ("invariant_files", False)):
        modes = contract["changed" if changed else "invariant"]
        for row in document[category]:
            path = row["path"]
            raw = _path_bytes(path, candidate_commit, modes[path])
            base_mode, base_raw = _git_blob(R_F_COMMIT, path)
            if (
                base_mode != modes[path]
                or row != {
                    "git_mode": modes[path], "path": path,
                    "sha256": _sha(raw), "size": len(raw),
                }
                or (changed and raw == base_raw)
                or (not changed and raw != base_raw)
            ):
                raise RebindError(f"projection row bytes/change classification differs: {path}")


def _projection(provider: str, candidate_commit: str | None) -> dict[str, Any]:
    arguments = [
        sys.executable, "-B", provider, PROVIDER_MODES[provider],
        "--expected-r-commit", R_F_COMMIT, "--expected-r-tree", R_F_TREE,
    ]
    if candidate_commit is not None:
        arguments.extend(["--candidate-commit", candidate_commit])
    result = subprocess.run(
        arguments, cwd=REPO, capture_output=True, timeout=300,
        env={
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0",
            "HOME": os.environ.get("HOME", ""), "LANG": "C", "LC_ALL": "C",
            "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "TZ": "UTC",
        },
    )
    if result.returncode != 0 or result.stderr:
        raise RebindError(f"projection provider failed closed: {provider}")
    document = parse_projection(result.stdout, provider=provider, candidate_commit=candidate_commit)
    verify_projection_rows(document, provider=provider, candidate_commit=candidate_commit)
    return document


def _atomic_restore(snapshot: Snapshot) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{snapshot.path.name}.rollback-", dir=snapshot.path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(snapshot.raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, snapshot.mode)
        os.replace(temporary, snapshot.path)
        parent_fd = os.open(snapshot.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def transactional_call(
    paths: list[Path],
    function: Callable[[Callable[[Path], None]], Any],
) -> Any:
    """Restore only callback-marked mutations which have not drifted since mark."""
    if len(paths) != len(set(paths)) or not paths:
        raise RebindError("transaction destination closure differs")
    snapshots = [Snapshot(path, raw, mode, identity) for path in paths for raw, mode, identity in [_read_state(path)]]
    locks: list[int] = []
    owned_after: dict[Path, tuple[bytes, int, tuple[int, ...]]] = {}
    try:
        for snapshot in snapshots:
            descriptor = os.open(snapshot.path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            locks.append(descriptor)
            if _identity(os.fstat(descriptor)) != snapshot.identity:
                raise RebindError("transaction input drifted before action")

        def mark_owned(path: Path) -> None:
            if path not in {snapshot.path for snapshot in snapshots}:
                raise RebindError("transaction attempted to mark an undeclared destination")
            owned_after[path] = _read_state(path)

        return function(mark_owned)
    except BaseException:
        failures: list[str] = []
        for snapshot in reversed(snapshots):
            owned = owned_after.get(snapshot.path)
            try:
                current = _read_state(snapshot.path)
            except BaseException as error:
                failures.append(type(error).__name__)
                continue
            if owned is None:
                if current != (snapshot.raw, snapshot.mode, snapshot.identity):
                    failures.append("unmarked-mutation-preserved")
                continue
            if current != owned:
                failures.append("concurrent-drift-preserved")
                continue
            try:
                _atomic_restore(snapshot)
            except BaseException as error:
                failures.append(type(error).__name__)
        for snapshot in snapshots:
            if snapshot.path in owned_after and not any(
                item in failures for item in ("concurrent-drift-preserved", "unmarked-mutation-preserved")
            ):
                try:
                    raw, mode, _identity_value = _read_state(snapshot.path)
                    if raw != snapshot.raw or mode != snapshot.mode:
                        failures.append("verification")
                except BaseException as error:
                    failures.append(type(error).__name__)
        if failures:
            raise RebindError(f"rollback failed closed without overwriting drift: {failures}")
        raise
    finally:
        for descriptor in reversed(locks):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


VALIDATION_GRAPH: tuple[tuple[tuple[str, ...], int, str | None], ...] = (
    (("assurance/supply-chain/generate.py", "--check"), 0, None),
    (("assurance/supply-chain/verify.py", "--ci"), 0, None),
    (("assurance/supply-chain/selftest.py",), 0, None),
    (("assurance/supply-chain/verify.py", "--release"), 3, "operational SBOM"),
    (("assurance/error-api-v4/generate.py", "--check"), 0, None),
    (("assurance/error-api-v4/verify.py", "--ci"), 0, None),
    (("assurance/error-api-v4/selftest.py",), 0, None),
    (("assurance/error-api-v4/verify.py", "--release"), 3, "v4 version preparation"),
    (("assurance/generate-assurance-ledger.py", "--check"), 0, None),
    (("assurance/verify-assurance-ledger.py", "--mode", "ci", "--snapshot-only"), 0, None),
    (("assurance/interoperability/generate-interoperability-matrix.py", "--check"), 0, None),
    (("assurance/interoperability/verify-interoperability.py", "--mode", "ci"), 0, None),
    (("assurance/interoperability/interoperability-selftest.py",), 0, None),
    (("assurance/interoperability/verify-interoperability.py", "--mode", "release"), 3, "total=14816"),
    (("assurance/threat-models/generate-threat-models.py", "--check"), 0, None),
    (("assurance/threat-models/verify-threat-models.py", "--mode", "ci"), 0, None),
    (("assurance/threat-models/threat-model-selftest.py",), 0, None),
    (("assurance/threat-models/verify-threat-models.py", "--mode", "release"), 1, "release-blocking high residual risk"),
    (("assurance/fuzzing/generate.py", "--check"), 0, None),
    (("assurance/fuzzing/verify.py", "--ci"), 0, None),
    (("assurance/fuzzing/selftest.py",), 0, None),
    (("assurance/fuzzing/verify.py", "--release"), 3, '"release_gate": "HOLD"'),
    (("assurance/side-channel/generate.py", "--check"), 0, None),
    (("assurance/side-channel/verify.py", "--ci"), 0, None),
    (("assurance/side-channel/selftest.py",), 0, None),
    (("assurance/side-channel/verify.py", "--release"), 3, "all 9,198 rows remain blocked"),
    (("assurance/interoperability/protocol-specs/verify-protocol-specs.py", "--require-final-subject", "--check-current-subject"), 0, None),
    (("assurance/interoperability/protocol-specs/protocol-specs-selftest.py",), 0, None),
)


def run_validation_graph() -> None:
    for arguments, expected_rc, fragment in VALIDATION_GRAPH:
        result = subprocess.run(
            [sys.executable, "-B", *arguments], cwd=REPO, capture_output=True,
            timeout=900,
            env={
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0",
                "HOME": os.environ.get("HOME", ""), "LANG": "C", "LC_ALL": "C",
                "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "TZ": "UTC",
            },
        )
        combined = result.stdout + result.stderr
        if result.returncode != expected_rc or (
            fragment is not None and fragment.encode("utf-8") not in combined
        ):
            raise RebindError(
                f"Package F validation graph failed: {list(arguments)} "
                f"rc={result.returncode} expected={expected_rc}"
            )
    if any(path.name == "__pycache__" for path in REPO.joinpath("assurance").rglob("__pycache__")):
        raise RebindError("validation graph left forbidden bytecode cache residue")


def _staged_paths() -> list[str]:
    result = _git(["diff", "--cached", "--name-only", "-z", "--", "."], binary=True)
    if result.returncode != 0:
        raise RebindError("cannot inspect staged path closure")
    return _decode_paths(result.stdout, label="staged path closure")


def _worktree_paths() -> list[str]:
    tracked = _git(["diff", "--name-only", "-z", "HEAD", "--", "."], binary=True)
    untracked = _git(["ls-files", "--others", "--exclude-standard", "-z", "--", "."], binary=True)
    ignored = _git(["ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", "assurance"], binary=True)
    if tracked.returncode != 0 or untracked.returncode != 0 or ignored.returncode != 0:
        raise RebindError("cannot inspect worktree path closure")
    paths = [
        *_decode_paths(tracked.stdout, label="tracked worktree paths"),
        *_decode_paths(untracked.stdout, label="untracked worktree paths"),
        *_decode_paths(ignored.stdout, label="ignored assurance paths"),
    ]
    if len(paths) != len(set(paths)):
        raise RebindError("worktree path classes overlap")
    return sorted(path for path in paths if path != PROTECTED_GITIGNORE)


def validate_changed_paths(paths: list[str]) -> None:
    if (
        FINAL_CHANGED_PATHS_SHA256 == "0" * 64
        or _sha(_canonical(list(FINAL_PATHS))) != FINAL_CHANGED_PATHS_SHA256
    ):
        raise RebindError("Package F literal F46 path freeze is not finalized")
    if paths != list(FINAL_PATHS):
        raise RebindError(
            "Package F F46 path closure differs: "
            f"missing={sorted(set(FINAL_PATHS) - set(paths))} "
            f"surplus={sorted(set(paths) - set(FINAL_PATHS))}"
        )


def classify_gitignore(
    *, committed_mode: str, committed: bytes, current: bytes,
    difference: bytes, staged_paths: list[str],
) -> tuple[str, str]:
    if committed_mode != "100644" or PROTECTED_GITIGNORE in staged_paths:
        raise RebindError("protected .gitignore mode/index state differs")
    if current == committed and difference == b"" and _sha(current) == PROTECTED_GITIGNORE_COMMITTED_SHA256:
        return "clean-replay", _sha(current)
    if (
        _sha(committed) == PROTECTED_GITIGNORE_COMMITTED_SHA256
        and _sha(current) == PROTECTED_GITIGNORE_WORKTREE_SHA256
        and _sha(difference) == PROTECTED_GITIGNORE_DIFF_SHA256
    ):
        return "protected-dirty-shared-workspace", _sha(current)
    raise RebindError("protected .gitignore bytes/diff differ")


def _gitignore_variant(revision: str) -> tuple[str, str]:
    committed_mode, committed = _git_blob(revision, PROTECTED_GITIGNORE)
    current, current_mode = _read(REPO / PROTECTED_GITIGNORE)
    if _git_mode_from_filesystem(current_mode) != "100644":
        raise RebindError("protected .gitignore filesystem mode differs")
    difference = _git(["diff", "--binary", revision, "--", PROTECTED_GITIGNORE], binary=True)
    if difference.returncode != 0:
        raise RebindError("cannot inspect protected .gitignore difference")
    return classify_gitignore(
        committed_mode=committed_mode, committed=committed, current=current,
        difference=difference.stdout, staged_paths=_staged_paths(),
    )


def _candidate_rows(revision: str | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    outside = {row["path"]: row for row in OUTSIDE_ROWS}
    for path in FINAL_PATHS:
        mode = FINAL_MODES[path]
        raw = _path_bytes(path, revision, mode)
        row = {"git_mode": mode, "path": path, "sha256": _sha(raw), "size": len(raw)}
        if path in outside and row != outside[path]:
            raise RebindError(f"frozen outside-F12 row differs: {path}")
        rows.append(row)
    return rows


def _manifest(
    rows: list[dict[str, Any]], *, candidate_commit: str | None,
    gitignore_variant: str, gitignore_sha256: str,
    projections: list[dict[str, Any]],
) -> dict[str, Any]:
    body = {
        "candidate_commit": candidate_commit,
        "changed_paths": list(FINAL_PATHS),
        "content_policy": "dcrypt-package-f-exact-global-candidate-v1",
        "files": rows,
        "projection_sha256": sorted(row["projection_sha256"] for row in projections),
        "protected_gitignore_sha256": gitignore_sha256,
        "r_commit": R_F_COMMIT, "r_tree": R_F_TREE,
        "schema_version": 1,
        "subject_manifest_sha256": R_F_SUBJECT_MANIFEST_SHA256,
        "worktree_variant": gitignore_variant,
    }
    return {**body, "candidate_manifest_sha256": _sha(_canonical(body))}


def pre_commit_manifest() -> dict[str, Any]:
    verify_base_topology()
    if _resolve("HEAD") != R_F_COMMIT or _staged_paths():
        raise RebindError("pre-A_F requires exact R_F HEAD and empty index")
    verify_reviewed_anchors()
    paths = _worktree_paths(); validate_changed_paths(paths)
    variant = _gitignore_variant(R_F_COMMIT)
    first_rows = _candidate_rows(None)
    run_validation_graph()
    projections = [_projection(provider, None) for provider in sorted(PROVIDER_MODES)]
    verify_reviewed_anchors()
    if (
        _resolve("HEAD") != R_F_COMMIT or _staged_paths()
        or _worktree_paths() != paths or _gitignore_variant(R_F_COMMIT) != variant
        or _candidate_rows(None) != first_rows
    ):
        raise RebindError("pre-A_F candidate changed during anchored validation")
    return _manifest(
        first_rows, candidate_commit=None, gitignore_variant=variant[0],
        gitignore_sha256=variant[1], projections=projections,
    )


def post_commit_manifest(candidate_commit: str) -> dict[str, Any]:
    verify_base_topology()
    if (
        _resolve(candidate_commit) != candidate_commit
        or _parents(candidate_commit) != [R_F_COMMIT]
        or _resolve("HEAD") != candidate_commit or _staged_paths() or _worktree_paths()
    ):
        raise RebindError("post-A_F topology/index/worktree state differs")
    validate_changed_paths(_diff_paths(R_F_COMMIT, candidate_commit))
    verify_reviewed_anchors(candidate_commit)
    variant = _gitignore_variant(candidate_commit)
    first_rows = _candidate_rows(candidate_commit)
    run_validation_graph()
    projections = [
        _projection(provider, candidate_commit) for provider in sorted(PROVIDER_MODES)
    ]
    verify_reviewed_anchors(candidate_commit)
    if (
        _resolve("HEAD") != candidate_commit or _staged_paths() or _worktree_paths()
        or _gitignore_variant(candidate_commit) != variant
        or _candidate_rows(candidate_commit) != first_rows
    ):
        raise RebindError("post-A_F candidate changed during anchored validation")
    return _manifest(
        first_rows, candidate_commit=candidate_commit, gitignore_variant=variant[0],
        gitignore_sha256=variant[1], projections=projections,
    )


def self_test() -> int:
    controls = 0
    validate_literal_tables(); controls += 1
    verify_base_topology(); controls += 1
    raw, _mode = _read(Path(__file__))
    normalized = _normalized_rebind_sha256(raw)
    if HEX64.fullmatch(normalized) is None:
        raise RebindError("normalized self digest is malformed")
    if NORMALIZED_REBIND_SHA256 != "0" * 64 and normalized != NORMALIZED_REBIND_SHA256:
        raise RebindError("normalized self digest differs")
    controls += 1
    for provider in sorted(PROVIDER_MODES):
        projection = _projection(provider, None); controls += 1
        for mutation in (
            "policy", "commit", "tree", "subject", "counts", "binding",
            "changed-path", "invariant-path", "mode", "hash", "size",
            "candidate", "surplus", "duplicate", "projection-digest",
            "schema-bool", "count-bool", "row-nondict",
        ):
            changed = copy.deepcopy(projection)
            if mutation == "policy": changed["content_policy"] += "-weakened"
            elif mutation == "commit": changed["r_commit"] = A_E_COMMIT
            elif mutation == "tree": changed["r_tree"] = A_E_TREE
            elif mutation == "subject": changed["subject_manifest_sha256"] = "0" * 64
            elif mutation == "counts": changed["counts"][sorted(changed["counts"])[0]] += 1
            elif mutation == "binding": changed["binding_assignments"][sorted(changed["binding_assignments"])[0]] = "0" * 64
            elif mutation == "changed-path": changed["changed_files"][0]["path"] += "-drift"
            elif mutation == "invariant-path": changed["invariant_files"][0]["path"] += "-drift"
            elif mutation == "mode": changed["changed_files"][0]["git_mode"] = "100755"
            elif mutation == "hash": changed["changed_files"][0]["sha256"] = "0" * 64
            elif mutation == "size": changed["changed_files"][0]["size"] += 1
            elif mutation == "candidate": changed["candidate_commit"] = R_F_COMMIT
            elif mutation == "surplus": changed["surplus"] = True
            elif mutation == "duplicate": changed["invariant_files"].append(copy.deepcopy(changed["changed_files"][0]))
            elif mutation == "schema-bool": changed["schema_version"] = True
            elif mutation == "count-bool": changed["counts"][sorted(changed["counts"])[0]] = False
            elif mutation == "row-nondict": changed["changed_files"][0] = []
            else: changed["projection_sha256"] = "0" * 64
            if mutation != "projection-digest":
                body = {key: value for key, value in changed.items() if key != "projection_sha256"}
                changed["projection_sha256"] = _sha(_canonical(body))
            try:
                parsed = parse_projection(_canonical(changed), provider=provider, candidate_commit=None)
                verify_projection_rows(parsed, provider=provider, candidate_commit=None)
            except (KeyError, RebindError):
                controls += 1
            else:
                raise RebindError(f"projection negative control passed: {provider} {mutation}")
    first_provider = sorted(PROVIDER_MODES)[0]
    for label, malformed in (
        ("root-list", _canonical([])),
        ("duplicate-key", b'{"schema_version":1,"schema_version":1}\n'),
        ("float", b'{"schema_version":1.0}\n'),
        ("nonfinite", b'{"schema_version":NaN}\n'),
        ("non-nfc", '{"value":"e\u0301"}\n'.encode("utf-8")),
    ):
        try:
            parse_projection(malformed, provider=first_provider, candidate_commit=None)
        except RebindError:
            controls += 1
        else:
            raise RebindError(f"strict projection JSON negative control passed: {label}")
    if _staged_paths():
        raise RebindError("rebind self-test requires empty index")
    mode, committed = _git_blob(R_F_COMMIT, PROTECTED_GITIGNORE)
    current, _current_mode = _read(REPO / PROTECTED_GITIGNORE)
    difference = _git(["diff", "--binary", R_F_COMMIT, "--", PROTECTED_GITIGNORE], binary=True)
    if difference.returncode != 0:
        raise RebindError("cannot inspect protected .gitignore self-test state")
    classify_gitignore(
        committed_mode=mode, committed=committed, current=current,
        difference=difference.stdout, staged_paths=[],
    ); controls += 1
    for mutation in ("mode", "current", "diff", "staged"):
        values: dict[str, Any] = {
            "committed_mode": mode, "committed": committed, "current": current,
            "difference": difference.stdout, "staged_paths": [],
        }
        if mutation == "mode": values["committed_mode"] = "100755"
        elif mutation == "current": values["current"] = current + b"drift"
        elif mutation == "diff": values["difference"] = difference.stdout + b"drift"
        else: values["staged_paths"] = [PROTECTED_GITIGNORE]
        try: classify_gitignore(**values)
        except RebindError: controls += 1
        else: raise RebindError(f"protected .gitignore negative control passed: {mutation}")
    for paths in (list(FINAL_PATHS[:-1]), [*FINAL_PATHS, "surplus"]):
        if sorted(paths) == list(FINAL_PATHS):
            raise RebindError("literal path negative control is ineffective")
        controls += 1
    with tempfile.TemporaryDirectory(prefix="dcrypt-package-f-rebind-") as temporary:
        first = Path(temporary) / "first"
        second = Path(temporary) / "second"
        first.write_bytes(b"first-before")
        second.write_bytes(b"second-before")
        os.chmod(first, 0o644); os.chmod(second, 0o600)
        def fail(mark_owned: Callable[[Path], None]) -> None:
            first.write_bytes(b"first-after"); os.chmod(first, 0o600); mark_owned(first)
            second.write_bytes(b"second-after"); os.chmod(second, 0o644); mark_owned(second)
            raise KeyboardInterrupt("rollback control")
        try:
            transactional_call([first, second], fail)
        except KeyboardInterrupt:
            pass
        else:
            raise RebindError("rollback control did not raise")
        if first.read_bytes() != b"first-before" or second.read_bytes() != b"second-before":
            raise RebindError("rollback bytes differ")
        if stat.S_IMODE(first.stat().st_mode) != 0o644 or stat.S_IMODE(second.stat().st_mode) != 0o600:
            raise RebindError("rollback modes differ")
        controls += 1
        def drift_after_mark(mark_owned: Callable[[Path], None]) -> None:
            first.write_bytes(b"invocation-owned"); mark_owned(first)
            first.write_bytes(b"concurrent-drift")
            raise ValueError("injected concurrent drift")
        try:
            transactional_call([first], drift_after_mark)
        except RebindError as error:
            if "concurrent-drift-preserved" not in str(error):
                raise
        else:
            raise RebindError("concurrent drift rollback control did not fail closed")
        if first.read_bytes() != b"concurrent-drift":
            raise RebindError("concurrent drift was overwritten during rollback")
        first.write_bytes(b"first-before"); os.chmod(first, 0o644)
        controls += 1
    if FINAL_CHANGED_PATHS_SHA256 == "0" * 64 or not EXPECTED_REVIEWED_FILES:
        controls += 1  # construction state must remain visibly fail-closed to pre/post modes
    else:
        validate_changed_paths(list(FINAL_PATHS)); controls += 1
        verify_reviewed_anchors(); controls += 1
        for path, expected in {**EXPECTED_REVIEWED_FILES, **EXPECTED_PROVIDER_FILES}.items():
            raw_value, filesystem_mode = _read(REPO / path)
            mode_value = _git_mode_from_filesystem(filesystem_mode)
            try: _validate_file_anchor(path, mode_value, raw_value + b"mutation", expected)
            except RebindError: controls += 1
            else: raise RebindError(f"anchor mutation passed: {path}")
    if (
        len(VALIDATION_GRAPH) != 28
        or sum(rc == 3 for _args, rc, _fragment in VALIDATION_GRAPH) != 5
        or sum(rc == 1 for _args, rc, _fragment in VALIDATION_GRAPH) != 1
    ):
        raise RebindError("Package F validation graph closure differs")
    controls += 1
    print(
        f"Package F rebind self-test passed: controls={controls} "
        f"final-global-closure={'frozen' if EXPECTED_REVIEWED_FILES else 'HOLD-until-literal-freeze'}"
    )
    return controls


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pre-commit", action="store_true")
    mode.add_argument("--post-commit", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--candidate-commit")
    args = parser.parse_args()
    try:
        if args.self_test:
            if args.candidate_commit is not None:
                raise RebindError("self-test does not accept a candidate commit")
            self_test()
            return 0
        if args.pre_commit:
            if args.candidate_commit is not None:
                raise RebindError("pre-commit does not accept a candidate commit")
            document = pre_commit_manifest()
        else:
            if args.candidate_commit is None or HEX40.fullmatch(args.candidate_commit) is None:
                raise RebindError("post-commit requires exact lowercase 40-hex candidate commit")
            document = post_commit_manifest(args.candidate_commit)
        sys.stdout.buffer.write(_canonical(document))
        return 0
    except (OSError, RebindError, UnicodeError, ValueError) as error:
        print(f"Package F rebind HOLD: {error}", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
