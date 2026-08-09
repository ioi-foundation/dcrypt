#!/usr/bin/env python3
"""Fail-closed zero-unsafe, zero-native-code, and zero-FFI release gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
POLICY_PATH = PROJECT_ROOT / "implementation-boundary.toml"
LOCK_PATH = PROJECT_ROOT / "Cargo.lock"

SKIP_DIRECTORIES = {".git", "target", "__pycache__"}
DEV_TARGET_KINDS = {"bench", "example", "test"}
NATIVE_CRATE_TYPES = {"cdylib", "dylib", "staticlib"}
FORBID_ATTRIBUTE = re.compile(
    r"#!\s*\[\s*forbid\s*\([^\]]*\bunsafe_code\b[^\]]*\)\s*\]"
)
UNSAFE_TOKEN = re.compile(r"\bunsafe\b")
FOREIGN_ABI = re.compile(
    r'\b(?:unsafe\s+)?extern\s+(?:unsafe\s+)?(?:"[^"\r\n]+"|fn\b|\{)'
)
LINK_ATTRIBUTE = re.compile(
    r"#\s*(?:!\s*)?\[\s*(?:unsafe\s*\(\s*)?"
    r"(?:export_name|link|link_args|link_name|link_ordinal|link_section|no_mangle|used)\b"
)
ABI_ATTRIBUTE = re.compile(
    r"#\s*(?:!\s*)?\[\s*(?:unsafe\s*\(\s*)?"
    r"(?:ffi_(?:const|pure|returns_twice)|instruction_set|naked|target_feature)\b"
    r"|#\s*(?:!\s*)?\[\s*repr\s*\([^\]]*"
    r"(?:\bC\b|\btransparent\b|\bpacked\b|\bsimd\b)"
)
ASSEMBLY_MACRO = re.compile(r"\b(?:asm|global_asm|llvm_asm|naked_asm)\s*!")
ARCH_INTRINSIC = re.compile(r"\b(?:core|std)\s*::\s*arch\s*::")
FFI_API = re.compile(
    r"\b(?:alloc|core|std)\s*::\s*ffi\b"
    r"|\b(?:CStr|CString|VaList|c_char|c_double|c_float|c_int|c_long|c_longlong|"
    r"c_schar|c_short|c_uchar|c_uint|c_ulong|c_ulonglong|c_ushort|c_void)\b"
    r"|\b(?:dlclose|dlopen|dlsym|GetProcAddress|LoadLibrary(?:A|W)?)\b"
)
NATIVE_BUILD_API = re.compile(
    r"\b(?:bindgen|cc|cmake|libloading|nasm_rs|pkg_config|vcpkg)\s*::"
)
BUILD_LINK_DIRECTIVE = re.compile(
    r"(?:cargo:|cargo::)rustc-(?:cdylib-link-arg|"
    r"link-(?:arg(?:-[A-Za-z0-9_-]+)?|lib|search))\b"
)
INTERNAL_ENTROPY = re.compile(
    r"\b(?:OsRng|thread_rng|getrandom|from_entropy)\b|\brand\s*::\s*random\b"
)
GROWABLE_ZEROIZING_BYTES = re.compile(
    r"\bZeroizing\s*<\s*(?:(?:alloc|std)\s*::\s*vec\s*::\s*)?Vec\s*<\s*u8\s*>"
)
INFERRED_GROWABLE_ZEROIZING_BYTES = re.compile(
    r"\bZeroizing\s*::\s*new\s*\(\s*(?:"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?decode\s*\("
    r"|[^();]{0,120}\.\s*to_vec\s*\("
    r"|(?:(?:alloc|std)\s*::\s*)?Vec\s*::\s*(?:new|with_capacity|from)\s*\()",
    re.DOTALL,
)
SECRET_STRING_EXPORT = re.compile(
    r"\bfn\s+(?:to_secure_string|serialize_(?:private|secret)_key)\b"
    r"[^{};]*->\s*(?:(?:alloc|std)\s*::\s*string\s*::\s*)?String\b",
    re.DOTALL,
)
RAW_SECRET_BYTE_OUTPUT = re.compile(
    r"\b(?:derive|derive_array|derive_key|extract|expand|hash_password|"
    r"h_prime_variable_output|kdf_hkdf_[A-Za-z0-9_]+|keyed_generate|mac|pbkdf2|pbkdf2_secure|"
    r"serialize_private_key|serialize_secret_key|squeeze_into_vec|"
    r"to_bytes_zeroizing)\s*(?:<[^>{};]*>)?\s*\([^{};]*\)\s*->\s*"
    r"(?:(?:core\s*::\s*result\s*::\s*)?Result\s*<\s*)?"
    r"(?:(?:(?:alloc|std)\s*::\s*vec\s*::\s*)?Vec\s*<\s*u8\s*>|"
    r"\[\s*u8\s*;)",
    re.DOTALL,
)
DIRECT_RNG_FILL = re.compile(r"\.\s*try_fill_bytes\s*\(")
UNPROTECTED_EC_SCALAR_IMPORT = re.compile(
    r"(?:pub\s+fn\s+new\s*\(\s*data\s*:\s*\[\s*u8\s*;[^]]+\]"
    r"[^{}]*\{[^{}]{0,240}validate_canonical_nonzero\s*\(\s*&data\s*\)\s*\?|"
    r"pub\s+fn\s+from_secret_buffer\b[^{}]*\{[^{}]{0,360}"
    r"let\s+mut\s+\w+\s*=\s*\[|"
    r"pub\s+fn\s+deserialize\b[^{}]*\{[^{}]{0,360}"
    r"let\s+mut\s+\w+\s*=\s*\[)",
    re.DOTALL,
)
UNPROTECTED_ECIES_SHARED_COORDINATE = re.compile(
    r"\blet\s+mut\s+z_bytes\s*=\s*shared_point\s*\.\s*x_coordinate_bytes\s*\(\s*\)"
)
UNPROTECTED_STREAMING_PLAINTEXT = re.compile(
    r"(?:\blet\s+mut\s+buffer\s*=\s*\[\s*0u8\s*;\s*8192\s*\]|"
    r"\bfn\s+open\b[^{};]*->\s*Result\s*<\s*Vec\s*<\s*u8\s*>|"
    r"\blet\s+mut\s+plaintext\s*=\s*self\s*\.\s*cipher\s*\.\s*open\s*\()",
    re.DOTALL,
)
UNPROTECTED_HCHACHA_OUTPUT = re.compile(
    r"\bfn\s+hchacha20\b[^{}]*?->\s*\[\s*u8\s*;|"
    r"\blet\s+mut\s+out\s*=\s*\[\s*0u8\s*;\s*CHACHA20_KEY_SIZE\s*\]|"
    r"\blet\s+mut\s+state\s*=\s*\[\s*0u32\s*;\s*16\s*\]|"
    r"\blet\s+(?:mut\s+)?words\s*=\s*\[\s*state\s*\[",
    re.DOTALL,
)
UNPROTECTED_GCM_KEYED_SCRATCH = re.compile(
    r"(?:\bfn\s+generate_j0\b[^{};]*Result\s*<\s*\[\s*u8\s*;|"
    r"\blet\s+mut\s+counter\s*=\s*\*j0|"
    r"\bfn\s+gf_multiply\b[^{};]*->\s*\[\s*u8\s*;|"
    r"\blet\s+mut\s+(?:z|v)\s*=\s*(?:\[|\*y)|"
    r"\blet\s+mut\s+h_copy\s*=\s*\[)",
    re.DOTALL,
)
UNPROTECTED_MLDSA_CHALLENGE_SCRATCH = re.compile(
    r"\blet\s+mut\s+(?:signs|byte)\s*=\s*\[\s*0u8\s*;"
)
UNPROTECTED_HIGH_LEVEL_KEY_COPY = re.compile(
    r"(?:\blet\s+mut\s+(?:buffer_bytes|key_array|key_data|key|serialized)\b"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*\[\s*0u8\s*;|"
    r"\blet\s+mut\s+encryption_key_arr(?:_aes)?\b"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*\[\s*0u8\s*;)",
    re.DOTALL,
)
UNPROTECTED_ECDSA_CANDIDATE_X = re.compile(
    r"\blet\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*"
    r"kg\s*\.\s*x_coordinate_bytes\s*\(\s*\)"
)
ECDSA_PROTECTED_CANDIDATE_X = re.compile(
    r"\blet\s+r_bytes\s*=\s*Zeroizing\s*::\s*new\s*\(\s*"
    r"kg\s*\.\s*x_coordinate_bytes\s*\(\s*\)\s*\)"
)
BLS_SECRET_CAPABLE_MSM = re.compile(r"\bpub\s+fn\s+msm\s*\(")
ARGON2_BLOCK_GUARDED_ZEROIZE = re.compile(
    r"impl\s+Zeroize\s+for\s+Block\s*\{[^{}]*"
    r"fn\s+zeroize\s*\(\s*&mut\s+self\s*\)\s*\{[^{}]*"
    r"self\s*\.\s*0\s*\.\s*zeroize\s*\(\s*\)",
    re.DOTALL,
)
MISLEADING_SECURE_OPERATION_API = re.compile(
    r"\b(?:trait\s+SecureOperation(?:Ext)?|"
    r"struct\s+SecureOperationBuilder|type\s+CleanupFn)\b"
)
REMOVED_CONSTANT_TIME_CONVENIENCE = re.compile(
    r"\b(?:pub\s+fn\s+(?:ct_select|ct_assign|ct_eq_choice|ct_and|ct_or|"
    r"ct_xor|ct_op|ct_mask)\b|pub\s+trait\s+ConstantTimeEquals\b)"
)
TARGETED_SECRET_SCRATCH = {
    "src/block/aes/mod.rs": re.compile(
        r"(?:\blet\s+mut\s+(?:round_keys_u32|round_key_bytes|state)"
        r"(?:\s*:\s*[^=;]+)?\s*=\s*\[|"
        r"\blet\s+mut\s+temp\s*=\s*round_keys_u32\s*\[|"
        r"\blet\s+(?:bytes|sub_bytes)\s*=\s*(?:u32_to_bytes\s*\(|\[))"
    ),
    "src/block/modes/cbc/mod.rs": re.compile(
        r"\blet\s+mut\s+block\s*=\s*\[\s*0u8\s*;\s*16\s*\]"
    ),
    "src/xof/blake3/mod.rs": re.compile(
        r"(?:\blet\s+mut\s+(?:permuted|state|block|output|result|block_words|"
        r"padded_block|words|key_bytes|arr|key_words|tmp|input_chaining_value)"
        r"(?:\s*:\s*[^=;]+)?\s*=\s*\[|"
        r"\b(?:u32|u64)::from_le_bytes\s*\(\s*\[)"
    ),
    "src/hash/blake2/mod.rs": re.compile(
        r"(?:\blet\s+mut\s+key_secret_buf_content(?:\s*:\s*[^=;]+)?\s*=\s*\[|"
        r"\blet\s+mut\s+h\s*=\s*BLAKE2[BS]_IV\b|"
        r"\b(?:u32|u64)::from_le_bytes\s*\(\s*\[)"
    ),
    "src/kdf/argon2/mod.rs": re.compile(
        r"\blet\s+mut\s+(?:r|tmp|input_q|address_block_qwords|buf|data|xv|yv|gbytes)"
        r"(?:\s*:\s*[^=;]+)?\s*=\s*\["
    ),
    "src/mac/poly1305/mod.rs": re.compile(
        r"\blet\s+mut\s+(?:h|products|reduced|tag_words|operands)"
        r"(?:\s*:\s*[^=;]+)?\s*=\s*\["
    ),
    "src/random.rs": re.compile(
        r"(?:\blet\s+(?:mut\s+)?(?:bytes|key|initial|state|output)"
        r"(?:\s*:\s*[^=;]+)?\s*=\s*\[|"
        r"\b(?:u32|u64)::from_le_bytes\s*\(\s*\[|"
        r"\.to_le_bytes\s*\(\s*\)|"
        r"#\s*\[\s*derive\s*\([^]]*\bClone\b[^]]*\)\s*\]\s*"
        r"pub\s+struct\s+ChaCha20Rng\b)"
    ),
    "src/dilithium/sign.rs": re.compile(
        r"\blet\s+mut\s+(?:c_tilde_seed|selected_c_tilde)"
        r"(?:\s*:\s*[^=;]+)?\s*=\s*(?:vec!|Vec\s*::)"
    ),
    "src/dilithium/encoding.rs": re.compile(
        r"(?:fn\s+(?:pack_hints_bitpacked|pack_polyveck_w1)[^{;]*"
        r"Result\s*<\s*Vec\s*<\s*u8\s*>|"
        r"\blet\s+mut\s+sig_bytes\s*=\s*Vec\s*::)"
    ),
    "src/eddsa/field.rs": re.compile(
        r"(?:fn\s+(?:add|sub)\b[^{}]*\{[^{}]*\blet\s+mut\s+limbs\s*=\s*\[|"
        r"\blet\s+(?:a|b)\s*=\s*(?:self|rhs)\.0\.map\s*\(|"
        r"fn\s+pow\b[^{}]*\{[^{}]*\blet\s+mut\s+accumulator\s*=\s*Self::one\s*\()",
        re.DOTALL,
    ),
    "src/eddsa/scalar.rs": re.compile(
        r"(?:fn\s+to_bytes\b[^{};]*->\s*\[\s*u8\s*;|"
        r"fn\s+(?:load_limbs|conditional_subtract_order)\b[^{};]*->\s*\[\s*u64\s*;|"
        r"fn\s+subtract_limbs\b[^{};]*->\s*\(\s*\[\s*u64\s*;|"
        r"\blet\s+mut\s+(?:sum|limbs|difference|result|bytes|chunk)\s*=\s*\[|"
        r"\blet\s+mut\s+accumulator\s*=\s*Self::zero\s*\(\s*\))",
        re.DOTALL,
    ),
    "src/eddsa/point.rs": re.compile(
        r"(?:fn\s+(?:add|double)\b[^{}]*\{[^{}]*"
        r"\blet\s+(?:a|b|c|d|e|f|g|h)\s*=(?!\s*Zeroizing\s*::)\s*|"
        r"fn\s+scalar_mult\b[^{}]*\{[^{}]*"
        r"\blet\s+mut\s+accumulator\s*=\s*Self::identity\s*\()",
        re.DOTALL,
    ),
    "src/ec/bls12_381/g1.rs": BLS_SECRET_CAPABLE_MSM,
    "src/ec/bls12_381/g2.rs": BLS_SECRET_CAPABLE_MSM,
}
TARGETED_LIFECYCLE_REQUIREMENTS = {
    "src/block/aes/mod.rs": (
        re.compile(r"round_keys_u32\s*=\s*Zeroizing\s*::\s*new"),
        re.compile(r"round_key_bytes\s*=\s*Zeroizing\s*::\s*new"),
        re.compile(r"state\s*=\s*Zeroizing\s*::\s*new"),
    ),
    "src/block/modes/cbc/mod.rs": (
        re.compile(r"block\s*=\s*Zeroizing\s*::\s*new\s*\(\s*\[\s*0u8\s*;\s*16"),
    ),
    "src/xof/blake3/mod.rs": (
        re.compile(r"type\s+ProtectedChainingValue\s*=\s*Zeroizing\s*<"),
        re.compile(r"impl\s+Drop\s+for\s+Output\b"),
        re.compile(r"impl\s+Drop\s+for\s+ChunkState\b"),
    ),
    "src/hash/blake2/mod.rs": (
        re.compile(r"SecretBuffer\s*::\s*<\s*BLAKE2B_KEY_SIZE\s*>\s*::\s*zeroed"),
        re.compile(r"SecretBuffer\s*::\s*<\s*BLAKE2S_KEY_SIZE\s*>\s*::\s*zeroed"),
        re.compile(r"impl\s+Drop\s+for\s+Blake2b\b"),
        re.compile(r"impl\s+Drop\s+for\s+Blake2s\b"),
    ),
    "src/kdf/argon2/mod.rs": (
        ARGON2_BLOCK_GUARDED_ZEROIZE,
        re.compile(r"impl\s+Drop\s+for\s+Block\b"),
        re.compile(r"fn\s+argon2_g\s*\([^)]*\)\s*->\s*Zeroizing\s*<", re.DOTALL),
    ),
    "src/mac/poly1305/mod.rs": (
        re.compile(r"fn\s+mul_reduce\s*\([^)]*\)\s*->\s*Zeroizing\s*<", re.DOTALL),
        re.compile(r"let\s+mut\s+h\s*=\s*Zeroizing\s*::\s*new"),
    ),
    "src/random.rs": (
        re.compile(r"let\s+seed\s*=\s*crate::zeroing::Zeroizing\s*::\s*new\s*\(\s*seed\s*\)"),
        re.compile(r"let\s+initial\s*=\s*crate::zeroing::Zeroizing\s*::\s*new"),
        re.compile(r"let\s+mut\s+state\s*=\s*crate::zeroing::Zeroizing\s*::\s*new"),
        re.compile(r"fn\s+chacha20_block\s*\([^)]*output:\s*&mut\s*\[u8;\s*64\]", re.DOTALL),
    ),
    "src/dilithium/sign.rs": (
        re.compile(r"c_tilde_seed:\s*ZeroizingBytes"),
        re.compile(
            r"selected_c_tilde\s*=\s*Zeroizing\s*::\s*new\s*\(\s*"
            r"boxed_bytes_zeroed"
        ),
    ),
    "src/dilithium/encoding.rs": (
        re.compile(
            r"fn\s+pack_polyveck_w1[^{;]*Result\s*<\s*ZeroizingBytes",
            re.DOTALL,
        ),
        re.compile(r"sig_bytes\s*=\s*Zeroizing\s*::\s*new\s*\(\s*boxed_bytes_zeroed"),
    ),
    "src/eddsa/field.rs": (
        re.compile(r"impl\s+Zeroize\s+for\s+FieldElement"),
        re.compile(r"accumulator\s*=\s*Zeroizing\s*::\s*new\s*\(\s*Self::one"),
    ),
    "src/eddsa/scalar.rs": (
        re.compile(
            r"fn\s+to_bytes\s*\(\s*&self\s*\)\s*->\s*Zeroizing\s*<\s*\[\s*u8\s*;\s*32\s*\]"
        ),
        re.compile(r"accumulator\s*=\s*Zeroizing\s*::\s*new\s*\(\s*Self::zero"),
        re.compile(
            r"fn\s+subtract_limbs\b[^{}]*?->\s*\(\s*Zeroizing\s*<",
            re.DOTALL,
        ),
    ),
    "src/eddsa/ed25519/mod.rs": (
        re.compile(r"let\s+response_bytes\s*=\s*response\s*\.\s*to_bytes\s*\(\s*\)"),
    ),
    "src/eddsa/point.rs": (
        re.compile(r"impl\s+Zeroize\s+for\s+EdwardsPoint"),
        re.compile(r"accumulator\s*=\s*Zeroizing\s*::\s*new\s*\(\s*Self::identity"),
        re.compile(r"doubled\s*=\s*Zeroizing\s*::\s*new"),
        re.compile(r"added\s*=\s*Zeroizing\s*::\s*new"),
    ),
    "src/ecdsa/p224/mod.rs": (ECDSA_PROTECTED_CANDIDATE_X,),
    "src/ecdsa/p256/mod.rs": (ECDSA_PROTECTED_CANDIDATE_X,),
    "src/ecdsa/p384/mod.rs": (ECDSA_PROTECTED_CANDIDATE_X,),
    "src/ecdsa/p521/mod.rs": (ECDSA_PROTECTED_CANDIDATE_X,),
    "src/ec/bls12_381/g1.rs": (
        re.compile(r"pub\s+fn\s+msm_vartime\s*\("),
        re.compile(r"fn\s+pippenger_vartime\s*\("),
    ),
    "src/ec/bls12_381/g2.rs": (
        re.compile(r"pub\s+fn\s+msm_vartime\s*\("),
        re.compile(r"fn\s+pippenger_vartime\s*\("),
    ),
}
VERSIONED_SHARED_OBJECT = re.compile(r"\.so(?:\.\d+)*$", re.IGNORECASE)
VERSIONED_DYLIB = re.compile(r"(?:\.\d+)*\.dylib$", re.IGNORECASE)
NATIVE_MAGIC = (
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "PE/COFF executable"),
    (b"!<arch>\n", "native/static archive"),
    (b"\x00asm", "WebAssembly binary"),
    (b"BC\xc0\xde", "LLVM bitcode"),
    (b"\xde\xc0\x17\x0b", "LLVM bitcode wrapper"),
    (b"Microsoft C/C++ MSF 7.00", "PDB/debug database"),
)
MACH_O_MAGIC = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
NATIVE_FILENAMES = {
    "build.ninja",
    "cmakelists.txt",
    "makefile",
    "meson.build",
}


@dataclass(frozen=True, order=True)
class Violation:
    scope: str
    detail: str


class BoundaryAudit:
    def __init__(self, report_path: Path) -> None:
        self.report_path = report_path
        self.violations: set[Violation] = set()
        self.metadata_profiles: dict[str, dict[str, Any]] = {}
        self.closures: dict[str, set[str]] = {}
        self.packages: dict[str, dict[str, Any]] = {}
        self.archive_hashes: dict[str, str] = {}
        self.excluded_workspace_closures: dict[str, list[str]] = {}
        self.excluded_lock_hashes: dict[str, str] = {}
        self.excluded_workspace_metadata: dict[str, dict[str, Any]] = {}
        self.commands: list[dict[str, Any]] = []
        self.head_sha: str | None = None

    def fail(self, scope: str, detail: str) -> None:
        self.violations.add(Violation(scope, detail))

    def bind_git_head(self) -> None:
        result = self.command(["git", "rev-parse", "--verify", "HEAD"])
        head_sha = result.stdout.strip()
        if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
            self.fail("report", "could not bind the audit to exact Git HEAD")
            return
        self.head_sha = head_sha

    def command(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        display_env = ""
        if env:
            changed = {
                key: value
                for key, value in env.items()
                if os.environ.get(key) != value
            }
            display_env = " ".join(f"{key}={value!r}" for key, value in changed.items())
        display = " ".join(args)
        if display_env:
            display = f"{display_env} {display}"
        print(f"$ {display}", flush=True)
        completed = subprocess.run(
            args,
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            capture_output=capture,
            check=False,
        )
        self.commands.append({"command": display, "status": completed.returncode})
        return completed

    def cargo_metadata(self, profile: str, feature_args: list[str]) -> dict[str, Any]:
        completed = self.command(
            [
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                *feature_args,
            ],
            env=clean_cargo_env(),
        )
        if completed.returncode != 0:
            self.fail(profile, f"cargo metadata failed: {tail(completed.stderr)}")
            return {}
        try:
            metadata = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            self.fail(profile, f"cargo metadata returned invalid JSON: {error}")
            return {}
        self.metadata_profiles[profile] = metadata
        return metadata

    def collect_closure(
        self, profile: str, metadata: dict[str, Any], published_names: set[str]
    ) -> None:
        if not metadata:
            return
        packages = {package["id"]: package for package in metadata["packages"]}
        nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        workspace_members = set(metadata["workspace_members"])
        roots = {
            package_id
            for package_id in workspace_members
            if packages[package_id]["name"] in published_names
        }
        found_names = {packages[package_id]["name"] for package_id in roots}
        missing = sorted(published_names - found_names)
        extra = sorted(found_names - published_names)
        if missing or extra or len(roots) != len(published_names):
            self.fail(
                profile,
                f"published root mismatch; missing={missing}, extra={extra}, count={len(roots)}",
            )

        closure = set(roots)
        queue: deque[str] = deque(sorted(roots))
        while queue:
            package_id = queue.popleft()
            node = nodes.get(package_id)
            if node is None:
                self.fail(profile, f"missing resolve node for {package_id}")
                continue
            for dependency in node.get("deps", []):
                dependency_kinds = dependency.get("dep_kinds", [])
                if not any(
                    item.get("kind") in (None, "normal", "build")
                    for item in dependency_kinds
                ):
                    continue
                dependency_id = dependency["pkg"]
                if dependency_id not in closure:
                    closure.add(dependency_id)
                    queue.append(dependency_id)

        self.closures[profile] = closure
        for package_id in closure:
            self.packages[package_id] = packages[package_id]

    def normal_build_closure(
        self,
        scope: str,
        metadata: dict[str, Any],
        roots: set[str],
    ) -> set[str]:
        packages = {package["id"]: package for package in metadata.get("packages", [])}
        nodes = {
            node["id"]: node
            for node in (metadata.get("resolve") or {}).get("nodes", [])
        }
        closure = set(roots)
        queue: deque[str] = deque(sorted(roots))
        while queue:
            package_id = queue.popleft()
            node = nodes.get(package_id)
            if node is None:
                self.fail(scope, f"missing resolve node for {package_id}")
                continue
            for dependency in node.get("deps", []):
                if not any(
                    item.get("kind") in (None, "normal", "build")
                    for item in dependency.get("dep_kinds", [])
                ):
                    continue
                dependency_id = dependency["pkg"]
                if dependency_id not in packages:
                    self.fail(scope, f"missing package metadata for {dependency_id}")
                    continue
                if dependency_id not in closure:
                    closure.add(dependency_id)
                    queue.append(dependency_id)
        return closure

    def audit_package_metadata(self, policy: dict[str, Any]) -> None:
        forbidden = set(policy["forbidden-packages"])
        suffixes = tuple(policy["forbidden-package-suffixes"])
        oracle_names = set(policy["test-oracle-packages"])
        published_names = set(policy["published-packages"])
        allowed_dependencies = set(policy["allowed-normal-build-packages"])

        all_features = self.metadata_profiles.get("all-features", {})
        workspace_members = set(all_features.get("workspace_members", []))
        package_map = {
            package["id"]: package for package in all_features.get("packages", [])
        }
        published_package_ids = published_workspace_package_ids(
            all_features, published_names
        )
        publishable_names = {
            package_map[package_id]["name"]
            for package_id in workspace_members
            if package_map[package_id].get("publish") != []
        }
        if publishable_names != published_names:
            self.fail(
                "published-roots",
                "policy must exactly match publishable workspace packages; "
                f"missing={sorted(publishable_names - published_names)}, "
                f"extra={sorted(published_names - publishable_names)}",
            )

        external_labels = {
            package_label(package)
            for package_id, package in self.packages.items()
            if package_id not in published_package_ids
        }
        missing_labels, unknown_labels = dependency_snapshot_difference(
            external_labels, allowed_dependencies
        )
        if missing_labels or unknown_labels:
            self.fail(
                "dependency-snapshot",
                "normal/build dependency snapshot mismatch; "
                f"missing={missing_labels}, extra={unknown_labels}",
            )

        for package_id, package in sorted(self.packages.items()):
            label = package_label(package)
            name = package["name"]
            if package.get("links"):
                self.fail(label, f"Cargo package declares links={package['links']!r}")
            for target in package.get("targets", []):
                crate_types = set(target.get("crate_types", []))
                native_types = sorted(crate_types & NATIVE_CRATE_TYPES)
                if native_types:
                    self.fail(
                        label,
                        "Cargo target emits native-library crate type(s): "
                        f"{', '.join(native_types)}",
                    )
            if name in forbidden or name.endswith(suffixes):
                self.fail(label, "forbidden native/FFI/OS-entropy bridge package")
            if name in oracle_names and package_id not in published_package_ids:
                self.fail(
                    label,
                    "external cryptographic implementation appears in the normal/build closure",
                )

        for package_id in sorted(workspace_members):
            package = package_map[package_id]
            if package_id in published_package_ids:
                for dependency in package.get("dependencies", []):
                    if dependency.get("kind") not in (None, "normal", "build"):
                        continue
                    requirement = dependency.get("req", "")
                    if not is_exact_requirement(requirement):
                        self.fail(
                            package_label(package),
                            "normal/build dependency is not exactly pinned: "
                            f"{dependency['name']} {requirement!r}",
                        )
            dependency_oracles = sorted(
                {
                    dependency["name"]
                    for dependency in package.get("dependencies", [])
                    if dependency.get("kind") in (None, "normal", "build")
                    if dependency["name"] in oracle_names
                }
            )
            if not dependency_oracles:
                continue
            if package_id in published_package_ids:
                self.fail(
                    package_label(package),
                    "external cryptographic implementation(s) appear in a published "
                    f"manifest: {', '.join(dependency_oracles)}",
                )
            else:
                self.fail(
                    package_label(package),
                    "differential oracle dependency remains in the main workspace; "
                    f"move it to {policy['verification-workspace']}: "
                    f"{', '.join(dependency_oracles)}",
                )

        self.audit_verification_workspace(policy, all_features)

    def audit_workspace_exclude_classification(self, policy: dict[str, Any]) -> None:
        try:
            classified = classified_excluded_workspaces(policy)
            root_manifest = tomllib.loads((PROJECT_ROOT / "Cargo.toml").read_text())
        except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
            self.fail("workspace-exclude", str(error))
            return

        declared_values = root_manifest.get("workspace", {}).get("exclude", [])
        if not isinstance(declared_values, list) or not all(
            isinstance(value, str) and value for value in declared_values
        ):
            self.fail("workspace-exclude", "root [workspace].exclude must be a string array")
            return

        declared = {Path(value).as_posix() for value in declared_values}
        missing, extra = excluded_classification_difference(declared_values, classified)
        if len(declared) != len(declared_values):
            self.fail("workspace-exclude", "root [workspace].exclude contains duplicates")
        if missing or extra:
            self.fail(
                "workspace-exclude",
                "root [workspace].exclude classification mismatch; "
                f"missing={sorted(missing)}, extra={sorted(extra)}",
            )

    def audit_verification_workspace(
        self, policy: dict[str, Any], main_metadata: dict[str, Any]
    ) -> None:
        relative_workspace = Path(policy["verification-workspace"])
        verification_root = (PROJECT_ROOT / relative_workspace).resolve()
        verification_manifest = verification_root / "Cargo.toml"
        verification_lock = verification_root / "Cargo.lock"
        try:
            root_manifest = tomllib.loads((PROJECT_ROOT / "Cargo.toml").read_text())
        except (OSError, tomllib.TOMLDecodeError) as error:
            self.fail("oracle-isolation", f"cannot parse root Cargo.toml: {error}")
            return

        excluded_roots = {
            (PROJECT_ROOT / entry).resolve()
            for entry in root_manifest.get("workspace", {}).get("exclude", [])
        }
        if verification_root not in excluded_roots:
            self.fail(
                "oracle-isolation",
                f"{relative_workspace.as_posix()} must be listed in [workspace].exclude",
            )

        main_member_manifests = {
            Path(package["manifest_path"]).resolve()
            for package in main_metadata.get("packages", [])
            if package["id"] in set(main_metadata.get("workspace_members", []))
        }
        if any(path.is_relative_to(verification_root) for path in main_member_manifests):
            self.fail(
                "oracle-isolation",
                "verification packages are members of the published workspace",
            )
        if not verification_manifest.is_file():
            self.fail(
                "oracle-isolation",
                f"separate verification workspace is missing: "
                f"{relative_workspace.as_posix()}/Cargo.toml",
            )
            return
        if not verification_lock.is_file():
            self.fail("oracle-isolation", "verification/Cargo.lock is missing")
            return
        tracked_lock = self.command(
            [
                "git",
                "ls-files",
                "--error-unmatch",
                "--",
                verification_lock.relative_to(PROJECT_ROOT).as_posix(),
            ]
        )
        if tracked_lock.returncode != 0:
            self.fail("oracle-isolation", "verification/Cargo.lock must be git-tracked")
        self.excluded_lock_hashes[relative_workspace.as_posix()] = sha256_file(
            verification_lock
        )

        completed = self.command(
            [
                "cargo",
                "metadata",
                "--locked",
                "--no-deps",
                "--format-version",
                "1",
                "--manifest-path",
                str(verification_manifest),
            ],
            env=clean_cargo_env(),
        )
        if completed.returncode != 0:
            self.fail(
                "oracle-isolation",
                f"verification workspace metadata failed: {tail(completed.stderr)}",
            )
            return
        try:
            metadata = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            self.fail(
                "oracle-isolation",
                f"verification workspace metadata returned invalid JSON: {error}",
            )
            return
        if Path(metadata.get("workspace_root", "")).resolve() != verification_root:
            self.fail(
                "oracle-isolation",
                "verification/Cargo.toml does not define an independent Cargo workspace",
            )

        oracle_names = set(policy["test-oracle-packages"])
        members = set(metadata.get("workspace_members", []))
        for package in metadata.get("packages", []):
            if package["id"] not in members:
                continue
            label = package_label(package)
            if package.get("publish") != []:
                self.fail(label, "verification package must set package.publish = false")
            for dependency in package.get("dependencies", []):
                requirement = dependency.get("req", "")
                if not is_exact_requirement(requirement):
                    self.fail(
                        label,
                        "verification dependency is not exactly pinned: "
                        f"{dependency['name']} {requirement!r}",
                    )
                if (
                    dependency["name"] in oracle_names
                    and dependency.get("kind") != "dev"
                ):
                    self.fail(
                        label,
                        "verification oracle dependency must be dev/test-only: "
                        f"{dependency['name']} ({dependency.get('kind') or 'normal'})",
                    )
            for target in package.get("targets", []):
                source = Path(target.get("src_path", "")).resolve()
                if source.is_file() and not has_crate_level_forbid(
                    source.read_text(errors="replace")
                ):
                    self.fail(
                        label,
                        "verification target lacks top-level #![forbid(unsafe_code)]: "
                        f"{source}",
                    )

        audit_source_tree(
            self,
            "verification:owned-sources",
            verification_root,
            set(policy["native-extensions"]),
            check_internal_entropy=False,
            scan_all_rust=True,
            required_rust_files=set(),
        )

    def audit_fuzz_workspace(
        self, policy: dict[str, Any], main_metadata: dict[str, Any]
    ) -> None:
        relative_value = policy.get("fuzz-workspace")
        allowed_value = policy.get("fuzz-allowed-external-normal-build-packages")
        if not isinstance(relative_value, str) or not relative_value:
            self.fail("fuzz-workspace", "policy path must be a non-empty string")
            return
        if not isinstance(allowed_value, list) or not all(
            isinstance(label, str) and label for label in allowed_value
        ):
            self.fail(
                "fuzz-workspace",
                "fuzz-allowed-external-normal-build-packages must be a string array",
            )
            return

        relative = Path(relative_value)
        workspace_root = (PROJECT_ROOT / relative).resolve()
        manifest = workspace_root / "Cargo.toml"
        lock = workspace_root / "Cargo.lock"
        scope = f"fuzz:{relative.as_posix()}"
        if not manifest.is_file() or not lock.is_file():
            self.fail(scope, "independent Cargo.toml and Cargo.lock are required")
            return
        tracked_lock = self.command(
            [
                "git",
                "ls-files",
                "--error-unmatch",
                "--",
                lock.relative_to(PROJECT_ROOT).as_posix(),
            ]
        )
        if tracked_lock.returncode != 0:
            self.fail(scope, "fuzz workspace Cargo.lock must be git-tracked")
        self.excluded_lock_hashes[relative.as_posix()] = sha256_file(lock)

        completed = self.command(
            [
                "cargo",
                "metadata",
                "--locked",
                "--all-features",
                "--format-version",
                "1",
                "--manifest-path",
                str(manifest),
            ],
            env=clean_cargo_env(),
        )
        if completed.returncode != 0:
            self.fail(scope, f"cargo metadata failed: {tail(completed.stderr)}")
            return
        try:
            metadata = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            self.fail(scope, f"cargo metadata returned invalid JSON: {error}")
            return
        if Path(metadata.get("workspace_root", "")).resolve() != workspace_root:
            self.fail(scope, "Cargo.toml must define an independent Cargo workspace")

        members = set(metadata.get("workspace_members", []))
        packages = {package["id"]: package for package in metadata.get("packages", [])}
        if not members:
            self.fail(scope, "fuzz workspace has no members")
            return
        for package_id in sorted(members):
            package = packages.get(package_id)
            if package is None:
                self.fail(scope, f"missing member metadata for {package_id}")
                continue
            label = package_label(package)
            if package.get("publish") != []:
                self.fail(label, "fuzz workspace package must set publish = false")
            if package.get("metadata", {}).get("cargo-fuzz") is not True:
                self.fail(label, "fuzz workspace package lacks package.metadata.cargo-fuzz=true")
            for target in package.get("targets", []):
                source = Path(target.get("src_path", "")).resolve()
                if not source.is_file():
                    self.fail(label, f"Cargo target source is missing: {source}")
                elif not has_crate_level_forbid(source.read_text(errors="replace")):
                    self.fail(
                        label,
                        "fuzz target lacks top-level #![forbid(unsafe_code)]: "
                        f"{source}",
                    )

            try:
                member_manifest = tomllib.loads(Path(package["manifest_path"]).read_text())
            except (OSError, tomllib.TOMLDecodeError) as error:
                self.fail(label, f"cannot parse member Cargo.toml: {error}")
                continue
            for table_name, dependency_name, specification in iter_manifest_dependencies(
                member_manifest
            ):
                requirement = (
                    specification
                    if isinstance(specification, str)
                    else specification.get("version", "")
                    if isinstance(specification, dict)
                    else ""
                )
                if not isinstance(requirement, str) or not is_exact_requirement(requirement):
                    self.fail(
                        label,
                        "fuzz normal/build dependency is not exactly pinned: "
                        f"{table_name}.{dependency_name} {requirement!r}",
                    )

        closure = self.normal_build_closure(scope, metadata, members)
        closure_packages = [
            packages[package_id]
            for package_id in sorted(closure)
            if package_id in packages
        ]
        external_labels: set[str] = set()
        for package in closure_packages:
            label = package_label(package)
            package_root = Path(package["manifest_path"]).resolve().parent
            if not package_root.is_relative_to(PROJECT_ROOT):
                external_labels.add(label)
                if package.get("source") != (
                    "registry+https://github.com/rust-lang/crates.io-index"
                ):
                    self.fail(label, "external fuzz dependency is not from crates.io")
                continue
            required_sources = cargo_target_sources(self, package, package_root)
            audit_source_tree(
                self,
                f"{scope}:{label}",
                package_root,
                set(policy["native-extensions"]),
                check_internal_entropy=True,
                scan_all_rust=True,
                required_rust_files=required_sources,
            )

        allowed_labels = set(allowed_value)
        if external_labels != allowed_labels:
            self.fail(
                scope,
                "external normal/build dependency snapshot mismatch; "
                f"missing={sorted(allowed_labels - external_labels)}, "
                f"extra={sorted(external_labels - allowed_labels)}",
            )
        self.excluded_workspace_closures[relative.as_posix()] = sorted(
            package_label(package) for package in closure_packages
        )
        self.excluded_workspace_metadata[relative.as_posix()] = metadata

    def audit_owned_excluded_workspaces(
        self, policy: dict[str, Any], main_metadata: dict[str, Any]
    ) -> None:
        configurations = policy.get("owned-excluded-workspaces", [])
        if not isinstance(configurations, list):
            self.fail(
                "owned-excluded-workspaces",
                "policy entry must be an array of workspace tables",
            )
            return

        try:
            root_manifest = tomllib.loads((PROJECT_ROOT / "Cargo.toml").read_text())
        except (OSError, tomllib.TOMLDecodeError) as error:
            self.fail(
                "owned-excluded-workspaces",
                f"cannot parse root Cargo.toml: {error}",
            )
            return
        excluded_roots = {
            (PROJECT_ROOT / entry).resolve()
            for entry in root_manifest.get("workspace", {}).get("exclude", [])
        }
        main_members = set(main_metadata.get("workspace_members", []))
        main_member_manifests = {
            Path(package["manifest_path"]).resolve()
            for package in main_metadata.get("packages", [])
            if package["id"] in main_members
        }
        forbidden = set(policy["forbidden-packages"])
        suffixes = tuple(policy["forbidden-package-suffixes"])
        oracles = set(policy["test-oracle-packages"])
        native_extensions = set(policy["native-extensions"])
        seen_roots: set[Path] = set()

        for configuration in configurations:
            if not isinstance(configuration, dict):
                self.fail(
                    "owned-excluded-workspaces",
                    "each workspace policy entry must be a table",
                )
                continue
            relative_value = configuration.get("path")
            allowed_value = configuration.get(
                "allowed-external-normal-build-packages"
            )
            if not isinstance(relative_value, str) or not relative_value:
                self.fail(
                    "owned-excluded-workspaces",
                    "workspace path must be a non-empty string",
                )
                continue
            if not isinstance(allowed_value, list) or not all(
                isinstance(label, str) and label for label in allowed_value
            ):
                self.fail(
                    relative_value,
                    "allowed-external-normal-build-packages must be a string array",
                )
                continue

            relative = Path(relative_value)
            workspace_root = (PROJECT_ROOT / relative).resolve()
            scope = f"excluded:{relative.as_posix()}"
            if (
                relative.is_absolute()
                or workspace_root == PROJECT_ROOT
                or not workspace_root.is_relative_to(PROJECT_ROOT)
            ):
                self.fail(scope, "workspace path must remain inside the repository")
                continue
            if workspace_root in seen_roots:
                self.fail(scope, "workspace is configured more than once")
                continue
            seen_roots.add(workspace_root)

            manifest = workspace_root / "Cargo.toml"
            lock = workspace_root / "Cargo.lock"
            if workspace_root not in excluded_roots:
                self.fail(scope, "workspace must be listed in root [workspace].exclude")
            if any(path.is_relative_to(workspace_root) for path in main_member_manifests):
                self.fail(scope, "excluded packages are members of the published workspace")
            if not manifest.is_file() or not lock.is_file():
                self.fail(scope, "independent Cargo.toml and Cargo.lock are required")
                continue
            tracked_lock = self.command(
                [
                    "git",
                    "ls-files",
                    "--error-unmatch",
                    "--",
                    lock.relative_to(PROJECT_ROOT).as_posix(),
                ]
            )
            if tracked_lock.returncode != 0:
                self.fail(scope, "excluded workspace Cargo.lock must be git-tracked")
            self.excluded_lock_hashes[relative.as_posix()] = sha256_file(lock)

            completed = self.command(
                [
                    "cargo",
                    "metadata",
                    "--locked",
                    "--all-features",
                    "--format-version",
                    "1",
                    "--manifest-path",
                    str(manifest),
                ],
                env=clean_cargo_env(),
            )
            if completed.returncode != 0:
                self.fail(scope, f"cargo metadata failed: {tail(completed.stderr)}")
                continue
            try:
                metadata = json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                self.fail(scope, f"cargo metadata returned invalid JSON: {error}")
                continue
            if Path(metadata.get("workspace_root", "")).resolve() != workspace_root:
                self.fail(scope, "Cargo.toml must define an independent Cargo workspace")
            members = set(metadata.get("workspace_members", []))
            packages = {
                package["id"]: package for package in metadata.get("packages", [])
            }
            if not members:
                self.fail(scope, "excluded workspace has no members")
                continue
            for package_id in sorted(members):
                package = packages.get(package_id)
                if package is None:
                    self.fail(scope, f"missing member metadata for {package_id}")
                    continue
                label = package_label(package)
                if package.get("publish") != []:
                    self.fail(label, "excluded workspace package must set publish = false")
                for target in package.get("targets", []):
                    source = Path(target.get("src_path", "")).resolve()
                    if not source.is_file():
                        self.fail(label, f"Cargo target source is missing: {source}")
                        continue
                    if not has_crate_level_forbid(source.read_text(errors="replace")):
                        self.fail(
                            label,
                            "excluded workspace target lacks top-level "
                            f"#![forbid(unsafe_code)]: {source}",
                        )

                try:
                    member_manifest = tomllib.loads(
                        Path(package["manifest_path"]).read_text()
                    )
                except (OSError, tomllib.TOMLDecodeError) as error:
                    self.fail(label, f"cannot parse member Cargo.toml: {error}")
                    continue
                for table_name, dependency_name, specification in iter_manifest_dependencies(
                    member_manifest
                ):
                    if isinstance(specification, dict) and "path" in specification:
                        dependency_path = (
                            Path(package["manifest_path"]).parent
                            / specification["path"]
                        ).resolve()
                        if not dependency_path.is_relative_to(PROJECT_ROOT):
                            self.fail(
                                label,
                                "path dependency escapes the repository: "
                                f"{table_name}.{dependency_name}",
                            )
                        requirement = specification.get("version", "")
                        if not isinstance(requirement, str) or not is_exact_requirement(
                            requirement
                        ):
                            self.fail(
                                label,
                                "path normal/build dependency is not exactly pinned: "
                                f"{table_name}.{dependency_name} {requirement!r}",
                            )
                        continue
                    requirement = (
                        specification
                        if isinstance(specification, str)
                        else specification.get("version", "")
                        if isinstance(specification, dict)
                        else ""
                    )
                    if not isinstance(requirement, str) or not is_exact_requirement(
                        requirement
                    ):
                        self.fail(
                            label,
                            "registry normal/build dependency is not exactly pinned: "
                            f"{table_name}.{dependency_name} {requirement!r}",
                        )

            closure = self.normal_build_closure(scope, metadata, members)
            closure_packages = [
                packages[package_id]
                for package_id in sorted(closure)
                if package_id in packages
            ]
            external_labels: set[str] = set()
            for package in closure_packages:
                label = package_label(package)
                name = package["name"]
                package_root = Path(package["manifest_path"]).resolve().parent
                owned_source = package_root.is_relative_to(PROJECT_ROOT)
                if not owned_source:
                    external_labels.add(label)
                    if package.get("source") != (
                        "registry+https://github.com/rust-lang/crates.io-index"
                    ):
                        self.fail(label, "external dependency is not from crates.io")
                if package.get("links"):
                    self.fail(label, f"Cargo package declares links={package['links']!r}")
                for target in package.get("targets", []):
                    native_types = sorted(
                        set(target.get("crate_types", [])) & NATIVE_CRATE_TYPES
                    )
                    if native_types:
                        self.fail(
                            label,
                            "Cargo target emits native-library crate type(s): "
                            f"{', '.join(native_types)}",
                        )
                if name in forbidden or name.endswith(suffixes):
                    self.fail(label, "forbidden native/FFI/OS-entropy bridge package")
                if name in oracles:
                    self.fail(
                        label,
                        "external cryptographic implementation appears in the "
                        "excluded workspace normal/build closure",
                    )

                required_sources = cargo_target_sources(self, package, package_root)
                audit_source_tree(
                    self,
                    f"{scope}:{label}",
                    package_root,
                    native_extensions,
                    check_internal_entropy=owned_source,
                    scan_all_rust=package_root == workspace_root,
                    required_rust_files=required_sources,
                )

            allowed_labels = set(allowed_value)
            if external_labels != allowed_labels:
                self.fail(
                    scope,
                    "external normal/build dependency snapshot mismatch; "
                    f"missing={sorted(allowed_labels - external_labels)}, "
                    f"extra={sorted(external_labels - allowed_labels)}",
                )
            self.excluded_workspace_closures[relative.as_posix()] = sorted(
                package_label(package) for package in closure_packages
            )
            self.excluded_workspace_metadata[relative.as_posix()] = metadata

    def run_owned_excluded_active_scans(self, policy: dict[str, Any]) -> None:
        native_extensions = set(policy["native-extensions"])
        configurations = policy.get("owned-excluded-workspaces", [])
        with tempfile.TemporaryDirectory(prefix="dcrypt-excluded-boundary-") as temp:
            target_root = Path(temp)
            for configuration in configurations:
                if not isinstance(configuration, dict):
                    continue
                relative_value = configuration.get("path")
                if not isinstance(relative_value, str):
                    continue
                metadata = self.excluded_workspace_metadata.get(relative_value)
                if not metadata:
                    continue
                manifest = PROJECT_ROOT / relative_value / "Cargo.toml"
                scope = f"excluded:{relative_value}:active"
                package_map = {
                    package["id"]: package for package in metadata.get("packages", [])
                }
                target_directory = target_root / hashlib.sha256(
                    relative_value.encode()
                ).hexdigest()[:16]
                env = clean_cargo_env()
                env["RUSTFLAGS"] = "--force-warn=unsafe-code"
                env["CARGO_TARGET_DIR"] = str(target_directory)
                completed = self.command(
                    [
                        "cargo",
                        "check",
                        "--locked",
                        "--all-targets",
                        "--all-features",
                        "--manifest-path",
                        str(manifest),
                        "--message-format=json",
                    ],
                    env=env,
                )
                unsafe_counts: dict[str, int] = defaultdict(int)
                unsafe_first: dict[str, str] = {}
                for line in completed.stdout.splitlines():
                    try:
                        message = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    reason = message.get("reason")
                    if reason == "compiler-message":
                        diagnostic = message.get("message", {})
                        code = diagnostic.get("code") or {}
                        if code.get("code") != "unsafe_code":
                            continue
                        package_id = message.get("package_id", "unknown")
                        label = package_label(
                            package_map.get(package_id, {"id": package_id})
                        )
                        unsafe_counts[label] += 1
                        spans = diagnostic.get("spans", [])
                        if label not in unsafe_first and spans:
                            span = spans[0]
                            unsafe_first[label] = (
                                f"{span.get('file_name')}:{span.get('line_start')}"
                            )
                    elif reason == "build-script-executed":
                        linked = message.get("linked_libs", [])
                        linked_paths = message.get("linked_paths", [])
                        if linked or linked_paths:
                            package_id = message.get("package_id", "unknown")
                            label = package_label(
                                package_map.get(package_id, {"id": package_id})
                            )
                            self.fail(
                                f"{scope}:{label}",
                                "build script emitted native links: "
                                f"libs={linked}, paths={linked_paths}",
                            )
                for label, count in sorted(unsafe_counts.items()):
                    self.fail(
                        f"{scope}:{label}",
                        f"compiler emitted {count} active unsafe-code diagnostic(s); "
                        f"first={unsafe_first.get(label, 'unknown')}",
                    )
                if completed.returncode != 0:
                    self.fail(
                        scope,
                        "active excluded-workspace audit did not compile: "
                        f"{tail(completed.stderr)}",
                    )
                for output_directory in sorted(target_directory.glob("**/build/*/out")):
                    if output_directory.is_dir():
                        audit_source_tree(
                            self,
                            f"{scope}:generated:{output_directory.parent.name}",
                            output_directory,
                            native_extensions,
                            check_internal_entropy=False,
                            scan_all_rust=True,
                            required_rust_files=set(),
                        )

    def run_fuzz_active_scan(self, policy: dict[str, Any]) -> None:
        relative_value = policy.get("fuzz-workspace")
        if not isinstance(relative_value, str) or not relative_value:
            return
        manifest = PROJECT_ROOT / relative_value / "Cargo.toml"
        with tempfile.TemporaryDirectory(prefix="dcrypt-fuzz-boundary-") as temp:
            env = clean_cargo_env()
            env["CARGO_TARGET_DIR"] = temp
            completed = self.command(
                [
                    "cargo",
                    "check",
                    "--locked",
                    "--all-targets",
                    "--all-features",
                    "--manifest-path",
                    str(manifest),
                ],
                env=env,
            )
            if completed.returncode != 0:
                self.fail(
                    f"fuzz:{relative_value}:active",
                    f"fuzz workspace did not compile: {tail(completed.stderr)}",
                )

    def audit_dependency_sources(
        self, policy: dict[str, Any], published_names: set[str]
    ) -> None:
        published_package_ids = published_workspace_package_ids(
            self.metadata_profiles.get("all-features", {}), published_names
        )
        for package in sorted(self.packages.values(), key=package_label):
            if package["id"] in published_package_ids:
                continue
            root = Path(package["manifest_path"]).resolve().parent
            if not root.is_dir():
                self.fail(package_label(package), f"source directory is missing: {root}")
                continue
            required_target_sources = cargo_target_sources(self, package, root)
            audit_source_tree(
                self,
                package_label(package),
                root,
                set(policy["native-extensions"]),
                check_internal_entropy=False,
                scan_all_rust=False,
                required_rust_files=required_target_sources,
            )

    def package_and_audit_owned_sources(
        self, policy: dict[str, Any], metadata: dict[str, Any]
    ) -> None:
        workspace_members = set(metadata.get("workspace_members", []))
        packages_by_name = {
            package["name"]: package
            for package in metadata.get("packages", [])
            if package["id"] in workspace_members
            if package["name"] in set(policy["published-packages"])
        }
        with tempfile.TemporaryDirectory(prefix="dcrypt-package-audit-") as temp:
            temp_root = Path(temp)
            cargo_target = temp_root / "cargo-target"
            extract_root = temp_root / "unpacked"
            extract_root.mkdir()
            env = os.environ.copy()
            env.pop("CARGO_ENCODED_RUSTFLAGS", None)
            env["CARGO_TARGET_DIR"] = str(cargo_target)
            package_command = [
                "cargo",
                "package",
                "--workspace",
                "--locked",
                "--no-verify",
                "--allow-dirty",
                "--target-dir",
                str(cargo_target),
            ]
            workspace_names = {
                package["name"]
                for package in metadata.get("packages", [])
                if package["id"] in set(metadata.get("workspace_members", []))
            }
            if "dcrypt-tests" in workspace_names:
                package_command.extend(["--exclude", "dcrypt-tests"])
            completed = self.command(package_command, env=env)
            if completed.returncode != 0:
                self.fail(
                    "package-artifacts",
                    f"workspace cargo package failed: {tail(completed.stderr)}",
                )
                return

            for name in policy["published-packages"]:
                package = packages_by_name.get(name)
                if package is None:
                    self.fail("package-artifacts", f"metadata is missing {name}")
                    continue
                archive = cargo_target / "package" / f"{name}-{package['version']}.crate"
                if not archive.is_file():
                    self.fail(name, f"expected package archive is missing: {archive.name}")
                    continue
                self.archive_hashes[f"{name}@{package['version']}"] = sha256_file(archive)
                destination = extract_root / name
                destination.mkdir()
                try:
                    safe_extract(archive, destination)
                except (OSError, tarfile.TarError, ValueError) as error:
                    self.fail(name, f"could not safely unpack archive: {error}")
                    continue
                unpacked = destination / f"{name}-{package['version']}"
                if not unpacked.is_dir():
                    self.fail(name, "archive did not contain the expected package root")
                    continue

                vcs_path = unpacked / ".cargo_vcs_info.json"
                try:
                    vcs_info = json.loads(vcs_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    self.fail(name, f"package provenance is unavailable: {error}")
                else:
                    git_info = vcs_info.get("git") if isinstance(vcs_info, dict) else None
                    if (
                        not isinstance(git_info, dict)
                        or git_info.get("sha1") != self.head_sha
                        or git_info.get("dirty", False) is not False
                    ):
                        self.fail(
                            name,
                            "package provenance is not clean and bound to exact Git HEAD",
                        )

                original_manifest = Path(package["manifest_path"]).resolve()
                library_targets = [
                    target
                    for target in package.get("targets", [])
                    if "lib" in target.get("kind", [])
                ]
                if len(library_targets) != 1:
                    self.fail(name, f"expected one library target, found {len(library_targets)}")
                else:
                    source_path = Path(library_targets[0]["src_path"]).resolve()
                    try:
                        relative_source = source_path.relative_to(original_manifest.parent)
                    except ValueError:
                        self.fail(name, f"library root escapes the package: {source_path}")
                    else:
                        packaged_root = unpacked / relative_source
                        if not packaged_root.is_file():
                            self.fail(name, f"packaged crate root is missing: {relative_source}")
                        else:
                            source_text = packaged_root.read_text(errors="replace")
                            if not has_crate_level_forbid(source_text):
                                self.fail(
                                    name,
                                    "crate root lacks a top-level "
                                    f"#![forbid(unsafe_code)]: {relative_source}",
                                )

                packaged_manifest = unpacked / "Cargo.toml"
                if not packaged_manifest.is_file():
                    self.fail(name, "packaged Cargo.toml is missing")
                else:
                    audit_packaged_manifest(self, name, packaged_manifest)

                audit_source_tree(
                    self,
                    f"{name}@{package['version']} (.crate)",
                    unpacked,
                    set(policy["native-extensions"]),
                    check_internal_entropy=True,
                    scan_all_rust=True,
                    required_rust_files=set(),
                )

    def validate_supported_targets(self, policy: dict[str, Any]) -> set[str]:
        targets = policy["targets"]
        rustc_version = self.command(["rustc", "-vV"], env=clean_cargo_env())
        host_match = re.search(r"^host: (\S+)$", rustc_version.stdout, re.MULTILINE)
        actual_host = host_match.group(1) if host_match else "unknown"
        if actual_host != targets["linux-x86-64"]:
            self.fail(
                "linux-x86-64",
                f"gate must run on {targets['linux-x86-64']}; actual host is {actual_host}",
            )
        installed = self.command(
            ["rustup", "target", "list", "--installed"], env=clean_cargo_env()
        )
        installed_targets = set(installed.stdout.split()) if installed.returncode == 0 else set()
        for label, target in targets.items():
            if target not in installed_targets:
                self.fail(label, f"Rust target is not installed: {target}")
        return installed_targets

    def run_active_dependency_unsafe_scans(
        self, policy: dict[str, Any], installed_targets: set[str]
    ) -> None:
        native_extensions = set(policy["native-extensions"])
        with tempfile.TemporaryDirectory(prefix="dcrypt-active-boundary-") as temp:
            temp_root = Path(temp)
            for scope, target, profile, feature_args in compilation_matrix(policy):
                if target not in installed_targets:
                    continue
                metadata = self.metadata_profiles.get(profile, {})
                package_map = {
                    package["id"]: package for package in metadata.get("packages", [])
                }
                target_directory = temp_root / scope
                env = clean_cargo_env()
                env["RUSTFLAGS"] = "--force-warn=unsafe-code"
                env["CARGO_TARGET_DIR"] = str(target_directory)
                completed = self.command(
                    [
                        "cargo",
                        "check",
                        "--locked",
                        "--workspace",
                        "--exclude",
                        "dcrypt-tests",
                        "--lib",
                        *feature_args,
                        "--target",
                        target,
                        "--message-format=json",
                    ],
                    env=env,
                )
                unsafe_counts: dict[str, int] = defaultdict(int)
                unsafe_first: dict[str, str] = {}
                for line in completed.stdout.splitlines():
                    try:
                        message = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    reason = message.get("reason")
                    if reason == "compiler-message":
                        diagnostic = message.get("message", {})
                        code = diagnostic.get("code") or {}
                        if code.get("code") != "unsafe_code":
                            continue
                        package_id = message.get("package_id", "unknown")
                        label = package_label(package_map.get(package_id, {"id": package_id}))
                        unsafe_counts[label] += 1
                        spans = diagnostic.get("spans", [])
                        if label not in unsafe_first and spans:
                            span = spans[0]
                            unsafe_first[label] = (
                                f"{span.get('file_name')}:{span.get('line_start')}"
                            )
                    elif reason == "build-script-executed":
                        linked = message.get("linked_libs", [])
                        linked_paths = message.get("linked_paths", [])
                        if linked or linked_paths:
                            package_id = message.get("package_id", "unknown")
                            label = package_label(
                                package_map.get(package_id, {"id": package_id})
                            )
                            self.fail(
                                f"{scope}:{label}",
                                "build script emitted native links: "
                                f"libs={linked}, paths={linked_paths}",
                            )
                for label, count in sorted(unsafe_counts.items()):
                    self.fail(
                        f"{scope}:{label}",
                        f"compiler emitted {count} active unsafe-code diagnostic(s); "
                        f"first={unsafe_first.get(label, 'unknown')}",
                    )
                if completed.returncode != 0:
                    self.fail(
                        scope,
                        "active dependency audit did not compile: "
                        f"{tail(completed.stderr)}",
                    )
                for output_directory in sorted(
                    target_directory.glob("**/build/*/out")
                ):
                    if output_directory.is_dir():
                        audit_source_tree(
                            self,
                            f"{scope}:generated:{output_directory.parent.name}",
                            output_directory,
                            native_extensions,
                            check_internal_entropy=False,
                            scan_all_rust=True,
                            required_rust_files=set(),
                        )

    def run_no_std_contract_checks(
        self,
        policy: dict[str, Any],
        published_names: set[str],
        installed_targets: set[str],
    ) -> None:
        target = policy["targets"]["no-std"]
        if target not in installed_targets:
            return
        package_features = policy.get("no-std-package-features", {})
        configured_packages = set(package_features)
        if configured_packages != published_names:
            missing = sorted(published_names - configured_packages)
            extra = sorted(configured_packages - published_names)
            if missing:
                self.fail(
                    "no-std-policy",
                    "missing per-package feature profiles: " + ", ".join(missing),
                )
            if extra:
                self.fail(
                    "no-std-policy",
                    "unknown per-package feature profiles: " + ", ".join(extra),
                )
        with tempfile.TemporaryDirectory(prefix="dcrypt-no-std-") as temp:
            env = clean_cargo_env()
            env["RUSTFLAGS"] = ""
            env["CARGO_TARGET_DIR"] = temp
            for package_name in sorted(published_names):
                scope = f"no-std:{package_name}"
                features = package_features.get(package_name, [])
                if not isinstance(features, list) or not all(
                    isinstance(feature, str) and feature for feature in features
                ):
                    self.fail(scope, "no_std feature profile must be a string array")
                    continue
                feature_args = (
                    ["--features", ",".join(features)] if features else []
                )
                tree = self.command(
                    [
                        "cargo",
                        "tree",
                        "--locked",
                        "--package",
                        package_name,
                        "--no-default-features",
                        *feature_args,
                        "--target",
                        target,
                        "--edges",
                        "normal,features",
                        "--prefix",
                        "none",
                    ],
                    env=env,
                )
                if tree.returncode != 0:
                    self.fail(scope, f"feature resolution failed: {tail(tree.stderr)}")
                else:
                    std_packages = sorted(
                        {
                            match.group(1)
                            for line in tree.stdout.splitlines()
                            if (
                                match := re.match(
                                    r'^([A-Za-z0-9_.+-]+) feature "std"(?: \(\*\))?$',
                                    line,
                                )
                            )
                        }
                    )
                    if std_packages:
                        self.fail(
                            scope,
                            "the target normal dependency graph resolved std feature(s): "
                            f"{', '.join(std_packages)}",
                        )

                completed = self.command(
                    [
                        "cargo",
                        "check",
                        "--locked",
                        "--package",
                        package_name,
                        "--lib",
                        "--no-default-features",
                        *feature_args,
                        "--target",
                        target,
                    ],
                    env=env,
                )
                if completed.returncode != 0:
                    self.fail(
                        scope,
                        "per-package no_std library check failed: "
                        f"{tail(completed.stderr)}",
                    )

    def write_report(self, policy: dict[str, Any]) -> None:
        report = {
            "schema_version": policy["schema-version"],
            "head_sha": self.head_sha,
            "policy_sha256": sha256_file(POLICY_PATH),
            "lock_sha256": sha256_file(LOCK_PATH) if LOCK_PATH.is_file() else None,
            "published_packages": policy["published-packages"],
            "no_std_package_features": policy.get(
                "no-std-package-features", {}
            ),
            "closures": {
                profile: sorted(
                    package_label(self.packages[package_id])
                    for package_id in package_ids
                    if package_id in self.packages
                )
                for profile, package_ids in sorted(self.closures.items())
            },
            "archive_sha256": dict(sorted(self.archive_hashes.items())),
            "owned_excluded_workspace_locks": dict(
                sorted(self.excluded_lock_hashes.items())
            ),
            "owned_excluded_workspace_closures": dict(
                sorted(self.excluded_workspace_closures.items())
            ),
            "commands": self.commands,
            "violations": [
                {"scope": violation.scope, "detail": violation.detail}
                for violation in sorted(self.violations)
            ],
            "passed": not self.violations,
        }
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def classified_excluded_workspaces(policy: dict[str, Any]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for category, key in (
        ("verification", "verification-workspace"),
        ("fuzz", "fuzz-workspace"),
    ):
        value = policy.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"policy {key} must be a non-empty string")
        entries.append((category, Path(value).as_posix()))

    configurations = policy.get("owned-excluded-workspaces", [])
    if not isinstance(configurations, list):
        raise ValueError("policy owned-excluded-workspaces must be an array")
    for configuration in configurations:
        if not isinstance(configuration, dict):
            raise ValueError("each owned excluded workspace entry must be a table")
        value = configuration.get("path")
        if not isinstance(value, str) or not value:
            raise ValueError("owned excluded workspace path must be a non-empty string")
        entries.append(("owned", Path(value).as_posix()))

    paths = [path for _, path in entries]
    if len(set(paths)) != len(paths):
        raise ValueError("classified excluded workspace paths must be unique")
    for path in paths:
        candidate = Path(path)
        resolved = (PROJECT_ROOT / candidate).resolve()
        if (
            candidate.is_absolute()
            or resolved == PROJECT_ROOT
            or not resolved.is_relative_to(PROJECT_ROOT)
        ):
            raise ValueError(f"classified workspace path escapes repository: {path}")
    return entries


def excluded_classification_difference(
    declared: Iterable[str], classified: Iterable[tuple[str, str]]
) -> tuple[set[str], set[str]]:
    declared_paths = {Path(path).as_posix() for path in declared}
    classified_paths = {path for _, path in classified}
    return classified_paths - declared_paths, declared_paths - classified_paths


def dependency_snapshot_difference(
    actual: Iterable[str], allowed: Iterable[str]
) -> tuple[list[str], list[str]]:
    """Return stale policy entries and unclassified dependency entries."""

    actual_labels = set(actual)
    allowed_labels = set(allowed)
    return (
        sorted(allowed_labels - actual_labels),
        sorted(actual_labels - allowed_labels),
    )


def published_workspace_package_ids(
    metadata: dict[str, Any], published_names: set[str]
) -> set[str]:
    """Identify owned published crates by workspace identity, never by name alone."""

    workspace_members = set(metadata.get("workspace_members", []))
    return {
        package["id"]
        for package in metadata.get("packages", [])
        if package["id"] in workspace_members and package["name"] in published_names
    }


def package_label(package: dict[str, Any]) -> str:
    if "name" in package and "version" in package:
        return f"{package['name']}@{package['version']}"
    return str(package.get("id", "unknown-package"))


def clean_cargo_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    return env


def compilation_matrix(
    policy: dict[str, Any],
) -> list[tuple[str, str, str, list[str]]]:
    targets = policy["targets"]
    profiles = (
        ("all-features", ["--all-features"]),
        ("no-default-features", ["--no-default-features"]),
    )
    matrix: list[tuple[str, str, str, list[str]]] = []
    # `--all-features` intentionally enables the workspace's `std` features,
    # so it is meaningful only on targets that provide `std`. The bare-metal
    # target is exercised below with no defaults and again by the functional
    # per-package no_std profiles; asking Cargo for `std` on thumb would test an
    # impossible feature combination instead of the supported contract.
    for target_label in ("linux-x86-64", "linux-aarch64", "wasm"):
        for profile, feature_args in profiles:
            matrix.append(
                (
                    f"{target_label}:{profile}",
                    targets[target_label],
                    profile,
                    feature_args,
                )
            )
    matrix.append(
        (
            "no-std:no-default-features",
            targets["no-std"],
            "no-default-features",
            ["--no-default-features"],
        )
    )
    return matrix


def is_exact_requirement(requirement: str) -> bool:
    return (
        re.fullmatch(
            r"=\s*[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?",
            requirement.strip(),
        )
        is not None
    )


def has_crate_level_forbid(text: str) -> bool:
    """Recognize an unconditional leading inner crate attribute only."""

    masked = mask_rust(text)[1]
    index = 1 if masked.startswith("\ufeff") else 0
    if masked.startswith("#!", index) and not masked.startswith("#![", index):
        newline = masked.find("\n", index)
        index = len(masked) if newline == -1 else newline + 1

    while index < len(masked):
        while index < len(masked) and masked[index].isspace():
            index += 1
        if not masked.startswith("#![", index):
            return False
        start = index
        index += 3
        depth = 1
        while index < len(masked) and depth:
            if masked[index] == "[":
                depth += 1
            elif masked[index] == "]":
                depth -= 1
            index += 1
        if depth:
            return False
        if FORBID_ATTRIBUTE.fullmatch(masked[start:index].strip()):
            return True
    return False


def cargo_target_sources(
    audit: BoundaryAudit, package: dict[str, Any], root: Path
) -> set[Path]:
    required: set[Path] = set()
    for target in package.get("targets", []):
        kinds = set(target.get("kind", []))
        if kinds & DEV_TARGET_KINDS:
            continue
        source = Path(target.get("src_path", "")).resolve()
        try:
            relative = source.relative_to(root)
        except ValueError:
            audit.fail(
                package_label(package),
                f"Cargo target source escapes its package: {source}",
            )
            continue
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            audit.fail(
                package_label(package),
                f"Cargo target source is under a skipped directory: {relative}",
            )
            continue
        if not source.is_file():
            audit.fail(
                package_label(package),
                f"Cargo target source is missing: {relative}",
            )
            continue
        if source.suffix != ".rs":
            audit.fail(
                package_label(package),
                f"Cargo target source is not Rust: {relative}",
            )
            continue
        required.add(source)
    return required


def iter_manifest_dependencies(
    manifest: dict[str, Any],
) -> Iterable[tuple[str, str, Any]]:
    for table_name in ("dependencies", "build-dependencies"):
        for name, specification in manifest.get(table_name, {}).items():
            yield table_name, name, specification
    for target_name, target_table in manifest.get("target", {}).items():
        if not isinstance(target_table, dict):
            continue
        for table_name in ("dependencies", "build-dependencies"):
            for name, specification in target_table.get(table_name, {}).items():
                yield f"target.{target_name}.{table_name}", name, specification


def audit_packaged_manifest(
    audit: BoundaryAudit, package_name: str, manifest_path: Path
) -> None:
    try:
        manifest = tomllib.loads(manifest_path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        audit.fail(package_name, f"cannot parse packaged Cargo.toml: {error}")
        return
    for table_name, dependency_name, specification in iter_manifest_dependencies(
        manifest
    ):
        if isinstance(specification, str):
            requirement = specification
        elif isinstance(specification, dict):
            requirement = specification.get("version", "")
        else:
            requirement = ""
        if not isinstance(requirement, str) or not is_exact_requirement(requirement):
            audit.fail(
                package_name,
                "packaged normal/build dependency is not exactly pinned: "
                f"{table_name}.{dependency_name} {requirement!r}",
            )


def tail(output: str, lines: int = 20) -> str:
    selected = output.strip().splitlines()[-lines:]
    return " | ".join(selected) if selected else "no diagnostic output"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def native_file_reason(path: Path) -> str | None:
    name = path.name
    if VERSIONED_SHARED_OBJECT.search(name) or VERSIONED_DYLIB.search(name):
        return "versioned shared-library filename"
    try:
        with path.open("rb") as handle:
            header = handle.read(32)
    except OSError as error:
        return f"unreadable file while checking native magic ({error})"
    for magic, description in NATIVE_MAGIC:
        if header.startswith(magic):
            return description
    if header[:4] in MACH_O_MAGIC:
        return "Mach-O binary"
    return None


def safe_extract(archive: Path, destination: Path) -> None:
    destination = destination.resolve()
    with tarfile.open(archive, "r:gz") as package:
        for member in package.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination):
                raise ValueError(f"archive member escapes destination: {member.name}")
            if member.issym() or member.islnk():
                raise ValueError(f"archive contains a link: {member.name}")
        package.extractall(destination, filter="data")


def mask_rust(text: str) -> tuple[str, str]:
    """Return (comments-masked, comments-and-literals-masked) Rust text."""

    commentless = list(text)
    code_only = list(text)

    def mask(start: int, end: int, *, comments_too: bool) -> None:
        for index in range(start, end):
            if text[index] == "\n":
                continue
            code_only[index] = " "
            if comments_too:
                commentless[index] = " "

    index = 0
    length = len(text)
    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end == -1 else end
            mask(index, end, comments_too=True)
            index = end
            continue
        if text.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            mask(index, end, comments_too=True)
            index = end
            continue

        raw_match = re.match(r"(?:br|cr|r)(#{0,255})\"", text[index:])
        if raw_match:
            hashes = raw_match.group(1)
            terminator = '"' + hashes
            content_start = index + raw_match.end()
            terminator_at = text.find(terminator, content_start)
            end = length if terminator_at == -1 else terminator_at + len(terminator)
            mask(index, end, comments_too=False)
            index = end
            continue

        prefix_length = 0
        if text.startswith(('b"', 'c"'), index):
            prefix_length = 1
        if text[index + prefix_length : index + prefix_length + 1] == '"':
            end = index + prefix_length + 1
            escaped = False
            while end < length:
                character = text[end]
                end += 1
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    break
            mask(index, end, comments_too=False)
            index = end
            continue

        index += 1

    return "".join(commentless), "".join(code_only)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def audit_source_tree(
    audit: BoundaryAudit,
    label: str,
    root: Path,
    native_extensions: set[str],
    *,
    check_internal_entropy: bool,
    scan_all_rust: bool,
    required_rust_files: set[Path],
) -> None:
    findings: dict[str, list[str]] = defaultdict(list)
    native_files: list[tuple[str, str]] = []
    symlinks: list[str] = []
    normalized_extensions = {extension.lower() for extension in native_extensions}
    required_resolved = {path.resolve() for path in required_rust_files}
    scanned_required: set[Path] = set()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            continue
        if path.is_symlink():
            symlinks.append(relative.as_posix())
            continue
        if not path.is_file():
            continue
        native_reason = native_file_reason(path)
        if path.suffix.lower() in normalized_extensions:
            native_reason = native_reason or f"native extension {path.suffix}"
        if path.name.lower() in NATIVE_FILENAMES:
            native_reason = native_reason or "native build-system filename"
        if native_reason:
            native_files.append((relative.as_posix(), native_reason))
        if path.suffix.lower() != ".rs":
            continue
        resolved = path.resolve()
        if (
            not scan_all_rust
            and relative.parts
            and relative.parts[0] in {"benches", "examples", "tests"}
            and resolved not in required_resolved
        ):
            continue
        if resolved in required_resolved:
            scanned_required.add(resolved)

        text = path.read_text(errors="replace")
        commentless, code_only = mask_rust(text)
        patterns: list[tuple[str, re.Pattern[str], str]] = [
            ("unsafe Rust", UNSAFE_TOKEN, code_only),
            ("foreign ABI", FOREIGN_ABI, code_only),
            ("native link/export attribute", LINK_ATTRIBUTE, code_only),
            ("FFI/ABI representation attribute", ABI_ATTRIBUTE, code_only),
            ("inline/global assembly", ASSEMBLY_MACRO, code_only),
            ("architecture intrinsic", ARCH_INTRINSIC, code_only),
            ("FFI API", FFI_API, code_only),
            ("native build API", NATIVE_BUILD_API, code_only),
            ("build-script native link directive", BUILD_LINK_DIRECTIVE, commentless),
        ]
        is_test_module = "tests" in relative.parts or relative.name in {
            "test.rs",
            "tests.rs",
        }
        is_production_source = (
            (relative.parts and relative.parts[0] == "src" and not is_test_module)
            or (relative.parts and relative.parts[0] == "fuzz_targets")
        )
        if (
            check_internal_entropy
            and relative.parts
            and relative.parts[0] == "src"
            and not is_test_module
        ):
            patterns.append(("internally sourced OS/random entropy", INTERNAL_ENTROPY, code_only))
        if relative.parts and relative.parts[0] == "src" and not is_test_module:
            patterns.append(
                (
                    "growable zeroizing byte storage",
                    GROWABLE_ZEROIZING_BYTES,
                    code_only,
                )
            )
            patterns.append(
                (
                    "inferred growable zeroizing byte storage",
                    INFERRED_GROWABLE_ZEROIZING_BYTES,
                    code_only,
                )
            )
            patterns.append(
                (
                    "non-wiping secret string export",
                    SECRET_STRING_EXPORT,
                    code_only,
                )
            )
            patterns.extend(
                (
                    ("unprotected EC scalar import", UNPROTECTED_EC_SCALAR_IMPORT, code_only),
                    (
                        "unprotected ECIES shared coordinate",
                        UNPROTECTED_ECIES_SHARED_COORDINATE,
                        code_only,
                    ),
                    (
                        "unprotected streaming plaintext scratch",
                        UNPROTECTED_STREAMING_PLAINTEXT,
                        code_only,
                    ),
                    (
                        "unprotected HChaCha subkey output",
                        UNPROTECTED_HCHACHA_OUTPUT,
                        code_only,
                    ),
                    (
                        "unprotected GCM/GHASH keyed scratch",
                        UNPROTECTED_GCM_KEYED_SCRATCH,
                        code_only,
                    ),
                    (
                        "unprotected ML-DSA challenge scratch",
                        UNPROTECTED_MLDSA_CHALLENGE_SCRATCH,
                        code_only,
                    ),
                    (
                        "unprotected high-level key copy",
                        UNPROTECTED_HIGH_LEVEL_KEY_COPY,
                        code_only,
                    ),
                    (
                        "unprotected ECDSA nonce-point coordinate",
                        UNPROTECTED_ECDSA_CANDIDATE_X,
                        code_only,
                    ),
                    (
                        "misleading manual secret-cleanup abstraction",
                        MISLEADING_SECURE_OPERATION_API,
                        code_only,
                    ),
                    (
                        "removed raw constant-time convenience API",
                        REMOVED_CONSTANT_TIME_CONVENIENCE,
                        code_only,
                    ),
                )
            )
            if check_internal_entropy:
                patterns.append(
                    (
                        "raw secret byte output API",
                        RAW_SECRET_BYTE_OUTPUT,
                        code_only,
                    )
                )
        if is_production_source and not (
            "dcrypt-internal" in label and relative.as_posix() == "src/random.rs"
        ):
            patterns.append(
                (
                    "direct fallible RNG fill outside the zero-on-error boundary",
                    DIRECT_RNG_FILL,
                    code_only,
                )
            )
        target_path = relative.as_posix()
        targeted_lifecycle_source = (
            "dcrypt-algorithms" in label
            or ("dcrypt-internal" in label and target_path == "src/random.rs")
            or (
                "dcrypt-sign" in label
                and target_path
                in {
                    "src/dilithium/sign.rs",
                    "src/dilithium/encoding.rs",
                    "src/eddsa/field.rs",
                    "src/eddsa/scalar.rs",
                    "src/eddsa/point.rs",
                    "src/eddsa/ed25519/mod.rs",
                    "src/ecdsa/p224/mod.rs",
                    "src/ecdsa/p256/mod.rs",
                    "src/ecdsa/p384/mod.rs",
                    "src/ecdsa/p521/mod.rs",
                }
            )
        )
        if targeted_lifecycle_source:
            scratch_pattern = TARGETED_SECRET_SCRATCH.get(target_path)
            if scratch_pattern is not None:
                patterns.append(
                    (
                        "unprotected targeted secret scratch",
                        scratch_pattern,
                        code_only,
                    )
                )
                for requirement in TARGETED_LIFECYCLE_REQUIREMENTS[target_path]:
                    if requirement.search(code_only) is None:
                        findings["missing targeted zeroizing lifecycle guard"].append(
                            relative.as_posix()
                        )
        for kind, pattern, searchable in patterns:
            match = pattern.search(searchable)
            if match:
                findings[kind].append(
                    f"{relative.as_posix()}:{line_number(searchable, match.start())}"
                )

    if native_files:
        first_path, first_reason = native_files[0]
        audit.fail(
            label,
            f"contains {len(native_files)} native source/binary file(s); "
            f"first={first_path} ({first_reason})",
        )
    missing_required = sorted(
        path.as_posix() for path in required_resolved - scanned_required
    )
    if missing_required:
        audit.fail(
            label,
            "Cargo target Rust source was not scanned; "
            f"first={missing_required[0]}",
        )
    if symlinks:
        audit.fail(label, f"contains {len(symlinks)} symlink(s); first={symlinks[0]}")
    for kind, locations in sorted(findings.items()):
        audit.fail(
            label,
            f"{kind} found in {len(locations)} Rust file(s); first={locations[0]}",
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="exercise the Rust lexical masks and forbidden-pattern detectors",
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="run metadata and source/package audits without compiler target checks",
    )
    parser.add_argument(
        "--list-classified-workspaces",
        action="store_true",
        help="print the authoritative excluded-workspace category and path pairs",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=PROJECT_ROOT / "target" / "implementation-boundary" / "report.json",
    )
    return parser.parse_args()


def self_test() -> None:
    sample = r'''
// unsafe { extern "C" { } }
/* unsafe fn nested() { /* extern "C" {} */ } */
const WORD: &str = "unsafe extern \\"C\\" cargo:rustc-link-lib=x";
const RAW: &str = r###"unsafe /* extern \\"C\\" */"###;
#![forbid(unsafe_code)]
let secret: Zeroizing<Vec<u8>> = todo!();
let inferred = Zeroizing::new(
    STANDARD.decode(encoded)?
);
fn to_secure_string(&self) -> String { todo!() }
pub fn new(data: [u8; 32]) -> Result<Self> {
    Self::validate_canonical_nonzero(&data)?;
    todo!()
}
let mut z_bytes = shared_point.x_coordinate_bytes();
let mut buffer = [0u8; 8192];
fn hchacha20(key: &[u8; 32]) -> [u8; 32] { todo!() }
fn generate_j0() -> Result<[u8; 16]> { todo!() }
let mut signs = [0u8; 8];
let mut key_data = [0u8; 32];
let candidate_x = kg.x_coordinate_bytes();
pub struct SecureOperationBuilder<T>(T);
pub fn ct_xor<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] { *a }
fn derive_key(input: &[u8]) -> Result<Vec<u8>> { todo!() }
rng.try_fill_bytes(&mut secret)?;
let mut key_words = [0u32; 8];
unsafe fn bad() {}
extern "C" { fn foreign(); }
#[link(name = "native")]
#[unsafe(no_mangle)]
#[repr(C)]
#[target_feature(enable = "sse2")]
global_asm!("nop");
core::arch::asm!("nop");
let _: *mut core::ffi::c_void;
cc::Build::new();
println!("cargo:rustc-link-lib=native");
'''
    commentless, code_only = mask_rust(sample)
    assert len(commentless) == len(sample)
    assert len(code_only) == len(sample)
    assert FORBID_ATTRIBUTE.search(code_only)
    assert len(UNSAFE_TOKEN.findall(code_only)) == 2
    assert len(FOREIGN_ABI.findall(commentless)) == 1
    assert len(LINK_ATTRIBUTE.findall(code_only)) == 2
    assert len(ABI_ATTRIBUTE.findall(code_only)) == 2
    assert len(ASSEMBLY_MACRO.findall(code_only)) == 2
    assert len(ARCH_INTRINSIC.findall(code_only)) == 1
    assert len(FFI_API.findall(code_only)) == 2
    assert len(NATIVE_BUILD_API.findall(code_only)) == 1
    assert len(BUILD_LINK_DIRECTIVE.findall(commentless)) == 2
    assert len(GROWABLE_ZEROIZING_BYTES.findall(code_only)) == 1
    assert len(INFERRED_GROWABLE_ZEROIZING_BYTES.findall(code_only)) == 1
    assert len(SECRET_STRING_EXPORT.findall(code_only)) == 1
    assert len(UNPROTECTED_EC_SCALAR_IMPORT.findall(code_only)) == 1
    assert len(UNPROTECTED_ECIES_SHARED_COORDINATE.findall(code_only)) == 1
    assert len(UNPROTECTED_STREAMING_PLAINTEXT.findall(code_only)) == 1
    assert len(UNPROTECTED_HCHACHA_OUTPUT.findall(code_only)) == 1
    assert len(UNPROTECTED_GCM_KEYED_SCRATCH.findall(code_only)) == 1
    assert len(UNPROTECTED_MLDSA_CHALLENGE_SCRATCH.findall(code_only)) == 1
    assert len(UNPROTECTED_HIGH_LEVEL_KEY_COPY.findall(code_only)) == 1
    assert UNPROTECTED_HCHACHA_OUTPUT.search("let mut state = [0u32; 16];")
    assert UNPROTECTED_HCHACHA_OUTPUT.search("let words = [state[0], state[1]];")
    assert UNPROTECTED_GCM_KEYED_SCRATCH.search("let mut h_copy = [0u8; 16];")
    assert UNPROTECTED_HIGH_LEVEL_KEY_COPY.search(
        "let mut encryption_key_arr = [0u8; CHACHA20POLY1305_KEY_LEN];"
    )
    assert UNPROTECTED_HIGH_LEVEL_KEY_COPY.search("let mut buffer_bytes = [0u8; 32];")
    assert len(UNPROTECTED_ECDSA_CANDIDATE_X.findall(code_only)) == 1
    assert ECDSA_PROTECTED_CANDIDATE_X.search(
        "let r_bytes = Zeroizing::new(kg.x_coordinate_bytes());"
    )
    assert not UNPROTECTED_ECDSA_CANDIDATE_X.search(
        "let r_bytes = Zeroizing::new(kg.x_coordinate_bytes());"
    )
    assert len(MISLEADING_SECURE_OPERATION_API.findall(code_only)) == 1
    assert len(REMOVED_CONSTANT_TIME_CONVENIENCE.findall(code_only)) == 1
    assert ARGON2_BLOCK_GUARDED_ZEROIZE.search(
        "impl Zeroize for Block { fn zeroize(&mut self) { self.0.zeroize(); } }"
    )
    assert not ARGON2_BLOCK_GUARDED_ZEROIZE.search(
        "impl Zeroize for Block { fn zeroize(&mut self) { "
        "self.0.iter_mut().for_each(|byte| *byte = 0); } }"
    )
    assert len(RAW_SECRET_BYTE_OUTPUT.findall(code_only)) == 1
    assert len(DIRECT_RNG_FILL.findall(code_only)) == 1
    assert (
        len(TARGETED_SECRET_SCRATCH["src/xof/blake3/mod.rs"].findall(code_only))
        == 1
    )
    assert TARGETED_SECRET_SCRATCH["src/random.rs"].search(
        "let mut bytes = [0u8; 32];"
    )
    assert TARGETED_SECRET_SCRATCH["src/random.rs"].search(
        "#[derive(Clone)]\npub struct ChaCha20Rng { key: [u32; 8] }"
    )
    assert TARGETED_SECRET_SCRATCH["src/block/aes/mod.rs"].search(
        "let mut round_keys_u32 = [0u32; 44];"
    )
    assert TARGETED_SECRET_SCRATCH["src/block/modes/cbc/mod.rs"].search(
        "let mut block = [0u8; 16];"
    )
    assert TARGETED_SECRET_SCRATCH["src/eddsa/field.rs"].search(
        "fn pow(&self) { let mut accumulator = Self::one(); }"
    )
    assert TARGETED_SECRET_SCRATCH["src/eddsa/scalar.rs"].search(
        "fn to_bytes(&self) -> [u8; 32] { let mut bytes = [0u8; 32]; }"
    )
    assert TARGETED_SECRET_SCRATCH["src/eddsa/scalar.rs"].search(
        "fn mul(&self) { let mut accumulator = Self::zero(); }"
    )
    assert TARGETED_SECRET_SCRATCH["src/eddsa/point.rs"].search(
        "fn scalar_mult(&self) { let mut accumulator = Self::identity(); }"
    )
    assert TARGETED_SECRET_SCRATCH["src/ec/bls12_381/g1.rs"].search(
        "pub fn msm(points: &[G1Affine], scalars: &[Scalar]) -> Result<Self> { todo!() }"
    )
    assert TARGETED_SECRET_SCRATCH["src/ec/bls12_381/g2.rs"].search(
        "pub fn msm(points: &[G2Affine], scalars: &[Scalar]) -> Result<Self> { todo!() }"
    )
    assert UNSAFE_TOKEN.search("#![forbid(unsafe_code)]") is None
    assert has_crate_level_forbid("// header\n#![forbid(unsafe_code)]\nfn ok() {}")
    assert not has_crate_level_forbid("mod nested { #![forbid(unsafe_code)] }")
    assert not has_crate_level_forbid("fn first() {}\n#![forbid(unsafe_code)]")
    assert is_exact_requirement("=1.2.3")
    assert not is_exact_requirement("1.2.3")
    assert not is_exact_requirement("^1.2.3")
    classified = classified_excluded_workspaces(
        {
            "verification-workspace": "verification",
            "fuzz-workspace": "fuzz",
            "owned-excluded-workspaces": [{"path": "migration/tool"}],
        }
    )
    assert excluded_classification_difference(
        ["verification", "fuzz", "migration/tool"], classified
    ) == (set(), set())
    assert excluded_classification_difference(
        ["verification", "fuzz", "unclassified"], classified
    ) == ({"migration/tool"}, {"unclassified"})
    assert dependency_snapshot_difference(
        {"base64@0.22.1", "hex@0.4.3"},
        {"base64@0.22.1", "hex@0.4.3", "stale@1.0.0"},
    ) == (["stale@1.0.0"], [])
    assert dependency_snapshot_difference(
        {"base64@0.22.1", "unknown@1.0.0"},
        {"base64@0.22.1"},
    ) == ([], ["unknown@1.0.0"])
    identity_fixture = {
        "workspace_members": ["path+dcrypt-params@2.0.0"],
        "packages": [
            {"id": "path+dcrypt-params@2.0.0", "name": "dcrypt-params"},
            {"id": "registry+dcrypt-params@1.2.2", "name": "dcrypt-params"},
        ],
    }
    assert published_workspace_package_ids(identity_fixture, {"dcrypt-params"}) == {
        "path+dcrypt-params@2.0.0"
    }

    with tempfile.TemporaryDirectory(prefix="dcrypt-boundary-self-test-") as temp:
        root = Path(temp)
        (root / "lib.rs").write_text("pub type Opaque = core::ffi::c_void;\n")
        (root / "native.bin").write_bytes(b"\x7fELF" + b"\0" * 28)
        (root / "libexample.so.1").write_bytes(b"not really native")
        assert native_file_reason(root / "native.bin") == "ELF binary"
        assert (
            native_file_reason(root / "libexample.so.1")
            == "versioned shared-library filename"
        )
        audit = BoundaryAudit(root / "report.json")
        audit_source_tree(
            audit,
            "fixture",
            root,
            {".c"},
            check_internal_entropy=False,
            scan_all_rust=True,
            required_rust_files={root / "lib.rs"},
        )
        details = "\n".join(violation.detail for violation in audit.violations)
        assert "FFI API" in details
        assert "versioned shared-library filename" in details


def main() -> int:
    args = parse_args()
    if sys.version_info < (3, 11):
        print("error: Python 3.11 or newer is required", file=sys.stderr)
        return 2
    if args.list_classified_workspaces:
        try:
            policy = tomllib.loads(POLICY_PATH.read_text())
            for category, path in classified_excluded_workspaces(policy):
                print(f"{category}\t{path}")
        except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
            print(f"error: cannot list classified workspaces: {error}", file=sys.stderr)
            return 2
        return 0
    if args.self_test:
        self_test()
        print("implementation-boundary scanner self-test passed")
        return 0
    if not POLICY_PATH.is_file() or not LOCK_PATH.is_file():
        print("error: implementation-boundary.toml and tracked Cargo.lock are required", file=sys.stderr)
        return 2
    missing_commands = [
        command
        for command in ("cargo", "git", "rustc", "rustup")
        if shutil.which(command) is None
    ]
    if missing_commands:
        print(
            f"error: required command(s) unavailable: {', '.join(missing_commands)}",
            file=sys.stderr,
        )
        return 2

    try:
        policy = tomllib.loads(POLICY_PATH.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"error: cannot parse implementation-boundary.toml: {error}", file=sys.stderr)
        return 2
    if policy.get("schema-version") != 2:
        print("error: implementation-boundary.toml schema-version must be 2", file=sys.stderr)
        return 2
    audit = BoundaryAudit(args.report.resolve())
    audit.bind_git_head()
    tracked_lock = audit.command(
        ["git", "ls-files", "--error-unmatch", "--", "Cargo.lock"]
    )
    if tracked_lock.returncode != 0:
        audit.fail("Cargo.lock", "Cargo.lock must be git-tracked")
    published_names = set(policy["published-packages"])

    all_features = audit.cargo_metadata("all-features", ["--all-features"])
    no_default = audit.cargo_metadata("no-default-features", ["--no-default-features"])
    audit.collect_closure("all-features", all_features, published_names)
    audit.collect_closure("no-default-features", no_default, published_names)
    audit.audit_workspace_exclude_classification(policy)
    audit.audit_package_metadata(policy)
    audit.audit_fuzz_workspace(policy, all_features)
    audit.audit_owned_excluded_workspaces(policy, all_features)
    audit.audit_dependency_sources(policy, published_names)
    audit.package_and_audit_owned_sources(policy, all_features)

    if not args.scan_only:
        installed_targets = audit.validate_supported_targets(policy)
        audit.run_active_dependency_unsafe_scans(policy, installed_targets)
        audit.run_owned_excluded_active_scans(policy)
        audit.run_fuzz_active_scan(policy)
        audit.run_no_std_contract_checks(policy, published_names, installed_targets)

    audit.write_report(policy)
    print(f"Implementation-boundary report: {audit.report_path}")
    if audit.violations:
        print(f"FAILED: {len(audit.violations)} implementation-boundary violation(s)")
        for violation in sorted(audit.violations)[:250]:
            print(f"  - [{violation.scope}] {violation.detail}")
        if len(audit.violations) > 250:
            print(f"  ... {len(audit.violations) - 250} more; see the JSON report")
        return 1
    print("PASSED: zero unsafe Rust, native code, FFI, and internal OS entropy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
