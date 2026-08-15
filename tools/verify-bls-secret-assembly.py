#!/usr/bin/env python3
"""Fail closed if optimized BLS secret-scalar loops gain extra branches.

This is a compiler-output regression gate, not a general proof of constant
time. It checks the two concrete protected multiplication entry points on
every supported target. Each function must retain its reviewed control-flow
fingerprint: canonical-input rejection, two fixed-count loop backedges, and
only the reviewed target-specific copy scaffolding when LLVM emits it. It
also requires evidence that the secret bit is lowered through mask selection.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

SUPPORTED_TARGETS = {
    "x86_64-unknown-linux-gnu": "x86_64",
    "aarch64-unknown-linux-gnu": "aarch64",
    "thumbv7em-none-eabihf": "thumb",
    "wasm32-unknown-unknown": "wasm32",
}
GROUPS = ("G1Projective", "G2Projective")

# Bind the complete compiler emission, not only selected function bodies.  GAS
# directives, aliases, relocations, local constants, and lexical state outside
# a protected function can change the assembled program without changing that
# function's source text.  The release gate therefore accepts only the exact
# whole-file output independently reviewed for the two supported stable Rust
# compiler profiles.  The semantic checks below remain useful diagnostics, but
# this fingerprint is the primary fail-closed boundary.
COMPILER_PROFILES: dict[str, dict[str, object]] = {
    "rust-1.93.1": {
        "version": "rustc 1.93.1 (01f6ddf75 2026-02-11)",
        "hashes": {
            "x86_64-unknown-linux-gnu":
                "3bc0993b20f0f5d2a57e18a1e317158040828b9c68f7406bb4132f3ebc160382",
            "aarch64-unknown-linux-gnu":
                "f41c29bece26d7cd42071ac8a3037fd6bb8af2333d67257ed009dd231e9e79ad",
            "thumbv7em-none-eabihf":
                "97ec647cc1c209f54e700c3a9a6bb8d9158061c17542199a758cb32d4276e2d1",
            "wasm32-unknown-unknown":
                "b2926b10987a94919c1cf51930d4cd77a20f266f532851fc2ffc2d86922ca29a",
        },
    },
    "rust-1.97.1": {
        "version": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
        "hashes": {
            "x86_64-unknown-linux-gnu":
                "bb2d80dae4ba710a33e672aeb4fba9d4d1547efeefcaf4bc138103d35f134546",
            "aarch64-unknown-linux-gnu":
                "94097ce0bced9f000c0daa89de1716e259f28a8c1ff6b16272757d805ca69cf1",
            "thumbv7em-none-eabihf":
                "5ddfe428104e16a6b13a74c01abe9fdcc53c6a3193f4da50d5486790ac975d5e",
            "wasm32-unknown-unknown":
                "5950bc2cf310615bfba7ead04b125d87c534320af36bf694eec7ea6e4076c759",
        },
    },
}
EXPECTED_BRANCHES = {
    "x86_64-unknown-linux-gnu": {
        "G1Projective": ("je", "ja", "jne"),
        "G2Projective": ("je", "ja", "jne"),
    },
    "aarch64-unknown-linux-gnu": {
        # Rust 1.93 lowers the public canonical-input rejection to `tbz`,
        # while Rust 1.97 lowers the same validator result to `tst; b.eq`.
        # `aarch64_public_control_markers` binds either reviewed form to the
        # validator call and separately binds both fixed loop backedges.
        "G1Projective": (("tbz", "b.eq"), "b.hi", "b.ne"),
        "G2Projective": (("tbz", "b.eq"), "b.hi", "b.ne"),
    },
    "thumbv7em-none-eabihf": {
        "G1Projective": ("beq.w", "bhi.w", "bne.w"),
        "G2Projective": ("beq.w", "bhi.w", "bne.w"),
    },
    # wasm-ld retains constant-size memcpy guards which compare only immediate
    # lengths on Rust 1.93. Rust 1.97 removes those guards, leaving only the
    # validator result and two fixed-count loops. Both exact profiles are
    # dataflow-bound by `wasm_public_control_markers`.
    "wasm32-unknown-unknown": {
        "G1Projective": (("br_if",) * 4, ("br_if",) * 3),
        "G2Projective": (("br_if",) * 7, ("br_if",) * 3),
    },
}

# Complete function-closure fingerprints for the two independently reviewed
# compiler profiles used by the local and hosted release gates. Each closure
# includes the exact executable-section preamble, raw function body, and every
# referenced out-of-body local object.
EXPECTED_FUNCTION_CLOSURE_SHA256: dict[str, dict[str, frozenset[str]]] = {
    "x86_64-unknown-linux-gnu": {
        "G1Projective": frozenset({
            "6ddb2ea16c5a1aa71914e06da50580afe61f991962f3f4d27887e4c83ab4fb65",
            "f98bdee3e9e7585392b91d74da0333d2e4e735b9fa62330f9233a5b7c9dcd854",
        }),
        "G2Projective": frozenset({
            "17f1b2fbc6da8c19aa86f4b001520cbe13c344a6e1b78d3a21dfaf531dea5249",
            "dbfd6016eaaa04c2a6bc049ba47e9e2af93483b585b5de6a5eab45e127d0bd68",
        }),
    },
    "aarch64-unknown-linux-gnu": {
        "G1Projective": frozenset({
            "dfbf25aa2f997f73e2b98abc488d8b9b3f3c6c73ef6a4dc7b13078acb8fe7c03",
            "aec9d927950ce119c68bf387674ce237844b735a83c7466e9daab41603c0a9a3",
        }),
        "G2Projective": frozenset({
            "8dc39086819ce0ae5f61b28c93e1d8e607675bf8079f0167ae57411fabafcffe",
            "6382934e780235a60ebed56bb0ec18a54dfb458053300a47be0f2a08785dfc7f",
        }),
    },
    "thumbv7em-none-eabihf": {
        "G1Projective": frozenset({
            "3bf6726d8964edba92d97ebc2631dff9949dae6a636d3790a0cfebac43135399",
            "05554abba7b9a3b5dadd931c28d257813cfb59780514c842551938905178833b",
        }),
        "G2Projective": frozenset({
            "32a5eae054cd0e033a05d862e36f88cdd2d43f0727f1e792ab032e5c689209c7",
            "0bb056404fe06f52cf17284fcc0a8acb226b05165a19d09e384471acf51aaad6",
        }),
    },
    "wasm32-unknown-unknown": {
        "G1Projective": frozenset({
            "c6bffd9321f16ba0f9f2db4f655d400d30cba90c1e1f2cba75ce73a1be0c3b09",
            "28ec6407396c9a76ba1b63cf6c47c4a2b484d3d18d96c5c55720532ba499c7b1",
        }),
        "G2Projective": frozenset({
            "e36d4f8dec49037e4f7ab11a255005e48e7fe462dd011f71d12dd9e4b772bc6b",
            "907d12294feb2927e72d6f8c737dc23063d89e39a185762cfd09d225c1ee8b60",
        }),
    },
}

# Rust emits a small, deterministic set of whole-file symbol deduplication
# aliases.  A bare GAS assignment can also redirect a call without changing
# the protected function text, so bind the complete sorted assignment set for
# each independently reviewed compiler profile.
EXPECTED_ASSIGNMENT_SHA256: dict[str, frozenset[str]] = {
    "x86_64-unknown-linux-gnu": frozenset({
        "4a72469a169670da606f9f68a19fac353307ff0d3b03e4a9530f0ffff09daad6",
        "914688057462993b33c247d17cb778cf53dafc65b2badfa54f8e60bc4db95acf",
    }),
    "aarch64-unknown-linux-gnu": frozenset({
        "077b775bf87ceff168b461e1c56635a2eaab3f5f4a236e3fb0a66e635e17888a",
        "74b62e2ed731766ff77a66de8d321b75a071c6ea8f617d9bf93c1d047b821341",
    }),
    "thumbv7em-none-eabihf": frozenset({
        "8b3341e7c961490a0d27304d7e34cde48bf3f132ca7fa4742feb1848387833bc",
        "1e537dc6925661ac5a02eb923039442b2be90565c128edd0bb6d5ff21012127e",
    }),
    "wasm32-unknown-unknown": frozenset({
        "1c382af66b001615da3442166471426e4253f7325ace7cfef374f9e9cb454ca6",
        "24d462bd7723a8920fce0e4bd98885ef1ba728360b3f809d7a0cfd8f3d2b722e",
    }),
}

BARE_ASSIGNMENT = re.compile(
    r"^\s*(?P<left>[A-Za-z_.$][A-Za-z0-9_.$]*)\s*=\s*"
    r"(?P<right>[A-Za-z_.$][A-Za-z0-9_.$]*)\s*$"
)
STATEFUL_DIRECTIVE = re.compile(
    r"^\s*\.(?:if\S*|elseif\S*|else|endif|macro|endm|exitm|purgem|"
    r"altmacro|noaltmacro|rept|endr|irp|irpc|include|incbin|req|unreq|"
    r"set|thumb_set|equ|equiv|eqv|weakref|symver|reloc|intel_syntax|"
    r"att_syntax|arch|arch_extension|cpu|option|machine|pushsection|"
    r"popsection|previous|subsection|comm|lcomm|arm|thumb)\b",
    re.IGNORECASE,
)


def assembly_code_lines(
    assembly: str, architecture: str
) -> tuple[list[str], list[str]]:
    """Return comment/string-masked statements and lexical-state violations."""

    code_lines: list[str] = []
    hazards: list[str] = []
    for line_number, line in enumerate(assembly.splitlines(), start=1):
        code: list[str] = []
        in_string = False
        escaped = False
        index = 0
        while index < len(line):
            character = line[index]
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                    code.append('""')
                index += 1
                continue
            if character == '"':
                in_string = True
                index += 1
                continue
            if line.startswith(("/*", "*/"), index):
                hazards.append(f"line {line_number}: C-style block comment")
                break
            if architecture == "wasm32" and line.startswith(";;", index):
                break
            if architecture in {"x86_64", "wasm32"} and character == "#":
                break
            if architecture == "thumb" and character == "@":
                break
            if architecture in {"aarch64", "thumb", "wasm32"} and line.startswith(
                "//", index
            ):
                break
            if character == ";":
                hazards.append(f"line {line_number}: statement separator")
                break
            code.append(character)
            index += 1
        if in_string:
            hazards.append(f"line {line_number}: unterminated quoted string")
        statement = "".join(code).strip()
        if statement:
            if re.match(r"^[A-Za-z0-9_.$]+:\s*\S", statement):
                hazards.append(f"line {line_number}: statement after label")
            if (
                re.match(r"^[A-Za-z_.$][A-Za-z0-9_.$]*\s*=", statement)
                and BARE_ASSIGNMENT.fullmatch(statement) is None
            ):
                hazards.append(f"line {line_number}: noncanonical symbol assignment")
            code_lines.append(statement)
    return code_lines, hazards


def bare_assignments(code_lines: list[str]) -> list[tuple[str, str]]:
    """Return canonical whole-file GAS symbol assignments."""

    assignments: list[tuple[str, str]] = []
    for line in code_lines:
        match = BARE_ASSIGNMENT.fullmatch(line)
        if match is not None:
            assignments.append((match.group("left"), match.group("right")))
    return assignments


def assignment_fingerprint(assignments: list[tuple[str, str]]) -> str:
    canonical = "\n".join(
        sorted(f"{left} = {right}" for left, right in assignments)
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def protected_call_targets(body: str, architecture: str) -> set[str]:
    """Collect every exact symbol whose implementation the body can invoke."""

    targets: set[str] = set()
    for line in executable_lines(body, architecture):
        if architecture == "x86_64":
            direct = re.fullmatch(r"callq? (?P<target>[^*]\S*)", line)
            indirect = re.fullmatch(r"callq? \*\s*(?P<target>\S+)", line)
            got_load = re.fullmatch(
                r"movq (?P<target>\S+)@GOTPCREL\(%rip\), %r\d+", line
            )
            match = direct or indirect or got_load
            if match is None:
                continue
            target = match.group("target")
            if target.startswith("%"):
                continue
            target = re.sub(r"@GOTPCREL\(%rip\)$", "", target)
            targets.add(target)
        else:
            mnemonic = "call" if architecture == "wasm32" else "bl"
            match = re.fullmatch(rf"{mnemonic} (?P<target>\S+)", line)
            if match is not None:
                targets.add(match.group("target"))
    return targets


def external_protected_call_target(target: str) -> bool:
    """Classify reviewed runtime/dependency callees that stay undefined here."""

    return target in {"memcpy", "__aeabi_memclr8", "__aeabi_memcpy8"} or bool(
        "constant_time" in target
        and "Choice" in target
        and "Zeroize" in target
        and "zeroize" in target
    )


def call_target_binding_errors(
    assembly: str,
    functions: dict[str, list[str]],
    architecture: str,
    assignments: list[tuple[str, str]],
    *,
    require_definitions: bool,
) -> list[str]:
    """Reject aliases or local overrides of the exact reviewed callees."""

    targets = {
        target
        for bodies in functions.values()
        for body in bodies
        for target in protected_call_targets(body, architecture)
    }
    errors: list[str] = []
    for left, right in assignments:
        if left in targets or right in targets:
            errors.append(f"protected call target alias: {left} = {right}")

    if not require_definitions:
        return errors

    label_counts = {
        target: sum(
            line.strip() == f"{target}:" for line in assembly.splitlines()
        )
        for target in targets
    }
    for target, count in sorted(label_counts.items()):
        expected = 0 if external_protected_call_target(target) else 1
        if count != expected:
            errors.append(
                f"protected call target {target!r} has {count} local definitions; "
                f"expected {expected}"
            )
    return errors


def instruction(line: str) -> str:
    line = line.split("#", 1)[0].split("//", 1)[0].strip()
    if not line or line.startswith(".") or line.endswith(":"):
        return ""
    return line.split(None, 1)[0].lower()


def executable_lines(body: str, architecture: str) -> list[str]:
    """Return normalized executable assembly, excluding labels/comments/directives."""

    executable: list[str] = []
    for raw_line in body.splitlines():
        if architecture == "x86_64":
            line = raw_line.split("#", 1)[0]
        elif architecture == "wasm32":
            line = (
                raw_line.split("#", 1)[0]
                .split("//", 1)[0]
                .split(";;", 1)[0]
            )
        elif architecture == "thumb":
            line = raw_line.split("@", 1)[0].split("//", 1)[0]
        else:
            line = raw_line.split("//", 1)[0]
        line = line.strip()
        if not line or line.startswith(".") or line.endswith(":"):
            continue
        executable.append(" ".join(line.split()))
    return executable


def conditional_branch_mnemonics(body: str, architecture: str) -> list[str]:
    mnemonics = [instruction(line) for line in body.splitlines()]
    if architecture == "x86_64":
        return [
            value
            for value in mnemonics
            if (
                value.startswith("j")
                and value not in {"jmp", "jmpq", "ljmp"}
            )
            or value.startswith("loop")
        ]
    if architecture == "aarch64":
        return [
            value
            for value in mnemonics
            if value.startswith(("b.", "bc."))
            or value in {"cbz", "cbnz", "tbz", "tbnz"}
        ]
    if architecture == "thumb":
        conditions = (
            "beq", "bne", "bcs", "bcc", "bhs", "blo", "bmi", "bpl",
            "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble",
        )
        return [
            value
            for value in mnemonics
            if value in {"cbz", "cbnz"}
            or any(
                value in {condition, f"{condition}.n", f"{condition}.w"}
                for condition in conditions
            )
        ]
    if architecture == "wasm32":
        return [
            value
            for value in mnemonics
            if value in {"br_if", "if"} or value.startswith("br_on_")
        ]
    raise ValueError(f"unsupported architecture: {architecture}")


def x86_reviewed_symbol(target: str, group: str, operation: str) -> bool:
    """Match only the reviewed legacy or v0-mangled callable symbols."""

    target_suffix = r"@gotpcrel\(%rip\)"
    curve = "1" if group == "G1Projective" else "2"
    if operation in {"add", "double"}:
        method = "3add" if operation == "add" else "6double"
        legacy = (
            rf"_zn17dcrypt_algorithms2ec9bls12_3812g{curve}"
            rf"12g{curve}projective{method}17h[0-9a-f]{{16}}e{target_suffix}"
        )
        v0 = (
            rf"_rnvms1a_ntntntc[0-9a-z]+_17dcrypt_algorithms2ec9bls12_3812g{curve}"
            rf"ntb6_12g{curve}projective{method}{target_suffix}"
        )
        return re.fullmatch(rf"(?:{legacy}|{v0})", target) is not None
    if operation == "choice-zeroize":
        legacy = (
            r"_zn92_\$lt\$dcrypt_internal\.\.constant_time\.\.choice\$u20\$as\$u20\$"
            r"dcrypt_internal\.\.zeroing\.\.zeroize\$gt\$7zeroize17h[0-9a-f]{16}e"
            + target_suffix
        )
        v0 = (
            r"_rnvxs3_ntc[0-9a-z]+_15dcrypt_internal13constant_timentb5_6choice"
            r"ntntb7_7zeroing7zeroize7zeroize"
            + target_suffix
        )
        return re.fullmatch(rf"(?:{legacy}|{v0})", target) is not None
    if operation == "array-zeroize":
        legacy = (
            r"_zn76_\$lt\$\$u5b\$t\$u3b\$\$u20\$n\$u5d\$\$u20\$as\$u20\$"
            r"dcrypt_internal\.\.zeroing\.\.zeroize\$gt\$7zeroize17h[0-9a-f]{16}e"
            + target_suffix
        )
        v0 = (
            r"_rnvxs0_ntc[0-9a-z]+_15dcrypt_internal7zeroingayj6_ntb5_7zeroize"
            r"7zeroizec[0-9a-z]+_17dcrypt_algorithms"
            + target_suffix
        )
        return re.fullmatch(rf"(?:{legacy}|{v0})", target) is not None
    raise ValueError(f"unsupported reviewed x86 operation: {operation}")


def reviewed_validator_symbol(target: str) -> bool:
    """Match only the reviewed legacy or v0 BLS scalar validator symbol."""

    legacy = (
        r"_ZN17dcrypt_algorithms2ec9bls12_3816scalar"
        r"25secret_be_bytes_are_valid17h[0-9a-f]{16}E"
    )
    v0 = (
        r"_RNvNtNtNtC[0-9A-Za-z]+_17dcrypt_algorithms2ec9bls12_3816scalar"
        r"25secret_be_bytes_are_valid"
    )
    return re.fullmatch(rf"(?:{legacy}|{v0})", target) is not None


def exact_validator_call_is_reviewed(body: str, architecture: str) -> bool:
    """Require one exact direct call to the canonical BLS scalar validator."""

    call_mnemonic = "call" if architecture == "wasm32" else r"(?:callq?|bl)"
    calls: list[str] = []
    for line in executable_lines(body, architecture):
        match = re.fullmatch(rf"{call_mnemonic} (?P<target>\S+)", line)
        if match is None:
            continue
        target = match.group("target")
        if "secret_be_bytes_are_valid" in target:
            calls.append(target)
    return len(calls) == 1 and reviewed_validator_symbol(calls[0])


def x86_indirect_call_violations(body: str, group: str) -> list[str]:
    """Require every x86 indirect call to have a reviewed immutable target."""

    lines = [
        " ".join(raw.split("#", 1)[0].strip().lower().split())
        for raw in body.splitlines()
    ]
    calls: dict[str, list[int]] = {}
    violations: list[str] = []
    for index, line in enumerate(lines):
        call = re.fullmatch(r"callq? (?P<operands>.+)", line)
        if call is None or not call.group("operands").startswith("*"):
            continue
        match = re.fullmatch(r"\*\s*(?P<target>\S+)", call.group("operands"))
        if match is None:
            violations.append(line)
            continue
        target = match.group("target")
        register = re.fullmatch(r"%(r(?:\d+|[a-z]+))", target)
        if register is not None:
            calls.setdefault(register.group(1), []).append(index)
            continue
        fixed_got_target = (
            target == "memcpy@gotpcrel(%rip)"
            or x86_reviewed_symbol(target, group, "add")
            or x86_reviewed_symbol(target, group, "choice-zeroize")
        )
        if not fixed_got_target:
            violations.append(line)

    expected_registers = {
        "G1Projective": {"r12": "double", "r14": "array-zeroize"},
        "G2Projective": {"r13": "double", "r14": "array-zeroize"},
    }[group]
    for register, call_indices in calls.items():
        operation = expected_registers.get(register)
        if operation is None:
            violations.extend(lines[index] for index in call_indices)
            continue
        initializer = re.compile(
            rf"movq (?P<target>\S+@gotpcrel\(%rip\)), %{re.escape(register)}$"
        )
        initializers = [
            (index, match)
            for index, line in enumerate(lines[: call_indices[0]])
            if (match := initializer.fullmatch(line)) is not None
        ]
        if len(initializers) != 1:
            violations.extend(lines[index] for index in call_indices)
            continue
        initializer_index, initializer_match = initializers[0]
        target = initializer_match.group("target")
        if not x86_reviewed_symbol(target, group, operation):
            violations.extend(lines[index] for index in call_indices)
            continue
        alias = re.compile(rf"%{re.escape(register)}(?:b|w|d)?\b")
        allowed_call = re.compile(rf"callq? \*\s*%{re.escape(register)}$")
        for index in range(initializer_index + 1, call_indices[-1] + 1):
            if alias.search(lines[index]) and allowed_call.fullmatch(lines[index]) is None:
                violations.append(lines[index])
    return violations


def forbidden_control(body: str, architecture: str, group: str) -> list[str]:
    """Identify unreviewed indirect, table, and predicated control transfers."""

    found: list[str] = []
    reviewed_thumb_returns = 0
    for raw_line in body.splitlines():
        if architecture == "x86_64":
            line = raw_line.split("#", 1)[0].strip().lower()
        else:
            line = raw_line.split("//", 1)[0].strip().lower()
        if not line or line.startswith(".") or line.endswith(":"):
            continue
        parts = line.split(None, 1)
        mnemonic = parts[0]
        operands = parts[1].strip() if len(parts) == 2 else ""
        if architecture == "x86_64":
            forbidden_prefixes = {
                "notrack", "bnd", "data16", "addr16", "addr32", "rex64",
                "rep", "repe", "repz", "repne", "repnz", "lock",
                "cs", "ds", "es", "fs", "gs", "ss",
            }
            if (
                mnemonic in forbidden_prefixes
                or mnemonic.startswith("rex")
                or mnemonic == "lcall"
                or (mnemonic.startswith("call") and mnemonic not in {"call", "callq"})
                or (
                    mnemonic in {"jmp", "jmpq", "ljmp"}
                    and operands.startswith("*")
                )
            ):
                found.append(line)
        elif architecture == "aarch64":
            if mnemonic in {
                "br", "blr", "braa", "brab", "braaz", "brabz",
                "blraa", "blrab", "blraaz", "blrabz", "eret", "eretaa",
                "eretab", "drps", "retaa", "retab",
            } or (mnemonic == "ret" and operands not in {"", "x30", "lr"}):
                found.append(line)
        elif architecture == "thumb":
            first_destination = operands.split(",", 1)[0].strip()
            writes_pc_list = re.search(r"\b(?:pc|r15)\b", operands) is not None
            reviewed_return = (
                mnemonic == "pop" and operands == "{r4, r5, r6, r7, pc}"
            )
            if reviewed_return:
                reviewed_thumb_returns += 1
            if (
                mnemonic in {"blx", "blxns", "bxns", "tbb", "tbh"}
                or re.fullmatch(r"it[te]{0,3}", mnemonic) is not None
                or (mnemonic == "bx" and operands not in {"lr", "r14"})
                or first_destination in {"pc", "r15"}
                or (writes_pc_list and not reviewed_return)
            ):
                found.append(line)
        elif architecture == "wasm32":
            if mnemonic in {
                "br_table", "call_indirect", "return_call_indirect", "call_ref",
                "return_call_ref", "return_call", "return",
            } or mnemonic.startswith("br_on_"):
                found.append(line)
        else:
            raise ValueError(f"unsupported architecture: {architecture}")
    if architecture == "x86_64":
        found.extend(x86_indirect_call_violations(body, group))
    elif architecture == "thumb" and reviewed_thumb_returns != 2:
        found.append(
            f"reviewed Thumb return count is {reviewed_thumb_returns}; expected 2"
        )
    return found


def selection_markers(body: str, architecture: str) -> dict[str, bool]:
    mnemonics = [
        line.split(None, 1)[0].lower()
        for line in executable_lines(body, architecture)
    ]

    def contains(pattern: str) -> bool:
        return any(re.fullmatch(pattern, mnemonic) for mnemonic in mnemonics)

    if architecture == "x86_64":
        return {
            "secret-bit extraction": contains(r"bt[a-z]*"),
            "set-to-mask": contains(r"set[a-z]+"),
            "masked AND": contains(r"v?pandn?"),
            "masked OR": contains(r"v?por"),
        }
    if architecture == "aarch64":
        return {
            "secret-bit extraction": contains(r"(?:lsr|lsrv|ubfx)"),
            "all-bits mask": contains(r"(?:neg|csetm)"),
            "branchless vector blend": contains(r"(?:bit|bif|bsl)"),
        }
    if architecture == "thumb":
        return {
            "secret-bit extraction": contains(r"(?:lsr|lsrs|lsrv|ubfx)"),
            "masked AND": contains(r"ands?"),
            "masked OR": contains(r"orrs?"),
        }
    if architecture == "wasm32":
        return {
            "secret-bit extraction": contains(r"(?:i32|i64)\.shr_u"),
            "masked AND": contains(r"(?:i32|i64)\.and"),
            "masked XOR blend": contains(r"(?:i32|i64)\.xor"),
        }
    raise ValueError(f"unsupported architecture: {architecture}")


def normalized_lines_with_labels(body: str, architecture: str) -> list[str]:
    """Return lowercased instructions and labels, excluding reviewed directives."""

    lines: list[str] = []
    for raw_line in body.splitlines():
        if architecture == "x86_64":
            line = raw_line.split("#", 1)[0]
        elif architecture == "thumb":
            line = raw_line.split("@", 1)[0].split("//", 1)[0]
        else:
            line = raw_line.split("//", 1)[0]
        line = line.strip()
        if not line or (line.startswith(".") and not line.endswith(":")):
            continue
        lines.append(" ".join(line.lower().split()))
    return lines


def previous_instruction(lines: list[str], index: int) -> int | None:
    for candidate in range(index - 1, -1, -1):
        if not lines[candidate].endswith(":"):
            return candidate
    return None


def unique_label_index(lines: list[str], label: str) -> int | None:
    matches = [index for index, line in enumerate(lines) if line == f"{label}:"]
    return matches[0] if len(matches) == 1 else None


def x86_public_control_markers(body: str) -> dict[str, bool]:
    """Bind all x86 conditional branches to public/fixed-count dataflow."""

    lines = normalized_lines_with_labels(body, "x86_64")
    branches = [
        index
        for index, line in enumerate(lines)
        if instruction(line) in {"je", "ja", "jne"}
    ]
    validator_ok = False
    inner_ok = False
    outer_ok = False
    if len(branches) == 3:
        validator_branch, inner_branch, outer_branch = branches

        validator_test = previous_instruction(lines, validator_branch)
        validator_call = (
            previous_instruction(lines, validator_test)
            if validator_test is not None
            else None
        )
        validator_target = lines[validator_branch].split()[-1]
        validator_target_index = unique_label_index(lines, validator_target)
        validator_ok = bool(
            validator_test is not None
            and validator_call is not None
            and lines[validator_test] == "testb %al, %al"
            and re.fullmatch(
                r"callq? \S*secret_be_bytes_are_valid\S*", lines[validator_call]
            ) is not None
            and exact_validator_call_is_reviewed(body, "x86_64")
            and validator_target_index is not None
            and validator_target_index > validator_branch
        )

        inner_target = lines[inner_branch].split()[-1]
        inner_label = unique_label_index(lines, inner_target)
        inner_cmp = previous_instruction(lines, inner_branch)
        inner_decrement = (
            previous_instruction(lines, inner_cmp) if inner_cmp is not None else None
        )
        inner_initializer = (
            previous_instruction(lines, inner_label) if inner_label is not None else None
        )
        inner_region = (
            lines[inner_initializer : inner_branch + 1]
            if inner_initializer is not None
            else []
        )
        inner_allowed = (
            r"movl \$9, %r15d",
            r"leal -2\(%r15\), %ecx",
            r"decl %r15d",
            r"cmpl \$1, %r15d",
        )
        inner_uses = [
            line
            for line in inner_region
            if re.search(r"%r15(?:b|w|d)?\b", line)
        ]
        inner_ok = bool(
            inner_label is not None
            and inner_label < inner_branch
            and inner_cmp is not None
            and inner_decrement is not None
            and inner_initializer is not None
            and lines[inner_initializer] == "movl $9, %r15d"
            and lines[inner_decrement] == "decl %r15d"
            and lines[inner_cmp] == "cmpl $1, %r15d"
            and len(inner_uses) == 4
            and all(
                any(re.fullmatch(pattern, line) for pattern in inner_allowed)
                for line in inner_uses
            )
        )

        outer_target = lines[outer_branch].split()[-1]
        outer_label = unique_label_index(lines, outer_target)
        outer_cmp = previous_instruction(lines, outer_branch)
        outer_increment = (
            previous_instruction(lines, outer_cmp) if outer_cmp is not None else None
        )
        outer_reload = (
            previous_instruction(lines, outer_increment)
            if outer_increment is not None
            else None
        )
        outer_store = None
        outer_initializer = None
        if outer_label is not None:
            outer_store = next(
                (
                    index
                    for index in range(outer_label + 1, len(lines))
                    if not lines[index].endswith(":")
                ),
                None,
            )
            prior_rax = [
                index
                for index, line in enumerate(lines[:outer_label])
                if re.search(r"%(?:r?ax|eax|ax|al|ah)\b", line)
            ]
            outer_initializer = prior_rax[-1] if prior_rax else None
        slot_lines = (
            [
                line
                for line in lines[outer_label : outer_branch + 1]
                if re.search(r"(?<!\d)16\(%rsp\)", line)
            ]
            if outer_label is not None
            else []
        )
        outer_ok = bool(
            outer_label is not None
            and inner_label is not None
            and outer_label < inner_label < inner_branch < outer_branch
            and outer_cmp is not None
            and outer_increment is not None
            and outer_reload is not None
            and outer_store is not None
            and outer_initializer is not None
            and lines[outer_initializer] == "xorl %eax, %eax"
            and lines[outer_store] == "movq %rax, 16(%rsp)"
            and lines[outer_reload] == "movq 16(%rsp), %rax"
            and lines[outer_increment] == "incq %rax"
            and lines[outer_cmp] == "cmpq $32, %rax"
            and slot_lines
            == [
                "movq %rax, 16(%rsp)",
                "movq 16(%rsp), %rcx",
                "movq 16(%rsp), %rax",
            ]
        )

    return {
        "canonical-input branch bound to validator result": validator_ok,
        "fixed eight-bit loop backedge": inner_ok,
        "fixed 32-byte loop backedge": outer_ok,
    }


def thumb_writes_r0(line: str) -> bool:
    """Conservatively identify writes to Thumb's public counter register."""

    if line.endswith(":"):
        return False
    parts = line.split(None, 1)
    if len(parts) != 2:
        return False
    mnemonic, operands = parts
    if mnemonic.startswith("bl"):
        return True
    if mnemonic.startswith(("cmp", "cmn", "tst", "teq", "str", "stm", "push")):
        return False
    first = operands.split(",", 1)[0].strip()
    return first == "r0" or (
        mnemonic.startswith(("ldm", "pop"))
        and re.search(r"\br0\b", operands) is not None
    )


def thumb_public_control_markers(body: str, group: str) -> dict[str, bool]:
    """Bind all Thumb conditional branches to public/fixed-count dataflow."""

    lines = normalized_lines_with_labels(body, "thumb")
    branches = [
        index
        for index, line in enumerate(lines)
        if instruction(line) in {"beq.w", "bhi.w", "bne.w"}
    ]
    validator_ok = False
    inner_ok = False
    outer_ok = False
    if len(branches) == 3:
        validator_branch, inner_branch, outer_branch = branches
        outer_slot, inner_slot = {
            "G1Projective": (36, 300),
            "G2Projective": (68, 620),
        }[group]

        validator_cmp = previous_instruction(lines, validator_branch)
        validator_uxtb = (
            previous_instruction(lines, validator_cmp) if validator_cmp is not None else None
        )
        validator_call = (
            previous_instruction(lines, validator_uxtb)
            if validator_uxtb is not None
            else None
        )
        validator_target = lines[validator_branch].split()[-1]
        validator_target_index = unique_label_index(lines, validator_target)
        validator_ok = bool(
            validator_cmp is not None
            and validator_uxtb is not None
            and validator_call is not None
            and lines[validator_cmp] == "cmp r0, #0"
            and lines[validator_uxtb] == "uxtb r0, r0"
            and re.fullmatch(
                r"bl \S*secret_be_bytes_are_valid\S*", lines[validator_call]
            ) is not None
            and exact_validator_call_is_reviewed(body, "thumb")
            and validator_target_index is not None
            and validator_target_index > validator_branch
        )

        inner_target = lines[inner_branch].split()[-1]
        inner_label = unique_label_index(lines, inner_target)
        inner_move = previous_instruction(lines, inner_branch)
        inner_cmp = previous_instruction(lines, inner_move) if inner_move is not None else None
        inner_decrement = (
            previous_instruction(lines, inner_cmp) if inner_cmp is not None else None
        )
        inner_register = None
        if inner_move is not None:
            match = re.fullmatch(r"mov r(?P<reg>[89]), r0", lines[inner_move])
            inner_register = match.group("reg") if match else None
        inner_load_candidates = (
            [
                index
                for index in range(max(0, inner_decrement - 2), inner_decrement)
                if lines[index] == f"ldr r0, [sp, #{inner_slot}]"
            ]
            if inner_decrement is not None
            else []
        )
        inner_initializer = None
        outer_state_store = None
        if inner_label is not None:
            outer_state_store = previous_instruction(lines, inner_label)
            inner_initializer = (
                previous_instruction(lines, outer_state_store)
                if outer_state_store is not None
                else None
            )
        inner_slot_lines = (
            [
                line
                for line in lines[inner_initializer : inner_branch + 1]
                if f"[sp, #{inner_slot}]" in line
            ]
            if inner_initializer is not None
            else []
        )
        inner_ok = bool(
            inner_label is not None
            and inner_label < inner_branch
            and inner_move is not None
            and inner_cmp is not None
            and inner_decrement is not None
            and inner_register is not None
            and len(inner_load_candidates) == 1
            and inner_initializer is not None
            and outer_state_store is not None
            and lines[inner_initializer] == f"mov.w r{inner_register}, #9"
            and lines[outer_state_store] == f"str r0, [sp, #{outer_slot}]"
            and lines[inner_decrement] == "subs r0, #1"
            and lines[inner_cmp] == "cmp r0, #1"
            and any(
                line == f"sub.w r1, r{inner_register}, #2"
                for line in lines[inner_label:inner_branch]
            )
            and inner_slot_lines
            == [
                f"str.w r{inner_register}, [sp, #{inner_slot}]",
                f"ldr r0, [sp, #{inner_slot}]",
            ]
        )

        outer_target = lines[outer_branch].split()[-1]
        outer_label = unique_label_index(lines, outer_target)
        outer_cmp = previous_instruction(lines, outer_branch)
        outer_increment = (
            previous_instruction(lines, outer_cmp) if outer_cmp is not None else None
        )
        outer_load = (
            previous_instruction(lines, outer_increment)
            if outer_increment is not None
            else None
        )
        prior_r0_writes = (
            [
                index
                for index, line in enumerate(lines[:outer_label])
                if thumb_writes_r0(line)
            ]
            if outer_label is not None
            else []
        )
        outer_initializer = prior_r0_writes[-1] if prior_r0_writes else None
        outer_slot_lines = (
            [
                line
                for line in lines[outer_label : outer_branch + 1]
                if f"[sp, #{outer_slot}]" in line
            ]
            if outer_label is not None
            else []
        )
        outer_ok = bool(
            outer_label is not None
            and inner_label is not None
            and outer_label < inner_label < inner_branch < outer_branch
            and outer_cmp is not None
            and outer_increment is not None
            and outer_load is not None
            and outer_initializer is not None
            and lines[outer_initializer] == "movs r0, #0"
            and lines[outer_load] == f"ldr r0, [sp, #{outer_slot}]"
            and lines[outer_increment] == "adds r0, #1"
            and lines[outer_cmp] == "cmp r0, #32"
            and outer_slot_lines
            == [
                f"str r0, [sp, #{outer_slot}]",
                f"ldr r0, [sp, #{outer_slot}]",
                f"ldr r0, [sp, #{outer_slot}]",
            ]
        )

    return {
        "canonical-input branch bound to validator result": validator_ok,
        "fixed eight-bit loop backedge": inner_ok,
        "fixed 32-byte loop backedge": outer_ok,
    }


def aarch64_lines(body: str) -> list[str]:
    """Return normalized AArch64 instructions and labels."""

    lines: list[str] = []
    for line in body.splitlines():
        line = line.split("//", 1)[0].strip().lower()
        if not line or (line.startswith(".") and not line.endswith(":")):
            continue
        lines.append(" ".join(line.split()))
    return lines


def previous_aarch64_instruction(lines: list[str], index: int) -> int | None:
    for candidate in range(index - 1, -1, -1):
        if not lines[candidate].endswith(":"):
            return candidate
    return None


def aarch64_label_index(lines: list[str], label: str) -> int | None:
    matches = [index for index, line in enumerate(lines) if line == f"{label}:"]
    return matches[0] if len(matches) == 1 else None


def aarch64_writes_register(line: str, register_number: str) -> bool:
    """Conservatively identify aggregate-register writes in reviewed loops."""

    if line.endswith(":"):
        return False
    parts = line.split(None, 1)
    if len(parts) != 2:
        return False
    mnemonic, operands = parts
    non_writers = {
        "b", "bl", "br", "ret", "cmp", "cmn", "ccmp", "tst", "cbz",
        "cbnz", "tbz", "tbnz", "str", "stur", "stp", "prfm", "nop",
    }
    if re.search(
        rf"\[[wx]{re.escape(register_number)}(?:,[^\]]+)?\](?:!|,)", line
    ):
        return True
    if mnemonic in non_writers or mnemonic.startswith("b."):
        return False
    operand_list = [operand.strip() for operand in operands.split(",")]
    destinations = operand_list[:2] if mnemonic == "ldp" else operand_list[:1]
    return any(
        re.fullmatch(rf"[wx]{re.escape(register_number)}", destination) is not None
        for destination in destinations
    )


def aarch64_counter_uses_are_reviewed(
    lines: list[str], start: int, end: int, counter: str, *, inner: bool
) -> bool:
    """Reject every counter occurrence outside the exact reviewed operations."""

    token = re.compile(rf"\b[wx]{re.escape(counter)}\b")
    for line in lines[start : end + 1]:
        if token.search(line) is None:
            continue
        if inner:
            candidates = (
                rf"mov w{counter}, #9",
                rf"sub w(?P<bit>\d+), w{counter}, #2",
                rf"sub w{counter}, w{counter}, #1",
                rf"cmp w{counter}, #1",
            )
            matched = next(
                (match for pattern in candidates if (match := re.fullmatch(pattern, line))),
                None,
            )
            if matched is None:
                return False
            if matched.groupdict().get("bit") == counter:
                return False
        else:
            candidates = (
                rf"mov x{counter}, xzr",
                rf"ldrb w\d+, \[x\d+, x{counter}\]",
                rf"add x{counter}, x{counter}, #1",
                rf"cmp x{counter}, #32",
            )
            if not any(re.fullmatch(pattern, line) for pattern in candidates):
                return False
    return True


def aarch64_public_control_markers(body: str) -> dict[str, bool]:
    """Bind each AArch64 branch to reviewed public/fixed-count dataflow."""

    lines = aarch64_lines(body)
    branch_indices = [
        index
        for index, line in enumerate(lines)
        if instruction(line) in {"tbz", "b.eq", "b.hi", "b.ne"}
    ]

    validator_ok = False
    if len(branch_indices) == 3:
        branch_index = branch_indices[0]
        branch = lines[branch_index]
        target = branch.split()[-1]
        target_index = aarch64_label_index(lines, target)
        previous = previous_aarch64_instruction(lines, branch_index)
        before_previous = (
            previous_aarch64_instruction(lines, previous) if previous is not None else None
        )
        if (
            instruction(branch) == "tbz"
            and previous is not None
            and before_previous is not None
        ):
            masked = re.fullmatch(
                r"and w(?P<valid>\d+), w0, #0xff", lines[previous]
            )
            tested = re.fullmatch(
                r"tbz w(?P<valid>\d+), #0, (?P<label>\.l\S+)", branch
            )
            validator_ok = bool(
                masked
                and tested
                and masked.group("valid") == tested.group("valid")
                and re.fullmatch(
                    r"bl \S*secret_be_bytes_are_valid\S*",
                    lines[before_previous],
                ) is not None
            )
        elif (
            instruction(branch) == "b.eq"
            and previous is not None
            and before_previous is not None
        ):
            validator_ok = bool(
                lines[previous] == "tst w0, #0xff"
                and re.fullmatch(
                    r"bl \S*secret_be_bytes_are_valid\S*",
                    lines[before_previous],
                ) is not None
            )
        validator_ok = bool(
            validator_ok
            and exact_validator_call_is_reviewed(body, "aarch64")
            and target_index is not None
            and target_index > branch_index
        )

    inner_ok = False
    outer_ok = False
    inner_counter: str | None = None
    outer_counter: str | None = None
    if len(branch_indices) == 3:
        inner_branch_index, outer_branch_index = branch_indices[1:]

        inner_target = lines[inner_branch_index].split()[-1]
        inner_label_index = aarch64_label_index(lines, inner_target)
        inner_cmp_index = previous_aarch64_instruction(lines, inner_branch_index)
        inner_sub_index = (
            previous_aarch64_instruction(lines, inner_cmp_index)
            if inner_cmp_index is not None
            else None
        )
        if inner_cmp_index is not None and inner_sub_index is not None:
            decrement = re.fullmatch(
                r"sub w(?P<counter>\d+), w(?P=counter), #1",
                lines[inner_sub_index],
            )
            compared = re.fullmatch(
                r"cmp w(?P<counter>\d+), #1", lines[inner_cmp_index]
            )
            counter = decrement.group("counter") if decrement else None
            inner_counter = counter
            initializer_index = (
                previous_aarch64_instruction(lines, inner_label_index)
                if inner_label_index is not None
                else None
            )
            no_other_writes = bool(
                counter is not None
                and 19 <= int(counter) <= 28
                and initializer_index is not None
                and not any(
                    aarch64_writes_register(line, counter)
                    for line in lines[initializer_index + 1 : inner_sub_index]
                )
            )
            inner_ok = bool(
                decrement
                and compared
                and decrement.group("counter") == compared.group("counter")
                and lines[inner_branch_index].startswith("b.hi ")
                and inner_label_index is not None
                and inner_label_index < inner_branch_index
                and initializer_index is not None
                and lines[initializer_index] == f"mov w{counter}, #9"
                and no_other_writes
                and aarch64_counter_uses_are_reviewed(
                    lines,
                    initializer_index,
                    inner_branch_index,
                    counter,
                    inner=True,
                )
            )

        outer_target = lines[outer_branch_index].split()[-1]
        outer_label_index = aarch64_label_index(lines, outer_target)
        outer_cmp_index = previous_aarch64_instruction(lines, outer_branch_index)
        outer_add_index = (
            previous_aarch64_instruction(lines, outer_cmp_index)
            if outer_cmp_index is not None
            else None
        )
        if outer_cmp_index is not None and outer_add_index is not None:
            increment = re.fullmatch(
                r"add x(?P<counter>\d+), x(?P=counter), #1",
                lines[outer_add_index],
            )
            compared = re.fullmatch(
                r"cmp x(?P<counter>\d+), #32", lines[outer_cmp_index]
            )
            counter = increment.group("counter") if increment else None
            outer_counter = counter
            initializer_indices = (
                [
                    index
                    for index, line in enumerate(lines[:outer_label_index])
                    if counter is not None and aarch64_writes_register(line, counter)
                ]
                if outer_label_index is not None
                else []
            )
            initializer_index = initializer_indices[-1] if initializer_indices else None
            no_other_writes = bool(
                counter is not None
                and 19 <= int(counter) <= 28
                and outer_label_index is not None
                and not any(
                    aarch64_writes_register(line, counter)
                    for line in lines[outer_label_index + 1 : outer_add_index]
                )
            )
            outer_ok = bool(
                increment
                and compared
                and increment.group("counter") == compared.group("counter")
                and lines[outer_branch_index].startswith("b.ne ")
                and outer_label_index is not None
                and outer_label_index < outer_branch_index
                and initializer_index is not None
                and lines[initializer_index] == f"mov x{counter}, xzr"
                and no_other_writes
                and aarch64_counter_uses_are_reviewed(
                    lines,
                    initializer_index,
                    outer_branch_index,
                    counter,
                    inner=False,
                )
            )

        if not (
            outer_label_index is not None
            and inner_label_index is not None
            and outer_label_index < inner_label_index < inner_branch_index < outer_branch_index
        ):
            inner_ok = False
            outer_ok = False
        if inner_counter is None or outer_counter is None or inner_counter == outer_counter:
            inner_ok = False
            outer_ok = False

    return {
        "canonical-input rejection bound to validator result": validator_ok,
        "fixed eight-bit loop backedge": inner_ok,
        "fixed 32-byte loop backedge": outer_ok,
    }


def wasm_public_control_markers(body: str, group: str) -> dict[str, bool]:
    normalized = " ".join(executable_lines(body, "wasm32"))
    branches = conditional_branch_mnemonics(body, "wasm32")
    old_branch_count = 4 if group == "G1Projective" else 7
    old_validator_match = re.search(
        r"call (?P<validator>\S+) "
        r"i32\.const 255 i32\.and br_if",
        normalized,
    )
    current_validator_match = re.search(
        r"call (?P<validator>\S+) "
        r"i32\.const 255 i32\.and i32\.eqz br_if",
        normalized,
    )
    fixed_loop_match = re.search(
        r"i32\.const 0 local\.set (?P<outer>\d+).*?\bloop\b"
        r".*?i32\.const 9 local\.set (?P<inner>\d+).*?\bloop\b "
        r".*?local\.get (?P=inner) i32\.const -1 i32\.add "
        r"local\.tee (?P=inner) i32\.const 1 i32\.gt_u br_if 0 end_loop "
        r"local\.get (?P=outer) i32\.const 1 i32\.add "
        r"local\.tee (?P=outer) i32\.const 32 i32\.ne br_if 0",
        normalized,
    )
    fixed_loops = False
    if fixed_loop_match is not None:
        outer = fixed_loop_match.group("outer")
        inner = fixed_loop_match.group("inner")
        loop_region = fixed_loop_match.group(0)
        inner_region = loop_region[loop_region.index(f"i32.const 9 local.set {inner}") :]

        def count_local(region: str, operation: str, local: str) -> int:
            return len(
                re.findall(rf"\blocal\.{operation} {re.escape(local)}\b", region)
            )

        fixed_loops = (
            outer != inner
            and count_local(loop_region, "set", outer) == 1
            and count_local(loop_region, "tee", outer) == 1
            and count_local(inner_region, "set", inner) == 1
            and count_local(inner_region, "tee", inner) == 1
        )

    if len(branches) == 3:
        validator_match = current_validator_match
        copy_profile = (
            validator_match is not None
            and normalized.count("i32.eqz") == 1
            and "i32.const 144 i32.eqz" not in normalized
            and "i32.const 288 i32.eqz" not in normalized
        )
    elif len(branches) == old_branch_count:
        validator_match = old_validator_match
        if group == "G1Projective":
            copy_profile = (
                re.search(r"i32\.const 144 i32\.eqz br_if", normalized) is not None
                and normalized.count("i32.eqz") == 1
            )
        else:
            copy_match = re.search(
                r"i32\.const 96 i32\.eqz local\.tee (?P<copy>\d+) br_if 0 "
                r".*?local\.get (?P=copy) br_if 0 "
                r".*?local\.get (?P=copy) br_if 0",
                normalized,
            )
            copy_local = copy_match.group("copy") if copy_match else None
            copy_region = copy_match.group(0) if copy_match else ""
            copy_profile = (
                copy_match is not None
                and copy_local is not None
                and len(
                    re.findall(rf"\blocal\.tee {re.escape(copy_local)}\b", copy_region)
                )
                == 1
                and len(
                    re.findall(rf"\blocal\.get {re.escape(copy_local)}\b", copy_region)
                )
                == 2
                and re.search(
                    rf"\blocal\.set {re.escape(copy_local)}\b", copy_region
                )
                is None
                and re.search(r"i32\.const 288 i32\.eqz br_if", normalized) is not None
                and normalized.count("i32.eqz") == 2
            )
    else:
        validator_match = None
        copy_profile = False

    validator = bool(
        validator_match is not None
        and reviewed_validator_symbol(validator_match.group("validator"))
        and fixed_loop_match is not None
        and validator_match.start() < fixed_loop_match.start()
        and len(re.findall(r"\bcall \S*secret_be_bytes_are_valid\S*", normalized)) == 1
    )

    return {
        "canonical-input branch bound to validator result": validator,
        "fixed public loop-counter dataflow": fixed_loops,
        "reviewed LLVM constant-copy profile": copy_profile,
        "all branches target the reviewed innermost block": all(
            re.fullmatch(r"br_if\s+0", " ".join(line.split())) is not None
            for line in body.splitlines()
            if instruction(line) == "br_if"
        ),
    }


def protected_symbol_group(symbol: str) -> str | None:
    """Classify only exact legacy/v0 protected multiplication symbols."""

    for curve, group in (("1", "G1Projective"), ("2", "G2Projective")):
        legacy = (
            rf"_ZN17dcrypt_algorithms2ec9bls12_3812g{curve}12{group}"
            r"24multiply_secret_be_bytes17h[0-9a-f]{16}E"
        )
        v0 = (
            rf"_RNvMs1a_NtNtNtC[0-9A-Za-z]+_17dcrypt_algorithms2ec9bls12_3812g{curve}"
            rf"NtB6_12{group}24multiply_secret_be_bytes"
        )
        if re.fullmatch(rf"(?:{legacy}|{v0})", symbol):
            return group
    return None


def extract_functions(assembly: str) -> dict[str, list[str]]:
    lines = assembly.splitlines()
    found = {group: [] for group in GROUPS}
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.endswith(":"):
            continue
        symbol = stripped[:-1]
        group = protected_symbol_group(symbol)
        if group is None:
            continue
        body = [line]
        terminated = False
        for following in lines[index + 1 :]:
            body.append(following)
            following_stripped = following.strip()
            if following_stripped == "end_function":
                terminated = True
                break
            size = re.fullmatch(r"\.size\s+(?P<symbol>\S+),.*", following_stripped)
            if size is not None and size.group("symbol") == symbol:
                terminated = True
                break
        if terminated:
            found[group].append("\n".join(body))
    return found


def exact_symbol_definition_indices(assembly_lines: list[str], symbol: str) -> list[int]:
    return [
        index
        for index, line in enumerate(assembly_lines)
        if line.strip() == f"{symbol}:"
    ]


def function_preamble(assembly_lines: list[str], symbol: str) -> str | None:
    """Return the exact section/type/alignment preamble for one function."""

    definitions = exact_symbol_definition_indices(assembly_lines, symbol)
    if len(definitions) != 1:
        return None
    label_index = definitions[0]
    section_indices = [
        index
        for index, line in enumerate(assembly_lines[:label_index])
        if line.strip().startswith(".section")
    ]
    if not section_indices:
        return None
    section_index = section_indices[-1]
    return "\n".join(assembly_lines[section_index:label_index])


def local_symbol_evidence(assembly_lines: list[str], symbol: str) -> str | None:
    """Return the exact defining section/type/data for one local object."""

    definitions = exact_symbol_definition_indices(assembly_lines, symbol)
    if len(definitions) != 1:
        return None
    label_index = definitions[0]
    section_indices = [
        index
        for index, line in enumerate(assembly_lines[:label_index])
        if line.strip().startswith(".section")
    ]
    if not section_indices:
        return None
    start = section_indices[-1]
    type_indices = [
        index
        for index, line in enumerate(assembly_lines[:label_index])
        if re.match(rf"^\s*\.type\s+{re.escape(symbol)}(?:,|\s)", line)
    ]
    if type_indices and type_indices[-1] < start:
        start = type_indices[-1]

    matching_size = next(
        (
            index
            for index in range(label_index + 1, len(assembly_lines))
            if re.match(
                rf"^\s*\.size\s+{re.escape(symbol)}(?:,|\s)",
                assembly_lines[index],
            )
        ),
        None,
    )
    if matching_size is not None:
        end = matching_size + 1
    else:
        end = len(assembly_lines)
        for index in range(label_index + 1, len(assembly_lines)):
            stripped = assembly_lines[index].strip()
            if stripped.startswith(".section") or stripped.endswith(":"):
                end = index
                break
    return "\n".join(assembly_lines[start:end])


def function_closure_evidence(
    assembly: str, body: str
) -> tuple[str | None, list[str]]:
    """Bind the body, its executable metadata, and referenced local data."""

    errors: list[str] = []
    assembly_lines = assembly.splitlines()
    body_lines = body.splitlines()
    if not body_lines or not body_lines[0].strip().endswith(":"):
        return None, ["protected body has no exact symbol label"]
    symbol = body_lines[0].strip()[:-1]
    preamble = function_preamble(assembly_lines, symbol)
    if preamble is None:
        return None, [f"protected function {symbol!r} has no unique preamble"]

    referenced = set(
        re.findall(r"(?<![A-Za-z0-9_.$])(\.L[A-Za-z0-9_.$]+)", body)
    )
    body_labels = {
        line.strip()[:-1]
        for line in body_lines
        if line.strip().endswith(":")
    }
    external = sorted(referenced - body_labels)
    components = [preamble, body]
    for local_symbol in external:
        evidence = local_symbol_evidence(assembly_lines, local_symbol)
        if evidence is None:
            errors.append(
                f"local data symbol {local_symbol!r} has no unique definition"
            )
            continue
        components.append(f"{local_symbol}\n{evidence}")
    if errors:
        return None, errors
    return "\n--closure-component--\n".join(components), []


def audit(
    target: str,
    assembly: str | bytes,
    *,
    compiler_profile: str | None = None,
    enforce_fingerprint: bool = True,
) -> list[str]:
    raw_assembly = (
        assembly if isinstance(assembly, bytes) else assembly.encode("utf-8")
    )
    assembly_hash = hashlib.sha256(raw_assembly).hexdigest()
    fingerprint_error = None
    if enforce_fingerprint:
        if compiler_profile not in COMPILER_PROFILES:
            fingerprint_error = "a reviewed compiler profile is required"
        else:
            profile_hashes = COMPILER_PROFILES[compiler_profile]["hashes"]
            assert isinstance(profile_hashes, dict)
            expected_hash = profile_hashes[target]
            if assembly_hash != expected_hash:
                fingerprint_error = (
                    f"whole compiler-emission fingerprint changed for "
                    f"{compiler_profile}: {assembly_hash}; expected {expected_hash}"
                )
    if isinstance(assembly, bytes):
        try:
            assembly = raw_assembly.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            errors = [] if fingerprint_error is None else [fingerprint_error]
            errors.append(f"compiler emission is not valid UTF-8: {error}")
            return errors
    architecture = SUPPORTED_TARGETS[target]
    functions = extract_functions(assembly)
    errors: list[str] = [] if fingerprint_error is None else [fingerprint_error]
    code_lines, source_hazards = assembly_code_lines(assembly, architecture)
    if source_hazards:
        errors.append(
            "unreviewed assembly lexical state: " + ", ".join(source_hazards)
        )
    stateful_directives = [
        line
        for line in code_lines
        if STATEFUL_DIRECTIVE.match(line)
    ]
    if stateful_directives:
        errors.append(
            "unreviewed stateful assembler directives: "
            + ", ".join(stateful_directives)
        )
    assignments = bare_assignments(code_lines)
    assignment_hash = assignment_fingerprint(assignments)
    if (
        enforce_fingerprint
        and assignment_hash not in EXPECTED_ASSIGNMENT_SHA256[target]
    ):
        errors.append(
            f"whole-file symbol-assignment fingerprint changed: {assignment_hash}; "
            f"expected one of {sorted(EXPECTED_ASSIGNMENT_SHA256[target])!r}"
        )
    binding_errors = call_target_binding_errors(
        assembly,
        functions,
        architecture,
        assignments,
        require_definitions=enforce_fingerprint,
    )
    if binding_errors:
        errors.extend(binding_errors)
    for group in GROUPS:
        bodies = functions[group]
        if len(bodies) != 1:
            errors.append(f"{group}: found {len(bodies)} protected multiplication bodies; expected 1")
            continue
        body = bodies[0]
        if enforce_fingerprint:
            closure, closure_errors = function_closure_evidence(assembly, body)
            errors.extend(f"{group}: {error}" for error in closure_errors)
            expected_fingerprints = EXPECTED_FUNCTION_CLOSURE_SHA256[target][group]
        else:
            closure = None
            expected_fingerprints = frozenset()
        if closure is not None:
            fingerprint = hashlib.sha256(closure.encode("utf-8")).hexdigest()
            if fingerprint not in expected_fingerprints:
                errors.append(
                    f"{group}: complete function-closure fingerprint changed: "
                    f"{fingerprint}; expected one of "
                    f"{sorted(expected_fingerprints)!r}"
                )
        branches = conditional_branch_mnemonics(body, architecture)
        expected_branches = EXPECTED_BRANCHES[target][group]
        if architecture == "x86_64":
            public_markers = x86_public_control_markers(body)
            missing = [name for name, present in public_markers.items() if not present]
            if missing:
                errors.append(
                    f"{group}: unexplained x86 branch context: {', '.join(missing)}"
                )
        if architecture == "aarch64":
            branch_shape_matches = (
                len(branches) == 3
                and branches[0] in expected_branches[0]
                and tuple(branches[1:]) == expected_branches[1:]
            )
        elif architecture == "wasm32":
            branch_shape_matches = tuple(branches) in expected_branches
        else:
            branch_shape_matches = tuple(branches) == expected_branches
        if not branch_shape_matches:
            errors.append(
                f"{group}: conditional branch shape changed: {branches!r}; expected "
                f"{list(expected_branches)!r}"
            )
        forbidden = forbidden_control(body, architecture, group)
        if forbidden:
            errors.append(
                f"{group}: unreviewed indirect/table/predicated control: "
                + ", ".join(forbidden)
            )
        markers = selection_markers(body, architecture)
        missing = [name for name, present in markers.items() if not present]
        if missing:
            errors.append(f"{group}: missing mask-selection evidence: {', '.join(missing)}")
        if architecture == "aarch64":
            public_markers = aarch64_public_control_markers(body)
            missing = [name for name, present in public_markers.items() if not present]
            if missing:
                errors.append(
                    f"{group}: unexplained AArch64 branch context: {', '.join(missing)}"
                )
        if architecture == "thumb":
            public_markers = thumb_public_control_markers(body, group)
            missing = [name for name, present in public_markers.items() if not present]
            if missing:
                errors.append(
                    f"{group}: unexplained Thumb branch context: {', '.join(missing)}"
                )
        if architecture == "wasm32":
            public_markers = wasm_public_control_markers(body, group)
            missing = [name for name, present in public_markers.items() if not present]
            if missing:
                errors.append(
                    f"{group}: unexplained WebAssembly branch context: {', '.join(missing)}"
                )
    return errors


def self_test() -> None:
    def semantic_audit(target: str, assembly: str) -> list[str]:
        return audit(target, assembly, enforce_fingerprint=False)

    assert all(
        profile["version"] in {
            "rustc 1.93.1 (01f6ddf75 2026-02-11)",
            "rustc 1.97.1 (8bab26f4f 2026-07-14)",
        }
        and isinstance(profile["hashes"], dict)
        and set(profile["hashes"]) == set(SUPPORTED_TARGETS)
        and all(
            re.fullmatch(r"[0-9a-f]{64}", value)
            for value in profile["hashes"].values()
        )
        for profile in COMPILER_PROFILES.values()
    )
    fingerprint_errors = audit(
        "x86_64-unknown-linux-gnu", b"", compiler_profile="rust-1.93.1"
    )
    assert any(
        "whole compiler-emission fingerprint changed" in error
        for error in fingerprint_errors
    )

    synthetic_validator = (
        "_ZN17dcrypt_algorithms2ec9bls12_3816scalar"
        "25secret_be_bytes_are_valid17h0123456789abcdefE"
    )

    def synthetic_protected_symbol(group: str) -> str:
        curve = "1" if group == "G1Projective" else "2"
        return (
            f"_ZN17dcrypt_algorithms2ec9bls12_3812g{curve}12{group}"
            "24multiply_secret_be_bytes17h0123456789abcdefE"
        )

    def thumb_sample(group: str) -> str:
        outer_slot, inner_slot = {
            "G1Projective": (36, 300),
            "G2Projective": (68, 620),
        }[group]
        return (
            f"bl {synthetic_validator}\n"
            "uxtb r0, r0\n"
            "cmp r0, #0\n"
            "beq.w .bad\n"
            "movs r0, #0\n"
            ".outer:\n"
            "mov.w r8, #9\n"
            f"str r0, [sp, #{outer_slot}]\n"
            ".inner:\n"
            f"ldr r0, [sp, #{outer_slot}]\n"
            "sub.w r1, r8, #2\n"
            "lsrs r0, r1, r2\n"
            "ands r0, r3\n"
            "orrs r0, r4\n"
            f"str.w r8, [sp, #{inner_slot}]\n"
            f"ldr r0, [sp, #{inner_slot}]\n"
            "subs r0, #1\n"
            "cmp r0, #1\n"
            "mov r8, r0\n"
            "bhi.w .inner\n"
            f"ldr r0, [sp, #{outer_slot}]\n"
            "adds r0, #1\n"
            "cmp r0, #32\n"
            "bne.w .outer\n"
            "pop {r4, r5, r6, r7, pc}\n"
            ".bad:\n"
            "pop {r4, r5, r6, r7, pc}"
        )

    samples = {
        "x86_64": (
            f"callq {synthetic_validator}\n"
            "testb %al, %al\n"
            "je .bad\n"
            "xorl %eax, %eax\n"
            ".outer:\n"
            "movq %rax, 16(%rsp)\n"
            "movl $9, %r15d\n"
            ".inner:\n"
            "setb %al\n"
            "btq %rcx, %rax\n"
            "pand %xmm0, %xmm1\n"
            "por %xmm1, %xmm2\n"
            "leal -2(%r15), %ecx\n"
            "movq 16(%rsp), %rcx\n"
            "decl %r15d\n"
            "cmpl $1, %r15d\n"
            "ja .inner\n"
            "movq 16(%rsp), %rax\n"
            "incq %rax\n"
            "cmpq $32, %rax\n"
            "jne .outer\n"
            ".bad:\n"
            "retq"
        ),
        "aarch64": (
            f"bl {synthetic_validator}\n"
            "and w8, w0, #0xff\n"
            "tbz w8, #0, .Lbad\n"
            "mov x22, xzr\n"
            ".Louter:\n"
            "mov w26, #9\n"
            ".Linner:\n"
            "lsrv w1, w2, w3\n"
            "neg x9, x8\n"
            "bit v1.16b, v3.16b, v0.16b\n"
            "sub w26, w26, #1\n"
            "cmp w26, #1\n"
            "b.hi .Linner\n"
            "add x22, x22, #1\n"
            "cmp x22, #32\n"
            "b.ne .Louter\n"
            ".Lbad:\n"
            "ret"
        ),
        "thumb": thumb_sample("G1Projective"),
        "wasm32": "br_if 0\ni32.shr_u\ni32.and\ni32.xor\nbr_if 1\nbr_if 0",
    }
    for architecture, body in samples.items():
        branches = conditional_branch_mnemonics(body, architecture)
        assert len(branches) == 3, (architecture, branches)
        assert all(selection_markers(body, architecture).values()), architecture
    fake_marker_comments = {
        "x86_64": ("btq %rcx, %rax", "# btq %rcx, %rax"),
        "aarch64": ("lsrv w1, w2, w3", "// lsrv w1, w2, w3"),
        "thumb": ("lsrs r0, r1, r2", "@ lsrs r0, r1, r2"),
        "wasm32": ("i32.shr_u", "# i32.shr_u"),
    }
    for architecture, (marker, comment) in fake_marker_comments.items():
        commented = samples[architecture].replace(marker, comment, 1)
        assert not all(selection_markers(commented, architecture).values())

    synthetic = "\n".join(
        f"{synthetic_protected_symbol(group)}:\n{samples['x86_64']}\n"
        f".size {synthetic_protected_symbol(group)}, .-"
        f"{synthetic_protected_symbol(group)}"
        for group in GROUPS
    )
    assert semantic_audit("x86_64-unknown-linux-gnu", synthetic) == []
    x86_call_impersonation = synthetic
    for marker, replacement in (
        ("btq %rcx, %rax", "call bt"),
        ("setb %al", "call setb"),
        ("pand %xmm0, %xmm1", "call pand"),
        ("por %xmm1, %xmm2", "call por"),
    ):
        x86_call_impersonation = x86_call_impersonation.replace(marker, replacement)
    assert semantic_audit("x86_64-unknown-linux-gnu", x86_call_impersonation)
    altered = synthetic.replace("jne .outer", "jne .outer\nje .secret", 1)
    assert semantic_audit("x86_64-unknown-linux-gnu", altered)
    assert semantic_audit(
        "x86_64-unknown-linux-gnu",
        synthetic.replace("jne .outer", "jne .outer\nloop .secret", 1),
    )
    assert semantic_audit(
        "x86_64-unknown-linux-gnu",
        synthetic.replace("jne .outer", "jne .outer\njmp *%rax", 1),
    )
    assert semantic_audit(
        "x86_64-unknown-linux-gnu",
        synthetic.replace("jne .outer", "jne .outer\ncallq *%rax", 1),
    )
    assert semantic_audit(
        "x86_64-unknown-linux-gnu",
        synthetic.replace("jne .outer", "jne .outer\ncallq * %rax", 1),
    )
    for prefixed_call in (
        "notrack callq *%rax",
        "bnd callq *%rax",
        "rex.W callq *%rax",
        "callw *%ax",
    ):
        assert semantic_audit(
            "x86_64-unknown-linux-gnu",
            synthetic.replace("jne .outer", f"jne .outer\n{prefixed_call}", 1),
        )
    reviewed_register_call = synthetic.replace(
        "leal -2(%r15), %ecx",
        "movq _ZN17dcrypt_algorithms2ec9bls12_3812g112G1Projective6double"
        "17h0123456789abcdefE@GOTPCREL(%rip), %r12\n"
        "callq *%r12\n"
        "leal -2(%r15), %ecx",
        1,
    )
    assert semantic_audit("x86_64-unknown-linux-gnu", reviewed_register_call) == []
    assert semantic_audit(
        "x86_64-unknown-linux-gnu",
        reviewed_register_call.replace("callq *%r12", "callq * %r12", 1),
    ) == []
    reviewed_spaced_got_call = synthetic.replace(
        "leal -2(%r15), %ecx",
        "callq * _ZN17dcrypt_algorithms2ec9bls12_3812g112G1Projective3add"
        "17h0123456789abcdefE@GOTPCREL(%rip)\nleal -2(%r15), %ecx",
        1,
    )
    assert semantic_audit("x86_64-unknown-linux-gnu", reviewed_spaced_got_call) == []
    assert semantic_audit(
        "x86_64-unknown-linux-gnu",
        reviewed_register_call.replace(
            "callq *%r12", "movq %rdi, %r12\ncallq *%r12", 1
        ),
    )
    assert semantic_audit(
        "x86_64-unknown-linux-gnu",
        reviewed_register_call.replace(
            "callq *%r12", "movl %edi, %r12d\ncallq *%r12", 1
        ),
    )
    assert semantic_audit(
        "x86_64-unknown-linux-gnu",
        reviewed_register_call.replace(
            "_ZN17dcrypt_algorithms2ec9bls12_3812g112G1Projective6double",
            "evil_not_G1Projective6double",
            1,
        ),
    )
    for lookalike in (
        "evil_not_G1Projective3add@GOTPCREL(%rip)",
        "evil_choice_not_zeroize_zeroing@GOTPCREL(%rip)",
    ):
        assert semantic_audit(
            "x86_64-unknown-linux-gnu",
            synthetic.replace("jne .outer", f"callq *{lookalike}\njne .outer", 1),
        )
        assert semantic_audit(
            "x86_64-unknown-linux-gnu",
            synthetic.replace(
                "jne .outer", f"callq * {lookalike}\njne .outer", 1
            ),
        )
    assert semantic_audit(
        "x86_64-unknown-linux-gnu",
        synthetic.replace(
            "jne .outer", "callq *symbol_secret@GOTPCREL(%rip)\njne .outer", 1
        ),
    )

    aarch64_synthetic = "\n".join(
        f"{synthetic_protected_symbol(group)}:\n{samples['aarch64']}\n"
        f".size {synthetic_protected_symbol(group)}, .-"
        f"{synthetic_protected_symbol(group)}"
        for group in GROUPS
    )
    assert semantic_audit("aarch64-unknown-linux-gnu", aarch64_synthetic) == []
    aarch64_call_impersonation = aarch64_synthetic
    for marker, replacement in (
        ("lsrv w1, w2, w3", "bl lsr"),
        ("neg x9, x8", "bl neg"),
        ("bit v1.16b, v3.16b, v0.16b", "bl bit"),
    ):
        aarch64_call_impersonation = aarch64_call_impersonation.replace(
            marker, replacement
        )
    assert semantic_audit("aarch64-unknown-linux-gnu", aarch64_call_impersonation)
    current_aarch64 = aarch64_synthetic.replace(
        "and w8, w0, #0xff\ntbz w8, #0, .Lbad",
        "tst w0, #0xff\nb.eq .Lbad",
    )
    assert semantic_audit("aarch64-unknown-linux-gnu", current_aarch64) == []
    assert semantic_audit(
        "aarch64-unknown-linux-gnu",
        current_aarch64.replace(synthetic_validator, "evil_secret_be_bytes_are_valid"),
    )
    assert semantic_audit(
        "aarch64-unknown-linux-gnu",
        current_aarch64.replace("tst w0, #0xff", "tst w1, #0xff", 1),
    )
    assert semantic_audit(
        "aarch64-unknown-linux-gnu",
        current_aarch64.replace("cmp x22, #32", "cmp x23, #32", 1),
    )
    assert semantic_audit(
        "aarch64-unknown-linux-gnu",
        current_aarch64.replace("mov x22, xzr", "mov x22, x3", 1),
    )
    assert semantic_audit(
        "aarch64-unknown-linux-gnu",
        current_aarch64.replace("mov w26, #9", "mov w26, w7", 1),
    )
    assert semantic_audit(
        "aarch64-unknown-linux-gnu",
        current_aarch64.replace("b.hi .Linner", "b.hi .Lfuture", 1),
    )
    assert semantic_audit(
        "aarch64-unknown-linux-gnu",
        current_aarch64.replace("mov w26, #9", "mov w0, #9", 1)
        .replace("sub w26, w26", "sub w0, w0", 1)
        .replace("cmp w26", "cmp w0", 1),
    )
    assert semantic_audit(
        "aarch64-unknown-linux-gnu",
        current_aarch64.replace(
            ".Linner:\nlsrv", ".Linner:\nldr x5, [x22], #1\nlsrv", 1
        ),
    )
    for counter_overwrite in (
        "ldnp w5, w26, [x0]",
        "ldxp w5, w26, [x0]",
        "ldaxp x5, x22, [x0]",
        "casp x5, x22, x7, x8, [x0]",
    ):
        assert semantic_audit(
            "aarch64-unknown-linux-gnu",
            current_aarch64.replace(
                ".Linner:\nlsrv",
                f".Linner:\n{counter_overwrite}\nlsrv",
                1,
            ),
        )
    assert semantic_audit(
        "aarch64-unknown-linux-gnu",
        current_aarch64.replace("b.hi .Linner", "bc.eq .Lsecret\nb.hi .Linner", 1),
    )
    assert semantic_audit(
        "aarch64-unknown-linux-gnu",
        current_aarch64.replace("b.hi .Linner", "br x9\nb.hi .Linner", 1),
    )
    for hidden_control in ("ret x9", "eret", "eretaa", "eretab", "drps"):
        assert semantic_audit(
            "aarch64-unknown-linux-gnu",
            current_aarch64.replace(
                "b.hi .Linner", f"{hidden_control}\nb.hi .Linner", 1
            ),
        )
    assert semantic_audit(
        "aarch64-unknown-linux-gnu",
        current_aarch64.replace(
            ".Louter:\nmov w26, #9\n.Linner:",
            ".Linner:\nmov w26, #9\n.Louter:",
            1,
        ),
    )

    thumb_synthetic = "\n".join(
        f"{synthetic_protected_symbol(group)}:\n{thumb_sample(group)}\n"
        f".size {synthetic_protected_symbol(group)}, .-"
        f"{synthetic_protected_symbol(group)}"
        for group in GROUPS
    )
    assert semantic_audit("thumbv7em-none-eabihf", thumb_synthetic) == []
    thumb_call_impersonation = thumb_synthetic
    for marker, replacement in (
        ("lsrs r0, r1, r2", "bl lsrs"),
        ("ands r0, r3", "bl ands"),
        ("orrs r0, r4", "bl orrs"),
    ):
        thumb_call_impersonation = thumb_call_impersonation.replace(
            marker, replacement
        )
    assert semantic_audit("thumbv7em-none-eabihf", thumb_call_impersonation)
    for hidden_control in ("it eq", "tbb [pc, r0]", "blx r0", "beq.n .secret"):
        assert semantic_audit(
            "thumbv7em-none-eabihf",
            thumb_synthetic.replace("bhi.w .inner", f"{hidden_control}\nbhi.w .inner", 1),
        )
    for hidden_control in (
        "pop {pc}",
        "pop {r4, pc}",
        "ldmia r0!, {r4, pc}",
        "pop {r4, r5, r6, r7, pc}",
    ):
        assert semantic_audit(
            "thumbv7em-none-eabihf",
            thumb_synthetic.replace(
                "bhi.w .inner", f"{hidden_control}\nbhi.w .inner", 1
            ),
        )

    wasm_selection = "i32.shr_u\ni32.and\ni32.xor\n"
    wasm_loops = (
        "i32.const 0\n"
        "local.set 4\n"
        "loop\n"
        "local.get 2\n"
        "i32.const 9\n"
        "local.set 12\n"
        "loop\n"
        "local.get 12\n"
        "i32.const -1\n"
        "i32.add\n"
        "local.tee 12\n"
        "i32.const 1\n"
        "i32.gt_u\n"
        "br_if 0\n"
        "end_loop\n"
        "local.get 4\n"
        "i32.const 1\n"
        "i32.add\n"
        "local.tee 4\n"
        "i32.const 32\n"
        "i32.ne\n"
        "br_if 0\n"
    )
    old_wasm_validator = (
        f"call {synthetic_validator}\n"
        "i32.const 255\n"
        "i32.and\n"
        "br_if 0\n"
    )
    current_wasm_validator = old_wasm_validator.replace(
        "i32.and\nbr_if", "i32.and\ni32.eqz\nbr_if"
    )
    old_wasm_g1 = (
        old_wasm_validator
        + wasm_selection
        + wasm_loops
        + "i32.const 144\ni32.eqz\nbr_if 0\n"
    )
    old_wasm_g2 = (
        old_wasm_validator
        + "i32.const 96\ni32.eqz\nlocal.tee 5\nbr_if 0\n"
        + "local.get 5\nbr_if 0\nlocal.get 5\nbr_if 0\n"
        + wasm_selection
        + wasm_loops
        + "i32.const 288\ni32.eqz\nbr_if 0\n"
    )
    assert all(wasm_public_control_markers(old_wasm_g1, "G1Projective").values())
    assert all(wasm_public_control_markers(old_wasm_g2, "G2Projective").values())

    current_wasm = current_wasm_validator + wasm_selection + wasm_loops
    current_wasm_assembly = "\n".join(
        f"{synthetic_protected_symbol(group)}:\n{current_wasm}end_function"
        for group in GROUPS
    )
    assert semantic_audit("wasm32-unknown-unknown", current_wasm_assembly) == []
    assert semantic_audit(
        "wasm32-unknown-unknown",
        current_wasm_assembly.replace(
            synthetic_validator, "evil_secret_be_bytes_are_valid"
        ),
    )
    wasm_call_impersonation = current_wasm_assembly.replace(
        "i32.shr_u", "call symbol.i32.shr_u"
    ).replace("i32.xor", "call symbol.i32.xor")
    assert semantic_audit("wasm32-unknown-unknown", wasm_call_impersonation)
    old_wasm_assembly = "\n".join(
        (
            f"{synthetic_protected_symbol(group)}:\n"
            f"{old_wasm_g1 if group == 'G1Projective' else old_wasm_g2}"
            "end_function"
        )
        for group in GROUPS
    )
    assert semantic_audit("wasm32-unknown-unknown", old_wasm_assembly) == []
    assert semantic_audit(
        "wasm32-unknown-unknown",
        old_wasm_assembly.replace(
            "local.get 5\nbr_if 0",
            "local.get 77\nlocal.set 5\nlocal.get 5\nbr_if 0",
            1,
        ),
    )
    assert semantic_audit(
        "wasm32-unknown-unknown",
        old_wasm_assembly.replace(
            "local.get 5\nbr_if 0",
            "local.get 77\nlocal.tee 5\ndrop\nlocal.get 5\nbr_if 0",
            1,
        ),
    )
    assert semantic_audit(
        "wasm32-unknown-unknown",
        current_wasm_assembly.replace(
            "i32.const 0\nlocal.set 4", "local.get 9\nlocal.set 4", 1
        ),
    )
    assert semantic_audit(
        "wasm32-unknown-unknown",
        current_wasm_assembly.replace("end_function", "br_if 0\nend_function", 1),
    )
    assert semantic_audit(
        "wasm32-unknown-unknown",
        current_wasm_assembly.replace("i32.gt_u\nbr_if 0", "i32.gt_u\nbr_if 1", 1),
    )
    for hidden_control in (
        "br_table 0 0",
        "call_indirect 0",
        "return_call_indirect 0",
        "br_on_null 0",
        "br_on_non_null 0",
        "br_on_cast 0",
        "call_ref",
        "return_call_ref",
        "return",
    ):
        assert semantic_audit(
            "wasm32-unknown-unknown",
            current_wasm_assembly.replace(
                "end_function", f"{hidden_control}\nend_function", 1
            ),
        )
    fake_loop_comment = (
        "# i32.const 0 local.set 4 loop i32.const 9 local.set 12 loop "
        "local.get 12 i32.const -1 i32.add local.tee 12 i32.const 1 i32.gt_u "
        "br_if 0 end_loop local.get 4 i32.const 1 i32.add local.tee 4 "
        "i32.const 32 i32.ne br_if 0"
    )
    secret_wasm = current_wasm_assembly.replace(
        wasm_loops,
        f"{fake_loop_comment}\nlocal.get 77\nbr_if 0\nlocal.get 77\nbr_if 0\n",
    )
    assert semantic_audit("wasm32-unknown-unknown", secret_wasm)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--target", choices=sorted(SUPPORTED_TARGETS))
    parser.add_argument("--compiler-profile", choices=sorted(COMPILER_PROFILES))
    parser.add_argument("assembly", nargs="?", type=Path)
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("BLS secret-assembly checker self-test passed")
        if not args.target and not args.assembly:
            return 0
    if not args.target or args.compiler_profile is None or args.assembly is None:
        parser.error(
            "--target, --compiler-profile, and exactly one assembly file are required"
        )

    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        descriptor = os.open(args.assembly, flags)
    except OSError as error:
        print(f"error: cannot open assembly input: {error}", file=sys.stderr)
        return 1
    try:
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                print("error: assembly input is not a regular file", file=sys.stderr)
                return 1
            assembly_bytes = stream.read()
    except OSError as error:
        print(f"error: cannot read assembly input: {error}", file=sys.stderr)
        return 1

    errors = audit(
        args.target,
        assembly_bytes,
        compiler_profile=args.compiler_profile,
    )
    if errors:
        for error in errors:
            print(f"error: {args.target}: {error}", file=sys.stderr)
        print(
            "error: compiler output changed; inspect the emitted assembly before updating this fail-closed gate",
            file=sys.stderr,
        )
        return 1

    print(
        f"{args.target}: G1/G2 protected multiplication retained the reviewed "
        "public-control branch fingerprint and mask selection"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
