#!/usr/bin/env python3
"""Fail closed if optimized BLS secret-scalar loops gain extra branches.

This is a compiler-output regression gate, not a general proof of constant
time. It checks the two concrete protected multiplication entry points on
every supported target. Each function must retain its reviewed control-flow
fingerprint: canonical-input rejection, two fixed-count loop backedges, and
only the target-specific constant-size copy guards emitted by LLVM. It also
requires evidence that the secret bit is lowered through mask selection.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SUPPORTED_TARGETS = {
    "x86_64-unknown-linux-gnu": "x86_64",
    "aarch64-unknown-linux-gnu": "aarch64",
    "thumbv7em-none-eabihf": "thumb",
    "wasm32-unknown-unknown": "wasm32",
}
GROUPS = ("G1Projective", "G2Projective")
EXPECTED_BRANCHES = {
    "x86_64-unknown-linux-gnu": {
        "G1Projective": ("je", "ja", "jne"),
        "G2Projective": ("je", "ja", "jne"),
    },
    "aarch64-unknown-linux-gnu": {
        "G1Projective": ("tbz", "b.hi", "b.ne"),
        "G2Projective": ("tbz", "b.hi", "b.ne"),
    },
    "thumbv7em-none-eabihf": {
        "G1Projective": ("beq.w", "bhi.w", "bne.w"),
        "G2Projective": ("beq.w", "bhi.w", "bne.w"),
    },
    # wasm-ld retains constant-size memcpy guards which compare only immediate
    # lengths. They are public compiler scaffolding, not secret-bit branches.
    "wasm32-unknown-unknown": {
        "G1Projective": ("br_if",) * 4,
        "G2Projective": ("br_if",) * 7,
    },
}


def instruction(line: str) -> str:
    line = line.split("#", 1)[0].split("//", 1)[0].strip()
    if not line or line.startswith(".") or line.endswith(":"):
        return ""
    return line.split(None, 1)[0].lower()


def conditional_branch_mnemonics(body: str, architecture: str) -> list[str]:
    mnemonics = [instruction(line) for line in body.splitlines()]
    if architecture == "x86_64":
        return [value for value in mnemonics if value.startswith("j") and value != "jmp"]
    if architecture == "aarch64":
        return [
            value
            for value in mnemonics
            if value.startswith("b.") or value in {"cbz", "cbnz", "tbz", "tbnz"}
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
            or any(value == condition or value == f"{condition}.w" for condition in conditions)
        ]
    if architecture == "wasm32":
        return [value for value in mnemonics if value in {"br_if", "if"}]
    raise ValueError(f"unsupported architecture: {architecture}")


def selection_markers(body: str, architecture: str) -> dict[str, bool]:
    lowered = body.lower()
    if architecture == "x86_64":
        return {
            "secret-bit extraction": re.search(r"\bbt[a-z]*\b", lowered) is not None,
            "set-to-mask": re.search(r"\bset[a-z]+\b", lowered) is not None,
            "masked AND": re.search(r"\bv?pandn?\b", lowered) is not None,
            "masked OR": re.search(r"\bv?por\b", lowered) is not None,
        }
    if architecture == "aarch64":
        return {
            "secret-bit extraction": re.search(r"\b(lsr|lsrv|ubfx)\b", lowered) is not None,
            "all-bits mask": re.search(r"\b(neg|csetm)\b", lowered) is not None,
            "branchless vector blend": re.search(r"\b(bit|bif|bsl)\b", lowered) is not None,
        }
    if architecture == "thumb":
        return {
            "secret-bit extraction": re.search(r"\b(lsr|lsrs|lsrv|ubfx)\b", lowered) is not None,
            "masked AND": re.search(r"\bands?\b", lowered) is not None,
            "masked OR": re.search(r"\borrs?\b", lowered) is not None,
        }
    if architecture == "wasm32":
        return {
            "secret-bit extraction": ".shr_u" in lowered,
            "masked AND": ".and" in lowered,
            "masked XOR blend": ".xor" in lowered,
        }
    raise ValueError(f"unsupported architecture: {architecture}")


def wasm_public_control_markers(body: str, group: str) -> dict[str, bool]:
    normalized = " ".join(body.split())
    markers = {
        "canonical-input branch": re.search(
            r"secret_be_bytes_are_valid\S* i32\.const 255 i32\.and br_if", normalized
        )
        is not None,
        "fixed eight-bit loop": re.search(
            r"i32\.const 1 i32\.gt_u br_if", normalized
        )
        is not None,
        "fixed 32-byte loop": re.search(
            r"i32\.const 32 i32\.ne br_if", normalized
        )
        is not None,
    }
    if group == "G1Projective":
        markers["constant 144-byte copy guard"] = (
            re.search(r"i32\.const 144 i32\.eqz br_if", normalized) is not None
            and normalized.count("i32.eqz") == 1
        )
    else:
        markers["constant G2 copy guards"] = (
            re.search(r"i32\.const 96 i32\.eqz local\.tee \d+ br_if", normalized)
            is not None
            and re.search(r"i32\.const 288 i32\.eqz br_if", normalized) is not None
            and normalized.count("i32.eqz") == 2
        )
    return markers


def extract_functions(assembly: str) -> dict[str, list[str]]:
    lines = assembly.splitlines()
    found = {group: [] for group in GROUPS}
    for index, line in enumerate(lines):
        stripped = line.strip()
        if "multiply_secret_be_bytes" not in stripped or not stripped.endswith(":"):
            continue
        group = next((name for name in GROUPS if name in stripped), None)
        if group is None:
            continue
        body = [line]
        for following in lines[index + 1 :]:
            body.append(following)
            following_stripped = following.strip()
            if (
                following_stripped == "end_function"
                or (
                    following_stripped.startswith(".size")
                    and "multiply_secret_be_bytes" in following_stripped
                )
            ):
                break
        found[group].append("\n".join(body))
    return found


def audit(target: str, assembly: str) -> list[str]:
    architecture = SUPPORTED_TARGETS[target]
    functions = extract_functions(assembly)
    errors: list[str] = []
    for group in GROUPS:
        bodies = functions[group]
        if len(bodies) != 1:
            errors.append(f"{group}: found {len(bodies)} protected multiplication bodies; expected 1")
            continue
        body = bodies[0]
        branches = conditional_branch_mnemonics(body, architecture)
        expected_branches = EXPECTED_BRANCHES[target][group]
        if tuple(branches) != expected_branches:
            errors.append(
                f"{group}: conditional branch shape changed: {branches!r}; expected "
                f"{list(expected_branches)!r}"
            )
        markers = selection_markers(body, architecture)
        missing = [name for name, present in markers.items() if not present]
        if missing:
            errors.append(f"{group}: missing mask-selection evidence: {', '.join(missing)}")
        if architecture == "wasm32":
            public_markers = wasm_public_control_markers(body, group)
            missing = [name for name, present in public_markers.items() if not present]
            if missing:
                errors.append(
                    f"{group}: unexplained WebAssembly branch context: {', '.join(missing)}"
                )
    return errors


def self_test() -> None:
    samples = {
        "x86_64": "je .bad\nsetb %al\nbtq %rcx, %rax\npand %xmm0, %xmm1\npor %xmm1, %xmm2\nja .inner\njne .outer",
        "aarch64": "tbz w0, #0, .bad\nlsrv w1, w2, w3\nneg x9, x8\nbit v1.16b, v3.16b, v0.16b\nb.hi .inner\nb.ne .outer",
        "thumb": "beq.w .bad\nlsrs r0, r1, r2\nands r0, r3\norrs r0, r4\nbhi.w .inner\nbne.w .outer",
        "wasm32": "br_if 0\ni32.shr_u\ni32.and\ni32.xor\nbr_if 1\nbr_if 0",
    }
    for architecture, body in samples.items():
        branches = conditional_branch_mnemonics(body, architecture)
        assert len(branches) == 3, (architecture, branches)
        assert all(selection_markers(body, architecture).values()), architecture

    synthetic = "\n".join(
        f"symbol_{group}_multiply_secret_be_bytes:\n{samples['x86_64']}\n"
        f".size symbol_{group}_multiply_secret_be_bytes"
        for group in GROUPS
    )
    assert audit("x86_64-unknown-linux-gnu", synthetic) == []
    altered = synthetic.replace("jne .outer", "jne .outer\nje .secret", 1)
    assert audit("x86_64-unknown-linux-gnu", altered)

    wasm_common = (
        "secret_be_bytes_are_valid_hash i32.const 255 i32.and br_if "
        "i32.const 1 i32.gt_u br_if i32.const 32 i32.ne br_if"
    )
    wasm_g1 = f"{wasm_common} i32.const 144 i32.eqz br_if"
    assert all(wasm_public_control_markers(wasm_g1, "G1Projective").values())
    wasm_g2 = (
        f"{wasm_common} i32.const 96 i32.eqz local.tee 5 br_if "
        "local.get 5 br_if local.get 5 br_if i32.const 288 i32.eqz br_if"
    )
    assert all(wasm_public_control_markers(wasm_g2, "G2Projective").values())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--target", choices=sorted(SUPPORTED_TARGETS))
    parser.add_argument("assembly", nargs="*", type=Path)
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("BLS secret-assembly checker self-test passed")
        if not args.target and not args.assembly:
            return 0
    if not args.target or not args.assembly:
        parser.error("--target and at least one assembly file are required")

    combined = "\n".join(path.read_text(encoding="utf-8") for path in args.assembly)
    errors = audit(args.target, combined)
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
