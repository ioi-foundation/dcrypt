#!/usr/bin/env python3
"""Fail closed if optimized GHASH multiplication gains secret branches.

This is a compiler-output regression gate, not a general proof of constant
time. It checks the concrete owned GHASH multiplication entry point on every
supported target. The reviewed implementation has one conditional branch: the
backedge of a fixed-count loop. Whole-width arithmetic masks select both the
addend and reduction polynomial without branching.
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
EXPECTED_BRANCHES = {
    "x86_64-unknown-linux-gnu": ("jne",),
    "aarch64-unknown-linux-gnu": ("b.ne",),
    "thumbv7em-none-eabihf": ("bne.w",),
    "wasm32-unknown-unknown": ("br_if",),
}


def code_text(line: str, architecture: str) -> str:
    """Return instruction text without target-specific trailing comments."""
    if architecture == "x86_64":
        line = line.split("#", 1)[0]
    else:
        line = line.split("//", 1)[0]
    return line.strip().lower()


def instruction_parts(line: str, architecture: str) -> tuple[str, str]:
    line = code_text(line, architecture)
    if not line or line.startswith(".") or line.endswith(":"):
        return "", ""
    parts = line.split(None, 1)
    return parts[0], parts[1].strip() if len(parts) == 2 else ""


def instruction(line: str, architecture: str) -> str:
    return instruction_parts(line, architecture)[0]


def executable_lines(body: str, architecture: str) -> list[tuple[int, str, str]]:
    result = []
    for index, line in enumerate(body.splitlines()):
        mnemonic, operands = instruction_parts(line, architecture)
        if mnemonic:
            result.append((index, mnemonic, operands))
    return result


def conditional_branch_mnemonics(body: str, architecture: str) -> list[str]:
    mnemonics = [instruction(line, architecture) for line in body.splitlines()]
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
        return [value for value in mnemonics if value in {"br_if", "if"}]
    raise ValueError(f"unsupported architecture: {architecture}")


def forbidden_indirect_control(body: str, architecture: str) -> list[str]:
    """Identify indirect/table control transfers, excluding ordinary returns."""
    found = []
    bounds = fixed_loop_bounds(body, architecture)
    loop_end = bounds[1] if bounds is not None else -1
    return_index = normal_return_index(body, architecture, loop_end)
    for index, mnemonic, operands in executable_lines(body, architecture):
        if architecture == "x86_64":
            if mnemonic in {"jmp", "jmpq", "ljmp"} and operands.startswith("*"):
                found.append(f"{mnemonic} {operands}")
            elif mnemonic in {"ret", "retq"} and index != return_index:
                found.append(f"{mnemonic} {operands}")
            elif mnemonic in {"call", "callq"} and operands.startswith("*"):
                reviewed_zeroize = (
                    index > loop_end and is_reviewed_u128_zeroize_target(operands)
                )
                reviewed_cleanup_panic = (
                    return_index is not None
                    and index > return_index
                    and is_panic_in_cleanup_target(operands)
                )
                if not (reviewed_zeroize or reviewed_cleanup_panic):
                    found.append(f"{mnemonic} {operands}")
        elif architecture == "aarch64":
            if mnemonic in {
                "br", "blr", "braa", "brab", "braaz", "brabz",
                "blraa", "blrab", "blraaz", "blrabz",
            } or (
                mnemonic == "ret"
                and (index != return_index or operands not in {"", "x30", "lr"})
            ):
                found.append(f"{mnemonic} {operands}")
        elif architecture == "thumb":
            returns_through_pc = (
                mnemonic in {"pop", "pop.w"}
                and re.search(r"\b(?:pc|r15)\b", operands) is not None
            )
            first_destination = operands.split(",", 1)[0].strip()
            if (
                mnemonic in {"blx", "blxns", "bxns", "tbb", "tbh"}
                or re.fullmatch(r"it[te]{0,3}", mnemonic) is not None
                or (
                    mnemonic == "bx"
                    and (operands not in {"lr", "r14"} or index != return_index)
                )
                or (returns_through_pc and index != return_index)
                or first_destination in {"pc", "r15"}
            ):
                found.append(f"{mnemonic} {operands}")
        elif architecture == "wasm32":
            if mnemonic in {"br_table", "call_indirect", "return_call_indirect", "return"}:
                found.append(f"{mnemonic} {operands}")
        else:
            raise ValueError(f"unsupported architecture: {architecture}")
    return found


def extract_functions(assembly: str) -> list[str]:
    lines = assembly.splitlines()
    found: list[str] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not (
            "ghash" in stripped
            and "GHash" in stripped
            and "gf_multiply" in stripped
            and stripped.endswith(":")
        ):
            continue
        body = [line]
        for following in lines[index + 1 :]:
            body.append(following)
            following_stripped = following.strip()
            if (
                following_stripped == "end_function"
                or (
                    following_stripped.startswith(".size")
                    and "gf_multiply" in following_stripped
                )
            ):
                break
        found.append("\n".join(body))
    return found


def selection_markers(body: str, architecture: str) -> dict[str, bool]:
    lowered = "\n".join(
        f"{mnemonic} {operands}".strip()
        for _, mnemonic, operands in executable_lines(body, architecture)
    )
    if architecture == "x86_64":
        return {
            "secret-accumulator sign mask": re.search(r"\bsarq\s+\$63\b", lowered) is not None,
            "whole-width masked selection": len(re.findall(r"\bandq\b", lowered)) >= 3,
            "branchless reduction mask": (
                re.search(r"\bnegq\b", lowered) is not None
                and re.search(r"\bsbbq\b", lowered) is not None
            ),
            "masked accumulation/reduction": len(re.findall(r"\bxorq\b", lowered)) >= 3,
            "fixed one-bit field shift": re.search(r"\bshrdq\s+\$1\b", lowered) is not None,
        }
    if architecture == "aarch64":
        return {
            "secret-accumulator sign mask": re.search(r"\basr\s+x\d+,\s*x\d+,\s*#63\b", lowered)
            is not None,
            "branchless reduction bit mask": re.search(
                r"\bsbfx\s+x\d+,\s*x\d+,\s*#0,\s*#1\b", lowered
            )
            is not None,
            "whole-width masked selection": len(re.findall(r"\band\s+x", lowered)) >= 3,
            "masked accumulation/reduction": len(re.findall(r"\beor\s+x", lowered)) >= 3,
            "fixed one-bit field shift": re.search(r"\bextr\s+x[^\n]+#1\b", lowered) is not None,
        }
    if architecture == "thumb":
        return {
            "secret-accumulator sign mask": "asr #31" in lowered,
            "whole-width masked selection": len(re.findall(r"\band(?:s|\.w)?\b", lowered)) >= 3,
            "branchless reduction mask": (
                re.search(r"\brsbs\b", lowered) is not None
                and re.search(r"\bsbcs?\b", lowered) is not None
            ),
            "masked accumulation/reduction": len(re.findall(r"\beors?(?:\.w)?\b", lowered)) >= 3,
            "fixed one-bit field shift": (
                re.search(r"\blsrs?(?:\.w)?\b", lowered) is not None
                and re.search(r"\brrx\b", lowered) is not None
            ),
        }
    if architecture == "wasm32":
        return {
            "secret-accumulator sign mask": "i64.shr_s" in lowered,
            "whole-width masked selection": lowered.count("i64.and") >= 3,
            "branchless reduction mask": "i64.sub" in lowered,
            "masked accumulation/reduction": lowered.count("i64.xor") >= 3,
            "fixed one-bit field shift": "i64.shr_u" in lowered,
        }
    raise ValueError(f"unsupported architecture: {architecture}")


def fixed_loop_bounds(body: str, architecture: str) -> tuple[int, int] | None:
    """Validate one noninterfering fixed counter and return loop bounds."""
    lines = body.splitlines()
    executable = executable_lines(body, architecture)
    expected_branch = next(
        EXPECTED_BRANCHES[target][0]
        for target, candidate in SUPPORTED_TARGETS.items()
        if candidate == architecture
    )
    branches = [entry for entry in executable if entry[1] == expected_branch]
    if len(branches) != 1:
        return None
    branch_position = executable.index(branches[0])
    branch_index, _, branch_operands = branches[0]

    if architecture == "wasm32":
        if branch_operands != "0" or branch_position < 4:
            return None
        counter_get = executable[branch_position - 4]
        decrement = executable[branch_position - 3]
        addition = executable[branch_position - 2]
        counter_tee = executable[branch_position - 1]
        if not (
            counter_get[1] == "local.get"
            and re.fullmatch(r"\d+", counter_get[2])
            and decrement[1:] == ("i32.const", "-2")
            and addition[1:] == ("i32.add", "")
            and counter_tee[1] == "local.tee"
            and counter_tee[2] == counter_get[2]
        ):
            return None
        loop_start = next(
            (
                index
                for index in range(branch_index - 1, -1, -1)
                if code_text(lines[index], architecture).split(None, 1)[0:1] == ["loop"]
            ),
            None,
        )
        loop_end = next(
            (
                index
                for index in range(branch_index + 1, len(lines))
                if code_text(lines[index], architecture).split(None, 1)[0:1]
                == ["end_loop"]
            ),
            None,
        )
        if loop_start is None or loop_end is None:
            return None
        prior = [entry for entry in executable if entry[0] < loop_start]
        initializations = [
            (left, right)
            for left, right in zip(prior, prior[1:])
            if left[1:] == ("i32.const", "128")
            and right[1] == "local.set"
            and right[2] == counter_get[2]
        ]
        if len(initializations) != 1:
            return None
        init_set = initializations[0][1]
        counter_references = [
            entry
            for entry in executable
            if entry[1] in {"local.get", "local.set", "local.tee"}
            and entry[2] == counter_get[2]
        ]
        if counter_references != [init_set, counter_get, counter_tee]:
            return None
        return loop_start, branch_index

    if branch_position == 0:
        return None
    decrement_position = branch_position - 1
    if architecture in {"aarch64", "thumb"}:
        flag_writers = {
            "adds", "subs", "ands", "bics", "adcs", "sbcs", "negs",
            "cmp", "cmn", "tst", "ccmp", "ccmn", "movs", "lsls", "lsrs",
            "asrs", "eors", "orrs", "muls", "rsbs",
        }
        decrement_position = next(
            (
                position
                for position in range(branch_position - 1, -1, -1)
                if executable[position][1].removesuffix(".w").removesuffix(".n")
                in flag_writers
            ),
            -1,
        )
        if decrement_position < 0:
            return None
    decrement = executable[decrement_position]

    if architecture == "x86_64":
        match = re.fullmatch(r"%(r(?:[0-9]+|[a-z]+)d)", decrement[2])
        if decrement[1] != "decl" or match is None:
            return None
        counter = f"%{match.group(1)}"
        init_pattern = re.compile(rf"\$128,\s*{re.escape(counter)}$")
        init_mnemonics = {"movl"}
    elif architecture == "aarch64":
        match = re.fullmatch(r"(w\d+),\s*\1,\s*#1", decrement[2])
        if decrement[1] != "subs" or match is None:
            return None
        counter = match.group(1)
        init_pattern = re.compile(rf"{re.escape(counter)},\s*#128$")
        init_mnemonics = {"mov"}
    elif architecture == "thumb":
        match = re.fullmatch(r"(r\d+)(?:,\s*\1)?,\s*#4", decrement[2])
        if decrement[1] not in {"subs", "subs.w"} or match is None:
            return None
        counter = match.group(1)
        init_pattern = re.compile(rf"{re.escape(counter)},\s*#128$")
        init_mnemonics = {"movs", "movs.w"}
    else:
        raise ValueError(f"unsupported architecture: {architecture}")

    target_label = branch_operands.split(",", 1)[0].strip()
    loop_start = next(
        (
            index
            for index, line in enumerate(lines[:branch_index])
            if code_text(line, architecture) == f"{target_label}:"
        ),
        None,
    )
    if loop_start is None:
        return None
    initializations = [
        entry
        for entry in executable
        if entry[0] < loop_start
        and entry[1] in init_mnemonics
        and init_pattern.fullmatch(entry[2])
    ]
    if len(initializations) != 1:
        return None
    initialization = initializations[0]

    if architecture == "x86_64":
        register_base = counter[1:-1]
        alias = re.compile(rf"%{re.escape(register_base)}(?:b|w|d)?\b")
        uses = [entry for entry in executable if alias.search(entry[2])]
        if uses != [initialization, decrement]:
            return None
    elif architecture == "aarch64":
        register_number = counter[1:]
        alias = re.compile(rf"\b[wx]{re.escape(register_number)}\b")
        uses = [entry for entry in executable if alias.search(entry[2])]
        if uses != [initialization, decrement]:
            return None
    else:
        loop_entries = [
            entry for entry in executable if loop_start < entry[0] < decrement[0]
        ]
        counter_word = re.compile(rf"\b{re.escape(counter)}\b")
        first_use = next(
            (entry for entry in loop_entries if counter_word.search(entry[2])), None
        )
        if first_use is None or first_use[1] not in {"strd", "strd.w"}:
            return None
        spill = re.fullmatch(
            rf"r\d+,\s*{re.escape(counter)},\s*\[sp,\s*#(\d+)\]",
            first_use[2],
        )
        if spill is None:
            return None
        counter_slot = int(spill.group(1)) + 4
        destinations = [
            entry
            for entry in loop_entries
            if re.match(rf"{re.escape(counter)},\s*", entry[2])
        ]
        if not destinations:
            return None
        reload = destinations[-1]
        if not (
            reload[1] in {"ldr", "ldr.w"}
            and re.fullmatch(
                rf"{re.escape(counter)},\s*\[sp,\s*#{counter_slot}\]", reload[2]
            )
        ):
            return None
        slot_writers = []
        for entry in loop_entries:
            if not entry[1].startswith("str"):
                continue
            offset_match = re.search(r"\[sp,\s*#(\d+)\]", entry[2])
            if offset_match is None:
                continue
            offset = int(offset_match.group(1))
            written_offsets = {offset, offset + 4} if entry[1].startswith("strd") else {offset}
            if counter_slot in written_offsets:
                slot_writers.append(entry)
        if slot_writers != [first_use]:
            return None
        if any(
            counter_word.search(entry[2])
            for entry in executable[decrement_position + 1 : branch_position]
        ):
            return None
        pre_loop = [
            entry
            for entry in executable
            if initialization[0] < entry[0] < loop_start
            and re.match(rf"{re.escape(counter)},\s*", entry[2])
        ]
        if pre_loop:
            return None
    return loop_start, branch_index


def loop_has_no_calls(body: str, architecture: str) -> bool:
    bounds = fixed_loop_bounds(body, architecture)
    if bounds is None:
        return False
    loop_start, loop_end = bounds
    call_ops = {
        "x86_64": {"call", "callq", "lcall"},
        "aarch64": {"bl", "blr", "blraa", "blrab", "blraaz", "blrabz"},
        "thumb": {"bl", "blx", "blxns"},
        "wasm32": {"call", "call_indirect", "return_call", "return_call_indirect"},
    }[architecture]
    return all(
        mnemonic not in call_ops
        for index, mnemonic, _ in executable_lines(body, architecture)
        if loop_start < index < loop_end
    )


def is_reviewed_u128_zeroize_target(operands: str) -> bool:
    target = operands.strip().lower()
    if target == "zeroize":
        return True
    suffix = r"(?:@gotpcrel\(%rip\)|@plt)?"
    legacy = (
        r"\*?_zn58_\$lt\$u128\$u20\$as\$u20\$dcrypt_internal\.\.zeroing\.\."
        r"zeroize\$gt\$7zeroize17h[0-9a-f]+e" + suffix
    )
    v0 = (
        r"\*?_rnvxso_ntc[a-z0-9]+_15dcrypt_internal7zeroingontb5_"
        r"7zeroize7zeroize" + suffix
    )
    return re.fullmatch(legacy, target) is not None or re.fullmatch(v0, target) is not None


def is_panic_in_cleanup_target(operands: str) -> bool:
    target = operands.strip().lower()
    legacy = (
        r"\*?_zn4core9panicking16panic_in_cleanup17h[0-9a-f]+e"
        r"(?:@gotpcrel\(%rip\)|@plt)?"
    )
    v0 = (
        r"\*?_rnvntc[a-z0-9]+_4core9panicking16panic_in_cleanup"
        r"(?:@gotpcrel\(%rip\)|@plt)?"
    )
    return re.fullmatch(legacy, target) is not None or re.fullmatch(v0, target) is not None


def normal_return_index(body: str, architecture: str, after: int) -> int | None:
    for index, mnemonic, operands in executable_lines(body, architecture):
        if index <= after:
            continue
        if architecture == "x86_64" and mnemonic in {"ret", "retq"}:
            return index
        if architecture == "aarch64" and mnemonic == "ret":
            return index
        if architecture == "thumb" and (
            (mnemonic == "bx" and operands in {"lr", "r14"})
            or (mnemonic in {"pop", "pop.w"} and re.search(r"\b(?:pc|r15)\b", operands))
        ):
            return index
        if architecture == "wasm32" and mnemonic == "end_function":
            return index
    return None


def normal_path_call_counts(body: str, architecture: str) -> tuple[int, int]:
    bounds = fixed_loop_bounds(body, architecture)
    if bounds is None:
        return 0, 0
    _, loop_end = bounds
    return_index = normal_return_index(body, architecture, loop_end)
    if return_index is None:
        return 0, 0
    call_ops = {
        "x86_64": {"call", "callq"},
        "aarch64": {"bl"},
        "thumb": {"bl"},
        "wasm32": {"call"},
    }[architecture]
    calls = [
        operands
        for index, mnemonic, operands in executable_lines(body, architecture)
        if loop_end < index < return_index and mnemonic in call_ops
    ]
    return len(calls), sum(is_reviewed_u128_zeroize_target(target) for target in calls)


def audit(target: str, assembly: str) -> list[str]:
    architecture = SUPPORTED_TARGETS[target]
    bodies = extract_functions(assembly)
    if len(bodies) != 1:
        return [f"found {len(bodies)} owned GHASH multiplication bodies; expected 1"]

    body = bodies[0]
    errors: list[str] = []
    branches = conditional_branch_mnemonics(body, architecture)
    if tuple(branches) != EXPECTED_BRANCHES[target]:
        errors.append(
            f"conditional branch shape changed: {branches!r}; expected "
            f"{list(EXPECTED_BRANCHES[target])!r}"
        )

    bounds = fixed_loop_bounds(body, architecture)
    if bounds is None:
        errors.append(
            "fixed loop does not bind the 128 initialization, decrement, and sole backedge "
            "to one counter"
        )
    if not loop_has_no_calls(body, architecture):
        errors.append("fixed multiplication loop contains a call or could not be isolated")

    indirect = forbidden_indirect_control(body, architecture)
    if indirect:
        errors.append(
            f"indirect/table/IT conditional control present: {', '.join(indirect)}"
        )

    if bounds is None:
        markers = {"isolated multiplication loop": False}
    else:
        loop_start, loop_end = bounds
        loop_body = "\n".join(body.splitlines()[loop_start : loop_end + 1])
        markers = selection_markers(loop_body, architecture)
    missing = [name for name, present in markers.items() if not present]
    if missing:
        errors.append(f"missing arithmetic-mask evidence: {', '.join(missing)}")

    # x, v, z, and both reusable masks remain in clearing wrappers. Compiler
    # output changes that inline or remove this evidence require manual review.
    total_calls, zeroize_calls = normal_path_call_counts(body, architecture)
    if (total_calls, zeroize_calls) != (5, 5):
        errors.append(
            "normal post-loop path has "
            f"{total_calls} total calls/{zeroize_calls} reviewed u128 zeroization calls; "
            "expected exactly 5/5"
        )
    return errors


def synthetic_body(architecture: str) -> str:
    zeroize_opcode = {
        "x86_64": "callq Zeroize",
        "aarch64": "bl Zeroize",
        "thumb": "bl Zeroize",
        "wasm32": "call Zeroize",
    }[architecture]
    zeroize = "\n".join(zeroize_opcode for _ in range(5))
    if architecture == "x86_64":
        body = """
ghash_GHash_gf_multiply:
movl $128, %r10d
.LBB1_1:
sarq $63, %rbx
andq %rbx, %r14
andq %rbx, %r13
andq %r11, %rcx
negq %r14
sbbq %r15, %r15
xorq %r14, %rax
xorq %r13, %r9
xorq %r12, %rcx
shrdq $1, %rcx, %r8
decl %r10d
jne .LBB1_1
{zeroize}
retq
.size ghash_GHash_gf_multiply
"""
    elif architecture == "aarch64":
        body = """
ghash_GHash_gf_multiply:
mov w14, #128
.LBB1_1:
sbfx x17, x13, #0, #1
asr x16, x10, #63
and x1, x17, x15
and x18, x13, x16
and x2, x11, x16
extr x13, x11, x13, #1
eor x11, x1, x11, lsr #1
eor x9, x9, x2
eor x8, x8, x18
subs w14, w14, #1
b.ne .LBB1_1
{zeroize}
ret
.size ghash_GHash_gf_multiply
"""
    elif architecture == "thumb":
        body = """
ghash_GHash_gf_multiply:
movs r3, #128
.LBB1_1:
strd r2, r3, [sp, #20]
and.w r1, r10, r11, asr #31
and.w r2, r10, r11, asr #31
ands r4, r1
rsbs r4, r4, #0
sbcs r12, r3, #0
eor.w r2, r0, r1
eors r2, r4
eors r1, r2
lsrs.w r3, r0, #1
rrx r4, r10
ldr r3, [sp, #24]
subs r3, #4
mov r2, r1
str r5, [sp, #48]
bne.w .LBB1_1
{zeroize}
bx lr
.size ghash_GHash_gf_multiply
"""
    else:
        body = """
ghash_GHash_gf_multiply:
i32.const 128
local.set 6
i64.const 0
local.set 7
loop
i64.shr_s
i64.shr_u
i64.and
i64.and
i64.and
i64.sub
i64.xor
i64.xor
i64.xor
local.get 6
i32.const -2
i32.add
local.tee 6
br_if 0
end_loop
{zeroize}
end_function
"""
    return body.format(zeroize=zeroize)


def insert_in_loop(body: str, architecture: str, inserted: str) -> str:
    anchors = {
        "x86_64": "decl %r10d",
        "aarch64": "subs w14, w14, #1",
        "thumb": "subs r3, #4",
        "wasm32": "local.get 6\ni32.const -2",
    }
    anchor = anchors[architecture]
    return body.replace(anchor, f"{inserted}\n{anchor}", 1)


def self_test() -> None:
    for target, architecture in SUPPORTED_TARGETS.items():
        body = synthetic_body(architecture)
        assert audit(target, body) == [], (target, audit(target, body))
        assert audit(target, ""), (target, "missing body")
        wipe_opcode = {
            "x86_64": "callq Zeroize",
            "aarch64": "bl Zeroize",
            "thumb": "bl Zeroize",
            "wasm32": "call Zeroize",
        }[architecture]

        branch = EXPECTED_BRANCHES[target][0]
        altered = body.replace(branch, f"{branch}\n{branch}", 1)
        assert audit(target, altered), target

        altered = body.replace("128", "127", 1)
        assert audit(target, altered), target

        counter_mutations = {
            "x86_64": (
                ("movl $128, %r10d", "movl $128, %r11d"),
                ("decl %r10d", "decl %r11d"),
            ),
            "aarch64": (
                ("mov w14, #128", "mov w15, #128"),
                ("subs w14, w14, #1", "subs w15, w15, #1"),
            ),
            "thumb": (
                ("movs r3, #128", "movs r2, #128"),
                ("subs r3, #4", "subs r2, #4"),
            ),
            "wasm32": (
                ("local.set 6", "local.set 5"),
                ("local.tee 6", "local.tee 5"),
            ),
        }[architecture]
        for old, new in counter_mutations:
            altered = body.replace(old, new, 1)
            assert audit(target, altered), (target, old, new)

        if architecture == "thumb":
            altered = body.replace("subs r3, #4", "subs r3, #4\nmov r3, r0", 1)
            assert audit(target, altered), (target, "post-decrement counter overwrite")
            altered = body.replace(
                "strd r2, r3, [sp, #20]",
                "strd r2, r3, [sp, #20]\nstrd r0, r1, [sp, #20]",
                1,
            )
            assert audit(target, altered), (target, "counter spill overwrite")

        calls = {
            "x86_64": "callq helper",
            "aarch64": "bl helper",
            "thumb": "bl helper",
            "wasm32": "call helper",
        }
        altered = insert_in_loop(body, architecture, calls[architecture])
        assert audit(target, altered), (target, "loop call")

        indirect_controls = {
            "x86_64": ("jmp *%rax",),
            "aarch64": ("br x9", "blr x9"),
            "thumb": (
                "bx r0", "blx r0", "tbb [r0, r1]", "tbh [r0, r1, lsl #1]",
                "ldr pc, [r0]", "mov pc, r0", "it eq", "itt eq", "ite eq",
                "ittee eq", "pop {pc}", "bx lr", "add pc, r0",
            ),
            "wasm32": ("br_table 0", "call_indirect 0"),
        }[architecture]
        if architecture == "x86_64":
            indirect_controls += ("callq *%rax",)
        for control in indirect_controls:
            altered = insert_in_loop(body, architecture, control)
            assert audit(target, altered), (target, control)

        mask_mutations = {
            "x86_64": {
                "secret-accumulator sign mask": ("sarq $63", "shrq $63"),
                "whole-width masked selection": ("andq", "orq"),
                "branchless reduction mask": ("negq", "addq"),
                "masked accumulation/reduction": ("xorq", "orq"),
                "fixed one-bit field shift": ("shrdq $1", "shrdq $2"),
            },
            "aarch64": {
                "secret-accumulator sign mask": ("asr x16", "lsr x16"),
                "branchless reduction bit mask": ("sbfx x17", "ubfx x17"),
                "whole-width masked selection": ("and x", "orr x"),
                "masked accumulation/reduction": ("eor x", "orr x"),
                "fixed one-bit field shift": ("extr x13, x11, x13, #1", "lsr x13, x13, #1"),
            },
            "thumb": {
                "secret-accumulator sign mask": ("asr #31", "lsr #31"),
                "whole-width masked selection": ("and", "orr"),
                "branchless reduction mask": ("rsbs", "adds"),
                "masked accumulation/reduction": ("eor", "add"),
                "fixed one-bit field shift": ("rrx", "mov"),
            },
            "wasm32": {
                "secret-accumulator sign mask": ("i64.shr_s", "i64.shr_u"),
                "whole-width masked selection": ("i64.and", "i64.or"),
                "branchless reduction mask": ("i64.sub", "i64.add"),
                "masked accumulation/reduction": ("i64.xor", "i64.or"),
                "fixed one-bit field shift": ("i64.shr_u", "i64.shl"),
            },
        }[architecture]
        assert set(mask_mutations) == set(selection_markers(body, architecture)), target
        for marker, (old, new) in mask_mutations.items():
            altered = body.replace(old, new)
            assert not selection_markers(altered, architecture)[marker], (target, marker)
            assert audit(target, altered), (target, marker)

            # Marker-looking text in a directive, comment, or outside the
            # isolated loop must not satisfy executable in-loop evidence.
            altered = insert_in_loop(altered, architecture, f'.ascii "{old}"')
            comment = "#" if architecture == "x86_64" else "//"
            backedge = {
                "x86_64": "jne .LBB1_1",
                "aarch64": "b.ne .LBB1_1",
                "thumb": "bne.w .LBB1_1",
                "wasm32": "br_if 0",
            }[architecture]
            altered = altered.replace(
                backedge,
                f"{backedge} {comment} {old}",
                1,
            )
            altered = altered.replace(wipe_opcode, f"{old}\n{wipe_opcode}", 1)
            assert audit(target, altered), (target, marker, "non-loop marker text")

        altered = body.replace(wipe_opcode, '.ascii "Zeroize"', 1)
        assert audit(target, altered), target

        altered = body.replace(wipe_opcode, "Zeroize_marker:")
        assert audit(target, altered), (target, "fake zeroize labels")

        altered = body.replace(wipe_opcode, wipe_opcode.replace("Zeroize", "not_zeroize"))
        assert audit(target, altered), (target, "false zeroize call target")

        altered = body.replace(
            wipe_opcode,
            f"{calls[architecture]}\n{wipe_opcode}",
            1,
        )
        assert audit(target, altered), (target, "extra normal-path call")

        if architecture == "x86_64":
            zeroize_got = (
                "callq *_ZN58_$LT$u128$u20$as$u20$dcrypt_internal..zeroing.."
                "Zeroize$GT$7zeroize17h0123456789abcdefE@GOTPCREL(%rip)"
            )
            panic_got = (
                "callq *_ZN4core9panicking16panic_in_cleanup17h0123456789abcdefE"
                "@GOTPCREL(%rip)"
            )
            unwind_body = body.replace(wipe_opcode, zeroize_got).replace(
                "retq\n.size",
                f"retq\n.Lcleanup:\n{zeroize_got}\n{panic_got}\n.size",
                1,
            )
            assert audit(target, unwind_body) == [], audit(target, unwind_body)

            altered = unwind_body.replace(panic_got, "callq *%rax", 1)
            assert audit(target, altered), (target, "unreviewed EH indirect call")
            altered = body.replace("retq", f"{panic_got}\nretq", 1)
            assert audit(target, altered), (target, "cleanup panic on normal path")

        assert audit(target, body + "\n" + body), target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--target", choices=sorted(SUPPORTED_TARGETS))
    parser.add_argument("assembly", nargs="*", type=Path)
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("GHASH secret-assembly checker self-test passed")
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
            "error: compiler output changed; inspect optimized GHASH assembly before updating this fail-closed gate",
            file=sys.stderr,
        )
        return 1

    print(
        f"{args.target}: owned GHASH multiplication retained one fixed-loop "
        "backedge, whole-width arithmetic masks, and protected intermediates"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
