#!/usr/bin/env python3
"""Deterministic negative controls for the v4 release profile."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("dcrypt_release_profile", HERE / "verify.py")
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def rejected(mutator) -> None:
    policy = copy.deepcopy(module.load_policy())
    mutator(policy)
    try:
        module.verify_policy(policy)
    except module.InvalidProfile:
        return
    raise AssertionError("mutated release profile was accepted")


def main() -> int:
    module.verify_policy(module.load_policy())
    rejected(lambda p: p["claims"].__setitem__("known-critical-or-high-code-findings-allowed", True))
    rejected(lambda p: p["nonclaims"].__setitem__("physical-leakage-resistance", False))
    rejected(lambda p: p["disposition"].pop())
    rejected(lambda p: p["mandatory-tools"].pop())
    rejected(lambda p: p.__setitem__("target-version", "3.0.0"))
    print("v4 release profile self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
