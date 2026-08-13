# Constant-Time Implementation Policy

This document defines review requirements for code paths that handle secret
values. It does not assert that every current dcrypt implementation satisfies
them. Constant-time behavior depends on the full backend, compiler, target, and
microarchitecture; source inspection and statistical tests are evidence, not a
proof.

## Requirements

1. **Secret-Independent Execution Time:**
   - Operations in scope for a constant-time claim MUST have control flow and
     memory access independent of secret values.
   - Public lengths, nonces, protocol state, and error variants may affect
     execution unless a protocol explicitly treats them as secret.

2. **No Secret-Dependent Branches:**
   - Code MUST NOT contain conditional branches (if/else, switch, etc.) that depend on secret data.
   - Such operations MUST use a reviewed constant-time backend or reviewed
     branchless/conditional-selection primitives. Replacing one branch is not
     sufficient if point formulas or representations remain variable-time.

3. **No Secret-Dependent Memory Access:**
   - Memory access patterns MUST NOT depend on secret data.
   - Table lookups with secret-derived indices MUST be avoided or mitigated.

4. **Constant-Time Comparisons:**
   - Equality checks involving secret values MUST use dcrypt-owned, reviewed
     mask-based equality after public length validation has completed.
     Source-level masks are not sufficient by themselves; the claimed
     operation still requires compiler- and target-specific evidence.

5. **Error Handling:**
   - A result variant that depends on a secret MUST NOT be used as ordinary
     branching control flow. The historical `ConstantTimeResult` and
     `SecureErrorHandling` compatibility APIs were removed for v4 because their
     names provided no timing guarantee. Standard `Result` inspection and
     mapping also use ordinary, data-dependent control flow.
   - Error messages MUST NOT include details about secret values.

## Implementation Guidelines

1. **GF(2^8) Arithmetic:**
   - Use the provided branchless implementations for all Galois Field operations.

2. **Authentication Tag Verification:**
   - Use dcrypt's owned mask-based `ConstantTimeEq` for equal-length AEAD and
     MAC tag verification. Public length rejection remains a separate ordinary
     branch.

3. **S-Box Lookups:**
   - Prefer maintained hardware-accelerated or bitsliced implementations with a
     documented side-channel design. Prefetching alone is not an acceptable
     mitigation for secret-indexed lookups.

4. **Testing:**
   - Each claimed operation MUST identify its declared release toolchain and
     target scope and provide the applicable combination of source review,
     optimized-assembly inspection, and statistical timing regression.
   - Supported dynamic side-channel analysis MAY supplement that evidence; no
     single tool is a universal gate for every operation or target.
   - A secret-dependent branch, memory access, or reproducible statistical
     signal in the declared scope blocks the claim and release. Passing evidence
     does not prove constant-time execution on other compilers, targets, or
     microarchitectures.

## Verification

All changes to a path carrying a constant-time claim MUST receive dedicated
side-channel review before release. The release gate must bind the exact source,
compiler, target, assembly or dynamic evidence where applicable, and statistical
regression result declared for that operation. Missing or negative required
evidence blocks that scoped claim and release. These checks do not establish a
universal compiler, target, microarchitectural, or production constant-time
proof, and no documentation may present them as one.
