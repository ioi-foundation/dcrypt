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
   - Equality checks involving secret values SHOULD use reviewed constant-time
     primitives such as `subtle`; public length validation remains separate.

5. **Error Handling:**
   - A result variant that depends on a secret MUST NOT be used as ordinary
     branching control flow. The deprecated `ConstantTimeResult` and
     `SecureErrorHandling` compatibility names provide no timing guarantee.
   - Error messages MUST NOT include details about secret values.

## Implementation Guidelines

1. **GF(2^8) Arithmetic:**
   - Use the provided branchless implementations for all Galois Field operations.

2. **Authentication Tag Verification:**
   - Always use `subtle::ConstantTimeEq` for AEAD and MAC tag verification.

3. **S-Box Lookups:**
   - Prefer maintained hardware-accelerated or bitsliced implementations with a
     documented side-channel design. Prefetching alone is not an acceptable
     mitigation for secret-indexed lookups.

4. **Testing:**
   - Claimed operations SHOULD have dudect-style or equivalent statistical
     tests on each relevant target, supplemented by ctgrind or other dynamic
     analysis where available.
   - Negative results block release. Positive statistical results do not prove
     constant-time execution.

## Verification

All changes to a path carrying a constant-time claim MUST receive dedicated
side-channel review before release. The repository's current statistical timing
harness is a regression tool; dudect/ctgrind coverage is a release blocker until
it is actually configured and passing in CI. No documentation may turn this
policy into a blanket production or constant-time claim.
