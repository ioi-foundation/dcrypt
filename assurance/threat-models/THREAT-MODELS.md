# dcrypt candidate threat models

> Status: candidate and independently unreviewed. This document records scope,
> residual risk, and required evidence. It is not a passing assurance verdict.

## Bound inventory

- Model set: `2026-08-11-candidate-1`
- Coverage policy: `conservative-all-atomic-rows-v1`
- Public API units: 18,891
- Exact atomic rows: 9,198
- Curated rows: 566
- Semantically unreviewed rows: 8,632
- Release-blocked rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Public binding set SHA-256: `e888664029152c3fd621028c2687d7ee5fba91b4e81a73a7d87399c2db7bd92d`

Every exact row in `coverage.json` names all eleven applicable threat models.
This deliberately conservative mapping remains in force while low-level rows await
semantic review. It does not clear or reduce any release blocker.

## Model summary

| ID | Status | Independent review | Residual rating | Valid through | Exact rows |
| --- | --- | --- | --- | --- | ---: |
| `TM-DEPENDENCY-ORACLE-COMMON-MODE` | candidate | required | critical | 2026-11-09 | 9,198 |
| `TM-DOS-RESOURCE-BOUNDS` | candidate | required | high | 2026-11-09 | 9,198 |
| `TM-EMBEDDED-PHYSICAL-ACCESS` | candidate | required | critical | 2026-11-09 | 9,198 |
| `TM-FAULT-INJECTION` | candidate | required | critical | 2026-11-09 | 9,198 |
| `TM-LOCAL-CORESIDENT-CACHE` | candidate | required | critical | 2026-11-09 | 9,198 |
| `TM-POWER-EM` | candidate | required | critical | 2026-11-09 | 9,198 |
| `TM-PROTOCOL-MISUSE` | candidate | required | critical | 2026-11-09 | 9,198 |
| `TM-REMOTE-MALICIOUS-INPUT` | candidate | required | critical | 2026-11-09 | 9,198 |
| `TM-RNG-FAILURE` | candidate | required | critical | 2026-11-09 | 9,198 |
| `TM-SECRET-LIFECYCLE` | candidate | required | critical | 2026-11-09 | 9,198 |
| `TM-SUPPLY-CHAIN-TOOLCHAIN` | candidate | required | critical | 2026-11-09 | 9,198 |

## TM-DEPENDENCY-ORACLE-COMMON-MODE: Dependency and interoperability-oracle common-mode failure

- Owner: dcrypt interoperability assurance
- Reviewer: dcrypt release assurance review (independent review pending)
- Review state: `required`
- Independent review evidence: none
- Review date: 2026-08-11
- Expiry: 2026-11-09
- Public scope: Every atomic row and every vector/oracle result used to support its correctness or interoperability classification.
- Exact atomic rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Exact mapping: `coverage.json#/models/TM-DEPENDENCY-ORACLE-COMMON-MODE`
- Affected algorithms: `coverage.json#/dimensions/algorithms/values`
- Affected operations: `coverage.json#/dimensions/operations/values`
- Affected profiles: `coverage.json#/dimensions/feature_profiles/values`
- Affected platforms: `coverage.json#/dimensions/platforms/values`

### Assets and security properties

- `correctness-oracles`: independence, provenance, semantic agreement
- `standards-and-vectors`: authenticity, correct interpretation

### Trust boundaries

- External libraries, reference implementations, generated vectors, standards text, and adapters are separate evidence producers.
- Shared source ancestry, arithmetic, tables, FFI backends, or generators can silently remove implementation independence.

### Attacker capabilities

- Exploit a shared defect or compromised upstream that appears consistently in dcrypt and its nominal oracle.
- Supply incomplete, transformed, stale, or incorrectly attributed vectors and provenance.

### Preconditions

- An assurance conclusion relies on agreement with a dependency, oracle, vector corpus, or common specification interpretation.

### Explicitly excluded capabilities

- A mathematically independent implementation with separately verified provenance and no shared lineage is outside the common-mode condition but still requires review.

### Assumptions

- Different package or language names do not establish independence; lineage must be documented and reviewed.
- Oracle execution is offline after a pinned provisioning step and cannot mutate production dependencies.

### Known limitations

- Current independent-oracle coverage is incomplete and lineage/provenance is uneven; the ACVP-format corpus has no verified upstream acquisition identity.
- A second independent BLS lineage and several standardized algorithm oracles remain Leg 4 work.

### Required evidence tiers

- external-audit
- independent-interoperability
- source-policy
- supply-chain-reproducibility

### Claim-invalidation conditions

- An accepted oracle has unknown/shared lineage, unpinned source, checksum drift, missing license/provenance, or requires network access during final verification.
- Dcrypt and its oracle agree only because they share the implementation, arithmetic backend, tables, generator, or malformed vector interpretation.

### Mitigations

- `isolated-verification-workspace` — **implemented-unverified**; evidence: `implementation-boundary`, `bls-interoperability`, `xchacha-interoperability`. Oracle dependencies are isolated, but existing records are informational and not complete lineage evidence.
- `oracle-provenance-dossiers` — **planned**; evidence: none. Leg 4 must bind source, version, checksum, license, acquisition, and lineage.
- `multi-lineage-review` — **planned**; evidence: none. Critical standardized rows require genuinely independent implementations and human lineage review.

### Residual risk

- Likelihood: `high`
- Impact: `critical`
- Rating: `critical`
- Disposition: `mitigate`
- Rationale: Common-mode implementation or vector defects can produce convincing but false agreement across the current test stack.
- Acceptance authority: dcrypt security assurance plus independent oracle-lineage reviewer

## TM-DOS-RESOURCE-BOUNDS: Denial of service through lengths, allocations, streams, decoding, and rejection loops

- Owner: dcrypt availability assurance
- Reviewer: dcrypt release assurance review (independent review pending)
- Review state: `required`
- Independent review evidence: none
- Review date: 2026-08-11
- Expiry: 2026-11-09
- Public scope: All atomic rows, including low-level parsing/data surfaces and operations with caller-controlled lengths, iterations, streams, or rejection work.
- Exact atomic rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Exact mapping: `coverage.json#/models/TM-DOS-RESOURCE-BOUNDS`
- Affected algorithms: `coverage.json#/dimensions/algorithms/values`
- Affected operations: `coverage.json#/dimensions/operations/values`
- Affected profiles: `coverage.json#/dimensions/feature_profiles/values`
- Affected platforms: `coverage.json#/dimensions/platforms/values`

### Assets and security properties

- `service-resources`: availability, bounded CPU, bounded memory, bounded stack
- `parser-and-stream-state`: progress, bounded buffering, fail-closed termination

### Trust boundaries

- Attacker-controlled lengths, iteration counts, encoded points, signatures, ciphertexts, streams, and malformed objects drive allocation and computation.
- Caller-provided readers/writers and no_std allocators may have different blocking and resource behavior.

### Attacker capabilities

- Submit pathological lengths, encodings, rejection patterns, iteration counts, partial streams, decompression points, and repeated expensive invalid operations.
- Hold connections or repeatedly invoke public endpoints to amplify bounded per-call cost.

### Preconditions

- An application exposes parsing, verification, derivation, streaming, or migration work to untrusted or weakly rate-limited inputs.

### Explicitly excluded capabilities

- Network-layer rate limiting, quotas, scheduling, admission control, and global memory limits are application responsibilities unless explicitly bound.

### Assumptions

- Public API limits are validated before allocation or expensive secret work where the format permits it.
- Product operators provision quotas and timeouts for legitimate worst-case cryptographic cost.

### Known limitations

- There is no machine-readable cross-surface resource budget or adversarial allocation/timeout campaign.
- Rejection loops, password-work factors, arbitrary streams, and point decoding have uneven worst-case evidence.

### Required evidence tiers

- external-audit
- persistent-fuzz
- platform-runtime
- resource-bound-analysis

### Claim-invalidation conditions

- Attacker-controlled input causes unbounded allocation, nontermination, panic, stack exhaustion, integer overflow, or cost beyond a declared limit.
- A release lacks explicit time, memory, length, and iteration limits for a remotely reachable parser or loop.

### Mitigations

- `bounded-stream-regressions` — **implemented-unverified**; evidence: `fuzz-symmetric`, `fuzz-hybrid`. Streaming and decoder regression/fuzz smoke exists but is not sustained resource-bound evidence.
- `resource-budget-registry` — **planned**; evidence: none. Every parser, stream, migration path, and rejection loop needs declared limits.
- `adversarial-resource-campaign` — **planned**; evidence: none. Persistent fuzz and dedicated OOM/timeout tests must exercise worst-case inputs.

### Residual risk

- Likelihood: `high`
- Impact: `high`
- Rating: `high`
- Disposition: `mitigate`
- Rationale: Historical streaming allocations approached 4 GiB, and the current repository lacks complete cross-surface worst-case resource evidence.
- Acceptance authority: dcrypt security release authority plus service operator

## TM-EMBEDDED-PHYSICAL-ACCESS: Embedded deployment and physical-access adversaries

- Owner: dcrypt embedded assurance
- Reviewer: dcrypt release assurance review (independent review pending)
- Review state: `required`
- Independent review evidence: none
- Review date: 2026-08-11
- Expiry: 2026-11-09
- Public scope: All atomic rows and declared Thumb/no_std profiles, conservatively including code that may be linked into embedded products.
- Exact atomic rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Exact mapping: `coverage.json#/models/TM-EMBEDDED-PHYSICAL-ACCESS`
- Affected algorithms: `coverage.json#/dimensions/algorithms/values`
- Affected operations: `coverage.json#/dimensions/operations/values`
- Affected profiles: `coverage.json#/dimensions/feature_profiles/values`
- Affected platforms: `coverage.json#/dimensions/platforms/values`

### Assets and security properties

- `embedded-secret-material`: confidentiality, integrity, availability
- `firmware-and-boot-state`: code integrity, rollback resistance

### Trust boundaries

- Dcrypt code and caller-owned RNG state execute on devices an adversary may possess or instrument.
- Memory, debug interfaces, storage, firmware update, and board-level signals are outside dcrypt's direct control.

### Attacker capabilities

- Possess a device, repeat operations, inspect externally exposed buses or debug facilities, and collect physical side-channel observations.
- Reset, brown out, or manipulate the surrounding execution environment within the device threat profile.

### Preconditions

- A product deploys dcrypt on supported allocator-backed no_std/Thumb or comparable embedded hardware.

### Explicitly excluded capabilities

- No claim is made against invasive semiconductor modification or arbitrary privileged firmware compromise without a product-specific model.

### Assumptions

- The integrator defines secure boot, debug-lock, storage, memory-protection, entropy, and key-erasure controls outside dcrypt.
- Cross-compilation alone is not runtime or physical assurance.

### Known limitations

- The repository has Thumb compilation/assembly checks but no native embedded runtime, board, secure-boot, debug-interface, or physical-lab evidence.
- Safe-Rust zeroization cannot guarantee removal of historical register, stack, allocator, swap, or crash-dump copies.

### Required evidence tiers

- external-audit
- physical-validation
- platform-runtime
- source-policy

### Claim-invalidation conditions

- A documented embedded deployment claim lacks product-specific memory, entropy, debug, update, and physical-access assumptions.
- A reproducible physical observation or device-state manipulation leaks a key or bypasses authentication.

### Mitigations

- `thumb-boundary-build` — **implemented-unverified**; evidence: `implementation-boundary`. Declared Thumb profile compilation is implementation-boundary evidence only.
- `embedded-profile-validation` — **planned**; evidence: none. Representative native-device execution and integrator threat profiles remain required.
- `physical-lab-assessment` — **planned**; evidence: none. Power/EM and fault work is required where the product profile justifies it.

### Residual risk

- Likelihood: `high`
- Impact: `critical`
- Rating: `critical`
- Disposition: `mitigate`
- Rationale: No repository-only test establishes resistance on a physically accessible embedded product, and crucial controls belong to the integrator.
- Acceptance authority: product security authority plus dcrypt security release authority

## TM-FAULT-INJECTION: Fault injection against authentication and secret operations

- Owner: dcrypt fault-analysis assurance
- Reviewer: dcrypt release assurance review (independent review pending)
- Review state: `required`
- Independent review evidence: none
- Review date: 2026-08-11
- Expiry: 2026-11-09
- Public scope: All atomic rows are included until operation-level fault relevance is independently classified.
- Exact atomic rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Exact mapping: `coverage.json#/models/TM-FAULT-INJECTION`
- Affected algorithms: `coverage.json#/dimensions/algorithms/values`
- Affected operations: `coverage.json#/dimensions/operations/values`
- Affected profiles: `coverage.json#/dimensions/feature_profiles/values`
- Affected platforms: `coverage.json#/dimensions/platforms/values`

### Assets and security properties

- `authentication-decisions`: fail-closed verification, integrity
- `secret-computation-state`: confidentiality, correctness

### Trust boundaries

- Hardware execution, memory, clock, voltage, reset, and instruction delivery can deviate from the fault-free Rust abstract machine.
- Caller retry and error-handling behavior can amplify or expose a faulted result.

### Attacker capabilities

- Induce transient data, instruction-skip, clock, voltage, reset, or memory faults and observe whether an operation succeeds, fails, or leaks correlated output.

### Preconditions

- The deployment threat model permits physical or privileged fault induction and repeated observations.

### Explicitly excluded capabilities

- Ordinary malformed input without induced execution faults is covered by the remote-input model.

### Assumptions

- Fault resistance is not inherited from memory safety, constant-time structure, or correct fault-free test vectors.
- Product-specific redundancy, sensors, reset policy, and key invalidation are external unless explicitly bound.

### Known limitations

- No instruction-skip, data-fault, voltage/clock, or fault-simulation campaign currently exists.
- Implicit rejection and authentication checks have not been assessed for faulted control flow.

### Required evidence tiers

- external-audit
- fault-analysis
- physical-validation
- platform-runtime

### Claim-invalidation conditions

- A reproducible fault causes acceptance of invalid data, predictable/recovered secret material, unauthenticated plaintext, or bypass of a required failure path.
- A product claims fault resistance without exact fault model, device/build identity, campaign parameters, and independent review.

### Mitigations

- `fault-path-analysis` — **planned**; evidence: none. Audit authentication, implicit rejection, key validation, and error paths for plausible fault outcomes.
- `fault-campaign` — **planned**; evidence: none. Run simulation or physical campaigns where product threat profiles justify them.

### Residual risk

- Likelihood: `high`
- Impact: `critical`
- Rating: `critical`
- Disposition: `mitigate`
- Rationale: Fault behavior is presently untested and may invalidate authentication or secret-handling assumptions even when fault-free behavior is correct.
- Acceptance authority: product security authority plus dcrypt security release authority

## TM-LOCAL-CORESIDENT-CACHE: Local and co-resident timing, cache, branch, and memory-address observation

- Owner: dcrypt side-channel assurance
- Reviewer: dcrypt release assurance review (independent review pending)
- Review state: `required`
- Independent review evidence: none
- Review date: 2026-08-11
- Expiry: 2026-11-09
- Public scope: All atomic rows are conservatively included until every low-level secret/public data flow is classified.
- Exact atomic rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Exact mapping: `coverage.json#/models/TM-LOCAL-CORESIDENT-CACHE`
- Affected algorithms: `coverage.json#/dimensions/algorithms/values`
- Affected operations: `coverage.json#/dimensions/operations/values`
- Affected profiles: `coverage.json#/dimensions/feature_profiles/values`
- Affected platforms: `coverage.json#/dimensions/platforms/values`

### Assets and security properties

- `secret-dependent-execution`: secret-independent control flow, secret-independent memory access
- `long-term-and-ephemeral-secrets`: confidentiality

### Trust boundaries

- Secret-bearing code executes on a CPU shared with operating-system, process, VM, container, or co-resident adversaries.
- Compiler, target, microcode, caches, predictors, and memory hierarchy mediate source behavior.

### Attacker capabilities

- Collect repeated high-resolution timings and branch/cache/memory-address observations under attacker-selected public inputs.
- Co-schedule code or otherwise create a local observation channel without arbitrary process-memory access.

### Preconditions

- The deployment threat profile includes local or co-resident adversaries and repeated operations under related or identical secret material.

### Explicitly excluded capabilities

- Direct physical power/EM probing, invasive fault injection, and privileged arbitrary memory read are modeled separately.

### Assumptions

- A constant-time claim is limited to exact source, compiler, flags, target, binary, microarchitecture, and measured environment.
- Public lengths and protocol state may vary unless a protocol explicitly treats them as secret.

### Known limitations

- The in-repository statistical suite is not dudect or ctgrind and does not provide dedicated cache evidence.
- Only selected BLS and GHASH emissions have dedicated assembly guards; transitive optimized secret paths remain incomplete.

### Required evidence tiers

- dedicated-side-channel
- external-audit
- platform-runtime
- source-policy

### Claim-invalidation conditions

- Any reproducible secret-dependent branch, memory address, cache signal, or statistically meaningful timing signal in the claimed scope.
- Any compiler or target change not covered by current source/binary/disassembly-bound evidence.

### Mitigations

- `constant-time-policy` — **implemented-unverified**; evidence: `constant-time-smoke`, `implementation-boundary`. Current policy, statistical smoke, and selected assembly gates are regression layers only.
- `dedicated-dudect-and-taint` — **planned**; evidence: none. Leg 6 must add dedicated-host fixed-vs-random and secret-taint branch/address analysis.
- `transitive-assembly-review` — **planned**; evidence: none. Every claimed secret path requires compiler/target-bound assembly review.

### Residual risk

- Likelihood: `high`
- Impact: `critical`
- Rating: `critical`
- Disposition: `mitigate`
- Rationale: Historical GHASH compiler behavior demonstrates that source masks and smoke timing alone cannot support a broad constant-time claim.
- Acceptance authority: dcrypt security release authority; reproducible secret-dependent execution blocks release

## TM-POWER-EM: Power and electromagnetic side-channel observation

- Owner: dcrypt physical side-channel assurance
- Reviewer: dcrypt release assurance review (independent review pending)
- Review state: `required`
- Independent review evidence: none
- Review date: 2026-08-11
- Expiry: 2026-11-09
- Public scope: All atomic rows are conservatively included; product-specific scope must later identify secret-bearing operations and physical profiles.
- Exact atomic rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Exact mapping: `coverage.json#/models/TM-POWER-EM`
- Affected algorithms: `coverage.json#/dimensions/algorithms/values`
- Affected operations: `coverage.json#/dimensions/operations/values`
- Affected profiles: `coverage.json#/dimensions/feature_profiles/values`
- Affected platforms: `coverage.json#/dimensions/platforms/values`

### Assets and security properties

- `physical-leakage-profile`: secret confidentiality, trace non-distinguishability

### Trust boundaries

- Instruction/data activity becomes device-level power and electromagnetic emissions outside the language abstraction.
- Measurement fixtures, probes, acquisition equipment, and analysis code form an external evidence boundary.

### Attacker capabilities

- Collect aligned or unaligned power/EM traces across chosen or fixed inputs and repeat operations under a target secret.

### Preconditions

- The deployment permits sufficiently close physical access and repeated measurement, or the product makes a physical side-channel claim.

### Explicitly excluded capabilities

- Fault injection and arbitrary firmware compromise are covered by separate models.

### Assumptions

- Trace collection hardware, firmware build, trigger path, analysis version, and environmental controls are recorded and independently replayable.

### Known limitations

- No TVLA, power, or EM trace corpus currently exists in the repository.
- Portable source structure and timing tests do not establish physical leakage resistance.

### Required evidence tiers

- dedicated-side-channel
- external-audit
- physical-validation
- platform-runtime

### Claim-invalidation conditions

- A reproducible leakage assessment produces a statistically meaningful secret-correlated signal in a claimed profile.
- Required raw traces, build identity, device identity, harness parameters, or analysis provenance are missing.

### Mitigations

- `physical-evidence-policy` — **planned**; evidence: none. Leg 6 must define evidence capture and disposition for relevant physical profiles.
- `representative-tvla-campaign` — **planned**; evidence: none. Run TVLA-class and deeper assessment only for justified embedded/physical profiles.

### Residual risk

- Likelihood: `high`
- Impact: `critical`
- Rating: `critical`
- Disposition: `mitigate`
- Rationale: There is currently no physical trace evidence, so dcrypt cannot make a power/EM resistance claim.
- Acceptance authority: product security authority plus dcrypt side-channel authority

## TM-PROTOCOL-MISUSE: Protocol misuse, nonce reuse, downgrade, replay, and domain separation

- Owner: dcrypt security assurance
- Reviewer: dcrypt release assurance review (independent review pending)
- Review state: `required`
- Independent review evidence: none
- Review date: 2026-08-11
- Expiry: 2026-11-09
- Public scope: Every public operation and low-level composition surface that can participate in a protocol; exact rows are recorded in coverage.json.
- Exact atomic rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Exact mapping: `coverage.json#/models/TM-PROTOCOL-MISUSE`
- Affected algorithms: `coverage.json#/dimensions/algorithms/values`
- Affected operations: `coverage.json#/dimensions/operations/values`
- Affected profiles: `coverage.json#/dimensions/feature_profiles/values`
- Affected platforms: `coverage.json#/dimensions/platforms/values`

### Assets and security properties

- `protocol-transcripts`: domain separation, context binding, downgrade resistance
- `nonces-and-one-time-keys`: uniqueness, single use
- `serialized-objects`: version integrity, canonical interpretation

### Trust boundaries

- Applications choose algorithms, features, keys, nonces, AAD, contexts, DSTs, prehash modes, and framing around dcrypt operations.
- Custom ECIES, hybrid, and streaming transcripts cross between dcrypt and application protocol state.

### Attacker capabilities

- Influence protocol negotiation, replay complete or partial objects, substitute contexts/DSTs/AAD, and induce nonce or key reuse through application workflows.
- Exploit ambiguity between standard, legacy, transitional, custom, and versioned formats.

### Preconditions

- A caller composes dcrypt operations into a stateful or multi-party protocol.
- At least one required uniqueness, ordering, version, context, or domain-separation property is enforced partly outside dcrypt.

### Explicitly excluded capabilities

- Cryptanalysis that breaks a correctly instantiated primitive without protocol misuse is outside this model and remains external-audit scope.

### Assumptions

- Applications authenticate algorithm negotiation and provide replay state where whole-object replay is a threat.
- Callers never reinterpret legacy dcrypt encodings as standardized objects and preserve explicit provenance during migration.

### Known limitations

- Whole-stream replay prevention remains application-owned, and custom ECIES/hybrid transcript specifications have not yet received clean-room interoperability review.
- Low-level generic exports permit compositions whose complete protocol semantics are not captured by the current ledger.

### Required evidence tiers

- deterministic-regression
- external-audit
- independent-interoperability
- persistent-fuzz

### Claim-invalidation conditions

- Any nonce, context, prehash, DST, AAD, version, recipient-key, or transcript component is omitted, ignored, ambiguously encoded, or accepted under the wrong profile.
- Any replay, reorder, truncation, downgrade, duplicate-message, or rogue-key case succeeds contrary to the declared protocol contract.

### Mitigations

- `versioned-framing-and-transcripts` — **implemented-unverified**; evidence: `fuzz-hybrid`, `fuzz-symmetric`. Existing framing and decoder regressions are bounded source evidence, not protocol assurance.
- `clean-room-protocol-references` — **planned**; evidence: none. Leg 4 must freeze wire specifications and build independent references.
- `protocol-audit` — **planned**; evidence: none. The external audit must review misuse resistance and domain separation end to end.

### Residual risk

- Likelihood: `high`
- Impact: `critical`
- Rating: `critical`
- Disposition: `mitigate`
- Rationale: Historical nonce, framing, standards-label, and domain-separation defects demonstrate that composition errors can defeat otherwise sound primitives.
- Acceptance authority: dcrypt security release authority; unresolved nonce or domain-separation risk is not releasable

## TM-REMOTE-MALICIOUS-INPUT: Remote malicious inputs and network-controlled cryptographic objects

- Owner: dcrypt security assurance
- Reviewer: dcrypt release assurance review (independent review pending)
- Review state: `required`
- Independent review evidence: none
- Review date: 2026-08-11
- Expiry: 2026-11-09
- Public scope: All operation-bearing public bindings and parameter/data surfaces; exact bindings are recorded per row in coverage.json.
- Exact atomic rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Exact mapping: `coverage.json#/models/TM-REMOTE-MALICIOUS-INPUT`
- Affected algorithms: `coverage.json#/dimensions/algorithms/values`
- Affected operations: `coverage.json#/dimensions/operations/values`
- Affected profiles: `coverage.json#/dimensions/feature_profiles/values`
- Affected platforms: `coverage.json#/dimensions/platforms/values`

### Assets and security properties

- `cryptographic-authenticity`: authenticity, integrity
- `secret-keys-and-shared-secrets`: confidentiality, unpredictability
- `parser-and-protocol-state`: availability, fail-closed validation

### Trust boundaries

- Public key, signature, ciphertext, tag, nonce, AAD, context, DST, framing, and serialized-key inputs cross from an untrusted caller into dcrypt.
- Returned success, error, plaintext, shared secret, or verification verdict crosses back to the caller.

### Attacker capabilities

- Choose, truncate, extend, mutate, replay, reorder, or make noncanonical every externally accepted byte string.
- Repeat calls and observe public results, errors, output lengths, process termination, and coarse remote timing.

### Preconditions

- An application exposes at least one dcrypt operation to data influenced by an untrusted remote party.
- The attacker can distinguish success, failure, output, connection behavior, or service availability.

### Explicitly excluded capabilities

- Direct process-memory read/write, privileged host control, physical probing, and precise co-resident cache observation are covered by separate models.

### Assumptions

- Callers preserve the documented type, key, nonce, context, and protocol preconditions that are outside the library's validation boundary.
- The implementation and dependency bytes are those bound by the assurance ledger; supply-chain substitution is covered separately.

### Known limitations

- The 8,632 semantically unreviewed low-level rows require conservative inclusion, so this model is intentionally broader than a final operation-specific remote surface.
- Persistent semantic fuzzing, complete independent interoperability, and an independent external cryptographic audit are not complete.

### Required evidence tiers

- deterministic-regression
- external-audit
- independent-interoperability
- persistent-fuzz
- resource-bound-analysis

### Claim-invalidation conditions

- Any malformed or noncanonical input accepted contrary to the applicable standard or wire contract.
- Any forgery, authentication bypass, key recovery, predictable shared secret, panic, memory exhaustion, unbounded loop, or fail-open verdict reachable from attacker-controlled input.

### Mitigations

- `strict-parser-regressions` — **implemented-unverified**; evidence: `acvp-harness-integrity`, `public-api-inventory-integrity`. Existing strict parser and ACVP regression layers are source evidence only.
- `persistent-semantic-fuzzing` — **planned**; evidence: none. Leg 5 persistent semantic and differential campaigns remain required.
- `external-cryptographic-audit` — **planned**; evidence: none. Independent review of all remote input and failure paths remains required.

### Residual risk

- Likelihood: `high`
- Impact: `critical`
- Rating: `critical`
- Disposition: `mitigate`
- Rationale: Broad public parsing and cryptographic verification surfaces remain unaudited and incompletely fuzzed; a correctness defect can enable authentication bypass, key compromise, or denial of service.
- Acceptance authority: dcrypt security release authority; Critical residual risk is not releasable

## TM-RNG-FAILURE: Caller-owned RNG failure, entropy degradation, and randomness misuse

- Owner: dcrypt randomness assurance
- Reviewer: dcrypt release assurance review (independent review pending)
- Review state: `required`
- Independent review evidence: none
- Review date: 2026-08-11
- Expiry: 2026-11-09
- Public scope: Every atomic row is conservatively included until all randomness-consuming and randomness-dependent low-level operations are classified.
- Exact atomic rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Exact mapping: `coverage.json#/models/TM-RNG-FAILURE`
- Affected algorithms: `coverage.json#/dimensions/algorithms/values`
- Affected operations: `coverage.json#/dimensions/operations/values`
- Affected profiles: `coverage.json#/dimensions/feature_profiles/values`
- Affected platforms: `coverage.json#/dimensions/platforms/values`

### Assets and security properties

- `generated-secrets-and-nonces`: unpredictability, uniqueness, uniformity
- `failure-path-state`: fail-closed behavior, clearing on partial write

### Trust boundaries

- Caller-owned `CryptoRng + RngCore` implementations supply all cryptographic randomness across the public API.
- Partial writes, errors, deterministic test RNGs, entropy sources, seeding, reseeding, and process-fork behavior are outside dcrypt's implementation boundary.

### Attacker capabilities

- Influence entropy availability or quality, trigger partial-write/error paths, force state reuse/forking, or cause deterministic/repeated outputs through caller integration.

### Preconditions

- An operation generates a key, scalar, nonce, salt, seed, encapsulation randomness, or hedged-signing randomness from caller state.

### Explicitly excluded capabilities

- A correct and uncompromised caller RNG with sufficient entropy is assumed unpredictable; its internal design is not audited as dcrypt code.

### Assumptions

- Applications select, seed, protect, reseed, and monitor a suitable cryptographic RNG for their platform and threat model.
- Dcrypt propagates RNG errors and clears partially initialized secret destinations before returning.

### Known limitations

- The type contract cannot prove entropy quality, fork safety, hardware RNG health, or application key/nonce uniqueness.
- Randomness failure and fault combinations have not received an independent cross-surface audit.

### Required evidence tiers

- deterministic-regression
- external-audit
- fault-analysis
- platform-runtime

### Claim-invalidation conditions

- An RNG failure is ignored, transformed into success, leaks a partially initialized secret, or permits repeated/predictable cryptographic output.
- Documentation or API behavior implies that the `CryptoRng` trait alone proves entropy quality or nonce uniqueness.

### Mitigations

- `caller-owned-rng-contract` — **implemented-unverified**; evidence: `implementation-boundary`. Published code excludes OS entropy and exposes caller-owned RNG/error paths; this is source-policy evidence only.
- `rng-failure-audit` — **planned**; evidence: none. The external audit must trace every random destination, partial write, clear, and returned error.
- `platform-rng-integration-guidance` — **planned**; evidence: none. Platform-specific integration fixtures and limitations remain required.

### Residual risk

- Likelihood: `high`
- Impact: `critical`
- Rating: `critical`
- Disposition: `mitigate`
- Rationale: All key-generation security ultimately depends on caller RNG quality and exact failure propagation, neither of which is established by the current boundary gate alone.
- Acceptance authority: application security authority plus dcrypt security release authority

## TM-SECRET-LIFECYCLE: Secret ownership, copying, logging, persistence, and zeroization limitations

- Owner: dcrypt secret-lifecycle assurance
- Reviewer: dcrypt release assurance review (independent review pending)
- Review state: `required`
- Independent review evidence: none
- Review date: 2026-08-11
- Expiry: 2026-11-09
- Public scope: Every atomic row is included because unreviewed low-level declarations may create, copy, format, serialize, retain, or destroy secret-derived state.
- Exact atomic rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Exact mapping: `coverage.json#/models/TM-SECRET-LIFECYCLE`
- Affected algorithms: `coverage.json#/dimensions/algorithms/values`
- Affected operations: `coverage.json#/dimensions/operations/values`
- Affected profiles: `coverage.json#/dimensions/feature_profiles/values`
- Affected platforms: `coverage.json#/dimensions/platforms/values`

### Assets and security properties

- `owned-secret-bytes`: confidentiality, bounded lifetime, redacted diagnostics
- `secret-derived-intermediates`: best-effort clearing, copy minimization

### Trust boundaries

- Secrets cross public construction, serialization, result/error, allocator, stack/register, compiler, logging, crash-dump, swap, and caller ownership boundaries.
- Safe-Rust zeroization requests cross into compiler optimization and platform memory behavior that dcrypt cannot universally control.

### Attacker capabilities

- Read process memory, crash dumps, swap, allocator reuse, logs, diagnostics, or stale copies after an operation, subject to deployment privileges.
- Induce errors, clones, replacement, resizing, serialization, or panics that extend or expose secret lifetime.

### Preconditions

- A dcrypt operation or caller holds secret key material, password data, shared secrets, derived keys, nonces, or secret-dependent intermediates.

### Explicitly excluded capabilities

- Guaranteed physical erasure of every historical register, stack, allocator, device, or externally copied value is explicitly outside the portable library claim.

### Assumptions

- Callers control serialized secret destinations, logging, crash dumps, swap, process isolation, backups, and downstream copies.
- Best-effort clearing reduces exposure but is not a proof of physical erasure.

### Known limitations

- Historical copies can survive compiler transformations, moves, stack/register allocation, allocator behavior, panic paths, and caller serialization.
- The complete transitive secret-data inventory and compiler-emission review remain unfinished.

### Required evidence tiers

- dedicated-side-channel
- external-audit
- platform-runtime
- source-policy

### Claim-invalidation conditions

- A public debug/error path reveals secret bytes, an owned secret retains avoidable stale capacity, or a documented clearing path does not execute on an ordinary replacement/drop/error path.
- Documentation promises physical erasure or universal zeroization beyond the exact tested implementation scope.

### Mitigations

- `exact-size-secret-owners` — **implemented-unverified**; evidence: `implementation-boundary`. Exact-size secret types and source scans exist but are not an independent lifecycle audit.
- `transitive-secret-inventory` — **planned**; evidence: none. Leg 6 and the external audit must trace all secret-derived state and compiler emissions.
- `platform-lifecycle-validation` — **planned**; evidence: none. Representative platform runtime evidence must record unavoidable limitations.

### Residual risk

- Likelihood: `high`
- Impact: `critical`
- Rating: `critical`
- Disposition: `mitigate`
- Rationale: Portable Rust can reduce unnecessary retention but cannot guarantee physical erasure, and the transitive secret lifecycle has not been independently audited.
- Acceptance authority: dcrypt security release authority with deployment-specific risk owner

## TM-SUPPLY-CHAIN-TOOLCHAIN: Source, dependency, toolchain, action, runner, and artifact compromise

- Owner: dcrypt supply-chain assurance
- Reviewer: dcrypt release assurance review (independent review pending)
- Review state: `required`
- Independent review evidence: none
- Review date: 2026-08-11
- Expiry: 2026-11-09
- Public scope: Every atomic row, published crate, excluded workspace, workflow, build input, and generated evidence path.
- Exact atomic rows: 9,198
- Atomic row ID set SHA-256: `ec0a192f6067448d9c610d38719ee47dc95d3ffdeb385708291cb7989f46e0ff`
- Exact mapping: `coverage.json#/models/TM-SUPPLY-CHAIN-TOOLCHAIN`
- Affected algorithms: `coverage.json#/dimensions/algorithms/values`
- Affected operations: `coverage.json#/dimensions/operations/values`
- Affected profiles: `coverage.json#/dimensions/feature_profiles/values`
- Affected platforms: `coverage.json#/dimensions/platforms/values`

### Assets and security properties

- `source-and-release-artifacts`: integrity, provenance, reproducibility
- `dependency-and-toolchain-closures`: integrity, availability, policy compliance
- `assurance-evidence`: authenticity, freshness, independent replayability

### Trust boundaries

- Git objects, crates.io archives, dependency registries, Rust toolchains, linkers, containers, GitHub Actions, runners, caches, and generated evidence cross administrative boundaries.
- Local build products and downloaded artifacts may be attacker-controlled until independently verified.

### Attacker capabilities

- Substitute source, dependency, action, compiler, linker, container, registry archive, cache entry, or generated evidence.
- Compromise a maintainer credential or build runner without necessarily changing reviewed source.

### Preconditions

- A release or assurance conclusion consumes an external or generated input without an independently verified immutable binding.

### Explicitly excluded capabilities

- Cryptographic compromise of SHA-256 or Git object hashing is outside the current model and would require an immediate model revision.

### Assumptions

- Immutable identifiers are verified from at least one independently controlled source and clean-room replay is separated from evidence generation.
- Secrets and credentials are not written into manifests, logs, or command lines.

### Known limitations

- SBOMs, signed attestations, container digests, independent clean-room rebuilds, and complete published-archive replay are not yet bound by the ledger.
- The current dependency exception lacks machine-enforced ownership and expiry; Leg 8 remains required.

### Required evidence tiers

- external-audit
- platform-runtime
- source-policy
- supply-chain-reproducibility

### Claim-invalidation conditions

- Any bound source, lockfile, toolchain, action, container, archive, artifact, or evidence digest differs or cannot be independently obtained and replayed.
- A generated result is treated as trusted without independent replay or an unclassified dependency/workspace enters scope.

### Mitigations

- `implementation-boundary` — **implemented-unverified**; evidence: `implementation-boundary`, `assurance-ledger-control`. Exact package/dependency/source controls exist but remain informational evidence.
- `reproducible-audit-freeze` — **planned**; evidence: none. Leg 3 must bind all audit inputs and clearly record missing artifacts.
- `signed-clean-room-attestations` — **planned**; evidence: none. Leg 8 must add SBOM, signing, and independent offline rebuild evidence.

### Residual risk

- Likelihood: `high`
- Impact: `critical`
- Rating: `critical`
- Disposition: `mitigate`
- Rationale: Current source and closure controls are strong but do not yet establish independent artifact reproducibility or protect every build-service trust boundary.
- Acceptance authority: dcrypt release and supply-chain security authorities
