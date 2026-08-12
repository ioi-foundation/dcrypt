# Request for Proposal and Statement of Work: dcrypt external cryptographic audit

- Status: **candidate / uncommissioned — do not issue**
- Candidate freeze ID: `dcrypt-v3.0.0-audit-candidate-003`
- Candidate freeze content identity: `resolved-by-post-subject-evidence-envelope`
- Directly supersedes freeze ID: `dcrypt-v3.0.0-audit-candidate-002`
- Ordered supersession history: `dcrypt-v3.0.0-audit-candidate-001`, then `dcrypt-v3.0.0-audit-candidate-002`
- Candidate-001 superseded state: `invalidated-after-partial-independent-replay-before-acceptance`
- Candidate-002 superseded state: `invalidated-after-first-party-diagnostic-before-valid-wrapper-compliant-generation`
- Machine policy SHA-256: `eda28392c5e52b6242a7b796562afeb5c4af342ae17a31f1115b83e3463b4a99`
- Machine scope SHA-256: `066f83e994f0a3fa15b6c8180048290b65d68a856f3cd8cfac476db0efef2a58`

This document is a vendor-ready template, not evidence that an audit has been
commissioned, scheduled, started, or completed. No vendor contact is authorized
by this file. Candidate-003 directly supersedes candidate-002; the ordered,
immutable supersession history is candidate-001 followed by candidate-002.

Candidate-002 supersedes candidate-001 because a documented PTY wrapper mismatch
invalidated candidate-001 after partial independent replay observations but
before completion and acceptance under the full required replay contract. The
reviewer observed a non-PTY self-test, materialization, 13-file regeneration,
and structural/release replay for candidate-001. Those partial observations are
not a completed required independent replay, acceptance, completed external
review, external audit, or accepted audit or assurance evidence for
candidate-001; it must not be reused, promoted, or issued.

Candidate-002 bound subject commit
`852c771c7d764752e23322ab412b419925fb5a5f`, subject tree
`ae5779e73b64b60cc4ce198468ef9fd781cda2df`, and parent/SOW commit
`8e3b8d7ee3ea9ec7d1901dadf9c85f3aa0706c02`. It was invalidated after
first-party diagnostic temporary materialization and diagnostic bundle creation,
but before valid wrapper-compliant materialization, valid candidate generation,
an evidence commit, complete independent replay, or acceptance. The triggering
invalidation defect was `provision/generation README fences could return 0 after
failed gate due trailing assignment`. The exact ordered, exhaustive set of all
four known candidate-002 invalidation defects is:

1. Triggering defect: `provision/generation README fences could return 0 after failed gate due trailing assignment`.
2. `clone fence could continue to checkout preexisting repo after failed clone`.
3. `candidate import fence could mask mkdir/middle install failures and omitted prose-required unexpected-source-entry rejection`.
4. `provisioning transfer fence could mask intermediate failures`.

The independent review covered source, self-test, and fence diagnostics only,
not candidate-002 bundle evidence. Its diagnostic hashes are typed first-party
diagnostic non-evidence only:

- provisioning manifest: `f48385357526d1bdb141dbb624ae355c094b3c292f4b4d191a06095f29067e69`;
- provisioning sums: `e6adb59c5ec6e687c6652dd7938b5213ac310418a85cf8384b1e348f1633f1a6`;
- freeze: `ed7e7a26c9ee645350d53245a71468e82b9a77310367a71b737d8691fa418335`; and
- `SHA256SUMS`: `8c8d4948cf3d6356028bf4dffaead4f256bb2e755a5882e4c07bb88e67335b43`.

For candidate-002, diagnostic first-party materialization and bundle observation
are true; wrapper-contract validity, valid materialization, valid candidate
bundle generation, evidence-commit creation, complete independent replay,
external-review completion, and audit-evidence acceptance are all false. No
external audit occurred and no vendor contact occurred for candidate-002.
Candidate-002 is non-evidence and must not be reused, promoted, or issued.

Before issue, candidate-003 must be independently replayed; a post-subject
evidence envelope must map the stable ID to the canonical `freeze.json`, policy,
scope, and SOW SHA-256 digests; and the security lead must separately authorize
vendor contact. The in-subject SOW is not rewritten with the later freeze digest,
avoiding a self-referential freeze. No external audit occurred and no vendor was
contacted for either superseded candidate.

## 1. Subject and objective

dcrypt requests an independent security assessment of the exact
post-v3.0.0 assurance-branch candidate-003 bytes bound by the candidate freeze. The
objective is to find correctness, forgery, key-recovery, authentication,
domain-separation, nonce, parsing, implementation, protocol-composition,
side-channel, fault, dependency, build, and supply-chain defects before those
bytes can satisfy release assurance requirements.

Audit conclusions apply only to the candidate-freeze bytes. They do **not**
apply to the published v3.0.0 Git tag or registry archives unless the auditor
performs an explicit byte-for-byte comparison, records its method and hashes,
and names the additional subject in the final report. A matching version label,
manifest, or source-tree resemblance is not such a comparison.

The authoritative scope and contract controls are
`audit-scope.toml` and `audit-policy.toml`. Their hashes above must match the
issued files. If this prose and the machine-readable policy conflict, the more
release-conservative requirement applies until the parties resolve and version
the discrepancy.

## 2. Frozen inputs and access

The issued package must identify the subject commit and tree and include a
canonical candidate-freeze manifest. The auditor will receive, where available:

- the complete SHA-256 manifest, source archive, expected registry archives,
  and the exact bytes actually downloaded or rebuilt;
- every root and isolated-workspace lockfile and dependency closure;
- the published and non-published feature/profile matrix and
  `implementation-boundary.toml`;
- bound Rust, Cargo, rustdoc, LLVM, linker, target, container, action, and
  build-shaping environment identities;
- SBOMs, build logs, artifacts, and compiler/target-bound disassemblies;
- the assurance ledger, 9,298-row atomic inventory or its superseding exact
  count, public-API snapshot, generated supported-algorithm documentation,
  threat models, known limitations, and unresolved blocker inventory;
- historical-advisory regression inventory, fixtures, and replay commands;
- ACVP-format corpus and local byte manifest, retaining the explicit fact that
  upstream provenance is unverified unless the freeze supplies independent
  acquisition evidence; and
- interoperability-oracle dossiers and offline replay material accepted for
  the candidate.

Missing material must be reported as a scope limitation and mapped to affected
assurance rows. Metadata is not a substitute for missing artifact bytes.
Repository-generated evidence is untrusted until independently replayed.

## 3. Technical scope

The auditor must map coverage and findings to exact IDs in
`assurance/atomic-operations.toml`. Every public alias must trace to its owning
implementation; a finding without an existing match requires a new explicit
row rather than an empty mapping.

### 3.1 ML-KEM-512/768/1024

Review FIPS 203 key generation, encapsulation, decapsulation, implicit
rejection, parsing, canonical encoding, NTT arithmetic, sampling, randomness,
failure behavior, malformed input handling, and all parameter-set boundaries.
Examine decapsulation for ciphertext-dependent leakage and distinguish
specified implicit-rejection behavior from accidental error oracles.

### 3.2 ML-DSA-44/65/87

Review FIPS 204 key generation, deterministic and hedged signing,
verification, contexts, prehash modes, rejection sampling, canonical encodings,
malformed signatures, randomness, failure behavior, and all parameter sets.
Include rejection-loop resource bounds and leakage through attempts, errors,
control flow, and memory access.

### 3.3 BLS12-381 arithmetic and signatures

Review field, group, pairing, and subgroup arithmetic; point parsing and
validation; hash-to-curve and domain separation; KeyGen; Basic, Augmented, and
Proof-of-Possession profiles; the Ethereum consensus profile; aggregation;
duplicate-message and rogue-key attacks; and invalid, identity, torsion, and
non-subgroup points. Evaluate RFC 9380 and profile-specific DST handling and
look for variants of prior subgroup-validation and hash-to-curve findings.

### 3.4 Ed25519

Review RFC 8032 key generation, signing, strict verification, canonical point
and scalar encodings, small-order and identity points, malleability, malformed
keys and signatures, and seed/key import semantics. Include variant analysis
for the historical universal-forgery defect.

### 3.5 P-curves and secp256k1

Review P-224, P-256, P-384, P-521, and secp256k1 field/scalar/point arithmetic;
ECDSA signing and strict verification; RFC 6979 deterministic nonces; DER
parsing and serialization; low-S policy; ECDH with arbitrary and invalid
peers; point validation; and every dcrypt ECIES protocol and transcript.
Explicitly assess P-224's transitional status and any profile divergence.

### 3.6 AES-128/256-GCM and GHASH

Review AES-128-GCM, AES-256-GCM, and standalone GHASH field arithmetic;
encryption/decryption; authentication behavior; nonce use and reuse contracts;
tag generation and verification; tampering/truncation; compiler output; and
platform-specific implementations. Include variant analysis for the ignored
operation-nonce and secret-dependent compiled-GHASH-branch advisories.

### 3.7 ChaCha-family and Poly1305 constructions

Review ChaCha20, HChaCha20, Poly1305, ChaCha20-Poly1305, and high-level
XChaCha20-Poly1305: core arithmetic, subkey derivation, seal/open, nonce and AAD
handling, transcript construction, tag verification, framing, tampering, and
truncation. Include variants of the historical zero-nonce and nonstandard
XChaCha construction defects.

### 3.8 KDFs and password-derived operations

Review HKDF, PBKDF2, Argon2d/i/id, and dcrypt key-derivation profiles for
extract/expand semantics, salt/context and domain separation, parameter
validation, resource bounds, random-salt generation, RNG failures, and
password/secret lifecycle.

### 3.9 Hybrid constructions, ECIES and framing

Review ECDH+ML-KEM hybrid KEMs, ECDSA+ML-DSA hybrid signatures, ECIES,
streaming, and migration formats against the frozen wire and transcript
specifications. Cover wire encoding, framing, transcript construction, domain
separation, KDF inputs, key confirmation, component-failure composition,
downgrade/version behavior, and tampering/truncation. Include variants of the
unauthenticated streaming-framing defect. Ambiguity is a finding, not license
to invent new public semantics.

### 3.10 RNG, errors and secret lifecycle

Review entropy assumptions and degradation, caller-owned RNG contracts,
failure propagation, partial output, panic behavior, operation-scoped errors,
the deprecated global error-registry compatibility path, secret creation,
copying and exposure, and documented zeroization limitations. Analyze fault
conditions that could bypass authentication, skip validation, reuse a secret,
or expose key material.

### 3.11 Historical-advisory regression and variant analysis

Independently replay and perform common-root variant analysis for
DCRYPT-2026-0001 through DCRYPT-2026-0011: error-registry memory unsafety,
Ed25519 universal forgery, ignored GCM operation nonce, unauthenticated stream
framing, predictable legacy ECDH-KEM secret, BLS subgroup bypass, BLS
hash-to-curve incompatibility, pre-final ML-KEM incompatibility, XChaCha
zero-nonce reuse, nonstandard XChaCha construction, and compiled GHASH
secret-dependent branches. A passing repository fixture alone is not closure.

### 3.12 Build, dependency and supply-chain assurance

Review all twelve published crates and isolated workspaces: locked dependency
closures, packaged contents, unsafe/native/FFI boundaries, oracle/fuzz
isolation, toolchain and target binding, action/container pinning, SBOM
completeness, registry-archive correspondence, the precision of reproducible
build claims, and clean-room replay. Report exactly which artifact bytes were
rebuilt and compared.

Across every section, cover canonical and malformed inputs, empty/boundary/
maximum inputs, resource exhaustion, secret-dependent control flow and memory
access, compiler/platform variance, fault and partial-computation behavior,
public-API/feature drift, and dependency/oracle common-mode failure.

## 4. Required team and independence

The proposal must name specialists for post-quantum cryptography, pairing/ECC,
symmetric cryptography, side channels, protocols/compositions, and Rust
build/supply-chain assurance. It must explain each specialist's relevant work,
allocated time, and who owns each scope section.

Before access, the organization, specialists, and subcontractors must disclose
financial, employment, authorship, advisory, dependency-maintainer, and other
material conflicts. An assigned auditor must not have materially authored,
designed, or merged the audited dcrypt implementation or its assurance evidence
within the preceding 24 months. Prior assessment work is allowed only when
disclosed; prior material implementation contribution is not. Shared reference
code, generators, arithmetic backends, tables, and dependencies used as
analysis oracles must be disclosed. Remediation retesting must be performed by
an auditor who did not write the fix and who independently reproduces the
original finding first.

## 5. Required methodology

At minimum, perform manual source/specification review, independent test
derivation, negative and differential testing, parser/encoding and resource
analysis, transitive secret-path and optimized-assembly review for frozen
compiler/target/feature combinations, historical-variant analysis, and
dependency/package/build provenance review. Review exact public feature and
platform profiles, not an invented empty-feature configuration.

The proposal must identify tools, versions, qualifications, limitations, and
how results will be replayed. Harness existence, unexecuted scaffolding,
generated metadata, and inconclusive measurements do not count as passing
evidence. The auditor should preserve minimal reproductions and raw evidence
without placing exploit material in public channels during embargo.

## 6. Finding format and traceability

Each finding must contain the fields named in `audit-policy.toml`, including
severity and defect class; exact assurance row IDs and public paths; frozen
commit/tree, features, targets, and toolchains; threat model and attacker
preconditions; impact; deterministic reproduction; artifact hashes; root cause
and variants; remediation; regression-test ID; remediation-record ID;
independent-retest record ID; and disclosure state.

Confirmed findings remain open until the regression test, remediation record,
and independent retest are linked. “Unable to reproduce” is not a passing
retest unless the auditor documents a justified original-finding disposition.

## 7. Severity and response SLAs

<!-- BEGIN GENERATED SLA TABLE -->
| Severity | Exact characterization | Acknowledge | Containment plan | Remediate | Independent retest | Coordinated disclosure | Release blocking |
|---|---|---:|---:|---:|---:|---:|:---:|
| Critical | Practical or broadly exploitable key recovery, signature or authentication forgery, remote code execution or memory unsafety across a common/default use, catastrophic systemic protocol break, or equivalent impact. | 4 hours | 24 hours | 3 calendar days | 5 business days | 30 calendar days | yes |
| High | Key recovery, forgery, authentication bypass, material confidentiality/integrity loss, exploitable side channel, or standards/correctness failure under realistic preconditions. | 24 hours | 72 hours | 14 calendar days | 10 business days | 60 calendar days | yes |
| Medium | Security weakness requiring restrictive conditions, meaningful denial of service, defense-in-depth failure, or correctness defect with limited security reach. | 72 hours | 240 hours | 45 calendar days | 15 business days | 90 calendar days | no |
| Low | Limited-impact hardening, misuse-resistance, diagnostic, documentation or non-default weakness without a demonstrated material compromise. | 120 hours | 720 hours | 90 calendar days | 20 business days | 120 calendar days | no |
| Informational | Observation with no current security impact that records an assumption, limitation, quality improvement or future risk. | 120 hours | 1,440 hours | 180 calendar days | 20 business days | 180 calendar days | no |

- Clock starts: Auditor delivery to the designated private reporting channel
- Business day: One business day in the project security lead's published timezone, excluding published local holidays
- Calendar day: Continuous 24-hour periods
- Missed SLA: Escalate to the security lead and release authority; a missed Critical or High remediation or retest SLA blocks release unless a documented risk decision withdraws the affected functionality.
- Extensions: Require written agreement from the security lead and auditor, a reason, a replacement date, affected assurance rows, and an explicit release disposition. Critical and High findings cannot be risk-accepted for release.
<!-- END GENERATED SLA TABLE -->

## 8. Coordinated disclosure and handling

<!-- BEGIN GENERATED COORDINATED DISCLOSURE -->
- Private reporting required: `true`
- Need-to-know access required: `true`
- Embargo starts: first private report
- Embargo ends: the earliest coordinated publication date agreed by dcrypt and the auditor, or the applicable disclosure SLA
- Vendor and downstream notice: Notify affected dependencies and downstreams privately when their action is required, using least disclosure necessary during embargo.
- Credential handling: No secrets, signing credentials, registry tokens or production keys may enter audit artifacts; suspected credential exposure triggers the incident-response procedure immediately.
- Public report required: `true`
- Public report timing: after remediation and independent retest, or at the coordinated-disclosure deadline when remediation is incomplete
- Permitted redactions:
  - active exploit details during an agreed embargo
  - personal data
  - third-party confidential material not needed to understand risk or remediation
  - credentials and infrastructure secrets
- Forbidden redactions:
  - finding existence
  - final severity
  - affected algorithms and assurance rows
  - security impact
  - remediation status
  - whether independent retesting passed
  - material scope limitations or conflicts
<!-- END GENERATED COORDINATED DISCLOSURE -->

## 9. Deliverables

The engagement must produce:

1. Signed organization, specialist, and subcontractor independence disclosures.
2. An audit plan and exact assurance-row coverage map.
3. Private interim machine-readable finding records.
4. A final technical report with methods, coverage, findings, limitations, and unresolved questions.
5. A public report with only permitted redactions.
6. A finding-to-regression-test and remediation traceability matrix.
7. An independent retest letter naming every confirmed finding and the exact remediated commit/tree.
8. An artifact-return and confidential-data-destruction attestation.

## 10. Release acceptance

The audited candidate is unacceptable for release with any unresolved Critical
or High finding. It is also unacceptable with any unresolved correctness,
forgery, key-recovery, nonce, domain-separation, secret-dependent-control-flow,
or secret-dependent-memory-address defect, regardless of assigned severity.
Every confirmed finding requires a regression test, remediation record, and
mandatory independent retest. Inconclusive, scaffolded, generated-but-unreplayed,
or scope-limited evidence is not a pass and does not clear an assurance row.

Acceptance of this engagement's deliverables does not itself authorize a
release or certify all 9,298 assurance rows. Remaining audit, interoperability,
fuzzing, side-channel, platform, and supply-chain blockers stay fail closed.

## 11. Proposal response

The vendor response should include the named team and conflicts; scope
coverage; methods and tools; estimated person-weeks by specialist and section;
calendar schedule and dependencies; secure collaboration model; deliverable
examples; fixed-price or time-and-materials pricing with retest costs shown
separately; assumptions; requested exclusions; subcontractors; data location
and retention; insurance; and references for comparable PQC, pairing/ECC,
symmetric, side-channel, protocol, and Rust supply-chain audits.

Any proposed exclusion, substitution, or limitation must name the exact
assurance rows affected. It is not accepted merely because it appears in a
proposal. Vendor selection, contact, contracting, paid infrastructure, and
commissioning require separate authorization outside this candidate package.
