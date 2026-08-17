# dcrypt Open Security Lab

## Test the detection system, too.

Security testing is strongest when the test apparatus is itself exercised.
The dcrypt laboratory runs the product and introduces controlled signals, then
publishes both kinds of result in one reproducible bundle.

## Released v4.0.0 result

The public v4.0.0 run completed all 11 laboratory commands for commit
[`0d014c306c371b4d42d85001affb036f9fe4d3c3`](https://github.com/ioi-foundation/dcrypt/commit/0d014c306c371b4d42d85001affb036f9fe4d3c3).

| Read it as | Artifact |
| :--- | :--- |
| Human, interactive | [Self-contained visual report download](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.0/assurance-report.html) |
| Machine and policy | [Public Assurance Profile JSON](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.0/assurance-profile.json) |
| Markdown and procurement review | [Generated evidence ledger](V4-SUMMARY.md) |
| Independent reproduction | [Step-by-step reproduction guide](REPRODUCE.md) |

<a href="V4-SUMMARY.md">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/v4-evidence-flow-dark.svg">
    <img src="assets/v4-evidence-flow-light.svg" alt="v4 evidence production path — the four-step reproducible path">
  </picture>
</a>

## Adversarial sequence

Every complete v4 laboratory run performs the following sequence and stops at
the first failure:

1. Replay all eleven documented dcrypt vulnerability classes against the exact
   candidate.
2. Execute the complete post-quantum standards-vector target and confirm the
   repository corpus contains 615 ML-DSA plus 240 ML-KEM cases.
3. Generate and verify five deterministic CycloneDX 1.6 SBOMs.
4. Build all twelve publishable packages twice in separate clean target
   directories and require byte equality.
5. Run the supported target and `no_std` implementation-boundary matrix.
6. Inspect optimized BLS secret-scalar and GHASH compiler shapes.
7. Run a fresh 29-case timing baseline and a complete 29-case reproduction on
   a disclosed, qualified CPU.
8. Calibrate the leakage-analysis pipeline with deterministic positive and
   negative controls.
9. Inject every single-bit mutation in the declared artifact-fault subject and
   require all 432 mutations to be detected.
10. Sign the canonical evidence manifest with an ephemeral Ed25519 key and
    immediately verify the signature.
11. Generate the machine Assurance Profile and the self-contained visual
    report from the resulting evidence.

## Leakage calibration

The positive control combines byte Hamming weight with seeded Gaussian noise.
The negative control uses seeded noise without the Hamming-weight signal. Each
class contains 20,000 samples and the predeclared absolute Welch t threshold is
4.5.

A passing calibration requires both:

- the positive control exceeds the threshold; and
- the negative control remains at or below the threshold.

This proves that the deterministic analysis pipeline distinguishes the known
synthetic signal from its paired noise control under the published model. It
does not claim measurement of power, electromagnetic emanation, or timing on a
specific physical board.

## Fault simulation

The artifact-fault model flips each bit of the fixed simulation subject once.
Every mutation must change the SHA-256 digest. The resulting 432/432 result is
an exhaustive test of that declared single-bit artifact-mutation model—not a
claim of voltage, laser, clock, or electromagnetic fault injection against a
physical device.

## Why the distinction matters

Measured executions tell users how the candidate behaved on the recorded host
and targets. Calibrated simulations tell users whether the analysis machinery
responded correctly to a known condition. The Assurance Profile preserves both
without presenting one as the other.
