# Assurance Profile metrics

The visual report is generated from `lab-report.json` and its referenced
artifacts. Each headline metric has a fixed evidence class and interpretation.

| Metric | Source | Interpretation |
| :--- | :--- | :--- |
| Injected faults detected | `simulation_controls.artifact_single_bit_fault` | Detection coverage for the declared single-bit artifact-mutation model |
| Leakage positive and negative controls | `simulation_controls.hamming_weight_tvla` | Calibration of the deterministic synthetic leakage-analysis pipeline |
| Timing-sensitive paths | Structured output from both timing commands | Suite-wide Holm-corrected decisions for exactly 29 blocking cases, run twice |
| Historical failures closed | `historical-advisory-replay.json` | All eleven recorded vulnerability classes pass their source-bound regressions |
| Post-quantum vector cases | Complete `acvp_tests` execution plus corpus enumeration | Exact expected-field checks for 615 ML-DSA and 240 ML-KEM repository cases |
| Byte-equal packages | `packages/manifest.json` | Twelve package archives agree across two clean target directories |
| Deterministic SBOMs | `sboms/*.cdx.json` | Five classified dependency closures produce stable CycloneDX documents |
| Configured targets | Implementation-boundary and compiler-shape commands | Build evidence for the four target profiles declared by policy |

## Timing visualization

The report does not plot raw runtime as a security score. For each case it shows
the absolute paired mean difference relative to that case's predeclared
practical threshold. Hovering a row exposes the mean, threshold, primary
paired-randomization p-value, and family result.

The release blocks only when the suite-wide Holm procedure rejects a case and
the absolute paired mean difference exceeds its practical threshold. Confidence
intervals and additional distribution diagnostics remain descriptive.

## Standards-vector terminology

The 855-case metric is repository-corpus correctness evidence. The repository
does not currently authenticate the upstream acquisition history of these local
fixtures. Passing them is not NIST validation, FIPS module certification, or an
assertion that every algorithm is suitable for every protocol.

## Signature terminology

The laboratory generates a temporary Ed25519 key, signs the canonical evidence
manifest, verifies it immediately, and destroys the private key. This binds one
emitted bundle together. It does not establish a long-term project identity,
independent producer, or transparency-log entry.

## No composite score

dcrypt deliberately publishes a profile instead of a single score. Correctness,
timing behavior, historical regression closure, simulation calibration, and
supply-chain reproducibility answer different questions and should remain
independently inspectable.
