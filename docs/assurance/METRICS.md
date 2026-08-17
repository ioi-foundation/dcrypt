# Assurance Profile metrics

The visual report is generated from `lab-report.json` and its referenced
artifacts. Each headline metric has a fixed evidence class and interpretation.

For the released values, machine fields, profile digest, and direct artifact
links, use the generated [`v4.0.0` evidence ledger](V4-SUMMARY.md). The
[downloadable interactive report](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.0/assurance-report.html)
adds case-level timing exploration; the static overview below is generated from
the same public profile for Markdown readers.

<a href="V4-SUMMARY.md">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/v4-assurance-overview-dark.svg">
    <img src="assets/v4-assurance-overview-light.svg" alt="dcrypt v4 assurance metrics — four separate evidence panels">
  </picture>
</a>

| Metric | Source | Interpretation |
| :--- | :--- | :--- |
| Injected faults detected | [`metrics.artifact_faults`](V4-SUMMARY.md) · [`simulation_controls.artifact_single_bit_fault`](OPEN-SECURITY-LAB.md#fault-simulation) | Detection coverage for the declared single-bit artifact-mutation model |
| Leakage positive and negative controls | [`metrics.leakage_calibration`](V4-SUMMARY.md) · [`simulation_controls.hamming_weight_tvla`](OPEN-SECURITY-LAB.md#leakage-calibration) | Calibration of the deterministic synthetic leakage-analysis pipeline |
| Timing-sensitive paths | [`metrics.timing`](V4-SUMMARY.md) · structured output from both timing commands | Suite-wide Holm-corrected decisions for exactly 29 blocking cases, run twice |
| Historical failures closed | [`metrics.historical_replay`](V4-SUMMARY.md) · [`historical-advisory-replay.json`](../security/README.md) | All eleven recorded vulnerability classes pass their source-bound regressions |
| Post-quantum vector cases | [`metrics.standards`](V4-SUMMARY.md) · complete `acvp_tests` execution | Exact expected-field checks for 615 ML-DSA and 240 ML-KEM repository cases |
| Byte-equal packages | [`metrics.packages`](V4-SUMMARY.md) · `packages/manifest.json` | Twelve package archives agree across two clean target directories |
| Deterministic SBOMs | [`metrics.sboms`](V4-SUMMARY.md) · `sboms/*.cdx.json` | Five classified dependency closures produce stable CycloneDX documents |
| Configured targets | [`metrics.platforms`](V4-SUMMARY.md) · [implementation-boundary policy](../../implementation-boundary.toml) | Build evidence for the four target profiles declared by policy |

## Reading the graphics

The overview uses small multiples because the signals have different units and
answer different questions. A count states completion of that metric's declared
test set; it is not “100% secure.” The ML-DSA/ML-KEM bar shows corpus
composition, and the calibration strip places both controls and the declared
threshold on a logarithmic t-statistic scale. The timing graphic plots each
case's released primary p-value from both complete passes on a logarithmic
scale against the family-wise Holm policy. Exact values remain printed and the
machine profile remains authoritative.

## Timing visualization

<a href="https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.0/assurance-report.html">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/v4-timing-family-dark.svg">
    <img src="assets/v4-timing-family-light.svg" alt="Per-case primary p-values for both complete timing passes on a log scale">
  </picture>
</a>

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
