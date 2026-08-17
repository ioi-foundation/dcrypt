# dcrypt 4.0.1 — Assurance you can inspect

## Evidence, presented as evidence

dcrypt 4.0.1 turns the v4 Assurance Profile into a clearer public product
surface. The release ships a linked evidence ledger and quiet, theme-aware
graphics generated from the same machine profile that gates publication.

The charts show measurements instead of decorative completion meters:

- the leakage positive control, negative control, and decision threshold on a
  logarithmic t-statistic scale;
- the exact ML-DSA and ML-KEM composition of the 855-case repository corpus;
- every timing-sensitive case's released primary p-value from both complete
  passes against the family-wise Holm policy; and
- the path from exact source subject through laboratory execution, signed
  manifest, public profile, and report.

[Download the visual report](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/assurance-report.html) ·
[Download the machine profile](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/assurance-profile.json) ·
[Download the evidence ledger](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/V4-SUMMARY.md)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/v4-assurance-overview-dark.svg">
  <img src="https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/v4-assurance-overview-light.svg" alt="dcrypt 4.0.1 Assurance Profile overview — four separate evidence panels">
</picture>

## Automated from the exact release subject

The release laboratory now generates the evidence ledger and all six light/dark
SVGs from the post-versioning Assurance Profile. The GitHub draft handoff
attaches those files alongside the machine-readable profile and self-contained
HTML report. Profile validation fails closed on incomplete command results,
metric drift, missing cases, failed simulation controls, release-blocking timing
decisions, or an unverified evidence-manifest signature.

The top-level crates.io package is also scoped to the facade source and useful
end-user documentation. Large corpora and raw laboratory inputs remain public
in the Git repository and reproducible through the documented laboratory, but
they no longer force a custom-compressed upload. All twelve crates can use the
ordinary reviewed Cargo publication path.

## No cryptographic behavior change

This is a documentation, presentation, release-automation, and package-layout
patch. It does not change cryptographic implementation, public API, algorithm
behavior, wire format, or the published normal/build dependency closure.

The 4.0.1 candidate is nevertheless treated as a new subject. It must pass the
complete software release gate, produce byte-equal package rebuilds, receive a
new immutable tag, pass trusted checks at the exact tag commit, and publish a
fresh Assurance Profile before it becomes current.

## Claim boundary

The profile demonstrates the exact software executions and calibrated
simulation models it records. It does not claim physical-device leakage,
fault-injection, or erasure resistance; validation on an untested native
runtime; an independent cryptographic audit; independent rebuild certification;
formal verification; or FIPS validation. The stronger Package G certification
foundation remains visible and on HOLD.

The repository's ML-DSA and ML-KEM expected fields pass exactly, but their
upstream fixture acquisition history remains unauthenticated. This is
repository-corpus correctness evidence, not NIST validation.

## Install

```toml
dcrypt = "4.0.1"
```

Start with the
[Assurance Profile model](https://github.com/ioi-foundation/dcrypt/blob/v4.0.1/docs/assurance/README.md),
[Open Security Lab](https://github.com/ioi-foundation/dcrypt/blob/v4.0.1/docs/assurance/OPEN-SECURITY-LAB.md),
and [reproduction guide](https://github.com/ioi-foundation/dcrypt/blob/v4.0.1/docs/assurance/REPRODUCE.md).

Full changes:
[CHANGELOG.md](https://github.com/ioi-foundation/dcrypt/blob/v4.0.1/CHANGELOG.md) ·
[v4.0.0...v4.0.1](https://github.com/ioi-foundation/dcrypt/compare/v4.0.0...v4.0.1)
