# Reproduce the v4 Assurance Profile

Run the complete laboratory from the repository root:

```sh
python3 -B tools/run-v4-lab-simulation.py \
  --output target/release-evidence/v4-lab
```

The command selects a qualified CPU from the process affinity set unless
`DCRYPT_TIMING_CPU` names an eligible CPU explicitly. It uses locked offline
dependencies, pinned toolchains where declared, fixed simulation seeds, and
predeclared statistical thresholds.

On success, open:

```text
target/release-evidence/v4-lab/assurance-report/assurance-report.html
```

The corresponding machine-readable result is:

```text
target/release-evidence/v4-lab/assurance-report/assurance-profile.json
```

Confirm that the presentation reproduces exactly from the evidence:

```sh
python3 -B tools/generate-v4-assurance-report.py \
  --check \
  --lab-output target/release-evidence/v4-lab \
  --output target/release-evidence/v4-lab/assurance-report
```

Verify the emitted evidence manifest:

```sh
openssl pkeyutl -verify -pubin \
  -inkey target/release-evidence/v4-lab/simulation-signing-public.pem \
  -rawin \
  -in target/release-evidence/v4-lab/evidence-manifest.json \
  -sigfile target/release-evidence/v4-lab/evidence-manifest.sig
```

The private signing key is temporary and is destroyed after the laboratory
verifies the signature. See the [metric definitions](METRICS.md) and
[laboratory model](OPEN-SECURITY-LAB.md) before interpreting the results.

## Verify the released documentation projections

The Markdown ledger and static SVG graphics are generated from the exact
`v4.0.0` profile attachment preserved in the repository. Verify that they have
not drifted with:

```sh
python3 -B tools/generate-assurance-docs.py \
  --profile docs/assurance/releases/v4.0.0/assurance-profile.json \
  --summary docs/assurance/V4-SUMMARY.md \
  --assets-dir docs/assurance/assets \
  --source-ref v4.0.0 \
  --check
```

This check is fast, offline, and runs in the dedicated Assurance documentation
workflow. A new release should add its exact public profile as a versioned input
and deliberately regenerate the ledger and graphics; it should not overwrite a
historical release snapshot.
