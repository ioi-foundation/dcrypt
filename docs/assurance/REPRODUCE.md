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
