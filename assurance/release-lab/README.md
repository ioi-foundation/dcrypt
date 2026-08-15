# Reproducible v4 simulated laboratory

This laboratory is an openly reproducible evidence producer for the portable
software release and for explicitly named simulation models.  It combines
real product executions with deterministic synthetic controls:

- all historical advisory regressions run against the candidate;
- the complete post-quantum standards-vector target runs and the laboratory
  records the exact 615 ML-DSA and 240 ML-KEM repository-corpus case closure;
- the full statistical timing suite runs twice on one disclosed host CPU: a
  fresh lab-local baseline followed by a complete statistical reproduction;
  both suite-wide family decisions must pass, while host-noise drift is recorded
  as observational rather than misrepresented as physical-lab qualification;
- optimized BLS and GHASH compiler-shape checks run for every configured target;
- the implementation-boundary checker performs the supported-target and
  `no_std` compilation matrix;
- all five classified lockfiles produce deterministic CycloneDX 1.6 SBOMs;
- all twelve publishable packages are assembled twice in separate clean target
  directories and must be byte-identical; and
- deterministic positive/negative Hamming-weight leakage controls plus an
  exhaustive single-bit artifact-fault model validate the simulated analysis
  pipeline;
- an OpenAI Daybreak adversarial review records the claim boundary and known
  risk disposition; and
- an ephemeral Ed25519 key signs a canonical manifest of the generated lab
  artifacts, and the runner immediately verifies the signature; and
- the passing report automatically produces a machine-readable Assurance
  Profile plus a self-contained visual report.

The report is laboratory proof for those exact models and executions.  It is
not a claim that a simulated Hamming-weight trace is a measurement from a
particular board, probe, power rail, or electromagnetic environment.  Real
device certification can consume the same report format later without changing
the v4 portable-source release claim.

Run the complete lab with:

```text
python3 -B tools/run-v4-lab-simulation.py \
  --output target/release-evidence/v4-lab
```

Open the generated report at
`target/release-evidence/v4-lab/assurance-report/assurance-report.html`, or
consume
`target/release-evidence/v4-lab/assurance-report/assurance-profile.json`.
Neither file contains independently maintained marketing values: both are
deterministic projections of `lab-report.json` and its verified artifacts.

Confirm that the projection remains byte-for-byte reproducible with:

```text
python3 -B tools/generate-v4-assurance-report.py \
  --check \
  --lab-output target/release-evidence/v4-lab \
  --output target/release-evidence/v4-lab/assurance-report
```

The runner uses fixed commands, toolchain selectors, random seeds, statistical
thresholds, and artifact layouts.  It selects among the maximum-capacity CPUs in
its inherited affinity set, choosing the least busy during a fixed five-second
probe (then the lowest CPU id); the report records capacities, probe deltas, and
the selected CPU.  Set `DCRYPT_TIMING_CPU` to disclose and reproduce a specific
eligible CPU.  A nonzero command, failed control, missing artifact,
or differing package byte aborts the lab.

The repository's normal timing configuration remains fail-closed when a case
exceeds 3x its saved MAD baseline.  The simulation lab sets
`DCRYPT_CT_NOISE_POLICY=observe`: it records that drift in command output and
the profile, but requires two complete familywise statistical passes instead of
treating an uncontrolled desktop scheduler as a qualified physical timing
environment.  This distinction is part of the lab's explicit
physical-resistance nonclaim.

The Ed25519 signature proves that the manifest and evidence bundle verify as a
single lab-run output.  Its private key is generated in a temporary directory
and destroyed after signing.  Therefore it intentionally makes no external
identity, long-term trust-root, transparency-log, or administrative-independence
claim.  Anyone can verify an emitted bundle with:

```text
openssl pkeyutl -verify -pubin \
  -inkey target/release-evidence/v4-lab/simulation-signing-public.pem \
  -rawin -in target/release-evidence/v4-lab/evidence-manifest.json \
  -sigfile target/release-evidence/v4-lab/evidence-manifest.sig
```
