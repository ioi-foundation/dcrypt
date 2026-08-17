# dcrypt v4.0.0 assurance artifacts

This directory preserves the exact machine-readable Assurance Profile attached
to the public [`v4.0.0` GitHub release][release]. It gives documentation builds
an offline, versioned input while the release attachment remains the public
distribution artifact.

| Artifact | SHA-256 | Public copy |
| :--- | :--- | :--- |
| `assurance-profile.json` | `3233e23a2b78b6f4886da798b3dade0ced4c3b870f0691243bfbe587131445ab` | [JSON profile][profile] |
| `assurance-report.html` | `8a225e4abd8d0f9fac2436c6deb7131020926cd84774a15761d6397b6f03552a` | [Visual report][report] |

The tracked profile is an exact byte copy of the release asset, not a manually
transcribed metric source. `tools/generate-assurance-docs.py` consumes it to
produce the Markdown summary and SVG graphics. CI regenerates those projections
in memory and fails when checked-in output drifts.

The report and profile describe commit
[`0d014c306c371b4d42d85001affb036f9fe4d3c3`][commit]. Later runs may produce
new evidence, but they do not retroactively replace this released subject.

[commit]: https://github.com/ioi-foundation/dcrypt/commit/0d014c306c371b4d42d85001affb036f9fe4d3c3
[profile]: https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.0/assurance-profile.json
[release]: https://github.com/ioi-foundation/dcrypt/releases/tag/v4.0.0
[report]: https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.0/assurance-report.html
