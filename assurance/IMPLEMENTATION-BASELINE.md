# dcrypt assurance implementation baseline

This is the read-only baseline captured before the Leg 1 and Leg 2 changes.
It records repository and toolchain state; it is not evidence that later
working-tree content was present in the baseline commit.

## Repository identity

- Branch: `agent/v3-integration`
- HEAD commit: `2ad99cae96efef1636cf5b75e40d5b1d3135b34d`
- HEAD tree: `f869553e03b3854849f44f7df7b474a78d4d6c46`
- Initial `git status --short`: one tracked user modification, ` M .gitignore`
- Initial untracked paths: none

The pre-existing `.gitignore` modification was preserved, excluded from the
implementation scope, and not edited by the assurance work. It adds
`internal/` without a final line feed. Its preserved file SHA-256 is
`e4887e3f444e25b7baad39bd6ff3da3ae770f8dc5b3f7cf2c87a117219a8fe2c`;
the SHA-256 of `git diff --binary -- .gitignore` is
`caa005fda38ed3a65d8b92a5b788169ebba47e7106c1389bf4cd7bff980c6552`.

## Locked dependency state

All digests are SHA-256:

| Lockfile | Digest |
| --- | --- |
| `Cargo.lock` | `350de8b632d80329a7020f49b8ba3c8df35611b61c12039c30b8c7745b4170bd` |
| `verification/Cargo.lock` | `2f05e057dc06ea3e5634afc880fd01b401abdeab22627f05bb97b58acb2ba0d5` |
| `fuzz/Cargo.lock` | `9202ac98e38d9a27d2f08b9e33bba0dfbe6a525fdfc84ae0679561dcd5ae37b8` |
| `migration/legacy-xchacha20poly1305/Cargo.lock` | `f16bbd9659f7942daa68ddafec9e1731105fe617d88b57d8dc5f788f2df14e11` |

## Pinned inventory toolchain

The ledger requests logical toolchain `nightly-2026-08-07`. That dated rustup
alias was not installed on the implementation host; the installed `nightly`
alias was accepted only because its full rustdoc/rustc commit exactly matched
the ledger pin.

- rustc: `1.99.0-nightly (1a98b1e13 2026-08-07)`
- rustc/rustdoc commit: `1a98b1e135b254f209c67d447b6d8bcd56a859e0`
- rustc/rustdoc host: `x86_64-unknown-linux-gnu`
- LLVM: `23.1.0`
- cargo: `1.99.0-nightly (c79e8f894 2026-08-04)`
- cargo commit: `c79e8f89441b3e73d6d65d125c0c745792808c74`

The baseline was recorded on 2026-08-11 in `America/New_York`. The verifier
binds the full toolchain commit rather than trusting the mutable `nightly`
alias name.
