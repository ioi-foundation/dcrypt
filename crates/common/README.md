# dcrypt-common

`dcrypt-common` contains small shared types used by the published dcrypt crates.
It exposes:

- `SecretBuffer<N>` for exact-size secret byte storage that is zeroized on
  drop.
- `SecretVec` (with `alloc`) for exact-length allocation-backed secret storage.
- `EphemeralSecret` and `ZeroizeGuard` for scoped cleanup.
- `SecureCompare` and secure-operation helpers.
- compiler and memory fence helpers.
- generic integer-math and elliptic-curve data structures used by internal
  components.

All crate code is safe Rust and the crate root forbids unsafe code. The default
`std` feature includes `alloc`; allocation-backed `no_std` builds select
`default-features = false, features = ["alloc"]`.

Zeroization reduces data-remanence risk for owned, initialized storage. It
cannot erase caller-created copies, registers, crash dumps, or storage outside
the wrapper, and it is not a substitute for target-specific compiler
inspection. The crate does not provide locked memory.
