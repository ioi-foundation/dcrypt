# Common Security Primitives (`common/security`)

This module provides wrappers and cleanup utilities that reduce exposure of
sensitive data. They are defense-in-depth tools, not secure-memory or
side-channel guarantees.

## Key Components

1.  **Secret Data Handling (`secret.rs`)**:
    These types invoke `zeroize` on storage they own. They cannot erase caller
    copies, compiler/register copies, allocator history outside the current
    allocation, or data freed before ownership was transferred.
    *   **`SecretBuffer<const N: usize>`**:
        A fixed-size array (`[u8; N]`) wrapper implementing `Zeroize` and
        `ZeroizeOnDrop`. Each clone owns storage that invokes zeroization on
        drop.
    *   **`SecretVec`** (requires `alloc` feature):
        The exact-size `Box<[u8]>`-backed type from `dcrypt-api`, re-exported here. It never retains spare capacity, wipes its complete old allocation before replacement, and wipes its current allocation on drop.
    *   **`EphemeralSecret<T: Zeroize>`**:
        A generic wrapper for a `T: Zeroize` that invokes `T::zeroize` on drop.
    *   **`ZeroizeGuard<'a, T: Zeroize>`**:
        An RAII guard that invokes `zeroize` on a borrowed value when the guard
        is dropped.
    *   **`SecureZeroingType` Trait**:
        A trait for types that can be securely zeroed and cloned while maintaining their security properties. Both `SecretBuffer` and `SecretVec` implement this.

2.  **Constant-Time Comparisons (`memory.rs`)**:
    Equal-length comparison uses dcrypt's owned constant-time equality
    primitive; no whole-operation/compiler/target constant-time guarantee
    follows from using this helper.
    *   **`SecureCompare` Trait**:
        Provides methods for constant-time comparison:
        *   `secure_eq(&self, other: &Self) -> bool`: Constant-time equality check.
        *   `secure_cmp(&self, other: &Self) -> Choice`: Constant-time comparison returning dcrypt's owned `Choice`.
        Implementations are provided for `[u8; N]` and `&[u8]`.

3.  **Memory Barriers (`memory.rs::barrier`)**:
    These expose compiler and CPU fences. Fences alone do not make an algorithm
    constant-time or make memory securely erasable.
    *   `compiler_fence_seq_cst()`: Inserts a compiler fence with sequential consistency ordering.
    *   `memory_fence_seq_cst()`: Inserts a full memory fence with sequential consistency.
    *   `with_barriers<T, F: FnOnce() -> T>(f: F) -> T`: Executes a closure, wrapping it with compiler fences.

4.  **Secure Allocation (`memory.rs::alloc`)** (requires `alloc` feature):
    Provides exact-size initialized boxed storage (`zeroizing_box`) and explicit initialized-value clearing (`clear_box`). These helpers do not lock pages or claim operating-system memory protections; dcrypt's zero-FFI boundary intentionally excludes those platform interfaces.

## Purpose and Importance

These components centralize cleanup patterns and can reduce accidental data
retention. Their exact coverage must still be audited at every call site.

For example, cryptographic keys within `dcrypt-algorithms` may be stored in
`SecretBuffer`, while intermediate values may use `EphemeralSecret` or
`ZeroizeGuard`. `SecureCompare` avoids value-dependent early exit for supported
equal-length comparisons; surrounding code still needs its own timing review.
