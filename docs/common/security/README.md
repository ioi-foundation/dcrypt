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
        A variable-length `Vec<u8>` wrapper that wipes removed bytes on shrink, copies into a fresh allocation and wipes the old allocation before growth, and wipes its complete capacity on drop. Suitable for secrets whose size isn't known at compile time or can change.
    *   **`EphemeralSecret<T: Zeroize>`**:
        A generic wrapper for a `T: Zeroize` that invokes `T::zeroize` on drop.
    *   **`ZeroizeGuard<'a, T: Zeroize>`**:
        An RAII guard that invokes `zeroize` on a borrowed value when the guard
        is dropped.
    *   **`SecureZeroingType` Trait**:
        A trait for types that can be securely zeroed and cloned while maintaining their security properties. Both `SecretBuffer` and `SecretVec` implement this.

2.  **Secure Operations and Comparisons (`memory.rs`)**:
    This part supplies cleanup composition and equality helpers. Equal-length
    comparison uses `subtle`; no whole-operation/compiler/target constant-time
    guarantee follows from using these helpers.
    *   **`SecureOperation<T>` Trait**:
        Defines a contract for operations that handle sensitive data. The key method is `execute_secure(self) -> Result<T>`, which should perform the operation and then ensure all sensitive intermediate data is cleared via `clear_sensitive_data(&mut self)`.
    *   **`SecureOperationExt` Trait**:
        An extension trait for operations that produce a `Result`, providing `execute_with_cleanup` to ensure a cleanup function runs regardless of success or failure.
    *   **`SecureOperationBuilder<T>`**:
        A builder pattern for constructing complex operations step-by-step while allowing for cleanup functions to be registered and executed at the end.
    *   **`SecureCompare` Trait**:
        Provides methods for constant-time comparison:
        *   `secure_eq(&self, other: &Self) -> bool`: Constant-time equality check.
        *   `secure_cmp(&self, other: &Self) -> subtle::Choice`: Constant-time comparison returning a `subtle::Choice`.
        Implementations are provided for `[u8; N]` and `&[u8]` using the `subtle` crate.

3.  **Memory Barriers (`memory.rs::barrier`)**:
    These expose compiler and CPU fences. Fences alone do not make an algorithm
    constant-time or make memory securely erasable.
    *   `compiler_fence_seq_cst()`: Inserts a compiler fence with sequential consistency ordering.
    *   `memory_fence_seq_cst()`: Inserts a full memory fence with sequential consistency.
    *   `with_barriers<T, F: FnOnce() -> T>(f: F) -> T`: Executes a closure, wrapping it with compiler fences.

4.  **Secure Allocation (`memory.rs::alloc`)** (requires `alloc` feature):
    Provides placeholders for secure memory allocation (`secure_alloc`) and deallocation (`secure_free`). The intention is for these to eventually use platform-specific mechanisms (like `mlock`/`VirtualLock`) to prevent sensitive data from being paged to disk and to ensure it's zeroed. Currently, it uses standard allocation.

## Purpose and Importance

These components centralize cleanup patterns and can reduce accidental data
retention. Their exact coverage must still be audited at every call site.

For example, cryptographic keys within `dcrypt-algorithms` may be stored in
`SecretBuffer`, while intermediate values may use `EphemeralSecret` or
`ZeroizeGuard`. `SecureCompare` avoids value-dependent early exit for supported
equal-length comparisons; surrounding code still needs its own timing review.
