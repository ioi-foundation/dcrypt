# Common Security Primitives (`common/security`)

This module is a cornerstone of the dcrypt library's security model. It provides essential types, traits, and utilities for handling sensitive data securely, performing operations in a way that mitigates side-channel attacks (especially timing attacks), and ensuring proper memory management for cryptographic secrets.

## Key Components

1.  **Secret Data Handling (`secret.rs`)**:
    These types are designed to automatically manage the lifecycle of sensitive information, ensuring it's zeroed out from memory when no longer needed.
    *   **`SecretBuffer<const N: usize>`**:
        A fixed-size array (`[u8; N]`) wrapper that implements `Zeroize` and `ZeroizeOnDrop`. This means its contents are automatically overwritten with zeros when it goes out of scope. It's ideal for fixed-size secrets like symmetric keys or internal cryptographic state. It also provides `secure_clone` to ensure cloned instances maintain zeroization guarantees.
    *   **`SecretVec`** (requires `alloc` feature):
        A variable-length `Vec<u8>` wrapper with similar `Zeroize` and `ZeroizeOnDrop` guarantees. Suitable for secrets whose size isn't known at compile time or can change.
    *   **`EphemeralSecret<T: Zeroize>`**:
        A generic wrapper for any type `T` that implements `Zeroize`. It ensures that `T` is zeroized when the `EphemeralSecret` wrapper is dropped. This is particularly useful for intermediate values in cryptographic computations that are sensitive but short-lived.
    *   **`ZeroizeGuard<'a, T: Zeroize>`**:
        An RAII guard that takes a mutable reference to a `T: Zeroize` and ensures `T` is zeroized when the guard itself is dropped. This is useful for ensuring cleanup in complex functions with multiple exit points or potential panics.
    *   **`SecureZeroingType` Trait**:
        A trait for types that can be securely zeroed and cloned while maintaining their security properties. Both `SecretBuffer` and `SecretVec` implement this.

2.  **Secure Operations and Comparisons (`memory.rs`)**:
    This part focuses on performing operations and comparisons in a way that resists side-channel attacks.
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
    These are crucial for preventing compiler and CPU instruction reordering that could undermine constant-time code or cryptographic logic.
    *   `compiler_fence_seq_cst()`: Inserts a compiler fence with sequential consistency ordering.
    *   `memory_fence_seq_cst()`: Inserts a full memory fence with sequential consistency.
    *   `with_barriers<T, F: FnOnce() -> T>(f: F) -> T`: Executes a closure, wrapping it with compiler fences.

4.  **Secure Allocation (`memory.rs::alloc`)** (requires `alloc` feature):
    Provides placeholders for secure memory allocation (`secure_alloc`) and deallocation (`secure_free`). The intention is for these to eventually use platform-specific mechanisms (like `mlock`/`VirtualLock`) to prevent sensitive data from being paged to disk and to ensure it's zeroed. Currently, it uses standard allocation.

## Purpose and Importance

The `common::security` module underpins dcrypt's commitment to robust security practices. By providing these reusable components:
-   **Reduces Risk of Error**: Developers using dcrypt primitives are less likely to make common mistakes in handling sensitive data or implementing constant-time operations.
-   **Centralizes Security Logic**: Security-critical patterns are implemented once and reused, making auditing and maintenance easier.
-   **Enforces Best Practices**: The type system and trait bounds encourage or enforce the use of these secure patterns.

For example, cryptographic keys within `dcrypt-algorithms` are often stored in `SecretBuffer`, and intermediate results of permutations or mixing functions might be wrapped in `EphemeralSecret` or managed by `ZeroizeGuard`. Constant-time comparisons rely on `SecureCompare` or direct use of `subtle`. Memory barriers are strategically placed in algorithm implementations to ensure correctness and resist side-channel attacks.