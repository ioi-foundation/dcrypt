# dcrypt Common Utilities (`common`)

The `common` crate provides shared functionality, data structures, and security primitives that are used across multiple crates within the dcrypt workspace. Its main purpose is to centralize common code, especially related to security best practices, to ensure consistency and reduce redundancy.

## Core Components

1.  **Security Primitives (`dcrypt_docs/common/security/README.md`)**:
    This is the most critical part of the `common` crate. It defines types and traits for secure memory handling and cryptographic operations.
    *   **Secret Data Types**:
        *   `SecretBuffer<const N: usize>`: A fixed-size buffer that invokes zeroization on its owned bytes when dropped.
        *   `SecretVec`: (Requires `alloc` feature) The exact-size boxed secret type from `dcrypt-api`, re-exported here. It wipes old allocations as it changes size and its current allocation on drop.
        *   `EphemeralSecret<T: Zeroize>`: Wraps a value and invokes its `Zeroize` implementation on drop.
        *   `ZeroizeGuard<'a, T: Zeroize>`: A guard that invokes `zeroize` on a mutable reference when the guard goes out of
            scope, useful for RAII-style cleanup.
    *   **Traits**:
        *   `SecureZeroingType`: For types that can be securely zeroed and cloned.
        *   `SecureOperation<T>`: Defines a pattern for operations that need to ensure sensitive data is cleared regardless of success or failure.
        *   `SecureCompare`: For constant-time comparison of data.
    *   **Memory Barriers (`barrier`)**: Utilities for inserting compiler and memory fences. Fences alone do not establish constant-time execution or secure erasure.
    *   **Secure Allocation (`alloc`)**: (Requires `alloc` feature) Placeholder utilities for secure memory allocation and deallocation, aiming for future integration with platform-specific mechanisms like `mlock`.

2.  **Mathematical Utilities (`math_common.rs`)**:
    Provides common mathematical functions frequently used in cryptographic algorithms:
    *   `mod_exp(base, exp, modulus)`: Modular exponentiation.
    *   `gcd(a, b)`: Greatest Common Divisor.
    *   `mod_inv(a, modulus)`: Modular multiplicative inverse using the Extended Euclidean Algorithm.
    *   `mod_add`, `mod_sub`, `mod_mul`: Modular arithmetic operations.

3.  **Elliptic Curve Utilities (`ec_common.rs`)**:
    Defines basic structures for elliptic curve cryptography:
    *   `Point { x, y, z }`: Represents a point on an elliptic curve, supporting affine (z=None) and projective coordinates.
    *   `CurveParams`: Holds parameters for a curve in short Weierstrass form (a, b, p, order, cofactor, generator).

4.  **NTRU Utilities (`ntru_common.rs`)**:
    Currently a placeholder for common operations related to NTRU-based cryptography.

5.  **McEliece Utilities (`mceliece_common.rs`)**:
    Currently a placeholder for common operations related to McEliece-based cryptography.

## Purpose and Usage

The `common` crate is a foundational library within dcrypt. Its wrappers reduce
data-remanence risk for current owned allocations, but cannot erase caller,
compiler/register, or already-freed historical copies and do not provide locked
memory.
-   It promotes code reuse for essential security patterns (like zeroization and constant-time comparison).
-   It provides a centralized place for low-level utilities that don't fit into the `api` or `internal` crates but are needed by multiple algorithm implementations.
-   Higher-level crates like `algorithms`, `symmetric`, `kem`, and `sign` depend on `common` for these shared functionalities.

For instance, a cryptographic algorithm implementation in `dcrypt-algorithms` might use `SecretBuffer` to store its round keys, `EphemeralSecret` to manage temporary sensitive state during computation, and `barrier` functions to ensure correct execution order for side-channel resistance. Mathematical utilities might be used in RSA or Diffie-Hellman implementations.

Centralizing these elements makes their behavior easier to review; it does not
constitute a blanket security guarantee for their consumers.
