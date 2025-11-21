# dcrypt Common Utilities (`common`)

The `common` crate provides shared functionality, data structures, and security primitives that are used across multiple crates within the dcrypt workspace. Its main purpose is to centralize common code, especially related to security best practices, to ensure consistency and reduce redundancy.

## Core Components

1.  **Security Primitives (`dcrypt_docs/common/security/README.md`)**:
    This is the most critical part of the `common` crate. It defines types and traits for secure memory handling and cryptographic operations.
    *   **Secret Data Types**:
        *   `SecretBuffer<const N: usize>`: A fixed-size buffer for sensitive data that guarantees zeroization on drop. It ensures that secrets like keys or intermediate cryptographic values are wiped from memory.
        *   `SecretVec`: (Requires `alloc` feature) A variable-length vector for sensitive data, also guaranteeing zeroization.
        *   `EphemeralSecret<T: Zeroize>`: Wraps any type `T` that implements `Zeroize`, ensuring the inner value is zeroized when the `EphemeralSecret` is dropped. Useful for temporary secrets.
        *   `ZeroizeGuard<'a, T: Zeroize>`: A guard that ensures a mutable reference to `T` is zeroized when the guard goes out of
            scope, useful for RAII-style cleanup.
    *   **Traits**:
        *   `SecureZeroingType`: For types that can be securely zeroed and cloned.
        *   `SecureOperation<T>`: Defines a pattern for operations that need to ensure sensitive data is cleared regardless of success or failure.
        *   `SecureCompare`: For constant-time comparison of data.
    *   **Memory Barriers (`barrier`)**: Utilities for inserting compiler and memory fences (`compiler_fence_seq_cst`, `memory_fence_seq_cst`) to prevent reordering of operations by the compiler or CPU, crucial for constant-time code and correct cryptographic sequencing.
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

The `common` crate is a foundational library within dcrypt.
-   It promotes code reuse for essential security patterns (like zeroization and constant-time comparison).
-   It provides a centralized place for low-level utilities that don't fit into the `api` or `internal` crates but are needed by multiple algorithm implementations.
-   Higher-level crates like `algorithms`, `symmetric`, `kem`, and `sign` depend on `common` for these shared functionalities.

For instance, a cryptographic algorithm implementation in `dcrypt-algorithms` might use `SecretBuffer` to store its round keys, `EphemeralSecret` to manage temporary sensitive state during computation, and `barrier` functions to ensure correct execution order for side-channel resistance. Mathematical utilities might be used in RSA or Diffie-Hellman implementations.

By centralizing these common elements, dcrypt aims to maintain a higher standard of security and consistency across its various components.