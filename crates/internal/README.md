# dcrypt Internal Utilities (`internal`)

The `internal` crate provides low-level utility functions and modules that are shared across various dcrypt crates but are **not** intended to be part of the public API. These utilities typically deal with implementation details crucial for security or correctness, such as constant-time operations or byte-order conversions.

## Core Components

1.  **Constant-Time Operations (`constant_time.rs`)**:
    *   **Purpose**: Provides functions to perform operations in a way that their execution time does not depend on the secret values being processed. This is crucial for mitigating timing side-channel attacks.
    *   **Key Functions**:
        *   `ct_eq(a: AsRef<[u8]>, b: AsRef<[u8]>) -> bool`: Constant-time equality comparison for byte slices, leveraging the `subtle` crate.
        *   `ct_select<T: ConditionallySelectable>(a: T, b: T, condition: bool) -> T`: Constant-time conditional selection.
        *   `ct_assign(dst: &mut [u8], src: &[u8], condition: bool)`: Constant-time conditional assignment for byte slices.
        *   `ct_eq_choice(a, b) -> subtle::Choice`: Constant-time equality returning a `subtle::Choice`.
        *   `ct_and`, `ct_or`, `ct_xor`: Constant-time bitwise operations on fixed-size byte arrays.
        *   `ct_op`: Generic constant-time conditional operation on byte arrays.
        *   `ct_mask(condition: bool) -> u8`: Generates an all-1s or all-0s mask based on a condition.
    *   **Dependencies**: Relies heavily on the `subtle` crate for its underlying constant-time primitives.

2.  **Endianness Utilities (`endian.rs`)**:
    *   **Purpose**: Provides helper functions for converting between native byte order and little-endian or big-endian byte orders for `u32` and `u64` types.
    *   **Key Functions**:
        *   `u32_from_le_bytes`, `u32_from_be_bytes`
        *   `u32_to_le_bytes`, `u32_to_be_bytes`
        *   `u64_from_le_bytes`, `u64_from_be_bytes`
        *   `u64_to_le_bytes`, `u64_to_be_bytes`
    *   **Note**: These often wrap standard library or `byteorder` crate functionalities but provide a centralized internal API.

3.  **Secure Memory Zeroing (`zeroing.rs`)**:
    *   **Purpose**: Offers utilities for securely clearing sensitive data from memory.
    *   **Key Functions**:
        *   `secure_zero(data: &mut [u8])`: Uses `data.zeroize()` from the `zeroize` crate.
        *   `secure_clone_and_zero(data: &mut [u8]) -> Vec<u8>`: Clones a slice and then zeroes the original.
    *   **`ZeroGuard<'a>` Struct**: An RAII guard that ensures a mutable byte slice is zeroed when the guard goes out of scope.

4.  **SIMD Utilities (`simd` module in `lib.rs`)** (conditional on `simd` feature):
    *   **Purpose**: Placeholder for SIMD (Single Instruction, Multiple Data) related utility functions, such as checking for SIMD availability.
    *   `is_available() -> bool`: Checks for `sse2` target feature as an example.

## Intended Use

The `internal` crate is strictly for use by other dcrypt crates (e.g., `algorithms`, `common`). Its contents are considered implementation details and are subject to change without notice, as they are not governed by the public API stability promises of the dcrypt library.

By centralizing these low-level, security-critical utilities, dcrypt aims to:
-   Ensure consistent application of security best practices (like constant-time operations).
-   Reduce code duplication for common internal tasks.
-   Make it easier to audit and verify these critical pieces of code.