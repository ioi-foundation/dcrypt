# dcrypt Internal Utilities (`internal`)

The `internal` crate contains low-level utilities shared across dcrypt crates.
The `dcrypt` facade publicly re-exports its caller-supplied RNG traits; the
remaining items are implementation-oriented and have no separate stability
promise.

## Core Components

1.  **Mask-Based Operations (`constant_time.rs`)**:
    *   **Purpose**: Provides dcrypt-owned `Choice`, `CtOption`,
        `ConditionallySelectable`, `ConstantTimeEq`, and equal-length byte-slice
        comparison primitives.
    *   **Scope**: These source-level mask-based operations are dependency-free.
        Their use does not establish a blanket whole-operation, compiler, or
        target timing guarantee; supported-target assembly and statistical
        checks remain part of the release gate.

2.  **Endianness Utilities (`endian.rs`)**:
    *   **Purpose**: Provides helper functions for converting between native byte order and little-endian or big-endian byte orders for `u32` and `u64` types.
    *   **Key Functions**:
        *   `u32_from_le_bytes`, `u32_from_be_bytes`
        *   `u32_to_le_bytes`, `u32_to_be_bytes`
        *   `u64_from_le_bytes`, `u64_from_be_bytes`
        *   `u64_to_le_bytes`, `u64_to_be_bytes`
    *   **Note**: These are owned helpers around Rust primitive conversion
        methods; `dcrypt-internal` has no external normal/build dependency.

3.  **Owned Memory Clearing (`zeroing.rs`)**:
    *   **Purpose**: Offers best-effort safe-Rust utilities for explicitly
        clearing initialized storage owned by dcrypt types.
    *   **Key Functions**:
        *   `secure_zero(data: &mut [u8])`: Uses dcrypt's safe-Rust `Zeroize` implementation.
        *   `boxed_bytes_zeroed` / `boxed_bytes_from_slice`: Create exact-size boxed byte storage before secret data is written.
        *   `ZeroizingBytes`: An exact-size `Zeroizing<Box<[u8]>>` alias for secret-returning APIs.
        *   `secure_clone_and_zero(data: &mut [u8]) -> Box<[u8]>`: Clones a slice into exact-size storage and then zeroes the original.
    *   **`ZeroGuard<'a>` Struct**: An RAII guard that invokes best-effort
        explicit clearing of a mutable byte slice when it goes out of scope;
        safe Rust cannot promise physical erasure of compiler or register
        copies.

4.  **SIMD Utilities (`simd` module in `lib.rs`)** (conditional on `simd` feature):
    *   **Purpose**: Placeholder for SIMD (Single Instruction, Multiple Data) related utility functions, such as checking for SIMD availability.
    *   `is_available() -> bool`: Checks for `sse2` target feature as an example.

## Intended Use

Except for the caller RNG traits used by supported facade examples, this
crate's contents are implementation details and may change without a separate
API-stability promise.

By centralizing these low-level, security-critical utilities, dcrypt aims to:
-   Centralize reviewed mask-based operations and explicit memory-hygiene helpers.
-   Reduce code duplication for common internal tasks.
-   Make it easier to audit and verify these critical pieces of code.
