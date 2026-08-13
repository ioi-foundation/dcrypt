# API Error Handling (`api/error`)

The API crate exposes one primary [`Error`](../../../crates/api/src/error/types.rs)
enum, a `Result<T>` alias, and validation helpers. Fallible operations return
errors directly; callers should propagate or handle them with the standard Rust
`Result` API.

## Core components

### `Error`

`Error` represents invalid keys, signatures, ciphertexts, lengths and
parameters; serialization, randomness and authentication failures; unsupported
operations; and other errors. Variants carry a static operation context and,
under `std`, most variants also carry a dynamic message.

The inherent methods `Error::with_context()` and `Error::with_message()` enrich
an explicitly converted error. `with_message()` is available only with `std`.

### `Result<T>`

`Result<T>` aliases `core::result::Result<T, dcrypt_api::Error>`. Use `?` for
normal propagation and the standard `Result` combinators for deliberate mapping
or fallback behavior.

```rust
use dcrypt_api::error::{Error, Result};

fn parse_key(input: &[u8]) -> Result<()> {
    if input.len() != 32 {
        return Err(Error::InvalidLength {
            context: "parse key",
            expected: 32,
            actual: input.len(),
        });
    }
    Ok(())
}

fn initialize(input: &[u8]) -> Result<()> {
    parse_key(input).map_err(|error| error.with_context("initialize"))?;
    Ok(())
}
```

### Validation utilities

The `validate` module provides helpers for parameter and format checks. It
includes length, range, authentication, key, signature, ciphertext, and
unsupported-operation validation. These helpers return ordinary API `Result`
values and do not defer failures into global state.

## Caller-owned diagnostics and fallbacks

When fallback behavior is genuinely required, retain diagnostics in state owned
by the caller. A process-global “last error” can be overwritten by an unrelated
operation and is not part of the v4 API.

```rust
fn use_fallback(result: Result<u32>, diagnostic: &mut Option<Error>) -> u32 {
    result.unwrap_or_else(|error| {
        *diagnostic = Some(error);
        0
    })
}
```

All `Result` inspection and mapping is ordinary control flow. Do not branch on a
result variant when that variant itself carries secret information; no generic
`Result` helper makes arbitrary enum control flow or closures constant-time.

For exact replacements for the removed compatibility API, see the
[v4 error API migration guide](../../migration/V4-ERROR-API.md).
