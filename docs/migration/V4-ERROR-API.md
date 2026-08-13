# Migrating to the v4 error API

The future v4 API removes the process-global deferred-error registry and the
legacy `Result` compatibility extension traits. This is a local source migration
only: it does not change package versions, publish crates, alter advisory ranges,
or yank registry records.

## Replacement table

| Removed API | Replacement |
| --- | --- |
| `ERROR_REGISTRY`, `ErrorRegistry` | Return or propagate `Result`; store diagnostics in caller-owned state. |
| `ErrorRegistryExt::unwrap_or_record_with(default, on_error)` | Prefer `?` or `match`. For intentional fallback, use `unwrap_or_else` or `map_or_else` and update caller-owned diagnostics. |
| `SecureErrorHandling::secure_unwrap(default, on_error)` | Same as above. The historical name never provided constant-time execution. |
| `ConstantTimeResult::ct_is_ok()` | `Result::is_ok()` |
| `ConstantTimeResult::ct_is_err()` | `Result::is_err()` |
| `ConstantTimeResult::ct_map(ok_fn, err_fn)` | `result.map_or_else(err_fn, ok_fn)`; note the reversed closure order. Neither form is constant-time. |
| `ResultExt::wrap_err(f)` | `result.map_err(\|_\| f())`; this intentionally discards the original error. |
| `ResultExt::with_context(context)` | `result.map_err(\|error\| Into::<dcrypt_api::Error>::into(error).with_context(context))` |
| `ResultExt::with_message(message)` | Under `std`, use the same explicit conversion followed by `.with_message(message)`. |
| `SymmetricResultExt::map_io_err()` | `.map_err(dcrypt_symmetric::error::from_io_error)` |
| `SymmetricResultExt::map_primitive_err()` | `.map_err(dcrypt_symmetric::error::from_primitive_error)` |

The `dcrypt_api::error::registry` and `dcrypt_api::error::traits` module paths
remain as documented empty tombstones. The removed values and traits are not
available through those modules or through the former `dcrypt`,
`dcrypt-algorithms`, `dcrypt-kem`, and `dcrypt-symmetric` convenience reexports.

## Propagate errors directly

```rust
use dcrypt_api::error::Result;

fn caller() -> Result<u32> {
    let value = fallible_operation()?;
    Ok(value)
}
# fn fallible_operation() -> Result<u32> { Ok(7) }
```

## Keep fallback diagnostics local

```rust
use dcrypt_api::error::{Error, Result};

fn fallback(result: Result<u32>, diagnostic: &mut Option<Error>) -> u32 {
    result.unwrap_or_else(|error| {
        *diagnostic = Some(error);
        0
    })
}
```

This makes ownership and overwrite behavior explicit. Do not rebuild a
process-global last-error slot as a substitute.

## Convert and enrich errors explicitly

```rust
use dcrypt_api::error::{Error, Result};

fn enrich<E: Into<Error>>(result: core::result::Result<(), E>) -> Result<()> {
    result.map_err(|error| error.into().with_context("enrich operation"))
}
```

Under `std`, append `.with_message(...)` when a non-secret diagnostic is useful.
Messages must never reveal secret values.

## Convert symmetric implementation errors

```rust
use dcrypt_symmetric::error::{from_io_error, from_primitive_error};

# fn example(
#     io_result: std::io::Result<()>,
#     primitive_result: dcrypt_algorithms::error::Result<()>,
# ) -> dcrypt_api::error::Result<()> {
io_result.map_err(from_io_error)?;
primitive_result.map_err(from_primitive_error)?;
# Ok(())
# }
```

The downstream executable fixture at
`tests/tests/error_api_v4_migration.rs` compiles and checks these replacement
semantics against the workspace crates.

## Unchanged surfaces

This migration does not remove other transitional algorithms or APIs. In
particular, it does not change P-224, generic HKDF/HMAC/PBKDF2/SHA-1 surfaces,
the intentionally unsupported X25519 markers, or the separate legacy
XChaCha20-Poly1305 decrypt-only migration tool.
