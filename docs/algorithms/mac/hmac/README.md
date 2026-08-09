# HMAC

`Hmac<H>` applies the RFC 2104 HMAC transform to a supported `HashFunction`.
The crate is not a FIPS-validated module; interoperability and deployment
requirements must be assessed for the selected hash.

## API

```rust
use dcrypt_algorithms::hash::Sha256;
use dcrypt_algorithms::mac::Hmac;

let key = b"secret key";
let message = b"message";

let tag = Hmac::<Sha256>::mac(key, message)?;
assert!(Hmac::<Sha256>::verify(key, message, &tag)?);

let mut state = Hmac::<Sha256>::new(key)?;
state.update(b"mes")?;
state.update(b"sage")?;
assert_eq!(state.finalize()?, tag);
# Ok::<(), dcrypt_algorithms::error::Error>(())
```

The methods are:

- `new(key)` creates an incremental context.
- `update(data)` absorbs a chunk and rejects updates after finalization.
- `finalize()` returns the full digest-width tag and rejects a second call.
- `mac(key, data)` computes a full-width tag in one shot.
- `verify(key, data, tag)` rejects every non-exact tag length, including tags
  with 256 or other large numbers of appended bytes.

`verify` compares tag bytes without value-dependent early exit after accounting
for the public length. Key length, message length, allocation, hash failures,
state errors, and the returned boolean use ordinary control flow, so the entire
operation is not claimed to have identical timing.

The context owns zeroizing inner/outer pads and treats the hash state after
absorbing `ipad` as key-derived. It explicitly wipes key-derived temporaries on
success and fallible exits. As with software zeroization generally, this does
not guarantee removal of caller, compiler, register, or historical allocator
copies.
