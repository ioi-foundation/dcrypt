# Message Authentication Codes

The algorithms crate exposes two different kinds of authenticator:

- `Hmac<H>` is a reusable-key MAC with inherent `new`, `update`, `finalize`,
  `mac`, and `verify` methods.
- `Poly1305` is a one-time authenticator. It cannot be cloned or reset, and
  `finalize` consumes the context.

The public `Mac`/`MacExt` traits are generic extension points for reusable-key
MAC implementations. Neither built-in authenticator implements those traits;
in particular, they must never be implemented for `Poly1305`, because the
trait's `reset` operation is incompatible with a one-time key.

## HMAC

```rust
use dcrypt_algorithms::hash::Sha256;
use dcrypt_algorithms::mac::Hmac;

let key = b"application-managed secret key";
let message = b"authenticated message";

let tag = Hmac::<Sha256>::mac(key, message)?;
assert!(Hmac::<Sha256>::verify(key, message, &tag)?);

let mut incremental = Hmac::<Sha256>::new(key)?;
incremental.update(b"authenticated ")?;
incremental.update(b"message")?;
assert_eq!(incremental.finalize()?, tag);
# Ok::<(), dcrypt_algorithms::error::Error>(())
```

Verification requires the exact digest length. Equal-length tag bytes are
accumulated without value-dependent early exit. Input lengths, allocations,
hash errors, state errors, and the returned result use ordinary control flow;
this is not a whole-operation constant-time guarantee.

## Standalone Poly1305

```rust
use dcrypt_algorithms::mac::{Poly1305, POLY1305_KEY_SIZE};

let key = [0x42; POLY1305_KEY_SIZE];
let mut authenticator = Poly1305::new(&key)?;
authenticator.update(b"one message only")?;
let tag = authenticator.finalize(); // consumes the context
# let _ = tag;
# Ok::<(), dcrypt_algorithms::error::Error>(())
```

Never authenticate two messages with the same standalone Poly1305 key. Prefer
ChaCha20-Poly1305, which derives a per-nonce one-time key, or HMAC for a
general-purpose reusable-key MAC.

Owned key-derived buffers are zeroized when their wrappers are dropped. This
cannot promise erasure of caller-owned inputs, compiler/register copies,
allocator remnants outside the wrapper's allocation, or memory previously
freed before ownership was transferred.
