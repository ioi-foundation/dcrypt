# Historical construction and fixed-vector provenance

This file records why the migration code exists and where its compatibility
vector came from. It is evidence for a legacy format, not a new cryptographic
specification and not an endorsement of the withdrawn releases.

## Affected source range

Repository history first contains the custom construction at tag
`v0.5.0` (`4376927181745df5f1de49afa364bd46bacdb17e`). Its construction remains
semantically unchanged through tag `v1.2.3`
(`766a03feb860c8b05678754a3e81a00f687fe6c8`). The inspected tagged releases in
that interval are:

```text
v0.5.0
v0.6.0 v0.6.1 v0.6.2-pre v0.6.3-pre
v0.7.0-pre
v0.8.0-beta.1
v0.9.0-beta.1 v0.9.0-beta.2 v0.9.0-beta.3
v0.10.0-beta.1
v0.11.0-beta.1 v0.11.0-beta.2
v0.12.0-beta.1
v0.13.0-beta.1 v0.13.0-beta.2
v0.14.0-beta.7
v1.0.0
v1.1.0 v1.1.1
v1.2.0 v1.2.2 v1.2.3
```

The v0.5/v0.6 source used the former `dcrypt-primitives` layout, and the v0.7
and v0.8 tags predate the first `dcrypt-algorithms` crates.io artifact. The
published `dcrypt-algorithms` line starts at `0.9.0-beta.1`; every published
version before `2.0.0` contains the legacy construction. Treat untagged builds
derived from the full tagged source interval as affected too. The
construction derives a 32-byte subkey from bytes 0 through 31 of an ordinary
IETF ChaCha20 counter-zero stream using nonce bytes 0 through 11, then invokes
ChaCha20-Poly1305 using nonce bytes 12 through 23. v0.x serialized symmetric
keys used the uppercase `DCRYPT-` prefix; v1.x changed it to lowercase
`dcrypt-`. The migration CLI accepts both exact historical forms. This is not HChaCha20 and is
not standard XChaCha20-Poly1305. The v2 source replaced it with the standard
construction; the migration crate intentionally retains only decryption.

## Artifact identity

The fixed vector was regenerated with the exact crates.io archive
`dcrypt-algorithms-1.2.3.crate`. Its SHA-256, also recorded as the crates.io
index checksum, is:

```text
f5179e0e1e91c64ff843edd692db6931add07d84bfb1ff94688dbe6479dc178b
```

The following files extracted from that archive were byte-for-byte identical
to the corresponding files at the `v1.2.3` tag. Their SHA-256 digests are:

```text
276aee41daec47d7d0c2911f8a23417fd5bb12705d2cc6e8a86344431f9a59ec  src/aead/xchacha20poly1305/mod.rs
3a07d66769f61ac2093f022c9ea6ed23bb6e42ec7f32e0c1505a94ceb3f21298  src/aead/chacha20poly1305/mod.rs
1cd7c1e4aa1ccbb905c3dcbba476e88fee76504a34951736bb1ea0fa5f208b71  src/stream/chacha/chacha20/mod.rs
```

The old archive is not a dependency of this repository. It was used only in a
temporary isolated generator and differential review so a yanked implementation
cannot enter the current normal/build graph.

## Fixed vector

```text
key_hex = 4242424242424242424242424242424242424242424242424242424242424242
nonce_hex = 242424242424242424242424242424242424242424242424
aad = absent
plaintext_utf8 = Extended nonce allows for random nonces
ciphertext_and_tag_hex = 672c3b97cd4779f449bd39ba13bf4d213622067476b0cbfc0e053d1d9fb9c790e696fe066367d075374e3be5120e616b504ed6998fafa6
```

An exact-artifact generator reproduced those bytes. A separate review also
compared 2,880 key/nonce/plaintext/AAD combinations, including ChaCha block and
Poly1305 boundary lengths through 1,025 plaintext bytes, against the v1.2.3
artifact. The repository's excluded verification workspace reconstructs the
same operation with independent RustCrypto test primitives; the published and
migration dependency closures do not contain that oracle.
