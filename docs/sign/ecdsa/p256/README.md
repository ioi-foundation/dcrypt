# ECDSA with NIST P-256 (`dcrypt_sign::ecdsa::p256`)

This module implements ECDSA using the P-256 curve (also called `secp256r1` or
`prime256v1`) and SHA-256. It uses RFC 6979-style deterministic nonce generation
hedged with entropy from the supplied CSPRNG.

This project has not claimed or received FIPS validation or certification for
this implementation. References to FIPS or RFC algorithms describe the intended
operation and interoperability target, not a compliance status or security
guarantee.

## Public types

`EcdsaP256` implements `dcrypt_api::Signature` with distinct public-key,
secret-key, and signature types. Public keys use the module's validated P-256
point encoding, secret scalars must be in the range `1..n`, and signatures are
stored as DER bytes.

Secret-key types request zeroization on drop. Applications are still responsible
for copies, persistent storage, crash dumps, swap, allocator behavior, and any
serialized export of key material.

## Signature encoding

An `EcdsaP256Signature` is an ASN.1 DER sequence containing `(r, s)`:

```text
SEQUENCE {
  r INTEGER,
  s INTEGER
}
```

Parsing applies all of the following rules:

* The sequence and INTEGER lengths must be exact, with no trailing data.
* Each INTEGER must be nonempty, positive, and minimally encoded. A leading
  `0x00` is allowed only when needed to prevent a positive value from appearing
  negative.
* `r` and `s` must satisfy `1 <= r,s < n`, where `n` is the P-256 group order.
* `s` must be low. Signing normalizes `s`, and verification rejects high-`s`
  signatures.

Affected releases accepted negative INTEGER encodings as unsigned values,
noncanonical DER, and high-`s` signatures. Those byte strings intentionally fail
under the strict decoder. This may break historical fixtures and protocols that
treated signature bytes as identifiers; audit and migrate such data rather than
relaxing verification.

## Operations

`keypair` rejection-samples until it obtains a private scalar in `1..n` and
derives the corresponding public point. `sign` hashes the message with SHA-256,
derives a hedged per-message nonce, computes `(r, s)`, normalizes `s` to its low
form, and emits strict DER. `verify` validates the public key and signature
encoding, checks the scalar ranges and low-`s` rule, and then evaluates the ECDSA
verification equation.

The message hash and verification x-coordinate are reduced as required instead
of treating values at or above the group order as exceptional failures.

## Deployment notes

Public-key authenticity, message/domain binding, key rotation, algorithm policy,
and replay handling belong to the surrounding protocol. Passing verification
means only that this signature operation accepted the supplied inputs; it is not
proof of signer identity without a trusted key association, nor evidence of FIPS
certification.
