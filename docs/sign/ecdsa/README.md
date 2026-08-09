# ECDSA Signature Implementations (`sign::traditional::ecdsa`)

This module implements the **Elliptic Curve Digital Signature Algorithm
(ECDSA)** for several NIST prime curves. The implementation targets the ECDSA
algorithm and encodings described by relevant standards, but this project has
not claimed or received FIPS validation or certification. Documentation of an
algorithm or test-vector coverage is not a compliance certificate.

All schemes implement the `dcrypt_api::Signature` trait for a consistent and safe developer experience.

-----

## NIST curves supported

The module provides implementations for the following NIST-recommended curves, each paired with its standard hash function as per FIPS 186-5 recommendations.

| Struct Name | NIST Curve | Scalar Size | Hash Function | Status |
| :--- | :--- | :--- | :--- | :--- |
| **`EcdsaP224`** | `secp224r1` | 28 bytes | `SHA-224` | ✅ Implemented |
| **`EcdsaP256`** | `secp256r1` | 32 bytes | `SHA-256` | ✅ Implemented |
| **`EcdsaP384`** | `secp384r1` | 48 bytes | `SHA-384` | ✅ Implemented |
| **`EcdsaP521`** | `secp521r1` | 66 bytes | `SHA-512` | ✅ Implemented |

P-224 is retained for transition and interoperability at approximately
112-bit security. P-192 signing was removed for v3 because NIST SP 800-186
limits that curve to legacy use.

-----

## ✨ Features

  * **Nonce generation**: Uses RFC 6979-style deterministic nonce generation hedged with entropy from the supplied CSPRNG.
  * **Canonical signatures**: Emits low-`s` signatures and accepts only strict DER encodings with canonical scalar values.
  * **Verification comparison**: Uses constant-time equality for the final scalar comparison. This narrow property is not a blanket side-channel assurance for every compiler, target, or surrounding operation.
  * **Key handling**: Secret key types request zeroization on drop. Applications remain responsible for copies, storage, crash dumps, and platform-specific memory behavior.
  * **Type Safety**: Each curve (`P-256`, `P-384`, etc.) has distinct public key, secret key, and signature types. This prevents accidental misuse, such as trying to verify a `P-256` signature with a `P-384` key.

-----

## 🚀 Usage Example (P-256)

The API is consistent across all supported curves. Here is an example using `EcdsaP256`.

```rust
use dcrypt::sign::ecdsa::EcdsaP256;
use dcrypt::api::Signature;
use rand::rngs::OsRng;

fn main() -> dcrypt::api::Result<()> {
    // 1. Generate a new keypair using a cryptographically secure RNG.
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdsaP256::keypair(&mut rng)?;

    // 2. Define the message to be signed.
    let message = b"This message will be signed with ECDSA P-256.";

    // 3. Sign the message using the secret key.
    // The signature nonce 'k' is generated deterministically (RFC 6979)
    // with additional entropy for enhanced security.
    let signature = EcdsaP256::sign(message, &secret_key)?;
    println!("Signature generated successfully.");

    // 4. Verify the signature using the public key.
    let verification_result = EcdsaP256::verify(message, &signature, &public_key);
    assert!(verification_result.is_ok());
    println!("Signature is valid! ✅");

    // 5. Demonstrate that verification fails with a different message.
    let tampered_message = b"This is not the original message.";
    assert!(EcdsaP256::verify(tampered_message, &signature, &public_key).is_err());
    println!("Verification correctly failed for tampered message. ❌");

    Ok(())
}
```

-----

## Signature Format

Signatures are encoded as an ASN.1 DER `SEQUENCE` containing two `INTEGER`
values, `r` and `s`.

```
SEQUENCE {
  r INTEGER,
  s INTEGER
}
```

The decoder is intentionally strict:

* The outer `SEQUENCE` and both `INTEGER` objects must use exact DER lengths;
  trailing bytes are rejected.
* Each INTEGER must be nonempty, positive, and minimally encoded. A leading
  zero byte is permitted only when required to keep the value positive.
* Both scalars must satisfy `1 <= r,s < n`, where `n` is the selected curve's
  group order.
* `s` must be in the low half of the scalar range. Signing normalizes to low
  `s`, and verification rejects high-`s` inputs.

This is a compatibility break from affected releases, which accepted high-`s`,
negative-as-unsigned, and other noncanonical encodings. Callers must not expect
those historical byte strings to verify after upgrading. Re-encode or reissue
data through an explicitly reviewed migration process; never silently weaken
the new parser.

-----

## 🛡️ Security Considerations

  * **Secret Key Management**: Store and handle raw private-key material as sensitive data, including backups, process memory, and diagnostics.
  * **Public Key Authenticity**: When verifying a signature, you must have confidence that the public key belongs to the claimed entity. Use a secure method (like a PKI or a trusted channel) to obtain public keys.
  * **Signature identity**: Affected releases allowed multiple accepted byte encodings for one mathematical signature. Audit any protocol that used signature bytes as unique identifiers, receipts, cache keys, or consensus values.
  * **Algorithm policy**: Curve selection, lifetime, protocol binding, and deployment requirements must be decided by the consuming application's security policy. Availability in this module is not an endorsement or compliance claim.
