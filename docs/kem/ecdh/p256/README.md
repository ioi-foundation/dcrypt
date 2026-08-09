# ECDH-KEM with NIST P-256 (`secp256r1`)

This module provides a dcrypt-specific ECDH-plus-HKDF KEM adapter over NIST
P-256. It is not RFC 9180 HPKE; invalid inputs return errors, and no implicit
rejection or IND-CCA claim is made.

P-256 is one of the most widely used elliptic curves, offering approximately 128 bits of security. It is standardized by NIST in FIPS 186-4 and is commonly found in protocols like TLS. This implementation conforms to the `dcrypt::api::Kem` trait, ensuring a consistent and predictable API.

## Security Features

The `EcdhP256` implementation is built with a strong focus on cryptographic best practices and resilience against common vulnerabilities.

-   **Robust Key Derivation:** The final shared secret is derived using **HKDF-SHA256**. The KDF input includes the ECDH shared point's x-coordinate, the ephemeral public key, and the recipient's static public key. This construction binds the secret to the entire context of the exchange, protecting against unknown key-share attacks.

-   **Strongly-Typed Keys:** The module exposes distinct types for keys and ciphertexts (`EcdhP256PublicKey`, `EcdhP256SecretKey`, `EcdhP256Ciphertext`). This prevents the accidental mixing of keys from different algorithms or misuse of a key in the wrong context (e.g., using a secret key where a public key is expected).

-   **Owned-buffer zeroization:** `EcdhP256SecretKey` and `EcdhP256SharedSecret` wipe their owned storage on drop. Caller copies, registers, compiler temporaries, and allocator history are outside that guarantee.

-   **Serialization:** The secret-key wrapper implements `AsRef<[u8]>` for API compatibility and also offers explicit serialization/zeroizing export methods. Callers remain responsible for every copied byte string.

-   **Point Validation:** All external inputs representing curve points (public keys and ciphertexts) are rigorously validated. The implementation ensures that points are validly compressed, lie on the P-256 curve, and are not the point at infinity. This is a critical defense against invalid-curve attacks.

-   **Timing boundary:** Scalar code uses fixed-iteration and conditional-selection techniques in selected paths. A concrete constant-time claim still requires compiler/target-specific review and dynamic testing.

-   **Bandwidth Efficiency:** Public keys and ciphertexts are serialized using the compressed point format (33 bytes), minimizing data transmission size.

## API and Data Structures

| Type | Description | Size |
| :--- | :--- | :--- |
| **`EcdhP256`** | The main struct that implements the `dcrypt::api::Kem` trait for P-256. | - |
| **`EcdhP256PublicKey`** | The public key, representing a compressed point on the curve. | 33 bytes |
| **`EcdhP256SecretKey`** | The secret key, representing a 32-byte scalar. Automatically zeroized. | 32 bytes |
| **`EcdhP256Ciphertext`**| The ciphertext, an ephemeral public key in compressed format. | 33 bytes |
| **`EcdhP256SharedSecret`**| The final shared secret derived from HKDF-SHA256. Automatically zeroized. | 32 bytes |

## Usage Example

The following example demonstrates the complete key generation, encapsulation, and decapsulation flow using `EcdhP256`.

```rust
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::{EcdhP256, EcdhP256PublicKey, EcdhP256SecretKey, EcdhP256Ciphertext};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // == Recipient Side ==
    // 1. Generate a long-term P-256 key pair.
    let (recipient_pk, recipient_sk) = EcdhP256::keypair(&mut rng)?;

    // The public key can now be serialized and distributed.
    let pk_bytes = recipient_pk.to_bytes();
    assert_eq!(pk_bytes.len(), 33);


    // == Sender Side ==
    // 2. The sender obtains the recipient's public key and encapsulates a secret.
    // This creates a one-time ciphertext and a shared secret.
    let (ciphertext, shared_secret_sender) = EcdhP256::encapsulate(&mut rng, &recipient_pk)?;

    // The ciphertext is sent to the recipient.
    let ct_bytes = ciphertext.to_bytes();
    assert_eq!(ct_bytes.len(), 33);


    // == Recipient Side ==
    // 3. The recipient receives the ciphertext and uses their secret key to decapsulate it.
    let shared_secret_recipient = EcdhP256::decapsulate(&recipient_sk, &ciphertext)?;


    // == Verification ==
    // 4. Both parties now have the identical 32-byte shared secret.
    let sender_secret_bytes = shared_secret_sender.to_bytes_zeroizing();
    let recipient_secret_bytes = shared_secret_recipient.to_bytes_zeroizing();

    assert_eq!(*sender_secret_bytes, *recipient_secret_bytes);
    assert_eq!(sender_secret_bytes.len(), 32);

    println!("ECDH-P256 shared secret established successfully!");

    Ok(())
}
```

## Testing & Benchmarking

This module is supported by an extensive test suite located in `tests.rs`, which validates:
-   Correctness of the encapsulation/decapsulation roundtrip.
-   Handling of invalid and tampered public keys and ciphertexts.
-   Rejection of incorrect secret keys.
-   Serialization and deserialization integrity.
-   Proper zeroization of secret material.

To run the dedicated benchmarks for this module and assess its performance, execute:

```bash
cargo bench --bench ecdh_p256
```

## License

This crate is licensed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
