# Key Derivation Functions (KDFs)

## Overview

This module provides implementations of various Key Derivation Functions (KDFs) and Password Hashing Functions. These primitives are essential for securely deriving cryptographic keys from secrets or hashing user passwords for storage.

The design of this module emphasizes:
*   **Security:** Implementations are designed to be constant-time where applicable (e.g., during hash verification) and use secure memory types to prevent accidental leakage of sensitive information.
*   **Type Safety:** Leveraging Rust's trait system, KDFs are generic over the underlying hash functions, allowing for compile-time guarantees of correctness.
*   **Ergonomics:** A fluent builder pattern is provided for a clear and less error-prone API.
*   **Compliance:** Algorithms are implemented according to their respective RFCs and standards.

### Core Concepts

The module is built around two primary traits:

1.  **`KeyDerivationFunction`**: A generic trait for algorithms that derive keys from some input material. This is suitable for cryptographic protocols where you need to turn a shared secret or other non-uniform data into a cryptographically strong symmetric key.
2.  **`PasswordHashFunction`**: A specialized trait for algorithms designed to hash passwords. These functions are intentionally slow and resource-intensive to frustrate brute-force attacks. They produce a `PasswordHash` object, which contains all the necessary information (algorithm, parameters, salt, and hash) to verify a password later.

## Available Algorithms

This module includes the following industry-standard KDFs:

*   **HKDF (HMAC-based Key Derivation Function)**: Defined in [RFC 5869](https://tools.ietf.org/html/rfc5869). Ideal for deriving one or more cryptographic keys from a shared secret. It is generic over any `HashFunction`.
*   **PBKDF2 (Password-Based Key Derivation Function 2)**: Defined in [RFC 8018](https://tools.ietf.org/html/rfc8018). A widely-used password hashing standard. It is generic over any HMAC-compatible `HashFunction`.
*   **Argon2**: The winner of the Password Hashing Competition. It is highly resistant to both GPU and side-channel attacks. This implementation supports all three variants:
    *   `Argon2id` (Recommended Default): A hybrid version that provides a good balance of resistance against both side-channel and GPU-based attacks.
    *   `Argon2d`: Maximizes resistance to GPU cracking attacks.
    *   `Argon2i`: Optimized to resist side-channel attacks.

## Usage

### General-Purpose Key Derivation with HKDF

HKDF is excellent for turning a shared secret (e.g., from an ECDH exchange) into a key suitable for symmetric encryption.

```rust
use dcrypt::algorithms::kdf::Hkdf;
use dcrypt::algorithms::hash::Sha256;
use dcrypt::algorithms::kdf::KeyDerivationFunction; // Import the trait

fn derive_encryption_key() {
    let ikm = b"input-keying-material"; // e.g., the result of a key exchange
    let salt = b"some-random-salt";
    let info = b"encryption-key-for-session-123";
    let output_length = 32; // 256-bit key

    // Create a new HKDF instance generic over SHA-256
    let hkdf = Hkdf::<Sha256>::new();

    // Derive the key
    let derived_key = hkdf.derive_key(ikm, Some(salt), Some(info), output_length).unwrap();

    assert_eq!(derived_key.len(), 32);
    println!("HKDF-SHA256 Derived Key: {}", hex::encode(&derived_key));
}
```

### Password Hashing with Argon2

Argon2 is the state-of-the-art for password hashing. The `PasswordHashFunction` trait provides a high-level API for hashing and verification.

#### Hashing a Password

```rust
use dcrypt::algorithms::kdf::{Argon2, Argon2Params, Argon2Type, PasswordHashFunction};
use dcrypt::algorithms::types::{Salt, SecretBytes};
use dcrypt::internal::{CryptoRng, RngCore};

fn hash_a_password<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::algorithms::Result<()> {
    // 1. Define Argon2 parameters. These should be tuned for your specific application.
    let salt = Argon2::<16>::generate_salt(rng)?;
    let params = Argon2Params {
        argon_type: Argon2Type::Argon2id,
        memory_cost: 65536, // 64 MB
        time_cost: 3,       // 3 iterations
        parallelism: 4,     // 4 threads
        salt: salt,
        ..Default::default()
    };

    // 2. Create an Argon2 instance with the parameters.
    let argon2 = Argon2::new_with_params(params);

    // 3. Create a secure password type.
    let password = SecretBytes::<32>::new(*b"a-very-secure-password!         ");

    // 4. Hash the password.
    let password_hash = argon2.hash_password(&password).unwrap();

    // 5. The result can be serialized to the PHC string format for storage.
    let hash_string = password_hash.to_string();
    println!("Stored Password Hash: {}", hash_string);
    Ok(())
}
```

#### Verifying a Password

To verify, you parse the stored PHC string back into a `PasswordHash` object and use the `verify` method.

```rust
use dcrypt::algorithms::kdf::{Argon2, PasswordHash, PasswordHashFunction};
use dcrypt::algorithms::types::SecretBytes;
use std::str::FromStr;

fn verify_a_password() {
    // A previously stored hash string from the example above.
    let stored_hash_string = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQAAAAAAAAAAAAAAA$E1kt2qTSHhA4p_J2_6jE6Q";

    // 1. Parse the string into a PasswordHash object.
    let parsed_hash = PasswordHash::from_str(stored_hash_string).unwrap();

    // 2. Create a new Argon2 instance (default parameters are fine for verification,
    // as the actual parameters are read from the parsed hash).
    let argon2 = Argon2::<16>::new();

    // 3. Check the correct password.
    let correct_password = SecretBytes::<32>::new(*b"a-very-secure-password!         ");
    assert!(argon2.verify(&correct_password, &parsed_hash).unwrap());

    // 4. Check an incorrect password.
    let incorrect_password = SecretBytes::<32>::new(*b"incorrect-password...           ");
    assert!(!argon2.verify(&incorrect_password, &parsed_hash).unwrap());
}
```

### Using the Builder Pattern

The `builder()` method provides a fluent API for more complex derivation scenarios, such as overriding parameters on-the-fly.

```rust
use dcrypt::algorithms::kdf::{Hkdf, KeyDerivationFunction, KdfOperation};
use dcrypt::algorithms::hash::Sha256;

fn use_builder_pattern() {
    let kdf = Hkdf::<Sha256>::new();

    let derived_key: [u8; 64] = kdf.builder()
        .with_ikm(b"input-keying-material")
        .with_salt(b"override-salt")
        .with_info(b"override-info")
        .with_output_length(64)
        .derive_array() // Derives directly into a fixed-size array
        .unwrap();

    assert_eq!(derived_key.len(), 64);
}
```

## Algorithm Details

### HKDF (`Hkdf<H: HashFunction>`)
*   **Purpose:** General-purpose key derivation.
*   **Parameters:**
    *   `salt`: A non-secret random value. Optional, but highly recommended.
    *   `info`: A context string to bind the derived key to a specific purpose.
*   **Strengths:** Fast, secure, and flexible. It's the standard choice for deriving keys from non-uniform sources.

### PBKDF2 (`Pbkdf2<H: HashFunction>`)
*   **Purpose:** Password hashing.
*   **Parameters:**
    *   `iterations`: The number of hashing rounds. This is the primary work factor. Should be as high as your application can tolerate. OWASP recommends at least 600,000 for HMAC-SHA256.
*   **Strengths:** Venerable and widely supported.
*   **Weaknesses:** Vulnerable to GPU-based cracking attacks compared to more modern algorithms.

### Argon2 (`Argon2`)
*   **Purpose:** State-of-the-art password hashing.
*   **Parameters:**
    *   `memory_cost` (`m`): The amount of memory to use in KiB. Increases resistance to TMTO attacks.
    *   `time_cost` (`t`): The number of passes over memory. Increases the overall runtime.
    *   `parallelism` (`p`): The number of threads (lanes) to use. Can be used to leverage multi-core CPUs.
*   **Strengths:** Highly resistant to GPU, FPGA, and ASIC attacks due to its memory-hard nature. Offers the best security for password hashing currently available.

## `no_std` Support

The KDF module is compatible with `no_std` environments, provided the `alloc` feature is enabled, as all implementations require dynamic memory allocation.

```toml
[dependencies.dcrypt-algorithms]
version = "..."
default-features = false
features = ["alloc", "kdf"]
```
