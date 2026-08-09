# PBKDF2 (Password-Based Key Derivation Function 2)

## Overview

This module provides a secure and flexible implementation of the Password-Based Key Derivation Function 2 (PBKDF2), as specified in [RFC 8018](https://tools.ietf.org/html/rfc8018).

PBKDF2 is a widely-used key derivation function that applies a pseudorandom function (PRF), such as HMAC, to an input password or passphrase along with a salt value. It repeats this process for a specified number of iterations to produce a derived key that is computationally expensive to brute-force.

This implementation is generic over any hash function that implements the `HashFunction` trait, allowing you to use it with different HMAC variants like `HMAC-SHA256` or `HMAC-SHA512`.

## Security Considerations

*   **Iteration Count is Critical:** The security of PBKDF2 relies heavily on the number of iterations. A higher iteration count makes the function slower and more resistant to brute-force attacks. **You must choose an iteration count that is as high as your application can tolerate.** OWASP recommends a minimum of **600,000** iterations for `HMAC-SHA256`.

*   **GPU/ASIC Resistance:** PBKDF2 is primarily CPU-bound and does not require large amounts of memory. As a result, it is more vulnerable to cracking on specialized hardware like GPUs and ASICs compared to modern memory-hard functions.

*   **Recommendation for New Applications:** For new applications, the use of **Argon2 is strongly recommended** over PBKDF2. Argon2 was designed to be memory-hard, providing significantly better resistance against modern cracking hardware. PBKDF2 is provided for legacy system compatibility and for environments where FIPS compliance is a strict requirement.

## Usage

### Direct Usage for Key Derivation

You can use PBKDF2 directly to derive a key from a password. This is useful in protocols where a key needs to be generated from a shared secret.

```rust
use dcrypt::algorithms::kdf::pbkdf2::Pbkdf2;
use dcrypt::algorithms::hash::Sha256;

fn derive_key_from_password() {
    let password = b"my-secret-password";
    let salt = b"a-unique-salt-per-user";
    let iterations = 600_000;
    let output_length = 32; // 256-bit key

    let derived_key = Pbkdf2::<Sha256>::pbkdf2_secure(
        password,
        salt,
        iterations,
        output_length
    ).unwrap();

    assert_eq!(derived_key.len(), 32);
    println!("PBKDF2-SHA256 Derived Key: {}", hex::encode(&derived_key));
}
```

### Password Hashing and Verification

The primary use case for PBKDF2 is password storage. This implementation integrates with the `PasswordHashFunction` trait to provide a high-level API for hashing and verifying passwords, including support for the PHC string format.

#### Hashing a Password

When hashing a new password, you should generate a random salt for each user and store it with the hash.

```rust
use dcrypt::algorithms::kdf::{Pbkdf2, Pbkdf2Params, PasswordHashFunction};
use dcrypt::algorithms::hash::Sha256;
use dcrypt::algorithms::types::{Salt, SecretBytes};
use dcrypt::internal::{CryptoRng, RngCore};

fn hash_user_password<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::algorithms::Result<()> {
    // 1. Define PBKDF2 parameters.
    let salt = Pbkdf2::<Sha256, 16>::generate_salt(rng)?;
    let params = Pbkdf2Params {
        iterations: 600_000,
        salt,
        key_length: 32,
    };

    // 2. Create a PBKDF2 instance with the parameters.
    let pbkdf2 = Pbkdf2::with_params(params);

    // 3. Create a secure password type.
    let password = SecretBytes::<32>::new(*b"user-password-123!              ");

    // 4. Hash the password.
    let password_hash = pbkdf2.hash_password(&password).unwrap();

    // 5. The result can be serialized to the PHC string format for storage.
    // Example format: $pbkdf2-sha256$i=600000$c29tZXNhbHQ$hash...
    let hash_string = password_hash.to_string();
    println!("Stored Password Hash: {}", hash_string);

    // In a real application, you would store this string in your database.
    Ok(())
}
```

#### Verifying a Password

To verify a password, parse the stored PHC string and use the `verify` method. The parameters (like salt and iteration count) are automatically extracted from the hash string.

```rust
use dcrypt::algorithms::kdf::{Pbkdf2, PasswordHash, PasswordHashFunction};
use dcrypt::algorithms::hash::Sha256;
use dcrypt::algorithms::types::SecretBytes;
use std::str::FromStr;

fn verify_user_password() {
    // A previously stored hash string from the hashing example.
    let stored_hash_string = "$pbkdf2-sha256$i=600000$c2FsdFNBTFRzYWx0U0FMVHNhbHQ$Rpq9...example...hash";

    // 1. Parse the string into a PasswordHash object.
    let parsed_hash = PasswordHash::from_str(stored_hash_string).unwrap();

    // 2. Create a new, default PBKDF2 instance for verification.
    let pbkdf2_verifier = Pbkdf2::<Sha256, 16>::new();

    // 3. Check the correct password.
    let correct_password = SecretBytes::<32>::new(*b"user-password-123!              ");
    assert!(pbkdf2_verifier.verify(&correct_password, &parsed_hash).unwrap());

    // 4. Check an incorrect password.
    let incorrect_password = SecretBytes::<32>::new(*b"wrong-password...               ");
    assert!(!pbkdf2_verifier.verify(&incorrect_password, &parsed_hash).unwrap());
}
```

## Parameter Tuning

The number of iterations is the most critical security parameter for PBKDF2. The `PasswordHashFunction` trait provides helpers to assist with tuning this value for your specific hardware and security requirements.

### Benchmarking

You can use the `benchmark()` method to measure how long it takes to compute a hash with the current parameters on the host system.

```rust
use dcrypt::algorithms::kdf::{Pbkdf2, PasswordHashFunction, Pbkdf2Params};
use dcrypt::algorithms::hash::Sha256;
use dcrypt::algorithms::types::Salt;

let params = Pbkdf2Params {
    iterations: 100_000, // A test value
    salt: Salt::<16>::zeroed(),
    ..Default::default()
};
let pbkdf2 = Pbkdf2::<Sha256, 16>::with_params(params);
let duration = pbkdf2.benchmark();
println!("Hashing with 100,000 iterations took: {:?}", duration);```

### Recommending Parameters

The `recommended_params()` method can automatically calculate an iteration count that aims to meet a target duration.

```rust
use dcrypt::algorithms::kdf::{Pbkdf2, PasswordHashFunction};
use dcrypt::algorithms::hash::Sha256;
use std::time::Duration;

// Target a hash duration of 250 milliseconds.
let target_duration = Duration::from_millis(250);
let recommended_params = Pbkdf2::<Sha256, 16>::recommended_params(target_duration);

println!("Recommended iteration count: {}", recommended_params.iterations);
```

## API Reference

*   **`struct Pbkdf2<H, S>`**: The main struct for PBKDF2 operations. It is generic over the `HashFunction` `H` (e.g., `Sha256`) and the salt size `S`.
*   **`struct Pbkdf2Params<S>`**: Holds the configuration for a PBKDF2 instance, including `iterations`, `salt`, and `key_length`.
*   **`trait KeyDerivationFunction`**: Provides the core `derive_key` and `builder` methods for general-purpose key derivation.
*   **`trait PasswordHashFunction`**: Provides the high-level `hash_password`, `verify`, and parameter tuning methods for password hashing.
*   **`struct Pbkdf2Builder`**: A fluent builder for configuring and executing a single key derivation operation, obtained via the `.builder()` method.

## `no_std` Support

This module is compatible with `no_std` environments if the `alloc` feature is enabled. The `PasswordHashFunction` trait, which relies on `BTreeMap` and `Instant`, requires the `std` feature.
