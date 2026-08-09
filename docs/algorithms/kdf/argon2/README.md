# Argon2 Key Derivation and Password Hashing Function

## Overview

This module provides dcrypt's implementation of the Argon2 key-derivation and
password-hashing function specified in RFC 9106. Argon2 was the winner of the
[Password Hashing Competition](https://password-hashing.net/).

This implementation is designed with a focus on security and ergonomics:
*   **RFC 9106 interoperability:** Tested against the relevant specification vectors; this is not certification or formal validation.
*   **Owned memory hygiene:** Uses exact-size clearing wrappers for owned secret material and mask-based equal-length hash comparison. This does not prove whole-operation side-channel resistance or physical erasure.
*   **Flexible API:** Supports both high-level password hashing via the `PasswordHashFunction` trait and general-purpose key derivation through the `KeyDerivationFunction` trait.
*   **Type Safety:** Uses a strong type system for parameters (`Argon2Params`) and variants (`Argon2Type`) to ensure correct usage.

## Core Concepts

### Argon2 Variants

Argon2 comes in three main variants, each with different trade-offs. This implementation supports all three:

*   `Argon2id` (**Recommended Default**): A hybrid variant that uses data-independent memory access for the first half of the first pass and data-dependent access for the rest. It provides the best resistance against both side-channel attacks (like Argon2i) and GPU cracking attacks (like Argon2d). This is the recommended choice for most applications.
*   `Argon2i`: Uses data-independent memory access. This variant is optimized to resist side-channel timing attacks by preventing an attacker from inferring information about the secret input based on memory access patterns.
*   `Argon2d`: Uses data-dependent memory access. This variant provides the highest resistance to GPU-based cracking attacks but is more vulnerable to side-channel attacks.

### Parameters

Argon2's strength is highly configurable through three main parameters:

*   **Memory Cost (`m`)**: The amount of memory to use in KiB. This is the primary factor in resisting time-memory tradeoff (TMTO) attacks and making the algorithm difficult to parallelize on GPUs.
*   **Time Cost (`t`)**: The number of passes (iterations) over the memory. This increases the total runtime and provides a secondary work factor.
*   **Parallelism (`p`)**: The number of parallel lanes (threads). This allows the algorithm to leverage multi-core processors to increase computational cost without proportionally increasing the time for a legitimate user.

**OWASP Recommendations (as of 2023):**
A good starting point for interactive logins is:
*   `m`: 65536 (64 MiB)
*   `t`: 3
*   `p`: 4

These values should be benchmarked and adjusted based on your specific hardware and security requirements.

## Usage

The `Argon2` implementation can be used for two primary purposes: password hashing and general-purpose key derivation.

### 1. Password Hashing (Primary Use Case)

This is the most common use for Argon2. The `PasswordHashFunction` trait provides a simple and secure API.

#### Hashing a New Password

When a user creates a new password, you generate a random salt, hash the password with your chosen parameters, and store the resulting PHC (Password Hash Competition) string.

```rust
use dcrypt::algorithms::kdf::{Argon2, Argon2Params, Argon2Type, PasswordHashFunction};
use dcrypt::algorithms::types::{Salt, SecretBytes};
use dcrypt::internal::{CryptoRng, RngCore};

fn hash_password<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::algorithms::Result<()> {
// The application supplies a fresh cryptographic salt source.
let salt = Argon2::<16>::generate_salt(rng)?;
let params = Argon2Params {
    argon_type: Argon2Type::Argon2id,
    memory_cost: 65536, // 64 MB
    time_cost: 3,       // 3 iterations
    parallelism: 4,     // 4 threads
    salt,
    ..Default::default()
};

// 2. Create an Argon2 instance with your parameters.
let argon2 = Argon2::new_with_params(params);

// 3. Use a secure type for the user's password.
let password = SecretBytes::<32>::new(*b"a-very-secure-password!         ");

// 4. Hash the password.
let password_hash = argon2.hash_password(&password).unwrap();

// 5. Serialize the result to a PHC string for storage in your database.
// The string contains the algorithm, version, parameters, salt, and hash.
let hash_string = password_hash.to_string();
println!("Stored Password Hash: {}", hash_string);
Ok(())
}
```

#### Verifying a Password

When a user logs in, you retrieve their stored PHC string, parse it, and use the `verify` method to check their submitted password. The verification process automatically uses the parameters stored in the hash string.

```rust
use dcrypt::algorithms::kdf::{Argon2, PasswordHash, PasswordHashFunction};
use dcrypt::algorithms::types::SecretBytes;
use std::str::FromStr;

// This is the string you would retrieve from your database.
let stored_hash_string = "$argon2id$v=19$m=65536,t=3,p=4$YlJpblR1V2hFRGhzY2k2Rg$08dshrD8jI1K/I98An2sVpt34A045w0YwYx4AFjJgHI";

// 1. Parse the PHC string into a `PasswordHash` object.
let parsed_hash = PasswordHash::from_str(stored_hash_string).unwrap();

// 2. Create a default Argon2 instance for verification.
// The parameters from `parsed_hash` will be used automatically.
let argon2 = Argon2::<16>::new();

// 3. Verify the correct password. This is a constant-time comparison.
let correct_password = SecretBytes::<32>::new(*b"a-very-secure-password!         ");
assert!(argon2.verify(&correct_password, &parsed_hash).unwrap());

// 4. Verify an incorrect password.
let incorrect_password = SecretBytes::<32>::new(*b"incorrect-password...           ");
assert!(!argon2.verify(&incorrect_password, &parsed_hash).unwrap());
```

### 2. General-Purpose Key Derivation

Argon2 can also be used as a general, high-cost KDF. This is useful when you need to derive a key from a low-entropy source like a passphrase. The `KeyDerivationFunction` trait and its builder pattern are used for this.

```rust
use dcrypt::algorithms::kdf::{Argon2, KeyDerivationFunction, KdfOperation};

let kdf = Argon2::<16>::new(); // Create with default parameters

let derived_key: [u8; 64] = kdf.builder()
    .with_ikm(b"user passphrase")
    .with_salt(b"a-unique-salt-for-this-key")
    .with_info(b"AES-256 key for file encryption")
    .with_output_length(64)
    .derive_array() // Derives directly into a fixed-size array
    .unwrap();

assert_eq!(derived_key.len(), 64);
println!("Argon2 Derived Key: {}", hex::encode(derived_key));
```

## Parameter Tuning

The security of Argon2 is critically dependent on choosing the right parameters. The highest values that your system can tolerate for a legitimate user provide the best security.

This library provides tools to help you tune these parameters:

*   `benchmark()`: Measures the time it takes to hash a password with the current parameters on the local machine.
*   `recommended_params(target_duration)`: Suggests a new set of parameters (primarily by adjusting the iteration count `t`) to meet a target duration.

```rust
use std::time::Duration;
use dcrypt::algorithms::kdf::{Argon2, PasswordHashFunction};

// Target a 250ms delay for password hashing on your server.
let target_latency = Duration::from_millis(250);

// Get a recommended set of parameters.
let params = Argon2::<16>::recommended_params(target_latency);

println!("Recommended Parameters:");
println!("  Memory Cost (m): {}", params.memory_cost);
println!("  Time Cost (t):   {}", params.time_cost);
println!("  Parallelism (p): {}", params.parallelism);
```

## Security Considerations

*   **Salt**: Always use a cryptographically random salt that is unique for each password. The `generate_salt` method is provided for this purpose. Salts should be stored alongside the password hash.
*   **Secret Key (`secret`)**: The `secret` parameter can be used to provide a secret key (often called a "pepper") to the hashing process. This adds another layer of protection; if your database of hashes is stolen, the attacker still needs the pepper to crack them. The pepper must be kept separate from the database.
*   **Associated Data (`ad`)**: The `ad` parameter allows you to bind the hash to a specific context, such as a username or a key ID. This can prevent certain types of attacks where a hash from one context might be misused in another. This data is included in the hash calculation but is not part of the final output tag.

## Module API at a Glance

*   **`struct Argon2<const S: usize>`**: The main struct for Argon2 operations. Generic over the salt size `S`.
*   **`struct Params<const S: usize>`**: A struct to hold all configuration parameters for an Argon2 operation.
*   **`enum Algorithm`**: Represents the three Argon2 variants: `Argon2d`, `Argon2i`, and `Argon2id`.
