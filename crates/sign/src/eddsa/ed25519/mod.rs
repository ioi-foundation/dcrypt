//! Ed25519 signature scheme implementation
//!
//! This is a complete implementation of Ed25519 as specified in RFC 8032,
//! with full Curve25519 arithmetic operations included.

use super::constants::{ED25519_PUBLIC_KEY_SIZE, ED25519_SECRET_KEY_SIZE, ED25519_SIGNATURE_SIZE};
use dcrypt_algorithms::hash::sha2::Sha512;
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_api::{error::Error as ApiError, Result as ApiResult, Signature as SignatureTrait};
use dcrypt_internal::constant_time::ct_eq;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

// Import curve operations from the refactored modules
use super::operations;

/// Ed25519 signature scheme
///
/// # Security Considerations
///
/// - Always use a cryptographically secure RNG for key generation
/// - Protect secret keys using platform security features when available
/// - Verify public key authenticity through secure channels
/// - Never reuse seeds across different applications or purposes
/// - Clear sensitive data from memory after use (automatic for secret keys)
pub struct Ed25519;

/// Ed25519 public key (32 bytes)
///
/// # Security
///
/// This type contains public key material that can be shared freely.
/// However, you must ensure the key's authenticity through secure channels
/// to prevent man-in-the-middle attacks.
#[derive(Clone, Zeroize)]
pub struct Ed25519PublicKey(pub [u8; ED25519_PUBLIC_KEY_SIZE]);

// Implement Debug for Ed25519PublicKey without exposing key material
impl core::fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519PublicKey")
            .field("algorithm", &"Ed25519")
            .finish()
    }
}

/// Ed25519 secret key
///
/// # Security
///
/// This type contains secret key material that must be kept confidential:
/// - Store securely (encrypted at rest)
/// - Transmit securely (TLS/encrypted channels)  
/// - Clear from memory after use (automatic via Drop)
/// - Never log or display the key material
///
/// The internal representation includes both the seed and expanded key material.
/// Only the seed needs to be stored for persistence.
#[derive(Clone)]
pub struct Ed25519SecretKey {
    /// The original 32-byte seed
    seed: [u8; ED25519_SECRET_KEY_SIZE],
    /// The expanded key material (64 bytes from SHA-512)
    expanded: [u8; 64],
}

impl Zeroize for Ed25519SecretKey {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.expanded.zeroize();
    }
}

impl Drop for Ed25519SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Implement Debug without exposing key material
impl core::fmt::Debug for Ed25519SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519SecretKey")
            .field("algorithm", &"Ed25519")
            .finish()
    }
}

/// Ed25519 signature (64 bytes: R || s)
#[derive(Clone, Zeroize)]
pub struct Ed25519Signature(pub [u8; ED25519_SIGNATURE_SIZE]);

impl core::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519Signature")
            .field("length", &self.0.len())
            .finish()
    }
}

// Public key methods
impl Ed25519PublicKey {
    /// Create a public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ED25519_PUBLIC_KEY_SIZE {
            return Err(ApiError::InvalidKey {
                context: "Ed25519PublicKey::from_bytes",
                #[cfg(feature = "std")]
                message: format!(
                    "Invalid key size: expected {}, got {}",
                    ED25519_PUBLIC_KEY_SIZE,
                    bytes.len()
                ),
            });
        }
        let mut key = [0u8; ED25519_PUBLIC_KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Ed25519PublicKey(key))
    }

    /// Convert public key to bytes
    pub fn to_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_SIZE] {
        self.0
    }
}

// Secret key methods
impl Ed25519SecretKey {
    /// Create a secret key from a 32-byte seed
    ///
    /// This is useful when loading keys from storage. The seed is expanded
    /// using SHA-512 and the appropriate bits are clamped as per RFC 8032.
    ///
    /// # Security
    ///
    /// - Only use seeds from trusted sources
    /// - Ensure seeds were generated with a cryptographic RNG
    /// - Never use predictable or low-entropy seeds
    /// - Validate seed integrity if loading from storage
    ///
    /// # Example
    ///
    /// ```
    /// use dcrypt_sign::eddsa::{Ed25519, Ed25519SecretKey};
    /// use dcrypt_api::Signature;
    ///
    /// # fn main() -> dcrypt_api::Result<()> {
    /// // Load seed from storage (example uses fixed bytes)
    /// let seed = [42u8; 32];
    ///
    /// // Reconstruct secret key
    /// let secret = Ed25519SecretKey::from_seed(&seed)?;
    ///
    /// // Can now derive public key
    /// let public = secret.public_key()?;
    ///
    /// // Or use for signing
    /// let message = b"test";
    /// let signature = Ed25519::sign(message, &secret)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_seed(seed: &[u8; ED25519_SECRET_KEY_SIZE]) -> ApiResult<Self> {
        // Expand seed using SHA-512
        let mut hasher = Sha512::new();
        hasher.update(seed).map_err(ApiError::from)?;
        let hash = hasher.finalize().map_err(ApiError::from)?;

        let mut expanded = [0u8; 64];
        expanded.copy_from_slice(hash.as_ref());

        // Apply Ed25519 clamping to scalar (first 32 bytes)
        expanded[0] &= 248; // Clear bits 0, 1, 2
        expanded[31] &= 127; // Clear bit 255
        expanded[31] |= 64; // Set bit 254

        Ok(Ed25519SecretKey {
            seed: *seed,
            expanded,
        })
    }

    /// Get the 32-byte seed value
    ///
    /// This is the original random seed before expansion. This is what
    /// should be stored when saving keys to persistent storage.
    ///
    /// # Security  
    ///
    /// - Encrypt seeds before storing to disk
    /// - Use secure key derivation if password-protecting
    /// - Clear seed arrays from memory after use
    /// - Never log or transmit seeds over insecure channels
    pub fn seed(&self) -> &[u8; ED25519_SECRET_KEY_SIZE] {
        &self.seed
    }

    /// Export the seed as a Zeroizing vector for secure handling
    pub fn export_seed(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.seed.to_vec())
    }

    /// Get the public key corresponding to this secret key
    ///
    /// This derives the public key on-demand from the secret key material.
    /// The derivation is deterministic, so calling this multiple times
    /// will always return the same public key.
    ///
    /// # Example
    ///
    /// ```
    /// use dcrypt_sign::eddsa::Ed25519;
    /// use dcrypt_api::Signature;
    /// use rand::rngs::OsRng;
    ///
    /// # fn main() -> dcrypt_api::Result<()> {
    /// let mut rng = OsRng;
    /// let (_, secret) = Ed25519::keypair(&mut rng)?;
    ///
    /// // Get public key from secret key
    /// let public = secret.public_key()?;
    ///
    /// // Can use it for verification
    /// let message = b"test message";
    /// let signature = Ed25519::sign(message, &secret)?;
    /// assert!(Ed25519::verify(message, &signature, &public).is_ok());
    /// # Ok(())
    /// # }
    /// ```
    pub fn public_key(&self) -> ApiResult<Ed25519PublicKey> {
        Ed25519::derive_public_from_secret(self)
    }
}

// Signature methods
impl Ed25519Signature {
    /// Create a signature from bytes
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ED25519_SIGNATURE_SIZE {
            return Err(ApiError::InvalidSignature {
                context: "Ed25519Signature::from_bytes",
                #[cfg(feature = "std")]
                message: format!(
                    "Invalid signature size: expected {}, got {}",
                    ED25519_SIGNATURE_SIZE,
                    bytes.len()
                ),
            });
        }
        let mut sig = [0u8; ED25519_SIGNATURE_SIZE];
        sig.copy_from_slice(bytes);
        Ok(Ed25519Signature(sig))
    }

    /// Convert signature to bytes
    pub fn to_bytes(&self) -> [u8; ED25519_SIGNATURE_SIZE] {
        self.0
    }
}

impl SignatureTrait for Ed25519 {
    type PublicKey = Ed25519PublicKey;
    type SecretKey = Ed25519SecretKey;
    type SignatureData = Ed25519Signature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "Ed25519"
    }

    /// Generate an Ed25519 key pair
    ///
    /// This follows the key generation process from RFC 8032:
    /// 1. Generate a 32-byte random seed
    /// 2. Hash the seed with SHA-512 to get 64 bytes
    /// 3. Clear/set specific bits in the first 32 bytes (scalar clamping)
    /// 4. Use the clamped scalar to derive the public key
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        // Step 1: Generate random 32-byte seed
        let mut seed = [0u8; ED25519_SECRET_KEY_SIZE];
        rng.fill_bytes(&mut seed);

        // Step 2: Expand seed using SHA-512
        let mut hasher = Sha512::new();
        hasher.update(&seed).map_err(ApiError::from)?;
        let hash = hasher.finalize().map_err(ApiError::from)?;

        let mut expanded = [0u8; 64];
        expanded.copy_from_slice(hash.as_ref());

        // Step 3: Apply Ed25519 clamping to scalar (first 32 bytes)
        expanded[0] &= 248; // Clear bits 0, 1, 2
        expanded[31] &= 127; // Clear bit 255
        expanded[31] |= 64; // Set bit 254

        // Step 4: Derive public key A = \[scalar\]B
        let mut public_key = [0u8; ED25519_PUBLIC_KEY_SIZE];
        operations::derive_public_key(&expanded[0..32], &mut public_key).map_err(|e| {
            ApiError::InvalidParameter {
                context: "Ed25519 keypair generation",
                #[cfg(feature = "std")]
                message: format!("Failed to derive public key: {}", e),
            }
        })?;

        Ok((
            Ed25519PublicKey(public_key),
            Ed25519SecretKey { seed, expanded },
        ))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    /// Sign a message using Ed25519
    ///
    /// The signing process follows RFC 8032:
    /// 1. r = SHA-512(prefix || message) mod L
    /// 2. R = \[r\]B
    /// 3. k = SHA-512(R || A || message) mod L
    /// 4. s = (r + k*a) mod L
    /// 5. Return (R, s)
    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> ApiResult<Self::SignatureData> {
        // Extract scalar and prefix from expanded secret key
        let scalar = &secret_key.expanded[0..32];
        let prefix = &secret_key.expanded[32..64];

        // Step 1: Compute r = SHA-512(prefix || message) mod L
        let mut hasher = Sha512::new();
        hasher.update(prefix).map_err(ApiError::from)?;
        hasher.update(message).map_err(ApiError::from)?;
        let r_hash = hasher.finalize().map_err(ApiError::from)?;

        let mut r = [0u8; 32];
        operations::reduce_512_to_scalar(r_hash.as_ref(), &mut r);

        // Step 2: Compute R = \[r\]B
        let r_point = operations::scalar_mult_base(&r);

        // Step 3: Get public key A (we recompute it, but could cache)
        let mut public_key = [0u8; 32];
        operations::derive_public_key(scalar, &mut public_key).map_err(|e| {
            ApiError::InvalidParameter {
                context: "Ed25519 signing",
                #[cfg(feature = "std")]
                message: format!("Failed to derive public key: {}", e),
            }
        })?;

        // Step 4: Compute k = SHA-512(R || A || message) mod L
        let mut hasher = Sha512::new();
        hasher.update(&r_point).map_err(ApiError::from)?;
        hasher.update(&public_key).map_err(ApiError::from)?;
        hasher.update(message).map_err(ApiError::from)?;
        let k_hash = hasher.finalize().map_err(ApiError::from)?;

        let mut k = [0u8; 32];
        operations::reduce_512_to_scalar(k_hash.as_ref(), &mut k);

        // Step 5: Compute s = (r + k*a) mod L
        let mut s = [0u8; 32];
        operations::compute_s(&r, &k, scalar, &mut s);

        // Step 6: Construct signature (R || s)
        let mut signature = [0u8; ED25519_SIGNATURE_SIZE];
        signature[0..32].copy_from_slice(&r_point);
        signature[32..64].copy_from_slice(&s);

        Ok(Ed25519Signature(signature))
    }

    /// Verify an Ed25519 signature
    ///
    /// The verification process checks that:
    /// \[s\]B = R + \[k\]A
    /// where k = SHA-512(R || A || message) mod L
    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> ApiResult<()> {
        // Input validation
        if public_key.0.len() != ED25519_PUBLIC_KEY_SIZE {
            return Err(ApiError::InvalidKey {
                context: "Ed25519 verify",
                #[cfg(feature = "std")]
                message: "Invalid public key size".to_string(),
            });
        }

        if signature.0.len() != ED25519_SIGNATURE_SIZE {
            return Err(ApiError::InvalidSignature {
                context: "Ed25519 verify",
                #[cfg(feature = "std")]
                message: "Invalid signature size".to_string(),
            });
        }

        // Parse signature as (R, s)
        let r_bytes = &signature.0[0..32];
        let s_bytes = &signature.0[32..64];

        // Basic validation: s should not be all zeros
        if s_bytes.iter().all(|&b| b == 0) {
            return Err(ApiError::InvalidSignature {
                context: "Ed25519 verify",
                #[cfg(feature = "std")]
                message: "Invalid s value in signature (all zeros)".to_string(),
            });
        }

        // Compute k = SHA-512(R || A || message) mod L
        let mut hasher = Sha512::new();
        hasher.update(r_bytes).map_err(ApiError::from)?;
        hasher.update(&public_key.0).map_err(ApiError::from)?;
        hasher.update(message).map_err(ApiError::from)?;
        let k_hash = hasher.finalize().map_err(ApiError::from)?;

        let mut k = [0u8; 32];
        operations::reduce_512_to_scalar(k_hash.as_ref(), &mut k);

        // Verify the signature equation: \[s\]B = R + \[k\]A
        let mut check = [0u8; 32];
        operations::verify_equation(s_bytes, r_bytes, &k, &public_key.0, &mut check).map_err(
            |e| ApiError::InvalidSignature {
                context: "Ed25519 verify",
                #[cfg(feature = "std")]
                message: format!("Signature verification failed: {}", e),
            },
        )?;

        // Check result using constant-time comparison
        if !ct_eq(check, [1u8; 32]) {
            return Err(ApiError::InvalidSignature {
                context: "Ed25519 verify",
                #[cfg(feature = "std")]
                message: "Signature verification equation failed".to_string(),
            });
        }

        Ok(())
    }
}

impl Ed25519 {
    /// Derive the public key from an existing secret key
    ///
    /// This is useful when you have a secret key loaded from storage
    /// and need to reconstruct the corresponding public key.
    ///
    /// # Example
    ///
    /// ```
    /// use dcrypt_sign::eddsa::Ed25519;
    /// use dcrypt_api::Signature;
    /// use rand::rngs::OsRng;
    ///
    /// # fn main() -> dcrypt_api::Result<()> {
    /// let mut rng = OsRng;
    /// let (original_public, secret) = Ed25519::keypair(&mut rng)?;
    ///
    /// // Later, derive public key from secret
    /// let derived_public = Ed25519::derive_public_from_secret(&secret)?;
    ///
    /// assert_eq!(original_public.0, derived_public.0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn derive_public_from_secret(secret_key: &Ed25519SecretKey) -> ApiResult<Ed25519PublicKey> {
        // Extract the clamped scalar from the expanded key material
        let scalar = &secret_key.expanded[0..32];

        // Derive the public key A = [scalar]B
        let mut public_key_bytes = [0u8; ED25519_PUBLIC_KEY_SIZE];
        operations::derive_public_key(scalar, &mut public_key_bytes).map_err(|e| {
            ApiError::InvalidParameter {
                context: "Ed25519::derive_public_from_secret",
                #[cfg(feature = "std")]
                message: format!("Failed to derive public key: {}", e),
            }
        })?;

        Ok(Ed25519PublicKey(public_key_bytes))
    }
}

// Implement the optional serialization trait
#[cfg(feature = "serialization")]
use dcrypt_api::SignatureSerialize;

#[cfg(feature = "serialization")]
impl SignatureSerialize for Ed25519 {
    const PUBLIC_KEY_SIZE: usize = ED25519_PUBLIC_KEY_SIZE;
    const SECRET_KEY_SIZE: usize = ED25519_SECRET_KEY_SIZE;
    const SIGNATURE_SIZE: usize = ED25519_SIGNATURE_SIZE;

    fn serialize_public_key(key: &Self::PublicKey) -> Vec<u8> {
        key.0.to_vec()
    }

    fn deserialize_public_key(bytes: &[u8]) -> ApiResult<Self::PublicKey> {
        Ed25519PublicKey::from_bytes(bytes)
    }

    fn serialize_secret_key(key: &Self::SecretKey) -> Zeroizing<Vec<u8>> {
        key.export_seed()
    }

    fn deserialize_secret_key(bytes: &[u8]) -> ApiResult<Self::SecretKey> {
        if bytes.len() != ED25519_SECRET_KEY_SIZE {
            return Err(ApiError::InvalidKey {
                context: "Ed25519::deserialize_secret_key",
                #[cfg(feature = "std")]
                message: format!(
                    "Invalid seed size: expected {}, got {}",
                    ED25519_SECRET_KEY_SIZE,
                    bytes.len()
                ),
            });
        }
        let mut seed = [0u8; ED25519_SECRET_KEY_SIZE];
        seed.copy_from_slice(bytes);
        Ed25519SecretKey::from_seed(&seed)
    }

    fn serialize_signature(sig: &Self::SignatureData) -> Vec<u8> {
        sig.0.to_vec()
    }

    fn deserialize_signature(bytes: &[u8]) -> ApiResult<Self::SignatureData> {
        Ed25519Signature::from_bytes(bytes)
    }
}

// Implement the optional key derivation trait
#[cfg(feature = "key_derivation")]
use dcrypt_api::SignatureDerive;

#[cfg(feature = "key_derivation")]
impl SignatureDerive for Ed25519 {
    const MIN_SEED_SIZE: usize = ED25519_SECRET_KEY_SIZE;

    fn derive_keypair(seed: &[u8]) -> ApiResult<Self::KeyPair> {
        if seed.len() < Self::MIN_SEED_SIZE {
            return Err(ApiError::InvalidParameter {
                context: "Ed25519::derive_keypair",
                #[cfg(feature = "std")]
                message: format!(
                    "Seed too short: minimum {} bytes required",
                    Self::MIN_SEED_SIZE
                ),
            });
        }

        let mut seed_array = [0u8; ED25519_SECRET_KEY_SIZE];
        seed_array.copy_from_slice(&seed[..ED25519_SECRET_KEY_SIZE]);

        let secret = Ed25519SecretKey::from_seed(&seed_array)?;
        let public = secret.public_key()?;
        Ok((public, secret))
    }

    fn derive_public_key(secret_key: &Self::SecretKey) -> ApiResult<Self::PublicKey> {
        secret_key.public_key()
    }
}

#[cfg(test)]
mod tests;
