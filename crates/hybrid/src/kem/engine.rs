// File: crates/hybrid/src/kem/engine.rs

//! A generic engine for creating hybrid KEMs.

use super::traits::KemDimensions;
use dcrypt_algorithms::{hash::sha2::Sha256, kdf::hkdf::Hkdf};
use dcrypt_api::{
    error::Error as ApiError,
    error::Result as ApiResult,
    traits::serialize::{Serialize, SerializeSecret},
    Key as ApiKey,
};
use dcrypt_kem::kyber::KyberSharedSecret;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use core::marker::PhantomData;

// --- Generic Hybrid Data Structures ---

pub struct HybridPublicKey<C: KemDimensions, P: KemDimensions> {
    pub classical_pk: C::PublicKey,
    pub post_quantum_pk: P::PublicKey,
}

pub struct HybridSecretKey<C: KemDimensions, P: KemDimensions> {
    pub classical_sk: C::SecretKey,
    pub post_quantum_sk: P::SecretKey,
}

pub struct HybridCiphertext<C: KemDimensions, P: KemDimensions> {
    pub classical_ct: C::Ciphertext,
    pub post_quantum_ct: P::Ciphertext,
}

// --- Manual Trait Implementations for Hybrid Structs ---

// --- HybridPublicKey ---
impl<C: KemDimensions, P: KemDimensions> Clone for HybridPublicKey<C, P> {
    fn clone(&self) -> Self {
        Self {
            classical_pk: self.classical_pk.clone(),
            post_quantum_pk: self.post_quantum_pk.clone(),
        }
    }
}

impl<C: KemDimensions, P: KemDimensions> Serialize for HybridPublicKey<C, P> {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let total_len = C::PUBLIC_KEY_LEN + P::PUBLIC_KEY_LEN;
        if bytes.len() != total_len {
            return Err(ApiError::InvalidLength {
                context: "HybridPublicKey::from_bytes",
                expected: total_len,
                actual: bytes.len(),
            });
        }
        let (classical_bytes, post_quantum_bytes) = bytes.split_at(C::PUBLIC_KEY_LEN);
        Ok(Self {
            classical_pk: C::PublicKey::from_bytes(classical_bytes)?,
            post_quantum_pk: P::PublicKey::from_bytes(post_quantum_bytes)?,
        })
    }
    fn to_bytes(&self) -> Vec<u8> {
        [self.classical_pk.to_bytes(), self.post_quantum_pk.to_bytes()].concat()
    }
}

// --- HybridSecretKey ---
impl<C: KemDimensions, P: KemDimensions> Clone for HybridSecretKey<C, P> {
    fn clone(&self) -> Self {
        Self {
            classical_sk: self.classical_sk.clone(),
            post_quantum_sk: self.post_quantum_sk.clone(),
        }
    }
}

impl<C: KemDimensions, P: KemDimensions> Zeroize for HybridSecretKey<C, P> {
    fn zeroize(&mut self) {
        self.classical_sk.zeroize();
        self.post_quantum_sk.zeroize();
    }
}
impl<C: KemDimensions, P: KemDimensions> Drop for HybridSecretKey<C, P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl<C: KemDimensions, P: KemDimensions> ZeroizeOnDrop for HybridSecretKey<C, P> {}

impl<C: KemDimensions, P: KemDimensions> SerializeSecret for HybridSecretKey<C, P> {
    // FIX: Implement from_bytes to correctly deserialize a concatenated key.
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let total_len = C::SECRET_KEY_LEN + P::SECRET_KEY_LEN;
        if bytes.len() != total_len {
            return Err(ApiError::InvalidLength {
                context: "HybridSecretKey::from_bytes",
                expected: total_len,
                actual: bytes.len(),
            });
        }
        let (classical_bytes, post_quantum_bytes) = bytes.split_at(C::SECRET_KEY_LEN);
        Ok(Self {
            classical_sk: C::SecretKey::from_bytes(classical_bytes)?,
            post_quantum_sk: P::SecretKey::from_bytes(post_quantum_bytes)?,
        })
    }
    // FIX: Implement to_bytes_zeroizing to correctly serialize by concatenating the keys.
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        let classical_bytes = self.classical_sk.to_bytes_zeroizing();
        let post_quantum_bytes = self.post_quantum_sk.to_bytes_zeroizing();
        let mut combined = Vec::with_capacity(classical_bytes.len() + post_quantum_bytes.len());
        combined.extend_from_slice(&classical_bytes);
        combined.extend_from_slice(&post_quantum_bytes);
        Zeroizing::new(combined)
    }
}

// --- HybridCiphertext ---
impl<C: KemDimensions, P: KemDimensions> Clone for HybridCiphertext<C, P> {
    fn clone(&self) -> Self {
        Self {
            classical_ct: self.classical_ct.clone(),
            post_quantum_ct: self.post_quantum_ct.clone(),
        }
    }
}

impl<C: KemDimensions, P: KemDimensions> Serialize for HybridCiphertext<C, P> {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let total_len = C::CIPHERTEXT_LEN + P::CIPHERTEXT_LEN;
        if bytes.len() != total_len {
            return Err(ApiError::InvalidLength {
                context: "HybridCiphertext::from_bytes",
                expected: total_len,
                actual: bytes.len(),
            });
        }
        let (classical_bytes, post_quantum_bytes) = bytes.split_at(C::CIPHERTEXT_LEN);
        Ok(Self {
            classical_ct: C::Ciphertext::from_bytes(classical_bytes)?,
            post_quantum_ct: P::Ciphertext::from_bytes(post_quantum_bytes)?,
        })
    }
    fn to_bytes(&self) -> Vec<u8> {
        [self.classical_ct.to_bytes(), self.post_quantum_ct.to_bytes()].concat()
    }
}

// --- The Generic Engine ---

pub struct HybridKemEngine<C: KemDimensions, P: KemDimensions> {
    _classical: PhantomData<C>,
    _post_quantum: PhantomData<P>,
}

impl<C, P> HybridKemEngine<C, P>
where
    C: KemDimensions,
    P: KemDimensions,
{
    pub fn keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> ApiResult<(HybridPublicKey<C, P>, HybridSecretKey<C, P>)> {
        let classical_keypair = C::keypair(rng)?;
        let classical_pk = C::public_key(&classical_keypair);
        let classical_sk = C::secret_key(&classical_keypair);

        let post_quantum_keypair = P::keypair(rng)?;
        let post_quantum_pk = P::public_key(&post_quantum_keypair);
        let post_quantum_sk = P::secret_key(&post_quantum_keypair);

        Ok((
            HybridPublicKey {
                classical_pk,
                post_quantum_pk,
            },
            HybridSecretKey {
                classical_sk,
                post_quantum_sk,
            },
        ))
    }

    pub fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key: &HybridPublicKey<C, P>,
    ) -> ApiResult<(HybridCiphertext<C, P>, KyberSharedSecret)> {
        let (classical_ct, classical_ss) = C::encapsulate(rng, &public_key.classical_pk)?;
        let (post_quantum_ct, post_quantum_ss) =
            P::encapsulate(rng, &public_key.post_quantum_pk)?;

        let hybrid_ct = HybridCiphertext {
            classical_ct,
            post_quantum_ct,
        };

        let ikm = [
            classical_ss.to_bytes_zeroizing().to_vec(),
            post_quantum_ss.to_bytes_zeroizing().to_vec(),
        ]
        .concat();
        let okm = Hkdf::<Sha256>::derive(None, &ikm, Some(b"depin-hybrid-kem-v1"), 32).map_err(
            |_| ApiError::Other {
                context: "HKDF",
                #[cfg(feature = "std")]
                message: "HKDF derivation failed".to_string(),
            },
        )?;

        // Dereference Zeroizing<Vec<u8>> to get &[u8]
        Ok((hybrid_ct, KyberSharedSecret::new(ApiKey::new(&**okm))))
    }

    pub fn decapsulate(
        secret_key: &HybridSecretKey<C, P>,
        ciphertext: &HybridCiphertext<C, P>,
    ) -> ApiResult<KyberSharedSecret> {
        let classical_ss = C::decapsulate(&secret_key.classical_sk, &ciphertext.classical_ct)?;
        let post_quantum_ss =
            P::decapsulate(&secret_key.post_quantum_sk, &ciphertext.post_quantum_ct)?;

        let ikm = [
            classical_ss.to_bytes_zeroizing().to_vec(),
            post_quantum_ss.to_bytes_zeroizing().to_vec(),
        ]
        .concat();
        let okm = Hkdf::<Sha256>::derive(None, &ikm, Some(b"depin-hybrid-kem-v1"), 32).map_err(
            |_| ApiError::Other {
                context: "HKDF",
                #[cfg(feature = "std")]
                message: "HKDF derivation failed".to_string(),
            },
        )?;

        // Dereference Zeroizing<Vec<u8>> to get &[u8]
        Ok(KyberSharedSecret::new(ApiKey::new(&**okm)))
    }
}