// File: crates/hybrid/src/kem/engine.rs

//! A generic engine for creating hybrid KEMs.

use super::traits::KemDimensions;
use alloc::vec::Vec;
use core::marker::PhantomData;
use dcrypt_algorithms::{hash::sha2::Sha256, kdf::hkdf::Hkdf};
use dcrypt_api::{
    error::Error as ApiError,
    error::Result as ApiResult,
    traits::serialize::{Serialize, SerializeSecret},
    ZeroizingBytes,
};
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::{
    boxed_bytes_zeroed, zeroizing_bytes_from_slice, Zeroize, ZeroizeOnDrop, Zeroizing,
};

const HYBRID_KEM_INFO_LABEL: &[u8] = b"dcrypt-hybrid-kem/v2";

/// A 256-bit shared secret produced by the hybrid combiner.
pub struct HybridSharedSecret(Zeroizing<[u8; 32]>);

impl HybridSharedSecret {
    fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    pub const fn len(&self) -> usize {
        32
    }

    pub const fn is_empty(&self) -> bool {
        false
    }

    pub fn to_bytes_zeroizing(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(&self.0[..])
    }
}

impl Clone for HybridSharedSecret {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }
}

impl Zeroize for HybridSharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for HybridSharedSecret {}

impl core::fmt::Debug for HybridSharedSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HybridSharedSecret")
            .field("length", &32)
            .finish_non_exhaustive()
    }
}

impl SerializeSecret for HybridSharedSecret {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != 32 {
            return Err(ApiError::InvalidLength {
                context: "hybrid shared secret",
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut value = Zeroizing::new([0u8; 32]);
        value.copy_from_slice(bytes);
        Ok(Self(value))
    }

    fn to_bytes_zeroizing(&self) -> ZeroizingBytes {
        self.to_bytes_zeroizing()
    }
}

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
        [
            self.classical_pk.to_bytes(),
            self.post_quantum_pk.to_bytes(),
        ]
        .concat()
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
    fn to_bytes_zeroizing(&self) -> ZeroizingBytes {
        let classical_bytes = self.classical_sk.to_bytes_zeroizing();
        let post_quantum_bytes = self.post_quantum_sk.to_bytes_zeroizing();
        let mut combined = Zeroizing::new(boxed_bytes_zeroed(
            classical_bytes.len() + post_quantum_bytes.len(),
        ));
        combined[..classical_bytes.len()].copy_from_slice(&classical_bytes);
        combined[classical_bytes.len()..].copy_from_slice(&post_quantum_bytes);
        combined
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
        [
            self.classical_ct.to_bytes(),
            self.post_quantum_ct.to_bytes(),
        ]
        .concat()
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
    fn derive_shared_secret_from_bytes(
        ciphertext: &HybridCiphertext<C, P>,
        classical_ss_bytes: &[u8],
        post_quantum_ss_bytes: &[u8],
    ) -> ApiResult<HybridSharedSecret> {
        let ciphertext_bytes = ciphertext.to_bytes();

        let mut ikm = Zeroizing::new(boxed_bytes_zeroed(
            4 + classical_ss_bytes.len() + 4 + post_quantum_ss_bytes.len(),
        ));
        let mut ikm_offset = 0;
        write_len_prefixed(&mut ikm, &mut ikm_offset, classical_ss_bytes);
        write_len_prefixed(&mut ikm, &mut ikm_offset, post_quantum_ss_bytes);

        let mut info = Vec::with_capacity(
            HYBRID_KEM_INFO_LABEL.len()
                + 4
                + C::SUITE_ID.len()
                + 4
                + P::SUITE_ID.len()
                + 4
                + ciphertext_bytes.len(),
        );
        info.extend_from_slice(HYBRID_KEM_INFO_LABEL);
        append_len_prefixed(&mut info, C::SUITE_ID);
        append_len_prefixed(&mut info, P::SUITE_ID);
        append_len_prefixed(&mut info, &ciphertext_bytes);

        let derived =
            Hkdf::<Sha256>::derive(None, &ikm, Some(&info), 32).map_err(|_| ApiError::Other {
                context: "HKDF",
                #[cfg(feature = "std")]
                message: "HKDF derivation failed".to_string(),
            })?;
        let mut shared_secret = Zeroizing::new([0u8; 32]);
        shared_secret.copy_from_slice(&derived);
        Ok(HybridSharedSecret::new(shared_secret))
    }

    fn derive_shared_secret(
        ciphertext: &HybridCiphertext<C, P>,
        classical_ss: &C::SharedSecret,
        post_quantum_ss: &P::SharedSecret,
    ) -> ApiResult<HybridSharedSecret> {
        let classical_bytes = classical_ss.to_bytes_zeroizing();
        let post_quantum_bytes = post_quantum_ss.to_bytes_zeroizing();
        Self::derive_shared_secret_from_bytes(ciphertext, &classical_bytes, &post_quantum_bytes)
    }

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
    ) -> ApiResult<(HybridCiphertext<C, P>, HybridSharedSecret)> {
        let (classical_ct, classical_ss) = C::encapsulate(rng, &public_key.classical_pk)?;
        let (post_quantum_ct, post_quantum_ss) = P::encapsulate(rng, &public_key.post_quantum_pk)?;

        let hybrid_ct = HybridCiphertext {
            classical_ct,
            post_quantum_ct,
        };

        let hybrid_ss = Self::derive_shared_secret(&hybrid_ct, &classical_ss, &post_quantum_ss)?;
        Ok((hybrid_ct, hybrid_ss))
    }

    pub fn decapsulate(
        secret_key: &HybridSecretKey<C, P>,
        ciphertext: &HybridCiphertext<C, P>,
    ) -> ApiResult<HybridSharedSecret> {
        let classical_result = C::decapsulate(&secret_key.classical_sk, &ciphertext.classical_ct);
        let post_quantum_result =
            P::decapsulate(&secret_key.post_quantum_sk, &ciphertext.post_quantum_ct);

        let mut decapsulation_error = None;

        let classical_ss_bytes = match classical_result {
            Ok(shared_secret) => shared_secret.to_bytes_zeroizing(),
            Err(err) => {
                decapsulation_error = Some(err);
                Zeroizing::new(boxed_bytes_zeroed(C::SHARED_SECRET_LEN))
            }
        };

        let post_quantum_ss_bytes = match post_quantum_result {
            Ok(shared_secret) => shared_secret.to_bytes_zeroizing(),
            Err(err) => {
                if decapsulation_error.is_none() {
                    decapsulation_error = Some(err);
                }
                Zeroizing::new(boxed_bytes_zeroed(P::SHARED_SECRET_LEN))
            }
        };

        let hybrid_secret = Self::derive_shared_secret_from_bytes(
            ciphertext,
            &classical_ss_bytes,
            &post_quantum_ss_bytes,
        )?;

        if let Some(err) = decapsulation_error {
            drop(hybrid_secret);
            return Err(err);
        }

        Ok(hybrid_secret)
    }
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn write_len_prefixed(out: &mut [u8], offset: &mut usize, bytes: &[u8]) {
    let length_end = *offset + 4;
    out[*offset..length_end].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
    let data_end = length_end + bytes.len();
    out[length_end..data_end].copy_from_slice(bytes);
    *offset = data_end;
}
