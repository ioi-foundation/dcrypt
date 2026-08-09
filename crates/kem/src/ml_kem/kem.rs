//! FIPS 203 ML-KEM key encapsulation and validated public types.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use dcrypt_algorithms::hash::sha3::{Sha3_256, Sha3_512};
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_algorithms::xof::shake::ShakeXof256;
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_api::traits::serialize::{Serialize, SerializeSecret};
use dcrypt_api::{Error, Kem, Result};
use dcrypt_internal::constant_time::{ConditionallySelectable, ConstantTimeEq};
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::params::{pke_secret_key_bytes, MlKemParameterSet, SYM_BYTES};
use super::pke;

fn invalid_key(context: &'static str) -> Error {
    Error::InvalidKey {
        context,
        #[cfg(feature = "std")]
        message: "non-canonical or incoherent FIPS 203 key encoding".into(),
    }
}

fn invalid_ciphertext_length<P: MlKemParameterSet>(actual: usize) -> Error {
    Error::InvalidLength {
        context: "ML-KEM ciphertext",
        expected: P::CIPHERTEXT_BYTES,
        actual,
    }
}

fn invalid_key_length(context: &'static str, expected: usize, actual: usize) -> Error {
    Error::InvalidLength {
        context,
        expected,
        actual,
    }
}

fn primitive_failure(context: &'static str) -> Error {
    Error::Other {
        context,
        #[cfg(feature = "std")]
        message: "owned SHA3/SHAKE primitive failed".into(),
    }
}

fn randomness_failure(context: &'static str) -> Error {
    Error::RandomGenerationError {
        context,
        #[cfg(feature = "std")]
        message: "caller-provided randomness source failed".into(),
    }
}

fn hash_h(data: &[u8]) -> Result<Zeroizing<[u8; SYM_BYTES]>> {
    let mut hash = Sha3_256::new();
    hash.update(data)
        .map_err(|_| primitive_failure("ML-KEM H"))?;
    let digest = Zeroizing::new(hash.finalize().map_err(|_| primitive_failure("ML-KEM H"))?);
    let mut output = Zeroizing::new([0u8; SYM_BYTES]);
    output.copy_from_slice(digest.as_ref());
    Ok(output)
}

fn hash_g(first: &[u8], second: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    let mut hash = Zeroizing::new(Sha3_512::new());
    hash.update(first)
        .map_err(|_| primitive_failure("ML-KEM G"))?;
    hash.update(second)
        .map_err(|_| primitive_failure("ML-KEM G"))?;
    let digest = Zeroizing::new(hash.finalize().map_err(|_| primitive_failure("ML-KEM G"))?);
    let mut output = Zeroizing::new([0u8; 64]);
    output.copy_from_slice(digest.as_ref());
    Ok(output)
}

fn hash_j(z: &[u8; SYM_BYTES], ciphertext: &[u8]) -> Result<Zeroizing<[u8; SYM_BYTES]>> {
    let mut xof = ShakeXof256::new();
    xof.update(z).map_err(|_| primitive_failure("ML-KEM J"))?;
    xof.update(ciphertext)
        .map_err(|_| primitive_failure("ML-KEM J"))?;
    let mut output = Zeroizing::new([0u8; SYM_BYTES]);
    xof.squeeze(output.as_mut())
        .map_err(|_| primitive_failure("ML-KEM J"))?;
    Ok(output)
}

/// A validated FIPS 203 ML-KEM encapsulation key.
pub struct MlKemEncapsulationKey<P: MlKemParameterSet> {
    bytes: Vec<u8>,
    parameter_set: PhantomData<P>,
}

impl<P: MlKemParameterSet> MlKemEncapsulationKey<P> {
    /// Parse and validate a canonical encapsulation key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P::ENCAPSULATION_KEY_BYTES {
            return Err(invalid_key_length(
                "ML-KEM encapsulation key",
                P::ENCAPSULATION_KEY_BYTES,
                bytes.len(),
            ));
        }
        if !pke::public_key_is_canonical::<P>(bytes) {
            return Err(invalid_key("ML-KEM encapsulation key"));
        }
        Ok(Self::from_validated_bytes(bytes.to_vec()))
    }

    pub(crate) fn from_validated_bytes(bytes: Vec<u8>) -> Self {
        debug_assert!(pke::public_key_is_canonical::<P>(&bytes));
        Self {
            bytes,
            parameter_set: PhantomData,
        }
    }

    /// Borrow the canonical encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the canonical encoding.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `false`; standard ML-KEM encapsulation keys are never empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Return a copy of the canonical encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl<P: MlKemParameterSet> Clone for MlKemEncapsulationKey<P> {
    fn clone(&self) -> Self {
        Self::from_validated_bytes(self.bytes.clone())
    }
}

impl<P: MlKemParameterSet> fmt::Debug for MlKemEncapsulationKey<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlKemEncapsulationKey")
            .field("parameter_set", &P::NAME)
            .field("length", &self.bytes.len())
            .finish()
    }
}

impl<P: MlKemParameterSet> Serialize for MlKemEncapsulationKey<P> {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

/// A validated FIPS 203 ML-KEM decapsulation key.
pub struct MlKemDecapsulationKey<P: MlKemParameterSet> {
    bytes: Zeroizing<Box<[u8]>>,
    parameter_set: PhantomData<P>,
}

impl<P: MlKemParameterSet> MlKemDecapsulationKey<P> {
    /// Parse a decapsulation key and perform FIPS 203 modulus and hash checks.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P::DECAPSULATION_KEY_BYTES {
            return Err(invalid_key_length(
                "ML-KEM decapsulation key",
                P::DECAPSULATION_KEY_BYTES,
                bytes.len(),
            ));
        }
        let pke_len = pke_secret_key_bytes::<P>();
        let public_end = pke_len + P::ENCAPSULATION_KEY_BYTES;
        if !pke::pke_secret_key_is_canonical::<P>(&bytes[..pke_len])
            || !pke::public_key_is_canonical::<P>(&bytes[pke_len..public_end])
        {
            return Err(invalid_key("ML-KEM decapsulation key"));
        }
        let expected_hash = hash_h(&bytes[pke_len..public_end])?;
        let stored_hash = &bytes[public_end..public_end + SYM_BYTES];
        if expected_hash.as_slice().ct_eq(stored_hash).unwrap_u8() != 1 {
            return Err(invalid_key("ML-KEM decapsulation key"));
        }
        Ok(Self::from_validated_bytes(Zeroizing::new(Box::from(bytes))))
    }

    pub(crate) fn from_validated_bytes(bytes: Zeroizing<Box<[u8]>>) -> Self {
        Self {
            bytes,
            parameter_set: PhantomData,
        }
    }

    /// Length of the canonical encoding.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `false`; standard ML-KEM decapsulation keys are never empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Serialize into an exact-size boxed buffer that clears itself on drop.
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<Box<[u8]>> {
        Zeroizing::new(Box::from(&self.bytes[..]))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..]
    }
}

impl<P: MlKemParameterSet> Clone for MlKemDecapsulationKey<P> {
    fn clone(&self) -> Self {
        Self::from_validated_bytes(Zeroizing::new(Box::from(&self.bytes[..])))
    }
}

impl<P: MlKemParameterSet> Zeroize for MlKemDecapsulationKey<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: MlKemParameterSet> ZeroizeOnDrop for MlKemDecapsulationKey<P> {}

impl<P: MlKemParameterSet> fmt::Debug for MlKemDecapsulationKey<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlKemDecapsulationKey")
            .field("parameter_set", &P::NAME)
            .field("length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl<P: MlKemParameterSet> SerializeSecret for MlKemDecapsulationKey<P> {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }

    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        // `SerializeSecret` currently fixes `Vec<u8>` as its return type. The
        // inherent method above is the v3 exact-size export; this conversion is
        // retained only for trait compatibility until that shared trait changes.
        Zeroizing::new(self.bytes.to_vec())
    }
}

/// A parameter-set-typed ML-KEM ciphertext.
pub struct MlKemCiphertext<P: MlKemParameterSet> {
    bytes: Vec<u8>,
    parameter_set: PhantomData<P>,
}

impl<P: MlKemParameterSet> MlKemCiphertext<P> {
    /// Parse an exactly-sized ciphertext. Every fixed-width compressed
    /// coefficient encoding is canonical; altered ciphertexts are handled by
    /// implicit rejection during decapsulation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P::CIPHERTEXT_BYTES {
            return Err(invalid_ciphertext_length::<P>(bytes.len()));
        }
        Ok(Self::from_validated_bytes(bytes.to_vec()))
    }

    pub(crate) fn from_validated_bytes(bytes: Vec<u8>) -> Self {
        debug_assert_eq!(bytes.len(), P::CIPHERTEXT_BYTES);
        Self {
            bytes,
            parameter_set: PhantomData,
        }
    }

    /// Borrow the canonical fixed-width encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the encoding.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `false`; standard ML-KEM ciphertexts are never empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Return a copy of the encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl<P: MlKemParameterSet> Clone for MlKemCiphertext<P> {
    fn clone(&self) -> Self {
        Self::from_validated_bytes(self.bytes.clone())
    }
}

impl<P: MlKemParameterSet> fmt::Debug for MlKemCiphertext<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlKemCiphertext")
            .field("parameter_set", &P::NAME)
            .field("length", &self.bytes.len())
            .finish()
    }
}

impl<P: MlKemParameterSet> Serialize for MlKemCiphertext<P> {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

/// A 256-bit ML-KEM shared secret.
pub struct MlKemSharedSecret(Zeroizing<[u8; SYM_BYTES]>);

impl MlKemSharedSecret {
    pub(crate) fn new(bytes: Zeroizing<[u8; SYM_BYTES]>) -> Self {
        Self(bytes)
    }

    /// Shared-secret length in bytes.
    pub const fn len(&self) -> usize {
        SYM_BYTES
    }

    /// Returns `false`; ML-KEM shared secrets are always 32 bytes.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Serialize into an exact-size boxed buffer that clears itself on drop.
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<Box<[u8]>> {
        Zeroizing::new(Box::from(&self.0[..]))
    }
}

impl Clone for MlKemSharedSecret {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }
}

impl Zeroize for MlKemSharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for MlKemSharedSecret {}

impl fmt::Debug for MlKemSharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlKemSharedSecret")
            .field("length", &SYM_BYTES)
            .finish_non_exhaustive()
    }
}

impl SerializeSecret for MlKemSharedSecret {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SYM_BYTES {
            return Err(Error::InvalidLength {
                context: "ML-KEM shared secret",
                expected: SYM_BYTES,
                actual: bytes.len(),
            });
        }
        let mut value = Zeroizing::new([0u8; SYM_BYTES]);
        value.copy_from_slice(bytes);
        Ok(Self(value))
    }

    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        // Kept only for compatibility with the workspace-wide trait's fixed
        // `Vec<u8>` return type. Prefer the inherent exact-size export.
        Zeroizing::new(self.0.to_vec())
    }
}

/// A coherent ML-KEM keypair. Its fields are intentionally private.
pub struct MlKemKeyPair<P: MlKemParameterSet> {
    encapsulation_key: MlKemEncapsulationKey<P>,
    decapsulation_key: MlKemDecapsulationKey<P>,
}

impl<P: MlKemParameterSet> Clone for MlKemKeyPair<P> {
    fn clone(&self) -> Self {
        Self {
            encapsulation_key: self.encapsulation_key.clone(),
            decapsulation_key: self.decapsulation_key.clone(),
        }
    }
}

impl<P: MlKemParameterSet> fmt::Debug for MlKemKeyPair<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlKemKeyPair")
            .field("parameter_set", &P::NAME)
            .finish_non_exhaustive()
    }
}

/// Generic FIPS 203 ML-KEM implementation; use one of the three standard aliases.
pub struct MlKem<P: MlKemParameterSet>(PhantomData<P>);

impl<P: MlKemParameterSet> MlKem<P> {
    /// FIPS 203 `ML-KEM.KeyGen_internal(d, z)` for deterministic validation and
    /// callers that explicitly own deterministic inputs.
    pub fn keypair_deterministic(
        d: &[u8; SYM_BYTES],
        z: &[u8; SYM_BYTES],
    ) -> Result<MlKemKeyPair<P>> {
        let (encapsulation_bytes, pke_secret) =
            pke::keygen::<P>(d).map_err(|_| primitive_failure("ML-KEM key generation"))?;
        let encapsulation_hash = hash_h(&encapsulation_bytes)?;
        let mut decapsulation_bytes =
            Zeroizing::new(vec![0u8; P::DECAPSULATION_KEY_BYTES].into_boxed_slice());
        let pke_len = pke_secret_key_bytes::<P>();
        let public_end = pke_len + P::ENCAPSULATION_KEY_BYTES;
        decapsulation_bytes[..pke_len].copy_from_slice(&pke_secret);
        decapsulation_bytes[pke_len..public_end].copy_from_slice(&encapsulation_bytes);
        decapsulation_bytes[public_end..public_end + SYM_BYTES]
            .copy_from_slice(encapsulation_hash.as_slice());
        decapsulation_bytes[public_end + SYM_BYTES..].copy_from_slice(z);

        Ok(MlKemKeyPair {
            encapsulation_key: MlKemEncapsulationKey::from_validated_bytes(encapsulation_bytes),
            decapsulation_key: MlKemDecapsulationKey::from_validated_bytes(decapsulation_bytes),
        })
    }

    /// FIPS 203 `ML-KEM.Encaps_internal(ek, m)` for deterministic validation
    /// and callers that explicitly own deterministic inputs.
    pub fn encapsulate_deterministic(
        public_key: &MlKemEncapsulationKey<P>,
        message: &[u8; SYM_BYTES],
    ) -> Result<(MlKemCiphertext<P>, MlKemSharedSecret)> {
        let public_hash = hash_h(public_key.as_bytes())?;
        let key_and_randomness = hash_g(message, public_hash.as_slice())?;
        let mut key = Zeroizing::new([0u8; SYM_BYTES]);
        key.copy_from_slice(&key_and_randomness[..SYM_BYTES]);
        let mut randomness = Zeroizing::new([0u8; SYM_BYTES]);
        randomness.copy_from_slice(&key_and_randomness[SYM_BYTES..]);
        let ciphertext = pke::encrypt::<P>(public_key.as_bytes(), message, &randomness)
            .map_err(|_| primitive_failure("ML-KEM encapsulation"))?;
        Ok((
            MlKemCiphertext::from_validated_bytes(ciphertext.to_vec()),
            MlKemSharedSecret::new(key),
        ))
    }
}

impl<P: MlKemParameterSet> Kem for MlKem<P> {
    type PublicKey = MlKemEncapsulationKey<P>;
    type SecretKey = MlKemDecapsulationKey<P>;
    type SharedSecret = MlKemSharedSecret;
    type Ciphertext = MlKemCiphertext<P>;
    type KeyPair = MlKemKeyPair<P>;

    fn name() -> &'static str {
        P::NAME
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self::KeyPair> {
        let mut seeds = Zeroizing::new([0u8; 2 * SYM_BYTES]);
        rng.try_fill_bytes(seeds.as_mut())
            .map_err(|_| randomness_failure("ML-KEM key generation"))?;
        let mut d = Zeroizing::new([0u8; SYM_BYTES]);
        let mut z = Zeroizing::new([0u8; SYM_BYTES]);
        d.copy_from_slice(&seeds[..SYM_BYTES]);
        z.copy_from_slice(&seeds[SYM_BYTES..]);
        Self::keypair_deterministic(&d, &z)
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.encapsulation_key.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.decapsulation_key.clone()
    }

    fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        let mut message = Zeroizing::new([0u8; SYM_BYTES]);
        rng.try_fill_bytes(message.as_mut())
            .map_err(|_| randomness_failure("ML-KEM encapsulation"))?;
        Self::encapsulate_deterministic(public_key, &message)
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret> {
        let secret_bytes = secret_key.as_bytes();
        let pke_len = pke_secret_key_bytes::<P>();
        let public_end = pke_len + P::ENCAPSULATION_KEY_BYTES;
        let pke_secret = &secret_bytes[..pke_len];
        let public_key = &secret_bytes[pke_len..public_end];
        let stored_public_hash = &secret_bytes[public_end..public_end + SYM_BYTES];
        let mut z = Zeroizing::new([0u8; SYM_BYTES]);
        z.copy_from_slice(&secret_bytes[public_end + SYM_BYTES..]);

        let message = pke::decrypt::<P>(pke_secret, ciphertext.as_bytes())
            .map_err(|_| primitive_failure("ML-KEM decapsulation"))?;
        let key_and_randomness = hash_g(message.as_slice(), stored_public_hash)?;
        let mut candidate_key = Zeroizing::new([0u8; SYM_BYTES]);
        candidate_key.copy_from_slice(&key_and_randomness[..SYM_BYTES]);
        let mut randomness = Zeroizing::new([0u8; SYM_BYTES]);
        randomness.copy_from_slice(&key_and_randomness[SYM_BYTES..]);
        let expected_ciphertext = pke::encrypt::<P>(public_key, &message, &randomness)
            .map_err(|_| primitive_failure("ML-KEM decapsulation"))?;
        let rejection_key = hash_j(&z, ciphertext.as_bytes())?;
        let mut valid = expected_ciphertext[..].ct_eq(ciphertext.as_bytes());
        let mut shared_secret = Zeroizing::new([0u8; SYM_BYTES]);
        for index in 0..SYM_BYTES {
            shared_secret[index] =
                u8::conditional_select(&rejection_key[index], &candidate_key[index], valid);
        }
        // FIPS 203 requires destruction of implicit-rejection intermediates.
        // All key/message/ciphertext candidates above are zeroizing owners;
        // explicitly erase the one-bit validity selector as well.
        valid.zeroize();
        Ok(MlKemSharedSecret::new(shared_secret))
    }
}
