//! Adapters from test-only entropy sources to dcrypt's caller RNG traits.

use dcrypt_internal::random::{CryptoRng, Error, RngCore};
use rand::{RngCore as RandRngCore, SeedableRng};

/// Test-only operating-system entropy adapter.
pub struct OsRng;

impl RngCore for OsRng {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        rand::rngs::OsRng
            .try_fill_bytes(destination)
            .map_err(|_| Error)
    }
}

impl CryptoRng for OsRng {}

/// Test-only deterministic ChaCha20 adapter.
pub struct ChaCha20Rng(rand_chacha::ChaCha20Rng);

impl ChaCha20Rng {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(rand_chacha::ChaCha20Rng::from_seed(seed))
    }

    pub fn from_entropy() -> Self {
        Self(rand_chacha::ChaCha20Rng::from_entropy())
    }
}

impl RngCore for ChaCha20Rng {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(destination).map_err(|_| Error)
    }
}

impl CryptoRng for ChaCha20Rng {}
