use core::sync::atomic::{AtomicU64, Ordering};
use dcrypt_internal::random::{ChaCha20Rng, CryptoRng, Error, RngCore};

static NEXT_STREAM: AtomicU64 = AtomicU64::new(1);

/// Deterministic benchmark-only caller RNG.
pub struct TestRng;

impl RngCore for TestRng {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        let stream = NEXT_STREAM.fetch_add(1, Ordering::Relaxed);
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&stream.to_le_bytes());
        ChaCha20Rng::from_seed(seed).try_fill_bytes(destination)
    }
}

impl CryptoRng for TestRng {}
