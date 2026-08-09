// File: crates/hybrid/src/lib.rs
//! # dcrypt-hybrid
//!
//! Hybrid cryptographic schemes for the dcrypt library.
//!
//! This crate provides implementations of hybrid cryptographic primitives by composing
//! classical and post-quantum schemes from other dcrypt crates. This is crucial for
//! achieving post-quantum security for data-in-transit via "Harvest-Then-Decrypt"
//! resistance.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(test)]
pub(crate) mod test_rng {
    use core::sync::atomic::{AtomicU64, Ordering};
    use dcrypt_internal::random::{ChaCha20Rng, CryptoRng, Error, RngCore};

    static NEXT_STREAM: AtomicU64 = AtomicU64::new(1);

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
}

pub mod kem;
pub mod sign;
