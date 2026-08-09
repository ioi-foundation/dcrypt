//! Public Key Encryption (PKE) schemes for the dcrypt library.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

macro_rules! impl_zeroize_on_drop_tuple {
    ($type:ty) => {
        impl dcrypt_internal::zeroing::Zeroize for $type {
            fn zeroize(&mut self) {
                dcrypt_internal::zeroing::Zeroize::zeroize(&mut self.0);
            }
        }

        impl Drop for $type {
            fn drop(&mut self) {
                dcrypt_internal::zeroing::Zeroize::zeroize(self);
            }
        }

        impl dcrypt_internal::zeroing::ZeroizeOnDrop for $type {}
    };
}

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

// The published no_std profile requires an allocator, including when default
// features are disabled.
#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod ecies;
pub mod error;

// Re-export key items
pub use ecies::{EciesP224, EciesP256, EciesP384, EciesP521};
pub use error::{Error, Result};
