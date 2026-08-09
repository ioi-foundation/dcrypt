//! ChaCha20-Poly1305 and XChaCha20-Poly1305 authenticated encryption.
//!
//! ```
//! use dcrypt_symmetric::{
//!     Aead, ChaCha20Poly1305Cipher, ChaCha20Poly1305Key, ChaCha20Rng, Result,
//!     SymmetricCipher,
//! };
//!
//! fn round_trip() -> Result<()> {
//!     let mut rng = ChaCha20Rng::from_seed([9; 32]);
//!     let key = ChaCha20Poly1305Key::generate(&mut rng)?;
//!     let nonce = ChaCha20Poly1305Cipher::generate_nonce(&mut rng)?;
//!     let cipher = ChaCha20Poly1305Cipher::new(&key)?;
//!     let ciphertext = cipher.encrypt(&nonce, b"secret message", None)?;
//!     assert_eq!(cipher.decrypt(&nonce, &ciphertext, None)?, b"secret message");
//!     Ok(())
//! }
//! # round_trip().unwrap();
//! ```

mod cipher;
mod common;

pub use cipher::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher, XChaCha20Poly1305Nonce};
pub use common::{
    derive_chacha20poly1305_key, generate_salt, ChaCha20Poly1305CiphertextPackage,
    ChaCha20Poly1305Key, ChaCha20Poly1305Nonce,
};

pub use crate::cipher::{Aead, SymmetricCipher};
