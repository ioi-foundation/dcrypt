//! Authenticated encryption with associated data.

pub mod chacha20poly1305;
pub mod gcm;

pub use chacha20poly1305::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher};
pub use gcm::{Aes128Gcm, Aes256Gcm};
