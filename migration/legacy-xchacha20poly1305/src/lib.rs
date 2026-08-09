//! Decrypt-only migration support for the nonstandard construction shipped by
//! dcrypt from tagged source `v0.5.0` through `v1.2.3` under the
//! `XChaCha20Poly1305` name.
//!
//! This crate is deliberately outside the published dcrypt workspace and must
//! never be used for new encryption. Its sole purpose is authenticated,
//! provenance-aware migration of ciphertext known to have been produced by
//! the historical implementation.

#![forbid(unsafe_code)]

use dcrypt_algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt_algorithms::stream::chacha::chacha20::ChaCha20;
use dcrypt_algorithms::types::Nonce;
use dcrypt_internal::zeroing::{Zeroize, Zeroizing};
use std::fmt;

/// Exact format acknowledgement required by the command-line tool before decryption.
pub const REQUIRED_FORMAT_ACKNOWLEDGEMENT: &str =
    "dcrypt-v0.5.0-through-v1.2.3-custom-xchacha20poly1305";

/// Opaque authentication failure for the historical construction.
///
/// Deliberately does not expose the current primitive implementation or its
/// error variants across this isolated migration boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationError;

impl fmt::Display for AuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("legacy ciphertext authentication failed")
    }
}

impl std::error::Error for AuthenticationError {}

/// Authenticate and decrypt ciphertext from the nonstandard
/// `XChaCha20Poly1305` construction shipped in tagged source from `v0.5.0` through
/// `v1.2.3`.
///
/// The caller must establish ciphertext provenance before calling this
/// function. Ciphertext from standard XChaCha20-Poly1305 is intentionally
/// incompatible and will fail authentication. The returned exact-size box is
/// cleared on drop.
pub fn decrypt_legacy(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Zeroizing<Box<[u8]>>, AuthenticationError> {
    let mut nonce_prefix = [0u8; 12];
    nonce_prefix.copy_from_slice(&nonce[..12]);
    let nonce_prefix = Nonce::<12>::new(nonce_prefix);

    // The historical implementation derived its "subkey" from the first 32
    // bytes of an ordinary IETF ChaCha20 counter-0 block. This is not HChaCha20.
    let mut subkey = Zeroizing::new([0u8; 32]);
    let mut chacha = ChaCha20::new(key, &nonce_prefix);
    chacha
        .keystream(subkey.as_mut())
        .map_err(|_| AuthenticationError)?;

    let mut final_nonce = [0u8; 12];
    final_nonce.copy_from_slice(&nonce[12..]);
    let cipher = ChaCha20Poly1305::new(&subkey);
    let mut plaintext = cipher
        .decrypt_with_nonce(&final_nonce, ciphertext, aad)
        .map_err(|_| AuthenticationError)?;
    let exact = Zeroizing::new(Box::from(plaintext.as_slice()));
    plaintext.zeroize();
    Ok(exact)
}

#[cfg(test)]
mod tests {
    use super::decrypt_legacy;
    use dcrypt_algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
    use dcrypt_algorithms::aead::xchacha20poly1305::XChaCha20Poly1305;
    use dcrypt_algorithms::stream::chacha::chacha20::ChaCha20;
    use dcrypt_algorithms::types::Nonce;
    use dcrypt_internal::zeroing::Zeroizing;

    const KEY: [u8; 32] = [0x42; 32];
    const NONCE: [u8; 24] = [0x24; 24];
    // Generated with the exact crates.io dcrypt-algorithms 1.2.3 artifact
    // identified in ../PROVENANCE.md, not with the implementation under test.
    const CIPHERTEXT: [u8; 55] = [
        0x67, 0x2c, 0x3b, 0x97, 0xcd, 0x47, 0x79, 0xf4, 0x49, 0xbd, 0x39, 0xba, 0x13, 0xbf, 0x4d,
        0x21, 0x36, 0x22, 0x06, 0x74, 0x76, 0xb0, 0xcb, 0xfc, 0x0e, 0x05, 0x3d, 0x1d, 0x9f, 0xb9,
        0xc7, 0x90, 0xe6, 0x96, 0xfe, 0x06, 0x63, 0x67, 0xd0, 0x75, 0x37, 0x4e, 0x3b, 0xe5, 0x12,
        0x0e, 0x61, 0x6b, 0x50, 0x4e, 0xd6, 0x99, 0x8f, 0xaf, 0xa6,
    ];

    fn encrypt_historical_reference(plaintext: &[u8]) -> Vec<u8> {
        let prefix = Nonce::<12>::new(NONCE[..12].try_into().unwrap());
        let mut subkey = Zeroizing::new([0u8; 32]);
        ChaCha20::new(&KEY, &prefix)
            .keystream(subkey.as_mut())
            .unwrap();
        ChaCha20Poly1305::new(&subkey)
            .encrypt_with_nonce(&NONCE[12..].try_into().unwrap(), plaintext, None)
            .unwrap()
    }

    #[test]
    fn decrypts_fixed_historical_construction_vector() {
        assert_eq!(
            encrypt_historical_reference(b"Extended nonce allows for random nonces"),
            CIPHERTEXT
        );
        let plaintext = decrypt_legacy(&KEY, &NONCE, &CIPHERTEXT, None).unwrap();
        assert_eq!(&plaintext[..], b"Extended nonce allows for random nonces");
    }

    #[test]
    fn rejects_tampering_and_standard_xchacha_ciphertext() {
        let mut tampered = CIPHERTEXT;
        tampered[0] ^= 1;
        assert!(decrypt_legacy(&KEY, &NONCE, &tampered, None).is_err());

        let standard = XChaCha20Poly1305::new(&KEY)
            .encrypt(&Nonce::<24>::new(NONCE), b"not legacy", None)
            .unwrap();
        assert!(decrypt_legacy(&KEY, &NONCE, &standard, None).is_err());
    }
}
