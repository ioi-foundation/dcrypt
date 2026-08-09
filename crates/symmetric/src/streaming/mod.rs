//! Streaming encryption APIs for large data
//!
//! This module provides streaming interfaces for encrypting and decrypting
//! large amounts of data in a memory-efficient way.

use crate::error::Result;
use std::io::{Read, Write};

mod framed;

/// Trait for streaming encryption
pub trait StreamingEncrypt<W: Write> {
    /// Writes plaintext data to the stream
    fn write(&mut self, data: &[u8]) -> Result<()>;

    /// Finalizes the stream, encrypting any remaining data
    fn finalize(self) -> Result<W>;
}

/// Trait for streaming decryption
pub trait StreamingDecrypt<R: Read> {
    /// Reads and decrypts data from the stream
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
}

// Re-export streaming implementations
pub mod chacha20poly1305;
pub mod gcm;
