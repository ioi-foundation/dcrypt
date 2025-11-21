//! Public Key Encryption (PKE) schemes for the dcrypt library.
#![cfg_attr(not(feature = "std"), no_std)]

// Required for Vec, String, format! in no_std + alloc environments
// This makes the `alloc` crate available when the "alloc" feature of this crate ("pke") is enabled.
#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

pub mod ecies;
pub mod error;

// Re-export key items
pub use ecies::{EciesP192, EciesP224, EciesP256, EciesP384, EciesP521};
pub use error::{Error, Result};
