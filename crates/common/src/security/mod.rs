//! Security primitives and memory safety utilities
//!
//! This module provides foundational security types and patterns used throughout
//! the dcrypt ecosystem to ensure proper handling of sensitive cryptographic material.

pub mod memory;
pub mod secret;

// Re-export core security types
pub use secret::{EphemeralSecret, SecretBuffer, SecureZeroingType, ZeroizeGuard};

// Conditionally re-export SecretVec only when alloc feature is enabled
#[cfg(feature = "alloc")]
pub use secret::SecretVec;

// Re-export constant-time comparison utilities.
pub use memory::SecureCompare;

// Re-export memory barrier utilities
pub use memory::barrier;
