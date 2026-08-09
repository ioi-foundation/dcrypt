//! Common parameter structures and traits for key derivation functions

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

// Conditional imports based on available features
#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::collections::BTreeMap;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::String;
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use core::fmt;
use core::str::FromStr;
use dcrypt_internal::zeroing::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

/// Trait for algorithms with configurable parameters
pub trait ParamProvider {
    /// The parameter type associated with this algorithm
    type Params: Clone;

    /// Creates a new instance with the specified parameters
    fn with_params(params: Self::Params) -> Self;

    /// Returns the current parameters
    fn params(&self) -> &Self::Params;

    /// Updates the parameters
    fn set_params(&mut self, params: Self::Params);
}

/// A complete password hash with algorithm, parameters, salt, and hash
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash {
    /// The algorithm identifier
    pub algorithm: String,

    /// Algorithm-specific parameters
    pub params: BTreeMap<String, String>,

    /// The salt used for hashing
    pub salt: Zeroizing<Vec<u8>>,

    /// The password hash
    pub hash: Zeroizing<Vec<u8>>,
}

// Manual implementation of Zeroize for PasswordHash
impl Zeroize for PasswordHash {
    fn zeroize(&mut self) {
        self.algorithm.zeroize();
        for (mut key, mut value) in core::mem::take(&mut self.params) {
            key.zeroize();
            value.zeroize();
        }
        self.salt.zeroize();
        self.hash.zeroize();
    }
}

impl PasswordHash {
    /// Creates a new password hash
    pub fn new(
        algorithm: String,
        params: BTreeMap<String, String>,
        salt: Vec<u8>,
        hash: Vec<u8>,
    ) -> Self {
        Self {
            algorithm,
            params,
            salt: Zeroizing::new(salt),
            hash: Zeroizing::new(hash),
        }
    }

    /// Extracts a parameter value by key
    pub fn param(&self, key: &str) -> Option<&String> {
        self.params.get(key)
    }

    /// Parses a parameter as an integer
    pub fn param_as_u32(&self, key: &str) -> Result<u32> {
        match self.param(key) {
            Some(value) => value.parse::<u32>().map_err(|_| {
                Error::param(
                    key.to_string(), // Convert to owned String for dynamic lifetime
                    "Invalid parameter value - not a valid u32",
                )
            }),
            None => Err(Error::param(
                key.to_string(), // Convert to owned String for dynamic lifetime
                "Missing required parameter",
            )),
        }
    }
}

// String encoding for PasswordHash in PHC format
// $algorithm$param=value,param=value$salt$hash
impl fmt::Display for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${}", self.algorithm)?;

        if !self.params.is_empty() {
            write!(f, "$")?;
            let mut first = true;
            for (key, value) in &self.params {
                if !first {
                    write!(f, ",")?;
                }
                write!(f, "{}={}", key, value)?;
                first = false;
            }
        }

        // Encode salt and hash in base64
        let salt_b64 = STANDARD_NO_PAD.encode(self.salt.as_slice());
        let hash_b64 = STANDARD_NO_PAD.encode(self.hash.as_slice());

        write!(f, "${}${}", salt_b64, hash_b64)
    }
}

impl FromStr for PasswordHash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if !s.starts_with('$') {
            return Err(Error::param(
                "password_hash",
                "Invalid password hash format - must start with '$'",
            ));
        }

        let parts: Vec<&str> = s.split('$').skip(1).collect();
        if parts.len() < 3 {
            return Err(Error::param(
                "password_hash",
                "Invalid password hash format - insufficient components",
            ));
        }

        let algorithm = parts[0].to_string();

        // Parse parameters if present
        let mut params = BTreeMap::new();
        if parts.len() > 3 {
            for param_str in parts[1].split(',') {
                if param_str.is_empty() {
                    continue;
                }

                let param_parts: Vec<&str> = param_str.split('=').collect();
                if param_parts.len() != 2 {
                    return Err(Error::param(
                        "param",
                        "Invalid parameter format - must be key=value",
                    ));
                }

                params.insert(param_parts[0].to_string(), param_parts[1].to_string());
            }
        }

        // Parse salt and hash
        let salt_idx = if parts.len() > 3 { 2 } else { 1 };
        let hash_idx = if parts.len() > 3 { 3 } else { 2 };

        let salt = STANDARD_NO_PAD
            .decode(parts[salt_idx])
            .map_err(|_| Error::param("salt", "Invalid salt encoding - not valid base64"))?;

        let hash = STANDARD_NO_PAD
            .decode(parts[hash_idx])
            .map_err(|_| Error::param("hash", "Invalid hash encoding - not valid base64"))?;

        Ok(PasswordHash {
            algorithm,
            params,
            salt: Zeroizing::new(salt),
            hash: Zeroizing::new(hash),
        })
    }
}
