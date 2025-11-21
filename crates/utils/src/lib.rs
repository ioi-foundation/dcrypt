// File: dcrypt/crates/utils/src/lib.rs

//! Utility functions for the dcrypt library
//!
//! This crate provides common utilities and helpers that are used by
//! other dcrypt crates but are not part of the public API.

#![cfg_attr(not(feature = "std"), no_std)]

// Ensure alloc is available if no_std and alloc feature is on
#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

pub mod data_conversion; // Added this line
