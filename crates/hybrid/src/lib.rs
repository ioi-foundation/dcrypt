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


#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

pub mod kem;
pub mod sign;