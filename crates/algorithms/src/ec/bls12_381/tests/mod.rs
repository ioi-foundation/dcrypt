//! BLS12-381 test suite
//!
//! Tests are organized into focused modules for better maintainability.

#[cfg(test)]
mod field;

#[cfg(test)]
mod groups;

#[cfg(test)]
mod pairings;

#[cfg(test)]
mod serialization;

#[cfg(test)]
mod hash_to_curve;
