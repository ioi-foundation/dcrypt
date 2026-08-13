//! Removed `Result` compatibility extensions.
//!
//! The module path remains as an intentional v4 tombstone. Use the standard
//! [`core::result::Result`] combinators and the inherent enrichment methods on
//! [`super::Error`]. See `docs/migration/V4-ERROR-API.md` for exact replacements.
