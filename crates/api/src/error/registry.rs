//! Removed process-global deferred-error compatibility surface.
//!
//! The module path remains as an intentional v4 tombstone so API inventories
//! can distinguish the removed values from unrelated module metadata. Return
//! errors to the caller as [`super::Result`] and keep any diagnostics in
//! caller-owned state.
