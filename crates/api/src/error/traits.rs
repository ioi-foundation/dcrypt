//! Error handling traits for the cryptographic ecosystem

use super::registry::ERROR_REGISTRY;
use super::types::{Error, Result};
use subtle::ConditionallySelectable;

/// Extension trait for Result types
pub trait ResultExt<T, E>: Sized {
    /// Wrap an error with additional context
    fn wrap_err<F, E2>(self, f: F) -> core::result::Result<T, E2>
    where
        F: FnOnce() -> E2;

    /// Add context to an error when converting to Error
    fn with_context(self, context: &'static str) -> Result<T>
    where
        E: Into<Error>;

    #[cfg(feature = "std")]
    /// Add message to an error when converting to Error
    fn with_message(self, message: impl Into<String>) -> Result<T>
    where
        E: Into<Error>;
}

impl<T, E> ResultExt<T, E> for core::result::Result<T, E> {
    fn wrap_err<F, E2>(self, f: F) -> core::result::Result<T, E2>
    where
        F: FnOnce() -> E2,
    {
        self.map_err(|_| f())
    }

    fn with_context(self, context: &'static str) -> Result<T>
    where
        E: Into<Error>,
    {
        self.map_err(|e| {
            let err = e.into();
            err.with_context(context)
        })
    }

    #[cfg(feature = "std")]
    fn with_message(self, message: impl Into<String>) -> Result<T>
    where
        E: Into<Error>,
    {
        self.map_err(|e| {
            let err = e.into();
            err.with_message(message)
        })
    }
}

/// Result extension for recording an error before returning a fallback value.
///
/// This operation uses ordinary branching on the `Result` discriminant. It is
/// intended for diagnostics and must not be used when the success/failure state
/// itself is secret.
pub trait ErrorRegistryExt<T, E>: Sized {
    /// Return the successful value, or record `on_error()` and return `default`.
    fn unwrap_or_record_with<F>(self, default: T, on_error: F) -> T
    where
        F: FnOnce() -> E,
        E: Send + 'static;
}

impl<T, E> ErrorRegistryExt<T, E> for core::result::Result<T, E> {
    fn unwrap_or_record_with<F>(self, default: T, on_error: F) -> T
    where
        F: FnOnce() -> E,
        E: Send + 'static,
    {
        match self {
            Ok(value) => value,
            Err(_) => {
                ERROR_REGISTRY.store(on_error());
                default
            }
        }
    }
}

/// Legacy name for [`ErrorRegistryExt`].
///
/// Despite its historical name, this trait has never provided constant-time
/// execution: it branches on `Result`, invokes only the selected path, and
/// records an error only on failure.
pub trait SecureErrorHandling<T, E>: Sized {
    /// Return the successful value, or record `on_error()` and return `default`.
    ///
    /// This method is not constant-time and must not be used when the `Result`
    /// variant is secret.
    #[deprecated(
        note = "secure_unwrap is not constant-time; use ErrorRegistryExt::unwrap_or_record_with for non-secret control flow"
    )]
    fn secure_unwrap<F>(self, default: T, on_error: F) -> T
    where
        F: FnOnce() -> E,
        E: Send + 'static;
}

#[allow(deprecated)]
impl<T, E> SecureErrorHandling<T, E> for core::result::Result<T, E> {
    fn secure_unwrap<F>(self, default: T, on_error: F) -> T
    where
        F: FnOnce() -> E,
        E: Send + 'static,
    {
        self.unwrap_or_record_with(default, on_error)
    }
}

/// Deprecated compatibility helpers for inspecting a `Result`.
///
/// These methods perform ordinary, data-dependent branching. Their historical
/// `ct_` prefix is inaccurate; use `Result::is_ok`, `Result::is_err`, or
/// `Result::map_or_else` instead. No generic helper can make arbitrary closures
/// and enum-variant control flow constant-time.
pub trait ConstantTimeResult<T, E> {
    /// Equivalent to [`Result::is_ok`]; this is not constant-time.
    #[deprecated(
        note = "ct_is_ok branches on the Result variant; use Result::is_ok and do not treat the variant as secret"
    )]
    fn ct_is_ok(&self) -> bool;

    /// Equivalent to [`Result::is_err`]; this is not constant-time.
    #[deprecated(
        note = "ct_is_err branches on the Result variant; use Result::is_err and do not treat the variant as secret"
    )]
    fn ct_is_err(&self) -> bool;

    /// Map the selected variant; only one closure is called.
    ///
    /// This is not constant-time. The `ConditionallySelectable` bound remains
    /// only to avoid breaking the legacy method signature.
    #[deprecated(
        note = "ct_map invokes only the selected closure; use Result::map_or_else and do not treat the variant as secret"
    )]
    fn ct_map<U, F, G>(self, ok_fn: F, err_fn: G) -> U
    where
        F: FnOnce(T) -> U,
        G: FnOnce(E) -> U,
        U: ConditionallySelectable;
}

#[allow(deprecated)]
impl<T, E> ConstantTimeResult<T, E> for core::result::Result<T, E> {
    fn ct_is_ok(&self) -> bool {
        self.is_ok()
    }

    fn ct_is_err(&self) -> bool {
        self.is_err()
    }

    fn ct_map<U, F, G>(self, ok_fn: F, err_fn: G) -> U
    where
        F: FnOnce(T) -> U,
        G: FnOnce(E) -> U,
        U: ConditionallySelectable,
    {
        match self {
            Ok(value) => ok_fn(value),
            Err(error) => err_fn(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorRegistryExt;
    use crate::error::ERROR_REGISTRY;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn record_extension_invokes_error_factory_only_on_error() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        ERROR_REGISTRY.clear();

        let ok: core::result::Result<u8, &'static str> = Ok(7);
        assert_eq!(
            ok.unwrap_or_record_with(9, || {
                CALLS.fetch_add(1, Ordering::SeqCst);
                "recorded error"
            }),
            7
        );
        assert_eq!(CALLS.load(Ordering::SeqCst), 0);

        let error: core::result::Result<u8, &'static str> = Err("source error");
        assert_eq!(
            error.unwrap_or_record_with(9, || {
                CALLS.fetch_add(1, Ordering::SeqCst);
                "recorded error"
            }),
            9
        );
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        ERROR_REGISTRY.clear();
    }
}
