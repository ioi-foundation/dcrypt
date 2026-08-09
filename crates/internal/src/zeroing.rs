//! Safe-Rust memory clearing utilities.

#[cfg(any(feature = "alloc", feature = "std"))]
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::fmt;
use core::hint::black_box;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{compiler_fence, Ordering};

/// Overwrite the initialized representation of a value with its zero value.
///
/// This deliberately makes no claim about inaccessible allocator capacity. Secret
/// containers in dcrypt use exact-size boxed slices so every initialized byte can
/// be cleared using safe Rust.
pub trait Zeroize {
    fn zeroize(&mut self);
}

/// Marker for values whose `Drop` implementation invokes [`Zeroize`].
pub trait ZeroizeOnDrop {}

macro_rules! impl_zeroize_integer {
    ($($ty:ty),+ $(,)?) => {$ (
        impl Zeroize for $ty {
            #[inline(never)]
            fn zeroize(&mut self) {
                *self = 0;
                compiler_fence(Ordering::SeqCst);
                black_box(self);
            }
        }
    )+ };
}

impl_zeroize_integer!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

impl Zeroize for bool {
    #[inline(never)]
    fn zeroize(&mut self) {
        *self = false;
        compiler_fence(Ordering::SeqCst);
        black_box(self);
    }
}

impl<T: Zeroize> Zeroize for [T] {
    #[inline(never)]
    fn zeroize(&mut self) {
        for item in self.iter_mut() {
            item.zeroize();
        }
        compiler_fence(Ordering::SeqCst);
        black_box(self);
    }
}

impl<T: Zeroize, const N: usize> Zeroize for [T; N] {
    #[inline(never)]
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<T: Zeroize> Zeroize for Option<T> {
    fn zeroize(&mut self) {
        if let Some(value) = self.as_mut() {
            value.zeroize();
        }
        *self = None;
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<T: Zeroize> Zeroize for Vec<T> {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
        self.clear();
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<T: Zeroize> Zeroize for Box<[T]> {
    fn zeroize(&mut self) {
        self.as_mut().zeroize();
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl Zeroize for String {
    fn zeroize(&mut self) {
        let mut bytes = core::mem::take(self).into_bytes();
        bytes.zeroize();
    }
}

/// A wrapper that clears its initialized value when dropped.
#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> fmt::Debug for Zeroizing<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Zeroizing([REDACTED])")
    }
}

impl<T: Zeroize> Zeroizing<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Move the protected value out, leaving a zero/default value for `Drop`.
    ///
    /// This is primarily useful at an ownership boundary where an exact-size
    /// boxed secret must become the caller's output without creating a second
    /// secret allocation.
    pub fn into_inner(mut self) -> T
    where
        T: Default,
    {
        core::mem::take(&mut self.0)
    }
}

impl<T: Zeroize> Deref for Zeroizing<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Zeroize> DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Zeroize> AsRef<T> for Zeroizing<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> AsMut<T> for Zeroizing<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> Zeroize for Zeroizing<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Zeroizing<T> {}

/// An exact-size byte allocation that clears every initialized byte on drop.
///
/// Unlike `Zeroizing<Vec<u8>>`, this type has no inaccessible spare capacity.
/// New secret-returning APIs should prefer this representation.
#[cfg(any(feature = "alloc", feature = "std"))]
pub type ZeroizingBytes = Zeroizing<Box<[u8]>>;

#[cfg(any(feature = "alloc", feature = "std"))]
impl Zeroizing<Box<[u8]>> {
    /// Borrow the exact-size protected allocation as bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Mutably borrow the exact-size protected allocation as bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Exact-size allocations have no inaccessible spare capacity.
    pub fn capacity(&self) -> usize {
        self.0.len()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl AsRef<[u8]> for Zeroizing<Box<[u8]>> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl AsMut<[u8]> for Zeroizing<Box<[u8]>> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Allocate an exact-size boxed byte slice initialized to zero.
///
/// The temporary `Vec` contains only zeroes. Secret bytes must be written only
/// after conversion to the exact-size boxed slice.
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn boxed_bytes_zeroed(len: usize) -> Box<[u8]> {
    vec![0u8; len].into_boxed_slice()
}

/// Copy bytes directly into exact-size owned storage.
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn boxed_bytes_from_slice(data: &[u8]) -> Box<[u8]> {
    let mut boxed = boxed_bytes_zeroed(data.len());
    boxed.copy_from_slice(data);
    boxed
}

/// Copy bytes into exact-size storage that clears itself on drop.
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn zeroizing_bytes_from_slice(data: &[u8]) -> ZeroizingBytes {
    Zeroizing::new(boxed_bytes_from_slice(data))
}

/// Explicitly overwrite every initialized byte in a slice.
///
/// The implementation uses safe-Rust writes plus `compiler_fence` and
/// `black_box` as best-effort optimization barriers. It does not claim
/// compiler-guaranteed physical erasure of registers, copies, or freed memory.
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

/// Clone a slice into exact-size storage, then explicitly clear the source
/// afterwards.
///
/// This function clones the contents of the slice and then invokes the same
/// best-effort initialized-byte clearing used by [`secure_zero`].
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn secure_clone_and_zero(data: &mut [u8]) -> Box<[u8]> {
    let result = boxed_bytes_from_slice(data);
    secure_zero(data);
    result
}

/// Guard that invokes explicit initialized-byte clearing when dropped
///
/// `Drop` invokes [`secure_zero`] on the contained buffer. The same compiler
/// and out-of-scope-copy limitations documented there apply.
pub struct ZeroGuard<'a>(&'a mut [u8]);

impl<'a> ZeroGuard<'a> {
    /// Create a new guard that will zero the given data when dropped
    pub fn new(data: &'a mut [u8]) -> Self {
        Self(data)
    }

    /// Get a reference to the protected data
    pub fn data(&self) -> &[u8] {
        self.0
    }

    /// Get a mutable reference to the protected data
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl Drop for ZeroGuard<'_> {
    fn drop(&mut self) {
        secure_zero(self.0);
    }
}

#[cfg(all(test, any(feature = "alloc", feature = "std")))]
mod tests {
    use super::{
        boxed_bytes_from_slice, boxed_bytes_zeroed, secure_clone_and_zero, Zeroize, ZeroizingBytes,
    };

    #[cfg(not(feature = "std"))]
    use alloc::format;

    #[test]
    fn boxed_byte_helpers_use_exact_length_storage() {
        let zeroed = boxed_bytes_zeroed(17);
        assert_eq!(zeroed.len(), 17);
        assert!(zeroed.iter().all(|byte| *byte == 0));

        let copied = boxed_bytes_from_slice(&[1, 2, 3, 4]);
        assert_eq!(&*copied, &[1, 2, 3, 4]);
    }

    #[test]
    fn secure_clone_moves_secret_into_box_and_clears_source() {
        let mut source = [0xA5; 8];
        let copied = secure_clone_and_zero(&mut source);
        assert_eq!(&*copied, &[0xA5; 8]);
        assert_eq!(source, [0; 8]);
    }

    #[test]
    fn zeroizing_bytes_can_be_cleared_in_place() {
        let mut secret = ZeroizingBytes::new(boxed_bytes_from_slice(&[7, 8, 9]));
        assert_eq!(format!("{secret:?}"), "Zeroizing([REDACTED])");
        secret.zeroize();
        assert_eq!(&**secret, &[0, 0, 0]);
    }

    #[test]
    fn zeroizing_value_can_be_moved_out_without_copying() {
        let bytes = ZeroizingBytes::new(boxed_bytes_from_slice(&[1, 2, 3]));
        let inner = bytes.into_inner();
        assert_eq!(&*inner, &[1, 2, 3]);
    }
}
