//! Safe-Rust memory clearing utilities.

#[cfg(any(feature = "alloc", feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};
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
    }
}

impl<T: Zeroize> Zeroize for [T] {
    #[inline(never)]
    fn zeroize(&mut self) {
        for item in self {
            item.zeroize();
        }
        compiler_fence(Ordering::SeqCst);
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
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> Zeroizing<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
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

/// Securely zero a slice of memory
///
/// This function ensures that the contents of the slice are securely
/// zeroed, even if the compiler would otherwise optimize the operation away.
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

/// Securely clone a slice, zeroing the source afterwards
///
/// This function clones the contents of the slice and then securely
/// zeroes the original slice.
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn secure_clone_and_zero(data: &mut [u8]) -> Vec<u8> {
    let result = data.to_vec();
    secure_zero(data);
    result
}

/// Guard that zeroes memory when dropped
///
/// This struct provides a way to ensure that memory is zeroed when
/// it goes out of scope, by automatically zeroing the contained
/// buffer when the `ZeroGuard` is dropped.
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
