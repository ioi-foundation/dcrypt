//! Constant-time operations to prevent timing attacks.
//!
//! These small primitives are owned by dcrypt so the published implementation
//! does not need an unsafe-containing dependency for masks and comparisons.

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, Not};

/// A one-bit value used by constant-time operations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Choice(u8);

impl Choice {
    /// Return the normalized value (`0` or `1`).
    #[inline(always)]
    pub const fn unwrap_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for Choice {
    #[inline(always)]
    fn from(value: u8) -> Self {
        Self(value & 1)
    }
}

impl From<bool> for Choice {
    #[inline(always)]
    fn from(value: bool) -> Self {
        Self(value as u8)
    }
}

impl From<Choice> for bool {
    #[inline(always)]
    fn from(value: Choice) -> Self {
        value.0 == 1
    }
}

impl From<Choice> for u8 {
    #[inline(always)]
    fn from(value: Choice) -> Self {
        value.0
    }
}

impl Not for Choice {
    type Output = Self;

    #[inline(always)]
    fn not(self) -> Self::Output {
        Self(self.0 ^ 1)
    }
}

impl BitAnd for Choice {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for Choice {
    #[inline(always)]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitOr for Choice {
    type Output = Self;

    #[inline(always)]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Choice {
    #[inline(always)]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitXor for Choice {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

/// Select between two values without branching on `choice`.
pub trait ConditionallySelectable: Copy {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self;
}

macro_rules! impl_conditionally_selectable_integer {
    ($($ty:ty),+ $(,)?) => {$ (
        impl ConditionallySelectable for $ty {
            #[inline(always)]
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                let mask = (0 as $ty).wrapping_sub(choice.unwrap_u8() as $ty);
                a ^ (mask & (a ^ b))
            }
        }
    )+ };
}

impl_conditionally_selectable_integer!(u8, u16, u32, u64, u128, usize);

impl ConditionallySelectable for Choice {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u8::conditional_select(&a.0, &b.0, choice))
    }
}

/// Compare two values without data-dependent early exit.
pub trait ConstantTimeEq {
    fn ct_eq(&self, other: &Self) -> Choice;
}

macro_rules! impl_constant_time_eq_integer {
    ($($ty:ty),+ $(,)?) => {$ (
        impl ConstantTimeEq for $ty {
            #[inline(always)]
            fn ct_eq(&self, other: &Self) -> Choice {
                let difference = self ^ other;
                let nonzero = difference | difference.wrapping_neg();
                Choice::from(((nonzero >> (<$ty>::BITS - 1)) as u8) ^ 1)
            }
        }
    )+ };
}

impl_constant_time_eq_integer!(u8, u16, u32, u64, u128, usize);

impl ConstantTimeEq for Choice {
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<T: ConstantTimeEq, const N: usize> ConstantTimeEq for [T; N] {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut equal = Choice::from(1u8);
        for index in 0..N {
            equal &= self[index].ct_eq(&other[index]);
        }
        equal
    }
}

impl<T: ConstantTimeEq> ConstantTimeEq for [T] {
    fn ct_eq(&self, other: &Self) -> Choice {
        if self.len() != other.len() {
            return Choice::from(0u8);
        }
        let mut equal = Choice::from(1u8);
        for (left, right) in self.iter().zip(other) {
            equal &= left.ct_eq(right);
        }
        equal
    }
}

/// An option whose validity is represented by a [`Choice`].
#[derive(Clone, Copy, Debug)]
pub struct CtOption<T> {
    value: T,
    is_some: Choice,
}

impl<T> CtOption<T> {
    pub const fn new(value: T, is_some: Choice) -> Self {
        Self { value, is_some }
    }

    pub const fn is_some(&self) -> Choice {
        self.is_some
    }

    pub fn is_none(&self) -> Choice {
        !self.is_some
    }

    pub fn unwrap(self) -> T {
        assert!(
            bool::from(self.is_some),
            "called CtOption::unwrap on an invalid value"
        );
        self.value
    }

    pub fn unwrap_or(self, default: T) -> T
    where
        T: ConditionallySelectable,
    {
        T::conditional_select(&default, &self.value, self.is_some)
    }

    pub fn unwrap_or_else<F>(self, default: F) -> T
    where
        T: ConditionallySelectable,
        F: FnOnce() -> T,
    {
        self.unwrap_or(default())
    }

    pub fn and_then<U, F>(self, function: F) -> CtOption<U>
    where
        F: FnOnce(T) -> CtOption<U>,
    {
        let next = function(self.value);
        CtOption::new(next.value, self.is_some & next.is_some)
    }

    pub fn map<U, F>(self, function: F) -> CtOption<U>
    where
        F: FnOnce(T) -> U,
    {
        CtOption::new(function(self.value), self.is_some)
    }

    pub fn into_option(self) -> Option<T> {
        self.into()
    }

    pub fn or_else<F>(self, function: F) -> Self
    where
        T: ConditionallySelectable,
        F: FnOnce() -> Self,
    {
        let alternative = function();
        Self::new(
            T::conditional_select(&alternative.value, &self.value, self.is_some),
            self.is_some | alternative.is_some,
        )
    }
}

impl<T> From<CtOption<T>> for Option<T> {
    fn from(value: CtOption<T>) -> Self {
        if bool::from(value.is_some) {
            Some(value.value)
        } else {
            None
        }
    }
}

/// Constant-time comparison of two byte slices
///
/// Returns true if the slices are equal, false otherwise.
/// This function runs in constant time regardless of the input values.
pub fn ct_eq<A, B>(a: A, b: B) -> bool
where
    A: AsRef<[u8]>,
    B: AsRef<[u8]>,
{
    let a = a.as_ref();
    let b = b.as_ref();

    if a.len() != b.len() {
        return false;
    }

    bool::from(a.ct_eq(b))
}

/// Constant-time selection of a byte
///
/// Returns `a` if `condition` is false, `b` if `condition` is true.
/// This function runs in constant time regardless of the input values.
pub fn ct_select<T>(a: T, b: T, condition: bool) -> T
where
    T: ConditionallySelectable,
{
    let choice = Choice::from(condition as u8);
    T::conditional_select(&a, &b, choice)
}

/// Constant-time conditional assignment
///
/// Sets `dst` to `src` if `condition` is true, otherwise leaves `dst` unchanged.
/// This function runs in constant time regardless of the input values.
pub fn ct_assign(dst: &mut [u8], src: &[u8], condition: bool) {
    assert_eq!(dst.len(), src.len());

    let choice = Choice::from(condition as u8);

    for i in 0..dst.len() {
        dst[i] = u8::conditional_select(&dst[i], &src[i], choice);
    }
}

/// Trait for types that can be compared in constant time
pub trait ConstantTimeEquals {
    /// Compare two values in constant time
    fn ct_equals(&self, other: &Self) -> bool;
}

/// Implement ConstantTimeEquals for all types that implement AsRef<[u8]>
impl<T: AsRef<[u8]>> ConstantTimeEquals for T {
    fn ct_equals(&self, other: &Self) -> bool {
        ct_eq(self.as_ref(), other.as_ref())
    }
}

/// Constant-time equality check that returns a Choice (0 or 1)
pub fn ct_eq_choice<A, B>(a: A, b: B) -> Choice
where
    A: AsRef<[u8]>,
    B: AsRef<[u8]>,
{
    let a = a.as_ref();
    let b = b.as_ref();

    if a.len() != b.len() {
        return Choice::from(0);
    }

    a.ct_eq(b)
}

/// Apply a constant-time bitwise AND operation between two arrays
pub fn ct_and<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = a[i] & b[i];
    }
    result
}

/// Apply a constant-time bitwise OR operation between two arrays
pub fn ct_or<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = a[i] | b[i];
    }
    result
}

/// Apply a constant-time bitwise XOR operation between two arrays
pub fn ct_xor<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Generic constant-time conditional operation on byte arrays
///
/// Applies the function `op` to elements of `a` and `b` based on the condition.
/// This is useful for implementing constant-time bit operations.
pub fn ct_op<const N: usize, F>(a: &[u8; N], b: &[u8; N], condition: bool, op: F) -> [u8; N]
where
    F: Fn(u8, u8) -> u8,
{
    let choice = Choice::from(condition as u8);
    let mut result = [0u8; N];

    for i in 0..N {
        // If condition is true, apply op(a[i], b[i]), otherwise keep a[i]
        let operated = op(a[i], b[i]);
        result[i] = u8::conditional_select(&a[i], &operated, choice);
    }

    result
}

/// Constant-time mask generation for a boolean condition
///
/// Returns an all-1s mask if condition is true, all-0s if false
pub fn ct_mask(condition: bool) -> u8 {
    0u8.wrapping_sub(condition as u8)
}
