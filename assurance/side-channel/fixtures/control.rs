//! Deliberately leaky analyzer fixture; never linked into a production crate.

#![allow(dead_code)]

#[inline(never)]
pub fn secret_branch(secret: u8) -> u8 {
    if std::hint::black_box(secret) & 1 == 0 {
        0x55
    } else {
        0xaa
    }
}

#[inline(never)]
pub fn secret_address(secret: u8) -> u8 {
    let table = std::hint::black_box([0x11_u8, 0x22_u8]);
    table[usize::from(std::hint::black_box(secret) & 1)]
}

#[inline(never)]
pub fn public_branch(secret: u8, public_choice: bool) -> u8 {
    let value = std::hint::black_box(secret);
    if std::hint::black_box(public_choice) {
        value.wrapping_add(1)
    } else {
        value.wrapping_sub(1)
    }
}

#[inline(never)]
pub fn public_address(secret: u8, public_index: usize) -> u8 {
    let table = std::hint::black_box([secret, secret]);
    table[std::hint::black_box(public_index) & 1]
}

#[inline(never)]
pub fn timing_leak(secret: u8) -> u8 {
    let rounds = usize::from(std::hint::black_box(secret) & 0x0f);
    (0..rounds).fold(0_u8, |value, index| value.wrapping_add(index as u8))
}

#[inline(never)]
pub fn timing_noise_control(secret: u8) -> u8 {
    std::hint::black_box(secret).rotate_left(1)
}
