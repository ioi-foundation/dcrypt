//! Shared constants and helper functions for P-521 operations

/// Size of a P-521 scalar in bytes (66 bytes)
pub const P521_SCALAR_SIZE: usize = 66;

/// Size of a P-521 field element in bytes (66 bytes)
pub const P521_FIELD_ELEMENT_SIZE: usize = 66;

/// Size of an uncompressed P-521 point in bytes: format byte (0x04) + x-coordinate + y-coordinate
pub const P521_POINT_UNCOMPRESSED_SIZE: usize = 1 + 2 * P521_FIELD_ELEMENT_SIZE; // 1 + 132 = 133 bytes

/// Size of a compressed P-521 point in bytes: format byte (0x02/0x03) + x-coordinate
pub const P521_POINT_COMPRESSED_SIZE: usize = 1 + P521_FIELD_ELEMENT_SIZE; // 1 + 66 = 67 bytes

/// Size of the KDF output for P-521 ECDH-KEM shared secret derivation (e.g., for HKDF-SHA512)
pub const P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE: usize = 64;

/// Number of 32-bit limbs for P-521 field elements and scalars
pub(crate) const P521_LIMBS: usize = 17;
