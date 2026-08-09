use alloc::boxed::Box;

use dcrypt_api::{Error, Kem};
use dcrypt_internal::random::{CryptoRng, Error as RngError, RngCore};
use dcrypt_internal::zeroing::Zeroizing;

use super::kem::{MlKemCiphertext, MlKemDecapsulationKey, MlKemEncapsulationKey};
use super::params::{MlKem1024Params, MlKem512Params, MlKem768Params, MlKemParameterSet, Q};
use super::poly::Poly;
use super::{MlKem, MlKem1024, MlKem512, MlKem768};

struct FailingRng;

impl RngCore for FailingRng {
    fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> core::result::Result<(), RngError> {
        Err(RngError)
    }
}

impl CryptoRng for FailingRng {}

fn deterministic_inputs() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    let mut m = [0u8; 32];
    for index in 0..32 {
        d[index] = index as u8;
        z[index] = (index as u8).wrapping_add(0x40);
        m[index] = (index as u8).wrapping_mul(7).wrapping_add(3);
    }
    (d, z, m)
}

fn round_trip<P: MlKemParameterSet>() {
    let (d, z, m) = deterministic_inputs();
    let keypair = MlKem::<P>::keypair_deterministic(&d, &z).unwrap();
    let public_key = MlKem::<P>::public_key(&keypair);
    let secret_key = MlKem::<P>::secret_key(&keypair);
    let (ciphertext, first) = MlKem::<P>::encapsulate_deterministic(&public_key, &m).unwrap();
    let second = MlKem::<P>::decapsulate(&secret_key, &ciphertext).unwrap();
    assert_eq!(
        &first.to_bytes_zeroizing()[..],
        &second.to_bytes_zeroizing()[..]
    );
    assert_eq!(public_key.len(), P::ENCAPSULATION_KEY_BYTES);
    assert_eq!(secret_key.len(), P::DECAPSULATION_KEY_BYTES);
    assert_eq!(ciphertext.len(), P::CIPHERTEXT_BYTES);

    let public_encoded = public_key.to_bytes();
    let secret_encoded = secret_key.to_bytes_zeroizing();
    let _: &Zeroizing<Box<[u8]>> = &secret_encoded;
    let shared_encoded = first.to_bytes_zeroizing();
    let _: &Zeroizing<Box<[u8]>> = &shared_encoded;
    let ciphertext_encoded = ciphertext.to_bytes();
    assert_eq!(
        MlKemEncapsulationKey::<P>::from_bytes(&public_encoded)
            .unwrap()
            .as_bytes(),
        public_encoded
    );
    assert_eq!(
        MlKemDecapsulationKey::<P>::from_bytes(&secret_encoded)
            .unwrap()
            .to_bytes_zeroizing()[..],
        secret_encoded[..]
    );
    assert_eq!(
        MlKemCiphertext::<P>::from_bytes(&ciphertext_encoded)
            .unwrap()
            .as_bytes(),
        ciphertext_encoded
    );
}

#[test]
fn all_parameter_sets_round_trip() {
    round_trip::<MlKem512Params>();
    round_trip::<MlKem768Params>();
    round_trip::<MlKem1024Params>();
}

#[test]
fn exact_fips_203_lengths() {
    assert_eq!(MlKem512::name(), "ML-KEM-512");
    assert_eq!(MlKem768::name(), "ML-KEM-768");
    assert_eq!(MlKem1024::name(), "ML-KEM-1024");
    assert_eq!(MlKem512Params::ENCAPSULATION_KEY_BYTES, 800);
    assert_eq!(MlKem768Params::ENCAPSULATION_KEY_BYTES, 1_184);
    assert_eq!(MlKem1024Params::ENCAPSULATION_KEY_BYTES, 1_568);
    assert_eq!(MlKem512Params::DECAPSULATION_KEY_BYTES, 1_632);
    assert_eq!(MlKem768Params::DECAPSULATION_KEY_BYTES, 2_400);
    assert_eq!(MlKem1024Params::DECAPSULATION_KEY_BYTES, 3_168);
    assert_eq!(MlKem512Params::CIPHERTEXT_BYTES, 768);
    assert_eq!(MlKem768Params::CIPHERTEXT_BYTES, 1_088);
    assert_eq!(MlKem1024Params::CIPHERTEXT_BYTES, 1_568);
}

#[test]
fn constructors_reject_every_wrong_length_without_panicking() {
    for length in [0, 1, 31, 32, 383, 799, 801, 1_631, 1_633] {
        let bytes = vec![0u8; length];
        assert!(MlKemEncapsulationKey::<MlKem512Params>::from_bytes(&bytes).is_err());
        assert!(MlKemDecapsulationKey::<MlKem512Params>::from_bytes(&bytes).is_err());
        assert!(MlKemCiphertext::<MlKem512Params>::from_bytes(&bytes).is_err());
    }
}

/// Parser boundary exercise kept small enough for `cargo miri test`.
#[cfg(miri)]
#[test]
fn miri_validated_type_decoders_cover_length_boundaries() {
    for length in [0, 1, 767, 768, 799, 800, 801, 1_631, 1_632, 1_633] {
        let bytes = vec![0u8; length];
        let _ = MlKemEncapsulationKey::<MlKem512Params>::from_bytes(&bytes);
        let _ = MlKemDecapsulationKey::<MlKem512Params>::from_bytes(&bytes);
        let _ = MlKemCiphertext::<MlKem512Params>::from_bytes(&bytes);
    }
}

#[test]
fn encapsulation_key_rejects_non_canonical_twelve_bit_coefficient() {
    let (d, z, _) = deterministic_inputs();
    let keypair = MlKem512::keypair_deterministic(&d, &z).unwrap();
    let mut bytes = MlKem512::public_key(&keypair).to_bytes();
    let q = Q as u16;
    bytes[0] = q as u8;
    bytes[1] = (bytes[1] & 0xf0) | ((q >> 8) as u8 & 0x0f);
    assert!(MlKemEncapsulationKey::<MlKem512Params>::from_bytes(&bytes).is_err());
}

#[test]
fn decapsulation_key_rejects_non_canonical_secret_and_incoherent_hash() {
    let (d, z, _) = deterministic_inputs();
    let keypair = MlKem512::keypair_deterministic(&d, &z).unwrap();
    let secret = MlKem512::secret_key(&keypair).to_bytes_zeroizing();

    let mut noncanonical = secret.to_vec();
    let q = Q as u16;
    noncanonical[0] = q as u8;
    noncanonical[1] = (noncanonical[1] & 0xf0) | ((q >> 8) as u8 & 0x0f);
    assert!(MlKemDecapsulationKey::<MlKem512Params>::from_bytes(&noncanonical).is_err());

    let mut incoherent = secret.to_vec();
    let hash_offset = 2 * 384 + 800;
    incoherent[hash_offset] ^= 1;
    assert!(MlKemDecapsulationKey::<MlKem512Params>::from_bytes(&incoherent).is_err());
}

#[test]
fn modified_exact_length_ciphertext_uses_deterministic_implicit_rejection() {
    let (d, z, m) = deterministic_inputs();
    let keypair = MlKem768::keypair_deterministic(&d, &z).unwrap();
    let public_key = MlKem768::public_key(&keypair);
    let secret_key = MlKem768::secret_key(&keypair);
    let (valid_ciphertext, valid_secret) =
        MlKem768::encapsulate_deterministic(&public_key, &m).unwrap();
    let mut modified_bytes = valid_ciphertext.to_bytes();
    let middle = modified_bytes.len() / 2;
    modified_bytes[middle] ^= 0x80;
    let modified = MlKemCiphertext::<MlKem768Params>::from_bytes(&modified_bytes).unwrap();
    let first_rejection = MlKem768::decapsulate(&secret_key, &modified).unwrap();
    let second_rejection = MlKem768::decapsulate(&secret_key, &modified).unwrap();
    assert_ne!(
        valid_secret.to_bytes_zeroizing()[..],
        first_rejection.to_bytes_zeroizing()[..]
    );
    assert_eq!(
        first_rejection.to_bytes_zeroizing()[..],
        second_rejection.to_bytes_zeroizing()[..]
    );
}

#[test]
fn caller_rng_failures_are_preserved() {
    let mut failing = FailingRng;
    assert!(matches!(
        MlKem512::keypair(&mut failing),
        Err(Error::RandomGenerationError { .. })
    ));

    let (d, z, _) = deterministic_inputs();
    let keypair = MlKem512::keypair_deterministic(&d, &z).unwrap();
    let public_key = MlKem512::public_key(&keypair);
    assert!(matches!(
        MlKem512::encapsulate(&mut failing, &public_key),
        Err(Error::RandomGenerationError { .. })
    ));
}

#[test]
fn ml_kem_ntt_inverse_round_trip_has_required_montgomery_factor() {
    let mut polynomial = Poly::zero();
    for (index, coefficient) in polynomial.coeffs.iter_mut().enumerate() {
        *coefficient = (index as i16 * 13) % Q;
    }
    let transformed = super::pke::ntt_roundtrip(&polynomial);
    for (actual, original) in transformed.coeffs.iter().zip(polynomial.coeffs.iter()) {
        assert_eq!(
            *actual,
            (i32::from(*original) * 2_285 % i32::from(Q)) as i16
        );
    }
}
