#![no_main]
#![forbid(unsafe_code)]

mod support;

use dcrypt_api::traits::SerializeSecret;
use dcrypt_api::{Kem, Serialize};
use dcrypt_kem::ml_kem::{MlKem1024, MlKem512, MlKem768};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 4 * 1024;
const MAGIC: &[u8] = b"DCRYPT:MLKEM:V1:";

macro_rules! exercise {
    ($scheme:ty, $input:expr, $domain:expr) => {{
        let mut key_rng = support::rng($input, $domain);
        let keypair = <$scheme>::keypair(&mut key_rng).expect("input RNG yields a keypair");
        let public_key = <$scheme>::public_key(&keypair);
        let secret_key = <$scheme>::secret_key(&keypair);

        let public_bytes = public_key.to_bytes();
        let parsed_public = <<$scheme as Kem>::PublicKey as Serialize>::from_bytes(&public_bytes)
            .expect("generated public key roundtrips");
        let secret_bytes = secret_key.to_bytes_zeroizing();
        let parsed_secret =
            <<$scheme as Kem>::SecretKey as SerializeSecret>::from_bytes(&secret_bytes)
                .expect("generated secret key roundtrips");

        let mut encapsulation_rng = support::rng($input, $domain.wrapping_add(0x40));
        let (ciphertext, shared) = <$scheme>::encapsulate(&mut encapsulation_rng, &parsed_public)
            .expect("generated public key encapsulates");
        let recovered = <$scheme>::decapsulate(&parsed_secret, &ciphertext)
            .expect("generated ciphertext decapsulates");
        assert_eq!(
            &shared.to_bytes_zeroizing()[..],
            &recovered.to_bytes_zeroizing()[..]
        );

        let ciphertext_bytes = ciphertext.to_bytes();
        let parsed_ciphertext =
            <<$scheme as Kem>::Ciphertext as Serialize>::from_bytes(&ciphertext_bytes)
                .expect("generated ciphertext roundtrips");
        let replayed = <$scheme>::decapsulate(&parsed_secret, &parsed_ciphertext)
            .expect("roundtripped ciphertext decapsulates");
        assert_eq!(
            &shared.to_bytes_zeroizing()[..],
            &replayed.to_bytes_zeroizing()[..]
        );

        // FIPS 203 implicit rejection returns a pseudorandom secret rather than
        // a validity error for a same-sized modified ciphertext.
        let modified = support::tamper(&ciphertext_bytes, usize::from($domain));
        if let Ok(modified) = <<$scheme as Kem>::Ciphertext as Serialize>::from_bytes(&modified) {
            let rejected = <$scheme>::decapsulate(&parsed_secret, &modified)
                .expect("ML-KEM implicit rejection remains total");
            assert_ne!(
                &shared.to_bytes_zeroizing()[..],
                &rejected.to_bytes_zeroizing()[..]
            );
        }
    }};
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];
    let Some(input) = support::semantic_payload(input, MAGIC) else {
        return;
    };
    let Some(selector) = input.first().copied() else {
        return;
    };
    match support::selector(selector, 3) {
        0 => exercise!(MlKem512, input, 0x11u8),
        1 => exercise!(MlKem768, input, 0x22u8),
        _ => exercise!(MlKem1024, input, 0x33u8),
    }
});
