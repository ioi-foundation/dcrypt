#![no_main]
#![forbid(unsafe_code)]

mod support;

use dcrypt_api::traits::SerializeSecret;
use dcrypt_api::{Kem, Serialize};
use dcrypt_kem::ecdh::{EcdhK256, EcdhP224, EcdhP256, EcdhP384, EcdhP521};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 4 * 1024;
const MAGIC: &[u8] = b"DCRYPT:ECDH:V1:";

macro_rules! exercise {
    ($scheme:ty, $input:expr, $domain:expr) => {{
        let mut recipient_rng = support::rng($input, $domain);
        let keypair = <$scheme>::keypair(&mut recipient_rng).expect("input RNG yields ECDH keys");
        let public = <$scheme>::public_key(&keypair);
        let secret = <$scheme>::secret_key(&keypair);
        let parsed_public =
            <<$scheme as Kem>::PublicKey as Serialize>::from_bytes(&public.to_bytes())
                .expect("generated ECDH public key roundtrips");
        let parsed_secret = <<$scheme as Kem>::SecretKey as SerializeSecret>::from_bytes(
            &secret.to_bytes_zeroizing(),
        )
        .expect("generated ECDH secret key roundtrips");

        let mut sender_rng = support::rng($input, $domain.wrapping_add(0x20));
        let (ciphertext, shared) = <$scheme>::encapsulate(&mut sender_rng, &parsed_public)
            .expect("ECDH encapsulation succeeds");
        let recovered = <$scheme>::decapsulate(&parsed_secret, &ciphertext)
            .expect("ECDH decapsulation succeeds");
        assert_eq!(
            &shared.to_bytes_zeroizing()[..],
            &recovered.to_bytes_zeroizing()[..]
        );

        let bytes = ciphertext.to_bytes();
        let roundtripped = <<$scheme as Kem>::Ciphertext as Serialize>::from_bytes(&bytes)
            .expect("generated ECDH ciphertext roundtrips");
        assert_eq!(
            &shared.to_bytes_zeroizing()[..],
            &<$scheme>::decapsulate(&parsed_secret, &roundtripped)
                .unwrap()
                .to_bytes_zeroizing()[..]
        );

        let modified = support::tamper(&bytes, usize::from($domain));
        if let Ok(modified) = <<$scheme as Kem>::Ciphertext as Serialize>::from_bytes(&modified) {
            let result = <$scheme>::decapsulate(&parsed_secret, &modified);
            if let Ok(other) = result {
                assert_ne!(
                    &shared.to_bytes_zeroizing()[..],
                    &other.to_bytes_zeroizing()[..]
                );
            }
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
    match support::selector(selector, 5) {
        0 => exercise!(EcdhP224, input, 0xc1u8),
        1 => exercise!(EcdhP256, input, 0xc2u8),
        2 => exercise!(EcdhP384, input, 0xc3u8),
        3 => exercise!(EcdhP521, input, 0xc4u8),
        _ => exercise!(EcdhK256, input, 0xc5u8),
    }
});
