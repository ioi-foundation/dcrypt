#![no_main]
#![forbid(unsafe_code)]

mod support;

use dcrypt_api::traits::SerializeSecret;
use dcrypt_api::{Kem, Serialize, Signature};
use dcrypt_hybrid::{
    kem::{
        EcdhK256MlKem512, EcdhP256MlKem512, EcdhP256MlKem768, EcdhP384MlKem1024, EcdhP521MlKem1024,
    },
    sign::EcdsaMlDsa65Hybrid,
};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 4 * 1024;
const MAGIC: &[u8] = b"DCRYPT:HYBRID:V1:";

macro_rules! exercise_kem {
    ($scheme:ty, $input:expr, $domain:expr) => {{
        let mut key_rng = support::rng($input, $domain);
        let keypair = <$scheme>::keypair(&mut key_rng).expect("hybrid KEM key generation succeeds");
        let public = <$scheme>::public_key(&keypair);
        let secret = <$scheme>::secret_key(&keypair);
        let public = <<$scheme as Kem>::PublicKey as Serialize>::from_bytes(&public.to_bytes())
            .expect("hybrid public key roundtrips");
        let secret = <<$scheme as Kem>::SecretKey as SerializeSecret>::from_bytes(
            &secret.to_bytes_zeroizing(),
        )
        .expect("hybrid secret key roundtrips");
        let mut encapsulation_rng = support::rng($input, $domain.wrapping_add(1));
        let (ciphertext, shared) = <$scheme>::encapsulate(&mut encapsulation_rng, &public)
            .expect("hybrid encapsulation succeeds");
        let recovered =
            <$scheme>::decapsulate(&secret, &ciphertext).expect("hybrid decapsulation succeeds");
        assert_eq!(
            &shared.to_bytes_zeroizing()[..],
            &recovered.to_bytes_zeroizing()[..]
        );

        let bytes = ciphertext.to_bytes();
        let parsed = <<$scheme as Kem>::Ciphertext as Serialize>::from_bytes(&bytes)
            .expect("hybrid ciphertext roundtrips");
        assert_eq!(
            &shared.to_bytes_zeroizing()[..],
            &<$scheme>::decapsulate(&secret, &parsed)
                .unwrap()
                .to_bytes_zeroizing()[..]
        );
        let modified = support::tamper(&bytes, usize::from($domain));
        if let Ok(modified) = <<$scheme as Kem>::Ciphertext as Serialize>::from_bytes(&modified) {
            if let Ok(other) = <$scheme>::decapsulate(&secret, &modified) {
                assert_ne!(
                    &shared.to_bytes_zeroizing()[..],
                    &other.to_bytes_zeroizing()[..]
                );
            }
        }
    }};
}

fn exercise_signature(input: &[u8]) {
    type Scheme = EcdsaMlDsa65Hybrid;
    let mut rng = support::rng(input, 0x5f);
    let keypair = Scheme::keypair(&mut rng).expect("hybrid signature key generation succeeds");
    let public = Scheme::public_key(&keypair);
    let secret = Scheme::secret_key(&keypair);
    let message = support::message(input, 1, 2 * 1024);
    let signature = Scheme::sign(message, &secret).expect("hybrid signing succeeds");
    Scheme::verify(message, &signature, &public).expect("hybrid signature verifies");

    let parsed_public = <Scheme as Signature>::PublicKey::from_bytes(&public.to_bytes())
        .expect("hybrid signature public key roundtrips");
    let parsed_secret = <Scheme as Signature>::SecretKey::from_bytes(&secret.to_bytes_zeroizing())
        .expect("hybrid signature secret key roundtrips");
    let parsed_signature = <Scheme as Signature>::SignatureData::from_bytes(&signature.to_bytes())
        .expect("hybrid signature encoding roundtrips");
    Scheme::verify(message, &parsed_signature, &parsed_public)
        .expect("roundtripped hybrid signature verifies");
    let repeated = Scheme::sign(message, &parsed_secret).expect("imported hybrid key signs");
    assert_eq!(signature.to_bytes(), repeated.to_bytes());

    assert!(Scheme::verify(&support::tamper(message, input.len()), &signature, &public).is_err());
    let modified = support::tamper(&signature.to_bytes(), input.len() + 1);
    if let Ok(modified) = <Scheme as Signature>::SignatureData::from_bytes(&modified) {
        assert!(Scheme::verify(message, &modified, &public).is_err());
    }
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];
    let Some(input) = support::semantic_payload(input, MAGIC) else {
        return;
    };
    let Some(selector) = input.first().copied() else {
        return;
    };
    match support::selector(selector, 6) {
        0 => exercise_kem!(EcdhK256MlKem512, input, 0x51u8),
        1 => exercise_kem!(EcdhP256MlKem512, input, 0x52u8),
        2 => exercise_kem!(EcdhP256MlKem768, input, 0x53u8),
        3 => exercise_kem!(EcdhP384MlKem1024, input, 0x54u8),
        4 => exercise_kem!(EcdhP521MlKem1024, input, 0x55u8),
        _ => exercise_signature(input),
    }
});
