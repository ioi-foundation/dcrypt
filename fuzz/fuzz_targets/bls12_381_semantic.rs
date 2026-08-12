#![no_main]
#![forbid(unsafe_code)]

mod support;

use dcrypt_algorithms::ec::bls12_381::{
    multi_miller_loop, pairing, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective,
};
use dcrypt_sign::bls::{
    Bls12381G2Basic, Bls12381G2MessageAugmentation, Bls12381G2ProofOfPossession, Bls12381PublicKey,
    Bls12381SecretKey, Bls12381Signature, Eth2Bls12381G2PopV4,
};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 2 * 1024;
const MAGIC: &[u8] = b"DCRYPT:BLS12:V1:";

fn key(input: &[u8], domain: u8) -> Bls12381SecretKey {
    let ikm = support::seed(input, domain);
    let salt = support::seed(input, domain.wrapping_add(1));
    Bls12381SecretKey::key_gen(&ikm, &salt).expect("32-byte IKM produces a BLS key")
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];
    let Some(input) = support::semantic_payload(input, MAGIC) else {
        return;
    };
    let Some(state) = input.first().copied() else {
        return;
    };
    let selector = support::selector(state, 4);
    let message = support::message(input, 2, 512);
    let secret = key(input, 0x71);
    let public = secret.public_key().expect("derived BLS public key");
    let parsed_public = Bls12381PublicKey::from_bytes(&public.to_bytes())
        .expect("generated BLS public key roundtrips");
    let secret_bytes = secret.to_bytes_zeroizing();
    let parsed_secret = Bls12381SecretKey::from_bytes(&secret_bytes[..])
        .expect("generated BLS secret key roundtrips");
    assert_eq!(
        parsed_public.to_bytes(),
        parsed_secret.public_key().unwrap().to_bytes()
    );

    let signature = match selector {
        0 => {
            let signature = Bls12381G2Basic::sign(&secret, message).unwrap();
            Bls12381G2Basic::verify(&public, message, &signature).unwrap();
            assert!(Bls12381G2Basic::verify(
                &public,
                &support::tamper(message, usize::from(selector)),
                &signature
            )
            .is_err());
            let modified = support::tamper(&signature.to_bytes(), usize::from(selector) + 3);
            if let Ok(modified) = Bls12381Signature::from_bytes(&modified) {
                assert!(Bls12381G2Basic::verify(&public, message, &modified).is_err());
            }
            signature
        }
        1 => {
            let signature = Bls12381G2MessageAugmentation::sign(&secret, message).unwrap();
            Bls12381G2MessageAugmentation::verify(&public, message, &signature).unwrap();
            assert!(Bls12381G2MessageAugmentation::verify(
                &public,
                &support::tamper(message, usize::from(selector)),
                &signature
            )
            .is_err());
            assert!(Bls12381G2Basic::verify(&public, message, &signature).is_err());
            let modified = support::tamper(&signature.to_bytes(), usize::from(selector) + 3);
            if let Ok(modified) = Bls12381Signature::from_bytes(&modified) {
                assert!(
                    Bls12381G2MessageAugmentation::verify(&public, message, &modified).is_err()
                );
            }
            signature
        }
        2 => {
            let proof = Bls12381G2ProofOfPossession::pop_prove(&secret).unwrap();
            Bls12381G2ProofOfPossession::pop_verify(&public, &proof).unwrap();
            let signature = Bls12381G2ProofOfPossession::sign(&secret, message).unwrap();
            Bls12381G2ProofOfPossession::verify(&public, &proof, message, &signature).unwrap();
            assert!(Bls12381G2ProofOfPossession::verify(
                &public,
                &proof,
                &support::tamper(message, usize::from(selector)),
                &signature
            )
            .is_err());
            let modified = support::tamper(&signature.to_bytes(), usize::from(selector) + 3);
            if let Ok(modified) = Bls12381Signature::from_bytes(&modified) {
                assert!(
                    Bls12381G2ProofOfPossession::verify(&public, &proof, message, &modified)
                        .is_err()
                );
            }
            signature
        }
        _ => {
            let signature = Eth2Bls12381G2PopV4::sign(&secret, message).unwrap();
            Eth2Bls12381G2PopV4::verify(&public, message, &signature).unwrap();
            assert!(Eth2Bls12381G2PopV4::verify(
                &public,
                &support::tamper(message, usize::from(selector)),
                &signature
            )
            .is_err());
            let modified = support::tamper(&signature.to_bytes(), usize::from(selector) + 3);
            if let Ok(modified) = Bls12381Signature::from_bytes(&modified) {
                assert!(Eth2Bls12381G2PopV4::verify(&public, message, &modified).is_err());
            }
            signature
        }
    };
    let parsed_signature = Bls12381Signature::from_bytes(&signature.to_bytes())
        .expect("generated BLS signature roundtrips");
    assert_eq!(parsed_signature.to_bytes(), signature.to_bytes());

    // Exercise aggregation with two distinct keys and messages without using
    // any external comparator. Duplicate Basic messages must remain rejected.
    if input.get(1).copied() == Some(b'A') {
        let second_secret = key(input, 0x91);
        let second_public = second_secret.public_key().unwrap();
        let second_message = support::tamper(message, usize::from(selector) + 1);
        let first_signature = Bls12381G2Basic::sign(&secret, message).unwrap();
        let second_signature = Bls12381G2Basic::sign(&second_secret, &second_message).unwrap();
        let aggregate = Bls12381G2Basic::aggregate(&[first_signature, second_signature]).unwrap();
        Bls12381G2Basic::aggregate_verify(
            &[public.clone(), second_public.clone()],
            &[message, &second_message],
            &aggregate,
        )
        .unwrap();

        // Isolate the Basic-profile duplicate-message policy: both
        // signatures are otherwise valid for two distinct keys over the
        // same message, so the repeated message is the sole invalid axis.
        let first_duplicate = Bls12381G2Basic::sign(&secret, message).unwrap();
        let second_duplicate = Bls12381G2Basic::sign(&second_secret, message).unwrap();
        let duplicate_aggregate =
            Bls12381G2Basic::aggregate(&[first_duplicate, second_duplicate]).unwrap();
        assert!(Bls12381G2Basic::aggregate_verify(
            &[public.clone(), second_public],
            &[message, message],
            &duplicate_aggregate,
        )
        .is_err());
    }

    // The direct pairing and multi-Miller APIs must agree for the same public
    // points. This is an internal invariant, not independent evidence.
    let g1 = G1Affine::from(G1Projective::generator());
    let g2 = G2Affine::from(G2Projective::generator());
    let prepared = G2Prepared::from(g2.clone());
    assert_eq!(
        pairing(&g1, &g2),
        multi_miller_loop(&[(&g1, &prepared)]).final_exponentiation()
    );
});
