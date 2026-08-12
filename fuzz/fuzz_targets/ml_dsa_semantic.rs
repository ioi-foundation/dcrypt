#![no_main]
#![forbid(unsafe_code)]

mod support;

use dcrypt_api::Signature;
use dcrypt_sign::mldsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaSignature};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 2 * 1024;
const MAGIC: &[u8] = b"DCRYPT:MLDSA:V1:";

macro_rules! exercise {
    ($scheme:ty, $input:expr, $domain:expr, $hedged:expr) => {{
        let mut rng = support::rng($input, $domain);
        let keypair = <$scheme>::keypair(&mut rng).expect("input RNG yields a keypair");
        let public_key = <$scheme>::public_key(&keypair);
        let secret_key = <$scheme>::secret_key(&keypair);
        let message = support::message($input, 2, 512);
        let context_len = usize::from($input.get(1).copied().unwrap_or(0) % 33);
        let context_seed = support::seed($input, $domain.wrapping_add(1));
        let context = &context_seed[..context_len];

        let signature = if $hedged {
            let mut hedge_rng = support::rng($input, $domain.wrapping_add(2));
            <$scheme>::sign_with_context_rng(message, context, &secret_key, &mut hedge_rng)
                .expect("hedged signing succeeds")
        } else {
            let signature =
                <$scheme>::sign_deterministic_with_context(message, context, &secret_key)
                    .expect("deterministic signing succeeds");
            let repeated =
                <$scheme>::sign_deterministic_with_context(message, context, &secret_key)
                    .expect("repeated deterministic signing succeeds");
            assert_eq!(signature.to_bytes(), repeated.to_bytes());
            signature
        };
        <$scheme>::verify_with_context(message, context, &signature, &public_key)
            .expect("generated signature verifies");

        let parsed = MlDsaSignature::from_bytes(signature.to_bytes())
            .expect("generated signature encoding roundtrips");
        <$scheme>::verify_with_context(message, context, &parsed, &public_key)
            .expect("roundtripped signature verifies");

        let different_message = support::tamper(message, usize::from($domain));
        assert!(<$scheme>::verify_with_context(
            &different_message,
            context,
            &signature,
            &public_key
        )
        .is_err());

        let modified = support::tamper(signature.to_bytes(), usize::from($domain) + 7);
        if let Ok(modified) = MlDsaSignature::from_bytes(&modified) {
            assert!(
                <$scheme>::verify_with_context(message, context, &modified, &public_key).is_err()
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
    let hedged = input.get(1).copied() == Some(b'H');
    match support::selector(selector, 3) {
        0 => exercise!(MlDsa44, input, 0x41u8, hedged),
        1 => exercise!(MlDsa65, input, 0x52u8, hedged),
        _ => exercise!(MlDsa87, input, 0x63u8, hedged),
    }
});
