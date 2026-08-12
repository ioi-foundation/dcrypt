#![no_main]
#![forbid(unsafe_code)]

mod support;

use dcrypt_api::traits::Pke;
use dcrypt_pke::{EciesP224, EciesP256, EciesP384, EciesP521};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 32 * 1024;
const MAGIC: &[u8] = b"DCRYPT:ECIES:V1:";

macro_rules! exercise {
    ($scheme:ty, $input:expr, $domain:expr) => {{
        let mut key_rng = support::rng($input, $domain);
        let (public, secret) =
            <$scheme>::keypair(&mut key_rng).expect("input RNG yields an ECIES keypair");
        let plaintext = support::message($input, 1, 16 * 1024);
        let aad_len = usize::from($input.first().copied().unwrap_or(0) % 33);
        let aad_material = support::seed($input, $domain.wrapping_add(1));
        let aad = &aad_material[..aad_len];
        let mut encryption_rng = support::rng($input, $domain.wrapping_add(2));
        let ciphertext = <$scheme>::encrypt(&public, plaintext, Some(aad), &mut encryption_rng)
            .expect("ECIES encryption succeeds");
        assert_eq!(
            <$scheme>::decrypt(&secret, &ciphertext, Some(aad)).unwrap(),
            plaintext
        );

        let modified = support::tamper(ciphertext.as_ref(), usize::from($domain));
        assert!(<$scheme>::decrypt(&secret, &modified, Some(aad)).is_err());
        let wrong_aad = support::tamper(aad, usize::from($domain) + 1);
        assert!(<$scheme>::decrypt(&secret, &ciphertext, Some(&wrong_aad)).is_err());
        let truncated = ciphertext[..ciphertext.len().saturating_sub(1)].to_vec();
        assert!(<$scheme>::decrypt(&secret, &truncated, Some(aad)).is_err());
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
    match support::selector(selector, 4) {
        0 => exercise!(EciesP224, input, 0xf1u8),
        1 => exercise!(EciesP256, input, 0xf2u8),
        2 => exercise!(EciesP384, input, 0xf3u8),
        _ => exercise!(EciesP521, input, 0xf4u8),
    }
});
