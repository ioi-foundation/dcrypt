#![no_main]

use dcrypt_legacy_xchacha20poly1305_migration::decrypt_legacy_v1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 57 {
        return;
    }

    let key: &[u8; 32] = data[..32].try_into().unwrap();
    let nonce: &[u8; 24] = data[32..56].try_into().unwrap();
    let aad_len = usize::from(data[56]).min(data.len() - 57);
    let (aad, ciphertext) = data[57..].split_at(aad_len);
    let _ = decrypt_legacy_v1(key, nonce, ciphertext, Some(aad));
});
