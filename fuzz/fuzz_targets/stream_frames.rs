#![no_main]
#![forbid(unsafe_code)]

use dcrypt_symmetric::streaming::chacha20poly1305::{
    ChaCha20Poly1305DecryptStream, ChaCha20Poly1305EncryptStream,
};
use dcrypt_symmetric::streaming::gcm::{Aes128GcmDecryptStream, Aes128GcmEncryptStream};
use dcrypt_symmetric::streaming::{StreamingDecrypt, StreamingEncrypt};
use dcrypt_symmetric::{Aes128Key, ChaCha20Poly1305Key, ChaCha20Rng};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

const INPUT_MAX: usize = 64 * 1024;
const MAGIC: &[u8; 8] = b"DCRSTRM2";
const VERSION: u8 = 2;
const HEADER_SIZE: usize = 8 + 1 + 1 + 16 + 12;
const FRAME_HEADER_SIZE: usize = 8 + 1 + 4 + 4;
const SEMANTIC_PLAINTEXT_MAX: usize = 4 * 1024;
const SEMANTIC_READ_MAX: usize = SEMANTIC_PLAINTEXT_MAX + 2;

fn normalized_frame(input: &[u8], algorithm: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; HEADER_SIZE + FRAME_HEADER_SIZE];
    bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    bytes[8] = VERSION;
    bytes[9] = algorithm;

    let frame_header = &mut bytes[HEADER_SIZE..HEADER_SIZE + FRAME_HEADER_SIZE];
    let copied = frame_header.len().min(input.len());
    frame_header[..copied].copy_from_slice(&input[..copied]);

    // Preserve an arbitrary ciphertext tail while capping each iteration's
    // memory and I/O work. The transmitted u32 lengths remain fully arbitrary.
    if input.len() > copied {
        bytes.extend_from_slice(&input[copied..]);
    }
    bytes
}

fn consume_gcm(bytes: &[u8], read_size: usize) {
    let key = Aes128Key::new([0x42; 16]);
    let Ok(mut stream) = Aes128GcmDecryptStream::new(Cursor::new(bytes), &key, Some(b"fuzz"))
    else {
        return;
    };
    let mut output = vec![0u8; read_size];
    for _ in 0..4096 {
        match stream.read(&mut output) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

fn consume_chacha(bytes: &[u8], read_size: usize) {
    let key = ChaCha20Poly1305Key::new([0x24; 32]);
    let Ok(mut stream) =
        ChaCha20Poly1305DecryptStream::new(Cursor::new(bytes), &key, Some(b"fuzz"))
    else {
        return;
    };
    let mut output = vec![0u8; read_size];
    for _ in 0..4096 {
        match stream.read(&mut output) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

fn rejects_gcm(bytes: &[u8], aad: &[u8], read_size: usize) -> bool {
    let key = Aes128Key::new([0x42; 16]);
    let Ok(mut stream) = Aes128GcmDecryptStream::new(Cursor::new(bytes), &key, Some(aad)) else {
        return true;
    };
    let mut output = vec![0u8; read_size];
    for _ in 0..4096 {
        match stream.read(&mut output) {
            Err(_) => return true,
            Ok(0) => return false,
            Ok(_) => {}
        }
    }
    false
}

fn rejects_chacha(bytes: &[u8], aad: &[u8], read_size: usize) -> bool {
    let key = ChaCha20Poly1305Key::new([0x24; 32]);
    let Ok(mut stream) = ChaCha20Poly1305DecryptStream::new(Cursor::new(bytes), &key, Some(aad))
    else {
        return true;
    };
    let mut output = vec![0u8; read_size];
    for _ in 0..4096 {
        match stream.read(&mut output) {
            Err(_) => return true,
            Ok(0) => return false,
            Ok(_) => {}
        }
    }
    false
}

fn semantic_roundtrip(input: &[u8], read_size: usize, use_chacha: bool) {
    let plaintext = input
        .get(1..)
        .unwrap_or_default()
        .get(..input.len().saturating_sub(1).min(SEMANTIC_PLAINTEXT_MAX))
        .unwrap_or_default();
    let aad = input.get(..input.len().min(31)).unwrap_or_default();
    let mut seed = [0u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = input
            .get(index % input.len().max(1))
            .copied()
            .unwrap_or(index as u8)
            .wrapping_add(index as u8);
    }
    let ciphertext = if use_chacha {
        let key = ChaCha20Poly1305Key::new([0x24; 32]);
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut encryptor =
            ChaCha20Poly1305EncryptStream::new(Vec::new(), &key, Some(aad), &mut rng)
                .expect("bounded stream inputs are valid");
        encryptor.write(plaintext).unwrap();
        encryptor.finalize().unwrap()
    } else {
        let key = Aes128Key::new([0x42; 16]);
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut encryptor = Aes128GcmEncryptStream::new(Vec::new(), &key, Some(aad), &mut rng)
            .expect("bounded stream inputs are valid");
        encryptor.write(plaintext).unwrap();
        encryptor.finalize().unwrap()
    };

    let mut recovered = Vec::new();
    let mut output = vec![0u8; read_size];
    if use_chacha {
        let key = ChaCha20Poly1305Key::new([0x24; 32]);
        let mut decryptor =
            ChaCha20Poly1305DecryptStream::new(Cursor::new(&ciphertext), &key, Some(aad)).unwrap();
        for _ in 0..SEMANTIC_READ_MAX {
            match decryptor.read(&mut output) {
                Ok(0) => break,
                Ok(read) => recovered.extend_from_slice(&output[..read]),
                Err(error) => panic!("generated ChaCha stream decrypts: {error}"),
            }
        }
    } else {
        let key = Aes128Key::new([0x42; 16]);
        let mut decryptor =
            Aes128GcmDecryptStream::new(Cursor::new(&ciphertext), &key, Some(aad)).unwrap();
        for _ in 0..SEMANTIC_READ_MAX {
            match decryptor.read(&mut output) {
                Ok(0) => break,
                Ok(read) => recovered.extend_from_slice(&output[..read]),
                Err(error) => panic!("generated AES-GCM stream decrypts: {error}"),
            }
        }
    }
    assert_eq!(recovered, plaintext);

    let mut wrong_aad = aad.to_vec();
    if wrong_aad.is_empty() {
        wrong_aad.push(1);
    } else {
        wrong_aad[0] ^= 1;
    }
    if use_chacha {
        assert!(rejects_chacha(&ciphertext, &wrong_aad, read_size));
    } else {
        assert!(rejects_gcm(&ciphertext, &wrong_aad, read_size));
    }

    let mut tampered = ciphertext;
    let index = tampered.len().saturating_sub(1);
    tampered[index] ^= 1;
    if use_chacha {
        assert!(rejects_chacha(&tampered, aad, read_size));
    } else {
        assert!(rejects_gcm(&tampered, aad, read_size));
    }
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];
    let read_size = 1 + usize::from(input.first().copied().unwrap_or(0) % 64);

    // Raw input covers legacy/truncated/malformed headers.
    consume_gcm(input, read_size);
    consume_chacha(input, read_size);

    // Normalized headers reach sequence, flag, and both u32 length checks even
    // when the fuzzer has not yet discovered the stream magic by mutation.
    consume_gcm(&normalized_frame(input, 1), read_size);
    consume_chacha(&normalized_frame(input, 3), read_size);

    semantic_roundtrip(
        input,
        read_size,
        input.first().copied().unwrap_or(0) & 1 == 1,
    );
});
