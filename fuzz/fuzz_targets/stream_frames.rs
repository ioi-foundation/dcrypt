#![no_main]
#![forbid(unsafe_code)]

use dcrypt_symmetric::streaming::chacha20poly1305::ChaCha20Poly1305DecryptStream;
use dcrypt_symmetric::streaming::gcm::Aes128GcmDecryptStream;
use dcrypt_symmetric::streaming::StreamingDecrypt;
use dcrypt_symmetric::{Aes128Key, ChaCha20Poly1305Key};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

const INPUT_MAX: usize = 64 * 1024;
const MAGIC: &[u8; 8] = b"DCRSTRM2";
const VERSION: u8 = 2;
const HEADER_SIZE: usize = 8 + 1 + 1 + 16 + 12;
const FRAME_HEADER_SIZE: usize = 8 + 1 + 4 + 4;

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
});
