//! Benchmarks for AES-GCM authenticated encryption
//!
//! This benchmark suite tests the performance of AES-GCM with different key sizes
//! (128, 192, 256 bits) and various message/AAD sizes.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dcrypt_algorithms::aead::gcm::Gcm;
use dcrypt_algorithms::block::{Aes128, Aes192, Aes256, BlockCipher};
use dcrypt_algorithms::types::{Nonce, SecretBytes};
use dcrypt_internal::random::{ChaCha20Rng, RngCore};

/// Benchmark GCM setup (key schedule + GCM initialization)
fn bench_gcm_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_setup");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Standard 96-bit nonce
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::<12>::new(nonce_bytes);

    // AES-128-GCM
    group.bench_function("aes128_gcm", |b| {
        let mut key_bytes = [0u8; 16];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);

        b.iter(|| {
            let cipher = Aes128::new(black_box(&key));
            black_box(&nonce);
            let gcm = Gcm::new(cipher).unwrap();
            black_box(gcm);
        });
    });

    // AES-192-GCM
    group.bench_function("aes192_gcm", |b| {
        let mut key_bytes = [0u8; 24];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);

        b.iter(|| {
            let cipher = Aes192::new(black_box(&key));
            black_box(&nonce);
            let gcm = Gcm::new(cipher).unwrap();
            black_box(gcm);
        });
    });

    // AES-256-GCM
    group.bench_function("aes256_gcm", |b| {
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);

        b.iter(|| {
            let cipher = Aes256::new(black_box(&key));
            black_box(&nonce);
            let gcm = Gcm::new(cipher).unwrap();
            black_box(gcm);
        });
    });

    group.finish();
}

/// Benchmark GCM encryption with various message sizes
fn bench_gcm_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_encrypt");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Test different message sizes
    let sizes = [64, 256, 1024, 4096, 16384, 65536];

    // Setup keys and nonce
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::<12>::new(nonce_bytes);

    for size in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        // AES-128-GCM
        {
            let mut key_bytes = [0u8; 16];
            rng.fill_bytes(&mut key_bytes);
            let key = SecretBytes::new(key_bytes);
            let cipher = Aes128::new(&key);
            let gcm = Gcm::new(cipher).unwrap();

            group.bench_with_input(BenchmarkId::new("aes128_gcm", size), size, |b, &size| {
                let mut plaintext = vec![0u8; size];
                rng.fill_bytes(&mut plaintext[..]);

                b.iter(|| {
                    let ciphertext = gcm
                        .internal_encrypt(&nonce, black_box(&plaintext), None)
                        .unwrap();
                    black_box(ciphertext);
                });
            });
        }

        // AES-256-GCM
        {
            let mut key_bytes = [0u8; 32];
            rng.fill_bytes(&mut key_bytes);
            let key = SecretBytes::new(key_bytes);
            let cipher = Aes256::new(&key);
            let gcm = Gcm::new(cipher).unwrap();

            group.bench_with_input(BenchmarkId::new("aes256_gcm", size), size, |b, &size| {
                let mut plaintext = vec![0u8; size];
                rng.fill_bytes(&mut plaintext[..]);

                b.iter(|| {
                    let ciphertext = gcm
                        .internal_encrypt(&nonce, black_box(&plaintext), None)
                        .unwrap();
                    black_box(ciphertext);
                });
            });
        }
    }

    group.finish();
}

/// Benchmark GCM decryption with various message sizes
fn bench_gcm_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_decrypt");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Test different message sizes
    let sizes = [64, 256, 1024, 4096, 16384, 65536];

    // Setup keys and nonce
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::<12>::new(nonce_bytes);

    for size in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        // AES-128-GCM
        {
            let mut key_bytes = [0u8; 16];
            rng.fill_bytes(&mut key_bytes);
            let key = SecretBytes::new(key_bytes);
            let cipher = Aes128::new(&key);
            let gcm = Gcm::new(cipher).unwrap();

            group.bench_with_input(BenchmarkId::new("aes128_gcm", size), size, |b, &size| {
                let mut plaintext = vec![0u8; size];
                rng.fill_bytes(&mut plaintext[..]);
                let ciphertext = gcm.internal_encrypt(&nonce, &plaintext, None).unwrap();

                b.iter(|| {
                    let plaintext = gcm
                        .internal_decrypt(&nonce, black_box(&ciphertext), None)
                        .unwrap();
                    black_box(plaintext);
                });
            });
        }

        // AES-256-GCM
        {
            let mut key_bytes = [0u8; 32];
            rng.fill_bytes(&mut key_bytes);
            let key = SecretBytes::new(key_bytes);
            let cipher = Aes256::new(&key);
            let gcm = Gcm::new(cipher).unwrap();

            group.bench_with_input(BenchmarkId::new("aes256_gcm", size), size, |b, &size| {
                let mut plaintext = vec![0u8; size];
                rng.fill_bytes(&mut plaintext[..]);
                let ciphertext = gcm.internal_encrypt(&nonce, &plaintext, None).unwrap();

                b.iter(|| {
                    let plaintext = gcm
                        .internal_decrypt(&nonce, black_box(&ciphertext), None)
                        .unwrap();
                    black_box(plaintext);
                });
            });
        }
    }

    group.finish();
}

/// Benchmark GCM with Additional Authenticated Data (AAD)
fn bench_gcm_with_aad(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_with_aad");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Fixed message size, varying AAD size
    let message_size = 4096;
    let aad_sizes = [16, 64, 256, 1024];

    // Setup keys and nonce
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::<12>::new(nonce_bytes);

    for aad_size in &aad_sizes {
        // Total throughput is message + AAD
        group.throughput(Throughput::Bytes((message_size + aad_size) as u64));

        // AES-128-GCM
        {
            let mut key_bytes = [0u8; 16];
            rng.fill_bytes(&mut key_bytes);
            let key = SecretBytes::new(key_bytes);
            let cipher = Aes128::new(&key);
            let gcm = Gcm::new(cipher).unwrap();

            group.bench_with_input(
                BenchmarkId::new(format!("aes128_gcm_aad_{}", aad_size), aad_size),
                aad_size,
                |b, &aad_size| {
                    let mut plaintext = vec![0u8; message_size];
                    rng.fill_bytes(&mut plaintext[..]);
                    let mut aad = vec![0u8; aad_size];
                    rng.fill_bytes(&mut aad[..]);

                    b.iter(|| {
                        let ciphertext = gcm
                            .internal_encrypt(&nonce, black_box(&plaintext), Some(black_box(&aad)))
                            .unwrap();
                        black_box(ciphertext);
                    });
                },
            );
        }

        // AES-256-GCM
        {
            let mut key_bytes = [0u8; 32];
            rng.fill_bytes(&mut key_bytes);
            let key = SecretBytes::new(key_bytes);
            let cipher = Aes256::new(&key);
            let gcm = Gcm::new(cipher).unwrap();

            group.bench_with_input(
                BenchmarkId::new(format!("aes256_gcm_aad_{}", aad_size), aad_size),
                aad_size,
                |b, &aad_size| {
                    let mut plaintext = vec![0u8; message_size];
                    rng.fill_bytes(&mut plaintext[..]);
                    let mut aad = vec![0u8; aad_size];
                    rng.fill_bytes(&mut aad[..]);

                    b.iter(|| {
                        let ciphertext = gcm
                            .internal_encrypt(&nonce, black_box(&plaintext), Some(black_box(&aad)))
                            .unwrap();
                        black_box(ciphertext);
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark GCM with different nonce sizes
fn bench_gcm_nonce_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_nonce_sizes");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    let message_size = 4096;
    group.throughput(Throughput::Bytes(message_size as u64));

    // AES-128-GCM with 96-bit nonce (standard)
    {
        let mut key_bytes = [0u8; 16];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);

        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::<12>::new(nonce_bytes);

        let cipher = Aes128::new(&key);
        let gcm = Gcm::new(cipher).unwrap();

        group.bench_function("aes128_gcm_96bit_nonce", |b| {
            let mut plaintext = vec![0u8; message_size];
            rng.fill_bytes(&mut plaintext[..]);

            b.iter(|| {
                let ciphertext = gcm
                    .internal_encrypt(&nonce, black_box(&plaintext), None)
                    .unwrap();
                black_box(ciphertext);
            });
        });
    }

    // AES-128-GCM with 128-bit nonce (non-standard)
    {
        let mut key_bytes = [0u8; 16];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);

        let mut nonce_bytes = [0u8; 16];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::<16>::new(nonce_bytes);

        let cipher = Aes128::new(&key);
        let gcm = Gcm::new(cipher).unwrap();

        group.bench_function("aes128_gcm_128bit_nonce", |b| {
            let mut plaintext = vec![0u8; message_size];
            rng.fill_bytes(&mut plaintext[..]);

            b.iter(|| {
                let ciphertext = gcm
                    .internal_encrypt(&nonce, black_box(&plaintext), None)
                    .unwrap();
                black_box(ciphertext);
            });
        });
    }

    group.finish();
}

/// Benchmark small message sizes (common in protocols)
fn bench_gcm_small_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_small_messages");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Small message sizes common in protocols
    let sizes = [16, 32, 64, 128, 256];

    // Setup keys and nonce
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::<12>::new(nonce_bytes);

    for size in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        // AES-128-GCM
        {
            let mut key_bytes = [0u8; 16];
            rng.fill_bytes(&mut key_bytes);
            let key = SecretBytes::new(key_bytes);
            let cipher = Aes128::new(&key);
            let gcm = Gcm::new(cipher).unwrap();

            group.bench_with_input(BenchmarkId::new("aes128_gcm", size), size, |b, &size| {
                let mut plaintext = vec![0u8; size];
                rng.fill_bytes(&mut plaintext[..]);

                b.iter(|| {
                    let ciphertext = gcm
                        .internal_encrypt(&nonce, black_box(&plaintext), None)
                        .unwrap();
                    black_box(ciphertext);
                });
            });
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_gcm_setup,
    bench_gcm_encrypt,
    bench_gcm_decrypt,
    bench_gcm_with_aad,
    bench_gcm_nonce_sizes,
    bench_gcm_small_messages
);
criterion_main!(benches);
