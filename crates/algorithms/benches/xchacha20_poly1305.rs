//! Benchmarks for XChaCha20-Poly1305 authenticated encryption
//!
//! This benchmark suite tests the performance of XChaCha20-Poly1305
//! with its extended 24-byte nonce for various message sizes and configurations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dcrypt_algorithms::aead::chacha20poly1305::CHACHA20POLY1305_KEY_SIZE;
use dcrypt_algorithms::aead::xchacha20poly1305::{XChaCha20Poly1305, XCHACHA20POLY1305_NONCE_SIZE};
use dcrypt_algorithms::types::Nonce;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Benchmark XChaCha20-Poly1305 setup (key schedule initialization)
fn bench_xchacha20poly1305_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20poly1305_setup");
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    group.bench_function("new", |b| {
        let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
        rng.fill(&mut key);

        b.iter(|| {
            let cipher = XChaCha20Poly1305::new(black_box(&key));
            black_box(cipher);
        });
    });

    group.finish();
}

/// Benchmark XChaCha20-Poly1305 encryption with various message sizes
fn bench_xchacha20poly1305_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20poly1305_encrypt");
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    // Test different message sizes
    let sizes = [64, 256, 1024, 4096, 16384, 65536];

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill(&mut key);
    let cipher = XChaCha20Poly1305::new(&key);

    for size in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let mut plaintext = vec![0u8; size];
            rng.fill(&mut plaintext[..]);

            let mut nonce_bytes = [0u8; XCHACHA20POLY1305_NONCE_SIZE];
            rng.fill(&mut nonce_bytes);
            let nonce = Nonce::new(nonce_bytes);

            b.iter(|| {
                let ciphertext = cipher
                    .encrypt(black_box(&nonce), black_box(&plaintext), None)
                    .unwrap();
                black_box(ciphertext);
            });
        });
    }

    group.finish();
}

/// Benchmark XChaCha20-Poly1305 decryption with various message sizes
fn bench_xchacha20poly1305_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20poly1305_decrypt");
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    // Test different message sizes
    let sizes = [64, 256, 1024, 4096, 16384, 65536];

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill(&mut key);
    let cipher = XChaCha20Poly1305::new(&key);

    for size in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let mut plaintext = vec![0u8; size];
            rng.fill(&mut plaintext[..]);

            let mut nonce_bytes = [0u8; XCHACHA20POLY1305_NONCE_SIZE];
            rng.fill(&mut nonce_bytes);
            let nonce = Nonce::new(nonce_bytes);

            // Pre-encrypt the data
            let ciphertext = cipher.encrypt(&nonce, &plaintext, None).unwrap();

            b.iter(|| {
                let plaintext = cipher
                    .decrypt(black_box(&nonce), black_box(&ciphertext), None)
                    .unwrap();
                black_box(plaintext);
            });
        });
    }

    group.finish();
}

/// Benchmark XChaCha20-Poly1305 with Additional Authenticated Data (AAD)
fn bench_xchacha20poly1305_with_aad(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20poly1305_with_aad");
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    // Fixed message size, varying AAD size
    let message_size = 4096;
    let aad_sizes = [16, 64, 256, 1024];

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill(&mut key);
    let cipher = XChaCha20Poly1305::new(&key);

    for aad_size in &aad_sizes {
        // Total throughput is message + AAD
        group.throughput(Throughput::Bytes((message_size + aad_size) as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("aad_{}", aad_size)),
            aad_size,
            |b, &aad_size| {
                let mut plaintext = vec![0u8; message_size];
                rng.fill(&mut plaintext[..]);
                let mut aad = vec![0u8; aad_size];
                rng.fill(&mut aad[..]);

                let mut nonce_bytes = [0u8; XCHACHA20POLY1305_NONCE_SIZE];
                rng.fill(&mut nonce_bytes);
                let nonce = Nonce::new(nonce_bytes);

                b.iter(|| {
                    let ciphertext = cipher
                        .encrypt(
                            black_box(&nonce),
                            black_box(&plaintext),
                            Some(black_box(&aad)),
                        )
                        .unwrap();
                    black_box(ciphertext);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark small message sizes (common in protocols)
fn bench_xchacha20poly1305_small_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20poly1305_small_messages");
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    // Small message sizes common in protocols
    let sizes = [16, 32, 64, 128, 256];

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill(&mut key);
    let cipher = XChaCha20Poly1305::new(&key);

    for size in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let mut plaintext = vec![0u8; size];
            rng.fill(&mut plaintext[..]);

            let mut nonce_bytes = [0u8; XCHACHA20POLY1305_NONCE_SIZE];
            rng.fill(&mut nonce_bytes);
            let nonce = Nonce::new(nonce_bytes);

            b.iter(|| {
                let ciphertext = cipher
                    .encrypt(black_box(&nonce), black_box(&plaintext), None)
                    .unwrap();
                black_box(ciphertext);
            });
        });
    }

    group.finish();
}

/// Benchmark advantage of XChaCha20's extended nonce
fn bench_xchacha20poly1305_nonce_advantage(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20poly1305_nonce_advantage");
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    let message_size = 1024;
    let mut plaintext = vec![0u8; message_size];
    rng.fill(&mut plaintext[..]);

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill(&mut key);
    let cipher = XChaCha20Poly1305::new(&key);

    group.throughput(Throughput::Bytes(message_size as u64));

    // Fully random 24-byte nonce (main advantage of XChaCha20)
    group.bench_function("random_24byte_nonce", |b| {
        b.iter(|| {
            let mut nonce_bytes = [0u8; XCHACHA20POLY1305_NONCE_SIZE];
            rng.fill(&mut nonce_bytes);
            let nonce = Nonce::new(nonce_bytes);

            let ciphertext = cipher
                .encrypt(black_box(&nonce), black_box(&plaintext), None)
                .unwrap();
            black_box(ciphertext);
        });
    });

    group.finish();
}

/// Compare XChaCha20-Poly1305 vs ChaCha20-Poly1305 setup overhead
fn bench_xchacha20poly1305_vs_chacha20_setup(c: &mut Criterion) {
    use dcrypt_algorithms::aead::chacha20poly1305::ChaCha20Poly1305;

    let mut group = c.benchmark_group("xchacha20_vs_chacha20_setup");
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    let message_size = 1024;
    let mut plaintext = vec![0u8; message_size];
    rng.fill(&mut plaintext[..]);

    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill(&mut key);

    group.throughput(Throughput::Bytes(message_size as u64));

    // XChaCha20-Poly1305 (with HChaCha20 overhead)
    group.bench_function("xchacha20_poly1305", |b| {
        let cipher = XChaCha20Poly1305::new(&key);

        b.iter(|| {
            let mut nonce_bytes = [0u8; XCHACHA20POLY1305_NONCE_SIZE];
            rng.fill(&mut nonce_bytes);
            let nonce = Nonce::new(nonce_bytes);

            let ciphertext = cipher
                .encrypt(black_box(&nonce), black_box(&plaintext), None)
                .unwrap();
            black_box(ciphertext);
        });
    });

    // ChaCha20-Poly1305 (baseline)
    group.bench_function("chacha20_poly1305", |b| {
        let cipher = ChaCha20Poly1305::new(&key);

        b.iter(|| {
            let mut nonce_bytes = [0u8; 12];
            rng.fill(&mut nonce_bytes);
            let nonce = Nonce::new(nonce_bytes);

            let ciphertext = cipher
                .encrypt(black_box(&nonce), black_box(&plaintext), None)
                .unwrap();
            black_box(ciphertext);
        });
    });

    group.finish();
}

/// Benchmark parallel encryption with XChaCha20-Poly1305
fn bench_xchacha20poly1305_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20poly1305_parallel");
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    // Process 8 messages in parallel
    let message_count = 8;
    let message_size = 1024;
    group.throughput(Throughput::Bytes((message_count * message_size) as u64));

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill(&mut key);
    let cipher = XChaCha20Poly1305::new(&key);

    group.bench_function("8_messages", |b| {
        // Prepare messages and nonces
        let mut messages = vec![[0u8; 1024]; message_count];
        let mut nonces = vec![[0u8; XCHACHA20POLY1305_NONCE_SIZE]; message_count];

        for i in 0..message_count {
            rng.fill(&mut messages[i]);
            rng.fill(&mut nonces[i]);
        }

        b.iter(|| {
            let mut results = Vec::with_capacity(message_count);

            for i in 0..message_count {
                let nonce = Nonce::new(nonces[i]);
                let ciphertext = cipher.encrypt(&nonce, &messages[i], None).unwrap();
                results.push(ciphertext);
            }

            black_box(results);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_xchacha20poly1305_setup,
    bench_xchacha20poly1305_encrypt,
    bench_xchacha20poly1305_decrypt,
    bench_xchacha20poly1305_with_aad,
    bench_xchacha20poly1305_small_messages,
    bench_xchacha20poly1305_nonce_advantage,
    bench_xchacha20poly1305_vs_chacha20_setup,
    bench_xchacha20poly1305_parallel
);
criterion_main!(benches);
