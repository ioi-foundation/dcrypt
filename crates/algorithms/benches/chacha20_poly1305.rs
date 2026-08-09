//! Benchmarks for ChaCha20-Poly1305 authenticated encryption
//!
//! This benchmark suite tests the performance of ChaCha20-Poly1305
//! for various message sizes and AAD configurations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dcrypt_algorithms::aead::chacha20poly1305::{
    ChaCha20Poly1305, CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_NONCE_SIZE,
};
use dcrypt_algorithms::types::Nonce;
use dcrypt_internal::random::{ChaCha20Rng, RngCore};

/// Benchmark ChaCha20-Poly1305 setup (key schedule initialization)
fn bench_chacha20poly1305_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305_setup");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    group.bench_function("new", |b| {
        let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
        rng.fill_bytes(&mut key);

        b.iter(|| {
            let cipher = ChaCha20Poly1305::new(black_box(&key));
            black_box(cipher);
        });
    });

    group.finish();
}

/// Benchmark ChaCha20-Poly1305 encryption with various message sizes
fn bench_chacha20poly1305_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305_encrypt");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Test different message sizes
    let sizes = [64, 256, 1024, 4096, 16384, 65536];

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill_bytes(&mut key);
    let cipher = ChaCha20Poly1305::new(&key);

    for size in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let mut plaintext = vec![0u8; size];
            rng.fill_bytes(&mut plaintext[..]);

            let mut nonce_bytes = [0u8; CHACHA20POLY1305_NONCE_SIZE];
            rng.fill_bytes(&mut nonce_bytes);
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

/// Benchmark ChaCha20-Poly1305 decryption with various message sizes
fn bench_chacha20poly1305_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305_decrypt");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Test different message sizes
    let sizes = [64, 256, 1024, 4096, 16384, 65536];

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill_bytes(&mut key);
    let cipher = ChaCha20Poly1305::new(&key);

    for size in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let mut plaintext = vec![0u8; size];
            rng.fill_bytes(&mut plaintext[..]);

            let mut nonce_bytes = [0u8; CHACHA20POLY1305_NONCE_SIZE];
            rng.fill_bytes(&mut nonce_bytes);
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

/// Benchmark ChaCha20-Poly1305 with Additional Authenticated Data (AAD)
fn bench_chacha20poly1305_with_aad(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305_with_aad");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Fixed message size, varying AAD size
    let message_size = 4096;
    let aad_sizes = [16, 64, 256, 1024];

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill_bytes(&mut key);
    let cipher = ChaCha20Poly1305::new(&key);

    for aad_size in &aad_sizes {
        // Total throughput is message + AAD
        group.throughput(Throughput::Bytes((message_size + aad_size) as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("aad_{}", aad_size)),
            aad_size,
            |b, &aad_size| {
                let mut plaintext = vec![0u8; message_size];
                rng.fill_bytes(&mut plaintext[..]);
                let mut aad = vec![0u8; aad_size];
                rng.fill_bytes(&mut aad[..]);

                let mut nonce_bytes = [0u8; CHACHA20POLY1305_NONCE_SIZE];
                rng.fill_bytes(&mut nonce_bytes);
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
fn bench_chacha20poly1305_small_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305_small_messages");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Small message sizes common in protocols
    let sizes = [16, 32, 64, 128, 256];

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill_bytes(&mut key);
    let cipher = ChaCha20Poly1305::new(&key);

    for size in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let mut plaintext = vec![0u8; size];
            rng.fill_bytes(&mut plaintext[..]);

            let mut nonce_bytes = [0u8; CHACHA20POLY1305_NONCE_SIZE];
            rng.fill_bytes(&mut nonce_bytes);
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

/// Benchmark nonce generation and usage patterns
fn bench_chacha20poly1305_nonce_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305_nonce_patterns");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    let message_size = 1024;
    let mut plaintext = vec![0u8; message_size];
    rng.fill_bytes(&mut plaintext[..]);

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill_bytes(&mut key);
    let cipher = ChaCha20Poly1305::new(&key);

    group.throughput(Throughput::Bytes(message_size as u64));

    // Random nonce (most common pattern)
    group.bench_function("random_nonce", |b| {
        b.iter(|| {
            let mut nonce_bytes = [0u8; CHACHA20POLY1305_NONCE_SIZE];
            rng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::new(nonce_bytes);

            let ciphertext = cipher
                .encrypt(black_box(&nonce), black_box(&plaintext), None)
                .unwrap();
            black_box(ciphertext);
        });
    });

    // Counter-based nonce
    group.bench_function("counter_nonce", |b| {
        let mut counter = 0u64;

        b.iter(|| {
            let mut nonce_bytes = [0u8; CHACHA20POLY1305_NONCE_SIZE];
            nonce_bytes[..8].copy_from_slice(&counter.to_le_bytes());
            counter = counter.wrapping_add(1);
            let nonce = Nonce::new(nonce_bytes);

            let ciphertext = cipher
                .encrypt(black_box(&nonce), black_box(&plaintext), None)
                .unwrap();
            black_box(ciphertext);
        });
    });

    group.finish();
}

/// Benchmark parallel encryption (simulating concurrent operations)
fn bench_chacha20poly1305_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305_parallel");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Process 8 messages in parallel
    let message_count = 8;
    let message_size = 1024;
    group.throughput(Throughput::Bytes((message_count * message_size) as u64));

    // Setup key and cipher
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    rng.fill_bytes(&mut key);
    let cipher = ChaCha20Poly1305::new(&key);

    group.bench_function("8_messages", |b| {
        // Prepare messages and nonces
        let mut messages = vec![[0u8; 1024]; message_count];
        let mut nonces = vec![[0u8; CHACHA20POLY1305_NONCE_SIZE]; message_count];

        for i in 0..message_count {
            rng.fill_bytes(&mut messages[i]);
            rng.fill_bytes(&mut nonces[i]);
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
    bench_chacha20poly1305_setup,
    bench_chacha20poly1305_encrypt,
    bench_chacha20poly1305_decrypt,
    bench_chacha20poly1305_with_aad,
    bench_chacha20poly1305_small_messages,
    bench_chacha20poly1305_nonce_patterns,
    bench_chacha20poly1305_parallel
);
criterion_main!(benches);
