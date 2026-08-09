// File: crates/kem/benches/ecdh_p256.rs
//! Benchmarks for ECDH-P256 KEM operations
//!
//! This benchmark suite measures the performance of:
//! - Key generation
//! - Encapsulation
//! - Decapsulation
//! - Full round-trip operations

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dcrypt_api::Kem;
use dcrypt_internal::random::ChaCha20Rng;
use dcrypt_kem::ecdh::p256::EcdhP256;
mod support;
use support::TestRng;

/// Benchmark key generation
fn bench_keypair_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P256/Keypair");

    // Benchmark with a caller-provided RNG.
    group.bench_function("CallerRng", |b| {
        let mut rng = TestRng;
        b.iter(|| {
            let keypair = EcdhP256::keypair(&mut rng).unwrap();
            black_box(keypair);
        });
    });

    // Benchmark with ChaCha20Rng (deterministic for consistency)
    group.bench_function("ChaCha20Rng", |b| {
        let mut rng = ChaCha20Rng::from_seed([42; 32]);
        b.iter(|| {
            let keypair = EcdhP256::keypair(&mut rng).unwrap();
            black_box(keypair);
        });
    });

    group.finish();
}

/// Benchmark encapsulation
fn bench_encapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P256/Encapsulate");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Generate a recipient keypair
    let (recipient_pk, _) = EcdhP256::keypair(&mut rng).unwrap();

    group.bench_function("default", |b| {
        b.iter(|| {
            let (ciphertext, shared_secret) =
                EcdhP256::encapsulate(&mut rng, &recipient_pk).unwrap();
            black_box((ciphertext, shared_secret));
        });
    });

    group.finish();
}

/// Benchmark decapsulation
fn bench_decapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P256/Decapsulate");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Generate recipient keypair and create a ciphertext
    let (recipient_pk, recipient_sk) = EcdhP256::keypair(&mut rng).unwrap();
    let (ciphertext, _) = EcdhP256::encapsulate(&mut rng, &recipient_pk).unwrap();

    group.bench_function("default", |b| {
        b.iter(|| {
            let shared_secret = EcdhP256::decapsulate(&recipient_sk, &ciphertext).unwrap();
            black_box(shared_secret);
        });
    });

    group.finish();
}

/// Benchmark full round-trip (keypair + encapsulate + decapsulate)
fn bench_full_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P256/FullRoundtrip");

    group.bench_function("default", |b| {
        let mut rng = ChaCha20Rng::from_seed([42; 32]);
        b.iter(|| {
            // Generate recipient keypair
            let (recipient_pk, recipient_sk) = EcdhP256::keypair(&mut rng).unwrap();

            // Encapsulate
            let (ciphertext, shared_secret_sender) =
                EcdhP256::encapsulate(&mut rng, &recipient_pk).unwrap();

            // Decapsulate
            let shared_secret_recipient =
                EcdhP256::decapsulate(&recipient_sk, &ciphertext).unwrap();

            black_box((shared_secret_sender, shared_secret_recipient));
        });
    });

    group.finish();
}

/// Benchmark parallel operations to test scalability
fn bench_parallel_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P256/Parallel");

    // Test with different numbers of keypairs
    for num_keys in [1, 10, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("keypairs", num_keys),
            num_keys,
            |b, &num_keys| {
                let mut rng = ChaCha20Rng::from_seed([42; 32]);

                // Pre-generate recipient keys
                let recipients: Vec<_> = (0..num_keys)
                    .map(|_| EcdhP256::keypair(&mut rng).unwrap())
                    .collect();

                b.iter(|| {
                    for (pk, _) in &recipients {
                        let (ciphertext, shared_secret) =
                            EcdhP256::encapsulate(&mut rng, pk).unwrap();
                        black_box((ciphertext, shared_secret));
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P256/Memory");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Benchmark key sizes
    group.bench_function("key_sizes", |b| {
        let (pk, sk) = EcdhP256::keypair(&mut rng).unwrap();
        b.iter(|| {
            black_box((pk.as_ref().len(), sk.as_ref().len()));
        });
    });

    // Benchmark ciphertext size
    group.bench_function("ciphertext_size", |b| {
        let (pk, _) = EcdhP256::keypair(&mut rng).unwrap();
        let (ct, _) = EcdhP256::encapsulate(&mut rng, &pk).unwrap();
        b.iter(|| {
            black_box(ct.as_ref().len());
        });
    });

    group.finish();
}

/// Benchmark error cases and edge conditions
fn bench_error_cases(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P256/ErrorCases");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Benchmark invalid public key handling (identity point)
    group.bench_function("invalid_public_key", |b| {
        // Create a valid public key first, then modify it to be invalid
        let (mut invalid_pk, _) = EcdhP256::keypair(&mut rng).unwrap();
        // Set all bytes to zero to create an invalid identity point
        invalid_pk.as_mut().fill(0);

        b.iter(|| {
            let result = EcdhP256::encapsulate(&mut rng, &invalid_pk);
            black_box(result.is_err());
        });
    });

    // Benchmark invalid ciphertext handling
    group.bench_function("invalid_ciphertext", |b| {
        let (pk, sk) = EcdhP256::keypair(&mut rng).unwrap();
        let (mut invalid_ct, _) = EcdhP256::encapsulate(&mut rng, &pk).unwrap();
        // Set all bytes to zero to create an invalid ciphertext
        invalid_ct.as_mut().fill(0);

        b.iter(|| {
            let result = EcdhP256::decapsulate(&sk, &invalid_ct);
            black_box(result.is_err());
        });
    });

    // Benchmark tampered ciphertext handling
    group.bench_function("tampered_ciphertext", |b| {
        let (pk, sk) = EcdhP256::keypair(&mut rng).unwrap();
        let (mut tampered_ct, _) = EcdhP256::encapsulate(&mut rng, &pk).unwrap();
        // Tamper with the first byte
        tampered_ct.as_mut()[0] ^= 0xFF;

        b.iter(|| {
            let result = EcdhP256::decapsulate(&sk, &tampered_ct);
            // This might succeed but produce a different shared secret, or it might fail
            let _ = black_box(result);
        });
    });

    group.finish();
}

/// Benchmark KDF performance within the KEM
fn bench_kdf_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P256/KDF");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Measure the overhead of KDF in encapsulation
    group.bench_function("encapsulation_kdf_overhead", |b| {
        let (pk, _) = EcdhP256::keypair(&mut rng).unwrap();

        b.iter(|| {
            // The KDF is included in the encapsulation process
            let (_, shared_secret) = EcdhP256::encapsulate(&mut rng, &pk).unwrap();
            // The shared secret is derived through HKDF-SHA256
            black_box(shared_secret.as_ref().len());
        });
    });

    group.finish();
}

/// Compare compressed vs uncompressed point operations (if applicable)
fn bench_point_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P256/Compression");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Benchmark serialization/deserialization of compressed points
    group.bench_function("compressed_point_operations", |b| {
        let (pk, _) = EcdhP256::keypair(&mut rng).unwrap();

        b.iter(|| {
            // The implementation uses compressed points internally
            let pk_bytes = pk.as_ref();
            // P-256 compressed point is 33 bytes (1 byte prefix + 32 bytes x-coordinate)
            black_box(pk_bytes);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_keypair_generation,
    bench_encapsulation,
    bench_decapsulation,
    bench_full_roundtrip,
    bench_parallel_operations,
    bench_memory_patterns,
    bench_error_cases,
    bench_kdf_performance,
    bench_point_compression
);

criterion_main!(benches);
