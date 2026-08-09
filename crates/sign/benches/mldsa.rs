//! Benchmarks for ML-DSA digital signature algorithms (FIPS 204).
//!
//! This module benchmarks the performance of MlDsa44, MlDsa65, and MlDsa87
//! across key generation, signing, and verification operations with various message sizes.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dcrypt_api::Signature;
use dcrypt_internal::ChaCha20Rng;
use dcrypt_sign::mldsa::{MlDsa44, MlDsa65, MlDsa87};

/// Message sizes to benchmark (in bytes)
const MESSAGE_SIZES: &[usize] = &[
    32,    // Small message (hash size)
    256,   // Medium message
    1024,  // 1 KB
    4096,  // 4 KB
    16384, // 16 KB
    65536, // 64 KB
];

/// Benchmark key generation for all ML-DSA parameter sets
fn bench_keypair(c: &mut Criterion) {
    let mut group = c.benchmark_group("mldsa_keypair");

    // Fixed RNG for reproducibility
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    group.bench_function("mldsa2", |b| {
        b.iter(|| {
            let _ = black_box(MlDsa44::keypair(&mut rng).unwrap());
        });
    });

    group.bench_function("mldsa3", |b| {
        b.iter(|| {
            let _ = black_box(MlDsa65::keypair(&mut rng).unwrap());
        });
    });

    group.bench_function("mldsa5", |b| {
        b.iter(|| {
            let _ = black_box(MlDsa87::keypair(&mut rng).unwrap());
        });
    });

    group.finish();
}

/// Benchmark signing operations for different message sizes
fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("mldsa_sign");

    // Generate keypairs once
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (_, sk2) = MlDsa44::keypair(&mut rng).unwrap();
    let (_, sk3) = MlDsa65::keypair(&mut rng).unwrap();
    let (_, sk5) = MlDsa87::keypair(&mut rng).unwrap();

    for size in MESSAGE_SIZES {
        let message = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::new("mldsa2", size), size, |b, _| {
            b.iter(|| {
                let _ = black_box(MlDsa44::sign(&message, &sk2).unwrap());
            });
        });

        group.bench_with_input(BenchmarkId::new("mldsa3", size), size, |b, _| {
            b.iter(|| {
                let _ = black_box(MlDsa65::sign(&message, &sk3).unwrap());
            });
        });

        group.bench_with_input(BenchmarkId::new("mldsa5", size), size, |b, _| {
            b.iter(|| {
                let _ = black_box(MlDsa87::sign(&message, &sk5).unwrap());
            });
        });
    }

    group.finish();
}

/// Benchmark verification operations for different message sizes
fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("mldsa_verify");

    // Generate keypairs and signatures once
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (pk2, sk2) = MlDsa44::keypair(&mut rng).unwrap();
    let (pk3, sk3) = MlDsa65::keypair(&mut rng).unwrap();
    let (pk5, sk5) = MlDsa87::keypair(&mut rng).unwrap();

    for size in MESSAGE_SIZES {
        let message = vec![0x42u8; *size];

        // Pre-compute signatures
        let sig2 = MlDsa44::sign(&message, &sk2).unwrap();
        let sig3 = MlDsa65::sign(&message, &sk3).unwrap();
        let sig5 = MlDsa87::sign(&message, &sk5).unwrap();

        group.bench_with_input(BenchmarkId::new("mldsa2", size), size, |b, _| {
            b.iter(|| {
                black_box(MlDsa44::verify(&message, &sig2, &pk2)).unwrap();
            });
        });

        group.bench_with_input(BenchmarkId::new("mldsa3", size), size, |b, _| {
            b.iter(|| {
                black_box(MlDsa65::verify(&message, &sig3, &pk3)).unwrap();
            });
        });

        group.bench_with_input(BenchmarkId::new("mldsa5", size), size, |b, _| {
            b.iter(|| {
                black_box(MlDsa87::verify(&message, &sig5, &pk5)).unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark complete round-trip (keypair + sign + verify) operations
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("mldsa_roundtrip");

    let message = b"Test message for mldsa round-trip benchmark";
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    group.bench_function("mldsa2", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa44::keypair(&mut rng).unwrap();
            let sig = MlDsa44::sign(message, &sk).unwrap();
            black_box(MlDsa44::verify(message, &sig, &pk)).unwrap();
        });
    });

    group.bench_function("mldsa3", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa65::keypair(&mut rng).unwrap();
            let sig = MlDsa65::sign(message, &sk).unwrap();
            black_box(MlDsa65::verify(message, &sig, &pk)).unwrap();
        });
    });

    group.bench_function("mldsa5", |b| {
        b.iter(|| {
            let (pk, sk) = MlDsa87::keypair(&mut rng).unwrap();
            let sig = MlDsa87::sign(message, &sk).unwrap();
            black_box(MlDsa87::verify(message, &sig, &pk)).unwrap();
        });
    });

    group.finish();
}

/// Benchmark serialization/deserialization operations
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("mldsa_serialization");

    // Generate test data
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let message = b"Test message for serialization benchmark";

    // MlDsa44
    let (pk2, sk2) = MlDsa44::keypair(&mut rng).unwrap();
    let sig2 = MlDsa44::sign(message, &sk2).unwrap();
    let pk2_bytes = pk2.to_bytes();
    let sk2_bytes = sk2.to_bytes();
    let sig2_bytes = sig2.to_bytes();

    // MlDsa65
    let (pk3, sk3) = MlDsa65::keypair(&mut rng).unwrap();
    let sig3 = MlDsa65::sign(message, &sk3).unwrap();
    let pk3_bytes = pk3.to_bytes();
    let sk3_bytes = sk3.to_bytes();
    let sig3_bytes = sig3.to_bytes();

    // MlDsa87
    let (pk5, sk5) = MlDsa87::keypair(&mut rng).unwrap();
    let sig5 = MlDsa87::sign(message, &sk5).unwrap();
    let pk5_bytes = pk5.to_bytes();
    let sk5_bytes = sk5.to_bytes();
    let sig5_bytes = sig5.to_bytes();

    // Benchmark public key deserialization
    group.bench_function("mldsa2_pk_deserialize", |b| {
        b.iter(|| {
            use dcrypt_sign::mldsa::MlDsaPublicKey;
            let _ = black_box(MlDsaPublicKey::from_bytes(pk2_bytes).unwrap());
        });
    });

    group.bench_function("mldsa3_pk_deserialize", |b| {
        b.iter(|| {
            use dcrypt_sign::mldsa::MlDsaPublicKey;
            let _ = black_box(MlDsaPublicKey::from_bytes(pk3_bytes).unwrap());
        });
    });

    group.bench_function("mldsa5_pk_deserialize", |b| {
        b.iter(|| {
            use dcrypt_sign::mldsa::MlDsaPublicKey;
            let _ = black_box(MlDsaPublicKey::from_bytes(pk5_bytes).unwrap());
        });
    });

    // Benchmark secret key deserialization
    group.bench_function("mldsa2_sk_deserialize", |b| {
        b.iter(|| {
            use dcrypt_sign::mldsa::MlDsaSecretKey;
            let _ = black_box(MlDsaSecretKey::from_bytes(sk2_bytes).unwrap());
        });
    });

    group.bench_function("mldsa3_sk_deserialize", |b| {
        b.iter(|| {
            use dcrypt_sign::mldsa::MlDsaSecretKey;
            let _ = black_box(MlDsaSecretKey::from_bytes(sk3_bytes).unwrap());
        });
    });

    group.bench_function("mldsa5_sk_deserialize", |b| {
        b.iter(|| {
            use dcrypt_sign::mldsa::MlDsaSecretKey;
            let _ = black_box(MlDsaSecretKey::from_bytes(sk5_bytes).unwrap());
        });
    });

    // Benchmark signature deserialization
    group.bench_function("mldsa2_sig_deserialize", |b| {
        b.iter(|| {
            use dcrypt_sign::mldsa::MlDsaSignature;
            let _ = black_box(MlDsaSignature::from_bytes(sig2_bytes).unwrap());
        });
    });

    group.bench_function("mldsa3_sig_deserialize", |b| {
        b.iter(|| {
            use dcrypt_sign::mldsa::MlDsaSignature;
            let _ = black_box(MlDsaSignature::from_bytes(sig3_bytes).unwrap());
        });
    });

    group.bench_function("mldsa5_sig_deserialize", |b| {
        b.iter(|| {
            use dcrypt_sign::mldsa::MlDsaSignature;
            let _ = black_box(MlDsaSignature::from_bytes(sig5_bytes).unwrap());
        });
    });

    group.finish();
}

/// Benchmark signing iteration counts (to measure rejection sampling overhead)
/// This benchmark signs the same message multiple times to get statistics on iteration counts
fn bench_signing_iterations(c: &mut Criterion) {
    let mut group = c.benchmark_group("mldsa_signing_iterations");
    group.sample_size(100); // Run 100 iterations to get good statistics

    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    // Generate keypairs
    let (_, sk2) = MlDsa44::keypair(&mut rng).unwrap();
    let (_, sk3) = MlDsa65::keypair(&mut rng).unwrap();
    let (_, sk5) = MlDsa87::keypair(&mut rng).unwrap();

    // We'll use different messages to trigger different iteration counts
    let messages: Vec<Vec<u8>> = (0..10)
        .map(|i| format!("Message variant {}", i).into_bytes())
        .collect();

    group.bench_function("mldsa2_multi_sign", |b| {
        let mut msg_idx = 0;
        b.iter(|| {
            let msg = &messages[msg_idx % messages.len()];
            msg_idx += 1;
            let _ = black_box(MlDsa44::sign(msg, &sk2).unwrap());
        });
    });

    group.bench_function("mldsa3_multi_sign", |b| {
        let mut msg_idx = 0;
        b.iter(|| {
            let msg = &messages[msg_idx % messages.len()];
            msg_idx += 1;
            let _ = black_box(MlDsa65::sign(msg, &sk3).unwrap());
        });
    });

    group.bench_function("mldsa5_multi_sign", |b| {
        let mut msg_idx = 0;
        b.iter(|| {
            let msg = &messages[msg_idx % messages.len()];
            msg_idx += 1;
            let _ = black_box(MlDsa87::sign(msg, &sk5).unwrap());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_keypair,
    bench_sign,
    bench_verify,
    bench_roundtrip,
    bench_serialization,
    bench_signing_iterations
);

criterion_main!(benches);
