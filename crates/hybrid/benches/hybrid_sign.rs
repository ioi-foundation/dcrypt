//! Benchmarks for Hybrid Signature operations
//!
//! Measures performance of composite signatures combining classical schemes
//! with Post-Quantum schemes.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dcrypt_api::Signature;
use dcrypt_hybrid::sign::EcdsaMlDsa65Hybrid;
use dcrypt_internal::random::ChaCha20Rng;

fn bench_hybrid_sign_keypair(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid_Sign_Keypair");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // ECDSA P-384 + ML-DSA-65
    group.bench_function("ECDSA_P384_ML_DSA_65", |b| {
        b.iter(|| EcdsaMlDsa65Hybrid::keypair(&mut rng).unwrap());
    });

    group.finish();
}

fn bench_hybrid_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid_Sign_Sign");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let message = b"Benchmark message for hybrid signature schemes";

    // Set up ECDSA + ML-DSA.
    let (_, sk_ecdsa_dil) = EcdsaMlDsa65Hybrid::keypair(&mut rng).unwrap();

    group.bench_function("ECDSA_P384_ML_DSA_65", |b| {
        b.iter(|| {
            let sig = EcdsaMlDsa65Hybrid::sign(black_box(message), &sk_ecdsa_dil).unwrap();
            black_box(sig);
        });
    });

    group.finish();
}

fn bench_hybrid_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid_Sign_Verify");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let message = b"Benchmark message for hybrid signature schemes";

    // Set up ECDSA + ML-DSA.
    let (pk_ecdsa_dil, sk_ecdsa_dil) = EcdsaMlDsa65Hybrid::keypair(&mut rng).unwrap();
    let sig_ecdsa_dil = EcdsaMlDsa65Hybrid::sign(message, &sk_ecdsa_dil).unwrap();

    group.bench_function("ECDSA_P384_ML_DSA_65", |b| {
        b.iter(|| {
            EcdsaMlDsa65Hybrid::verify(
                black_box(message),
                black_box(&sig_ecdsa_dil),
                black_box(&pk_ecdsa_dil),
            )
            .unwrap();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hybrid_sign_keypair,
    bench_hybrid_sign,
    bench_hybrid_verify
);
criterion_main!(benches);
