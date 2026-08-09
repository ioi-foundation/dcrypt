//! Benchmarks for Hybrid Signature operations
//!
//! Measures performance of composite signatures combining classical schemes
//! with Post-Quantum schemes.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dcrypt_api::Signature;
use dcrypt_hybrid::sign::EcdsaDilithiumHybrid;
use dcrypt_internal::random::ChaCha20Rng;

fn bench_hybrid_sign_keypair(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid_Sign_Keypair");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // ECDSA P-384 + Dilithium3
    group.bench_function("ECDSA_P384_Dilithium3", |b| {
        b.iter(|| EcdsaDilithiumHybrid::keypair(&mut rng).unwrap());
    });

    group.finish();
}

fn bench_hybrid_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid_Sign_Sign");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let message = b"Benchmark message for hybrid signature schemes";

    // Setup ECDSA+Dilithium
    let (_, sk_ecdsa_dil) = EcdsaDilithiumHybrid::keypair(&mut rng).unwrap();

    group.bench_function("ECDSA_P384_Dilithium3", |b| {
        b.iter(|| {
            let sig = EcdsaDilithiumHybrid::sign(black_box(message), &sk_ecdsa_dil).unwrap();
            black_box(sig);
        });
    });

    group.finish();
}

fn bench_hybrid_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid_Sign_Verify");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let message = b"Benchmark message for hybrid signature schemes";

    // Setup ECDSA+Dilithium
    let (pk_ecdsa_dil, sk_ecdsa_dil) = EcdsaDilithiumHybrid::keypair(&mut rng).unwrap();
    let sig_ecdsa_dil = EcdsaDilithiumHybrid::sign(message, &sk_ecdsa_dil).unwrap();

    group.bench_function("ECDSA_P384_Dilithium3", |b| {
        b.iter(|| {
            EcdsaDilithiumHybrid::verify(
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
