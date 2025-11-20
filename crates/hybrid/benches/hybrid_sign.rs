//! Benchmarks for Hybrid Signature operations
//!
//! Measures performance of composite signatures combining classical schemes
//! with Post-Quantum schemes.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dcrypt_api::Signature;
use dcrypt_hybrid::sign::{EcdsaDilithiumHybrid, RsaFalconHybrid};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn bench_hybrid_sign_keypair(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid_Sign_Keypair");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // ECDSA P-384 + Dilithium3
    group.bench_function("ECDSA_P384_Dilithium3", |b| {
        b.iter(|| EcdsaDilithiumHybrid::keypair(&mut rng).unwrap());
    });

    // RSA-PSS + Falcon-512 (Optional comparison)
    // Note: RSA keygen is very slow, so sample size is reduced
    group.sample_size(10); 
    group.bench_function("RSA_PSS_Falcon512", |b| {
        b.iter(|| RsaFalconHybrid::keypair(&mut rng).unwrap());
    });
    
    group.finish();
}

fn bench_hybrid_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid_Sign_Sign");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let message = b"Benchmark message for hybrid signature schemes";

    // Setup ECDSA+Dilithium
    let (_, sk_ecdsa_dil) = EcdsaDilithiumHybrid::keypair(&mut rng).unwrap();

    // Setup RSA+Falcon
    let (_, sk_rsa_falcon) = RsaFalconHybrid::keypair(&mut rng).unwrap();

    group.bench_function("ECDSA_P384_Dilithium3", |b| {
        b.iter(|| {
            let sig = EcdsaDilithiumHybrid::sign(black_box(message), &sk_ecdsa_dil).unwrap();
            black_box(sig);
        });
    });

    group.bench_function("RSA_PSS_Falcon512", |b| {
        b.iter(|| {
            let sig = RsaFalconHybrid::sign(black_box(message), &sk_rsa_falcon).unwrap();
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

    // Setup RSA+Falcon
    let (pk_rsa_falcon, sk_rsa_falcon) = RsaFalconHybrid::keypair(&mut rng).unwrap();
    let sig_rsa_falcon = RsaFalconHybrid::sign(message, &sk_rsa_falcon).unwrap();

    group.bench_function("ECDSA_P384_Dilithium3", |b| {
        b.iter(|| {
            EcdsaDilithiumHybrid::verify(
                black_box(message), 
                black_box(&sig_ecdsa_dil), 
                black_box(&pk_ecdsa_dil)
            ).unwrap();
        });
    });

    group.bench_function("RSA_PSS_Falcon512", |b| {
        b.iter(|| {
            RsaFalconHybrid::verify(
                black_box(message), 
                black_box(&sig_rsa_falcon), 
                black_box(&pk_rsa_falcon)
            ).unwrap();
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