//! Benchmarks for Hybrid KEM operations
//! 
//! Measures performance of composite KEMs combining classical ECDH 
//! with Post-Quantum Kyber.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dcrypt_api::Kem;
use dcrypt_hybrid::kem::{
    EcdhP256Kyber768, EcdhP384Kyber1024
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn bench_hybrid_keypair(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid_KEM_Keypair");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    group.bench_function("P256_Kyber768", |b| {
        b.iter(|| EcdhP256Kyber768::keypair(&mut rng).unwrap());
    });

    group.bench_function("P384_Kyber1024", |b| {
        b.iter(|| EcdhP384Kyber1024::keypair(&mut rng).unwrap());
    });
    
    group.finish();
}

fn bench_hybrid_encapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid_KEM_Encapsulate");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Setup keys
    let (pk_p256, _) = EcdhP256Kyber768::keypair(&mut rng).unwrap();
    let (pk_p384, _) = EcdhP384Kyber1024::keypair(&mut rng).unwrap();

    group.bench_function("P256_Kyber768", |b| {
        b.iter(|| {
            let (ct, ss) = EcdhP256Kyber768::encapsulate(&mut rng, &pk_p256).unwrap();
            black_box((ct, ss));
        });
    });

    group.bench_function("P384_Kyber1024", |b| {
        b.iter(|| {
            let (ct, ss) = EcdhP384Kyber1024::encapsulate(&mut rng, &pk_p384).unwrap();
            black_box((ct, ss));
        });
    });

    group.finish();
}

fn bench_hybrid_decapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hybrid_KEM_Decapsulate");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Setup P256+Kyber768
    let (pk_p256, sk_p256) = EcdhP256Kyber768::keypair(&mut rng).unwrap();
    let (ct_p256, _) = EcdhP256Kyber768::encapsulate(&mut rng, &pk_p256).unwrap();

    // Setup P384+Kyber1024
    let (pk_p384, sk_p384) = EcdhP384Kyber1024::keypair(&mut rng).unwrap();
    let (ct_p384, _) = EcdhP384Kyber1024::encapsulate(&mut rng, &pk_p384).unwrap();

    group.bench_function("P256_Kyber768", |b| {
        b.iter(|| {
            let ss = EcdhP256Kyber768::decapsulate(&sk_p256, &ct_p256).unwrap();
            black_box(ss);
        });
    });

    group.bench_function("P384_Kyber1024", |b| {
        b.iter(|| {
            let ss = EcdhP384Kyber1024::decapsulate(&sk_p384, &ct_p384).unwrap();
            black_box(ss);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hybrid_keypair,
    bench_hybrid_encapsulate,
    bench_hybrid_decapsulate
);
criterion_main!(benches);