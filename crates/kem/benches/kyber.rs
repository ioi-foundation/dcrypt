// crates/kem/benches/kyber.rs

//! Benchmarks for Kyber Key Encapsulation Mechanisms

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dcrypt_api::Kem;
use dcrypt_internal::random::ChaCha20Rng;
use dcrypt_kem::kyber::{Kyber1024, Kyber512, Kyber768};

/// Benchmark Kyber-512 operations
fn bench_kyber512(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber512");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Benchmark key generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let _keypair = Kyber512::keypair(&mut rng).unwrap();
        });
    });

    // Setup for encapsulation benchmark
    let (pk, _) = Kyber512::keypair(&mut rng).unwrap();

    // Benchmark encapsulation
    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            let (_ct, _ss) = Kyber512::encapsulate(&mut rng, black_box(&pk)).unwrap();
        });
    });

    // Setup for decapsulation benchmark
    let (pk, sk) = Kyber512::keypair(&mut rng).unwrap();
    let (ct, _) = Kyber512::encapsulate(&mut rng, &pk).unwrap();

    // Benchmark decapsulation
    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            let _ss = Kyber512::decapsulate(black_box(&sk), black_box(&ct)).unwrap();
        });
    });

    // Benchmark full workflow
    group.bench_function("full_workflow", |b| {
        b.iter(|| {
            // Generate keypair
            let (pk, sk) = Kyber512::keypair(&mut rng).unwrap();
            // Encapsulate
            let (ct, ss1) = Kyber512::encapsulate(&mut rng, &pk).unwrap();
            // Decapsulate
            let ss2 = Kyber512::decapsulate(&sk, &ct).unwrap();
            // Return to prevent optimization
            (ss1, ss2)
        });
    });

    group.finish();
}

/// Benchmark Kyber-768 operations
fn bench_kyber768(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber768");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Benchmark key generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let _keypair = Kyber768::keypair(&mut rng).unwrap();
        });
    });

    // Setup for encapsulation benchmark
    let (pk, _) = Kyber768::keypair(&mut rng).unwrap();

    // Benchmark encapsulation
    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            let (_ct, _ss) = Kyber768::encapsulate(&mut rng, black_box(&pk)).unwrap();
        });
    });

    // Setup for decapsulation benchmark
    let (pk, sk) = Kyber768::keypair(&mut rng).unwrap();
    let (ct, _) = Kyber768::encapsulate(&mut rng, &pk).unwrap();

    // Benchmark decapsulation
    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            let _ss = Kyber768::decapsulate(black_box(&sk), black_box(&ct)).unwrap();
        });
    });

    // Benchmark full workflow
    group.bench_function("full_workflow", |b| {
        b.iter(|| {
            // Generate keypair
            let (pk, sk) = Kyber768::keypair(&mut rng).unwrap();
            // Encapsulate
            let (ct, ss1) = Kyber768::encapsulate(&mut rng, &pk).unwrap();
            // Decapsulate
            let ss2 = Kyber768::decapsulate(&sk, &ct).unwrap();
            // Return to prevent optimization
            (ss1, ss2)
        });
    });

    group.finish();
}

/// Benchmark Kyber-1024 operations
fn bench_kyber1024(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber1024");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Benchmark key generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let _keypair = Kyber1024::keypair(&mut rng).unwrap();
        });
    });

    // Setup for encapsulation benchmark
    let (pk, _) = Kyber1024::keypair(&mut rng).unwrap();

    // Benchmark encapsulation
    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            let (_ct, _ss) = Kyber1024::encapsulate(&mut rng, black_box(&pk)).unwrap();
        });
    });

    // Setup for decapsulation benchmark
    let (pk, sk) = Kyber1024::keypair(&mut rng).unwrap();
    let (ct, _) = Kyber1024::encapsulate(&mut rng, &pk).unwrap();

    // Benchmark decapsulation
    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            let _ss = Kyber1024::decapsulate(black_box(&sk), black_box(&ct)).unwrap();
        });
    });

    // Benchmark full workflow
    group.bench_function("full_workflow", |b| {
        b.iter(|| {
            // Generate keypair
            let (pk, sk) = Kyber1024::keypair(&mut rng).unwrap();
            // Encapsulate
            let (ct, ss1) = Kyber1024::encapsulate(&mut rng, &pk).unwrap();
            // Decapsulate
            let ss2 = Kyber1024::decapsulate(&sk, &ct).unwrap();
            // Return to prevent optimization
            (ss1, ss2)
        });
    });

    group.finish();
}

/// Comparative benchmark across all Kyber variants
fn bench_kyber_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber_Comparison");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Compare key generation across variants
    for variant in ["Kyber512", "Kyber768", "Kyber1024"].iter() {
        group.bench_with_input(
            BenchmarkId::new("keygen", variant),
            variant,
            |b, &variant| match variant {
                "Kyber512" => b.iter(|| Kyber512::keypair(&mut rng).unwrap()),
                "Kyber768" => b.iter(|| Kyber768::keypair(&mut rng).unwrap()),
                "Kyber1024" => b.iter(|| Kyber1024::keypair(&mut rng).unwrap()),
                _ => unreachable!(),
            },
        );
    }

    // Compare full workflow across variants
    for variant in ["Kyber512", "Kyber768", "Kyber1024"].iter() {
        group.bench_with_input(
            BenchmarkId::new("full_workflow", variant),
            variant,
            |b, &variant| match variant {
                "Kyber512" => b.iter(|| {
                    let (pk, sk) = Kyber512::keypair(&mut rng).unwrap();
                    let (ct, ss1) = Kyber512::encapsulate(&mut rng, &pk).unwrap();
                    let ss2 = Kyber512::decapsulate(&sk, &ct).unwrap();
                    (ss1, ss2)
                }),
                "Kyber768" => b.iter(|| {
                    let (pk, sk) = Kyber768::keypair(&mut rng).unwrap();
                    let (ct, ss1) = Kyber768::encapsulate(&mut rng, &pk).unwrap();
                    let ss2 = Kyber768::decapsulate(&sk, &ct).unwrap();
                    (ss1, ss2)
                }),
                "Kyber1024" => b.iter(|| {
                    let (pk, sk) = Kyber1024::keypair(&mut rng).unwrap();
                    let (ct, ss1) = Kyber1024::encapsulate(&mut rng, &pk).unwrap();
                    let ss2 = Kyber1024::decapsulate(&sk, &ct).unwrap();
                    (ss1, ss2)
                }),
                _ => unreachable!(),
            },
        );
    }

    group.finish();
}

/// Benchmark operations with different message patterns
fn bench_kyber_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber_Patterns");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Benchmark multiple sequential encapsulations (simulating multiple key exchanges)
    let (pk512, sk512) = Kyber512::keypair(&mut rng).unwrap();
    let (pk768, sk768) = Kyber768::keypair(&mut rng).unwrap();
    let (pk1024, sk1024) = Kyber1024::keypair(&mut rng).unwrap();

    group.bench_function("Kyber512_10_sequential_encaps", |b| {
        b.iter(|| {
            for _ in 0..10 {
                let (ct, ss) = Kyber512::encapsulate(&mut rng, &pk512).unwrap();
                let _ss2 = Kyber512::decapsulate(&sk512, &ct).unwrap();
                black_box(ss);
            }
        });
    });

    group.bench_function("Kyber768_10_sequential_encaps", |b| {
        b.iter(|| {
            for _ in 0..10 {
                let (ct, ss) = Kyber768::encapsulate(&mut rng, &pk768).unwrap();
                let _ss2 = Kyber768::decapsulate(&sk768, &ct).unwrap();
                black_box(ss);
            }
        });
    });

    group.bench_function("Kyber1024_10_sequential_encaps", |b| {
        b.iter(|| {
            for _ in 0..10 {
                let (ct, ss) = Kyber1024::encapsulate(&mut rng, &pk1024).unwrap();
                let _ss2 = Kyber1024::decapsulate(&sk1024, &ct).unwrap();
                black_box(ss);
            }
        });
    });

    group.finish();
}

/// Benchmark memory-intensive operations
fn bench_kyber_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber_Memory");
    let mut rng = ChaCha20Rng::from_seed([42; 32]);

    // Benchmark key generation with immediate drop (tests zeroization overhead)
    group.bench_function("Kyber512_keygen_with_drop", |b| {
        b.iter(|| {
            let (pk, sk) = Kyber512::keypair(&mut rng).unwrap();
            drop(pk);
            drop(sk);
        });
    });

    // Benchmark multiple keypair generation (tests memory allocation patterns)
    group.bench_function("Kyber512_100_keypairs", |b| {
        b.iter(|| {
            let mut keypairs = Vec::with_capacity(100);
            for _ in 0..100 {
                keypairs.push(Kyber512::keypair(&mut rng).unwrap());
            }
            black_box(keypairs);
        });
    });

    group.bench_function("Kyber768_100_keypairs", |b| {
        b.iter(|| {
            let mut keypairs = Vec::with_capacity(100);
            for _ in 0..100 {
                keypairs.push(Kyber768::keypair(&mut rng).unwrap());
            }
            black_box(keypairs);
        });
    });

    group.bench_function("Kyber1024_100_keypairs", |b| {
        b.iter(|| {
            let mut keypairs = Vec::with_capacity(100);
            for _ in 0..100 {
                keypairs.push(Kyber1024::keypair(&mut rng).unwrap());
            }
            black_box(keypairs);
        });
    });

    group.finish();
}

criterion_group!(
    kyber_benches,
    bench_kyber512,
    bench_kyber768,
    bench_kyber1024,
    bench_kyber_comparison,
    bench_kyber_patterns,
    bench_kyber_memory
);

criterion_main!(kyber_benches);
