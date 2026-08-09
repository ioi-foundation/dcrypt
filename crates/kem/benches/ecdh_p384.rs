// crates/kem/benches/ecdh_p384.rs
//! Benchmarks for ECDH-P384 KEM operations

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use dcrypt_api::Kem;
use dcrypt_kem::ecdh::p384::EcdhP384;
mod support;
use support::TestRng;

fn bench_p384_keypair(c: &mut Criterion) {
    let mut rng = TestRng;

    c.bench_function("ECDH-P384/keypair", |b| {
        b.iter(|| EcdhP384::keypair(&mut rng).unwrap());
    });
}

fn bench_p384_encapsulate(c: &mut Criterion) {
    let mut rng = TestRng;
    let (pk, _) = EcdhP384::keypair(&mut rng).unwrap();

    c.bench_function("ECDH-P384/encapsulate", |b| {
        b.iter(|| EcdhP384::encapsulate(&mut rng, &pk).unwrap());
    });
}

fn bench_p384_decapsulate(c: &mut Criterion) {
    let mut rng = TestRng;
    let (pk, sk) = EcdhP384::keypair(&mut rng).unwrap();
    let (ct, _) = EcdhP384::encapsulate(&mut rng, &pk).unwrap();

    c.bench_function("ECDH-P384/decapsulate", |b| {
        b.iter(|| EcdhP384::decapsulate(&sk, &ct).unwrap());
    });
}

fn bench_p384_full_kem_flow(c: &mut Criterion) {
    let mut rng = TestRng;

    c.bench_function("ECDH-P384/full_kem_flow", |b| {
        b.iter(|| {
            // Generate recipient keypair
            let (pk, sk) = EcdhP384::keypair(&mut rng).unwrap();

            // Sender encapsulates
            let (ct, ss_sender) = EcdhP384::encapsulate(&mut rng, &pk).unwrap();

            // Recipient decapsulates
            let ss_recipient = EcdhP384::decapsulate(&sk, &ct).unwrap();

            // In a real scenario, we'd verify the shared secrets match
            debug_assert_eq!(ss_sender.as_ref(), ss_recipient.as_ref());
        });
    });
}

fn bench_p384_batch_operations(c: &mut Criterion) {
    let mut rng = TestRng;
    let batch_sizes = vec![10, 100, 1000];

    let mut group = c.benchmark_group("ECDH-P384/batch");

    for batch_size in batch_sizes {
        // Benchmark batch key generation
        group.bench_with_input(
            BenchmarkId::new("keypair", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    for _ in 0..size {
                        EcdhP384::keypair(&mut rng).unwrap();
                    }
                });
            },
        );

        // Benchmark batch encapsulation
        let keypairs: Vec<_> = (0..batch_size)
            .map(|_| EcdhP384::keypair(&mut rng).unwrap())
            .collect();

        group.bench_with_input(
            BenchmarkId::new("encapsulate", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    for i in 0..size {
                        let (pk, _) = &keypairs[i % keypairs.len()];
                        EcdhP384::encapsulate(&mut rng, pk).unwrap();
                    }
                });
            },
        );

        // Benchmark batch decapsulation
        let ciphertexts: Vec<_> = keypairs
            .iter()
            .map(|(pk, _)| EcdhP384::encapsulate(&mut rng, pk).unwrap())
            .collect();

        group.bench_with_input(
            BenchmarkId::new("decapsulate", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    for i in 0..size {
                        let idx = i % keypairs.len();
                        let (_, sk) = &keypairs[idx];
                        let (ct, _) = &ciphertexts[idx];
                        EcdhP384::decapsulate(sk, ct).unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_p384_memory_patterns(c: &mut Criterion) {
    let mut rng = TestRng;

    // Benchmark memory allocation patterns
    c.bench_function("ECDH-P384/memory/keypair_allocation", |b| {
        b.iter(|| {
            let _keypair = EcdhP384::keypair(&mut rng).unwrap();
            // Keypair goes out of scope and is zeroized
        });
    });

    // Benchmark shared secret generation and cleanup
    c.bench_function("ECDH-P384/memory/shared_secret_lifecycle", |b| {
        let (pk, sk) = EcdhP384::keypair(&mut rng).unwrap();

        b.iter(|| {
            let (ct, ss1) = EcdhP384::encapsulate(&mut rng, &pk).unwrap();
            let ss2 = EcdhP384::decapsulate(&sk, &ct).unwrap();

            // Both shared secrets will be zeroized when dropped
            debug_assert_eq!(ss1.as_ref(), ss2.as_ref());
        });
    });
}

fn bench_p384_parallel_operations(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;

    let mut rng = TestRng;
    let num_threads = 4;

    c.bench_function("ECDH-P384/parallel/keypair_generation", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..num_threads)
                .map(|_| {
                    thread::spawn(|| {
                        let mut rng = TestRng;
                        EcdhP384::keypair(&mut rng).unwrap()
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
        });
    });

    // Benchmark parallel encapsulation with shared public key
    let (pk, _) = EcdhP384::keypair(&mut rng).unwrap();
    let pk_arc = Arc::new(pk);

    c.bench_function("ECDH-P384/parallel/encapsulation", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..num_threads)
                .map(|_| {
                    let pk_clone = Arc::clone(&pk_arc);
                    thread::spawn(move || {
                        let mut rng = TestRng;
                        EcdhP384::encapsulate(&mut rng, &pk_clone).unwrap()
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
}

criterion_group!(
    benches,
    bench_p384_keypair,
    bench_p384_encapsulate,
    bench_p384_decapsulate,
    bench_p384_full_kem_flow,
    bench_p384_batch_operations,
    bench_p384_memory_patterns,
    bench_p384_parallel_operations
);

criterion_main!(benches);
