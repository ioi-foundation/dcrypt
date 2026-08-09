//! Benchmarks for ECDH-K256 (secp256k1) KEM
//!
//! This benchmark suite measures the performance of:
//! - Key generation
//! - Encapsulation
//! - Decapsulation
//! - Full roundtrip operations

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dcrypt_api::Kem;
use dcrypt_internal::random::ChaCha20Rng;
use dcrypt_kem::ecdh::k256::{EcdhK256, EcdhK256PublicKey, EcdhK256SecretKey};
mod support;
use support::TestRng;

/// Benchmark key generation for ECDH-K256
fn bench_keypair_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-K256/keypair");
    // Set reasonable limits for slow operations
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(10));

    // Benchmark with a caller-provided RNG.
    group.bench_function("CallerRng", |b| {
        let mut rng = TestRng;
        b.iter(|| {
            let keypair = EcdhK256::keypair(&mut rng).unwrap();
            black_box(keypair);
        });
    });

    // Benchmark with ChaCha20Rng (deterministic, fast)
    group.bench_function("ChaCha20Rng", |b| {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        b.iter(|| {
            let keypair = EcdhK256::keypair(&mut rng).unwrap();
            black_box(keypair);
        });
    });

    group.finish();
}

/// Benchmark encapsulation for ECDH-K256
fn bench_encapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-K256/encapsulate");
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(10));

    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);

    // Generate a recipient keypair for benchmarking
    let (recipient_pk, _) = EcdhK256::keypair(&mut rng).unwrap();

    group.bench_function("standard", |b| {
        b.iter(|| {
            let (ciphertext, shared_secret) =
                EcdhK256::encapsulate(&mut rng, &recipient_pk).unwrap();
            black_box((ciphertext, shared_secret));
        });
    });

    // Benchmark with different recipients to measure cache effects
    let recipients: Vec<(EcdhK256PublicKey, EcdhK256SecretKey)> = (0..10)
        .map(|_| EcdhK256::keypair(&mut rng).unwrap())
        .collect();

    group.bench_function("varying_recipients", |b| {
        let mut i = 0;
        b.iter(|| {
            let recipient_pk = &recipients[i % recipients.len()].0;
            let (ciphertext, shared_secret) =
                EcdhK256::encapsulate(&mut rng, recipient_pk).unwrap();
            black_box((ciphertext, shared_secret));
            i += 1;
        });
    });

    group.finish();
}

/// Benchmark decapsulation for ECDH-K256
fn bench_decapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-K256/decapsulate");
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(10));

    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);

    // Generate recipient keypair and pre-compute ciphertexts
    let (recipient_pk, recipient_sk) = EcdhK256::keypair(&mut rng).unwrap();
    let ciphertexts: Vec<_> = (0..10)
        .map(|_| {
            let (ct, _) = EcdhK256::encapsulate(&mut rng, &recipient_pk).unwrap();
            ct
        })
        .collect();

    group.bench_function("standard", |b| {
        let mut i = 0;
        b.iter(|| {
            let shared_secret =
                EcdhK256::decapsulate(&recipient_sk, &ciphertexts[i % ciphertexts.len()]).unwrap();
            black_box(shared_secret);
            i += 1;
        });
    });

    // Benchmark with same ciphertext (best case for caching)
    let (fixed_ct, _) = EcdhK256::encapsulate(&mut rng, &recipient_pk).unwrap();

    group.bench_function("same_ciphertext", |b| {
        b.iter(|| {
            let shared_secret = EcdhK256::decapsulate(&recipient_sk, &fixed_ct).unwrap();
            black_box(shared_secret);
        });
    });

    group.finish();
}

/// Benchmark full roundtrip (keypair + encapsulate + decapsulate)
fn bench_full_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-K256/roundtrip");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(15));

    group.bench_function("complete", |b| {
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        b.iter(|| {
            // Generate recipient keypair
            let (recipient_pk, recipient_sk) = EcdhK256::keypair(&mut rng).unwrap();

            // Encapsulate
            let (ciphertext, shared_secret_sender) =
                EcdhK256::encapsulate(&mut rng, &recipient_pk).unwrap();

            // Decapsulate
            let shared_secret_recipient =
                EcdhK256::decapsulate(&recipient_sk, &ciphertext).unwrap();

            black_box((shared_secret_sender, shared_secret_recipient));
        });
    });

    // Benchmark roundtrip with pre-generated keypair
    group.bench_function("with_fixed_keypair", |b| {
        let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
        let (recipient_pk, recipient_sk) = EcdhK256::keypair(&mut rng).unwrap();

        b.iter(|| {
            // Encapsulate
            let (ciphertext, shared_secret_sender) =
                EcdhK256::encapsulate(&mut rng, &recipient_pk).unwrap();

            // Decapsulate
            let shared_secret_recipient =
                EcdhK256::decapsulate(&recipient_sk, &ciphertext).unwrap();

            black_box((shared_secret_sender, shared_secret_recipient));
        });
    });

    group.finish();
}

/// Benchmark batch operations for ECDH-K256
fn bench_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-K256/batch");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(20));

    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);

    // Benchmark batch key generation - reduced batch sizes
    for batch_size in [5, 10, 25] {
        group.bench_with_input(
            BenchmarkId::new("keypair_generation", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    let keys: Vec<_> = (0..size)
                        .map(|_| EcdhK256::keypair(&mut rng).unwrap())
                        .collect();
                    black_box(keys);
                });
            },
        );
    }

    // Benchmark batch encapsulation
    let (recipient_pk, _) = EcdhK256::keypair(&mut rng).unwrap();

    for batch_size in [5, 10, 25] {
        group.bench_with_input(
            BenchmarkId::new("encapsulation", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    let results: Vec<_> = (0..size)
                        .map(|_| EcdhK256::encapsulate(&mut rng, &recipient_pk).unwrap())
                        .collect();
                    black_box(results);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-K256/memory");
    group.sample_size(10);

    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);

    // Benchmark allocation/deallocation patterns
    group.bench_function("alloc_dealloc_cycle", |b| {
        let (recipient_pk, recipient_sk) = EcdhK256::keypair(&mut rng).unwrap();

        b.iter(|| {
            // This simulates a typical usage pattern with allocation and deallocation
            let (ct, ss1) = EcdhK256::encapsulate(&mut rng, &recipient_pk).unwrap();
            let ss2 = EcdhK256::decapsulate(&recipient_sk, &ct).unwrap();

            // Force drop to measure deallocation
            drop(ct);
            drop(ss1);
            drop(ss2);
        });
    });

    // Benchmark with reused allocations - reduced size
    group.bench_function("reused_allocations", |b| {
        let (recipient_pk, recipient_sk) = EcdhK256::keypair(&mut rng).unwrap();
        let mut ciphertexts = Vec::with_capacity(10);
        let mut shared_secrets = Vec::with_capacity(10);

        b.iter(|| {
            ciphertexts.clear();
            shared_secrets.clear();

            for _ in 0..5 {
                let (ct, ss) = EcdhK256::encapsulate(&mut rng, &recipient_pk).unwrap();
                ciphertexts.push(ct);
                shared_secrets.push(ss);
            }

            for ct in &ciphertexts {
                let ss = EcdhK256::decapsulate(&recipient_sk, ct).unwrap();
                black_box(ss);
            }
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
    bench_batch_operations,
    bench_memory_patterns
);

criterion_main!(benches);
