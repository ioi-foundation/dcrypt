//! Benchmarks for ECDH-B283k KEM operations
//!
//! This benchmark suite measures the performance of:
//! - Key pair generation
//! - Encapsulation (shared secret generation for sender)
//! - Decapsulation (shared secret recovery for receiver)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dcrypt_api::Kem;
use dcrypt_kem::ecdh::b283k::EcdhB283k;
mod support;
use support::TestRng;

/// Benchmark key pair generation for ECDH-B283k
fn bench_keypair_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_b283k_keypair");
    // Reduce sample size for this slow operation
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    group.bench_function("generate", |b| {
        let mut rng = TestRng;
        b.iter(|| {
            let keypair = EcdhB283k::keypair(&mut rng).expect("Keypair generation failed");
            black_box(keypair);
        });
    });

    group.finish();
}

/// Benchmark encapsulation operation for ECDH-B283k
fn bench_encapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_b283k_encapsulate");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(15));

    let mut rng = TestRng;

    // Generate a recipient keypair for benchmarking
    let (recipient_pk, _) = EcdhB283k::keypair(&mut rng).expect("Keypair generation failed");

    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            let (ciphertext, shared_secret) =
                EcdhB283k::encapsulate(&mut rng, black_box(&recipient_pk))
                    .expect("Encapsulation failed");
            black_box((ciphertext, shared_secret));
        });
    });

    group.finish();
}

/// Benchmark decapsulation operation for ECDH-B283k
fn bench_decapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_b283k_decapsulate");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(15));

    let mut rng = TestRng;

    // Generate recipient keypair and create a ciphertext
    let (recipient_pk, recipient_sk) =
        EcdhB283k::keypair(&mut rng).expect("Keypair generation failed");
    let (ciphertext, _) =
        EcdhB283k::encapsulate(&mut rng, &recipient_pk).expect("Encapsulation failed");

    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            let shared_secret =
                EcdhB283k::decapsulate(black_box(&recipient_sk), black_box(&ciphertext))
                    .expect("Decapsulation failed");
            black_box(shared_secret);
        });
    });

    group.finish();
}

/// Benchmark complete KEM flow (keypair + encapsulate + decapsulate)
fn bench_complete_flow(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_b283k_complete");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(20));

    group.bench_function("full_kem_flow", |b| {
        let mut rng = TestRng;
        b.iter(|| {
            // Generate recipient keypair
            let (recipient_pk, recipient_sk) =
                EcdhB283k::keypair(&mut rng).expect("Keypair generation failed");

            // Sender encapsulates
            let (ciphertext, shared_secret_sender) =
                EcdhB283k::encapsulate(&mut rng, &recipient_pk).expect("Encapsulation failed");

            // Recipient decapsulates
            let shared_secret_recipient =
                EcdhB283k::decapsulate(&recipient_sk, &ciphertext).expect("Decapsulation failed");

            // In practice, we'd verify these match
            black_box((shared_secret_sender, shared_secret_recipient));
        });
    });

    group.finish();
}

/// Benchmark multiple encapsulations with the same public key
fn bench_multiple_encapsulations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_b283k_multi_encap");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(20));

    let mut rng = TestRng;

    // Generate a single recipient keypair
    let (recipient_pk, _) = EcdhB283k::keypair(&mut rng).expect("Keypair generation failed");

    // Only test small batch sizes for this very slow curve
    for count in [2, 5, 10].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            b.iter(|| {
                for _ in 0..count {
                    let (ct, ss) = EcdhB283k::encapsulate(&mut rng, &recipient_pk)
                        .expect("Encapsulation failed");
                    black_box((ct, ss));
                }
            });
        });
    }

    group.finish();
}

/// Benchmark serialization/deserialization overhead
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_b283k_serialization");
    let mut rng = TestRng;

    // Generate test data
    let keypair = EcdhB283k::keypair(&mut rng).expect("Keypair generation failed");
    let pk = EcdhB283k::public_key(&keypair);
    let sk = EcdhB283k::secret_key(&keypair);
    let (ct, _) = EcdhB283k::encapsulate(&mut rng, &pk).expect("Encapsulation failed");

    group.bench_function("serialize_public_key", |b| {
        b.iter(|| {
            let bytes = pk.as_ref();
            black_box(bytes);
        });
    });

    group.bench_function("serialize_secret_key", |b| {
        b.iter(|| {
            let bytes = sk.as_ref();
            black_box(bytes);
        });
    });

    group.bench_function("serialize_ciphertext", |b| {
        b.iter(|| {
            let bytes = ct.as_ref();
            black_box(bytes);
        });
    });

    // Benchmark key extraction from keypair
    group.bench_function("extract_public_key", |b| {
        b.iter(|| {
            let pk = EcdhB283k::public_key(black_box(&keypair));
            black_box(pk);
        });
    });

    group.bench_function("extract_secret_key", |b| {
        b.iter(|| {
            let sk = EcdhB283k::secret_key(black_box(&keypair));
            black_box(sk);
        });
    });

    group.finish();
}

/// Compare B283k performance characteristics
fn bench_performance_characteristics(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_b283k_characteristics");
    group.sample_size(10);

    let mut rng = TestRng;

    // Measure the cost of shared secret validation (identity point checks)
    let (recipient_pk, recipient_sk) =
        EcdhB283k::keypair(&mut rng).expect("Keypair generation failed");

    // Benchmark encapsulation with validation
    group.bench_function("encapsulate_with_validation", |b| {
        b.iter(|| {
            let result = EcdhB283k::encapsulate(&mut rng, &recipient_pk);
            match result {
                Ok((ct, ss)) => black_box((ct, ss)),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        });
    });

    // Benchmark decapsulation with validation
    let (ciphertext, _) =
        EcdhB283k::encapsulate(&mut rng, &recipient_pk).expect("Encapsulation failed");

    group.bench_function("decapsulate_with_validation", |b| {
        b.iter(|| {
            let result = EcdhB283k::decapsulate(&recipient_sk, &ciphertext);
            match result {
                Ok(ss) => black_box(ss),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        });
    });

    group.finish();
}

/// Benchmark parallel operations (if running with multiple threads) - simplified for B283k
fn bench_parallel_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh_b283k_parallel");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(20));

    let mut rng = TestRng;

    // Generate fewer keypairs for this slow curve
    let keypairs: Vec<_> = (0..5)
        .map(|_| EcdhB283k::keypair(&mut rng).expect("Keypair generation failed"))
        .collect();

    group.bench_function("sequential_encapsulations", |b| {
        b.iter(|| {
            for keypair in &keypairs {
                let pk = EcdhB283k::public_key(keypair);
                let (ct, ss) = EcdhB283k::encapsulate(&mut rng, &pk).expect("Encapsulation failed");
                black_box((ct, ss));
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
    bench_complete_flow,
    bench_multiple_encapsulations,
    bench_serialization,
    bench_performance_characteristics,
    bench_parallel_operations
);

criterion_main!(benches);
