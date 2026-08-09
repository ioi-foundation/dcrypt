// File: crates/kem/benches/ecdh_p521.rs
//! Benchmarks for ECDH-KEM with P-521 curve

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use dcrypt_api::Kem;
use dcrypt_kem::ecdh::p521::{EcdhP521, EcdhP521PublicKey, EcdhP521SecretKey};
mod support;
use support::TestRng;

fn bench_p521_keypair(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P521");

    group.bench_function("keypair_generation", |b| {
        let mut rng = TestRng;
        b.iter(|| EcdhP521::keypair(&mut rng).unwrap());
    });

    group.finish();
}

fn bench_p521_encapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P521");
    let mut rng = TestRng;

    // Generate a recipient keypair for the benchmark
    let (recipient_pk, _) = EcdhP521::keypair(&mut rng).unwrap();

    group.bench_function("encapsulate", |b| {
        b.iter(|| EcdhP521::encapsulate(&mut rng, &recipient_pk).unwrap());
    });

    group.finish();
}

fn bench_p521_decapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P521");
    let mut rng = TestRng;

    // Generate a recipient keypair and ciphertext for the benchmark
    let (recipient_pk, recipient_sk) = EcdhP521::keypair(&mut rng).unwrap();
    let (ciphertext, _) = EcdhP521::encapsulate(&mut rng, &recipient_pk).unwrap();

    group.bench_function("decapsulate", |b| {
        b.iter(|| EcdhP521::decapsulate(&recipient_sk, &ciphertext).unwrap());
    });

    group.finish();
}

fn bench_p521_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P521");
    let mut rng = TestRng;

    // Generate a recipient keypair for the benchmark
    let (recipient_pk, recipient_sk) = EcdhP521::keypair(&mut rng).unwrap();

    group.bench_function("full_roundtrip", |b| {
        b.iter(|| {
            let (ciphertext, shared_secret_sender) =
                EcdhP521::encapsulate(&mut rng, &recipient_pk).unwrap();
            let shared_secret_recipient =
                EcdhP521::decapsulate(&recipient_sk, &ciphertext).unwrap();
            assert_eq!(
                shared_secret_sender.as_ref(),
                shared_secret_recipient.as_ref()
            );
        });
    });

    group.finish();
}

fn bench_p521_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P521");
    let mut rng = TestRng;

    // Benchmark different batch sizes
    for batch_size in [10, 50, 100].iter() {
        // Prepare recipients
        let recipients: Vec<_> = (0..*batch_size)
            .map(|_| EcdhP521::keypair(&mut rng).unwrap())
            .collect();

        group.bench_with_input(
            BenchmarkId::new("batch_encapsulate", batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    for (pk, _) in &recipients {
                        EcdhP521::encapsulate(&mut rng, pk).unwrap();
                    }
                });
            },
        );

        // Prepare ciphertexts for decapsulation benchmark
        let ciphertexts: Vec<_> = recipients
            .iter()
            .map(|(pk, _)| EcdhP521::encapsulate(&mut rng, pk).unwrap().0)
            .collect();

        group.bench_with_input(
            BenchmarkId::new("batch_decapsulate", batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    for (i, (_, sk)) in recipients.iter().enumerate() {
                        EcdhP521::decapsulate(sk, &ciphertexts[i]).unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_p521_parallel_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P521");
    let mut rng = TestRng;

    // Generate multiple keypairs for parallel operations
    let num_keypairs = 100;
    let keypairs: Vec<_> = (0..num_keypairs)
        .map(|_| EcdhP521::keypair(&mut rng).unwrap())
        .collect();

    group.bench_function("parallel_encapsulations", |b| {
        b.iter(|| {
            // Simulate parallel encapsulations to different recipients
            let _results: Vec<_> = keypairs
                .iter()
                .map(|(pk, _)| EcdhP521::encapsulate(&mut rng, pk).unwrap())
                .collect();
        });
    });

    group.finish();
}

fn bench_p521_key_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P521-sizes");
    let mut rng = TestRng;

    // Generate sample keys and ciphertext
    let (pk, sk) = EcdhP521::keypair(&mut rng).unwrap();
    let (ct, ss) = EcdhP521::encapsulate(&mut rng, &pk).unwrap();

    // Report sizes (these won't actually benchmark, just report)
    group.bench_function("measure_sizes", |b| {
        b.iter(|| {
            let _pk_size = pk.as_ref().len();
            let _sk_size = sk.as_ref().len();
            let _ct_size = ct.as_ref().len();
            let _ss_size = ss.as_ref().len();
        });
    });

    println!("P-521 Key and Ciphertext Sizes:");
    println!("  Public key: {} bytes", pk.as_ref().len());
    println!("  Secret key: {} bytes", sk.as_ref().len());
    println!("  Ciphertext: {} bytes", ct.as_ref().len());
    println!("  Shared secret: {} bytes", ss.as_ref().len());

    group.finish();
}

criterion_group!(
    benches,
    bench_p521_keypair,
    bench_p521_encapsulate,
    bench_p521_decapsulate,
    bench_p521_roundtrip,
    bench_p521_batch_operations,
    bench_p521_parallel_operations,
    bench_p521_key_sizes
);

criterion_main!(benches);
