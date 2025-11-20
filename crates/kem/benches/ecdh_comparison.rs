// File: crates/kem/benches/ecdh_comparison.rs
//! Comparison benchmarks for all ECDH-KEM implementations

use criterion::{
    criterion_group, criterion_main, AxisScale, BenchmarkId, Criterion, PlotConfiguration,
};
use dcrypt_api::Kem;
use rand::rngs::OsRng;

// Import all ECDH implementations
use dcrypt_kem::ecdh::b283k::EcdhB283k;
use dcrypt_kem::ecdh::k256::EcdhK256;
use dcrypt_kem::ecdh::p256::EcdhP256;
use dcrypt_kem::ecdh::p384::EcdhP384;
use dcrypt_kem::ecdh::p521::EcdhP521;

fn bench_ecdh_keypair_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-Keypair-Comparison");
    let mut rng = OsRng;

    group.bench_function("P-256", |b| {
        b.iter(|| EcdhP256::keypair(&mut rng).unwrap());
    });

    group.bench_function("P-384", |b| {
        b.iter(|| EcdhP384::keypair(&mut rng).unwrap());
    });

    group.bench_function("P-521", |b| {
        b.iter(|| EcdhP521::keypair(&mut rng).unwrap());
    });

    group.bench_function("K-256", |b| {
        b.iter(|| EcdhK256::keypair(&mut rng).unwrap());
    });

    group.bench_function("B-283k", |b| {
        b.iter(|| EcdhB283k::keypair(&mut rng).unwrap());
    });

    group.finish();
}

fn bench_ecdh_encapsulate_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-Encapsulate-Comparison");
    let mut rng = OsRng;

    // Pre-generate public keys for each curve
    let (pk_p256, _) = EcdhP256::keypair(&mut rng).unwrap();
    let (pk_p384, _) = EcdhP384::keypair(&mut rng).unwrap();
    let (pk_p521, _) = EcdhP521::keypair(&mut rng).unwrap();
    let (pk_k256, _) = EcdhK256::keypair(&mut rng).unwrap();
    let (pk_b283k, _) = EcdhB283k::keypair(&mut rng).unwrap();


    group.bench_function("P-256", |b| {
        b.iter(|| EcdhP256::encapsulate(&mut rng, &pk_p256).unwrap());
    });

    group.bench_function("P-384", |b| {
        b.iter(|| EcdhP384::encapsulate(&mut rng, &pk_p384).unwrap());
    });

    group.bench_function("P-521", |b| {
        b.iter(|| EcdhP521::encapsulate(&mut rng, &pk_p521).unwrap());
    });

    group.bench_function("K-256", |b| {
        b.iter(|| EcdhK256::encapsulate(&mut rng, &pk_k256).unwrap());
    });

    group.bench_function("B-283k", |b| {
        b.iter(|| EcdhB283k::encapsulate(&mut rng, &pk_b283k).unwrap());
    });

    group.finish();
}

fn bench_ecdh_decapsulate_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-Decapsulate-Comparison");
    let mut rng = OsRng;

    // Pre-generate keypairs and ciphertexts for each curve
    let (pk_p256, sk_p256) = EcdhP256::keypair(&mut rng).unwrap();
    let (ct_p256, _) = EcdhP256::encapsulate(&mut rng, &pk_p256).unwrap();

    let (pk_p384, sk_p384) = EcdhP384::keypair(&mut rng).unwrap();
    let (ct_p384, _) = EcdhP384::encapsulate(&mut rng, &pk_p384).unwrap();

    let (pk_p521, sk_p521) = EcdhP521::keypair(&mut rng).unwrap();
    let (ct_p521, _) = EcdhP521::encapsulate(&mut rng, &pk_p521).unwrap();

    let (pk_k256, sk_k256) = EcdhK256::keypair(&mut rng).unwrap();
    let (ct_k256, _) = EcdhK256::encapsulate(&mut rng, &pk_k256).unwrap();

    let (pk_b283k, sk_b283k) = EcdhB283k::keypair(&mut rng).unwrap();
    let (ct_b283k, _) = EcdhB283k::encapsulate(&mut rng, &pk_b283k).unwrap();

    group.bench_function("P-256", |b| {
        b.iter(|| EcdhP256::decapsulate(&sk_p256, &ct_p256).unwrap());
    });

    group.bench_function("P-384", |b| {
        b.iter(|| EcdhP384::decapsulate(&sk_p384, &ct_p384).unwrap());
    });

    group.bench_function("P-521", |b| {
        b.iter(|| EcdhP521::decapsulate(&sk_p521, &ct_p521).unwrap());
    });

    group.bench_function("K-256", |b| {
        b.iter(|| EcdhK256::decapsulate(&sk_k256, &ct_k256).unwrap());
    });

    group.bench_function("B-283k", |b| {
        b.iter(|| EcdhB283k::decapsulate(&sk_b283k, &ct_b283k).unwrap());
    });

    group.finish();
}

fn bench_ecdh_throughput_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-Throughput-Operations-per-Second");
    group.plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));

    // Reduce sample size for long-running benchmarks
    group.sample_size(10);
    // Set a reasonable time limit
    group.measurement_time(std::time::Duration::from_secs(20));

    let mut rng = OsRng;

    // Use different iteration counts based on curve performance
    // Deprecated curves (P-192, P-224) removed from benchmark
    let configs = [
        ("P-256", 100), // Fast curve, more iterations
        ("P-384", 50),  // Medium curve, fewer iterations
        ("P-521", 20),  // Slower curve, fewer iterations
        ("K-256", 10),  // Very slow curve, minimal iterations
        ("B-283k", 5),  // Extremely slow curve, minimal iterations
    ];

    // Benchmark operations per second for each curve
    for (curve_name, iterations) in configs {
        group.bench_function(curve_name, |b| {
            b.iter(|| match curve_name {

                "P-256" => {
                    for _ in 0..iterations {
                        let (pk, sk) = EcdhP256::keypair(&mut rng).unwrap();
                        let (ct, _) = EcdhP256::encapsulate(&mut rng, &pk).unwrap();
                        let _ = EcdhP256::decapsulate(&sk, &ct).unwrap();
                    }
                }
                "P-384" => {
                    for _ in 0..iterations {
                        let (pk, sk) = EcdhP384::keypair(&mut rng).unwrap();
                        let (ct, _) = EcdhP384::encapsulate(&mut rng, &pk).unwrap();
                        let _ = EcdhP384::decapsulate(&sk, &ct).unwrap();
                    }
                }
                "P-521" => {
                    for _ in 0..iterations {
                        let (pk, sk) = EcdhP521::keypair(&mut rng).unwrap();
                        let (ct, _) = EcdhP521::encapsulate(&mut rng, &pk).unwrap();
                        let _ = EcdhP521::decapsulate(&sk, &ct).unwrap();
                    }
                }
                "K-256" => {
                    for _ in 0..iterations {
                        let (pk, sk) = EcdhK256::keypair(&mut rng).unwrap();
                        let (ct, _) = EcdhK256::encapsulate(&mut rng, &pk).unwrap();
                        let _ = EcdhK256::decapsulate(&sk, &ct).unwrap();
                    }
                }
                "B-283k" => {
                    for _ in 0..iterations {
                        let (pk, sk) = EcdhB283k::keypair(&mut rng).unwrap();
                        let (ct, _) = EcdhB283k::encapsulate(&mut rng, &pk).unwrap();
                        let _ = EcdhB283k::decapsulate(&sk, &ct).unwrap();
                    }
                }
                _ => unreachable!(),
            });
        });
    }

    group.finish();
}

fn print_ecdh_sizes() {
    println!("\n=== ECDH-KEM Key and Ciphertext Sizes ===\n");

    let mut rng = OsRng;

    // P-256
    let (pk_p256, sk_p256) = EcdhP256::keypair(&mut rng).unwrap();
    let (ct_p256, ss_p256) = EcdhP256::encapsulate(&mut rng, &pk_p256).unwrap();
    println!("\nP-256:");
    println!("  Public key:    {:3} bytes", pk_p256.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_p256.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_p256.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_p256.as_ref().len());

    // P-384
    let (pk_p384, sk_p384) = EcdhP384::keypair(&mut rng).unwrap();
    let (ct_p384, ss_p384) = EcdhP384::encapsulate(&mut rng, &pk_p384).unwrap();
    println!("\nP-384:");
    println!("  Public key:    {:3} bytes", pk_p384.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_p384.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_p384.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_p384.as_ref().len());

    // P-521
    let (pk_p521, sk_p521) = EcdhP521::keypair(&mut rng).unwrap();
    let (ct_p521, ss_p521) = EcdhP521::encapsulate(&mut rng, &pk_p521).unwrap();
    println!("\nP-521:");
    println!("  Public key:    {:3} bytes", pk_p521.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_p521.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_p521.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_p521.as_ref().len());

    // K-256
    let (pk_k256, sk_k256) = EcdhK256::keypair(&mut rng).unwrap();
    let (ct_k256, ss_k256) = EcdhK256::encapsulate(&mut rng, &pk_k256).unwrap();
    println!("\nK-256 (secp256k1):");
    println!("  Public key:    {:3} bytes", pk_k256.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_k256.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_k256.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_k256.as_ref().len());

    // B-283k
    let (pk_b283k, sk_b283k) = EcdhB283k::keypair(&mut rng).unwrap();
    let (ct_b283k, ss_b283k) = EcdhB283k::encapsulate(&mut rng, &pk_b283k).unwrap();
    println!("\nB-283k (sect283k1):");
    println!("  Public key:    {:3} bytes", pk_b283k.as_ref().len());
    println!("  Secret key:    {:3} bytes", sk_b283k.as_ref().len());
    println!("  Ciphertext:    {:3} bytes", ct_b283k.as_ref().len());
    println!("  Shared secret: {:3} bytes", ss_b283k.as_ref().len());

    println!("\n=========================================\n");
}

fn setup_and_print_sizes(_: &mut Criterion) {
    print_ecdh_sizes();
}

criterion_group!(
    benches,
    setup_and_print_sizes,
    bench_ecdh_keypair_comparison,
    bench_ecdh_encapsulate_comparison,
    bench_ecdh_decapsulate_comparison,
    bench_ecdh_throughput_comparison
);

criterion_main!(benches);