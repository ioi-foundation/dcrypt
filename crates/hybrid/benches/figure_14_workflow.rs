//! Benchmark for Figure 14: Hybrid Full Workflow Latency
//!
//! This benchmark measures the end-to-end latency of a full ephemeral key exchange.
//! It includes:
//! 1. Keypair Generation (Classical ECC + Kyber)
//! 2. Encapsulation (Deriving Shared Secret + Ciphertext)
//! 3. Decapsulation (Recovering Shared Secret)
//!
//! This represents the total CPU time required for a complete handshake cycle.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dcrypt_api::Kem;
use dcrypt_hybrid::kem::{
    EcdhK256Kyber512,   // secp256k1 + Kyber512
    EcdhP256Kyber512,   // NIST P-256 + Kyber512
    EcdhP256Kyber768,   // NIST P-256 + Kyber768
    EcdhP384Kyber1024,  // NIST P-384 + Kyber1024
    EcdhP521Kyber1024,  // NIST P-521 + Kyber1024
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Generic helper to benchmark a specific KEM implementation
fn bench_kem_workflow<K: Kem>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group("Figure_14_Hybrid_Full_Workflow_Latency");
    
    // Use a deterministic RNG for reproducible benchmarks
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    group.bench_function(name, |b| {
        b.iter(|| {
            // 1. Alice generates ephemeral keypair
            // Note: In generic code, KeyPair is opaque. We must use accessor methods.
            let keypair = K::keypair(&mut rng).expect("Keypair gen failed");
            let pk = K::public_key(&keypair);
            let sk = K::secret_key(&keypair);

            // 2. Bob encapsulates shared secret
            let (ct, ss_sender) = K::encapsulate(&mut rng, &pk).expect("Encapsulation failed");

            // 3. Alice decapsulates shared secret
            let ss_receiver = K::decapsulate(&sk, &ct).expect("Decapsulation failed");

            // Prevent compiler optimizations
            black_box((ss_sender, ss_receiver));
        });
    });

    group.finish();
}

fn bench_full_workflow(c: &mut Criterion) {
    // 1. Security Level 1 equivalent (approximate)
    bench_kem_workflow::<EcdhP256Kyber512>(c, "P256_Kyber512");
    bench_kem_workflow::<EcdhK256Kyber512>(c, "K256_Kyber512");

    // 2. Security Level 3 equivalent (mixed)
    bench_kem_workflow::<EcdhP256Kyber768>(c, "P256_Kyber768");

    // 3. Security Level 5 equivalent
    bench_kem_workflow::<EcdhP384Kyber1024>(c, "P384_Kyber1024");
    bench_kem_workflow::<EcdhP521Kyber1024>(c, "P521_Kyber1024");
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(50); // Reduced sample size for heavier hybrid ops
    targets = bench_full_workflow
);
criterion_main!(benches);