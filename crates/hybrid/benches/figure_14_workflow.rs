//! Benchmark for Figure 14: Hybrid Full Workflow Latency
//!
//! This benchmark measures the end-to-end latency of a full ephemeral key exchange.
//! It includes:
//! 1. Keypair Generation (Classical ECC + MlKem)
//! 2. Encapsulation (Deriving Shared Secret + Ciphertext)
//! 3. Decapsulation (Recovering Shared Secret)
//!
//! This represents the total CPU time required for a complete handshake cycle.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dcrypt_api::Kem;
use dcrypt_hybrid::kem::{
    EcdhK256MlKem512,  // secp256k1 + MlKem512
    EcdhP256MlKem512,  // NIST P-256 + MlKem512
    EcdhP256MlKem768,  // NIST P-256 + MlKem768
    EcdhP384MlKem1024, // NIST P-384 + MlKem1024
    EcdhP521MlKem1024, // NIST P-521 + MlKem1024
};
use dcrypt_internal::random::ChaCha20Rng;

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
    bench_kem_workflow::<EcdhP256MlKem512>(c, "P256_MlKem512");
    bench_kem_workflow::<EcdhK256MlKem512>(c, "K256_MlKem512");

    // 2. Security Level 3 equivalent (mixed)
    bench_kem_workflow::<EcdhP256MlKem768>(c, "P256_MlKem768");

    // 3. Security Level 5 equivalent
    bench_kem_workflow::<EcdhP384MlKem1024>(c, "P384_MlKem1024");
    bench_kem_workflow::<EcdhP521MlKem1024>(c, "P521_MlKem1024");
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(50); // Reduced sample size for heavier hybrid ops
    targets = bench_full_workflow
);
criterion_main!(benches);
