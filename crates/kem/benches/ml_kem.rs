//! Benchmarks for the final FIPS 203 ML-KEM parameter sets.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dcrypt_api::Kem;
use dcrypt_internal::random::ChaCha20Rng;
use dcrypt_kem::ml_kem::{MlKem1024, MlKem512, MlKem768};

fn workflow<K: Kem>(rng: &mut ChaCha20Rng)
where
    K::PublicKey: Clone,
{
    let keypair = K::keypair(rng).unwrap();
    let public_key = K::public_key(&keypair);
    let secret_key = K::secret_key(&keypair);
    let (ciphertext, first) = K::encapsulate(rng, &public_key).unwrap();
    let second = K::decapsulate(&secret_key, &ciphertext).unwrap();
    black_box((first, second));
}

fn bench_ml_kem(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("ML-KEM");
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    group.bench_function("ML-KEM-512", |bencher| {
        bencher.iter(|| workflow::<MlKem512>(&mut rng))
    });
    group.bench_function("ML-KEM-768", |bencher| {
        bencher.iter(|| workflow::<MlKem768>(&mut rng))
    });
    group.bench_function("ML-KEM-1024", |bencher| {
        bencher.iter(|| workflow::<MlKem1024>(&mut rng))
    });
    group.finish();
}

criterion_group!(ml_kem_benches, bench_ml_kem);
criterion_main!(ml_kem_benches);
