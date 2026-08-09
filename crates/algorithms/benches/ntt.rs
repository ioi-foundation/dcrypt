//! Benchmarks for Number Theoretic Transform (NTT) operations
//!
//! This benchmark suite measures the performance of:
//! - Forward NTT for Dilithium and Kyber
//! - Inverse NTT for Dilithium and Kyber
//! - NTT-based polynomial multiplication
//! - Montgomery arithmetic operations

use criterion::{criterion_group, criterion_main, Criterion};

#[cfg(feature = "alloc")]
mod ntt_benchmarks {
    use criterion::{black_box, BenchmarkId, Criterion};
    use dcrypt_algorithms::poly::params::{DilithiumParams, Kyber256Params};
    use dcrypt_algorithms::poly::prelude::*;
    use dcrypt_algorithms::poly::sampling::{DefaultSamplers, UniformSampler};
    use dcrypt_internal::random::ChaCha20Rng;

    /// Benchmark forward NTT for Dilithium
    pub fn bench_dilithium_forward_ntt(c: &mut Criterion) {
        let mut group = c.benchmark_group("dilithium_ntt");
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // Create a random polynomial
        let poly = <DefaultSamplers as UniformSampler<DilithiumParams>>::sample_uniform(&mut rng)
            .expect("Failed to sample polynomial");

        group.bench_function("forward", |b| {
            b.iter_batched(
                || poly.clone(),
                |mut p| {
                    p.ntt_inplace().expect("NTT failed");
                    black_box(p)
                },
                criterion::BatchSize::SmallInput,
            )
        });

        group.finish();
    }

    /// Benchmark inverse NTT for Dilithium
    pub fn bench_dilithium_inverse_ntt(c: &mut Criterion) {
        let mut group = c.benchmark_group("dilithium_ntt");
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // Create a polynomial in NTT domain
        let mut poly =
            <DefaultSamplers as UniformSampler<DilithiumParams>>::sample_uniform(&mut rng)
                .expect("Failed to sample polynomial");
        poly.ntt_inplace().expect("NTT failed");

        group.bench_function("inverse", |b| {
            b.iter_batched(
                || poly.clone(),
                |mut p| {
                    p.from_ntt_inplace().expect("Inverse NTT failed");
                    black_box(p)
                },
                criterion::BatchSize::SmallInput,
            )
        });

        group.finish();
    }

    /// Benchmark forward NTT for Kyber
    pub fn bench_kyber_forward_ntt(c: &mut Criterion) {
        let mut group = c.benchmark_group("kyber_ntt");
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // Create a random polynomial
        let poly = <DefaultSamplers as UniformSampler<Kyber256Params>>::sample_uniform(&mut rng)
            .expect("Failed to sample polynomial");

        group.bench_function("forward", |b| {
            b.iter_batched(
                || poly.clone(),
                |mut p| {
                    p.ntt_inplace().expect("NTT failed");
                    black_box(p)
                },
                criterion::BatchSize::SmallInput,
            )
        });

        group.finish();
    }

    /// Benchmark inverse NTT for Kyber
    pub fn bench_kyber_inverse_ntt(c: &mut Criterion) {
        let mut group = c.benchmark_group("kyber_ntt");
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // Create a polynomial in NTT domain
        let mut poly =
            <DefaultSamplers as UniformSampler<Kyber256Params>>::sample_uniform(&mut rng)
                .expect("Failed to sample polynomial");
        poly.ntt_inplace().expect("NTT failed");

        group.bench_function("inverse", |b| {
            b.iter_batched(
                || poly.clone(),
                |mut p| {
                    p.from_ntt_inplace().expect("Inverse NTT failed");
                    black_box(p)
                },
                criterion::BatchSize::SmallInput,
            )
        });

        group.finish();
    }

    /// Benchmark NTT-based polynomial multiplication
    pub fn bench_ntt_multiplication(c: &mut Criterion) {
        let mut group = c.benchmark_group("ntt_multiplication");
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // Dilithium multiplication
        {
            let mut poly_a =
                <DefaultSamplers as UniformSampler<DilithiumParams>>::sample_uniform(&mut rng)
                    .expect("Failed to sample polynomial");
            let mut poly_b =
                <DefaultSamplers as UniformSampler<DilithiumParams>>::sample_uniform(&mut rng)
                    .expect("Failed to sample polynomial");

            poly_a.ntt_inplace().expect("NTT failed");
            poly_b.ntt_inplace().expect("NTT failed");

            group.bench_function("dilithium_pointwise", |b| {
                b.iter(|| {
                    let result = poly_a.ntt_mul(&poly_b);
                    black_box(result)
                })
            });
        }

        // Kyber multiplication
        {
            let mut poly_a =
                <DefaultSamplers as UniformSampler<Kyber256Params>>::sample_uniform(&mut rng)
                    .expect("Failed to sample polynomial");
            let mut poly_b =
                <DefaultSamplers as UniformSampler<Kyber256Params>>::sample_uniform(&mut rng)
                    .expect("Failed to sample polynomial");

            poly_a.ntt_inplace().expect("NTT failed");
            poly_b.ntt_inplace().expect("NTT failed");

            group.bench_function("kyber_pointwise", |b| {
                b.iter(|| {
                    let result = poly_a.ntt_mul(&poly_b);
                    black_box(result)
                })
            });
        }

        group.finish();
    }

    /// Benchmark full polynomial multiplication (NTT + multiply + inverse NTT)
    pub fn bench_full_polynomial_multiplication(c: &mut Criterion) {
        let mut group = c.benchmark_group("full_polynomial_multiplication");
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // Dilithium
        {
            let poly_a =
                <DefaultSamplers as UniformSampler<DilithiumParams>>::sample_uniform(&mut rng)
                    .expect("Failed to sample polynomial");
            let poly_b =
                <DefaultSamplers as UniformSampler<DilithiumParams>>::sample_uniform(&mut rng)
                    .expect("Failed to sample polynomial");

            group.bench_function("dilithium_ntt_based", |b| {
                b.iter_batched(
                    || (poly_a.clone(), poly_b.clone()),
                    |(mut a, mut b)| {
                        a.ntt_inplace().expect("NTT failed");
                        b.ntt_inplace().expect("NTT failed");
                        let mut result = a.ntt_mul(&b);
                        result.from_ntt_inplace().expect("Inverse NTT failed");
                        black_box(result)
                    },
                    criterion::BatchSize::SmallInput,
                )
            });

            group.bench_function("dilithium_schoolbook", |b| {
                b.iter_batched(
                    || (poly_a.clone(), poly_b.clone()),
                    |(a, b)| {
                        let result = a.schoolbook_mul(&b);
                        black_box(result)
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }

        // Kyber
        {
            let poly_a =
                <DefaultSamplers as UniformSampler<Kyber256Params>>::sample_uniform(&mut rng)
                    .expect("Failed to sample polynomial");
            let poly_b =
                <DefaultSamplers as UniformSampler<Kyber256Params>>::sample_uniform(&mut rng)
                    .expect("Failed to sample polynomial");

            group.bench_function("kyber_ntt_based", |b| {
                b.iter_batched(
                    || (poly_a.clone(), poly_b.clone()),
                    |(mut a, mut b)| {
                        a.ntt_inplace().expect("NTT failed");
                        b.ntt_inplace().expect("NTT failed");
                        let mut result = a.ntt_mul(&b);
                        result.from_ntt_inplace().expect("Inverse NTT failed");
                        black_box(result)
                    },
                    criterion::BatchSize::SmallInput,
                )
            });

            group.bench_function("kyber_schoolbook", |b| {
                b.iter_batched(
                    || (poly_a.clone(), poly_b.clone()),
                    |(a, b)| {
                        let result = a.schoolbook_mul(&b);
                        black_box(result)
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }

        group.finish();
    }

    /// Benchmark Montgomery reduction operations
    pub fn bench_montgomery_operations(c: &mut Criterion) {
        let mut group = c.benchmark_group("montgomery_operations");

        // Dilithium Montgomery reduction
        group.bench_function("dilithium_montgomery_reduce", |b| {
            let a: u64 = 0x12345678_9ABCDEF0;
            b.iter(|| {
                let result = montgomery_reduce::<DilithiumParams>(black_box(a));
                black_box(result)
            })
        });

        // Kyber Montgomery reduction
        group.bench_function("kyber_montgomery_reduce", |b| {
            let a: u64 = 0x12345678;
            b.iter(|| {
                let result = montgomery_reduce::<Kyber256Params>(black_box(a));
                black_box(result)
            })
        });

        group.finish();
    }

    /// Benchmark different polynomial sizes (if we add support for them in the future)
    pub fn bench_ntt_scaling(c: &mut Criterion) {
        let mut group = c.benchmark_group("ntt_scaling");
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // For now, we only have N=256, but this is structured to easily add more sizes
        let sizes = vec![("n256", 256)];

        for (label, _size) in sizes {
            // Dilithium
            let poly =
                <DefaultSamplers as UniformSampler<DilithiumParams>>::sample_uniform(&mut rng)
                    .expect("Failed to sample polynomial");

            group.bench_with_input(BenchmarkId::new("dilithium", label), &poly, |b, p| {
                b.iter_batched(
                    || p.clone(),
                    |mut poly| {
                        poly.ntt_inplace().expect("NTT failed");
                        black_box(poly)
                    },
                    criterion::BatchSize::SmallInput,
                )
            });

            // Kyber
            let poly =
                <DefaultSamplers as UniformSampler<Kyber256Params>>::sample_uniform(&mut rng)
                    .expect("Failed to sample polynomial");

            group.bench_with_input(BenchmarkId::new("kyber", label), &poly, |b, p| {
                b.iter_batched(
                    || p.clone(),
                    |mut poly| {
                        poly.ntt_inplace().expect("NTT failed");
                        black_box(poly)
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }

        group.finish();
    }

    /// Benchmark roundtrip operations (forward + inverse NTT)
    pub fn bench_ntt_roundtrip(c: &mut Criterion) {
        let mut group = c.benchmark_group("ntt_roundtrip");
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // Dilithium roundtrip
        let poly_dilithium =
            <DefaultSamplers as UniformSampler<DilithiumParams>>::sample_uniform(&mut rng)
                .expect("Failed to sample polynomial");

        group.bench_function("dilithium", |b| {
            b.iter_batched(
                || poly_dilithium.clone(),
                |mut p| {
                    p.ntt_inplace().expect("NTT failed");
                    p.from_ntt_inplace().expect("Inverse NTT failed");
                    black_box(p)
                },
                criterion::BatchSize::SmallInput,
            )
        });

        // Kyber roundtrip
        let poly_kyber =
            <DefaultSamplers as UniformSampler<Kyber256Params>>::sample_uniform(&mut rng)
                .expect("Failed to sample polynomial");

        group.bench_function("kyber", |b| {
            b.iter_batched(
                || poly_kyber.clone(),
                |mut p| {
                    p.ntt_inplace().expect("NTT failed");
                    p.from_ntt_inplace().expect("Inverse NTT failed");
                    black_box(p)
                },
                criterion::BatchSize::SmallInput,
            )
        });

        group.finish();
    }
}

// Feature-gated benchmark runner
#[cfg(feature = "alloc")]
fn run_ntt_benchmarks(c: &mut Criterion) {
    ntt_benchmarks::bench_dilithium_forward_ntt(c);
    ntt_benchmarks::bench_dilithium_inverse_ntt(c);
    ntt_benchmarks::bench_kyber_forward_ntt(c);
    ntt_benchmarks::bench_kyber_inverse_ntt(c);
    ntt_benchmarks::bench_ntt_multiplication(c);
    ntt_benchmarks::bench_full_polynomial_multiplication(c);
    ntt_benchmarks::bench_montgomery_operations(c);
    ntt_benchmarks::bench_ntt_scaling(c);
    ntt_benchmarks::bench_ntt_roundtrip(c);
}

#[cfg(not(feature = "alloc"))]
fn run_ntt_benchmarks(_c: &mut Criterion) {
    eprintln!("NTT benchmarks require the 'alloc' feature. Run with: cargo bench --bench ntt --features alloc");
}

criterion_group!(benches, run_ntt_benchmarks);
criterion_main!(benches);
