use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dcrypt_algorithms::kdf::argon2::{Algorithm, Argon2, Params};
use dcrypt_algorithms::kdf::{KdfOperation, KeyDerivationFunction, PasswordHashFunction};
use dcrypt_algorithms::types::{Salt, SecretBytes};

const PASSWORD: &[u8] = b"correct horse battery staple";
const SALT_SIZE: usize = 16;

fn bench_argon2_variants(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2/variants");
    group.sample_size(10); // Reduce sample size due to slow operations

    let salt = Salt::<SALT_SIZE>::new([0x42; SALT_SIZE]);

    // Test different variants with standard parameters
    let variants = [
        ("argon2i", Algorithm::Argon2i),
        ("argon2d", Algorithm::Argon2d),
        ("argon2id", Algorithm::Argon2id),
    ];

    for (name, variant) in variants {
        let params = Params::<SALT_SIZE> {
            argon_type: variant,
            version: 0x13,
            memory_cost: 65536, // 64 MiB
            time_cost: 3,
            parallelism: 4,
            output_len: 32,
            salt: salt.clone(),
            ad: None,
            secret: None,
        };

        let argon2 = Argon2::new_with_params(params);

        group.bench_function(name, |b| {
            b.iter(|| {
                let _ = argon2.hash_password(black_box(PASSWORD));
            });
        });
    }

    group.finish();
}

fn bench_memory_costs(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2/memory_cost");
    group.sample_size(10);

    let salt = Salt::<SALT_SIZE>::new([0x42; SALT_SIZE]);

    // Test different memory costs (in KiB)
    let memory_costs = [(4096, "4MiB"), (16384, "16MiB"), (65536, "64MiB")];

    for (memory_cost, label) in memory_costs {
        let params = Params::<SALT_SIZE> {
            argon_type: Algorithm::Argon2id,
            version: 0x13,
            memory_cost,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
            salt: salt.clone(),
            ad: None,
            secret: None,
        };

        let argon2 = Argon2::new_with_params(params);

        group.bench_with_input(BenchmarkId::new("argon2id", label), &memory_cost, |b, _| {
            b.iter(|| {
                let _ = argon2.hash_password(black_box(PASSWORD));
            });
        });
    }

    group.finish();
}

fn bench_time_costs(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2/time_cost");
    group.sample_size(10);

    let salt = Salt::<SALT_SIZE>::new([0x42; SALT_SIZE]);

    // Test different time costs (iterations)
    let time_costs = [1, 2, 3, 4];

    for time_cost in time_costs {
        let params = Params::<SALT_SIZE> {
            argon_type: Algorithm::Argon2id,
            version: 0x13,
            memory_cost: 4096, // 4 MiB - smaller for faster benchmarks
            time_cost,
            parallelism: 1,
            output_len: 32,
            salt: salt.clone(),
            ad: None,
            secret: None,
        };

        let argon2 = Argon2::new_with_params(params);

        group.bench_with_input(
            BenchmarkId::new("argon2id", format!("t={}", time_cost)),
            &time_cost,
            |b, _| {
                b.iter(|| {
                    let _ = argon2.hash_password(black_box(PASSWORD));
                });
            },
        );
    }

    group.finish();
}

fn bench_parallelism(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2/parallelism");
    group.sample_size(10);

    let salt = Salt::<SALT_SIZE>::new([0x42; SALT_SIZE]);

    // Test different parallelism levels
    let parallelism_levels = [1, 2, 4, 8];

    for parallelism in parallelism_levels {
        let params = Params::<SALT_SIZE> {
            argon_type: Algorithm::Argon2id,
            version: 0x13,
            memory_cost: 4096 * parallelism, // Scale memory with parallelism
            time_cost: 2,
            parallelism,
            output_len: 32,
            salt: salt.clone(),
            ad: None,
            secret: None,
        };

        let argon2 = Argon2::new_with_params(params);

        group.bench_with_input(
            BenchmarkId::new("argon2id", format!("p={}", parallelism)),
            &parallelism,
            |b, _| {
                b.iter(|| {
                    let _ = argon2.hash_password(black_box(PASSWORD));
                });
            },
        );
    }

    group.finish();
}

fn bench_kdf_trait_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2/kdf_trait");
    group.sample_size(10);

    // Standard parameters for KDF operations
    let params = Params::<SALT_SIZE> {
        argon_type: Algorithm::Argon2id,
        version: 0x13,
        memory_cost: 4096, // 4 MiB for faster benchmarks
        time_cost: 2,
        parallelism: 1,
        output_len: 32,
        salt: Salt::<SALT_SIZE>::new([0x42; SALT_SIZE]),
        ad: None,
        secret: None,
    };

    let argon2 = Argon2::new_with_params(params);
    let ikm = b"input key material";
    let salt = [0x42u8; 16];

    // Benchmark basic derive_key operation
    group.bench_function("derive_key", |b| {
        b.iter(|| {
            let _ = argon2.derive_key(black_box(ikm), Some(black_box(&salt)), None, 32);
        });
    });

    // Benchmark builder pattern
    group.bench_function("builder_derive", |b| {
        b.iter(|| {
            let _ = argon2
                .builder()
                .with_ikm(black_box(ikm))
                .with_salt(black_box(&salt))
                .with_output_length(32)
                .derive();
        });
    });

    group.finish();
}

fn bench_password_hash_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2/password_hash");
    group.sample_size(10);

    let params = Params::<SALT_SIZE> {
        argon_type: Algorithm::Argon2id,
        version: 0x13,
        memory_cost: 4096, // 4 MiB
        time_cost: 2,
        parallelism: 1,
        output_len: 32,
        salt: Salt::<SALT_SIZE>::new([0x42; SALT_SIZE]),
        ad: None,
        secret: None,
    };

    let argon2 = Argon2::new_with_params(params);
    let password = SecretBytes::<32>::new(*b"correct horse battery staple    ");

    // Benchmark password hashing
    group.bench_function("hash", |b| {
        b.iter(|| {
            let _ = <Argon2<SALT_SIZE> as PasswordHashFunction>::hash_password(
                &argon2,
                black_box(&password),
            );
        });
    });

    // Create a hash for verification benchmarks
    let hash = <Argon2<SALT_SIZE> as PasswordHashFunction>::hash_password(&argon2, &password)
        .expect("Failed to create hash");

    // Benchmark password verification
    group.bench_function("verify", |b| {
        b.iter(|| {
            let _ = argon2.verify(black_box(&password), black_box(&hash));
        });
    });

    group.finish();
}

fn bench_output_lengths(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2/output_length");
    group.sample_size(10);

    let salt = Salt::<SALT_SIZE>::new([0x42; SALT_SIZE]);
    let output_lengths = [16, 32, 64, 128];

    for output_len in output_lengths {
        let params = Params::<SALT_SIZE> {
            argon_type: Algorithm::Argon2id,
            version: 0x13,
            memory_cost: 4096, // 4 MiB
            time_cost: 2,
            parallelism: 1,
            output_len,
            salt: salt.clone(),
            ad: None,
            secret: None,
        };

        let argon2 = Argon2::new_with_params(params);

        group.throughput(Throughput::Bytes(output_len as u64));
        group.bench_with_input(
            BenchmarkId::new("argon2id", format!("{}B", output_len)),
            &output_len,
            |b, _| {
                b.iter(|| {
                    let _ = argon2.hash_password(black_box(PASSWORD));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_argon2_variants,
    bench_memory_costs,
    bench_time_costs,
    bench_parallelism,
    bench_kdf_trait_operations,
    bench_password_hash_operations,
    bench_output_lengths
);

criterion_main!(benches);
