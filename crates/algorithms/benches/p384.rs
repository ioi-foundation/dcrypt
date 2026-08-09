use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use dcrypt_algorithms::ec::p384::{self, FieldElement, Point, Scalar};
use dcrypt_internal::random::{ChaCha20Rng, RngCore};

fn bench_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0x74; 32])
}

/// Benchmark P384 field element operations
fn bench_field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_field");

    // Prepare test data
    let mut bytes_a = [0u8; 48];
    let mut bytes_b = [0u8; 48];
    bench_rng().fill_bytes(&mut bytes_a);
    bench_rng().fill_bytes(&mut bytes_b);
    // Ensure they're valid field elements by reducing modulo p
    bytes_a[0] &= 0x7F; // Clear high bits to ensure < p
    bytes_b[0] &= 0x7F;

    let a = FieldElement::from_bytes(&bytes_a).unwrap();
    let b = FieldElement::from_bytes(&bytes_b).unwrap();

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(a.add(&b)));
    });

    group.bench_function("sub", |bencher| {
        bencher.iter(|| black_box(a.sub(&b)));
    });

    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(a.mul(&b)));
    });

    group.bench_function("square", |bencher| {
        bencher.iter(|| black_box(a.square()));
    });

    group.bench_function("invert", |bencher| {
        bencher.iter(|| black_box(a.invert().unwrap()));
    });

    group.bench_function("sqrt", |bencher| {
        // Use a known quadratic residue
        let qr = a.square();
        bencher.iter(|| black_box(qr.sqrt()));
    });

    group.finish();
}

/// Benchmark P384 point operations
fn bench_point_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_point");

    // Get base point
    let g = p384::base_point_g();

    // Generate a random point
    let scalar = {
        let mut bytes = [0u8; 48];
        bench_rng().fill_bytes(&mut bytes);
        bytes[0] &= 0x7F; // Ensure valid scalar
        Scalar::new(bytes).unwrap()
    };
    let point = g.mul(&scalar).unwrap();

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(g.add(&point)));
    });

    group.bench_function("double", |bencher| {
        bencher.iter(|| black_box(g.double()));
    });

    group.bench_function("serialize_uncompressed", |bencher| {
        bencher.iter(|| black_box(point.serialize_uncompressed()));
    });

    group.bench_function("deserialize_uncompressed", |bencher| {
        let serialized = point.serialize_uncompressed();
        bencher.iter(|| black_box(Point::deserialize_uncompressed(&serialized).unwrap()));
    });

    group.bench_function("serialize_compressed", |bencher| {
        bencher.iter(|| black_box(point.serialize_compressed()));
    });

    group.bench_function("deserialize_compressed", |bencher| {
        let compressed = point.serialize_compressed();
        bencher.iter(|| black_box(Point::deserialize_compressed(&compressed).unwrap()));
    });

    group.finish();
}

/// Benchmark P384 scalar multiplication
fn bench_scalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_scalar_mul");

    let g = p384::base_point_g();

    // Benchmark scalar multiplication with base point
    group.bench_function("base_point", |bencher| {
        bencher.iter_batched(
            || {
                let mut bytes = [0u8; 48];
                bench_rng().fill_bytes(&mut bytes);
                bytes[0] &= 0x7F; // Ensure valid scalar
                Scalar::new(bytes).unwrap()
            },
            |scalar| black_box(p384::scalar_mult_base_g(&scalar).unwrap()),
            BatchSize::SmallInput,
        );
    });

    // Benchmark scalar multiplication with arbitrary point
    let point = {
        let mut bytes = [0u8; 48];
        bench_rng().fill_bytes(&mut bytes);
        bytes[0] &= 0x7F;
        let s = Scalar::new(bytes).unwrap();
        g.mul(&s).unwrap()
    };

    group.bench_function("arbitrary_point", |bencher| {
        bencher.iter_batched(
            || {
                let mut bytes = [0u8; 48];
                bench_rng().fill_bytes(&mut bytes);
                bytes[0] &= 0x7F;
                Scalar::new(bytes).unwrap()
            },
            |scalar| black_box(point.mul(&scalar).unwrap()),
            BatchSize::SmallInput,
        );
    });

    // Benchmark with different scalar bit lengths
    for bits in [128, 192, 256, 384] {
        group.bench_with_input(BenchmarkId::new("bits", bits), &bits, |bencher, &bits| {
            bencher.iter_batched(
                || {
                    let mut bytes = [0u8; 48];
                    // Generate random bytes for the specified bit length
                    let byte_len = bits / 8;
                    let byte_offset = 48 - byte_len;
                    bench_rng().fill_bytes(&mut bytes[byte_offset..]);
                    // Clear unused high-order bytes
                    for i in 0..byte_offset {
                        bytes[i] = 0;
                    }
                    // Ensure valid scalar
                    if byte_offset == 0 {
                        bytes[0] &= 0x7F;
                    }
                    Scalar::new(bytes).unwrap()
                },
                |scalar| black_box(g.mul(&scalar).unwrap()),
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark P384 scalar arithmetic
fn bench_scalar_arithmetic(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_scalar");

    // Generate test scalars
    let a = {
        let mut bytes = [0u8; 48];
        bench_rng().fill_bytes(&mut bytes);
        bytes[0] &= 0x7F;
        Scalar::new(bytes).unwrap()
    };

    let b = {
        let mut bytes = [0u8; 48];
        bench_rng().fill_bytes(&mut bytes);
        bytes[0] &= 0x7F;
        Scalar::new(bytes).unwrap()
    };

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(a.add_mod_n(&b).unwrap()));
    });

    group.bench_function("sub", |bencher| {
        bencher.iter(|| black_box(a.sub_mod_n(&b).unwrap()));
    });

    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(a.mul_mod_n(&b).unwrap()));
    });

    group.bench_function("invert", |bencher| {
        bencher.iter(|| black_box(a.inv_mod_n().unwrap()));
    });

    group.bench_function("negate", |bencher| {
        bencher.iter(|| black_box(a.negate()));
    });

    group.bench_function("serialize", |bencher| {
        bencher.iter(|| black_box(a.serialize()));
    });

    group.bench_function("deserialize", |bencher| {
        let bytes = a.serialize();
        bencher.iter(|| black_box(Scalar::deserialize(bytes.as_ref()).unwrap()));
    });

    group.finish();
}

/// Benchmark P384 key generation
fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_keygen");

    group.bench_function("generate_keypair", |bencher| {
        let mut rng = bench_rng();
        bencher.iter(|| black_box(p384::generate_keypair(&mut rng).unwrap()));
    });

    group.finish();
}

/// Benchmark P384 ECDH operations
fn bench_ecdh_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_ecdh");

    // Generate two keypairs for ECDH
    let mut rng = bench_rng();
    let (sk_a, _) = p384::generate_keypair(&mut rng).unwrap();
    let (_, pk_b) = p384::generate_keypair(&mut rng).unwrap();

    group.bench_function("shared_secret", |bencher| {
        bencher.iter(|| black_box(pk_b.mul(&sk_a).unwrap()));
    });

    group.bench_function("kdf_hkdf_sha384", |bencher| {
        let shared_point = pk_b.mul(&sk_a).unwrap();
        let shared_x = shared_point.x_coordinate_bytes();
        let info = b"P384 ECDH KDF Test";

        bencher
            .iter(|| black_box(p384::kdf_hkdf_sha384_for_ecdh_kem(&shared_x, Some(info)).unwrap()));
    });

    group.finish();
}

/// Benchmark complete ECDH key exchange
fn bench_complete_ecdh(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_ecdh_complete");

    group.bench_function("full_exchange", |bencher| {
        let mut rng = bench_rng();

        bencher.iter(|| {
            // Alice generates keypair
            let (sk_a, pk_a) = p384::generate_keypair(&mut rng).unwrap();

            // Bob generates keypair
            let (sk_b, pk_b) = p384::generate_keypair(&mut rng).unwrap();

            // Alice computes shared secret
            let shared_a = pk_b.mul(&sk_a).unwrap();
            let shared_a_x = shared_a.x_coordinate_bytes();

            // Bob computes shared secret
            let shared_b = pk_a.mul(&sk_b).unwrap();
            let shared_b_x = shared_b.x_coordinate_bytes();

            // Derive keys
            let key_a = p384::kdf_hkdf_sha384_for_ecdh_kem(&shared_a_x, Some(b"ECDH")).unwrap();
            let key_b = p384::kdf_hkdf_sha384_for_ecdh_kem(&shared_b_x, Some(b"ECDH")).unwrap();

            black_box((key_a, key_b))
        });
    });

    group.finish();
}

/// Benchmark batch operations
fn bench_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p384_batch");

    // Benchmark batch point addition
    let points: Vec<Point> = (0..10)
        .map(|_| {
            let mut bytes = [0u8; 48];
            bench_rng().fill_bytes(&mut bytes);
            bytes[0] &= 0x7F;
            let scalar = Scalar::new(bytes).unwrap();
            p384::base_point_g().mul(&scalar).unwrap()
        })
        .collect();

    group.bench_function("sum_10_points", |bencher| {
        bencher.iter(|| {
            let mut sum = Point::identity();
            for point in &points {
                sum = sum.add(point);
            }
            black_box(sum)
        });
    });

    // Benchmark batch scalar multiplication
    let scalars: Vec<Scalar> = (0..10)
        .map(|_| {
            let mut bytes = [0u8; 48];
            bench_rng().fill_bytes(&mut bytes);
            bytes[0] &= 0x7F;
            Scalar::new(bytes).unwrap()
        })
        .collect();

    group.bench_function("scalar_mul_10_points", |bencher| {
        let g = p384::base_point_g();
        bencher.iter(|| {
            let results: Vec<Point> = scalars.iter().map(|s| g.mul(s).unwrap()).collect();
            black_box(results)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_field_operations,
    bench_point_operations,
    bench_scalar_multiplication,
    bench_scalar_arithmetic,
    bench_key_generation,
    bench_ecdh_operations,
    bench_complete_ecdh,
    bench_batch_operations
);

criterion_main!(benches);
