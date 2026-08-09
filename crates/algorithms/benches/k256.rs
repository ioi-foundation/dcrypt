//! Benchmarks for secp256k1 (K256) elliptic curve operations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dcrypt_algorithms::ec::k256::{
    base_point_g, generate_keypair, scalar_mult, scalar_mult_base_g, FieldElement, Point, Scalar,
    K256_FIELD_ELEMENT_SIZE, K256_SCALAR_SIZE,
};
use dcrypt_internal::random::{ChaCha20Rng, RngCore};

fn bench_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0x72; 32])
}

/// Generate a random field element for benchmarking
fn random_field_element() -> FieldElement {
    let mut bytes = [0u8; K256_FIELD_ELEMENT_SIZE];
    bench_rng().fill_bytes(&mut bytes);
    // Retry if we happen to get a value >= p (very unlikely)
    loop {
        if let Ok(fe) = FieldElement::from_bytes(&bytes) {
            return fe;
        }
        bench_rng().fill_bytes(&mut bytes);
    }
}

/// Generate a random scalar for benchmarking
fn random_scalar() -> Scalar {
    let mut bytes = [0u8; K256_SCALAR_SIZE];
    loop {
        bench_rng().fill_bytes(&mut bytes);
        if let Ok(scalar) = Scalar::new(bytes) {
            return scalar;
        }
    }
}

/// Generate a random point on the curve for benchmarking
fn random_point() -> Point {
    let scalar = random_scalar();
    scalar_mult_base_g(&scalar).expect("scalar multiplication should succeed")
}

fn bench_field_arithmetic(c: &mut Criterion) {
    let mut group = c.benchmark_group("k256_field");

    // Setup test values
    let a = random_field_element();
    let b = random_field_element();

    group.bench_function("add", |bench| {
        bench.iter(|| black_box(&a).add(black_box(&b)));
    });

    group.bench_function("sub", |bench| {
        bench.iter(|| black_box(&a).sub(black_box(&b)));
    });

    group.bench_function("mul", |bench| {
        bench.iter(|| black_box(&a).mul(black_box(&b)));
    });

    group.bench_function("square", |bench| {
        bench.iter(|| black_box(&a).square());
    });

    group.bench_function("double", |bench| {
        bench.iter(|| black_box(&a).double());
    });

    group.bench_function("negate", |bench| {
        bench.iter(|| black_box(&a).negate());
    });

    group.bench_function("invert", |bench| {
        bench.iter(|| black_box(&a).invert().expect("inversion should succeed"));
    });

    group.bench_function("sqrt", |bench| {
        // Use a known square for consistent benchmarking
        let square = a.square();
        bench.iter(|| black_box(&square).sqrt());
    });

    group.finish();
}

fn bench_point_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("k256_point");

    // Setup test points
    let p1 = random_point();
    let p2 = random_point();

    group.bench_function("add", |bench| {
        bench.iter(|| black_box(&p1).add(black_box(&p2)));
    });

    group.bench_function("double", |bench| {
        bench.iter(|| black_box(&p1).double());
    });

    group.bench_function("serialize_compressed", |bench| {
        bench.iter(|| black_box(&p1).serialize_compressed());
    });

    group.bench_function("deserialize_compressed", |bench| {
        let compressed = p1.serialize_compressed();
        bench.iter(|| {
            Point::deserialize_compressed(black_box(&compressed))
                .expect("decompression should succeed")
        });
    });

    group.bench_function("is_identity", |bench| {
        bench.iter(|| black_box(&p1).is_identity());
    });

    group.finish();
}

fn bench_scalar_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("k256_scalar_mult");

    // Setup test values
    let scalar = random_scalar();
    let point = random_point();
    let base_g = base_point_g();

    group.bench_function("with_base_point_g", |bench| {
        bench.iter(|| {
            scalar_mult_base_g(black_box(&scalar)).expect("scalar multiplication should succeed")
        });
    });

    group.bench_function("with_random_point", |bench| {
        bench.iter(|| {
            scalar_mult(black_box(&scalar), black_box(&point))
                .expect("scalar multiplication should succeed")
        });
    });

    group.bench_function("point_mul_method", |bench| {
        bench.iter(|| {
            black_box(&base_g)
                .mul(black_box(&scalar))
                .expect("scalar multiplication should succeed")
        });
    });

    // Benchmark different scalar sizes to see performance characteristics
    group.bench_function("small_scalar", |bench| {
        let mut small_bytes = [0u8; K256_SCALAR_SIZE];
        small_bytes[31] = 42; // Small scalar value
        let small_scalar = Scalar::new(small_bytes).expect("scalar creation should succeed");

        bench.iter(|| {
            black_box(&base_g)
                .mul(black_box(&small_scalar))
                .expect("scalar multiplication should succeed")
        });
    });

    group.bench_function("large_scalar", |bench| {
        let mut large_bytes = [0xFF; K256_SCALAR_SIZE];
        large_bytes[31] = 0xFE; // Large but valid scalar
        let large_scalar = Scalar::new(large_bytes).expect("scalar creation should succeed");

        bench.iter(|| {
            black_box(&base_g)
                .mul(black_box(&large_scalar))
                .expect("scalar multiplication should succeed")
        });
    });

    group.finish();
}

fn bench_key_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("k256_keys");

    group.bench_function("generate_keypair", |bench| {
        bench.iter(|| {
            generate_keypair(&mut bench_rng()).expect("keypair generation should succeed")
        });
    });

    group.bench_function("scalar_creation", |bench| {
        let mut bytes = [0u8; K256_SCALAR_SIZE];
        bench_rng().fill_bytes(&mut bytes);
        bench.iter(|| Scalar::new(black_box(bytes)));
    });

    group.bench_function("scalar_reduction", |bench| {
        // Use bytes that are guaranteed to need reduction
        let bytes = [0xFF; K256_SCALAR_SIZE];
        bench.iter(|| Scalar::new(black_box(bytes)));
    });

    group.finish();
}

fn bench_field_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("k256_field_serialization");

    let fe = random_field_element();
    let bytes = fe.to_bytes();

    group.bench_function("to_bytes", |bench| {
        bench.iter(|| black_box(&fe).to_bytes());
    });

    group.bench_function("from_bytes", |bench| {
        bench.iter(|| {
            FieldElement::from_bytes(black_box(&bytes)).expect("deserialization should succeed")
        });
    });

    group.finish();
}

fn bench_point_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("k256_point_validation");

    // Generate valid and invalid test data
    let valid_point = random_point();
    let valid_x = valid_point.x_coordinate_bytes();
    let valid_y = valid_point.y_coordinate_bytes();

    // Create an invalid point (not on curve)
    let mut invalid_x = [0u8; K256_FIELD_ELEMENT_SIZE];
    let mut invalid_y = [0u8; K256_FIELD_ELEMENT_SIZE];
    bench_rng().fill_bytes(&mut invalid_x);
    bench_rng().fill_bytes(&mut invalid_y);

    group.bench_function("new_uncompressed_valid", |bench| {
        bench.iter(|| Point::new_uncompressed(black_box(&valid_x), black_box(&valid_y)));
    });

    group.bench_function("new_uncompressed_invalid", |bench| {
        bench.iter(|| Point::new_uncompressed(black_box(&invalid_x), black_box(&invalid_y)));
    });

    group.finish();
}

// Benchmark the complete ECDH flow
fn bench_ecdh_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("k256_ecdh");

    // Generate two keypairs for ECDH
    let (sk1, pk1) = generate_keypair(&mut bench_rng()).expect("keypair generation should succeed");
    let (sk2, pk2) = generate_keypair(&mut bench_rng()).expect("keypair generation should succeed");

    group.bench_function("shared_secret_computation", |bench| {
        bench.iter(|| {
            // Alice computes shared secret using Bob's public key
            scalar_mult(black_box(&sk1), black_box(&pk2))
                .expect("scalar multiplication should succeed")
        });
    });

    group.bench_function("full_ecdh_exchange", |bench| {
        bench.iter(|| {
            // Alice's side
            let shared1 = scalar_mult(black_box(&sk1), black_box(&pk2))
                .expect("scalar multiplication should succeed");
            // Bob's side
            let shared2 = scalar_mult(black_box(&sk2), black_box(&pk1))
                .expect("scalar multiplication should succeed");
            // In practice, these should be equal
            black_box(shared1);
            black_box(shared2);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_field_arithmetic,
    bench_point_operations,
    bench_scalar_multiplication,
    bench_key_operations,
    bench_field_serialization,
    bench_point_validation,
    bench_ecdh_operations
);
criterion_main!(benches);
