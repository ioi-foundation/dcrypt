// File: crates/algorithms/benches/p256.rs
// Comprehensive benchmarks for NIST P-256 elliptic curve operations

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use dcrypt_algorithms::ec::p256::{
    self, FieldElement, Point, Scalar, P256_FIELD_ELEMENT_SIZE, P256_SCALAR_SIZE,
};
use dcrypt_internal::random::{ChaCha20Rng, RngCore};

fn bench_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0x73; 32])
}

/// Generate a random field element for benchmarking
fn random_field_element() -> FieldElement {
    let mut bytes = [0u8; P256_FIELD_ELEMENT_SIZE];
    loop {
        bench_rng().fill_bytes(&mut bytes);
        // Ensure the value is less than the field modulus
        if let Ok(fe) = FieldElement::from_bytes(&bytes) {
            return fe;
        }
    }
}

/// Generate a random scalar for benchmarking
fn random_scalar() -> Scalar {
    let mut bytes = [0u8; P256_SCALAR_SIZE];
    loop {
        bench_rng().fill_bytes(&mut bytes);
        if let Ok(scalar) = Scalar::new(bytes) {
            return scalar;
        }
    }
}

/// Generate a random point on the curve
fn random_point() -> Point {
    let scalar = random_scalar();
    p256::scalar_mult_base_g(&scalar).unwrap()
}

/// Benchmark field element operations
fn bench_field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-field");

    // Field element addition
    group.bench_function("addition", |b| {
        b.iter_batched(
            || (random_field_element(), random_field_element()),
            |(a, b)| black_box(a.add(&b)),
            BatchSize::SmallInput,
        )
    });

    // Field element subtraction
    group.bench_function("subtraction", |b| {
        b.iter_batched(
            || (random_field_element(), random_field_element()),
            |(a, b)| black_box(a.sub(&b)),
            BatchSize::SmallInput,
        )
    });

    // Field element multiplication
    group.bench_function("multiplication", |b| {
        b.iter_batched(
            || (random_field_element(), random_field_element()),
            |(a, b)| black_box(a.mul(&b)),
            BatchSize::SmallInput,
        )
    });

    // Field element squaring
    group.bench_function("squaring", |b| {
        b.iter_batched(
            || random_field_element(),
            |a| black_box(a.square()),
            BatchSize::SmallInput,
        )
    });

    // Field element inversion
    group.bench_function("inversion", |b| {
        b.iter_batched(
            || random_field_element(),
            |a| black_box(a.invert().unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Field element square root
    group.bench_function("sqrt", |b| {
        b.iter_batched(
            || {
                // Generate a quadratic residue by squaring
                let x = random_field_element();
                x.square()
            },
            |a| black_box(a.sqrt()),
            BatchSize::SmallInput,
        )
    });

    // Field element serialization
    group.bench_function("to_bytes", |b| {
        b.iter_batched(
            || random_field_element(),
            |a| black_box(a.to_bytes()),
            BatchSize::SmallInput,
        )
    });

    // Field element deserialization
    group.bench_function("from_bytes", |b| {
        b.iter_batched(
            || random_field_element().to_bytes(),
            |bytes| black_box(FieldElement::from_bytes(&bytes).unwrap()),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Benchmark point operations
fn bench_point_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-point");

    // Point addition
    group.bench_function("addition", |b| {
        b.iter_batched(
            || (random_point(), random_point()),
            |(p1, p2)| black_box(p1.add(&p2)),
            BatchSize::SmallInput,
        )
    });

    // Point doubling
    group.bench_function("doubling", |b| {
        b.iter_batched(
            || random_point(),
            |p| black_box(p.double()),
            BatchSize::SmallInput,
        )
    });

    // Point scalar multiplication (variable-base)
    group.bench_function("scalar_mult", |b| {
        b.iter_batched(
            || (random_point(), random_scalar()),
            |(p, s)| black_box(p.mul(&s).unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Point scalar multiplication (fixed-base with generator)
    group.bench_function("scalar_mult_base", |b| {
        b.iter_batched(
            || random_scalar(),
            |s| black_box(p256::scalar_mult_base_g(&s).unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Point validation
    group.bench_function("validation", |b| {
        b.iter_batched(
            || {
                let p = random_point();
                (p.x_coordinate_bytes(), p.y_coordinate_bytes())
            },
            |(x, y)| black_box(Point::new_uncompressed(&x, &y)),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Benchmark scalar operations
fn bench_scalar_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-scalar");

    // Scalar addition mod n
    group.bench_function("add_mod_n", |b| {
        b.iter_batched(
            || (random_scalar(), random_scalar()),
            |(a, b)| black_box(a.add_mod_n(&b).unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Scalar subtraction mod n
    group.bench_function("sub_mod_n", |b| {
        b.iter_batched(
            || (random_scalar(), random_scalar()),
            |(a, b)| black_box(a.sub_mod_n(&b).unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Scalar multiplication mod n
    group.bench_function("mul_mod_n", |b| {
        b.iter_batched(
            || (random_scalar(), random_scalar()),
            |(a, b)| black_box(a.mul_mod_n(&b).unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Scalar inversion mod n
    group.bench_function("inv_mod_n", |b| {
        b.iter_batched(
            || random_scalar(),
            |a| black_box(a.inv_mod_n().unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Scalar negation
    group.bench_function("negate", |b| {
        b.iter_batched(
            || random_scalar(),
            |a| black_box(a.negate()),
            BatchSize::SmallInput,
        )
    });

    // Scalar validation/reduction
    group.bench_function("new", |b| {
        b.iter_batched(
            || {
                let mut bytes = [0u8; P256_SCALAR_SIZE];
                bench_rng().fill_bytes(&mut bytes);
                bytes
            },
            |bytes| black_box(Scalar::new(bytes)),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Benchmark serialization operations
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-serialization");

    // Uncompressed point serialization
    group.bench_function("serialize_uncompressed", |b| {
        b.iter_batched(
            || random_point(),
            |p| black_box(p.serialize_uncompressed()),
            BatchSize::SmallInput,
        )
    });

    // Uncompressed point deserialization
    group.bench_function("deserialize_uncompressed", |b| {
        b.iter_batched(
            || random_point().serialize_uncompressed(),
            |bytes| black_box(Point::deserialize_uncompressed(&bytes).unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Compressed point serialization
    group.bench_function("serialize_compressed", |b| {
        b.iter_batched(
            || random_point(),
            |p| black_box(p.serialize_compressed()),
            BatchSize::SmallInput,
        )
    });

    // Compressed point deserialization
    group.bench_function("deserialize_compressed", |b| {
        b.iter_batched(
            || random_point().serialize_compressed(),
            |bytes| black_box(Point::deserialize_compressed(&bytes).unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Point format detection
    group.bench_function("detect_format", |b| {
        b.iter_batched(
            || random_point().serialize_uncompressed(),
            |bytes| black_box(Point::detect_format(&bytes).unwrap()),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Benchmark key generation and ECDH operations
fn bench_crypto_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-crypto");

    // Key pair generation
    group.bench_function("generate_keypair", |b| {
        let mut rng = bench_rng();
        b.iter(|| black_box(p256::generate_keypair(&mut rng).unwrap()))
    });

    // ECDH shared secret computation (without KDF)
    group.bench_function("ecdh_raw", |b| {
        b.iter_batched(
            || {
                let mut rng = bench_rng();
                let (priv_a, _) = p256::generate_keypair(&mut rng).unwrap();
                let (_, pub_b) = p256::generate_keypair(&mut rng).unwrap();
                (priv_a, pub_b)
            },
            |(priv_key, pub_key)| black_box(p256::scalar_mult(&priv_key, &pub_key).unwrap()),
            BatchSize::SmallInput,
        )
    });

    // KDF for ECDH
    group.bench_function("kdf_hkdf_sha256", |b| {
        b.iter_batched(
            || {
                let mut ikm = [0u8; 32];
                bench_rng().fill_bytes(&mut ikm);
                ikm
            },
            |ikm| black_box(p256::kdf_hkdf_sha256_for_ecdh_kem(&ikm, Some(b"test info")).unwrap()),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Benchmark complete ECDH workflow
fn bench_ecdh_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-ecdh-workflow");

    // Complete ECDH key agreement (key gen + scalar mult + KDF)
    group.bench_function("complete", |b| {
        b.iter_batched(
            || {
                let mut rng = bench_rng();
                let (priv_a, _) = p256::generate_keypair(&mut rng).unwrap();
                let (_, pub_b) = p256::generate_keypair(&mut rng).unwrap();
                (priv_a, pub_b)
            },
            |(priv_key, pub_key)| {
                // Compute shared point
                let shared_point = p256::scalar_mult(&priv_key, &pub_key).unwrap();

                // Extract x-coordinate for KDF input
                let shared_x = shared_point.x_coordinate_bytes();

                // Derive key using KDF
                black_box(p256::kdf_hkdf_sha256_for_ecdh_kem(&shared_x, Some(b"ECDH")).unwrap())
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Benchmark various scalar sizes
fn bench_scalar_mult_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256-scalar-mult-sizes");

    // Small scalar (few bits set)
    group.bench_function("small_scalar", |b| {
        b.iter_batched(
            || {
                let mut bytes = [0u8; P256_SCALAR_SIZE];
                bytes[31] = 0xFF; // 8 bits
                (p256::base_point_g(), Scalar::new(bytes).unwrap())
            },
            |(p, s)| black_box(p.mul(&s).unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Medium scalar (half bits set)
    group.bench_function("medium_scalar", |b| {
        b.iter_batched(
            || {
                let mut bytes = [0u8; P256_SCALAR_SIZE];
                for i in 16..32 {
                    bytes[i] = 0xFF;
                }
                (p256::base_point_g(), Scalar::new(bytes).unwrap())
            },
            |(p, s)| black_box(p.mul(&s).unwrap()),
            BatchSize::SmallInput,
        )
    });

    // Large scalar (most bits set)
    group.bench_function("large_scalar", |b| {
        b.iter_batched(
            || {
                let mut bytes = [0xFF; P256_SCALAR_SIZE];
                bytes[0] = 0x00; // Ensure it's less than curve order
                (p256::base_point_g(), Scalar::new(bytes).unwrap())
            },
            |(p, s)| black_box(p.mul(&s).unwrap()),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_field_operations,
    bench_point_operations,
    bench_scalar_operations,
    bench_serialization,
    bench_crypto_operations,
    bench_ecdh_workflow,
    bench_scalar_mult_sizes
);

criterion_main!(benches);
