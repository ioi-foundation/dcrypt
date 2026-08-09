//! P-521 elliptic curve benchmarks

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dcrypt_algorithms::ec::p521::{self, FieldElement, Point, Scalar};
use dcrypt_internal::random::ChaCha20Rng;
use dcrypt_params::traditional::ecdsa::NIST_P521;

fn bench_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0x75; 32])
}

/// Benchmark field arithmetic operations
fn bench_field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521/field");

    // Sample field elements for benchmarking
    let x = FieldElement::from_bytes(&NIST_P521.g_x).unwrap();
    let y = FieldElement::from_bytes(&NIST_P521.g_y).unwrap();

    // Field addition
    group.bench_function("add", |b| b.iter(|| black_box(x.add(&y))));

    // Field subtraction
    group.bench_function("sub", |b| b.iter(|| black_box(x.sub(&y))));

    // Field multiplication
    group.bench_function("mul", |b| b.iter(|| black_box(x.mul(&y))));

    // Field squaring
    group.bench_function("square", |b| b.iter(|| black_box(x.square())));

    // Field inversion
    group.bench_function("invert", |b| b.iter(|| black_box(x.invert().unwrap())));

    // Field square root
    group.bench_function("sqrt", |b| {
        let square = x.square(); // Ensure we have a quadratic residue
        b.iter(|| black_box(square.sqrt().unwrap()))
    });

    group.finish();
}

/// Benchmark scalar arithmetic operations
fn bench_scalar_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521/scalar");

    // Generate two random scalars for testing
    let mut rng = bench_rng();
    let (scalar1, _) = p521::generate_keypair(&mut rng).unwrap();
    let (scalar2, _) = p521::generate_keypair(&mut rng).unwrap();

    // Scalar addition modulo n
    group.bench_function("add_mod_n", |b| {
        b.iter(|| black_box(scalar1.add_mod_n(&scalar2).unwrap()))
    });

    // Scalar subtraction modulo n
    group.bench_function("sub_mod_n", |b| {
        b.iter(|| black_box(scalar1.sub_mod_n(&scalar2).unwrap()))
    });

    // Scalar multiplication modulo n
    group.bench_function("mul_mod_n", |b| {
        b.iter(|| black_box(scalar1.mul_mod_n(&scalar2).unwrap()))
    });

    // Scalar inversion modulo n
    group.bench_function("inv_mod_n", |b| {
        b.iter(|| black_box(scalar1.inv_mod_n().unwrap()))
    });

    // Scalar negation
    group.bench_function("negate", |b| b.iter(|| black_box(scalar1.negate())));

    group.finish();
}

/// Benchmark elliptic curve point operations
fn bench_point_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521/point");

    let g = p521::base_point_g();
    let g2 = g.double();

    // Point addition
    group.bench_function("add", |b| b.iter(|| black_box(g.add(&g2))));

    // Point doubling
    group.bench_function("double", |b| b.iter(|| black_box(g.double())));

    // Scalar multiplication with small scalars
    let mut small_scalar_bytes = [0u8; 66];
    small_scalar_bytes[65] = 42;
    let small_scalar = Scalar::new(small_scalar_bytes).unwrap();

    group.bench_function("scalar_mul_small", |b| {
        b.iter(|| black_box(g.mul(&small_scalar).unwrap()))
    });

    // Scalar multiplication with random full-size scalar
    let mut rng = bench_rng();
    let (full_scalar, _) = p521::generate_keypair(&mut rng).unwrap();

    group.bench_function("scalar_mul_full", |b| {
        b.iter(|| black_box(g.mul(&full_scalar).unwrap()))
    });

    // Base point scalar multiplication
    group.bench_function("scalar_mult_base_g", |b| {
        b.iter(|| black_box(p521::scalar_mult_base_g(&full_scalar).unwrap()))
    });

    group.finish();
}

/// Benchmark point serialization and deserialization
fn bench_point_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521/serialization");

    let g = p521::base_point_g();

    // Serialize uncompressed
    group.bench_function("serialize_uncompressed", |b| {
        b.iter(|| black_box(g.serialize_uncompressed()))
    });

    // Deserialize uncompressed
    let uncompressed = g.serialize_uncompressed();
    group.bench_function("deserialize_uncompressed", |b| {
        b.iter(|| black_box(Point::deserialize_uncompressed(&uncompressed).unwrap()))
    });

    // Serialize compressed
    group.bench_function("serialize_compressed", |b| {
        b.iter(|| black_box(g.serialize_compressed()))
    });

    // Deserialize compressed (includes square root computation)
    let compressed = g.serialize_compressed();
    group.bench_function("deserialize_compressed", |b| {
        b.iter(|| black_box(Point::deserialize_compressed(&compressed).unwrap()))
    });

    group.finish();
}

/// Benchmark key generation
fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521/keygen");

    group.bench_function("generate_keypair", |b| {
        let mut rng = bench_rng();
        b.iter(|| black_box(p521::generate_keypair(&mut rng).unwrap()))
    });

    group.finish();
}

/// Benchmark ECDH operations
fn bench_ecdh_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521/ecdh");

    let mut rng = bench_rng();

    // Generate two keypairs for ECDH
    let (private_a, _) = p521::generate_keypair(&mut rng).unwrap();
    let (_, public_b) = p521::generate_keypair(&mut rng).unwrap();

    // Benchmark ECDH shared secret computation
    group.bench_function("shared_secret", |b| {
        b.iter(|| {
            // Alice computes shared secret using Bob's public key
            black_box(p521::scalar_mult(&private_a, &public_b).unwrap())
        })
    });

    // Benchmark KDF on shared secret
    let shared_point = p521::scalar_mult(&private_a, &public_b).unwrap();
    let shared_x = shared_point.x_coordinate_bytes();

    group.bench_function("kdf_hkdf_sha512", |b| {
        b.iter(|| black_box(p521::kdf_hkdf_sha512_for_ecdh_kem(&shared_x, None).unwrap()))
    });

    group.finish();
}

/// Benchmark various input sizes for scalar multiplication
fn bench_scalar_mult_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("p521/scalar_mult_sizes");

    let g = p521::base_point_g();

    // Test with scalars of different bit lengths
    let bit_sizes = vec![8, 16, 32, 64, 128, 256, 521];

    for bits in bit_sizes {
        let mut scalar_bytes = [0u8; 66];

        // Set bits in the scalar
        let byte_idx = (521 - bits) / 8;
        let bit_offset = (521 - bits) % 8;

        if byte_idx < 66 {
            scalar_bytes[byte_idx] = 1 << (7 - bit_offset);
            // Fill remaining bits
            for i in (byte_idx + 1)..66 {
                scalar_bytes[i] = 0xFF;
            }
        }

        let scalar = Scalar::new(scalar_bytes).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(bits), &scalar, |b, scalar| {
            b.iter(|| black_box(g.mul(scalar).unwrap()))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_field_operations,
    bench_scalar_operations,
    bench_point_operations,
    bench_point_serialization,
    bench_key_generation,
    bench_ecdh_operations,
    bench_scalar_mult_sizes
);

criterion_main!(benches);
