//! Benchmarks for sect283k1 binary elliptic curve operations

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use dcrypt_algorithms::ec::b283k::{
    base_point_g, generate_keypair, kdf_hkdf_sha384_for_ecdh_kem, scalar_mult, scalar_mult_base_g,
    FieldElement, Point, Scalar, B283K_FIELD_ELEMENT_SIZE, B283K_SCALAR_SIZE,
};
use dcrypt_internal::random::{ChaCha20Rng, RngCore};

fn bench_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0x71; 32])
}

fn bench_field_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("b283k_field");

    // Generate test field elements
    let mut bytes_a = [0u8; B283K_FIELD_ELEMENT_SIZE];
    let mut bytes_b = [0u8; B283K_FIELD_ELEMENT_SIZE];
    let mut rng = bench_rng();
    rng.fill_bytes(&mut bytes_a);
    rng.fill_bytes(&mut bytes_b);
    bytes_a[0] &= 0x07; // Ensure < 2^283
    bytes_b[0] &= 0x07;

    let a = FieldElement::from_bytes(&bytes_a).unwrap();
    let b = FieldElement::from_bytes(&bytes_b).unwrap();

    group.bench_function("add", |bencher| bencher.iter(|| a.add(&b)));

    group.bench_function("mul", |bencher| bencher.iter(|| a.mul(&b)));

    group.bench_function("square", |bencher| bencher.iter(|| a.square()));

    group.bench_function("invert", |bencher| bencher.iter(|| a.invert().unwrap()));

    group.bench_function("sqrt", |bencher| bencher.iter(|| a.sqrt()));

    group.finish();
}

fn bench_point_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("b283k_point");

    let g = base_point_g();
    let g2 = g.double();

    group.bench_function("add", |bencher| bencher.iter(|| g.add(&g2)));

    group.bench_function("double", |bencher| bencher.iter(|| g.double()));

    // Scalar multiplication with various bit lengths
    let scalar_sizes = [32, 64, 128, 256, 283];
    for bits in scalar_sizes.iter() {
        let mut scalar_bytes = [0u8; B283K_SCALAR_SIZE];
        let bytes_to_fill = (bits + 7) / 8;
        let mut rng = bench_rng();
        rng.fill_bytes(&mut scalar_bytes[B283K_SCALAR_SIZE - bytes_to_fill..]);

        // Ensure scalar is valid and < order
        scalar_bytes[0] &= 0x01;
        let scalar = match Scalar::new(scalar_bytes) {
            Ok(s) => s,
            Err(_) => {
                scalar_bytes[B283K_SCALAR_SIZE - 1] |= 0x01; // Ensure non-zero
                Scalar::new(scalar_bytes).unwrap()
            }
        };

        group.bench_with_input(
            BenchmarkId::new("scalar_mul", format!("{}_bits", bits)),
            &scalar,
            |bencher, scalar| bencher.iter(|| g.mul(scalar).unwrap()),
        );
    }

    group.finish();
}

fn bench_scalar_mult_base(c: &mut Criterion) {
    let mut group = c.benchmark_group("b283k_base_point");

    let mut scalar_bytes = [0u8; B283K_SCALAR_SIZE];
    let mut rng = bench_rng();
    rng.fill_bytes(&mut scalar_bytes);
    scalar_bytes[0] &= 0x01; // Ensure < 2^283
    scalar_bytes[B283K_SCALAR_SIZE - 1] |= 0x01; // Ensure non-zero
    let scalar = Scalar::new(scalar_bytes).unwrap();

    group.bench_function("scalar_mult_base_g", |bencher| {
        bencher.iter(|| scalar_mult_base_g(&scalar).unwrap())
    });

    group.finish();
}

fn bench_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("b283k_compression");

    let (_, point) = generate_keypair(&mut bench_rng()).unwrap();
    let compressed = point.serialize_compressed();

    group.bench_function("compress", |bencher| {
        bencher.iter(|| point.serialize_compressed())
    });

    group.bench_function("decompress", |bencher| {
        bencher.iter(|| Point::deserialize_compressed(&compressed).unwrap())
    });

    group.finish();
}

fn bench_keypair_generation(c: &mut Criterion) {
    c.bench_function("b283k_generate_keypair", |bencher| {
        bencher.iter(|| generate_keypair(&mut bench_rng()).unwrap())
    });
}

fn bench_ecdh(c: &mut Criterion) {
    let mut group = c.benchmark_group("b283k_ecdh");

    // Generate two keypairs for ECDH
    let (sk1, pk1) = generate_keypair(&mut bench_rng()).unwrap();
    let (sk2, pk2) = generate_keypair(&mut bench_rng()).unwrap();

    group.bench_function("shared_secret", |bencher| {
        bencher.iter(|| scalar_mult(&sk1, &pk2).unwrap())
    });

    // Benchmark the full ECDH with KDF
    let shared_point = scalar_mult(&sk1, &pk2).unwrap();
    let shared_x = shared_point.x_coordinate_bytes();
    let info = b"test context";

    group.bench_function("kdf_hkdf_sha384", |bencher| {
        bencher.iter(|| kdf_hkdf_sha384_for_ecdh_kem(&shared_x, Some(info)).unwrap())
    });

    group.finish();
}

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("b283k_serialization");

    // Generate test data
    let mut scalar_bytes = [0u8; B283K_SCALAR_SIZE];
    let mut rng = bench_rng();
    rng.fill_bytes(&mut scalar_bytes);
    scalar_bytes[0] &= 0x01;
    scalar_bytes[B283K_SCALAR_SIZE - 1] |= 0x01;
    let scalar = Scalar::new(scalar_bytes).unwrap();

    let mut field_bytes = [0u8; B283K_FIELD_ELEMENT_SIZE];
    rng.fill_bytes(&mut field_bytes);
    field_bytes[0] &= 0x07;
    let field_elem = FieldElement::from_bytes(&field_bytes).unwrap();

    group.bench_function("scalar_serialize", |bencher| {
        bencher.iter(|| scalar.serialize())
    });

    group.bench_function("field_to_bytes", |bencher| {
        bencher.iter(|| field_elem.to_bytes())
    });

    group.bench_function("field_from_bytes", |bencher| {
        bencher.iter(|| FieldElement::from_bytes(&field_bytes).unwrap())
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_field_operations,
    bench_point_operations,
    bench_scalar_mult_base,
    bench_compression,
    bench_keypair_generation,
    bench_ecdh,
    bench_serialization
);

criterion_main!(benches);
