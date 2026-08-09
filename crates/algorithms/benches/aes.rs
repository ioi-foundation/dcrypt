//! Benchmarks for AES block cipher implementations
//!
//! This benchmark suite tests the performance of AES-128, AES-192, and AES-256
//! for various operations including key expansion, single block encryption/decryption,
//! and multi-block operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use dcrypt_algorithms::block::{Aes128, Aes192, Aes256, BlockCipher};
use dcrypt_algorithms::types::SecretBytes;
use dcrypt_internal::random::{ChaCha20Rng, RngCore};

/// Benchmark AES key expansion
fn bench_key_expansion(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_key_expansion");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // AES-128 key expansion
    group.bench_function("aes128", |b| {
        let mut key_bytes = [0u8; 16];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);

        b.iter(|| {
            let cipher = Aes128::new(black_box(&key));
            black_box(cipher);
        });
    });

    // AES-192 key expansion
    group.bench_function("aes192", |b| {
        let mut key_bytes = [0u8; 24];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);

        b.iter(|| {
            let cipher = Aes192::new(black_box(&key));
            black_box(cipher);
        });
    });

    // AES-256 key expansion
    group.bench_function("aes256", |b| {
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);

        b.iter(|| {
            let cipher = Aes256::new(black_box(&key));
            black_box(cipher);
        });
    });

    group.finish();
}

/// Benchmark single block encryption
fn bench_block_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_block_encrypt");
    group.throughput(Throughput::Bytes(16)); // AES block size

    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // AES-128
    {
        let mut key_bytes = [0u8; 16];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);
        let cipher = Aes128::new(&key);

        group.bench_function("aes128", |b| {
            let mut block = [0u8; 16];
            rng.fill_bytes(&mut block);

            b.iter(|| {
                let mut data = block;
                cipher.encrypt_block(black_box(&mut data)).unwrap();
                black_box(data);
            });
        });
    }

    // AES-192
    {
        let mut key_bytes = [0u8; 24];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);
        let cipher = Aes192::new(&key);

        group.bench_function("aes192", |b| {
            let mut block = [0u8; 16];
            rng.fill_bytes(&mut block);

            b.iter(|| {
                let mut data = block;
                cipher.encrypt_block(black_box(&mut data)).unwrap();
                black_box(data);
            });
        });
    }

    // AES-256
    {
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);
        let cipher = Aes256::new(&key);

        group.bench_function("aes256", |b| {
            let mut block = [0u8; 16];
            rng.fill_bytes(&mut block);

            b.iter(|| {
                let mut data = block;
                cipher.encrypt_block(black_box(&mut data)).unwrap();
                black_box(data);
            });
        });
    }

    group.finish();
}

/// Benchmark single block decryption
fn bench_block_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_block_decrypt");
    group.throughput(Throughput::Bytes(16)); // AES block size

    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // AES-128
    {
        let mut key_bytes = [0u8; 16];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);
        let cipher = Aes128::new(&key);

        group.bench_function("aes128", |b| {
            let mut block = [0u8; 16];
            rng.fill_bytes(&mut block);
            cipher.encrypt_block(&mut block).unwrap(); // Pre-encrypt

            b.iter(|| {
                let mut data = block;
                cipher.decrypt_block(black_box(&mut data)).unwrap();
                black_box(data);
            });
        });
    }

    // AES-192
    {
        let mut key_bytes = [0u8; 24];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);
        let cipher = Aes192::new(&key);

        group.bench_function("aes192", |b| {
            let mut block = [0u8; 16];
            rng.fill_bytes(&mut block);
            cipher.encrypt_block(&mut block).unwrap(); // Pre-encrypt

            b.iter(|| {
                let mut data = block;
                cipher.decrypt_block(black_box(&mut data)).unwrap();
                black_box(data);
            });
        });
    }

    // AES-256
    {
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);
        let cipher = Aes256::new(&key);

        group.bench_function("aes256", |b| {
            let mut block = [0u8; 16];
            rng.fill_bytes(&mut block);
            cipher.encrypt_block(&mut block).unwrap(); // Pre-encrypt

            b.iter(|| {
                let mut data = block;
                cipher.decrypt_block(black_box(&mut data)).unwrap();
                black_box(data);
            });
        });
    }

    group.finish();
}

/// Benchmark multi-block encryption (ECB mode simulation)
fn bench_multi_block_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_multi_block_encrypt");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Test different message sizes
    let sizes = [64, 256, 1024, 4096, 16384];

    for size in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        // AES-128
        {
            let mut key_bytes = [0u8; 16];
            rng.fill_bytes(&mut key_bytes);
            let key = SecretBytes::new(key_bytes);
            let cipher = Aes128::new(&key);

            group.bench_with_input(BenchmarkId::new("aes128", size), size, |b, &size| {
                let mut data = vec![0u8; size];
                rng.fill_bytes(&mut data[..]);

                b.iter(|| {
                    let mut work_data = data.clone();
                    for chunk in work_data.chunks_exact_mut(16) {
                        cipher.encrypt_block(chunk).unwrap();
                    }
                    black_box(work_data);
                });
            });
        }

        // AES-256
        {
            let mut key_bytes = [0u8; 32];
            rng.fill_bytes(&mut key_bytes);
            let key = SecretBytes::new(key_bytes);
            let cipher = Aes256::new(&key);

            group.bench_with_input(BenchmarkId::new("aes256", size), size, |b, &size| {
                let mut data = vec![0u8; size];
                rng.fill_bytes(&mut data[..]);

                b.iter(|| {
                    let mut work_data = data.clone();
                    for chunk in work_data.chunks_exact_mut(16) {
                        cipher.encrypt_block(chunk).unwrap();
                    }
                    black_box(work_data);
                });
            });
        }
    }

    group.finish();
}

/// Benchmark parallel block operations (simulating parallel modes)
fn bench_parallel_blocks(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_parallel_blocks");
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Process 8 blocks in parallel (common for AES-NI implementations)
    let block_count = 8;
    group.throughput(Throughput::Bytes((block_count * 16) as u64));

    // AES-128
    {
        let mut key_bytes = [0u8; 16];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);
        let cipher = Aes128::new(&key);

        group.bench_function("aes128_8_blocks", |b| {
            let mut blocks = [[0u8; 16]; 8];
            for block in &mut blocks {
                rng.fill_bytes(block);
            }

            b.iter(|| {
                let mut work_blocks = blocks;
                for block in &mut work_blocks {
                    cipher.encrypt_block(block).unwrap();
                }
                black_box(work_blocks);
            });
        });
    }

    // AES-256
    {
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let key = SecretBytes::new(key_bytes);
        let cipher = Aes256::new(&key);

        group.bench_function("aes256_8_blocks", |b| {
            let mut blocks = [[0u8; 16]; 8];
            for block in &mut blocks {
                rng.fill_bytes(block);
            }

            b.iter(|| {
                let mut work_blocks = blocks;
                for block in &mut work_blocks {
                    cipher.encrypt_block(block).unwrap();
                }
                black_box(work_blocks);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_key_expansion,
    bench_block_encrypt,
    bench_block_decrypt,
    bench_multi_block_encrypt,
    bench_parallel_blocks
);
criterion_main!(benches);
