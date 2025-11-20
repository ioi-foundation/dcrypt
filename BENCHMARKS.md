# dcrypt Performance Benchmarks

This document contains performance benchmarks for the `dcrypt` cryptographic library.
These benchmarks are automatically generated during the release process using `criterion` and `cargo bench`.

## Key Encapsulation Mechanisms (KEM)

### Post-Quantum & Hybrid
<!-- START: KEM -->
| Algorithm / Operation | Average Execution Time |
|:----------------------|-----------------------:|
| `ECDH-P384_decapsulate` | 6.55 ms |
| `ECDH-P384_encapsulate` | 6.34 ms |
| `ECDH-P384_full_kem_flow` | 15.58 ms |
| `ECDH-P384_keypair` | 3.05 ms |
| `ECDH-P384_memory_keypair_allocation` | 3.00 ms |
| `ECDH-P384_memory_shared_secret_lifecycle` | 12.36 ms |
| `ECDH-P384_parallel_encapsulation` | 7.09 ms |
| `ECDH-P384_parallel_keypair_generation` | 3.59 ms |
| `K256_Kyber512` | 188.24 ms |
| `Kyber1024` | 977.15 µs |
| `Kyber1024_100_keypairs` | 31.47 ms |
| `Kyber1024_10_sequential_encaps` | 6.42 ms |
| `Kyber512` | 368.75 µs |
| `Kyber512_100_keypairs` | 11.23 ms |
| `Kyber512_10_sequential_encaps` | 2.42 ms |
| `Kyber512_keygen_with_drop` | 115.27 µs |
| `Kyber768` | 618.19 µs |
| `Kyber768_100_keypairs` | 19.79 ms |
| `Kyber768_10_sequential_encaps` | 4.19 ms |
| `P256_Kyber512` | 7.21 ms |
| `P256_Kyber768` | 2.33 ms |
| `P384_Kyber1024` | 6.69 ms |
| `P521_Kyber1024` | 47.93 ms |
| `decapsulate` | 211.58 µs |
| `decapsulate_with_validation` | 1.04 s |
| `encapsulate` | 199.20 µs |
| `encapsulate_with_validation` | 1.06 s |
| `encapsulation_kdf_overhead` | 2.22 ms |
| `parallel_encapsulations` | 878.02 ms |
| `sequential_encapsulations` | 5.31 s |
<!-- END: KEM -->

## Digital Signatures

### Post-Quantum & Hybrid
<!-- START: Sign -->
| Algorithm / Operation | Average Execution Time |
|:----------------------|-----------------------:|
| `ECDSA_P384_Dilithium3` | 28.13 ms |
| `RSA_PSS_Falcon512` | 76.26 ns |
| `SHA-256_verify-1KB` | 4.82 µs |
| `SHA-256_verify-1MB` | 4.54 ms |
| `SHA-512_verify-1KB` | 3.28 µs |
| `SHA-512_verify-1MB` | 2.85 ms |
| `dilithium2_multi_sign` | 862.88 µs |
| `dilithium3_multi_sign` | 6.34 ms |
| `dilithium5_multi_sign` | 13.69 ms |
| `verify` | 4.69 ms |
<!-- END: Sign -->

## Symmetric Encryption

### AEAD & Stream Ciphers
<!-- START: Symmetric -->
| Algorithm / Operation | Average Execution Time |
|:----------------------|-----------------------:|
| `AES-128-MCT-naive` | 8.45 ms |
| `AES-128-MCT-optimized` | 2.99 ms |
| `ChaCha20Rng` | 820.36 µs |
<!-- END: Symmetric -->

## Hashing & KDFs

### Hash Functions
<!-- START: Hash -->
| Algorithm / Operation | Average Execution Time |
|:----------------------|-----------------------:|
| `SHA-256_1MB-incremental` | 4.53 ms |
| `SHA-256_empty` | 350.46 ns |
| `SHA-256_single-block` | 341.68 ns |
| `SHA-512_1MB-incremental` | 2.95 ms |
| `SHA-512_empty` | 489.47 ns |
| `SHA-512_single-block` | 483.28 ns |
<!-- END: Hash -->

### Key Derivation Functions
<!-- START: KDF -->
| Algorithm / Operation | Average Execution Time |
|:----------------------|-----------------------:|
| `derive_key` | 4.81 ms |
<!-- END: KDF -->

## Low-Level Primitives
*Field arithmetic, scalar multiplication, and modular operations.*
<!-- START: Primitives -->
| Algorithm / Operation | Average Execution Time |
|:----------------------|-----------------------:|
| `arbitrary_point` | 3.12 ms |
| `base_point` | 3.22 ms |
| `compressed_point_operations` | 0.49 ns |
| `dilithium_ntt_based` | 8.92 µs |
| `dilithium_pointwise` | 377.23 ns |
| `field_from_bytes` | 6.55 ns |
| `field_to_bytes` | 6.51 ns |
| `invert` | 334.63 µs |
| `kyber_ntt_based` | 12.71 µs |
| `kyber_pointwise` | 179.03 ns |
| `large_scalar` | 810.27 µs |
| `medium_scalar` | 1.11 ms |
| `point_mul_method` | 773.03 µs |
| `scalar_creation` | 40.04 ns |
| `scalar_mul_10_points` | 31.31 ms |
| `scalar_mul_full` | 4.60 ms |
| `scalar_mul_small` | 399.50 µs |
| `scalar_mult` | 1.03 ms |
| `scalar_mult_base` | 1.05 ms |
| `scalar_mult_base_g` | 4.62 ms |
| `scalar_reduction` | 64.41 ns |
| `scalar_serialize` | 6.59 ns |
| `small_scalar` | 753.04 µs |
| `sqrt` | 30.48 µs |
| `sum_10_points` | 1.51 ms |
| `with_base_point_g` | 887.02 µs |
| `with_random_point` | 816.67 µs |
<!-- END: Primitives -->

## Uncategorized
<!-- START: Other -->
| Algorithm / Operation | Average Execution Time |
|:----------------------|-----------------------:|
| `1` | 2.21 ms |
| `10` | 30.72 ms |
| `100` | 305.91 ms |
| `1000` | 2.96 s |
| `1024` | 90.44 µs |
| `1048576` | 2.98 ms |
| `128` | 948.21 ns |
| `128B` | 4.78 ms |
| `128_bits` | 390.66 ms |
| `16` | 495.04 µs |
| `16384` | 1.45 ms |
| `16B` | 4.68 ms |
| `16MiB` | 21.18 ms |
| `192` | 3.05 ms |
| `2` | 2.15 s |
| `25` | 40.87 ms |
| `256` | 22.58 µs |
| `256_bits` | 396.75 ms |
| `283_bits` | 382.14 ms |
| `32` | 692.16 ns |
| `32B` | 4.83 ms |
| `32_bits` | 389.00 ms |
| `384` | 3.04 ms |
| `4096` | 357.97 µs |
| `4MiB` | 4.65 ms |
| `5` | 5.31 s |
| `50` | 437.95 ms |
| `521` | 4.43 ms |
| `64` | 5.68 µs |
| `64B` | 4.76 ms |
| `64MiB` | 115.18 ms |
| `64_bits` | 391.57 ms |
| `65536` | 268.23 µs |
| `8` | 471.74 µs |
| `8_messages` | 37.73 µs |
| `B-283k` | 10.24 s |
| `K-256` | 39.56 ms |
| `OsRng` | 832.41 µs |
| `P-256` | 539.86 ms |
| `P-384` | 800.53 ms |
| `P-521` | 459.18 ms |
| `aad_1024` | 18.23 µs |
| `aad_16` | 16.67 µs |
| `aad_256` | 16.95 µs |
| `aad_64` | 16.51 µs |
| `add` | 928.05 µs |
| `add_mod_n` | 130.49 ns |
| `addition` | 27.20 ns |
| `aes128` | 3.01 µs |
| `aes128_8_blocks` | 7.76 µs |
| `aes128_gcm` | 4.21 µs |
| `aes128_gcm_128bit_nonce` | 521.60 µs |
| `aes128_gcm_96bit_nonce` | 515.47 µs |
| `aes192` | 2.53 µs |
| `aes192_gcm` | 3.90 µs |
| `aes256` | 3.99 µs |
| `aes256_8_blocks` | 10.94 µs |
| `aes256_gcm` | 5.54 µs |
| `alloc_dealloc_cycle` | 3.26 ms |
| `argon2d` | 160.92 ms |
| `argon2i` | 165.35 ms |
| `argon2id` | 163.00 ms |
| `b283k_generate_keypair` | 382.60 ms |
| `builder_derive` | 4.87 ms |
| `chacha20_poly1305` | 4.47 µs |
| `ciphertext_size` | 0.24 ns |
| `complete` | 1.06 ms |
| `compress` | 738.21 µs |
| `counter_nonce` | 4.35 µs |
| `decompress` | 1.36 ms |
| `default` | 2.25 ms |
| `deserialize` | 143.15 ns |
| `deserialize_compressed` | 33.17 µs |
| `deserialize_uncompressed` | 618.38 ns |
| `detect_format` | 45.90 ns |
| `dilithium` | 5.98 µs |
| `dilithium2` | 4.94 ms |
| `dilithium2_pk_deserialize` | 12.10 µs |
| `dilithium2_sig_deserialize` | 22.02 µs |
| `dilithium2_sk_deserialize` | 26.53 µs |
| `dilithium3` | 23.83 ms |
| `dilithium3_pk_deserialize` | 18.12 µs |
| `dilithium3_sig_deserialize` | 29.68 µs |
| `dilithium3_sk_deserialize` | 42.75 µs |
| `dilithium5` | 94.38 ms |
| `dilithium5_pk_deserialize` | 24.08 µs |
| `dilithium5_sig_deserialize` | 41.82 µs |
| `dilithium5_sk_deserialize` | 52.09 µs |
| `dilithium_montgomery_reduce` | 1.13 ns |
| `dilithium_schoolbook` | 16.97 µs |
| `double` | 448.07 µs |
| `doubling` | 42.89 µs |
| `ecdh_raw` | 1.05 ms |
| `extract_public_key` | 8.37 ns |
| `extract_secret_key` | 33.71 ns |
| `forward` | 4.31 µs |
| `from_bytes` | 11.31 ns |
| `full_ecdh_exchange` | 1.51 ms |
| `full_exchange` | 12.41 ms |
| `full_kem_flow` | 2.66 s |
| `full_roundtrip` | 18.10 ms |
| `full_workflow` | 613.19 µs |
| `generate` | 539.14 ms |
| `generate_keypair` | 1.08 ms |
| `hash` | 4.78 ms |
| `inv_mod_n` | 50.26 ms |
| `invalid_ciphertext` | 99.74 ns |
| `invalid_public_key` | 28.36 ns |
| `inverse` | 4.05 µs |
| `inversion` | 39.99 µs |
| `is_identity` | 0.60 ns |
| `kdf_hkdf_sha256` | 4.69 µs |
| `kdf_hkdf_sha384` | 7.13 µs |
| `kdf_hkdf_sha512` | 6.58 µs |
| `key_sizes` | 0.48 ns |
| `keygen` | 195.56 µs |
| `keypair_generation` | 4.51 ms |
| `kyber` | 8.27 µs |
| `kyber_montgomery_reduce` | 1.13 ns |
| `kyber_schoolbook` | 17.08 µs |
| `measure_sizes` | 0.00 ns |
| `mul` | 307.52 ns |
| `mul_mod_n` | 55.20 µs |
| `multiplication` | 107.23 ns |
| `n256` | 4.27 µs |
| `negate` | 88.66 ns |
| `new` | 30.09 ns |
| `new_uncompressed_invalid` | 282.86 ns |
| `new_uncompressed_valid` | 280.65 ns |
| `p=1` | 4.67 ms |
| `p=2` | 9.96 ms |
| `p=4` | 21.21 ms |
| `p=8` | 56.34 ms |
| `random_24byte_nonce` | 4.65 µs |
| `random_nonce` | 4.39 µs |
| `reused_allocations` | 16.13 ms |
| `same_ciphertext` | 1.67 ms |
| `serialize` | 24.39 ns |
| `serialize_ciphertext` | 0.47 ns |
| `serialize_compressed` | 69.70 ns |
| `serialize_public_key` | 0.47 ns |
| `serialize_secret_key` | 0.47 ns |
| `serialize_uncompressed` | 102.79 ns |
| `shared_secret` | 4.54 ms |
| `shared_secret_computation` | 736.41 µs |
| `square` | 328.30 ns |
| `squaring` | 107.41 ns |
| `standard` | 1.69 ms |
| `sub` | 27.79 ns |
| `sub_mod_n` | 122.79 ns |
| `subtraction` | 13.40 ns |
| `t=1` | 2.38 ms |
| `t=2` | 4.67 ms |
| `t=3` | 6.79 ms |
| `t=4` | 9.51 ms |
| `tampered_ciphertext` | 107.92 ns |
| `to_bytes` | 20.60 ns |
| `validation` | 536.77 ns |
| `varying_recipients` | 1.70 ms |
| `with_fixed_keypair` | 3.21 ms |
| `xchacha20_poly1305` | 4.68 µs |
| `zero_nonce` | 4.66 µs |
<!-- END: Other -->