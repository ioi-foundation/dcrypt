# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] – 2025-12-03
### Added
- Support for zero-copy constructors: `Into<Vec<u8>>` for `SecretVec`, `Key`, `PublicKey`, and `Ciphertext`.  
- `From<Vec<u8>>` implementations for core secret/data types to allow direct ownership transfer without allocation.  
### Changed
- Refactored AEAD, Hybrid KEM, and ECIES code paths to move buffers where possible and pass slices otherwise; removed unnecessary cloning.  
- Updated plaintext/ciphertext handling to use the new zero-copy constructors where relevant.  
### Performance
- Reduced redundant allocations and lowered peak memory usage for large ciphertexts and secret data.  
### Security
- Strengthened zeroization guarantees: moving raw key / ciphertext data into `SecretVec` or `Ciphertext` ensures original memory can be zero-wiped reliably.

## [1.1.0] – 2025-11-24  
### Added
- Gen-2 constant-time verification harness: bootstrap CI + p-value statistical tests, KS-based distribution tests, Holm–Bonferroni multi-signal correction, and persistent noise profiling. :contentReference[oaicite:1]{index=1}  
### Changed
- No public API surface changed — backward-compatible. This is an assurance-level upgrade verifying timing behaviour across noisy environments. :contentReference[oaicite:2]{index=2}  
### Security / Assurance
- Provides statistically robust evidence that core cryptographic routines exhibit constant-time behaviour under diverse environments and CI runners. :contentReference[oaicite:3]{index=3}

## [1.0.0] – 2025-11-21  
### Added
- Initial stable release of dcrypt under IOI Foundation: symmetric crypto, post-quantum KEM, hybrid constructions, PKE, AEAD modules. :contentReference[oaicite:4]{index=4}  
- `no_std` support for embedded environments; modular crate structure; constant-time implementations; automatic zeroization for sensitive data. :contentReference[oaicite:5]{index=5}  
- Full API: public key, secret key, ciphertext types; encryption/decryption and key-encapsulation; serialization/deserialization. :contentReference[oaicite:6]{index=6}  
### Changed
- Stabilized API surface after beta series; breaking changes from prior betas resolved.  
### Fixed
- Bug fixes across classical and PQC modules; improved test coverage and baseline for cryptographic correctness.  
### Security
- Secret key material cannot be exposed via `AsRef/AsMut` — only safe, explicit serialization/export allowed.  

[Unreleased]: https://github.com/ioi-foundation/dcrypt/compare/v1.1.1...HEAD  
[1.1.1]: https://github.com/ioi-foundation/dcrypt/compare/v1.1.0...v1.1.1  
[1.1.0]: https://github.com/ioi-foundation/dcrypt/releases/tag/v1.1.0  
[1.0.0]: https://github.com/ioi-foundation/dcrypt/releases/tag/v1.0.0  