# dcrypt Interoperability Completeness Matrix

Status: **candidate framework; all executable interoperability atoms remain blocked**.

This document is generated from `matrix.json`. Candidate oracle dossiers, existing
test harnesses, and generated matrix bytes are not passing assurance evidence.
Evidence promotion is disabled in schema v1: dossiers cannot be accepted, override
records must be empty, and no matrix operation row can have passing status.

## Counts

- Curated operation rows: 552
- Exact operation path/profile/platform atoms: 6184
- Blocked operation atoms: 6184
- Passing operation atoms: 0
- Curated data-surface rows: 14
- Explicit N/A data-surface atoms: 56
- Individually digest-bound blocked unreviewed gaps: 8632
- Interoperability blocker atoms: 14816
- Existing assurance-ledger atomic blockers (unchanged): 9198
- Accepted oracle dossiers: 0
- Candidate oracle dossiers: 6
- Rejected-as-independent oracle dossiers: 6

The interoperability blocker count is a separate completeness dimension. It must
not be added to or substituted for the 9,198 atomic assurance-ledger blockers.

## Standards-scope atoms

- `compatibility`: 24
- `project-specified`: 716
- `standardized`: 4632
- `transitional`: 812

## Algorithm atoms

- `AES-GCM`: 576
- `ML-DSA`: 384
- `prime-field elliptic curve`: 384
- `BLS12-381 signatures`: 368
- `ECDH KEM`: 360
- `ChaCha20-Poly1305`: 356
- `ECDSA`: 288
- `dcrypt ECIES`: 288
- `SHA-2`: 200
- `ML-KEM`: 192
- `P-224 scalar arithmetic`: 192
- `XChaCha20-Poly1305`: 168
- `AES`: 160
- `ChaCha20`: 160
- `PBKDF2<H: HashFunction>`: 148
- `BLAKE2b`: 144
- `BLS12-381 Ethereum consensus signatures`: 144
- `GCM<B: BlockCipher>`: 136
- `CTR<B: BlockCipher>`: 128
- `HKDF<H: HashFunction>`: 128
- `ECDH+ML-KEM hybrid KEM`: 120
- `Argon2d`: 112
- `Argon2i`: 112
- `Argon2id`: 112
- `BLAKE2s`: 96
- `BLAKE3`: 96
- `HMAC<H: HashFunction>`: 72
- `CBC<B: BlockCipher>`: 64
- `Ed25519`: 64
- `BLS12-381`: 48
- `SHAKE`: 48
- `AES key derivation`: 32
- `caller-owned CSPRNG salt generation`: 32
- `ECDSA+ML-DSA hybrid signature`: 24
- `Keccak-256`: 24
- `Poly1305`: 24
- `SHA-1`: 24
- `SHA3-224`: 24
- `SHA3-256`: 24
- `SHA3-384`: 24
- `SHA3-512`: 24
- `ChaCha20-Poly1305 key derivation`: 16
- `SHA-512/224`: 16
- `SHA-512/256`: 16
- `AES-128-GCM`: 12
- `AES-256-GCM`: 12
- `P-224 curve parameters`: 8

## Gate semantics

CI mode validates deterministic bytes, exact source correspondence, all closed
records, candidate provenance, isolation, and fail-closed blockers. Release mode
must fail while any operation atom or unreviewed gap is blocked. The 56 public
metadata atoms are explicitly N/A because they have no executable direction;
their bytes and aliases remain bound by the assurance ledger.
