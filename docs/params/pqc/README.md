# Post-Quantum Cryptography (PQC) Parameters (`params/pqc`)

This module within the `params` crate centralizes constants and parameter sets for various Post-Quantum Cryptography (PQC) algorithms. Many of these parameters are aligned with the specifications from the NIST Post-Quantum Cryptography Standardization project.

Having these parameters in a dedicated location ensures consistency and ease of reference for PQC algorithm implementations throughout the dcrypt ecosystem.

## PQC Algorithm Parameter Sets

1.  **Kyber (`kyber.rs`)**:
    *   Defines `Kyber512Params`, `Kyber768Params`, `Kyber1024Params` structs and their corresponding `const` instances (`KYBER512`, `KYBER768`, `KYBER1024`).
    *   Parameters include polynomial degree (`n`), modulus (`q`), dimension (`k`), error distribution parameters (`eta1`, `eta2`), compression bits (`du`, `dv`), and sizes for public key, secret key, ciphertext, and shared secret.

2.  **Dilithium (`dilithium.rs`)**:
    *   Defines `Dilithium2Params`, `Dilithium3Params`, `Dilithium5Params` structs and `const` instances.
    *   Parameters include polynomial degree (`n`), modulus (`q`), dropped bits (`d`), matrix dimensions (`k`, `l`), infinity norm bound (`eta`), challenge sparsity (`tau`), and key/signature sizes.

3.  **NTRU (`ntru.rs`)**:
    *   Defines `NtruHpsParams` (for NTRU-HPS variants like 2048-509, 2048-677, 4096-821) and `NtruHrssParams` (for NTRU-HRSS-701).
    *   Parameters include polynomial degree (`n`), modulus (`q`), padding parameter (`p`), private key weight (`d` for HPS), and key/ciphertext/shared secret sizes.

4.  **SABER (`saber.rs`)**:
    *   Defines `LightSaberParams`, `SaberParams`, `FireSaberParams` structs and `const` instances.
    *   Parameters include polynomial degree (`n`), modulus (`q`), encoding modulus (`p`), dimension (`l`), rounding modulus (`t`), compression bits (`eq`, `ep`, `et`), and key/ciphertext/shared secret sizes.

5.  **SPHINCS+ (`sphincs.rs`)**:
    *   Defines `SphincsSha256Params` and `SphincsShakeParams` for different underlying hash functions, with variants for "-128s", "-128f", "-192s", "-192f".
    *   Parameters include security level, hypertree height (`h`), number of layers (`d`), Winternitz parameter (`w`), FORS tree count (`k`) and height (`t`), and key/signature sizes.

6.  **Falcon (`falcon.rs`)**:
    *   Defines `Falcon512Params` and `Falcon1024Params` structs and `const` instances.
    *   Parameters include polynomial degree (`n`), modulus (`q`), signature standard deviation (`sigma`), and key/signature sizes.

7.  **Classic McEliece (`mceliece.rs`)**:
    *   Defines `McEliece348864Params`, `McEliece460896Params`, `McEliece6960119Params` structs and `const` instances.
    *   Parameters include code length (`n`), code dimension (`k`), error correction capability (`t`), and key/ciphertext/shared secret sizes.

8.  **Rainbow (`rainbow.rs`)**:
    *   Defines `RainbowIParams`, `RainbowIIIParams`, `RainbowVParams` structs and `const` instances.
    *   Parameters include number of variables (`v`), oil variables per layer (`o`), equations for central map (`l`), field size (`q`), and key/signature sizes.

These parameter sets are crucial for the correct implementation and interoperability of the PQC algorithms. They provide the specific numerical values that define each scheme's variant and security level.