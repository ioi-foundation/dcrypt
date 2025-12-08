# BLS12-381 Pairing-Friendly Curve

## Overview

This module provides a pure-Rust implementation of the BLS12-381 pairing-friendly elliptic curve. It is designed to support advanced cryptographic schemes that rely on bilinear pairings, such as aggregate signatures, threshold signatures, and certain zero-knowledge proof systems.

> **Warning:** This is a low-level cryptographic implementation and has not been independently audited. Use at your own risk.

## Core Concepts

The BLS12-381 curve construction involves three distinct cryptographic groups:

*   **Group G₁**: A group of elliptic curve points defined over the base field Fₚ. In this implementation, these are represented by the `G1Affine` and `G1Projective` types.
*   **Group G₂**: A group of elliptic curve points defined over a quadratic extension field Fₚ². These are represented by the `G2Affine` and `G2Projective` types.
*   **Target Group Gₜ**: A multiplicative group over a twelfth-degree extension field Fₚ¹². The pairing function maps pairs of points from G₁ and G₂ into this group. It is represented by the `Gt` type.

The central feature of this curve is the **bilinear pairing**, which is a special map `e: G₁ × G₂ → Gₜ` with the following property:

`e(aP, bQ) = e(P, Q)^(ab)`

where `P` is a point in G₁, `Q` is a point in G₂, and `a` and `b` are scalars. This property allows for novel cryptographic constructions that are not possible with traditional elliptic curves.

## Features

*   **Pairing Implementation**: An efficient implementation of the optimal Ate pairing, including the Miller loop (`multi_miller_loop`) and the final exponentiation.
*   **Group Arithmetic**: Complete implementations for group operations in G₁, G₂, and Gₜ, including point addition, doubling, and negation.
*   **Multi-Scalar Multiplication (MSM)**: Optimized Pippenger's algorithm implementation for both G₁ and G₂, with both constant-time and variable-time variants for different security requirements.
*   **Hash-to-Curve**: Standards-compliant hash-to-curve implementation following RFC 9380 (hashing to G₁ and G₂ using the SSWU map).
*   **Hash-to-Field**: Standards-compliant hash-to-field implementation following the IETF specification.
*   **Coordinate Systems**: Both Affine and Jacobian Projective coordinates are used for points in G₁ and G₂, with projective coordinates being used internally for efficient, inversion-free arithmetic.
*   **Scalar Field Arithmetic**: A full implementation of the scalar field Fₙ, including arithmetic operations and modular inversion.
*   **Finite Field Tower**: The underlying tower of finite fields (Fₚ, Fₚ², Fₚ⁶, Fₚ¹²) required for the pairing is implemented in the `field` submodule.
*   **Serialization**: Support for both compressed and uncompressed point serialization for points in G₁ and G₂.
*   **Security Hardening**: Includes constant-time scalar multiplication, subgroup checks (`is_torsion_free`), and cofactor clearing to protect against a range of cryptographic attacks.

## Usage Examples

### Verifying the Bilinearity Property

The following example demonstrates the core bilinear property of the pairing function.

```rust
use dcrypt::algorithms::ec::bls12_381::{
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};

fn main() {
    // 1. Get the standard generator points for G1 and G2.
    let p_g1 = G1Affine::generator();
    let q_g2 = G2Affine::generator();

    // 2. Create two random scalars (representing private keys).
    let a = Scalar::from(12345u64);
    let b = Scalar::from(67890u64);

    // 3. Compute the corresponding points (representing public keys).
    //    aP = [a]P and bQ = [b]Q
    let ap = G1Affine::from(G1Projective::from(p_g1) * a);
    let bq = G2Affine::from(G2Projective::from(q_g2) * b);

    // 4. Compute the pairing in two different ways to verify bilinearity.

    // First way: e([a]P, [b]Q)
    let pairing1 = pairing(&ap, &bq);

    // Second way: e(P, Q)^(a*b)
    let scalar_prod = a * b;
    let pairing2 = pairing(&p_g1, &q_g2) * scalar_prod;

    // 5. The results must be equal.
    assert_eq!(pairing1, pairing2);

    println!("Bilinearity property verified successfully!");
    println!("e([a]P, [b]Q) = {:?}", pairing1);
    println!("e(P, Q)^(a*b)  = {:?}", pairing2);
}
```

### Multi-Scalar Multiplication (MSM)

Multi-scalar multiplication is a critical operation for many cryptographic protocols, particularly for efficient verification of aggregate signatures and polynomial commitments.

```rust
use dcrypt::algorithms::ec::bls12_381::{G1Affine, G1Projective, Scalar};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Prepare multiple points and scalars
    let points = vec![
        G1Affine::generator(),
        G1Affine::from(G1Projective::generator() * Scalar::from(2u64)),
        G1Affine::from(G1Projective::generator() * Scalar::from(3u64)),
    ];
    
    let scalars = vec![
        Scalar::from(100u64),
        Scalar::from(200u64),
        Scalar::from(300u64),
    ];
    
    // Compute the multi-scalar multiplication: ∑ᵢ [sᵢ]Pᵢ
    // Variable-time version (faster, but not constant-time)
    let result_vartime = G1Projective::msm_vartime(&points, &scalars)?;
    
    // Constant-time version (slower, but resistant to timing attacks)
    let result_ct = G1Projective::msm(&points, &scalars)?;
    
    // Both should produce the same result
    assert_eq!(G1Affine::from(result_vartime), G1Affine::from(result_ct));
    
    println!("MSM computation successful!");
    Ok(())
}
```

### Hash-to-Curve

The `hash_to_curve` function allows deterministic mapping of arbitrary data to elliptic curve points, as specified in RFC 9380.

```rust
use dcrypt::algorithms::ec::bls12_381::{G1Projective, G2Projective};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"Hello, BLS12-381!";
    
    // Hash to G1
    let dst_g1 = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    let point_g1 = G1Projective::hash_to_curve(message, dst_g1)?;
    println!("G1 Point: {:?}", point_g1);

    // Hash to G2
    let dst_g2 = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let point_g2 = G2Projective::hash_to_curve(message, dst_g2)?;
    println!("G2 Point: {:?}", point_g2);
    
    Ok(())
}
```

### BLS Signature Example

Here's a complete example showing how to use the BLS12-381 implementation for BLS signatures using the standard hash-to-curve construction:

```rust
use dcrypt::algorithms::ec::bls12_381::{
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use rand_core::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Key Generation
    let secret_key = Scalar::from(42u64); // In practice, use secure random generation
    let public_key = G2Affine::from(G2Projective::generator() * secret_key);
    
    // 2. Message to sign
    let message = b"Important message to sign";
    
    // 3. Hash message to G1 point using hash-to-curve
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    let msg_point_proj = G1Projective::hash_to_curve(message, dst)?;
    let msg_point = G1Affine::from(msg_point_proj);
    
    // 4. Sign: signature = [sk]H(message)
    let signature = G1Affine::from(msg_point_proj * secret_key);
    
    // 5. Verify: e(signature, g2) = e(H(message), public_key)
    let lhs = pairing(&signature, &G2Affine::generator());
    let rhs = pairing(&msg_point, &public_key);
    
    assert_eq!(lhs, rhs, "Signature verification failed!");
    println!("Signature verified successfully!");
    
    Ok(())
}
```

## Module Structure

The implementation is organized into several key modules:

*   `field/`: Contains the tower of finite fields (Fp, Fp2, Fp6, Fp12) that underpin the curve arithmetic.
    *   `fp.rs`: Base field implementation
    *   `fp2.rs`: Quadratic extension field
    *   `fp6.rs`: Degree-6 extension field
    *   `fp12.rs`: Degree-12 extension field (target group)
*   `g1.rs`: Implements the G₁ group, including:
    *   Point representations (Affine and Projective)
    *   Group arithmetic operations
    *   Multi-scalar multiplication (MSM)
    *   Serialization/deserialization
*   `g2.rs`: Implements the G₂ group, including:
    *   Point representations (Affine and Projective)
    *   Group arithmetic operations
    *   Multi-scalar multiplication (MSM)
    *   Serialization/deserialization
*   `scalar.rs`: Implements arithmetic for the scalar field Fₙ, including:
    *   Field arithmetic operations
    *   Modular inversion
    *   Hash-to-field functionality (IETF compliant)
*   `hash_to_curve.rs`: Implements hashing to G1 and G2 curves using the SSWU map.
*   `pairings.rs`: Implements the bilinear pairing, including:
    *   Miller loop computation
    *   Final exponentiation
    *   Single and multi-pairing functions
    *   G2 precomputation for efficiency
*   `tests/`: Contains comprehensive test suites:
    *   Field arithmetic tests
    *   Group operation tests
    *   Pairing property tests
    *   Serialization tests
    *   Test vectors from reference implementations

## Performance Considerations

### Multi-Scalar Multiplication

The MSM implementation uses Pippenger's algorithm, which is optimal for large numbers of points:
- **Variable-time** (`msm_vartime`): Faster but vulnerable to timing attacks. Use only with public data.
- **Constant-time** (`msm`): Slower but resistant to timing side-channels. Use for sensitive operations.

The window size is automatically optimized based on the number of points.

### Pairing Computation

For multiple pairings, use `multi_miller_loop` with precomputed G2 points for better performance:

```rust
use dcrypt::algorithms::ec::bls12_381::{G2Prepared, multi_miller_loop};

// Precompute G2 points once
let g2_prepared = G2Prepared::from(g2_point);

// Use in multiple pairing computations
let result = multi_miller_loop(&[
    (&g1_point1, &g2_prepared),
    (&g1_point2, &g2_prepared),
]).final_exponentiation();
```

## Security Considerations

1. **Subgroup Checks**: Always verify that deserialized points are in the correct subgroup using `is_torsion_free()`.

2. **Timing Attacks**: Use constant-time operations (`msm` instead of `msm_vartime`) when working with secret data.

3. **Domain Separation**: Always use appropriate domain separation tags (DST) when hashing to field elements or curve points.

4. **Random Number Generation**: Use cryptographically secure random number generators for key generation.

5. **Cofactor Clearing**: The implementation includes automatic cofactor clearing for random point generation.

## Standards Compliance

This implementation follows several standards and specifications:

- **IETF hash-to-curve**: The `hash_to_field` function implements expand_message_xmd and the map to curve functions follow RFC 9380.
- **Serialization**: Point serialization follows the Zcash/Ethereum 2.0 format.
- **Test Vectors**: The implementation passes test vectors from the BLST library and other reference implementations.

## Future Enhancements

Potential areas for future development include:

- [x] Full hash-to-curve implementation (hash-to-field and map-to-curve)
- [ ] GLV endomorphism optimization for scalar multiplication
- [ ] Assembly optimizations for critical field operations
- [ ] Batch verification optimizations
- [ ] Support for BLS12-377 and other pairing-friendly curves

## References

- [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381)
- [RFC 9380: Hashing to Elliptic Curves](https://www.rfc-editor.org/rfc/rfc9380.html)
- [Pairing-Based Cryptography](https://www.iacr.org/archive/asiacrypt2007/48330001/48330001.pdf)
- [BLST Library](https://github.com/supranational/blst)
- [Ethereum 2.0 BLS Signature Spec](https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#bls-signatures)