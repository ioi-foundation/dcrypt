# Keccak-256 (Ethereum Compatible)

This module provides an implementation of the **Keccak-256** hash function as used in the Ethereum ecosystem. While based on the same Keccak sponge construction as NIST SHA3-256, it uses a different padding scheme, making the outputs distinct and incompatible.

## Use Cases

You must use this `Keccak256` implementation instead of `Sha3_256` for:

*   **Ethereum Address Generation:** Deriving an address from a public key.
*   **Function Selectors:** Calculating the 4-byte selector for smart contract function calls.
*   **Event Signatures:** Computing topic hashes for Ethereum logs.
*   **EIP-712:** Hashing structured data (domain separators, type hashes).
*   **Merkle Patricia Tries:** Verifying proofs against Ethereum state roots.

## Technical Details

*   **Algorithm:** Keccak-256 (original submission)
*   **Output Size:** 32 bytes (256 bits)
*   **Block Size (Rate):** 136 bytes
*   **Domain Separator (Padding):** `0x01` (NIST SHA3 uses `0x06`)

## Usage

The API follows the standard `HashFunction` trait used throughout `dcrypt`.

### One-Shot Hashing

```rust
use dcrypt::algorithms::hash::{Keccak256, HashFunction};

fn main() {
    let data = b"transfer(address,uint256)";
    let digest = Keccak256::digest(data).unwrap();

    // The first 4 bytes of this digest are the function selector: 0xa9059cbb
    println!("Keccak-256 Digest: {}", digest.to_hex());
}
```

### Incremental Hashing

```rust
use dcrypt::algorithms::hash::{Keccak256, HashFunction};

fn main() {
    let mut hasher = Keccak256::new();
    hasher.update(b"Hello, ").unwrap();
    hasher.update(b"Ethereum!").unwrap();
    let digest = hasher.finalize().unwrap();

    println!("Digest: {}", digest.to_hex());
}
```

## Security

This implementation uses the same constant-time sponge construction as the other SHA-3 functions in this library. Sensitive intermediate states are zeroized on drop.