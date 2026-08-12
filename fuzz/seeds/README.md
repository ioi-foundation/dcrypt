# Reviewed fuzz bootstrap seeds

These small, public, non-secret byte inputs were authored in-repository for
Package C on 2026-08-12. They encode no crash and were not imported from a fork,
campaign, vendor, external corpus, or implementation comparator. Every target
has a directory named exactly for its cargo-fuzz target. Maintainer review is
required before replacement or addition; operational corpus promotion uses the
assurance trusted-writer and provenance controls rather than this directory.

Semantic inputs use an exact target-specific `DCRYPT:<TARGET>:V1:` prefix and
`:DCRYPT:END:V1:` trailer. The first payload byte is an ASCII state selector.
ECDSA uses its first byte for the curve and its second byte for one of six
bounded property states. The ML-DSA second payload byte is `D` for deterministic
or `H` for hedged, and the BLS second payload byte is `A` only for aggregation.
A target returns cheaply when framing is absent. This bounds fixed PR smoke cost
while persistent fuzzing can mutate the message payload behind retained framing.
The framing and state bytes are harness control data, not a wire format or
public API.

## Semantic-state inventory

| Target | Reviewed seed files and forced states |
| --- | --- |
| `ml_kem_semantic` | `ml-kem-512`, `ml-kem-768`, `ml-kem-1024` |
| `ml_dsa_semantic` | deterministic and hedged seeds for each of ML-DSA-44, -65, and -87 |
| `bls12_381_semantic` | `basic`, `augmentation`, `proof-of-possession`, `eth2-pop-v4`, `basic-aggregate` |
| `ed25519_semantic` | `deterministic-strict` |
| `ecdsa_semantic` | Six seeds for each of P-224, P-256, P-384, and P-521: `deterministic`, `sign-verify`, `key-roundtrip`, `signature-roundtrip`, `wrong-message`, and `wrong-signature` |
| `ecdh_semantic` | `p-224`, `p-256`, `p-384`, `p-521`, `k-256` |
| `aes_gcm_semantic` | `aes-128-gcm`, `aes-256-gcm`; each also covers AES-128/192/256 blocks and GHASH boundaries |
| `chacha_semantic` | `chacha-xchacha-poly1305` covers both AEADs plus ChaCha20 and Poly1305 chunking |
| `ecies_semantic` | `p-224`, `p-256`, `p-384`, `p-521` |
| `hybrid_semantic` | all five named hybrid KEMs and `ecdsa-ml-dsa-65-signature` |
| `stream_frames` | `aes-gcm-stream`, `chacha20-poly1305-stream` |

The decoder directories provide bounded malformed/selector bootstrap inputs.
The three migration seeds force raw rejection handling, successful legacy
decryption without AAD, and successful legacy decryption with AAD. These seeds
are bootstrap inputs, not campaign execution or assurance evidence.
