# Ethereum consensus BLS vectors

These 20 `data.yaml` files are copied verbatim from the official
[`ethereum/consensus-spec-tests`](https://github.com/ethereum/consensus-spec-tests)
repository at commit
`bc5c1a7fb2a8871aaffd4b16ee4dd9c72bb81908` (committed 2025-09-24 and
retrieved 2026-08-09). The preserved upstream root is
`tests/general/altair/bls`; no values or expected results were transformed.

The upstream Git blob identifiers provide an exact per-file provenance check:

| Suite/case | `data.yaml` blob |
| --- | --- |
| `eth_aggregate_pubkeys_empty_list` | `b7206529610901c4bd9f40b068f270d72a5b3054` |
| `eth_aggregate_pubkeys_infinity_pubkey` | `c69b48096b47690144a3e1691dff2896a8b86fc9` |
| `eth_aggregate_pubkeys_valid_0` | `604d21811280f6653606a99a10846777e9f9f728` |
| `eth_aggregate_pubkeys_valid_1` | `8f6312aed649619de1487c1660b2e04fd2c83745` |
| `eth_aggregate_pubkeys_valid_2` | `b1c8597c4aa46dec05660dbae523a2677c4ac0e4` |
| `eth_aggregate_pubkeys_valid_pubkeys` | `0cadccaef44562e8eb17afebfb19f94cc0efbeb3` |
| `eth_aggregate_pubkeys_x40_pubkey` | `a6c8b4644578f89c5be5752b544531723bc81caa` |
| `eth_aggregate_pubkeys_zero_pubkey` | `2127bd9f5c9d38bf2b5bc4c8c05fa9abd2c6515c` |
| `eth_fast_aggregate_verify_extra_pubkey_0` | `1cc73474e3d933697ecd1241384e6b76e4ab26f4` |
| `eth_fast_aggregate_verify_extra_pubkey_1` | `314e7d4826a573524eecad12d555fdb1f0b6a0d6` |
| `eth_fast_aggregate_verify_extra_pubkey_2` | `d95f1e5fa3afdd402df35f61082bbf62034178cb` |
| `eth_fast_aggregate_verify_infinity_pubkey` | `9532d6a0f9262d5e83974e9b8d1e5bc202f4cd6e` |
| `eth_fast_aggregate_verify_na_pubkeys_and_infinity_signature` | `ebeb261678dcb47de325c37bed6789cfb3d0db51` |
| `eth_fast_aggregate_verify_na_pubkeys_and_zero_signature` | `4ef80244f225660d8f4c67ed11f68efdb685051d` |
| `eth_fast_aggregate_verify_tampered_signature_0` | `7ba59ad8cfcbfff10ed3f58943310f23b8a46935` |
| `eth_fast_aggregate_verify_tampered_signature_1` | `e5b880c552fc07f8bc11f611a2b927eccb093fe4` |
| `eth_fast_aggregate_verify_tampered_signature_2` | `ef62f159c56df8b945fcbd78f111a1b6f2cccc31` |
| `eth_fast_aggregate_verify_valid_0` | `f64410c68207000e29c3d339ac888695cc266bb7` |
| `eth_fast_aggregate_verify_valid_1` | `c74feb3bf129999ad9280b64b20c3dfab67ffc7f` |
| `eth_fast_aggregate_verify_valid_2` | `72536bb236ea409c2b6226815389a77bbf819479` |

The fixtures exercise Ethereum's `eth_aggregate_pubkeys` and
`eth_fast_aggregate_verify` extension semantics. They remain in the isolated
verification workspace and are not included in any published dcrypt crate.
