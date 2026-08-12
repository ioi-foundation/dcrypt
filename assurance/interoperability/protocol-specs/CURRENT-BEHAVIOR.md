# dcrypt ECIES and hybrid current-behavior freeze

Status: **candidate; independent review required**. This document records the bytes emitted and accepted by the bound implementation sources. It is not a standards claim, protocol redesign, interoperability result, clean-room reference, or release-unblocking artifact. It accepts no oracle and clears no assurance blocker.

The normative machine-readable companion is `current-behavior.json`. `protocol-spec.schema.json` is closed at every object boundary, and `verify-protocol-specs.py` checks canonical encoding, reviewed semantic constants, exact source digests and roles, artifact-manifest completeness, path containment, and absence of symlinks. The verifier also carries reviewed expected SHA-256 digests for this normative registry, schema, authoritative rendering, and final-rebind tool; recomputing the mutable artifact manifest cannot rebind altered semantics. Those embedded digests do not authenticate the verifier itself: the reviewed Git subject/evidence binding must bind the verifier's exact bytes, and no manifest can safely bind its own bytes.

## Notation

- `||` means byte concatenation with no separator unless a separator is shown.
- `u8(x)` is one unsigned byte. `u32be(x)` is a four-byte unsigned big-endian integer.
- `R` is an ephemeral elliptic-curve public key, `N` an AEAD nonce, `C` ciphertext, and `T` an authentication tag.
- All component lengths below are bytes.
- A suite or version described as out of band is selected by the concrete dcrypt type and compatible application state, not decoded from the object.

## Subject binding and mandatory final rebind

This candidate currently has a **final-subject-candidate-review-required** binding. It binds source commit `b3ce4b6d14a5474645cdedb2c7de2b36827bdd48`, source tree `21ff85c3d12ffc8ff08f8e379d61d19d3ce16f92`, canonical `assurance/subject-manifest.json` SHA-256 `3e3615c19ecd0405882a9af03e45a8a4ef8d94347c37c767f242b3287ed15101` (1,510 owned subject files under include policy `production-and-evidence-v1`), and `assurance/curated-operations.toml` SHA-256 `5e2b8cf7de029ff79bda08c0709d6c14b58b2ee655ef44966ef0a0a876ab21f4`. The curated-operations binding is required because the ECIES table retains support classifications.

The complete subject manifest, not the 70-entry critical subset, is the coverage boundary. The subset provides role-oriented review anchors for dependency resolution, Cargo features, public exports and traits, primitive boundaries, ECIES, hybrid KEM, ML-KEM parameters and aliases, ECDSA, and the ML-DSA encoding/signing leaves. Every subset digest must equal its row in the complete manifest and its current repository byte. The default verifier validates every manifest row against the immutable Git commit. `--check-current-subject` additionally requires the current owned path set, bytes, and executable modes to be identical.

This is deliberately not a forever-final claim. Any later Package B non-assurance commit invalidates the then-current binding. While `final_rebind_required` is true, `--require-final-subject` fails until an explicit rebind is performed. After all reviewed non-assurance changes are committed:

1. Record that exact subject commit and its `git rev-parse <commit>^{tree}` value in the assurance ledger, then regenerate `assurance/subject-manifest.json` with the repository's documented `--refresh-subject-manifest` command.
2. Run `rebind-final-subject.py --expected-commit <commit> --expected-tree <tree>`. Before changing a byte, the tool requires the canonical eight-artifact set and exact reviewed modes, rejects symlinks and hardlinks, and requires every artifact plus the curated classifications to equal committed `HEAD`. Immutable normalized pins independently reject semantic changes outside `subject_binding`, critical-source SHA fields, and this exact binding paragraph; in particular, rebinding cannot bless a changed frame grammar, false evidence claim, or changed curated support classification. The tool then updates only those binding fields and critical digests, this paragraph, verifier binding constants/pins, and the local artifact manifest, marking the result `final-subject-candidate-review-required`.
3. Candidate bytes are staged in Git-private storage and only four allowlisted files are atomically replaced. Every caught `BaseException` triggers byte-exact verified rollback. An incomplete interrupted transaction is recovered and fails closed on the next invocation; a complete verified transaction remains recoverable until explicitly finalized.
4. Review every changed path and digest, run `verify-protocol-specs.py --require-final-subject --check-current-subject` and the adversarial self-test, then run `rebind-final-subject.py --finalize-transaction` before creating the later assurance/evidence commit. Use `--rollback-transaction` instead if review rejects the candidate.

The source commit must precede the assurance/evidence commit. A freeze manifest cannot safely bind the commit that contains itself.

## ECIES current behavior

### Suite selection and keys

The four concrete types are selected out of band. Recipient public keys and ephemeral public keys use fixed-width SEC1 uncompressed encodings. Recipient secret keys are fixed-width big-endian scalars. Encryption rejects a recipient public key that is noncanonical, invalid, or the identity.

| Concrete name | Curve | Point | HKDF hash | AEAD | KDF info | Frame overhead |
|---|---:|---:|---|---|---|---:|
| `ECIES-P224-HKDF-SHA256-ChaCha20Poly1305` | P-224 | 57 | SHA-256 | ChaCha20-Poly1305 | `dcrypt-v3/ECIES-P224/HKDF-SHA256/ChaCha20Poly1305` | 91 |
| `ECIES-P256-HKDF-SHA256-ChaCha20Poly1305` | P-256 | 65 | SHA-256 | ChaCha20-Poly1305 | `dcrypt-v3/ECIES-P256/HKDF-SHA256/ChaCha20Poly1305` | 99 |
| `ECIES-P384-HKDF-SHA384-AES256GCM` | P-384 | 97 | SHA-384 | AES-256-GCM | `dcrypt-v3/ECIES-P384/HKDF-SHA384/AES-256-GCM` | 131 |
| `ECIES-P521-HKDF-SHA512-AES256GCM` | P-521 | 133 | SHA-512 | AES-256-GCM | `dcrypt-v3/ECIES-P521/HKDF-SHA512/AES-256-GCM` | 167 |

P-224 remains a transitional surface. The table freezes current behavior; it does not promote that suite or any other row.

### Ciphertext frame

The exact outer encoding is:

```text
u8(R_len) || R || u8(N_len) || N || u32be(CT_len) || C || T
```

Encryption emits the suite's uncompressed point length, a 12-byte random nonce, and `CT_len = plaintext_length + 16`. Both AEADs emit ciphertext followed by a 16-byte tag. The fixed overhead is `point_length + 34`.

The generic frame parser accepts the encoded `u8` and `u32` lengths first, requires the declared payload to end exactly at the input boundary, rejects trailing bytes, and does not allocate the three component vectors until all boundaries have been checked. Suite-specific decryption then requires the selected suite's exact point encoding, a 12-byte nonce, and a payload of at least 16 bytes.

No version, suite, curve, KDF, AEAD, or object magic is present in this frame. Different current point lengths are not a safe negotiation protocol.

### ECDH and key derivation

Encryption generates an ephemeral key pair, computes the ECDH shared point, rejects the identity, and uses only the fixed-width x-coordinate as `Z`. Decryption reconstructs the recipient public key from the recipient scalar and computes the same values.

For the suite-selected hash, derive a 32-byte AEAD key with HKDF-Extract and HKDF-Expand:

```text
salt = ASCII("dcrypt-v3/ECIES/extract")
IKM  = Z || R_uncompressed || recipient_public_key_uncompressed
info = suite-specific KDF-info literal from the table
L    = 32
```

The nonce is generated independently by the caller-supplied RNG; it is not an HKDF output. `None` AAD and an explicitly empty AAD both authenticate the empty byte string. AAD is passed to the AEAD but appears in neither the frame nor HKDF transcript.

### Authentication, tampering, and errors

There is no separate outer key-confirmation field. A successful AEAD verification provides receiver-side confirmation of the derived AEAD key and AAD, but there is no sender confirmation, acknowledgement, or in-band suite/version confirmation.

Current failures are observably nonuniform:

- Empty, truncated, inconsistent, or trailing outer framing produces `InvalidCiphertext` with context `ECIES`.
- A decoded nonce whose length is not 12 produces an underlying nonce/primitive-derived API error, not a normalized ECIES decryption failure.
- An AEAD payload shorter than its tag produces `InvalidCiphertext` with context `ECIES AEAD payload`.
- A wrong-length, noncanonical, invalid, or identity ephemeral key produces `InvalidCiphertext` with context `ECIES ephemeral public key`.
- An identity ECDH result during decryption produces `DecryptionFailed` with context `ECIES Decryption`.
- A wrong recipient key, wrong AAD, modified ciphertext, or modified tag that reaches AEAD verification produces `DecryptionFailed` with context `ECIES Decryption: AEAD authentication failed`.

In particular, the invalid-ephemeral-point behavior is `InvalidCiphertext`, even though existing prose elsewhere may describe it as a general decryption failure. This freeze records the implementation behavior; it does not silently reconcile that discrepancy.

### Versioning and migration limitation

The `dcrypt-v3` text exists only in HKDF literals. The ciphertext has no in-band version and no compatibility decoder or migration record. A caller must already know the exact concrete ECIES type and compatible implementation version. Defining a self-describing envelope, new error contract, negotiation scheme, or migration wire format would change public semantics and is outside this freeze.

## Hybrid KEM current behavior

### Exported suites and raw object encodings

Five concrete types are exported:

| Concrete name | Classical suite ID | PQ suite ID | Public key | Secret key | Ciphertext | Classical secret |
|---|---|---|---:|---:|---:|---:|
| `ECDH-K256-ML-KEM-512` | `ECDH-K256` | `ML-KEM-512` | 833 | 1664 | 801 | 32 |
| `ECDH-P256-ML-KEM-512` | `ECDH-P256` | `ML-KEM-512` | 833 | 1664 | 801 | 32 |
| `ECDH-P256-ML-KEM-768` | `ECDH-P256` | `ML-KEM-768` | 1217 | 2432 | 1121 | 32 |
| `ECDH-P384-ML-KEM-1024` | `ECDH-P384` | `ML-KEM-1024` | 1617 | 3216 | 1617 | 48 |
| `ECDH-P521-ML-KEM-1024` | `ECDH-P521` | `ML-KEM-1024` | 1635 | 3234 | 1635 | 64 |

Each object is a raw concatenation split at compile-time lengths selected by the concrete type:

```text
hybrid_public_key = classical_compressed_public_key || ML-KEM_encapsulation_key
hybrid_secret_key = classical_secret_scalar || ML-KEM_decapsulation_key
hybrid_ciphertext = classical_KEM_ciphertext || ML-KEM_ciphertext
```

There is no magic, component length, suite ID, or version in any object. Length cannot disambiguate the two 512 suites: K256+ML-KEM-512 and P256+ML-KEM-512 have the same three total lengths. Decoding rejects any total-length mismatch before splitting, then decodes the classical component before the post-quantum component.

### Classical component inputs

The current exported suites use compressed SEC1 ECDH public keys and ciphertexts. Their classical shared secret is an HKDF output over:

```text
classical_IKM = ECDH_x_coordinate || ephemeral_compressed_point || recipient_compressed_point
classical_salt = empty
```

K256 and P-256 use HKDF-SHA-256, 32-byte output, and respectively `dcrypt-v3/ECDH-K256-KEM/shared-secret` or `dcrypt-v3/ECDH-P256-KEM/shared-secret` as info. P-384 uses HKDF-SHA-384 with 48-byte output and `dcrypt-v3/ECDH-P384-KEM/shared-secret`. P-521 uses HKDF-SHA-512 with 64-byte output and `dcrypt-v3/ECDH-P521-KEM/shared-secret`.

The generic dimension trait also describes an authenticated P-224 ECDH component, but none of the five concrete exported hybrid suites uses it. This freeze does not invent a P-224 hybrid suite.

### Outer combiner transcript

The outer combiner always uses HKDF-SHA-256 with an empty salt and a 32-byte output:

```text
IKM = u32be(len(classical_ss)) || classical_ss
   || u32be(len(pq_ss))        || pq_ss

info = ASCII("dcrypt-hybrid-kem/v2")
    || u32be(len(classical_suite_id)) || classical_suite_id
    || u32be(len(pq_suite_id))        || pq_suite_id
    || u32be(len(hybrid_ciphertext))  || hybrid_ciphertext
```

The complete raw hybrid ciphertext is bound in `info`. Component public keys are bound indirectly by the classical and ML-KEM component computations, not copied into this outer transcript.

### Decapsulation, implicit rejection, and confirmation

Both component decapsulations run before the outer function returns a component error. A failed component is represented temporarily by an all-zero byte string of that component's declared shared-secret length; the combiner runs; its result is discarded; then the error is returned. If both components fail, the classical error has precedence.

A valid-width modified ML-KEM ciphertext follows FIPS 203 implicit rejection and normally yields a pseudorandom component secret rather than an error. A modified compressed ECDH component that is still a valid point can also yield `Ok` with a different secret; an invalid point yields an error. A wrong but valid hybrid secret key normally produces `Ok` with a different 32-byte final secret.

There is no outer MAC, tag, or explicit key-confirmation step. `Ok` alone is not peer confirmation; applications require a separate confirmation protocol. The `v2` literal is only HKDF info, not an object header. No in-band version negotiation, compatibility decoder, or migration record exists.

## ECDSA P-384 + ML-DSA-65 hybrid signature current behavior

### Framing

Public key, secret key, and signature use the same exact framing shape:

```text
u8(label_len) || label || u32be(first_len) || first || u32be(second_len) || second
```

The labels and component roles are:

| Object | Exact label | First component | Second component | Total length |
|---|---|---|---|---:|
| Public key | `dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/public/v2` | 97-byte uncompressed ECDSA P-384 public key | 1952-byte ML-DSA-65 public key | 2106 |
| Secret key | `dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/secret/v2` | 48-byte ECDSA P-384 scalar | 4032-byte ML-DSA-65 expanded private key | 4137 |
| Signature | `dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/signature/v2` | canonical DER ECDSA P-384 signature | 3309-byte ML-DSA-65 signature | `3369 + DER_length` |

The public and secret labels are 48 bytes; the signature label is 51. Generated low-S ECDSA DER has a mathematical length range of 8 through 103 bytes, giving a generated hybrid-signature range of 3377 through 3472 bytes. In practice almost all outputs are near the upper end; the range is not a fixed-length promise.

The decoder requires the exact object-specific label, bounds-checks both `u32` component lengths, delegates canonicality and length checks to the component decoders, and rejects trailing bytes. An ECDSA high-S signature can pass DER object decoding but is rejected during ECDSA verification.

### What is signed

The component key pairs are generated independently, in ECDSA-then-ML-DSA order, from the caller's RNG. Signing and verification use:

```text
ECDSA input message = caller raw message
ECDSA profile       = SHA-384, deterministic RFC 6979, low-S, canonical DER

ML-DSA input M'     = 0x00 || 0x00 || caller raw message
ML-DSA profile      = FIPS 204 ML-DSA-65 pure mode, empty context,
                      deterministic 32-byte all-zero randomizer
```

The hybrid framing label, component public keys, component lengths, suite name, and `v2` marker are not signed by either component. The labels separate serialized object kinds; they do not domain-separate the signed message.

Verification checks ECDSA first and checks ML-DSA only after ECDSA succeeds. Both must succeed. Component decoding and verification errors remain observable rather than being collapsed to a new hybrid error.

### Versioning and migration

The three v2 framing labels carry the suite, object kind, and version in band. There is no negotiation API. Historical labels containing `ecdsa-p384+dilithium3/.../v1` are explicitly rejected. The decoder does not convert old objects; identification and migration must occur externally. Defining a conversion, cross-component key binding, hybrid context, or prehash profile would be a semantic change.

## Clean-room reference stop condition

This candidate is suitable for independent review of whether it faithfully describes current implementation bytes. It is not yet authority to implement or accept an assurance-bearing clean-room reference.

Reference acceptance remains blocked until reviewers explicitly address the out-of-band ECIES and hybrid-KEM dispatch, equal-length hybrid-KEM ambiguity, hybrid-signature message-domain limitation, and nonuniform errors. Any proposed reference must then receive a separate provenance and lineage decision, use no dcrypt source or generated code, reproduce fixtures independently in both directions, run offline, and preserve disagreements instead of selecting new semantics.

If review proposes a wire-format, transcript, error-contract, or public-semantic change, stop. Preserve the discrepancy and commission that change separately.
