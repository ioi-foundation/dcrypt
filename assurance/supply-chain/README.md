# Package F supply-chain foundation

This directory is the fail-closed local foundation for dcrypt supply-chain,
SBOM, provenance, signing, and independent-rebuild evidence. It records the
reviewed source graph and typed evidence slots without creating, acquiring,
executing, trusting, accepting, or promoting operational evidence.

`reviewed-inventory.toml` is the human-reviewed semantic authority.
`package-f.json`, `schema.json`, and `ARTIFACTS.json` are canonical generated
views. Structural CI may pass when those views reproduce exactly; release mode
always exits 3 while every operational slot remains blocked. Package F does not
authorize version preparation, publishing, signing, registry access, or a
release transition.

`fixtures/control.json` is only a canonical, synthetic parser/path negative-
control index. It is not operational evidence and carries no semantic counts.
`selftest.py` independently constructs and mutates the exact 18-subject,
two-producer, 18-comparison, toolchain, lock, advisory-exception, role-schema,
and package-document controls; the fixture cannot bless or weaken them.

The source topology is a sole-parent chain from the completed Package E commit
through `S_F`, which contains six release-tooling prerequisites, to `R_F`,
which contains only the three oracle-provisioning rebind files. The generated
model binds those committed identities and the later reviewed core/cascade
inputs. `rebind-final-subject.py` separately freezes the literal final changed
path closure; generated artifacts never try to embed the hash of their own
future commit.

The candidate schema has five disjoint roles:

* `local-foundation-proof` is generated structural state and cannot be captured;
* `first-party-build-candidate`, `signature-transparency-candidate`, and
  `independent-rebuild-candidate` are private, untrusted diagnostic bundles;
* `acceptance` has a stable disabled shape and is rejected by v1 validation and
  capture.

Every role is closed, subject-bound, `trusted=false`, and
`promotion_eligible=false`. Captured candidates remain unreviewed. A claimed
signature, signer, independent producer, replay, byte match, toolchain, runner,
or SBOM is data to inspect, not proof that Package F verifies cryptography,
identity, independence, provenance, or reproducibility.

Each raw artifact declaration binds its canonical relative path, exact `0600`
file mode, nonzero bounded size, SHA-256 digest, artifact class, and exact
subject. First-party candidates cover exactly 18 subjects; signature
obligations cover those same 18 subjects; independent replay candidates bind
exactly 18 comparisons and separate producer/replayer identities. Acceptance
remains disabled even when a document is schema-shaped.

Capture accepts only a fixed private source bundle containing canonical
`candidate.json` plus its exact declared artifact closure. It uses descriptor-
anchored no-follow reads, bounded traversal, nonblocking regular-file checks,
private no-replace publication, stability rechecks, fsync, and verified cleanup.
It requires a normal checkout with a `.git` directory, executes no subprocess,
uses no network, and makes no trust or promotion decision. Source and
destination aliases, overlaps, symlinks, hard links, special files, surplus
members, non-private modes, observed identity drift, and existing destinations
fail closed. The private `0700` namespace assumes no noncooperative process
sharing the invoking Unix UID mutates directory entries between a verified
identity check and POSIX name-based unlink; such a same-UID actor is outside
this copier's security boundary, so this package makes no absolute
compare-and-swap cleanup claim against it.

The current foundation binds 17 tracked Cargo manifests, five tracked locks,
342 lock-package occurrences, 255 unique lock identities, five SBOM slots,
twelve candidate archive slots, twelve registry archive slots, and the exact
twelve-crate publication order with 42 internal edges. The sole reviewed
advisory exception is machine-joined bijectively to `deny.toml` and the exact
verification lock path and expires on 2026-09-10. No evidence slot is accepted.

Run structural checks with Python bytecode disabled:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -B assurance/supply-chain/generate.py --check
PYTHONDONTWRITEBYTECODE=1 python3 -B assurance/supply-chain/verify.py --ci
PYTHONDONTWRITEBYTECODE=1 python3 -B assurance/supply-chain/selftest.py
PYTHONDONTWRITEBYTECODE=1 python3 -B assurance/supply-chain/verify.py --release
```

The final command must return 3. A return of zero would be a defect, not release
authorization.
