# Candidate audit freezes

This directory defines dcrypt's first-party, fail-closed candidate audit-freeze
format. A structurally valid freeze is not an audit report, an independent
replay, a reproducible-build claim, or release approval. Missing bytes and
unreplayed evidence remain explicit release blockers.

## Immutable two-commit model

1. Commit the source, assurance tooling, threat models, policy, and audit SOW.
   That one-parent commit is the **audit subject**.
2. Use a separate, strictly clean checkout at that exact subject to generate
   `assurance/audit/freezes/dcrypt-v3.0.0-audit-candidate-002/`.
3. Commit only that directory in one **candidate evidence** commit whose sole
   parent is the audit subject.
4. Verify from two separate, strictly clean checkouts: the evidence commit
   supplies committed bundle bytes and its parent supplies regeneration bytes.

The verifier machine-checks the parent relation, exact added path set, regular
`100644` modes, committed blobs versus worktree bytes, and byte-for-byte
regeneration. It rejects unrelated evidence-commit changes, merge commits,
modified/untracked/ignored files, `assume-unchanged`/`skip-worktree` flags,
replacement objects, grafts, alternates, shallow/promisor state, and shaped Git
configuration. Any subject change invalidates the candidate and requires a new
freeze identifier and evidence commit.

Candidate `002` supersedes local candidate `001`. Candidate `001` bound subject
`de9f8a118c227643a938251ddae3d8bc426aaa98` and evidence commit
`d8c7949a94c53cda00efdff99ff6b55413a5e1a6`; it was invalidated before
independent acceptance when a PTY replay exposed an undocumented
`/dev/console` mount. Its exact subject/evidence trees and generated hashes are
retained in the machine-readable supersession record. None of its generated
bytes count as evidence for candidate `002`.

The preflight-observed user-owned *uncommitted `.gitignore` delta* is retained
in policy only as commissioning context. That dirty delta is never accepted in
generation or replay; both checkouts must be strictly clean, including ignored
paths. The committed `.gitignore` blob is still part of the audit subject and
is explicitly bound in `source-manifest.json`.

`freeze.json` hashes eight subordinate JSON manifests. It deliberately omits
itself, `freeze-envelope.json`, and `SHA256SUMS`. The post-subject envelope binds
the immutable subject SOW, audit policy, audit scope, subject identity, and
`freeze.json` digest without rewriting the SOW. `SHA256SUMS` hashes all eleven JSON
documents and never hashes itself. The verifier rejects any other file set or
self-reference.

## Bound local runtime and sandbox

This candidate's structural tooling is bound to these locally observed bytes:

- `/usr/bin/python3.12`: Python 3.12.3,
  SHA-256 `e1efa562c2cc2e35521a5c9c9b9939921001ff8ca9708a13ef15ace68cc2ccd7`;
- `/usr/bin/git`: Git 2.43.0,
  SHA-256 `2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668`;
- `/usr/bin/bwrap`: bubblewrap 0.11.0,
  SHA-256 `a6203eb2d9ebc2e0e9549c55cda170df85a4e269d4369db3f58dc6c2413d1ba3`.

Those observations are not a provisioned toolchain. Distribution provenance,
kernel/user-namespace policy, runtime libraries, and independent host replay
remain release-blocking limitations. Bubblewrap exposes only read-only `/usr`,
`/bin`, `/lib`, `/lib64`, and `/etc/ld.so.cache`, the named checkouts, fresh
`/dev` and `/proc`, and tmpfs `/tmp` and `/cargo`; the namespace root is
remounted read-only. Generation additionally mounts a dedicated tmpfs-backed
`/output`. `--unshare-all` removes the host network namespace. The tools require
only loopback to be visible, umask `0022`, Python `-I -B -S`, an absent and
non-creatable `/nonexistent` HOME, and the exact cleared environment below.

## Exact no-hardlink checkout preparation

Start from a locally available repository containing the designated subject and
the historical `v3.0.0` tag objects. Network acquisition is outside this
procedure. Set `AUDIT_SOURCE`, `AUDIT_CHECKOUT`, and the already reviewed exact
40-hex `AUDIT_SUBJECT`. Run the clone and checkout with this closed environment;
the preparation remains untrusted until the generator repeats its Git,
filesystem, object-storage, HEAD, tree, index, and worktree checks:

```sh
umask 0022
env -i LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC GIT_ALLOW_PROTOCOL=file \
  GIT_ASKPASS=/bin/false GIT_ATTR_NOSYSTEM=1 GIT_CONFIG_COUNT=0 \
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
  GIT_CONFIG_SYSTEM=/dev/null GIT_LFS_SKIP_SMUDGE=1 \
  GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
  GIT_PAGER=cat GIT_PROTOCOL_FROM_USER=0 GIT_TERMINAL_PROMPT=0 \
  PAGER=cat SSH_ASKPASS=/bin/false \
  /usr/bin/git -c pack.writeReverseIndex=false clone --no-local \
  --no-hardlinks --no-checkout "$AUDIT_SOURCE" "$AUDIT_CHECKOUT"
env -i LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC GIT_ALLOW_PROTOCOL=file \
  GIT_ASKPASS=/bin/false GIT_ATTR_NOSYSTEM=1 GIT_CONFIG_COUNT=0 \
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
  GIT_CONFIG_SYSTEM=/dev/null GIT_LFS_SKIP_SMUDGE=1 \
  GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0 \
  GIT_PAGER=cat GIT_PROTOCOL_FROM_USER=0 GIT_TERMINAL_PROMPT=0 \
  PAGER=cat SSH_ASKPASS=/bin/false \
  /usr/bin/git -C "$AUDIT_CHECKOUT" checkout --detach "$AUDIT_SUBJECT"
```

Derive `AUDIT_EPOCH` using the same environment and
`/usr/bin/git -C "$AUDIT_CHECKOUT" show -s --format=%ct "$AUDIT_SUBJECT"`.
Record exact HEAD, `HEAD^{tree}`, `status --porcelain=v1 -z
--untracked-files=all --ignored=matching`, and `git count-objects -v`; the
generator independently rejects hardlinked objects, alternates, replace refs,
grafts, shallow/promisor state, semantic caches, external config, and a dirty
checkout. Never use a local/hardlink clone for replay.

## Materialize the observed structural handoff

This executable provisioning step emits exactly two uniquely linked regular
files: `PROVISIONING-MANIFEST.json` and `SHA256SUMS`. It binds the subject inputs,
lockfile bytes, locally observed host-tool bytes, exact command rows, blockers,
and the fact that the namespace exposed only loopback. It deliberately contains
no registry archive, vendor tree, toolchain distribution, action source,
advisory database, runner/container image, Cargo output, SBOM, or build artifact.

Create an externally visible, initially empty tmpfs directory so bytes survive
the sandbox exit. Its device must differ from the checkout device. Then run:

```sh
PROVISION_OUTPUT=$(/usr/bin/mktemp -d /dev/shm/dcrypt-audit-output.XXXXXX)
PROVISION_LOG_DIR=$(/usr/bin/mktemp -d /dev/shm/dcrypt-audit-provision.XXXXXX)
PROVISION_LOG="$PROVISION_LOG_DIR/operator.log"
umask 0077
set -C
exec 8>"$PROVISION_LOG"
set +C
umask 0022
exec 9</proc/$$/fd/8
PROVISION_LOG_ID=$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/8)
PROVISION_LOG_PRECHECK=0
test ! -L "$PROVISION_LOG_DIR" && test -d "$PROVISION_LOG_DIR" || PROVISION_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %a "$PROVISION_LOG_DIR")" = 700 || PROVISION_LOG_PRECHECK=1
test -f /proc/$$/fd/8 && test -f /proc/$$/fd/9 || PROVISION_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/9)" = "$PROVISION_LOG_ID" || PROVISION_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %h /proc/$$/fd/8)" = 1 || PROVISION_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %a /proc/$$/fd/8)" = 600 || PROVISION_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" = 0 || PROVISION_LOG_PRECHECK=1
test ! -L "$PROVISION_LOG" && test -f "$PROVISION_LOG" || PROVISION_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %d:%i "$PROVISION_LOG")" = "$PROVISION_LOG_ID" || PROVISION_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %d "$PROVISION_OUTPUT")" != \
  "$(/usr/bin/stat -c %d "$AUDIT_CHECKOUT")" || PROVISION_LOG_PRECHECK=1
if test "$PROVISION_LOG_PRECHECK" -eq 0
then
  if (
    exec 8>&-
    exec 9<&-
    umask 0022
    /usr/bin/bwrap \
      --unshare-all --die-with-parent --new-session \
      --ro-bind /usr /usr --ro-bind /bin /bin \
      --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
      --ro-bind /etc/ld.so.cache /etc/ld.so.cache \
      --ro-bind "$AUDIT_CHECKOUT" /dcrypt --bind "$PROVISION_OUTPUT" /output \
      --dev /dev --proc /proc --tmpfs /tmp --tmpfs /cargo --remount-ro / \
      --clearenv --setenv DCRYPT_AUDIT_SANDBOX unshare-all-v1 \
      --setenv DCRYPT_AUDIT_OPERATION provision --setenv CARGO_HOME /cargo \
      --setenv CARGO_INCREMENTAL 0 --setenv CARGO_NET_OFFLINE true \
      --setenv HOME /nonexistent --setenv LANG C.UTF-8 --setenv LC_ALL C.UTF-8 \
      --setenv SOURCE_DATE_EPOCH "$AUDIT_EPOCH" --setenv TZ UTC --chdir /dcrypt \
      /usr/bin/python3.12 -I -B -S /dcrypt/assurance/generate-audit-freeze.py \
      --materialize-provisioning --repo /dcrypt --subject "$AUDIT_SUBJECT" \
      --output /output/dcrypt-audit-provisioning-v1
  ) </dev/null >&8 2>&1
  then
    PROVISION_RC=0
  else
    PROVISION_RC=$?
  fi
else
  PROVISION_RC=125
fi
PROVISION_LOG_POSTCHECK=0
test -f /proc/$$/fd/8 && test -f /proc/$$/fd/9 || PROVISION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/8)" = "$PROVISION_LOG_ID" || PROVISION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/9)" = "$PROVISION_LOG_ID" || PROVISION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %h /proc/$$/fd/8)" = 1 || PROVISION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %a /proc/$$/fd/8)" = 600 || PROVISION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" -le 16777216 || PROVISION_LOG_POSTCHECK=1
test ! -L "$PROVISION_LOG" && test -f "$PROVISION_LOG" || PROVISION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -c %d:%i "$PROVISION_LOG")" = "$PROVISION_LOG_ID" || PROVISION_LOG_POSTCHECK=1
if test "$PROVISION_LOG_POSTCHECK" -eq 0
then
  PROVISION_LOG_SNAPSHOT=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/8) || PROVISION_LOG_POSTCHECK=1
  PROVISION_LOG_SIZE=$(/usr/bin/stat -Lc %s /proc/$$/fd/8) || PROVISION_LOG_POSTCHECK=1
fi
if test "$PROVISION_LOG_POSTCHECK" -eq 0
then
  test "$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/9)" = "$PROVISION_LOG_SNAPSHOT" || PROVISION_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' "$PROVISION_LOG")" = "$PROVISION_LOG_SNAPSHOT" || PROVISION_LOG_POSTCHECK=1
  PROVISION_LOG_FINAL=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/8) || PROVISION_LOG_POSTCHECK=1
  test "$PROVISION_LOG_FINAL" = "$PROVISION_LOG_SNAPSHOT" || PROVISION_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" = "$PROVISION_LOG_SIZE" || PROVISION_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/9)" = "$PROVISION_LOG_SNAPSHOT" || PROVISION_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' "$PROVISION_LOG")" = "$PROVISION_LOG_SNAPSHOT" || PROVISION_LOG_POSTCHECK=1
fi
exec 9<&-
exec 8>&-
if test "$PROVISION_LOG_POSTCHECK" -eq 0
then
  /usr/bin/printf 'operator_log_path_untrusted=%s operator_log_size=%s child_exit=%s\n' \
    "$PROVISION_LOG" "$PROVISION_LOG_SIZE" "$PROVISION_RC" || PROVISION_LOG_POSTCHECK=1
fi
test "$PROVISION_LOG_PRECHECK" -eq 0 && \
  test "$PROVISION_LOG_POSTCHECK" -eq 0 && \
  test "$PROVISION_RC" -eq 0
PROVISION_HANDOFF="$PROVISION_OUTPUT/dcrypt-audit-provisioning-v1"
```

The writer requires an empty `/output`, creates files descriptor-relatively,
checks the complete inventory before and after rename, and leaves a `0555`
directory containing only `0644`, link-count-one files. A generation or replay
sandbox consumes that child as a separate read-only `/provision` mount and
regenerates both bytes before trusting them. Missing, extra, changed,
hardlinked, symlinked, noncanonical, or network-promoting inputs fail.

## Generate the candidate bundle

Use a second empty tmpfs output. The generated directory contains exactly 13
files: eleven canonical JSON documents, `PROVISIONING-SHA256SUMS`, and the main
`SHA256SUMS`.

```sh
GENERATION_OUTPUT=$(/usr/bin/mktemp -d /dev/shm/dcrypt-audit-output.XXXXXX)
GENERATION_LOG_DIR=$(/usr/bin/mktemp -d /dev/shm/dcrypt-audit-generation.XXXXXX)
GENERATION_LOG="$GENERATION_LOG_DIR/operator.log"
umask 0077
set -C
exec 8>"$GENERATION_LOG"
set +C
umask 0022
exec 9</proc/$$/fd/8
GENERATION_LOG_ID=$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/8)
GENERATION_LOG_PRECHECK=0
test ! -L "$GENERATION_LOG_DIR" && test -d "$GENERATION_LOG_DIR" || GENERATION_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %a "$GENERATION_LOG_DIR")" = 700 || GENERATION_LOG_PRECHECK=1
test -f /proc/$$/fd/8 && test -f /proc/$$/fd/9 || GENERATION_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/9)" = "$GENERATION_LOG_ID" || GENERATION_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %h /proc/$$/fd/8)" = 1 || GENERATION_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %a /proc/$$/fd/8)" = 600 || GENERATION_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" = 0 || GENERATION_LOG_PRECHECK=1
test ! -L "$GENERATION_LOG" && test -f "$GENERATION_LOG" || GENERATION_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %d:%i "$GENERATION_LOG")" = "$GENERATION_LOG_ID" || GENERATION_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %d "$GENERATION_OUTPUT")" != \
  "$(/usr/bin/stat -c %d "$AUDIT_CHECKOUT")" || GENERATION_LOG_PRECHECK=1
if test "$GENERATION_LOG_PRECHECK" -eq 0
then
  if (
    exec 8>&-
    exec 9<&-
    umask 0022
    /usr/bin/bwrap \
      --unshare-all --die-with-parent --new-session \
      --ro-bind /usr /usr --ro-bind /bin /bin \
      --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
      --ro-bind /etc/ld.so.cache /etc/ld.so.cache \
      --ro-bind "$AUDIT_CHECKOUT" /dcrypt \
      --ro-bind "$PROVISION_HANDOFF" /provision \
      --bind "$GENERATION_OUTPUT" /output \
      --dev /dev --proc /proc --tmpfs /tmp --tmpfs /cargo --remount-ro / \
      --clearenv --setenv DCRYPT_AUDIT_SANDBOX unshare-all-v1 \
      --setenv DCRYPT_AUDIT_OPERATION generation --setenv CARGO_HOME /cargo \
      --setenv CARGO_INCREMENTAL 0 --setenv CARGO_NET_OFFLINE true \
      --setenv HOME /nonexistent --setenv LANG C.UTF-8 --setenv LC_ALL C.UTF-8 \
      --setenv SOURCE_DATE_EPOCH "$AUDIT_EPOCH" --setenv TZ UTC --chdir /dcrypt \
      /usr/bin/python3.12 -I -B -S /dcrypt/assurance/generate-audit-freeze.py \
      --repo /dcrypt --subject "$AUDIT_SUBJECT" --provision /provision \
      --output /output/dcrypt-v3.0.0-audit-candidate-002
  ) </dev/null >&8 2>&1
  then
    GENERATION_RC=0
  else
    GENERATION_RC=$?
  fi
else
  GENERATION_RC=125
fi
GENERATION_LOG_POSTCHECK=0
test -f /proc/$$/fd/8 && test -f /proc/$$/fd/9 || GENERATION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/8)" = "$GENERATION_LOG_ID" || GENERATION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/9)" = "$GENERATION_LOG_ID" || GENERATION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %h /proc/$$/fd/8)" = 1 || GENERATION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %a /proc/$$/fd/8)" = 600 || GENERATION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" -le 16777216 || GENERATION_LOG_POSTCHECK=1
test ! -L "$GENERATION_LOG" && test -f "$GENERATION_LOG" || GENERATION_LOG_POSTCHECK=1
test "$(/usr/bin/stat -c %d:%i "$GENERATION_LOG")" = "$GENERATION_LOG_ID" || GENERATION_LOG_POSTCHECK=1
if test "$GENERATION_LOG_POSTCHECK" -eq 0
then
  GENERATION_LOG_SNAPSHOT=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/8) || GENERATION_LOG_POSTCHECK=1
  GENERATION_LOG_SIZE=$(/usr/bin/stat -Lc %s /proc/$$/fd/8) || GENERATION_LOG_POSTCHECK=1
fi
if test "$GENERATION_LOG_POSTCHECK" -eq 0
then
  test "$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/9)" = "$GENERATION_LOG_SNAPSHOT" || GENERATION_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' "$GENERATION_LOG")" = "$GENERATION_LOG_SNAPSHOT" || GENERATION_LOG_POSTCHECK=1
  GENERATION_LOG_FINAL=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/8) || GENERATION_LOG_POSTCHECK=1
  test "$GENERATION_LOG_FINAL" = "$GENERATION_LOG_SNAPSHOT" || GENERATION_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" = "$GENERATION_LOG_SIZE" || GENERATION_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/9)" = "$GENERATION_LOG_SNAPSHOT" || GENERATION_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' "$GENERATION_LOG")" = "$GENERATION_LOG_SNAPSHOT" || GENERATION_LOG_POSTCHECK=1
fi
exec 9<&-
exec 8>&-
if test "$GENERATION_LOG_POSTCHECK" -eq 0
then
  /usr/bin/printf 'operator_log_path_untrusted=%s operator_log_size=%s child_exit=%s\n' \
    "$GENERATION_LOG" "$GENERATION_LOG_SIZE" "$GENERATION_RC" || GENERATION_LOG_POSTCHECK=1
fi
test "$GENERATION_LOG_PRECHECK" -eq 0 && \
  test "$GENERATION_LOG_POSTCHECK" -eq 0 && \
  test "$GENERATION_RC" -eq 0
CANDIDATE="$GENERATION_OUTPUT/dcrypt-v3.0.0-audit-candidate-002"
```

To copy into the evidence checkout without preserving links, enumerate the 13
expected names from `SHA256SUMS`, reject any other name, create a fresh
destination, and use `/usr/bin/install -m 0644` once per enumerated filename;
then `chmod 0555` the destination. Do not use `cp -a`, reflinks, hardlinks, or a
recursive archive extraction. Commit only that exact destination. The verifier
compares worktree files with committed Git blobs, so the handoff remains
untrusted.

```sh
EVIDENCE_BUNDLE="$EVIDENCE_CHECKOUT/assurance/audit/freezes/dcrypt-v3.0.0-audit-candidate-002"
/usr/bin/mkdir -p "$(/usr/bin/dirname "$EVIDENCE_BUNDLE")"
/usr/bin/mkdir -m 0755 "$EVIDENCE_BUNDLE"
for name in PROVISIONING-MANIFEST.json PROVISIONING-SHA256SUMS SHA256SUMS \
  actions-and-runners.json artifact-manifest.json assurance-inputs.json \
  environment.json freeze-envelope.json freeze.json limitations.json \
  source-manifest.json toolchains.json workspace-dependencies.json; do
  /usr/bin/install -m 0644 "$CANDIDATE/$name" "$EVIDENCE_BUNDLE/$name"
done
/usr/bin/chmod 0555 "$EVIDENCE_BUNDLE"
```

## Verify with two clean checkouts

Prepare evidence and subject checkouts with the same no-local/no-hardlink
procedure. They must be different directories; the evidence commit must have
exactly one parent, which is the subject. Transfer the two provisioning files
to a fresh tmpfs directory with two explicit `install -m 0644` commands and
`chmod 0555`; do not preserve source metadata or links. Bind that directory as
`/provision` and run:

```sh
REPLAY_PROVISION_PARENT=$(/usr/bin/mktemp -d /dev/shm/dcrypt-audit-handoff.XXXXXX)
REPLAY_PROVISION="$REPLAY_PROVISION_PARENT/dcrypt-audit-provisioning-v1"
/usr/bin/mkdir -m 0755 "$REPLAY_PROVISION"
/usr/bin/install -m 0644 "$PROVISION_HANDOFF/PROVISIONING-MANIFEST.json" \
  "$REPLAY_PROVISION/PROVISIONING-MANIFEST.json"
/usr/bin/install -m 0644 "$PROVISION_HANDOFF/SHA256SUMS" \
  "$REPLAY_PROVISION/SHA256SUMS"
/usr/bin/chmod 0555 "$REPLAY_PROVISION"
PROVISION_HANDOFF="$REPLAY_PROVISION"
```

```sh
STRUCTURAL_LOG_DIR=$(/usr/bin/mktemp -d /dev/shm/dcrypt-audit-structural.XXXXXX)
STRUCTURAL_LOG="$STRUCTURAL_LOG_DIR/operator.log"
umask 0077
set -C
exec 8>"$STRUCTURAL_LOG"
set +C
umask 0022
exec 9</proc/$$/fd/8
STRUCTURAL_LOG_ID=$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/8)
STRUCTURAL_LOG_PRECHECK=0
test ! -L "$STRUCTURAL_LOG_DIR" && test -d "$STRUCTURAL_LOG_DIR" || STRUCTURAL_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %a "$STRUCTURAL_LOG_DIR")" = 700 || STRUCTURAL_LOG_PRECHECK=1
test -f /proc/$$/fd/8 && test -f /proc/$$/fd/9 || STRUCTURAL_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/9)" = "$STRUCTURAL_LOG_ID" || STRUCTURAL_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %h /proc/$$/fd/8)" = 1 || STRUCTURAL_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %a /proc/$$/fd/8)" = 600 || STRUCTURAL_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" = 0 || STRUCTURAL_LOG_PRECHECK=1
test ! -L "$STRUCTURAL_LOG" && test -f "$STRUCTURAL_LOG" || STRUCTURAL_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %d:%i "$STRUCTURAL_LOG")" = "$STRUCTURAL_LOG_ID" || STRUCTURAL_LOG_PRECHECK=1
if test "$STRUCTURAL_LOG_PRECHECK" -eq 0
then
  if (
    exec 8>&-
    exec 9<&-
    umask 0022
    /usr/bin/bwrap \
      --unshare-all --die-with-parent --new-session \
      --ro-bind /usr /usr --ro-bind /bin /bin \
      --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
      --ro-bind /etc/ld.so.cache /etc/ld.so.cache \
      --ro-bind "$EVIDENCE_CHECKOUT" /evidence \
      --ro-bind "$SUBJECT_CHECKOUT" /dcrypt \
      --ro-bind "$PROVISION_HANDOFF" /provision \
      --dev /dev --proc /proc --tmpfs /tmp --tmpfs /cargo --remount-ro / \
      --clearenv --setenv DCRYPT_AUDIT_SANDBOX unshare-all-v1 \
      --setenv DCRYPT_AUDIT_OPERATION verification --setenv CARGO_HOME /cargo \
      --setenv CARGO_INCREMENTAL 0 --setenv CARGO_NET_OFFLINE true \
      --setenv HOME /nonexistent --setenv LANG C.UTF-8 --setenv LC_ALL C.UTF-8 \
      --setenv SOURCE_DATE_EPOCH "$AUDIT_EPOCH" --setenv TZ UTC --chdir /dcrypt \
      /usr/bin/python3.12 -I -B -S /dcrypt/assurance/verify-audit-freeze.py \
      --repo /evidence --subject-repo /dcrypt --provision /provision \
      --bundle /evidence/assurance/audit/freezes/dcrypt-v3.0.0-audit-candidate-002 \
      --mode structural
  ) </dev/null >&8 2>&1
  then
    STRUCTURAL_RC=0
  else
    STRUCTURAL_RC=$?
  fi
else
  STRUCTURAL_RC=125
fi
STRUCTURAL_LOG_POSTCHECK=0
test -f /proc/$$/fd/8 && test -f /proc/$$/fd/9 || STRUCTURAL_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/8)" = "$STRUCTURAL_LOG_ID" || STRUCTURAL_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/9)" = "$STRUCTURAL_LOG_ID" || STRUCTURAL_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %h /proc/$$/fd/8)" = 1 || STRUCTURAL_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %a /proc/$$/fd/8)" = 600 || STRUCTURAL_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" -le 16777216 || STRUCTURAL_LOG_POSTCHECK=1
test ! -L "$STRUCTURAL_LOG" && test -f "$STRUCTURAL_LOG" || STRUCTURAL_LOG_POSTCHECK=1
test "$(/usr/bin/stat -c %d:%i "$STRUCTURAL_LOG")" = "$STRUCTURAL_LOG_ID" || STRUCTURAL_LOG_POSTCHECK=1
if test "$STRUCTURAL_LOG_POSTCHECK" -eq 0
then
  STRUCTURAL_LOG_SNAPSHOT=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/8) || STRUCTURAL_LOG_POSTCHECK=1
  STRUCTURAL_LOG_SIZE=$(/usr/bin/stat -Lc %s /proc/$$/fd/8) || STRUCTURAL_LOG_POSTCHECK=1
fi
if test "$STRUCTURAL_LOG_POSTCHECK" -eq 0
then
  test "$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/9)" = "$STRUCTURAL_LOG_SNAPSHOT" || STRUCTURAL_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' "$STRUCTURAL_LOG")" = "$STRUCTURAL_LOG_SNAPSHOT" || STRUCTURAL_LOG_POSTCHECK=1
  STRUCTURAL_LOG_FINAL=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/8) || STRUCTURAL_LOG_POSTCHECK=1
  test "$STRUCTURAL_LOG_FINAL" = "$STRUCTURAL_LOG_SNAPSHOT" || STRUCTURAL_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" = "$STRUCTURAL_LOG_SIZE" || STRUCTURAL_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/9)" = "$STRUCTURAL_LOG_SNAPSHOT" || STRUCTURAL_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' "$STRUCTURAL_LOG")" = "$STRUCTURAL_LOG_SNAPSHOT" || STRUCTURAL_LOG_POSTCHECK=1
fi
exec 9<&-
exec 8>&-
if test "$STRUCTURAL_LOG_POSTCHECK" -eq 0
then
  /usr/bin/printf 'operator_log_path_untrusted=%s operator_log_size=%s child_exit=%s\n' \
    "$STRUCTURAL_LOG" "$STRUCTURAL_LOG_SIZE" "$STRUCTURAL_RC" || STRUCTURAL_LOG_POSTCHECK=1
fi
test "$STRUCTURAL_LOG_PRECHECK" -eq 0 && \
  test "$STRUCTURAL_LOG_POSTCHECK" -eq 0 && \
  test "$STRUCTURAL_RC" -eq 0
```

Run release verification separately with a new held log. Exit `3` is reserved
for a fully validated candidate rejected solely because the exact 9,319 blockers
remain. Exit `1` means validation, integrity, environment, or runtime failure;
exit `0`, a signal status, or any other result also fails this wrapper.

```sh
RELEASE_LOG_DIR=$(/usr/bin/mktemp -d /dev/shm/dcrypt-audit-release.XXXXXX)
RELEASE_LOG="$RELEASE_LOG_DIR/operator.log"
umask 0077
set -C
exec 8>"$RELEASE_LOG"
set +C
umask 0022
exec 9</proc/$$/fd/8
RELEASE_LOG_ID=$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/8)
RELEASE_LOG_PRECHECK=0
test ! -L "$RELEASE_LOG_DIR" && test -d "$RELEASE_LOG_DIR" || RELEASE_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %a "$RELEASE_LOG_DIR")" = 700 || RELEASE_LOG_PRECHECK=1
test -f /proc/$$/fd/8 && test -f /proc/$$/fd/9 || RELEASE_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/9)" = "$RELEASE_LOG_ID" || RELEASE_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %h /proc/$$/fd/8)" = 1 || RELEASE_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %a /proc/$$/fd/8)" = 600 || RELEASE_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" = 0 || RELEASE_LOG_PRECHECK=1
test ! -L "$RELEASE_LOG" && test -f "$RELEASE_LOG" || RELEASE_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %d:%i "$RELEASE_LOG")" = "$RELEASE_LOG_ID" || RELEASE_LOG_PRECHECK=1
if test "$RELEASE_LOG_PRECHECK" -eq 0
then
  if (
    exec 8>&-
    exec 9<&-
    umask 0022
    /usr/bin/bwrap \
      --unshare-all --die-with-parent --new-session \
      --ro-bind /usr /usr --ro-bind /bin /bin \
      --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
      --ro-bind /etc/ld.so.cache /etc/ld.so.cache \
      --ro-bind "$EVIDENCE_CHECKOUT" /evidence \
      --ro-bind "$SUBJECT_CHECKOUT" /dcrypt \
      --ro-bind "$PROVISION_HANDOFF" /provision \
      --dev /dev --proc /proc --tmpfs /tmp --tmpfs /cargo --remount-ro / \
      --clearenv --setenv DCRYPT_AUDIT_SANDBOX unshare-all-v1 \
      --setenv DCRYPT_AUDIT_OPERATION verification --setenv CARGO_HOME /cargo \
      --setenv CARGO_INCREMENTAL 0 --setenv CARGO_NET_OFFLINE true \
      --setenv HOME /nonexistent --setenv LANG C.UTF-8 --setenv LC_ALL C.UTF-8 \
      --setenv SOURCE_DATE_EPOCH "$AUDIT_EPOCH" --setenv TZ UTC --chdir /dcrypt \
      /usr/bin/python3.12 -I -B -S /dcrypt/assurance/verify-audit-freeze.py \
      --repo /evidence --subject-repo /dcrypt --provision /provision \
      --bundle /evidence/assurance/audit/freezes/dcrypt-v3.0.0-audit-candidate-002 \
      --mode release
  ) </dev/null >&8 2>&1
  then
    RELEASE_RC=0
  else
    RELEASE_RC=$?
  fi
else
  RELEASE_RC=125
fi
RELEASE_LOG_POSTCHECK=0
test -f /proc/$$/fd/8 && test -f /proc/$$/fd/9 || RELEASE_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/8)" = "$RELEASE_LOG_ID" || RELEASE_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/9)" = "$RELEASE_LOG_ID" || RELEASE_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %h /proc/$$/fd/8)" = 1 || RELEASE_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %a /proc/$$/fd/8)" = 600 || RELEASE_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" -le 16777216 || RELEASE_LOG_POSTCHECK=1
test ! -L "$RELEASE_LOG" && test -f "$RELEASE_LOG" || RELEASE_LOG_POSTCHECK=1
test "$(/usr/bin/stat -c %d:%i "$RELEASE_LOG")" = "$RELEASE_LOG_ID" || RELEASE_LOG_POSTCHECK=1
if test "$RELEASE_LOG_POSTCHECK" -eq 0
then
  RELEASE_LOG_SNAPSHOT=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/8) || RELEASE_LOG_POSTCHECK=1
  RELEASE_LOG_SIZE=$(/usr/bin/stat -Lc %s /proc/$$/fd/8) || RELEASE_LOG_POSTCHECK=1
fi
if test "$RELEASE_LOG_POSTCHECK" -eq 0
then
  test "$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/9)" = "$RELEASE_LOG_SNAPSHOT" || RELEASE_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' "$RELEASE_LOG")" = "$RELEASE_LOG_SNAPSHOT" || RELEASE_LOG_POSTCHECK=1
  RELEASE_LOG_FINAL=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/8) || RELEASE_LOG_POSTCHECK=1
  test "$RELEASE_LOG_FINAL" = "$RELEASE_LOG_SNAPSHOT" || RELEASE_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" = "$RELEASE_LOG_SIZE" || RELEASE_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/9)" = "$RELEASE_LOG_SNAPSHOT" || RELEASE_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' "$RELEASE_LOG")" = "$RELEASE_LOG_SNAPSHOT" || RELEASE_LOG_POSTCHECK=1
fi
exec 9<&-
exec 8>&-
if test "$RELEASE_LOG_POSTCHECK" -eq 0
then
  /usr/bin/printf 'operator_log_path_untrusted=%s operator_log_size=%s child_exit=%s\n' \
    "$RELEASE_LOG" "$RELEASE_LOG_SIZE" "$RELEASE_RC" || RELEASE_LOG_POSTCHECK=1
fi
test "$RELEASE_LOG_PRECHECK" -eq 0 && \
  test "$RELEASE_LOG_POSTCHECK" -eq 0 && \
  test "$RELEASE_RC" -eq 3
```

No network is used after the locally available source repository is handed to
the no-hardlink clone step. The sandbox accepts only the exact mount set and
environment for its declared operation. `structural` may succeed while
reporting blockers. `release` fails while any blocker exists. `replay` also
requires separately authorized independent evidence. Do not backdate `--as-of`;
operational verification uses current UTC and checks every expiry.

## Run the adversarial self-test

Use a new empty tmpfs output bind; `--tmpfs /output` is intentionally rejected
because its bytes disappear at sandbox exit and do not prove a transferable
handoff.

```sh
SELFTEST_OUTPUT=$(/usr/bin/mktemp -d /dev/shm/dcrypt-audit-output.XXXXXX)
SELFTEST_LOG_DIR=$(/usr/bin/mktemp -d /dev/shm/dcrypt-audit-selftest.XXXXXX)
SELFTEST_LOG="$SELFTEST_LOG_DIR/operator.log"
umask 0077
set -C
exec 8>"$SELFTEST_LOG"
set +C
umask 0022
exec 9</proc/$$/fd/8
SELFTEST_LOG_ID=$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/8)
SELFTEST_LOG_PRECHECK=0
test ! -L "$SELFTEST_LOG_DIR" && test -d "$SELFTEST_LOG_DIR" || SELFTEST_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %a "$SELFTEST_LOG_DIR")" = 700 || SELFTEST_LOG_PRECHECK=1
test -f /proc/$$/fd/8 && test -f /proc/$$/fd/9 || SELFTEST_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/9)" = "$SELFTEST_LOG_ID" || SELFTEST_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %h /proc/$$/fd/8)" = 1 || SELFTEST_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %a /proc/$$/fd/8)" = 600 || SELFTEST_LOG_PRECHECK=1
test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" = 0 || SELFTEST_LOG_PRECHECK=1
test ! -L "$SELFTEST_LOG" && test -f "$SELFTEST_LOG" || SELFTEST_LOG_PRECHECK=1
test "$(/usr/bin/stat -c %d:%i "$SELFTEST_LOG")" = "$SELFTEST_LOG_ID" || SELFTEST_LOG_PRECHECK=1
if test "$SELFTEST_LOG_PRECHECK" -eq 0
then
  if (
    exec 8>&-
    exec 9<&-
    umask 0022
    /usr/bin/bwrap \
      --unshare-all --die-with-parent --new-session \
      --ro-bind /usr /usr --ro-bind /bin /bin \
      --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
      --ro-bind /etc/ld.so.cache /etc/ld.so.cache \
      --ro-bind "$SUBJECT_CHECKOUT" /dcrypt --bind "$SELFTEST_OUTPUT" /output \
      --dev /dev --proc /proc --tmpfs /tmp --tmpfs /cargo --remount-ro / \
      --clearenv --setenv DCRYPT_AUDIT_SANDBOX unshare-all-v1 \
      --setenv DCRYPT_AUDIT_OPERATION selftest --setenv CARGO_HOME /cargo \
      --setenv CARGO_INCREMENTAL 0 --setenv CARGO_NET_OFFLINE true \
      --setenv HOME /nonexistent --setenv LANG C.UTF-8 --setenv LC_ALL C.UTF-8 \
      --setenv SOURCE_DATE_EPOCH "$AUDIT_EPOCH" --setenv TZ UTC --chdir /dcrypt \
      /usr/bin/python3.12 -I -B -S /dcrypt/assurance/verify-audit-freeze.py --self-test
  ) </dev/null >&8 2>&1
  then
    SELFTEST_RC=0
  else
    SELFTEST_RC=$?
  fi
else
  SELFTEST_RC=125
fi
SELFTEST_LOG_POSTCHECK=0
test -f /proc/$$/fd/8 && test -f /proc/$$/fd/9 || SELFTEST_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/8)" = "$SELFTEST_LOG_ID" || SELFTEST_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %d:%i /proc/$$/fd/9)" = "$SELFTEST_LOG_ID" || SELFTEST_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %h /proc/$$/fd/8)" = 1 || SELFTEST_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %a /proc/$$/fd/8)" = 600 || SELFTEST_LOG_POSTCHECK=1
test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" -le 16777216 || SELFTEST_LOG_POSTCHECK=1
test ! -L "$SELFTEST_LOG" && test -f "$SELFTEST_LOG" || SELFTEST_LOG_POSTCHECK=1
test "$(/usr/bin/stat -c %d:%i "$SELFTEST_LOG")" = "$SELFTEST_LOG_ID" || SELFTEST_LOG_POSTCHECK=1
if test "$SELFTEST_LOG_POSTCHECK" -eq 0
then
  SELFTEST_LOG_SNAPSHOT=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/8) || SELFTEST_LOG_POSTCHECK=1
  SELFTEST_LOG_SIZE=$(/usr/bin/stat -Lc %s /proc/$$/fd/8) || SELFTEST_LOG_POSTCHECK=1
fi
if test "$SELFTEST_LOG_POSTCHECK" -eq 0
then
  test "$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/9)" = "$SELFTEST_LOG_SNAPSHOT" || SELFTEST_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' "$SELFTEST_LOG")" = "$SELFTEST_LOG_SNAPSHOT" || SELFTEST_LOG_POSTCHECK=1
  SELFTEST_LOG_FINAL=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/8) || SELFTEST_LOG_POSTCHECK=1
  test "$SELFTEST_LOG_FINAL" = "$SELFTEST_LOG_SNAPSHOT" || SELFTEST_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -Lc %s /proc/$$/fd/8)" = "$SELFTEST_LOG_SIZE" || SELFTEST_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' /proc/$$/fd/9)" = "$SELFTEST_LOG_SNAPSHOT" || SELFTEST_LOG_POSTCHECK=1
  test "$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' "$SELFTEST_LOG")" = "$SELFTEST_LOG_SNAPSHOT" || SELFTEST_LOG_POSTCHECK=1
fi
exec 9<&-
exec 8>&-
if test "$SELFTEST_LOG_POSTCHECK" -eq 0
then
  /usr/bin/printf 'operator_log_path_untrusted=%s operator_log_size=%s child_exit=%s\n' \
    "$SELFTEST_LOG" "$SELFTEST_LOG_SIZE" "$SELFTEST_RC" || SELFTEST_LOG_POSTCHECK=1
fi
test "$SELFTEST_LOG_PRECHECK" -eq 0 && \
  test "$SELFTEST_LOG_POSTCHECK" -eq 0 && \
  test "$SELFTEST_RC" -eq 0
```

All three standard-I/O descriptors must be non-TTY before Bubblewrap starts.
An interactive PTY causes Bubblewrap to add `/dev/console`, which violates the
closed mount contract and is rejected. The exact wrappers above use `/dev/null`
for stdin. They create each log with shell noclobber (`O_EXCL` semantics) inside
a fresh private directory, retain separate write and read descriptors, duplicate
only the write descriptor onto child stdout/stderr, and close the extra held
descriptors in the child before exec. Postchecks use `fstat` through both held
descriptors, require the surviving pathname to identify the same nonsymlink,
link-count-one inode, enforce the 16 MiB bound, and compare two complete metadata
snapshots including nanosecond modification/change times. They never read or
render the untrusted log bytes automatically. Only a controlled summary of the
untrusted path, observed held size, and child exit is printed after successful
postchecks. A pathname swap therefore cannot redirect child writes or substitute
reviewed output; an oversize, truncate, append, or metadata change is a failing
postcondition and produces no log-byte output. The log is outside every subject,
output, provisioning, and evidence mount. Create a fresh log for every
invocation, including the separate release-mode verification; reusing a nonempty
log fails the runtime preflight. Each wrapper captures the child status before
any postcheck and compares it to the exact expected status as its final operation.

`freeze.json.commands[12..16]` records only exact sandbox-internal commands with
absolute virtual paths. Their expectation rows explicitly say they were not
executed by the generator and require the corresponding exact sandbox. Host
mount sources are represented as typed roles in `environment.json`, not as
executable placeholder argv. The complete operator wrappers above resolve those
roles and are independently replayed; no generated `pass` verdict is inferred
from a command template. Every repository script named by the command inventory
is itself a required, byte-hashed assurance input; deleting a threat-model or
SOW verifier/self-test target makes generation fail before a command is recorded.

## Schema, resource, and provisioning boundaries

All generated JSON is canonical UTF-8 NFC with sorted keys, compact separators,
no floats, no duplicate keys, and one final LF. The three versioned schemas are
digest-bound and evaluated by the in-tree closed schema-subset implementation;
semantic validators are stricter. Reads and writes hold descriptors through
the final inventory check. Paths, symlinks, hardlinks, unexpected entries,
duplicate records, parent swaps, oversized files, and oversized subject blobs
fail closed.

Before the first repository-aware Git subprocess, the raw filesystem preflight
also rejects `.git/commondir`, `.git/gitdir`, FIFOs/special files, hardlinked
critical state, and oversized `HEAD`, `config`, `index`, `packed-refs`, or
`info/exclude` inputs. Git cannot be asked to resolve external common storage or
consume an unbounded critical control file first.

The materialized two-file handoff is the complete executable provisioning
procedure only for **locally observed structural inputs**. It is not the full
offline dependency/toolchain provisioning bundle required for builds. Ten
machine-readable operations remain `blocked-not-materialized`, with owner and
deadline: registry archives, vendor tree, action sources, Rust distributions,
security tools, RustSec database, runner image, container image, live Cargo
ledger validation, and cold-cache artifact rebuilding. The bench processor also
lacks a tracked lock. No network acquisition command is authorized by this
package, and no unresolved pseudo-command is presented as executable.

The current subject intentionally has neither `rust-toolchain` nor
`rust-toolchain.toml`; the handoff must not invent one. Toolchain and action
selection is instead byte-bound to `.github/workflows/security-validation.yml`,
`assurance/ledger.toml`, and `assurance/audit/provisioning-lock.toml`. Appearance
of a root toolchain file is a policy change that fails generation until reviewed.

A later, separately reviewed provisioning package must bind acquisition-tool
binaries, URLs, response identities, licenses, acquisition times, archive
checksums, extraction rules, full regular-file manifests, and an offline runner.
Until then, warm Cargo/rustup caches are not evidence; live ledger checks,
dependency builds, source archives, SBOMs, package archives, disassembly, and
reproducible builds remain explicit release blockers. This package supports a
networkless **source-structural rehearsal**, not a cold-cache build replay.

## Current fail-closed accounting

The candidate preserves all 9,298 atomic assurance blockers. It adds 21 owned
infrastructure limitation records, for 9,319 blocking records under the stated
non-independent counting semantics. The extra infrastructure row records the
unprovisioned bubblewrap/kernel/namespace assumptions. Eighteen required
artifact records are blocked, including five SBOM rows (production,
verification, fuzz, migration, and bench processor) and exact 12-member slots
for candidate and published v3 `.crate` archives. Control-mode expected
failures are reported separately and are not added to 9,319.

## Reviewer checklist

- Confirm the exact subject/evidence commits and trees and the sole-parent
  relation; confirm the evidence delta contains only the candidate directory.
- Run the exact networkless self-test, generation, and two-checkout structural
  verification commands above on the bound local runtime.
- Confirm 9,298 atomic blockers, 21 infrastructure limitations, 9,319 blocking
  records, 18 blocked artifacts, and zero promoted/rebuilt artifact claims.
- Confirm all 17 Cargo manifests, five workspace classifications, four tracked
  locks, the explicitly lockless bench workspace, 12 publishable crate slots,
  and every path/source-less dependency identity.
- Confirm threat-model release mode remains fail-closed with 44 control errors,
  SOW issuance remains blocked, and ledger live-toolchain modes remain
  unprovisioned rather than being inferred from snapshot checks.
- Record command argv, UTC evaluation date, elapsed time, peak memory, host and
  kernel details, every output digest, and reviewer identity. Mark generated
  evidence as first-party until a separate reviewer reproduces it.
- Do not call the result a reproducible build or complete offline clean-room
  replay: dependency, compiler/runtime distribution, container, SBOM, build,
  package, registry, disassembly, and independent-replay bytes remain blocked.
