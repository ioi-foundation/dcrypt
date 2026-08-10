#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TOOLCHAIN="${DCRYPT_ASSEMBLY_TOOLCHAIN:-stable}"
TARGETS=(
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-gnu
    wasm32-unknown-unknown
    thumbv7em-none-eabihf
)

if [[ ! "$TOOLCHAIN" =~ ^[A-Za-z0-9._-]+$ ]]; then
    printf 'error: invalid DCRYPT_ASSEMBLY_TOOLCHAIN value\n' >&2
    exit 2
fi
for command in cargo find grep python3 rustup; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'error: required command is unavailable: %s\n' "$command" >&2
        exit 1
    }
done

installed_targets="$(rustup target list --installed --toolchain "$TOOLCHAIN")"
for target in "${TARGETS[@]}"; do
    if ! grep -Fqx -- "$target" <<<"$installed_targets"; then
        printf 'error: target %s is not installed for toolchain %s\n' "$target" "$TOOLCHAIN" >&2
        printf 'install it with: rustup target add --toolchain %s %s\n' "$TOOLCHAIN" "$target" >&2
        exit 1
    fi
done

build_root="$(mktemp -d "${TMPDIR:-/tmp}/dcrypt-ghash-assembly.XXXXXX")"
cleanup() {
    if [[ "${DCRYPT_KEEP_GHASH_ASSEMBLY:-0}" == "1" ]]; then
        printf 'GHASH assembly artifacts retained at %s\n' "$build_root"
    else
        rm -rf -- "$build_root"
    fi
}
trap cleanup EXIT

python3 "$SCRIPT_DIR/verify-ghash-assembly.py" --self-test
printf 'Inspecting owned GHASH multiplication assembly with %s\n' "$(rustc "+$TOOLCHAIN" --version)"
cd "$PROJECT_ROOT"
for target in "${TARGETS[@]}"; do
    CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="$build_root" \
    RUSTFLAGS="-C codegen-units=1 -C target-cpu=generic" \
        cargo "+$TOOLCHAIN" rustc --locked -p dcrypt-algorithms --release \
            --no-default-features --features aead,block --target "$target" -- --emit=asm

    mapfile -d '' assembly_files < <(
        find "$build_root/$target" -type f -name '*.s' -print0
    )
    if ((${#assembly_files[@]} == 0)); then
        printf 'error: compiler emitted no assembly for %s\n' "$target" >&2
        exit 1
    fi
    python3 "$SCRIPT_DIR/verify-ghash-assembly.py" \
        --target "$target" "${assembly_files[@]}"
done
