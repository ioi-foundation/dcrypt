#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
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

build_root="$(mktemp -d "${TMPDIR:-/tmp}/dcrypt-bls-assembly.XXXXXX")"
cargo_home="$(cd "${CARGO_HOME:-${HOME}/.cargo}" >/dev/null 2>&1 && pwd -P)"
# Make the raw compiler emission reproducible across physical checkout and
# Cargo-home paths before the Python gate binds its exact SHA-256.
encoded_rustflags="-C"$'\x1f'"codegen-units=1"$'\x1f'"-C"$'\x1f'"target-cpu=generic"$'\x1f'"--remap-path-prefix=$PROJECT_ROOT=/dcrypt"$'\x1f'"--remap-path-prefix=$cargo_home=/cargo"
cleanup() {
    if [[ "${DCRYPT_KEEP_BLS_ASSEMBLY:-0}" == "1" ]]; then
        printf 'BLS assembly artifacts retained at %s\n' "$build_root"
    else
        rm -rf -- "$build_root"
    fi
}
trap cleanup EXIT

python3 "$SCRIPT_DIR/verify-bls-secret-assembly.py" --self-test
compiler_version="$(rustc "+$TOOLCHAIN" --version)"
case "$compiler_version" in
    'rustc 1.93.1 (01f6ddf75 2026-02-11)') compiler_profile=rust-1.93.1 ;;
    'rustc 1.97.1 (8bab26f4f 2026-07-14)') compiler_profile=rust-1.97.1 ;;
    *)
        printf 'error: unreviewed Rust compiler for BLS assembly gate: %s\n' \
            "$compiler_version" >&2
        exit 1
        ;;
esac
printf 'Inspecting BLS secret-scalar assembly with %s\n' "$compiler_version"
cd "$PROJECT_ROOT"
for target in "${TARGETS[@]}"; do
    CARGO_INCREMENTAL=0 \
    CARGO_HOME="$cargo_home" \
    CARGO_TARGET_DIR="$build_root" \
    CARGO_ENCODED_RUSTFLAGS="$encoded_rustflags" \
        cargo "+$TOOLCHAIN" rustc --locked -p dcrypt-algorithms --release \
            --no-default-features --features ec --target "$target" -- --emit=asm

    mapfile -d '' assembly_files < <(
        find "$build_root/$target" -type f -name '*.s' -print0
    )
    if ((${#assembly_files[@]} != 1)); then
        printf 'error: compiler emitted %s assembly files for %s; expected exactly one\n' \
            "${#assembly_files[@]}" "$target" >&2
        exit 1
    fi
    assembly_file="${assembly_files[0]}"
    if [[ ! -f "$assembly_file" || -L "$assembly_file" || \
          "$(basename "$assembly_file")" != dcrypt_algorithms-*.s ]]; then
        printf 'error: compiler emission is not one regular dcrypt_algorithms assembly file: %s\n' \
            "$assembly_file" >&2
        exit 1
    fi
    python3 "$SCRIPT_DIR/verify-bls-secret-assembly.py" \
        --target "$target" --compiler-profile "$compiler_profile" "$assembly_file"
done
