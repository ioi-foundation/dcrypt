#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PROCESSOR_DIR="$SCRIPT_DIR/bench-processor"
TARGET_FILE="$PROJECT_ROOT/BENCHMARKS.md"
MARKER_DIR="$PROJECT_ROOT/target/bench_markers"

FORCE_RUN=false
CRATES=()
DEFAULT_CRATES=(
    "dcrypt-algorithms"
    "dcrypt-symmetric"
    "dcrypt-kem"
    "dcrypt-sign"
    "dcrypt-hybrid"
)

usage() {
    cat <<'EOF'
Usage: tools/update-benchmarks.sh [--force] [CRATE ...]

Runs Criterion benchmarks only for crates whose Rust sources or benchmark
inputs changed, then regenerates BENCHMARKS.md from Criterion's JSON output.

Options:
  -f, --force  Ignore source hashes and rerun every selected crate.
  -h, --help   Show this help.
EOF
}

is_supported_crate() {
    local candidate=$1
    local supported
    for supported in "${DEFAULT_CRATES[@]}"; do
        [[ "$candidate" == "$supported" ]] && return 0
    done
    return 1
}

while (($# > 0)); do
    case "$1" in
        -f|--force)
            FORCE_RUN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            is_supported_crate "$1" || {
                printf 'unsupported benchmark crate: %s\n' "$1" >&2
                exit 2
            }
            CRATES+=("$1")
            shift
            ;;
    esac
done

if ((${#CRATES[@]} == 0)); then
    CRATES=("${DEFAULT_CRATES[@]}")
fi

for command_name in cargo find sort xargs sha256sum awk; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command_name" >&2
        exit 1
    }
done

mkdir -p "$MARKER_DIR"

printf '\033[0;34mCompiling benchmark processor...\033[0m\n'
(cd "$PROCESSOR_DIR" && cargo build --release --quiet)

calc_hash() {
    local crate_name=$1
    local dir_name=${crate_name#dcrypt-}
    local src_path="$PROJECT_ROOT/crates/$dir_name/src"
    local bench_path="$PROJECT_ROOT/crates/$dir_name/benches"
    local -a input_paths=("$src_path")

    [[ -d "$src_path" ]] || {
        printf 'source directory does not exist for %s: %s\n' "$crate_name" "$src_path" >&2
        return 1
    }
    if [[ -d "$bench_path" ]]; then
        input_paths+=("$bench_path")
    fi

    find "${input_paths[@]}" -type f -name '*.rs' -print0 \
        | sort -z \
        | xargs -0 -r sha256sum \
        | sha256sum \
        | awk '{print $1}'
}

printf '\033[0;34mStarting benchmarks...\033[0m\n'
for crate_name in "${CRATES[@]}"; do
    current_hash=$(calc_hash "$crate_name")
    marker_file="$MARKER_DIR/$crate_name.sha256"

    if [[ "$FORCE_RUN" == false && -f "$marker_file" ]] && \
        [[ "$(<"$marker_file")" == "$current_hash" ]]; then
        printf '\033[0;32m[SKIP]\033[0m %s (unchanged)\n' "$crate_name"
        continue
    fi

    printf '\033[0;33m[RUN]\033[0m  %s\n' "$crate_name"
    if (cd "$PROJECT_ROOT" && cargo bench -p "$crate_name" --benches); then
        printf '%s\n' "$current_hash" >"$marker_file"
    else
        printf '\033[0;31m[FAIL]\033[0m benchmark failed for %s\n' "$crate_name" >&2
        exit 1
    fi
done

printf '\n\033[0;34mProcessing results into markdown...\033[0m\n'
"$PROCESSOR_DIR/target/release/bench-processor" \
    --target "$TARGET_FILE" \
    --criterion-dir "$PROJECT_ROOT/target/criterion"

printf '\033[0;32mBenchmark update complete.\033[0m\n'
