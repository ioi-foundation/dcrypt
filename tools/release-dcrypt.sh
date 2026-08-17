#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
STATE_FILE="$PROJECT_ROOT/.release-state.json"
USER_AGENT="dcrypt-release-tool/3.0 (+https://github.com/ioi-foundation/dcrypt)"
RELEASE_BRANCH="master"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

VERSION=""
MODE="dry-run"
SKIP_TESTS=false
SKIP_CHECKS=false
UPDATE_BENCHMARKS=false
RESUME_FROM=""
REGISTRY_WAIT_SECONDS=300
ACTIVE_LOG=""
CLASSIFIED_WORKSPACE_RECORDS=""
SELF_TEST=false

cleanup() {
    if [[ -n "$ACTIVE_LOG" ]]; then
        rm -f "$ACTIVE_LOG"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

PUBLISH_ORDER=(
    "crates/internal|dcrypt-internal"
    "crates/params|dcrypt-params"
    "crates/api|dcrypt-api"
    "crates/common|dcrypt-common"
    "crates/algorithms|dcrypt-algorithms"
    "crates/symmetric|dcrypt-symmetric"
    "crates/kem|dcrypt-kem"
    "crates/sign|dcrypt-sign"
    "crates/pke|dcrypt-pke"
    "crates/utils|dcrypt-utils"
    "crates/hybrid|dcrypt-hybrid"
    ".|dcrypt"
)

usage() {
    cat <<'EOF'
Usage: tools/release-dcrypt.sh --version VERSION [MODE] [OPTIONS]

Modes (choose at most one):
  (default)            Non-mutating rehearsal. Runs gates, packaging checks,
                       registry checks, and cargo-release's version dry-run.
                       Missing audit, deny, Miri, or fuzz tools are fatal.
  --prepare            From a clean tree, apply the version bump, create the
                       release commit if cargo-release did not, and create the
                       local annotated tag. Does not push or publish.
  --execute            Publish the already prepared release to crates.io. The
                       exact tagged commit must already be present on origin.

Options:
  --update-benchmarks  Refresh BENCHMARKS.md during --prepare. This must leave
                       a clean tree before versioning continues.
  --skip-tests         Development rehearsal only: skip workspace, vector,
                       interoperability, and isolated timing tests.
  --skip-checks        Development rehearsal only: skip format/check,
                       audit/deny, Miri, and deterministic semantic fuzz smoke. The
                       implementation-boundary, BLS assembly, and GHASH assembly
                       gates cannot be skipped.
  --resume CRATE       Resume a partial --execute at CRATE, or use "auto" to
                       trust crates.io as the source of truth.
  --registry-wait SEC  Maximum registry propagation wait per crate (default 300).
  --reset-state        Remove only .release-state.json and exit.
  --self-test          Run mock-only release-tool regression tests and exit.
  -h, --help           Show this help.

Safe workflow:
  tools/release-dcrypt.sh --version 3.0.0
  tools/release-dcrypt.sh --version 3.0.0 --prepare
  # Follow the printed candidate-check, atomic-push, and draft-release handoff.
  tools/release-dcrypt.sh --version 3.0.0 --execute
EOF
}

info() {
    printf "${CYAN}%s${NC}\n" "$*"
}

warn() {
    printf "${YELLOW}warning: %s${NC}\n" "$*" >&2
}

die() {
    printf "${RED}error: %s${NC}\n" "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

cargo_subcommand_available() {
    cargo "$1" --version >/dev/null 2>&1
}

load_classified_workspace_records() {
    local records
    if ! records=$("$SCRIPT_DIR/verify-implementation-boundary.py" \
        --list-classified-workspaces); then
        die "could not load the authoritative classified-workspace policy"
    fi
    [[ -n "$records" ]] || die "classified-workspace policy is empty"
    CLASSIFIED_WORKSPACE_RECORDS=$records
}

classified_workspace_records() {
    [[ -n "$CLASSIFIED_WORKSPACE_RECORDS" ]] \
        || die "classified-workspace policy was not loaded"
    printf '%s\n' "$CLASSIFIED_WORKSPACE_RECORDS"
}

is_classified_workspace_release_path() {
    local candidate=$1
    local category workspace
    while IFS=$'\t' read -r category workspace; do
        [[ -n "$category" && -n "$workspace" ]] || continue
        if [[ "$candidate" == "$workspace/Cargo.toml" || \
              "$candidate" == "$workspace/Cargo.lock" ]]; then
            return 0
        fi
    done < <(classified_workspace_records)
    return 1
}

is_valid_semver() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]
}

current_version() {
    cargo metadata --no-deps --format-version 1 2>/dev/null \
        | jq -r '.packages[] | select(.name == "dcrypt") | .version'
}

current_branch() {
    git branch --show-current
}

assert_clean_tree() {
    if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
        die "the working tree must be clean; commit and review changes before $MODE"
    fi
}

crate_version_exists() {
    local crate_name=$1
    local version=$2
    local response

    if ! response=$(curl --fail --silent --show-error --location \
        --user-agent "$USER_AGENT" \
        "https://crates.io/api/v1/crates/$crate_name"); then
        die "could not query crates.io for $crate_name"
    fi

    jq -e --arg version "$version" \
        '.versions | any(.num == $version)' <<<"$response" >/dev/null
}

target_registry_count() {
    local count=0
    local entry path crate_name
    for entry in "${PUBLISH_ORDER[@]}"; do
        IFS='|' read -r path crate_name <<<"$entry"
        if crate_version_exists "$crate_name" "$VERSION"; then
            count=$((count + 1))
        fi
    done
    printf '%d\n' "$count"
}

check_registry_target() {
    local published_count
    published_count=$(target_registry_count)

    if [[ "$MODE" == "prepare" && $published_count -ne 0 ]]; then
        die "$published_count target-version crate(s) already exist; preparation cannot overwrite crates.io"
    fi

    if [[ "$MODE" == "execute" && $published_count -gt 0 && -z "$RESUME_FROM" ]]; then
        die "$published_count target-version crate(s) already exist; use --resume auto after verifying the partial release"
    fi

    if [[ "$MODE" == "execute" && $published_count -eq ${#PUBLISH_ORDER[@]} ]]; then
        die "all crates are already published at $VERSION"
    fi

    if [[ "$MODE" == "dry-run" && $published_count -gt 0 ]]; then
        warn "$published_count target-version crate(s) already exist on crates.io"
    else
        info "crates.io target check: $published_count/${#PUBLISH_ORDER[@]} already published"
    fi
}

save_state() {
    local -a published=("$@")
    jq -n \
        --arg version "$VERSION" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --args \
        '{version: $version, published: $ARGS.positional, timestamp: $timestamp}' \
        "${published[@]}" \
        >"$STATE_FILE"
}

run_release_acceptance_gate() {
    local phase=$1
    case "$phase" in
        foundation|prepublish|postpublish)
            ;;
        *)
            die "unknown v4 release-profile phase: $phase"
            ;;
    esac

    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/assurance/release-profile/selftest.py" \
        || die "v4 release-profile adversarial self-tests failed"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/assurance/release-profile/verify.py" --phase "$phase" \
        || die "v4 portable-software release profile is not authorized"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/tools/replay-historical-advisories.py" --check \
        || die "historical advisory replay inventory is invalid"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/tools/generate-release-sboms.py" --self-test \
        || die "deterministic SBOM controls failed"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/tools/verify-repeatable-packages.py" --self-test \
        || die "repeatable-package controls failed"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/tools/run-v4-lab-simulation.py" --self-test \
        || die "simulated laboratory controls failed"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/tools/generate-v4-assurance-report.py" --self-test \
        || die "Assurance Profile generation controls failed"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/assurance/threat-models/generate-threat-models.py" --check \
        || die "threat-model generated artifacts are stale or invalid"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/assurance/threat-models/verify-threat-models.py" --self-test \
        || die "threat-model adversarial self-tests failed"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/assurance/threat-models/verify-threat-models.py" --mode ci \
        || die "threat-model foundation structure failed"

    local threat_model_release_rc
    set +e
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/assurance/threat-models/verify-threat-models.py" --mode release
    threat_model_release_rc=$?
    set -e
    [[ "$threat_model_release_rc" -eq 1 ]] \
        || die "threat-model release verifier returned $threat_model_release_rc; expected blocked rc 1"

    info "Package G certification HOLD preserved; v4 portable-software profile authorized for $phase"
}

run_publish_verifier() {
    local version=$1
    local require_unpublished=${2:-false}
    local -a args=(--version "$version" --assurance-phase prepublish)
    if [[ "$require_unpublished" == true ]]; then
        args+=(--require-unpublished)
    fi
    "$SCRIPT_DIR/verify-publish-ready.sh" "${args[@]}"
}

run_candidate_comparator_replay() {
    local workspace=$1
    local replay_root
    replay_root=$(mktemp -d "${TMPDIR:-/tmp}/dcrypt-oracle-release.XXXXXX")
    (
        set -Eeuo pipefail
        trap 'chmod -R u+w -- "$replay_root" 2>/dev/null || true; rm -rf -- "$replay_root"' EXIT
        python3 -B "$PROJECT_ROOT/verification/oracle-provisioning/acquire.py" \
            --manifest "$PROJECT_ROOT/verification/oracle-provisioning/manifest.json" \
            --lock "$PROJECT_ROOT/$workspace/Cargo.lock" \
            --output "$replay_root/archives"
        python3 -B "$PROJECT_ROOT/verification/oracle-provisioning/selftest.py" \
            --manifest "$PROJECT_ROOT/verification/oracle-provisioning/manifest.json" \
            --lock "$PROJECT_ROOT/$workspace/Cargo.lock" \
            --archives "$replay_root/archives" \
            --repo-root "$PROJECT_ROOT"
        python3 -B "$PROJECT_ROOT/verification/oracle-provisioning/materialize.py" \
            --manifest "$PROJECT_ROOT/verification/oracle-provisioning/manifest.json" \
            --lock "$PROJECT_ROOT/$workspace/Cargo.lock" \
            --archives "$replay_root/archives" \
            --output "$replay_root/materialized" \
            --repo-root "$PROJECT_ROOT"
        python3 -B "$PROJECT_ROOT/verification/oracle-provisioning/replay.py" \
            --manifest "$PROJECT_ROOT/verification/oracle-provisioning/manifest.json" \
            --lock "$PROJECT_ROOT/$workspace/Cargo.lock" \
            --archives "$replay_root/archives" \
            --materialized "$replay_root/materialized" \
            --toolchain-root "$(rustc +1.93.1 --print sysroot)"
    )
}

run_test_gates() {
    if [[ "$SKIP_TESTS" == true ]]; then
        warn "test gates were explicitly skipped"
        return
    fi

    info "Running workspace tests"
    cargo test --workspace --all-features --exclude dcrypt-tests --no-fail-fast

    info "Running the locked auxiliary bench-processor tests"
    cargo test --locked --all-features --manifest-path \
        "$PROJECT_ROOT/tools/bench-processor/Cargo.toml"

    info "Running dcrypt-tests library unit tests"
    cargo test -p dcrypt-tests --lib --all-features

    info "Running the complete ACVP suite, including exact ML-DSA and ML-KEM outputs"
    cargo test --release -p dcrypt-tests --test acvp_tests -- \
        --test-threads=1 --nocapture

    info "Running AES-CBC property tests"
    cargo test --release -p dcrypt-tests --test property_aes_cbc -- \
        --test-threads=1 --nocapture

    local category workspace
    while IFS=$'\t' read -r category workspace; do
        [[ -n "$category" && -n "$workspace" ]] || continue
        case "$category" in
            verification)
                info "Running isolated candidate comparators (not independent assurance evidence): $workspace"
                run_candidate_comparator_replay "$workspace"
                ;;
            owned)
                info "Testing classified owned workspace: $workspace"
                cargo test --release --locked --manifest-path \
                    "$PROJECT_ROOT/$workspace/Cargo.toml"
                ;;
            fuzz)
                ;;
            *)
                die "unsupported classified workspace category: $category"
                ;;
        esac
    done < <(classified_workspace_records)

    info "Running isolated statistical timing regressions"
    if [[ -n "${DCRYPT_TIMING_CPU:-}" ]]; then
        [[ "$DCRYPT_TIMING_CPU" =~ ^[0-9]+$ ]] \
            || die "DCRYPT_TIMING_CPU must be a nonnegative CPU index"
        require_command taskset
        info "Pinning only the statistical timing regressions to CPU $DCRYPT_TIMING_CPU"
        taskset -c "$DCRYPT_TIMING_CPU" \
            cargo test -p dcrypt-tests --test constant_time_tests -- \
            --test-threads=1 --nocapture
    else
        cargo test -p dcrypt-tests --test constant_time_tests -- \
            --test-threads=1 --nocapture
    fi
}

require_security_subcommand() {
    local subcommand=$1
    local install_hint=$2
    if cargo_subcommand_available "$subcommand"; then
        return 0
    fi

    die "cargo-$subcommand is required; install with: $install_hint"
}

run_check_gates() {
    if [[ "$SKIP_CHECKS" == true ]]; then
        warn "format, static, supply-chain, Miri, and fuzz gates were explicitly skipped; the implementation-boundary, BLS assembly, and GHASH assembly gates still ran"
        return
    fi

    info "Running formatting and all-target/all-feature checks"
    cargo fmt --all -- --check
    python3 "$SCRIPT_DIR/verify-remote-release-ready.py" --self-test
    local category workspace
    while IFS=$'\t' read -r category workspace; do
        [[ -n "$category" && -n "$workspace" ]] || continue
        cargo fmt --manifest-path "$PROJECT_ROOT/$workspace/Cargo.toml" -- --check
        if [[ "$category" == "owned" ]]; then
            RUSTFLAGS="-Dunsafe-code" cargo check --locked --all-targets --all-features \
                --manifest-path "$PROJECT_ROOT/$workspace/Cargo.toml"
        fi
    done < <(classified_workspace_records)
    cargo fmt --manifest-path \
        "$PROJECT_ROOT/tools/bench-processor/Cargo.toml" -- --check
    cargo check --locked --all-targets --all-features --manifest-path \
        "$PROJECT_ROOT/tools/bench-processor/Cargo.toml"
    cargo check --workspace --all-targets --all-features

    require_security_subcommand audit "cargo install cargo-audit --locked"
    cargo audit
    while IFS=$'\t' read -r category workspace; do
        [[ -n "$category" && -n "$workspace" ]] || continue
        cargo audit --file "$PROJECT_ROOT/$workspace/Cargo.lock"
    done < <(classified_workspace_records)
    cargo audit --file "$PROJECT_ROOT/tools/bench-processor/Cargo.lock"

    require_security_subcommand deny "cargo install cargo-deny --locked"
    cargo deny --workspace --all-features check
    while IFS=$'\t' read -r category workspace; do
        [[ -n "$category" && -n "$workspace" ]] || continue
        cargo deny --manifest-path "$PROJECT_ROOT/$workspace/Cargo.toml" \
            --all-features check
    done < <(classified_workspace_records)
    cargo deny --manifest-path "$PROJECT_ROOT/tools/bench-processor/Cargo.toml" \
        --all-features check

    if cargo +nightly-2026-08-07 miri --version >/dev/null 2>&1; then
        info "Running Miri on public error and secret-memory APIs"
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly-2026-08-07 miri test -p dcrypt-api --lib --all-features
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly-2026-08-07 miri test -p dcrypt-common --lib --all-features
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly-2026-08-07 miri test -p dcrypt-kem --lib --all-features miri_
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly-2026-08-07 miri test -p dcrypt-sign --lib --all-features \
                expanded_key_decoder_rejects_malformed_or_incoherent_components
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly-2026-08-07 miri test -p dcrypt-sign --lib --all-features \
                rejects_identity_public_key_and_universal_forgery
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly-2026-08-07 miri test -p dcrypt-sign --lib --all-features \
                secret_key_is_canonical_nonzero_and_debug_redacted
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly-2026-08-07 miri test -p dcrypt-algorithms --lib --all-features \
                secret_big_endian_bridge_matches_g1_and_g2_scalar_multiplication
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly-2026-08-07 miri test -p dcrypt-algorithms --lib --all-features \
                rfc9380_g1_random_oracle_vectors
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly-2026-08-07 miri test -p dcrypt-algorithms --lib --all-features \
                rfc9380_g2_random_oracle_vectors
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly-2026-08-07 miri test -p dcrypt-algorithms --lib --all-features \
                checked_decoders_reject_on_curve_non_subgroup_point
    else
        die "pinned nightly-2026-08-07 Miri is required (rustup component add miri --toolchain nightly-2026-08-07)"
    fi

    local fuzz_workspace_records
    fuzz_workspace_records=$(classified_workspace_records | awk -F '\t' \
        '$1 == "fuzz" { print }') \
        || die "could not classify the fuzz workspace"
    [[ "$fuzz_workspace_records" == $'fuzz\tfuzz' ]] \
        || die "expected exactly one classified fuzz workspace at fuzz"
    cargo +nightly-2026-08-08 fetch --locked \
        --manifest-path "$PROJECT_ROOT/fuzz/Cargo.toml" \
        || die "could not provision the exact locked fuzz dependency closure"
    info "Building and running every cargo-fuzz target through the sealed private-corpus runner"
    python3 -B "$PROJECT_ROOT/assurance/fuzzing/run-fuzz-smoke.py" \
        --mode pr --execute \
        || die "Package C deterministic fuzz smoke failed"
}

check_package_contents() {
    local allow_dirty=false
    local entry relative_path crate_name
    if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
        allow_dirty=true
    fi

    info "Validating packaged file lists"
    for entry in "${PUBLISH_ORDER[@]}"; do
        IFS='|' read -r relative_path crate_name <<<"$entry"
        printf '  %s\n' "$crate_name"
        if [[ "$allow_dirty" == true ]]; then
            (cd "$PROJECT_ROOT/$relative_path" && cargo package --list --allow-dirty >/dev/null)
        else
            (cd "$PROJECT_ROOT/$relative_path" && cargo package --list >/dev/null)
        fi
    done
}

run_v4_laboratory() {
    local evidence_root="$PROJECT_ROOT/target/release-evidence/v4-lab"
    local documentation_root="$evidence_root/assurance-docs"
    local version
    version=$(current_version)
    info "Running the open v4 software/simulated laboratory"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/tools/run-v4-lab-simulation.py" \
        --output "$evidence_root" \
        || die "v4 software/simulated laboratory failed"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/tools/generate-v4-assurance-report.py" \
        --check --lab-output "$evidence_root" \
        --output "$evidence_root/assurance-report" \
        || die "generated v4 Assurance Profile did not reproduce"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$PROJECT_ROOT/tools/generate-assurance-docs.py" \
        --profile "$evidence_root/assurance-report/assurance-profile.json" \
        --summary "$documentation_root/V4-SUMMARY.md" \
        --assets-dir "$documentation_root" \
        --source-ref "v$version" \
        || die "release-facing Assurance Profile graphics were not generated"
}

run_all_gates() {
    local version
    version=$(current_version)
    validate_isolated_workspace_versions "$version"
    run_publish_verifier "$version"
    run_check_gates
    run_test_gates
    check_package_contents
    run_v4_laboratory
}

update_benchmarks() {
    if [[ "$UPDATE_BENCHMARKS" != true ]]; then
        return 0
    fi
    info "Updating benchmark documentation"
    "$SCRIPT_DIR/update-benchmarks.sh"
    if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
        die "benchmark updates changed the tree; review and commit them, then rerun --prepare"
    fi
}

validate_release_documentation() {
    if ! grep -Fq "## [$VERSION]" "$PROJECT_ROOT/CHANGELOG.md"; then
        die "CHANGELOG.md needs a finalized '## [$VERSION]' section before preparation"
    fi
    if ! grep -Fq "v$VERSION" "$PROJECT_ROOT/SECURITY.md"; then
        die "SECURITY.md must identify v$VERSION and its support status before preparation"
    fi
}

validate_isolated_workspace_versions() {
    local expected=$1
    python3 "$SCRIPT_DIR/update-isolated-workspace-versions.py" \
        --expect "$expected"
}

update_isolated_workspace_versions() {
    local before=$1
    local after=$2
    python3 "$SCRIPT_DIR/update-isolated-workspace-versions.py" \
        --from-version "$before" \
        --to-version "$after"
    validate_isolated_workspace_versions "$after"
}

create_release_commit_if_needed() {
    local unexpected=""
    local status_line path

    while IFS= read -r status_line; do
        [[ -n "$status_line" ]] || continue
        path=${status_line:3}
        case "$path" in
            Cargo.toml|crates/*/Cargo.toml|tests/Cargo.toml|Cargo.lock)
                ;;
            *)
                if ! is_classified_workspace_release_path "$path"; then
                    unexpected+="  $path"$'\n'
                fi
                ;;
        esac
    done < <(git status --porcelain --untracked-files=all)

    if [[ -n "$unexpected" ]]; then
        printf '%s' "$unexpected" >&2
        die "versioning changed unexpected files; review without committing automatically"
    fi

    if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
        local -a generated_paths=(Cargo.toml Cargo.lock crates/*/Cargo.toml tests/Cargo.toml)
        local category workspace
        while IFS=$'\t' read -r category workspace; do
            [[ -n "$category" && -n "$workspace" ]] || continue
            generated_paths+=("$workspace/Cargo.toml" "$workspace/Cargo.lock")
        done < <(classified_workspace_records)
        git add "${generated_paths[@]}"
        git commit -m "chore: release version $VERSION"
    fi
}

refresh_isolated_workspace_locks() {
    local category workspace
    while IFS=$'\t' read -r category workspace; do
        [[ -n "$category" && -n "$workspace" ]] || continue
        cargo metadata --format-version 1 --manifest-path \
            "$PROJECT_ROOT/$workspace/Cargo.toml" >/dev/null
    done < <(classified_workspace_records)
}

prepare_release() {
    assert_clean_tree
    validate_release_documentation
    check_registry_target
    update_benchmarks
    run_all_gates

    local before_version
    before_version=$(current_version)
    validate_isolated_workspace_versions "$before_version"
    if [[ "$before_version" != "$VERSION" ]]; then
        info "Updating workspace from $before_version to $VERSION"
        cargo release version "$VERSION" --execute --no-confirm
        update_isolated_workspace_versions "$before_version" "$VERSION"
        refresh_isolated_workspace_locks
        create_release_commit_if_needed
    else
        info "Workspace is already versioned as $VERSION"
    fi

    [[ "$(current_version)" == "$VERSION" ]] || die "version update did not produce $VERSION"
    assert_clean_tree
    run_publish_verifier "$VERSION" true
    check_package_contents
    # The rehearsal laboratory ran before version preparation. Re-run it on the
    # exact versioned commit so release assets cannot describe the prior subject.
    run_v4_laboratory

    local tag="v$VERSION"
    if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
        [[ "$(git cat-file -t "refs/tags/$tag")" == "tag" ]] \
            || die "$tag already exists but is not an annotated tag object"
        [[ "$(git rev-list -n 1 "$tag")" == "$(git rev-parse HEAD)" ]] \
            || die "$tag already exists but does not point to HEAD"
        info "Local tag $tag already points to HEAD"
    else
        git tag -a "$tag" -m "Release version $VERSION"
        info "Created local annotated tag $tag"
    fi

    [[ -n "$(current_branch)" ]] \
        || die "cannot prepare a release from detached HEAD"

    local head_commit
    head_commit=$(git rev-parse HEAD)

    print_release_handoff "$tag" "$head_commit"
}

print_release_handoff() {
    local tag=$1
    local head_commit=$2
    local candidate_branch="release-candidate/$tag"

    printf "\n${GREEN}Release preparation complete; nothing was published.${NC}\n"
    printf '1. Push only a candidate branch; do not push the tag yet:\n'
    printf '  git push origin %q\n' \
        "$head_commit:refs/heads/$candidate_branch"
    printf '2. Require every trusted check to pass for exact SHA %s.\n' "$head_commit"
    printf '3. Fast-forward the release branch and push it with the annotated tag atomically:\n'
    printf '  git push --atomic origin %q %q\n' \
        "$head_commit:refs/heads/$RELEASE_BRANCH" \
        "refs/tags/$tag:refs/tags/$tag"
    printf '4. Verify origin/%s and the peeled origin tag both resolve to %s:\n' \
        "$RELEASE_BRANCH" "$head_commit"
    printf '  git ls-remote origin %q %q %q\n' \
        "refs/heads/$RELEASE_BRANCH" "refs/tags/$tag" "refs/tags/$tag^{}"
    printf '5. Create and review a GitHub draft with the generated Assurance Profile and graphics:\n'
    printf '  gh release create %q \\\n' "$tag"
    printf '    %q \\\n' \
        "target/release-evidence/v4-lab/assurance-report/assurance-profile.json" \
        "target/release-evidence/v4-lab/assurance-report/assurance-report.html" \
        "target/release-evidence/v4-lab/assurance-docs/V4-SUMMARY.md" \
        "target/release-evidence/v4-lab/assurance-docs/v4-assurance-overview-light.svg" \
        "target/release-evidence/v4-lab/assurance-docs/v4-assurance-overview-dark.svg" \
        "target/release-evidence/v4-lab/assurance-docs/v4-evidence-flow-light.svg" \
        "target/release-evidence/v4-lab/assurance-docs/v4-evidence-flow-dark.svg" \
        "target/release-evidence/v4-lab/assurance-docs/v4-timing-family-light.svg"
    printf '    %q --draft --verify-tag --title %q --notes-file RELEASE_NOTES.md\n' \
        "target/release-evidence/v4-lab/assurance-docs/v4-timing-family-dark.svg" \
        "dcrypt $tag"
    printf '6. Only after that draft exists, run:\n'
    printf '  tools/release-dcrypt.sh --version %q --execute\n' "$VERSION"
}

release_self_test() {
    local fixture_head="0123456789abcdef0123456789abcdef01234567"
    local fixture_tag="v9.8.7"
    local handoff

    handoff=$(print_release_handoff "$fixture_tag" "$fixture_head")
    [[ "$RELEASE_BRANCH" == "master" ]] \
        || die "self-test: release branch must remain master"
    grep -Fq \
        "$fixture_head:refs/heads/master" <<<"$handoff" \
        || die "self-test: handoff omitted the exact master refspec"
    grep -Fq \
        "$fixture_head:refs/heads/release-candidate/$fixture_tag" <<<"$handoff" \
        || die "self-test: handoff omitted the exact candidate refspec"
    if grep -Fq 'refs/heads/agent/' <<<"$handoff"; then
        die "self-test: handoff used a feature branch as the release branch"
    fi
    grep -Fq 'assurance-report/assurance-profile.json' <<<"$handoff" \
        || die "self-test: release handoff omitted the machine Assurance Profile"
    grep -Fq 'assurance-report/assurance-report.html' <<<"$handoff" \
        || die "self-test: release handoff omitted the visual assurance report"
    grep -Fq 'assurance-docs/v4-assurance-overview-light.svg' <<<"$handoff" \
        || die "self-test: release handoff omitted generated assurance graphics"
    grep -Fq 'RELEASE_BRANCH = "master"' \
        "$SCRIPT_DIR/verify-remote-release-ready.py" \
        || die "self-test: shell and remote gate release branches differ"
    grep -Fq 'run_candidate_comparator_replay "$workspace"' "$0" \
        || die "self-test: release test gate omitted the exact candidate comparator runner"
    grep -Fq 'not independent assurance evidence' "$0" \
        || die "self-test: candidate comparator status is not explicit"
    grep -Fq -- '--toolchain-root "$(rustc +1.93.1 --print sysroot)"' "$0" \
        || die "self-test: candidate comparator toolchain is not the exact normative stable"
    grep -Fq 'assurance/fuzzing/run-fuzz-smoke.py"' "$0" \
        || die "self-test: sealed private-corpus fuzz runner is missing"
    grep -Fq 'cargo +nightly-2026-08-08 fetch --locked' "$0" \
        || die "self-test: exact fuzz toolchain provisioning drifted"
    grep -Fq -- '--manifest-path "$PROJECT_ROOT/fuzz/Cargo.toml"' "$0" \
        || die "self-test: exact fuzz dependency provisioning drifted"
    grep -Fq -- '--mode pr --execute' "$0" \
        || die "self-test: complete deterministic fuzz smoke contract drifted"
    local reviewed_seed_bypass='seeds/$'
    reviewed_seed_bypass+='fuzz_target'
    if grep -Fq "$reviewed_seed_bypass" "$0"; then
        die "self-test: release tooling writes directly to reviewed fuzz seeds"
    fi
    # Package G release wiring assertions begin.
    local release_gate_section publish_gate_section workflow_gate_section
    release_gate_section=$(sed -n \
        '/^run_release_acceptance_gate() {$/,/^}$/p' "$0")
    publish_gate_section=$(sed -n \
        '/v4 portable-software release profile/,/require_command cargo/p' \
        "$SCRIPT_DIR/verify-publish-ready.sh" | sed '$d')
    workflow_gate_section=$(sed -n \
        '/Verify v4 release profile and preserved certification foundations/,/  implementation-boundary:/p' \
        "$PROJECT_ROOT/.github/workflows/security-validation.yml")

    assert_ordered_once() {
        local label=$1
        local source=$2
        shift 2
        local needle matches line previous=0
        for needle in "$@"; do
            matches=$(grep -nF -- "$needle" <<<"$source" || true)
            [[ "$(wc -l <<<"$matches")" -eq 1 && -n "$matches" ]] \
                || die "self-test: $label command is absent or ambiguous: $needle"
            line=${matches%%:*}
            ((line > previous)) \
                || die "self-test: $label command order differs at: $needle"
            previous=$line
        done
    }

    assert_ordered_once "release runner v4 profile" "$release_gate_section" \
        'assurance/release-profile/selftest.py' \
        'assurance/release-profile/verify.py" --phase "$phase"' \
        'tools/replay-historical-advisories.py" --check' \
        'tools/generate-release-sboms.py" --self-test' \
        'tools/verify-repeatable-packages.py" --self-test' \
        'tools/run-v4-lab-simulation.py" --self-test' \
        'tools/generate-v4-assurance-report.py" --self-test' \
        'assurance/threat-models/generate-threat-models.py' \
        'assurance/threat-models/verify-threat-models.py" --self-test' \
        'assurance/threat-models/verify-threat-models.py" --mode ci' \
        'assurance/threat-models/verify-threat-models.py" --mode release'
    assert_ordered_once "publish verifier v4 profile" "$publish_gate_section" \
        'assurance/release-profile/selftest.py' \
        'assurance/release-profile/verify.py" --phase "$ASSURANCE_PHASE"' \
        'tools/replay-historical-advisories.py" --check' \
        'tools/generate-release-sboms.py" --self-test' \
        'tools/verify-repeatable-packages.py" --self-test' \
        'tools/run-v4-lab-simulation.py" --self-test' \
        'tools/generate-v4-assurance-report.py" --self-test' \
        'assurance/threat-models/generate-threat-models.py' \
        'assurance/threat-models/verify-threat-models.py" --self-test' \
        'assurance/threat-models/verify-threat-models.py" --mode ci' \
        'assurance/threat-models/verify-threat-models.py" --mode release'
    assert_ordered_once "CI v4 profile" "$workflow_gate_section" \
        'assurance/release-profile/selftest.py' \
        'assurance/release-profile/verify.py --phase foundation' \
        'tools/replay-historical-advisories.py --check' \
        'tools/generate-release-sboms.py --self-test' \
        'tools/verify-repeatable-packages.py --self-test' \
        'tools/run-v4-lab-simulation.py --self-test' \
        'tools/generate-v4-assurance-report.py --self-test' \
        'assurance/threat-models/generate-threat-models.py --check' \
        'assurance/threat-models/verify-threat-models.py --self-test' \
        'assurance/threat-models/verify-threat-models.py --mode ci' \
        'assurance/threat-models/verify-threat-models.py --mode release' \
        'bash tools/release-dcrypt.sh --self-test'
    for source in "$release_gate_section" "$publish_gate_section" "$workflow_gate_section"; do
        if grep -Eq 'continue-on-error:|\|\|[[:space:]]+true|exit[[:space:]]+0|return[[:space:]]+0' \
            <<<"$source"; then
            die "self-test: v4 release-profile wiring contains a soft-success bypass"
        fi
    done
    grep -Fq '[[ "$threat_model_release_rc" -eq 1 ]]' <<<"$release_gate_section" \
        || die "self-test: release runner omitted exact threat-model rc 1"
    grep -Fq 'test "$threat_model_release_rc" -eq 1' <<<"$workflow_gate_section" \
        || die "self-test: CI omitted exact threat-model rc 1"
    grep -Fq 'local -a args=(--version "$version" --assurance-phase prepublish)' "$0" \
        || die "self-test: publish verifier phase is not explicit prepublish"
    local remote_phase_routing_section
    remote_phase_routing_section=$(sed -n \
        '/^run_remote_release_gate() {$/,/^}$/p' "$0")
    [[ "$(grep -Fc 'assurance_phase=prepublish' <<<"$remote_phase_routing_section")" -eq 2 ]] \
        || die "self-test: remote prepublish phase routing differs"
    [[ "$(grep -Fc 'assurance_phase=postpublish' <<<"$remote_phase_routing_section")" -eq 1 ]] \
        || die "self-test: remote complete state is not routed to postpublish"
    local acceptance_line cargo_line release_entry_section
    release_entry_section=$(sed -n '/^cd "$PROJECT_ROOT"$/,$p' "$0")
    acceptance_line=$(grep -nF 'run_release_acceptance_gate prepublish' \
        <<<"$release_entry_section")
    cargo_line=$(grep -nF 'require_command cargo' <<<"$release_entry_section")
    [[ "$(wc -l <<<"$acceptance_line")" -eq 1 ]] \
        || die "self-test: early Package G prepublish gate is absent or ambiguous"
    [[ "$(wc -l <<<"$cargo_line")" -eq 1 ]] \
        || die "self-test: Cargo requirement is absent or ambiguous"
    (( ${acceptance_line%%:*} < ${cargo_line%%:*} )) \
        || die "self-test: Package G HOLD is not checked before Cargo access"
    # Package G release wiring assertions end.

    local exact_stable_selectors
    exact_stable_selectors=$(grep -Ec \
        '^[[:space:]]+toolchain:[[:space:]]+1\.93\.1[[:space:]]*$' \
        "$PROJECT_ROOT/.github/workflows/security-validation.yml" || true)
    [[ "$exact_stable_selectors" -eq 7 ]] \
        || die "self-test: expected exactly seven reviewed stable toolchain selectors"
    if grep -Eq '^[[:space:]]+toolchain:[[:space:]]+stable[[:space:]]*$' \
        "$PROJECT_ROOT/.github/workflows/security-validation.yml"; then
        die "self-test: moving stable toolchain selector is forbidden"
    fi
    grep -Fq 'cargo +nightly-2026-08-07 miri --version' "$0" \
        || die "self-test: exact Miri toolchain selector drifted"
    if grep -Eq 'cargo[[:space:]]+\+nightly[[:space:]]+miri' "$0"; then
        die "self-test: moving nightly Miri selector is forbidden"
    fi
    local forbidden_oracle_claim='excluded independent interoperability'
    forbidden_oracle_claim+=' oracles'
    if grep -Fq "$forbidden_oracle_claim" "$0"; then
        die "self-test: release tooling still claims comparator independence"
    fi
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
        "$SCRIPT_DIR/verify-remote-release-ready.py" --self-test \
        || die "self-test: remote Package G and immutable A_F source audit failed"
    self_test_ambiguous_publish_resolution
    info "release-dcrypt self-test passed"
}

self_test_ambiguous_publish_resolution() {
    local fixture_root
    fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/dcrypt-publish-self-test.XXXXXX")
    local publish_seen="$fixture_root/publish-seen"
    local duplicate_publish="$fixture_root/duplicate-publish"
    local registry_queries=0

    cargo() {
        if [[ "$1" == "publish" && " $* " != *" --dry-run "* ]]; then
            if ! mkdir "$publish_seen" 2>/dev/null; then
                mkdir "$duplicate_publish"
            fi
            printf 'simulated ambiguous cargo publish failure\n' >&2
            return 1
        fi
        return 0
    }
    verify_reviewed_archive() {
        return 0
    }
    crate_version_exists() {
        registry_queries=$((registry_queries + 1))
        ((registry_queries >= 2))
    }
    sleep() {
        return 0
    }

    if ! publish_crate "." "dcrypt-self-test" >/dev/null 2>&1; then
        die "self-test: ambiguous publish was not resolved from registry truth"
    fi
    [[ -d "$publish_seen" ]] \
        || die "self-test: mock publish command was not exercised"
    [[ ! -e "$duplicate_publish" ]] \
        || die "self-test: ambiguous publish was retried before registry resolution"
    [[ "$registry_queries" == 2 ]] \
        || die "self-test: registry was not queried before and after propagation wait"

    rmdir "$publish_seen" "$fixture_root"
}

run_remote_release_gate() {
    local mode=${1:-preflight}
    local expected_prefix=${2:-}
    local assurance_phase
    case "$mode" in
        preflight)
            assurance_phase=prepublish
            if [[ -n "$RESUME_FROM" ]]; then
                :
            fi
            ;;
        verified-prefix)
            assurance_phase=prepublish
            ;;
        complete)
            assurance_phase=postpublish
            ;;
        *)
            die "unknown remote release-gate mode: $mode"
            ;;
    esac
    local -a args=(--version "$VERSION" --assurance-phase "$assurance_phase")
    case "$mode" in
        preflight)
            if [[ -n "$RESUME_FROM" ]]; then
                args+=(--resume "$RESUME_FROM")
            fi
            ;;
        verified-prefix)
            args+=(--resume auto --require-local-archives)
            if [[ -n "$expected_prefix" ]]; then
                args+=(--expected-prefix "$expected_prefix")
            fi
            ;;
        complete)
            args+=(--resume auto --require-local-archives --allow-complete \
                --expected-prefix "${#PUBLISH_ORDER[@]}")
            ;;
    esac
    "$SCRIPT_DIR/verify-remote-release-ready.py" "${args[@]}"
}

verify_registry_progress() {
    local crate_name=$1
    local expected_prefix=$2
    if [[ "$crate_name" == "dcrypt" ]]; then
        run_remote_release_gate complete
    else
        run_remote_release_gate verified-prefix "$expected_prefix"
    fi
}

wait_for_verified_registry() {
    local crate_name=$1
    local expected_prefix=$2
    local elapsed=0
    local log_file
    log_file=$(mktemp "${TMPDIR:-/tmp}/dcrypt-registry-${crate_name}.XXXXXX")
    ACTIVE_LOG=$log_file
    printf "  Waiting for verified %s@%s metadata" "$crate_name" "$VERSION"
    while ((elapsed < REGISTRY_WAIT_SECONDS)); do
        if verify_registry_progress "$crate_name" "$expected_prefix" \
            >"$log_file" 2>&1; then
            printf " ${GREEN}✓${NC}\n"
            cat "$log_file"
            rm -f "$log_file"
            ACTIVE_LOG=""
            return 0
        fi
        printf '.'
        sleep 5
        elapsed=$((elapsed + 5))
    done
    printf " ${RED}✗${NC}\n"
    cat "$log_file" >&2
    rm -f "$log_file"
    ACTIVE_LOG=""
    return 1
}

verify_reviewed_archive() {
    local crate_name=$1
    local report="$PROJECT_ROOT/target/implementation-boundary/report.json"
    local archive="$PROJECT_ROOT/target/package/${crate_name}-${VERSION}.crate"
    local label="${crate_name}@${VERSION}"
    local expected actual

    [[ -f "$archive" ]] || die "cargo package omitted $archive"
    if ! expected=$(jq -er --arg label "$label" \
        '.archive_sha256[$label] | select(type == "string")' "$report"); then
        die "implementation-boundary report omitted $label checksum"
    fi
    actual=$(sha256sum "$archive" | awk '{print $1}')
    [[ "$actual" == "$expected" ]] \
        || die "pre-upload package archive differs from reviewed $label archive"
}

publish_crate() {
    local relative_path=$1
    local crate_name=$2
    local attempt log_file

    for attempt in 1 2 3 4 5; do
        log_file=$(mktemp "${TMPDIR:-/tmp}/dcrypt-publish-${crate_name}.XXXXXX")
        ACTIVE_LOG=$log_file
        info "Packaging $crate_name (attempt $attempt/5)"
        if (cd "$PROJECT_ROOT/$relative_path" && \
            cargo publish --dry-run --locked >"$log_file" 2>&1); then
            if ! (cd "$PROJECT_ROOT/$relative_path" && \
                cargo package --locked --no-verify >>"$log_file" 2>&1); then
                cat "$log_file" >&2
                rm -f "$log_file"
                ACTIVE_LOG=""
                return 1
            fi
            verify_reviewed_archive "$crate_name"
            rm -f "$log_file"
            ACTIVE_LOG=""
        else
            cat "$log_file" >&2
            rm -f "$log_file"
            ACTIVE_LOG=""
            if ((attempt < 5)); then
                warn "package verification failed; waiting for registry propagation"
                sleep 15
                continue
            fi
            return 1
        fi

        log_file=$(mktemp "${TMPDIR:-/tmp}/dcrypt-publish-${crate_name}.XXXXXX")
        ACTIVE_LOG=$log_file
        info "Publishing $crate_name (attempt $attempt/5)"
        if ((attempt > 1)) && crate_version_exists "$crate_name" "$VERSION"; then
            rm -f "$log_file"
            ACTIVE_LOG=""
            warn "$crate_name@$VERSION became visible before the retry; using registry truth"
            return 0
        fi
        if (cd "$PROJECT_ROOT/$relative_path" && \
            cargo publish --locked >"$log_file" 2>&1); then
            cat "$log_file"
            rm -f "$log_file"
            ACTIVE_LOG=""
            return 0
        fi

        cat "$log_file" >&2
        if crate_version_exists "$crate_name" "$VERSION"; then
            rm -f "$log_file"
            ACTIVE_LOG=""
            warn "$crate_name@$VERSION exists after the failed publish command; using registry truth"
            return 0
        fi

        if grep -Eqi \
            'status (401 Unauthorized|403 Forbidden)|authentication failed|invalid (api )?token|token.*(expired|revoked)|not (an )?owner|insufficient permission|permission denied' \
            "$log_file"; then
            rm -f "$log_file"
            ACTIVE_LOG=""
            warn "publication was rejected permanently; refresh the crates.io token or its publish scope before resuming"
            return 2
        fi
        rm -f "$log_file"
        ACTIVE_LOG=""

        if ((attempt < 5)); then
            warn "publish failed and the exact registry record is absent; rechecking after 15 seconds before any retry"
            sleep 15
            if crate_version_exists "$crate_name" "$VERSION"; then
                warn "$crate_name@$VERSION became visible during the propagation wait; using registry truth"
                return 0
            fi
        fi
    done
    return 1
}

validate_manual_resume() {
    if [[ -z "$RESUME_FROM" || "$RESUME_FROM" == "auto" ]]; then
        return 0
    fi
    local entry relative_path crate_name found=false
    for entry in "${PUBLISH_ORDER[@]}"; do
        IFS='|' read -r relative_path crate_name <<<"$entry"
        if [[ "$crate_name" == "$RESUME_FROM" ]]; then
            found=true
            break
        fi
        crate_version_exists "$crate_name" "$VERSION" \
            || die "cannot resume at $RESUME_FROM: $crate_name@$VERSION is missing"
    done
    [[ "$found" == true ]] || die "unknown resume crate: $RESUME_FROM"
}

confirm_live_publish() {
    [[ -t 0 ]] || die "live publication requires an interactive terminal"
    local expected="publish dcrypt $VERSION"
    local response
    printf "\n${YELLOW}crates.io uploads are permanent.${NC}\n"
    printf 'Type %s to continue: ' "$expected"
    read -r response
    [[ "$response" == "$expected" ]] || die "publication confirmation did not match"
}

execute_release() {
    assert_clean_tree
    [[ "$(current_version)" == "$VERSION" ]] \
        || die "workspace is $(current_version), not $VERSION; run --prepare first"
    # Fail quickly before running the long local suite, then repeat immediately
    # before and after the interactive confirmation. The final check closes
    # both the validation-window and user-delay races before the first upload.
    run_remote_release_gate preflight
    local initial_prefix
    initial_prefix=$(target_registry_count)
    check_registry_target
    validate_manual_resume
    run_all_gates
    run_remote_release_gate verified-prefix "$initial_prefix"
    confirm_live_publish
    run_remote_release_gate verified-prefix "$initial_prefix"

    local -a published=()
    local entry relative_path crate_name expected_prefix=0
    for entry in "${PUBLISH_ORDER[@]}"; do
        IFS='|' read -r relative_path crate_name <<<"$entry"
        expected_prefix=$((expected_prefix + 1))
        if ((expected_prefix <= initial_prefix)); then
            crate_version_exists "$crate_name" "$VERSION" \
                || die "verified resume prefix regressed at $crate_name@$VERSION"
            run_remote_release_gate verified-prefix "$initial_prefix"
            printf "${MAGENTA}✓ %s@%s already exists${NC}\n" "$crate_name" "$VERSION"
            published+=("$crate_name")
            save_state "${published[@]}"
            continue
        fi
        if crate_version_exists "$crate_name" "$VERSION"; then
            save_state "${published[@]}"
            die "registry advanced beyond the confirmed prefix at $crate_name; inspect and resume explicitly"
        fi

        if publish_crate "$relative_path" "$crate_name"; then
            if ! wait_for_verified_registry "$crate_name" "$expected_prefix"; then
                save_state "${published[@]}"
                die "crates.io metadata did not verify for $crate_name; resume with --execute --resume auto"
            fi
        else
            local publish_status=$?
            save_state "${published[@]}"
            if [[ $publish_status -eq 2 ]]; then
                die "crates.io authentication or authorization failed for $crate_name; correct credentials, then resume with --execute --resume auto"
            fi
            die "failed to publish $crate_name; resume with --execute --resume auto"
        fi
        published+=("$crate_name")
        save_state "${published[@]}"
    done

    run_remote_release_gate complete

    rm -f "$STATE_FILE"
    printf "\n${GREEN}All dcrypt crates were published at %s.${NC}\n" "$VERSION"
    printf 'Next: create the GitHub release, publish the security advisories, and yank affected versions as approved.\n'
}

dry_run_release() {
    check_registry_target
    run_all_gates
    validate_isolated_workspace_versions "$(current_version)"
    python3 "$SCRIPT_DIR/update-isolated-workspace-versions.py" --self-test
    info "Previewing cargo-release version changes"
    cargo release version "$VERSION"
    printf "\n${GREEN}Release rehearsal completed without publishing or tagging.${NC}\n"
    printf 'Next: finalize CHANGELOG.md and SECURITY.md for v%s, commit the current remediation, then run --prepare.\n' "$VERSION"
}

while (($# > 0)); do
    case "$1" in
        --version)
            [[ $# -ge 2 ]] || die "--version requires a value"
            VERSION=$2
            shift 2
            ;;
        --prepare)
            [[ "$MODE" == "dry-run" ]] || die "choose only one release mode"
            MODE="prepare"
            shift
            ;;
        --execute)
            [[ "$MODE" == "dry-run" ]] || die "choose only one release mode"
            MODE="execute"
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --skip-checks)
            SKIP_CHECKS=true
            shift
            ;;
        --update-benchmarks)
            UPDATE_BENCHMARKS=true
            shift
            ;;
        --resume)
            [[ $# -ge 2 ]] || die "--resume requires a crate name or auto"
            RESUME_FROM=$2
            shift 2
            ;;
        --registry-wait)
            [[ $# -ge 2 ]] || die "--registry-wait requires seconds"
            REGISTRY_WAIT_SECONDS=$2
            shift 2
            ;;
        --reset-state)
            rm -f "$STATE_FILE"
            info "Removed $STATE_FILE"
            exit 0
            ;;
        --self-test)
            SELF_TEST=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

if [[ "$SELF_TEST" == true ]]; then
    [[ -z "$VERSION" && "$MODE" == "dry-run" && \
       "$SKIP_TESTS" == false && "$SKIP_CHECKS" == false && \
       "$UPDATE_BENCHMARKS" == false && -z "$RESUME_FROM" ]] \
        || die "--self-test cannot be combined with release options"
    release_self_test
    exit 0
fi

[[ -n "$VERSION" ]] || { usage >&2; die "--version is required"; }
is_valid_semver "$VERSION" || die "invalid semantic version: $VERSION"
[[ "$REGISTRY_WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] \
    || die "--registry-wait must be a positive integer"
[[ "$MODE" == "execute" || -z "$RESUME_FROM" ]] \
    || die "--resume is valid only with --execute"
[[ "$MODE" == "prepare" || "$UPDATE_BENCHMARKS" == false ]] \
    || die "--update-benchmarks is valid only with --prepare"
if [[ "$MODE" != "dry-run" && ("$SKIP_TESTS" == true || "$SKIP_CHECKS" == true) ]]; then
    die "--skip-tests and --skip-checks are development-rehearsal options; prepare and execute must run every release gate"
fi

cd "$PROJECT_ROOT"
require_command python3
run_release_acceptance_gate prepublish
require_command cargo
require_command git
require_command jq
require_command curl
require_command awk
require_command sha256sum
if [[ "$SKIP_TESTS" == false ]]; then
    require_command bwrap
    require_command strace
fi
load_classified_workspace_records
cargo_subcommand_available release \
    || die "cargo-release is required (cargo install cargo-release --locked)"

printf "${BLUE}dcrypt release %s — %s${NC}\n" "$VERSION" "$MODE"

case "$MODE" in
    dry-run) dry_run_release ;;
    prepare) prepare_release ;;
    execute) execute_release ;;
esac
