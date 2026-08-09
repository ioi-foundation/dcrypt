#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
STATE_FILE="$PROJECT_ROOT/.release-state.json"
USER_AGENT="dcrypt-release-tool/2.0 (+https://github.com/ioi-foundation/dcrypt)"

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
  --prepare            From a clean tree, apply the version bump, create the
                       release commit if cargo-release did not, and create the
                       local annotated tag. Does not push or publish.
  --execute            Publish the already prepared release to crates.io. The
                       exact tagged commit must already be present on origin.

Options:
  --update-benchmarks  Refresh BENCHMARKS.md during --prepare. This must leave
                       a clean tree before versioning continues.
  --skip-tests         Skip workspace, ACVP, and isolated timing tests.
  --skip-checks        Skip format/check, audit/deny, Miri, and fuzz builds.
  --resume CRATE       Resume a partial --execute at CRATE, or use "auto" to
                       trust crates.io as the source of truth.
  --registry-wait SEC  Maximum registry propagation wait per crate (default 300).
  --reset-state        Remove only .release-state.json and exit.
  -h, --help           Show this help.

Safe workflow:
  tools/release-dcrypt.sh --version 2.0.0
  tools/release-dcrypt.sh --version 2.0.0 --prepare
  git push origin <current-branch>
  git push origin v2.0.0
  tools/release-dcrypt.sh --version 2.0.0 --execute
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

run_publish_verifier() {
    local version=$1
    local -a args=(--version "$version")
    if [[ "$MODE" == "prepare" ]]; then
        args+=(--require-unpublished)
    fi
    "$SCRIPT_DIR/verify-publish-ready.sh" "${args[@]}"
}

run_test_gates() {
    if [[ "$SKIP_TESTS" == true ]]; then
        warn "test gates were explicitly skipped"
        return
    fi

    info "Running workspace tests"
    cargo test --workspace --all-features --exclude dcrypt-tests --no-fail-fast

    info "Running exact ML-DSA ACVP gates"
    cargo test -p dcrypt-tests --test acvp_tests ml_dsa_ -- --nocapture

    info "Running isolated statistical timing regressions"
    cargo test -p dcrypt-tests --test constant_time_tests -- \
        --test-threads=1 --nocapture
}

require_security_subcommand() {
    local subcommand=$1
    local install_hint=$2
    if cargo_subcommand_available "$subcommand"; then
        return 0
    fi

    if [[ "$MODE" == "dry-run" ]]; then
        warn "cargo-$subcommand is unavailable; install with: $install_hint"
        return 1
    fi
    die "cargo-$subcommand is required; install with: $install_hint"
}

run_check_gates() {
    if [[ "$SKIP_CHECKS" == true ]]; then
        warn "format, static, supply-chain, Miri, and fuzz gates were explicitly skipped"
        return
    fi

    info "Running formatting and all-target/all-feature checks"
    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features

    if require_security_subcommand audit "cargo install cargo-audit --locked"; then
        cargo audit
    fi

    if require_security_subcommand deny "cargo install cargo-deny --locked"; then
        cargo deny --workspace --all-features check
    fi

    if cargo +nightly miri --version >/dev/null 2>&1; then
        info "Running Miri on public error and secret-memory APIs"
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly miri test -p dcrypt-api --lib --all-features
        CARGO_TARGET_DIR="$PROJECT_ROOT/target/miri-release" \
            cargo +nightly miri test -p dcrypt-common --lib --all-features
    elif [[ "$MODE" == "dry-run" ]]; then
        warn "nightly Miri is unavailable"
    else
        die "nightly Miri is required (rustup +nightly component add miri)"
    fi

    if cargo_subcommand_available fuzz; then
        info "Building every cargo-fuzz target"
        while IFS= read -r fuzz_target; do
            [[ -n "$fuzz_target" ]] || continue
            cargo fuzz build "$fuzz_target"
        done < <(cargo fuzz list)
    elif [[ "$MODE" == "dry-run" ]]; then
        warn "cargo-fuzz is unavailable"
    else
        die "cargo-fuzz is required (cargo install cargo-fuzz --locked)"
    fi
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

run_all_gates() {
    local version
    version=$(current_version)
    run_publish_verifier "$version"
    run_check_gates
    run_test_gates
    check_package_contents
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
                unexpected+="  $path"$'\n'
                ;;
        esac
    done < <(git status --porcelain --untracked-files=all)

    if [[ -n "$unexpected" ]]; then
        printf '%s' "$unexpected" >&2
        die "versioning changed unexpected files; review without committing automatically"
    fi

    if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
        git add Cargo.toml crates/*/Cargo.toml tests/Cargo.toml
        git commit -m "chore: release version $VERSION"
    fi
}

prepare_release() {
    assert_clean_tree
    validate_release_documentation
    check_registry_target
    update_benchmarks
    run_all_gates

    local before_version
    before_version=$(current_version)
    if [[ "$before_version" != "$VERSION" ]]; then
        info "Updating workspace from $before_version to $VERSION"
        cargo release version "$VERSION" --execute --no-confirm
        create_release_commit_if_needed
    else
        info "Workspace is already versioned as $VERSION"
    fi

    [[ "$(current_version)" == "$VERSION" ]] || die "version update did not produce $VERSION"
    assert_clean_tree
    run_publish_verifier "$VERSION"
    check_package_contents

    local tag="v$VERSION"
    if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
        [[ "$(git rev-list -n 1 "$tag")" == "$(git rev-parse HEAD)" ]] \
            || die "$tag already exists but does not point to HEAD"
        info "Local tag $tag already points to HEAD"
    else
        git tag -a "$tag" -m "Release version $VERSION"
        info "Created local annotated tag $tag"
    fi

    local branch
    branch=$(current_branch)
    [[ -n "$branch" ]] || die "cannot prepare a release from detached HEAD"

    printf "\n${GREEN}Release preparation complete; nothing was published.${NC}\n"
    printf 'Review the commit and tag, then run:\n'
    printf '  git push origin %q\n' "$branch"
    printf '  git push origin %q\n' "$tag"
    printf '  tools/release-dcrypt.sh --version %q --execute\n' "$VERSION"
}

assert_tag_is_pushed() {
    local tag="v$VERSION"
    local head_commit local_tag_commit remote_tag_commit remote_direct

    head_commit=$(git rev-parse HEAD)
    git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null \
        || die "local tag $tag does not exist; run --prepare first"
    local_tag_commit=$(git rev-list -n 1 "$tag")
    [[ "$local_tag_commit" == "$head_commit" ]] \
        || die "$tag does not point to the checked-out commit"

    remote_tag_commit=$(git ls-remote --tags origin "refs/tags/$tag^{}" | awk 'NR == 1 {print $1}')
    if [[ -z "$remote_tag_commit" ]]; then
        remote_direct=$(git ls-remote --tags origin "refs/tags/$tag" | awk 'NR == 1 {print $1}')
        remote_tag_commit=$remote_direct
    fi
    [[ -n "$remote_tag_commit" ]] || die "$tag has not been pushed to origin"
    [[ "$remote_tag_commit" == "$head_commit" ]] \
        || die "origin's $tag does not resolve to the checked-out commit"

    local branch
    branch=$(current_branch)
    [[ -n "$branch" ]] || die "cannot publish from detached HEAD"
    git fetch --quiet origin "$branch"
    git merge-base --is-ancestor "$head_commit" "origin/$branch" \
        || die "the release commit is not present on origin/$branch"
}

wait_for_registry() {
    local crate_name=$1
    local elapsed=0
    printf "  Waiting for %s@%s in crates.io" "$crate_name" "$VERSION"
    while ((elapsed < REGISTRY_WAIT_SECONDS)); do
        if crate_version_exists "$crate_name" "$VERSION"; then
            printf " ${GREEN}✓${NC}\n"
            return 0
        fi
        printf '.'
        sleep 3
        elapsed=$((elapsed + 3))
    done
    printf " ${RED}✗${NC}\n"
    return 1
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
        if (cd "$PROJECT_ROOT/$relative_path" && \
            cargo publish --locked >"$log_file" 2>&1); then
            cat "$log_file"
            rm -f "$log_file"
            ACTIVE_LOG=""
            wait_for_registry "$crate_name"
            return $?
        fi

        cat "$log_file" >&2
        if grep -qi "already uploaded" "$log_file" && \
            crate_version_exists "$crate_name" "$VERSION"; then
            rm -f "$log_file"
            ACTIVE_LOG=""
            return 0
        fi
        rm -f "$log_file"
        ACTIVE_LOG=""

        if ((attempt < 5)); then
            warn "publish failed; retrying after 15 seconds"
            sleep 15
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
    printf 'Type %q to continue: ' "$expected"
    read -r response
    [[ "$response" == "$expected" ]] || die "publication confirmation did not match"
}

execute_release() {
    assert_clean_tree
    [[ "$(current_version)" == "$VERSION" ]] \
        || die "workspace is $(current_version), not $VERSION; run --prepare first"
    assert_tag_is_pushed
    check_registry_target
    validate_manual_resume
    run_all_gates
    confirm_live_publish

    local -a published=()
    local entry relative_path crate_name
    for entry in "${PUBLISH_ORDER[@]}"; do
        IFS='|' read -r relative_path crate_name <<<"$entry"
        if crate_version_exists "$crate_name" "$VERSION"; then
            printf "${MAGENTA}✓ %s@%s already exists${NC}\n" "$crate_name" "$VERSION"
            published+=("$crate_name")
            save_state "${published[@]}"
            continue
        fi

        if ! publish_crate "$relative_path" "$crate_name"; then
            save_state "${published[@]}"
            die "failed to publish $crate_name; resume with --execute --resume auto"
        fi
        published+=("$crate_name")
        save_state "${published[@]}"
    done

    rm -f "$STATE_FILE"
    printf "\n${GREEN}All dcrypt crates were published at %s.${NC}\n" "$VERSION"
    printf 'Next: create the GitHub release, publish the security advisories, and yank affected versions as approved.\n'
}

dry_run_release() {
    check_registry_target
    run_all_gates
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
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

[[ -n "$VERSION" ]] || { usage >&2; die "--version is required"; }
is_valid_semver "$VERSION" || die "invalid semantic version: $VERSION"
[[ "$REGISTRY_WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] \
    || die "--registry-wait must be a positive integer"
[[ "$MODE" == "execute" || -z "$RESUME_FROM" ]] \
    || die "--resume is valid only with --execute"
[[ "$MODE" == "prepare" || "$UPDATE_BENCHMARKS" == false ]] \
    || die "--update-benchmarks is valid only with --prepare"

cd "$PROJECT_ROOT"
require_command cargo
require_command git
require_command jq
require_command curl
cargo_subcommand_available release \
    || die "cargo-release is required (cargo install cargo-release --locked)"

printf "${BLUE}dcrypt release %s — %s${NC}\n" "$VERSION" "$MODE"

case "$MODE" in
    dry-run) dry_run_release ;;
    prepare) prepare_release ;;
    execute) execute_release ;;
esac
