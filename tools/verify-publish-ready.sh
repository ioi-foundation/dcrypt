#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
USER_AGENT="dcrypt-release-verifier/2.0 (+https://github.com/ioi-foundation/dcrypt)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

EXPECTED_VERSION=""
REQUIRE_UNPUBLISHED=false
CHECK_AUTH=true
ERRORS=0
WARNINGS=0

PUBLISH_ORDER=(
    "dcrypt-internal"
    "dcrypt-params"
    "dcrypt-api"
    "dcrypt-common"
    "dcrypt-algorithms"
    "dcrypt-symmetric"
    "dcrypt-kem"
    "dcrypt-sign"
    "dcrypt-pke"
    "dcrypt-utils"
    "dcrypt-hybrid"
    "dcrypt"
)

usage() {
    cat <<'EOF'
Usage: tools/verify-publish-ready.sh [OPTIONS]

Options:
  --version VERSION       Require every workspace package and exact internal
                          dependency to use VERSION. Defaults to the workspace
                          version reported by Cargo.
  --require-unpublished   Fail if VERSION already exists for any publishable
                          crate on crates.io.
  --skip-auth-check       Do not check whether Cargo credentials are configured.
  -h, --help              Show this help.
EOF
}

fail() {
    printf "${RED}  ✗ %s${NC}\n" "$*"
    ERRORS=$((ERRORS + 1))
}

pass() {
    printf "${GREEN}  ✓ %s${NC}\n" "$*"
}

warn() {
    printf "${YELLOW}  ⚠ %s${NC}\n" "$*"
    WARNINGS=$((WARNINGS + 1))
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "required command is unavailable: $1"
        return 1
    fi
}

is_valid_semver() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]
}

crate_version_exists() {
    local crate_name=$1
    local version=$2
    local response

    if ! response=$(curl --fail --silent --show-error --location \
        --user-agent "$USER_AGENT" \
        "https://crates.io/api/v1/crates/$crate_name"); then
        return 2
    fi

    jq -e --arg version "$version" \
        '.versions | any(.num == $version)' <<<"$response" >/dev/null
}

while (($# > 0)); do
    case "$1" in
        --version)
            [[ $# -ge 2 ]] || { echo "--version requires a value" >&2; exit 2; }
            EXPECTED_VERSION=$2
            shift 2
            ;;
        --require-unpublished)
            REQUIRE_UNPUBLISHED=true
            shift
            ;;
        --skip-auth-check)
            CHECK_AUTH=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

cd "$PROJECT_ROOT"

printf "${BLUE}=== Verifying dcrypt publish readiness ===${NC}\n"

require_command cargo || true
require_command jq || true
require_command curl || true
require_command git || true
require_command python3 || true
require_command rustdoc || true
require_command rustup || true
if ((ERRORS > 0)); then
    exit 1
fi

printf "\n${BLUE}Atomic public API assurance ledger${NC}\n"
if cargo fetch --locked; then
    pass "exact locked dependency closure fetched for offline assurance replay"
else
    fail "failed to fetch the exact locked dependency closure"
    exit 1
fi
release_assurance_failed=false
if python3 -B "$PROJECT_ROOT/assurance/verify-assurance-ledger.py" --mode release; then
    pass "assurance ledger and live public API inventory passed"
else
    fail "assurance ledger or live public API inventory failed"
    release_assurance_failed=true
fi

printf "\n${BLUE}Package B interoperability completeness and protocol controls${NC}\n"
if python3 -B "$PROJECT_ROOT/assurance/interoperability/generate-interoperability-matrix.py" --check \
    && python3 -B "$PROJECT_ROOT/assurance/interoperability/verify-interoperability.py" --mode ci \
    && python3 -B "$PROJECT_ROOT/assurance/interoperability/interoperability-selftest.py" \
    && python3 -B "$PROJECT_ROOT/assurance/interoperability/protocol-specs/verify-protocol-specs.py" \
        --require-final-subject --check-current-subject \
    && python3 -B "$PROJECT_ROOT/assurance/interoperability/protocol-specs/protocol-specs-selftest.py" \
    && python3 -B "$PROJECT_ROOT/verification/clean-room-protocol-reference/verify-scaffold.py" \
    && python3 -B "$PROJECT_ROOT/verification/clean-room-protocol-reference/scaffold-selftest.py"; then
    pass "Package B structural controls reproduced without promoting candidate evidence"
else
    fail "Package B structural interoperability controls failed"
    release_assurance_failed=true
fi
if python3 -B "$PROJECT_ROOT/assurance/interoperability/verify-interoperability.py" --mode release; then
    pass "interoperability release completeness passed"
else
    fail "interoperability completeness remains release-blocking"
    release_assurance_failed=true
fi
if [[ "$release_assurance_failed" == true ]]; then
    exit 1
fi

printf "\n${BLUE}Zero-unsafe and zero-FFI implementation boundary${NC}\n"
if "$SCRIPT_DIR/verify-implementation-boundary.sh"; then
    pass "implementation boundary passed"
else
    fail "implementation boundary failed"
    exit 1
fi

printf "\n${BLUE}Optimized BLS secret-scalar compiler inspection${NC}\n"
if "$SCRIPT_DIR/verify-bls-secret-assembly.sh"; then
    pass "BLS G1/G2 secret-scalar assembly shape passed on every supported target"
else
    fail "BLS secret-scalar assembly inspection failed"
    exit 1
fi

printf "\n${BLUE}Optimized owned GHASH compiler inspection${NC}\n"
if "$SCRIPT_DIR/verify-ghash-assembly.sh"; then
    pass "GHASH multiplication assembly shape passed on every supported target"
else
    fail "GHASH multiplication assembly inspection failed"
    exit 1
fi

metadata_file=$(mktemp "${TMPDIR:-/tmp}/dcrypt-metadata.XXXXXX")
trap 'rm -f "$metadata_file"' EXIT

if ! cargo metadata --no-deps --format-version 1 >"$metadata_file"; then
    fail "cargo metadata failed"
    exit 1
fi

workspace_version=$(jq -r \
    '.packages[] | select(.name == "dcrypt") | .version' \
    "$metadata_file")

if [[ -z "$EXPECTED_VERSION" ]]; then
    EXPECTED_VERSION=$workspace_version
fi

if ! is_valid_semver "$EXPECTED_VERSION"; then
    fail "invalid semantic version: $EXPECTED_VERSION"
fi

if [[ "$workspace_version" == "$EXPECTED_VERSION" ]]; then
    pass "workspace version is $EXPECTED_VERSION"
else
    fail "workspace version is $workspace_version, expected $EXPECTED_VERSION"
fi

printf "\n${BLUE}Package metadata and dependency checks${NC}\n"

for crate_name in "${PUBLISH_ORDER[@]}"; do
    package_count=$(jq -r --arg name "$crate_name" \
        '[.packages[] | select(.name == $name)] | length' "$metadata_file")
    if [[ "$package_count" != "1" ]]; then
        fail "$crate_name appears $package_count times in cargo metadata"
        continue
    fi

    package_version=$(jq -r --arg name "$crate_name" \
        '.packages[] | select(.name == $name) | .version' "$metadata_file")
    publish_setting=$(jq -c --arg name "$crate_name" \
        '.packages[] | select(.name == $name) | .publish' "$metadata_file")

    if [[ "$package_version" != "$EXPECTED_VERSION" ]]; then
        fail "$crate_name has version $package_version"
    elif [[ "$publish_setting" == "[]" ]]; then
        fail "$crate_name has package.publish = false"
    else
        pass "$crate_name@$package_version is publishable"
    fi

    for field in description repository readme; do
        value=$(jq -r --arg name "$crate_name" --arg field "$field" \
            '.packages[] | select(.name == $name) | .[$field] // ""' \
            "$metadata_file")
        if [[ -z "$value" ]]; then
            fail "$crate_name is missing package.$field"
        fi
    done

    license=$(jq -r --arg name "$crate_name" \
        '.packages[] | select(.name == $name) | .license // .license_file // ""' \
        "$metadata_file")
    if [[ -z "$license" ]]; then
        fail "$crate_name is missing package.license or package.license-file"
    fi

    while IFS=$'\t' read -r dependency requirement; do
        [[ -n "$dependency" ]] || continue
        if [[ "$requirement" != "=$EXPECTED_VERSION" ]]; then
            fail "$crate_name dependency $dependency uses $requirement; expected =$EXPECTED_VERSION"
        fi
    done < <(jq -r --arg name "$crate_name" '
        .packages[]
        | select(.name == $name)
        | .dependencies[]
        | select(.name == "dcrypt" or (.name | startswith("dcrypt-")))
        | [.name, .req] | @tsv
    ' "$metadata_file")
done

tests_publish=$(jq -c '.packages[] | select(.name == "dcrypt-tests") | .publish' "$metadata_file")
if [[ "$tests_publish" == "[]" ]]; then
    pass "dcrypt-tests is explicitly excluded from publication"
else
    fail "dcrypt-tests must set package.publish = false"
fi

tests_version=$(jq -r '.packages[] | select(.name == "dcrypt-tests") | .version' "$metadata_file")
if [[ "$tests_version" == "$EXPECTED_VERSION" ]]; then
    pass "dcrypt-tests shares workspace version $EXPECTED_VERSION"
else
    fail "dcrypt-tests has version $tests_version, expected $EXPECTED_VERSION"
fi

while IFS=$'\t' read -r dependency requirement; do
    [[ -n "$dependency" ]] || continue
    if [[ "$requirement" != "=$EXPECTED_VERSION" ]]; then
        fail "dcrypt-tests dependency $dependency uses $requirement; expected =$EXPECTED_VERSION"
    fi
done < <(jq -r '
    .packages[]
    | select(.name == "dcrypt-tests")
    | .dependencies[]
    | select(.name == "dcrypt" or (.name | startswith("dcrypt-")))
    | [.name, .req] | @tsv
' "$metadata_file")

if cargo release --version >/dev/null 2>&1; then
    pass "cargo-release is available"
else
    fail "cargo-release is unavailable (install with: cargo install cargo-release --locked)"
fi

if [[ "$CHECK_AUTH" == true ]]; then
    cargo_config_dir=${CARGO_HOME:-${HOME}/.cargo}
    if [[ -n "${CARGO_REGISTRY_TOKEN:-}" ]] || \
        { [[ -f "$cargo_config_dir/credentials.toml" ]] && \
          grep -Eq '^[[:space:]]*token[[:space:]]*=' "$cargo_config_dir/credentials.toml"; }; then
        pass "Cargo registry credentials are configured (authorization not exercised)"
    else
        fail "no crates.io credential configuration was found"
    fi
fi

if [[ "$REQUIRE_UNPUBLISHED" == true ]]; then
    printf "\n${BLUE}crates.io target-version checks${NC}\n"
    for crate_name in "${PUBLISH_ORDER[@]}"; do
        if crate_version_exists "$crate_name" "$EXPECTED_VERSION"; then
            fail "$crate_name@$EXPECTED_VERSION already exists on crates.io"
        else
            status=$?
            if [[ $status -eq 1 ]]; then
                pass "$crate_name@$EXPECTED_VERSION is available"
            else
                fail "could not query crates.io for $crate_name"
            fi
        fi
    done
fi

printf "\n${BLUE}Summary${NC}\n"
if ((ERRORS > 0)); then
    printf "${RED}%d error(s), %d warning(s); not ready to publish.${NC}\n" \
        "$ERRORS" "$WARNINGS"
    exit 1
fi

printf "${GREEN}Publish-readiness checks passed with %d warning(s).${NC}\n" "$WARNINGS"
