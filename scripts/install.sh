#!/bin/sh
# forgeseal installer
# Usage: curl -sSL https://raw.githubusercontent.com/sns45/forgeseal/main/scripts/install.sh | sh
# Version pinning: FORGESEAL_VERSION=0.1.0 curl -sSL ... | sh

set -eu

REPO="sns45/forgeseal"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux)  echo "linux" ;;
        Darwin) echo "darwin" ;;
        *)
            printf "Error: unsupported OS '%s'\n" "$(uname -s)" >&2
            exit 1
            ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *)
            printf "Error: unsupported architecture '%s'\n" "$(uname -m)" >&2
            exit 1
            ;;
    esac
}

# Get latest version from GitHub API
get_latest_version() {
    if [ -n "${FORGESEAL_VERSION:-}" ]; then
        echo "${FORGESEAL_VERSION}"
        return
    fi

    version=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed -E 's/.*"tag_name": *"v?([^"]+)".*/\1/')

    if [ -z "$version" ]; then
        printf "Error: could not determine latest version\n" >&2
        exit 1
    fi

    echo "$version"
}

# Verify checksum
verify_checksum() {
    archive="$1"
    checksums="$2"

    expected=$(grep "$(basename "$archive")" "$checksums" | awk '{print $1}')
    if [ -z "$expected" ]; then
        printf "Error: no checksum found for %s\n" "$(basename "$archive")" >&2
        exit 1
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$archive" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$archive" | awk '{print $1}')
    else
        printf "Error: no sha256sum or shasum found\n" >&2
        exit 1
    fi

    if [ "$expected" != "$actual" ]; then
        printf "Error: checksum mismatch\n  expected: %s\n  actual:   %s\n" "$expected" "$actual" >&2
        exit 1
    fi
}

main() {
    os=$(detect_os)
    arch=$(detect_arch)
    version=$(get_latest_version)

    printf "Installing forgeseal v%s (%s/%s)\n" "$version" "$os" "$arch"

    archive="forgeseal_${version}_${os}_${arch}.tar.gz"
    base_url="https://github.com/${REPO}/releases/download/v${version}"

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    printf "Downloading %s...\n" "$archive"
    curl -sSL -o "${tmpdir}/${archive}" "${base_url}/${archive}"
    curl -sSL -o "${tmpdir}/checksums.txt" "${base_url}/checksums.txt"

    printf "Verifying checksum...\n"
    verify_checksum "${tmpdir}/${archive}" "${tmpdir}/checksums.txt"

    printf "Extracting...\n"
    tar -xzf "${tmpdir}/${archive}" -C "${tmpdir}"

    printf "Installing to %s...\n" "$INSTALL_DIR"
    if [ -w "$INSTALL_DIR" ]; then
        cp "${tmpdir}/forgeseal" "${INSTALL_DIR}/forgeseal"
        chmod +x "${INSTALL_DIR}/forgeseal"
    else
        sudo cp "${tmpdir}/forgeseal" "${INSTALL_DIR}/forgeseal"
        sudo chmod +x "${INSTALL_DIR}/forgeseal"
    fi

    printf "forgeseal v%s installed successfully\n" "$version"
    "${INSTALL_DIR}/forgeseal" version
}

main
