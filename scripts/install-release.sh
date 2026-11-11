#!/usr/bin/env bash
#
# Install a vault release binary after checking its SHA256 and its GitHub build
# provenance attestation. Nothing is installed unless both checks pass.
#
# Usage: scripts/install-release.sh <tag> <target> <dest-dir>
#   tag       release tag, e.g. v1.2.3
#   target    macos-arm64 | linux-x64 | linux-arm64
#   dest-dir  directory to install `vault` into (created if missing)
#
# Needs the GitHub CLI (`gh`) 2.68.0 or newer, signed in, plus shasum (macOS) or sha256sum (Linux).
#
set -euo pipefail

REPO="alecramos-sudo/vault"
WORKFLOW="$REPO/.github/workflows/release.yml"

die() {
	echo "install-release: $*" >&2
	exit 1
}

usage() {
	echo "usage: $0 <tag> <target> <dest-dir>" >&2
	echo "targets: macos-arm64 linux-x64 linux-arm64" >&2
	exit 2
}

[[ $# -eq 3 ]] || usage
tag="$1"
target="$2"
dest="$3"

case "$target" in
macos-arm64 | linux-x64 | linux-arm64) ;;
*)
	echo "install-release: unknown target '$target'" >&2
	usage
	;;
esac
[[ -n "$tag" && -n "$dest" ]] || usage

command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is required"
# gh attestation verify --source-ref needs gh 2.68.0 or newer.
gh_version="$(gh --version | awk 'NR==1 {print $3}')"
IFS=. read -r gh_major gh_minor _ <<<"$gh_version"
if [[ ! "$gh_major" =~ ^[0-9]+$ || ! "$gh_minor" =~ ^[0-9]+$ ]] || ((gh_major < 2 || (gh_major == 2 && gh_minor < 68))); then
	die "gh $gh_version is too old; attestation checks need gh 2.68.0 or newer"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
	sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
	command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
	sha256() { sha256sum "$1" | awk '{print $1}'; }
fi

asset="vault-$target"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/vault-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

echo "==> Downloading $asset and SHA256SUMS from $REPO $tag"
gh release download "$tag" --repo "$REPO" --dir "$tmp" \
	--pattern "$asset" --pattern SHA256SUMS ||
	die "download failed"
[[ -f "$tmp/$asset" ]] || die "release $tag has no asset $asset"
[[ -f "$tmp/SHA256SUMS" ]] || die "release $tag has no SHA256SUMS"

echo "==> Verifying checksum"
# Exactly one line must name the asset ("<hash>  <name>" or "<hash> *<name>").
expected="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")"
[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || die "SHA256SUMS has no single valid entry for $asset"
actual="$(sha256 "$tmp/$asset")"
expected="$(tr '[:upper:]' '[:lower:]' <<<"$expected")"
actual="$(tr '[:upper:]' '[:lower:]' <<<"$actual")"
[[ "$actual" == "$expected" ]] || die "checksum mismatch for $asset: expected $expected, got $actual"
echo "    sha256 $actual OK"

echo "==> Verifying build provenance attestation"
# Must be signed by this repo's release workflow, on a GitHub-hosted runner, for this tag.
gh attestation verify "$tmp/$asset" --repo "$REPO" \
	--signer-workflow "$WORKFLOW" \
	--source-ref "refs/tags/$tag" \
	--deny-self-hosted-runners ||
	die "attestation verification failed for $asset"

echo "==> Installing to $dest/vault"
mkdir -p "$dest"
# Copy beside the target, then rename, so a failed copy never leaves a partial binary.
staged="$dest/.vault.install.$$"
install -m 755 "$tmp/$asset" "$staged" || {
	rm -f "$staged"
	die "could not write to $dest"
}
mv -f "$staged" "$dest/vault"
echo "Installed $dest/vault ($tag, $target)"
