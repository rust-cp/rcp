#!/usr/bin/env bash
# Install a CI tool from its own publisher's GitHub release, verified against a pinned sha256.
#
#   scripts/install-ci-tool.sh TOOL [DEST]     (DEST defaults to ~/.cargo/bin)
#
# Each tool comes from the project that builds it, not from an installer action in between.
# Renovate proposes version updates. Before accepting one, independently verify the new
# archive against the publisher's release and update the checksum. A version bump without
# the matching checksum deliberately fails here.
set -euo pipefail

tool=${1:?usage: install-ci-tool.sh TOOL [DEST]}
dest=${2:-$HOME/.cargo/bin}

case "$tool" in
  syft)
    # renovate: datasource=github-releases depName=anchore/syft
    version=v1.52.0
    url=https://github.com/anchore/syft/releases/download/$version/syft_${version#v}_linux_amd64.tar.gz
    sha=caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d ;;
  grype)
    # renovate: datasource=github-releases depName=anchore/grype
    version=v0.119.0
    url=https://github.com/anchore/grype/releases/download/$version/grype_${version#v}_linux_amd64.tar.gz
    sha=3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b ;;
  cargo-deny)
    # renovate: datasource=github-releases depName=EmbarkStudios/cargo-deny
    version=0.20.2
    url=https://github.com/EmbarkStudios/cargo-deny/releases/download/$version/cargo-deny-$version-x86_64-unknown-linux-musl.tar.gz
    sha=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f ;;
  cargo-hack)
    # renovate: datasource=github-releases depName=taiki-e/cargo-hack
    version=v0.6.45
    url=https://github.com/taiki-e/cargo-hack/releases/download/$version/cargo-hack-x86_64-unknown-linux-musl.tar.gz
    sha=b242dffcfd43317ac484dd2dbc3b9fc5f8a7eb3ba252af31b531503f0bad33d1 ;;
  mdbook)
    # renovate: datasource=github-releases depName=rust-lang/mdBook
    version=v0.5.4
    url=https://github.com/rust-lang/mdBook/releases/download/$version/mdbook-$version-x86_64-unknown-linux-musl.tar.gz
    sha=5222beabd3e37dc5be0d18ff99b79058469354db5c220153a1b92db5ba12be89 ;;
  zizmor)
    # renovate: datasource=github-releases depName=zizmorcore/zizmor
    version=v1.30.1
    url=https://github.com/zizmorcore/zizmor/releases/download/$version/zizmor-x86_64-unknown-linux-gnu.tar.gz
    sha=e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a ;;
  actionlint)
    # renovate: datasource=github-releases depName=rhysd/actionlint
    version=v1.7.12
    url=https://github.com/rhysd/actionlint/releases/download/$version/actionlint_${version#v}_linux_amd64.tar.gz
    sha=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 ;;
  gitleaks)
    # renovate: datasource=github-releases depName=gitleaks/gitleaks
    version=v8.30.1
    url=https://github.com/gitleaks/gitleaks/releases/download/$version/gitleaks_${version#v}_linux_x64.tar.gz
    sha=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
  shellcheck)
    # renovate: datasource=github-releases depName=koalaman/shellcheck
    version=v0.11.0
    url=https://github.com/koalaman/shellcheck/releases/download/$version/shellcheck-$version.linux.x86_64.tar.gz
    sha=b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6 ;;
  *) echo "unknown tool: $tool" >&2; exit 2 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl --proto '=https' --tlsv1.2 -sSfL -o "$work/archive.tar.gz" "$url"
echo "$sha  $work/archive.tar.gz" | sha256sum --check --quiet
tar -xzf "$work/archive.tar.gz" -C "$work"
mkdir -p "$dest"
find "$work" -type f -name "$tool" -perm -u+x -exec install -m 0755 {} "$dest/$tool" \;
# Cargo subcommands are invoked with their subcommand name first, as cargo would.
case "$tool" in
  cargo-*) "$dest/$tool" "${tool#cargo-}" --version ;;
  *) "$dest/$tool" --version ;;
esac
