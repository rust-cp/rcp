#!/usr/bin/env bash
# Publish the rcp binary as an OCI artifact with oras, carrying its provenance as annotations.
#
#   scripts/publish.sh [REGISTRY/REPO] [TAG]
#     default target: ghcr.io/<owner-from-git-remote>/rcp-binary, tag = crate version
#   env: RCP_BIN (an existing binary), RCP_BUILD_TARGET/RCP_BUILD_RUSTC (optional provenance),
#        ORAS_USERNAME/ORAS_PASSWORD or a prior `oras login`,
#        PUBLISH_PLAIN_HTTP=1 for a local rehearsal registry.
#
# What is pushed: one layer, the supplied or locally built binary, media type
# application/vnd.rust-cp.rcp.binary.v1+octet-stream, plus SHA256SUMS as a second layer.
# The manifest annotations record the source repository, the exact commit, whether the tree
# was dirty, the rustc that built it, the sha256 of the binary and the build time, so the
# artifact digest can be traced back to source without trusting the tag name. In CI the
# workflow additionally attaches a SLSA provenance attestation to the pushed digest.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$HERE"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
OWNER=$(git config --get remote.origin.url | sed -E 's#.*[:/]([^/]+)/[^/]+(\.git)?$#\1#')
TARGET=${1:-ghcr.io/${OWNER}/rcp-binary}
TAG=${2:-$VERSION}
command -v oras >/dev/null || { echo "oras is not installed (https://oras.land)" >&2; exit 2; }

CUSTOM_BINARY=${RCP_BIN:+true}
RCP_BIN=${RCP_BIN:-target/release/rcp}
BUILD_TARGET=${RCP_BUILD_TARGET:-unknown}
BUILD_RUSTC=${RCP_BUILD_RUSTC:-unknown}
BUILT_HERE=false
if [ ! -x "$RCP_BIN" ]; then
  if [ -n "$CUSTOM_BINARY" ]; then
    echo "RCP_BIN is not executable: $RCP_BIN" >&2
    exit 2
  fi
  echo "building a static release binary"
  BUILD_TARGET=$(rustc -vV | sed -n 's/^host: //p')
  BUILD_RUSTC=$(rustc --version)
  # An explicit target prevents Cargo configuration from silently selecting another target.
  RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --offline --target "$BUILD_TARGET"
  RCP_BIN="${CARGO_TARGET_DIR:-target}/$BUILD_TARGET/release/rcp"
  BUILT_HERE=true
fi
FILE_DESCRIPTION=$(LC_ALL=C file -b -- "$RCP_BIN")
LINKAGE=unknown
case "$FILE_DESCRIPTION" in
  *"statically linked"*|*"static-pie linked"*) LINKAGE=static ;;
  *"dynamically linked"*) LINKAGE=dynamic ;;
esac

STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT
cp "$RCP_BIN" "$STAGE/rcp"
( cd "$STAGE" && sha256sum rcp > SHA256SUMS )
SHA=$(cut -d' ' -f1 "$STAGE/SHA256SUMS")
COMMIT=$(git rev-parse HEAD)
DIRTY=$(git status --porcelain -- . | grep -q . && echo true || echo false)
SOURCE=$(git config --get remote.origin.url | sed -E 's#^git@github.com:#https://github.com/#; s#\.git$##')
BUILD_REVISION=${RCP_BUILD_REVISION:-unknown}
BUILD_SOURCE=${RCP_BUILD_SOURCE:-unknown}
BUILD_VERSION=${RCP_BUILD_VERSION:-unknown}
BUILD_DIRTY=unknown
if [ "$BUILT_HERE" = true ]; then
  BUILD_REVISION=$COMMIT
  BUILD_SOURCE=$SOURCE
  BUILD_VERSION=$VERSION
  BUILD_DIRTY=$DIRTY
fi
CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

ARGS=()
[ "${PUBLISH_PLAIN_HTTP:-0}" = 1 ] && ARGS+=(--plain-http)
echo "pushing $TARGET:$TAG (binary sha256 $SHA, commit ${COMMIT:0:12}, dirty=$DIRTY)"
( cd "$STAGE" && oras push "${ARGS[@]}" \
    --artifact-type application/vnd.rust-cp.rcp.artifact.v1 \
    --annotation "org.opencontainers.image.title=rcp" \
    --annotation "org.opencontainers.image.version=$BUILD_VERSION" \
    --annotation "org.opencontainers.image.source=$BUILD_SOURCE" \
    --annotation "org.opencontainers.image.revision=$BUILD_REVISION" \
    --annotation "org.opencontainers.image.created=$CREATED" \
    --annotation "org.opencontainers.image.description=rcp (Rust copy): a data mover for local and mounted paths" \
    --annotation "io.github.rust-cp.rcp.binary.sha256=$SHA" \
    --annotation "io.github.rust-cp.rcp.source.dirty=$BUILD_DIRTY" \
    --annotation "io.github.rust-cp.rcp.publisher.revision=$COMMIT" \
    --annotation "io.github.rust-cp.rcp.publisher.source=$SOURCE" \
    --annotation "io.github.rust-cp.rcp.publisher.dirty=$DIRTY" \
    --annotation "io.github.rust-cp.rcp.build.rustc=$BUILD_RUSTC" \
    --annotation "io.github.rust-cp.rcp.build.target=$BUILD_TARGET" \
    --annotation "io.github.rust-cp.rcp.binary.linkage=$LINKAGE" \
    --annotation "io.github.rust-cp.rcp.binary.format=$FILE_DESCRIPTION" \
    --format json \
    "$TARGET:$TAG" \
    "rcp:application/vnd.rust-cp.rcp.binary.v1+octet-stream" \
    "SHA256SUMS:text/plain" ) > "$STAGE/push.json"
DIGEST=$(python3 -c 'import json, re, sys; d=json.load(open(sys.argv[1])).get("digest"); assert isinstance(d, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", d), "invalid registry digest"; print(d)' "$STAGE/push.json")
echo "pushed $TARGET@$DIGEST"
echo "verify with: oras manifest fetch ${ARGS[*]} $TARGET@$DIGEST | jq .annotations"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  { echo "digest=$DIGEST"; echo "target=$TARGET"; echo "binary_sha256=$SHA"; } >> "$GITHUB_OUTPUT"
fi
exit 0
