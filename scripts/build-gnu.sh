#!/usr/bin/env bash
# Run inside the digest-pinned official Rust/Bullseye builder. No publication.
set -euo pipefail
output=${1:?usage: build-gnu.sh OUTPUT_DIRECTORY}
target=${2:-x86_64-unknown-linux-gnu}
case "$target" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
  *) echo 'unsupported GNU/Linux release target' >&2; exit 2 ;;
esac
mkdir -p "$output"
output=$(realpath "$output")
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/rcp-gnu-target}
cargo build --release --locked --features rustls --target "$target"
binary=$CARGO_TARGET_DIR/$target/release/rcp
bash scripts/check-glibc.sh "$binary" 2.34 "$target" | tee "$output/glibc-requirements.txt"
"$binary" version
cp "$binary" "$output/rcp"
cp Cargo.lock "$output/"
cargo metadata --locked --features rustls --filter-platform "$target" --format-version 1 > "$output/cargo-metadata.json"
python3 scripts/third-party-licenses.py < "$output/cargo-metadata.json" > "$output/THIRD_PARTY_LICENSES.txt"
{ rustc --version; cargo --version; getconf GNU_LIBC_VERSION; sha256sum "$output/rcp"; } > "$output/build-toolchain.txt"
