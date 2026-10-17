#!/usr/bin/env bash
# Build the libFuzzer targets and run each one for a bounded number of seconds.
#
#   scripts/fuzz.sh [SECONDS]
#
# The targets live in fuzz/, which is its own crate, so the release binary stays
# free of third-party crates. A crash fails this script.
set -euo pipefail

seconds=${1:-20}
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root/fuzz"
# libFuzzer is C++. Prefer g++ so the standard library matches the compiler.
export CXX=${CXX:-g++}
cargo build --release --locked
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for target in json zstd deflate lz4; do
    printf 'fuzz %s for %ss\n' "$target" "$seconds"
    mkdir -p "$work/$target"
    cp -a "corpus/$target/." "$work/$target/"
    "./target/release/$target" \
        -max_total_time="$seconds" \
        -timeout=10 \
        -rss_limit_mb=2048 \
        -max_len=65536 \
        "$work/$target"
done
