#!/usr/bin/env bash
# Ordinary native portability qualification; full protocol/KDC qualification is separate.
set -euo pipefail
test "$(uname -m)" = aarch64
test "$(rustc -vV | sed -n 's/^host: //p')" = aarch64-unknown-linux-gnu
uname -m
rustc -vV
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
# Exercise core/crypto/local adapters and bounded protocol fixtures, without
# enabling NFS, HDFS, remote, SFTP, tar or OCI unit/realm tests.
cargo test --locked --no-default-features --features s3,smb,dav,https,rustls \
  --lib --bin rcp \
  -- --test-threads=1
cargo test --locked --test hexagon --test describe --test docs --test xxh3
# The shared CLI contract file requires default features to compile. Run an
# explicit ordinary allowlist; never silently execute the excluded contracts.
cases=(
  copy_then_verify_preserves_content_modes_links_and_times
  every_engine_produces_the_same_tree
  sparse_input_stays_sparse_on_every_engine
  verify_reports_each_kind_of_difference_and_passes_when_clean
  resume_finishes_an_interrupted_copy_and_new_ids_are_unique
  sync_copies_changes_and_removes_what_the_source_dropped
  delete_counts_first_and_removes_only_with_force
  hard_links_are_preserved_unless_asked_otherwise
  extended_attributes_travel_with_the_file
  version_states_the_engines_and_sha256_vectors_hold
  the_mcp_server_speaks_the_protocol_and_keeps_the_rails
  a_job_outlives_the_call_that_started_it_and_leaves_a_resumable_catalog
  a_killed_server_takes_its_child_with_it
)
for case in "${cases[@]}"; do
  cargo test --locked --release --features rustls --test contract "$case" -- --exact --test-threads=1
done
cargo build --locked --release --features rustls
mkdir -p target/portability
source_date_epoch=$(git show -s --format=%ct HEAD)
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
  -C target/release -cf - rcp | gzip -n > target/portability/rcp-linux-arm64-candidate.tar.gz
sha256sum target/portability/rcp-linux-arm64-candidate.tar.gz
readelf -h target/release/rcp
readelf -d target/release/rcp
readelf --version-info target/release/rcp
