# Install, upgrade and uninstall

## Quick start

1. Install rcp (either way below).
2. Copy a tree, then check it:

   ```sh
   rcp copy /data /backup
   rcp verify /data /backup
   ```

3. Run it again later: `rcp sync` moves only what changed, using the catalog the first copy
   recorded. `rcp help` lists every command and option, and the
   [command-line reference](reference/cli.md) has the same tables.

## From a release archive

Each release on the [releases page](https://github.com/rust-cp/rcp/releases) carries an
x86-64 GNU/Linux archive, `SHA256SUMS`, an SPDX SBOM, a Sigstore signature and build
provenance ([Releases](releases.md) shows how to verify them). Install into a prefix, using
the usual `PREFIX` and `DESTDIR` conventions:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf rcp-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
PREFIX=${PREFIX:-$HOME/.local}
install -D -m 0755 rcp-vX.Y.Z-x86_64-unknown-linux-gnu/rcp "${DESTDIR}${PREFIX}/bin/rcp"
```

Uninstall by removing that file: `rm "${DESTDIR}${PREFIX}/bin/rcp"`. rcp installs nothing
else. Its catalog (`~/.local/state/rcp/catalog` unless `-catalog`, `RCP_CATALOG` or
`XDG_STATE_HOME` says otherwise; see [The catalog](guide/catalog.md)) is yours to keep or delete.

## With Cargo

From source, with Cargo's own install convention (`--root`, or `CARGO_INSTALL_ROOT`, picks
the location; the default is `~/.cargo`):

```sh
cargo install --locked --git https://github.com/rust-cp/rcp --tag vX.Y.Z            # default build
cargo install --locked --git https://github.com/rust-cp/rcp --tag vX.Y.Z --features rustls
cargo uninstall rcp
```

The release profile strips symbols. For a build that keeps debugging information, Cargo's
profile variables apply: `CARGO_PROFILE_RELEASE_STRIP=none CARGO_PROFILE_RELEASE_DEBUG=true`.
`RUSTFLAGS` and Cargo's other standard variables are honored; the build adds no flags of its
own beyond `Cargo.toml`'s release profile.

## Upgrade

Install the new version over the old one, by either method above. Only the latest release
is supported (`SECURITY.md`). Read the release's section of `CHANGELOG.md` first: changes a
user must act on are listed there, and the project follows Semantic Versioning, so before
1.0 a minor version can carry a breaking change and says so in its notes.

## Development environment

Everything needed to change rcp and run its tests, on Debian or Ubuntu:

```sh
git clone https://github.com/rust-cp/rcp && cd rcp
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --profile minimal -c clippy,rustfmt
sudo apt-get install -y --no-install-recommends zstd krb5-kdc krb5-admin-server krb5-user libgssapi-krb5-2
python3 -m pip install --user --require-hashes -r tests/support/requirements.txt
cargo test && cargo test --features rustls
```

These are the same steps CI runs (`.github/workflows/ci.yml`). `CONTRIBUTING.md` lists the
checks to run before pushing.
