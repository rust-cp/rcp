# External dependencies

## Where they are listed

Every external dependency is declared in a machine-readable file:

- Rust crates: `Cargo.toml`, with exact versions and checksums in `Cargo.lock`.
- Python test peers: `tests/support/requirements.txt`, hash-locked and generated from
  `tests/support/requirements.in`.
- CI tools: `scripts/install-ci-tool.sh`, each with a pinned version and SHA-256.
- GitHub Actions: pinned to commit SHAs in `.github/workflows/`.
- Container base images: digest-pinned in `container/` and the workflows.
- The released binary's runtime dependency graph: the SPDX SBOM published with each release
  (`*.tar.gz.spdx.json`, and `rcp.spdx.json` in the repository).

## Policy

- **Few, and allow-listed.** rcp depends on a small set of widely used crates chosen for one
  job each (TLS, and standard cryptographic primitives: RustCrypto `sha2`, `hmac`, `md4`,
  `md-5`, `aes` and `cmac`, and the official `blake3`). The default build's complete list,
  support crates included, is `scripts/allowed-dependencies.txt`, and CI's
  `dependency-allowlist` job fails on any crate not in it. Adding a crate needs the
  maintainer's approval in the pull request that adds it, with the reason, and the crate
  must pass the checks below.
- **Licenses.** `deny.toml` allows only Apache-2.0, BSD-3-Clause, ISC and MIT; anything else
  fails `cargo deny`.
- **Sources.** Crates come only from crates.io (`deny.toml` `[sources]`); git and unknown
  registries are refused.
- **Audits.** `cargo vet` (`supply-chain/`) runs on every pull request: each crate version
  must be audited, covered by an imported audit, or listed as an exemption in
  `supply-chain/config.toml`, so a new or changed crate cannot arrive unreviewed.
- **Known vulnerabilities.** `cargo deny` checks the RustSec advisory database on every pull
  request; GitHub Dependabot alerts and security updates are on. A reported vulnerability
  in a dependency is fixed by updating it, or documented as not exploitable in rcp.
- **Updates.** `renovate.json` configures Renovate to propose updates for crates, actions,
  test peers, images and tools. Updates are not merged automatically, and a version bump of a pinned
  tool must carry its independently verified checksum.

The crates are used through Cargo, not vendored or forked, so a fixed version reaches rcp
with a `Cargo.lock` update.
