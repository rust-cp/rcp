# Contributing

## Workflow

This project follows the [code of conduct](CODE_OF_CONDUCT.md).

`main` is the only long-lived branch. Changes land through short-lived branches and pull
requests, which are squash-merged, so the pull request title becomes the commit message. Use
[Conventional Commits](https://www.conventionalcommits.org/) for titles (`feat(smb): …`,
`fix(nfs): …`, `docs: …`). The `Title` workflow checks every title with
`scripts/check-title.sh`, which runs locally too; the scope is the endpoint or module, in
lowercase, and `!` before the colon marks a breaking change. `CHANGELOG.md` is written by
hand rather than generated from these titles: an entry says what changed for someone running
rcp and what was measured, which a commit subject cannot.

Work that is not ready to ship stays behind a Cargo feature that is off by default, so `main`
is always releasable.

The minimum supported Rust version is `rust-version` in `Cargo.toml` (1.87). Use American
English in code, comments and documentation. Commit messages and pull request descriptions
describe the change itself.

Measure before claiming. A statement that something works, is fixed or is covered cites the
command that showed it. A failing test is a finding until a cause is shown, never a flake by
assumption.

New features must come with tests in the automated test suite (`cargo test`), and a bug fix
comes with a test that fails without the fix. A pull request that changes behavior without a
test is not ready to merge.

### Coding standards

Rust code follows the [Rust Style Guide](https://doc.rust-lang.org/style-guide/) as
implemented by `rustfmt` with its default settings, and the
[Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) for public items. Clippy's
default lints are the project's lint set, with warnings treated as errors. CI enforces both:
`cargo fmt --all --check`, and Clippy with `-D warnings` on every feature combination and on
the minimum supported Rust version. An exception is an `#[allow]` or `#[expect]` on the
smallest item it applies to, with a comment saying why. Workflows must pass `actionlint`
and `zizmor`, which CI runs.

### Contribution terms

By opening a pull request you certify the [Developer Certificate of Origin
1.1](https://developercertificate.org/): the contribution is your own work, or you have the
right to submit it, and you submit it under the project's license (Apache-2.0, whose
section 5 makes a contribution licensed on those terms unless you say otherwise). A
`Signed-off-by` line is welcome but not required.

See [GOVERNANCE.md](GOVERNANCE.md) for how decisions are made and who holds which role, and
[ROADMAP.md](ROADMAP.md) for where the project is heading.

## Before you push

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --features rustls
```

`cargo test` covers the default features, and every endpoint feature is on by default.
`rustls` is off by default and gates the TLS tests, so the second test command is required
too. `cargo test --all-features` also enables `system-zstd`, which links the system libzstd.
A build with the endpoint features off is `cargo test --no-default-features --lib`.

CI also runs Clippy for each feature alone and every pair, Clippy on the minimum supported
Rust version, documentation builds and doctests with warnings denied for no default
features, default features and all features, and `cargo deny check` and `cargo vet`.

### Test peers

Most endpoint tests run against stand-in servers in `tests/support/`. A few need tools on
`PATH` (`tar`, `gzip`, `zstd`, `openssl`) and two Python packages:

```sh
python3 -m pip install --require-hashes -r tests/support/requirements.txt
```

A test whose peer is missing prints `SKIP:` with the reason and returns, so check the output
of a local run for skips before relying on it.

### Fuzzing

Parser fuzz targets live in `fuzz/` and are not part of the release build. From a
host with `clang`:

```sh
scripts/fuzz.sh 30
```

### Generated documentation

`docs/src/reference/cli.md` is generated from the option tables in `src/describe.rs`. After
changing an option, regenerate it:

```sh
UPDATE_DOCS=1 cargo test --test docs
```

Public API examples belong in Rust documentation comments and must run as doctests. The
book is built with `mdbook build docs`; its API links target the accompanying `cargo doc`
output. Keep both outputs together when checking links.

### Dependency updates and workflow inputs

`renovate.json` owns Cargo, GitHub Actions, hash-locked Python test peers, integration
containers and annotated build-tool versions. Automatic merging is disabled; major
updates and minor updates to pre-1.0 Rust crates require dashboard approval. The installed
Renovate App must have access to this repository before updates can run. A valid
configuration alone does not establish that access.

Check the configuration with the version of `renovate-config-validator` named in CI.
Python updates must regenerate the hashed lockfiles from their `.in` inputs. Container
updates must preserve digest pins. For the installer tools and k3s, independently verify
the new archive checksum against the publisher's release before updating the literal
checksum; a version-only change deliberately fails verification.

GitHub Actions are pinned to reviewed publisher commits, downloaded CI tools are checked
against repository-pinned SHA-256 values, and integration images are digest-pinned.
Rust `stable` remains a compatibility check supplied by official rustup, and Ubuntu 24.04
runners and packages receive updates through the official signed distribution channels.
The local OCI fixture tag is created from a digest-verified Alpine image.

The current checkout is scanned with redacted Gitleaks output; that check does not cover
Git history. CodeQL SARIF is uploaded to code scanning and also retained as a short-lived
artifact that is checked for findings. Findings need
individual disposition, never a blanket suppression. Public example credentials in
protocol tests are fixtures, not usable repository credentials.

Reviewed CodeQL dispositions identify individual rule/path/fingerprint triples, their
owning functions, and evidence distinguishing test fixtures or non-secret report fields
from credentials. SHA-256 values pin every reported flow source and compilation-scope
evidence, and a separate digest pins the reported flow locations. Source or flow changes
require renewed review even at an existing sink. PRs and `main` use the complete query set
with diff-informed analysis disabled. New findings still fail the gate, and raw reports
remain available for inspection. The Scorecard workflow uses the official
`ossf/scorecard-action` in the form the Scorecard API accepts for publishing results:
its job has only `uses:` steps, and any extra reporting goes in a separate job.

## Releases

1. `scripts/release.sh prepare 0.2.0` moves the `Unreleased` entries in `CHANGELOG.md` under
   `[0.2.0]` with today's date, sets the version in `Cargo.toml` and `Cargo.lock`, and
   commits `chore: release 0.2.0` on a new branch `release/v0.2.0`. It refuses a dirty tree,
   an empty `Unreleased`, and a version that is not above the current one.
2. Push that branch, open a pull request, and merge it. Then run the `Release` workflow by
   hand on `main` with the version (`gh workflow run release.yml -f version=0.2.0`). It makes
   the same checks as `scripts/release.sh check`, creates the tag `v0.2.0` on that commit,
   **signs it keylessly with gitsign** under the workflow's own identity, and publishes in
   the same run. This is the normal path, because it is the one that produces a signed tag.
   `scripts/release.sh tag 0.2.0` followed by `git push origin v0.2.0` still works, but makes
   an unsigned annotated tag: signing it locally with gitsign would put the maintainer's
   personal e-mail address in a public transparency-log certificate.
3. The release workflow requires the real Kerberos tests, then builds the Linux x86-64 and
   Linux ARM64 GNU binaries with system GNU libc linkage and publishes a GitHub release with
   checksums, an SPDX bill of materials for each archive, and the matching `CHANGELOG.md`
   section as notes. Each archive includes dependency license notices, `SBOM.spdx.json`, and
   `RUNTIME.txt` identifying the build environment and runtime requirements. Each archive is
   signed keylessly with cosign, and the release carries SLSA build provenance. The workflow
   also pushes the signed multi-arch image (`linux/amd64` and `linux/arm64`), with an SBOM
   attestation, to `ghcr.io/rust-cp/rcp`. When the `CARGO_REGISTRY_TOKEN` secret is set, a
   tag release also runs `cargo publish`; when it is not set, that step skips. See
   `docs/src/releases.md` for the asset names and verification commands.
