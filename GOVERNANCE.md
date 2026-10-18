# Governance

rcp is a single-maintainer project. This file says how decisions are made, who holds which
role, and what each role does.

## Decision model

The maintainer makes the final decision on every change, release and dispute. Decisions are
made in public, on the issue or pull request they concern, with the reason stated. A
proposal that is turned down gets the reason, and can be reopened with new evidence: the
project's rule is that a claim cites the command that showed it (see
[CONTRIBUTING.md](CONTRIBUTING.md)), and that applies to arguments about direction too.

Disagreements are settled on the issue or pull request. If they cannot be settled there,
the maintainer decides and records why. Conduct concerns follow the
[code of conduct](CODE_OF_CONDUCT.md), not this process.

## Roles

| Role | Who | Responsibilities |
| --- | --- | --- |
| Maintainer | Jonathan Agustin ([@jonathanagustin](https://github.com/jonathanagustin)), owner of the `rust-cp` organization | Reviews and merges pull requests; triages issues; keeps `main` releasable; cuts releases (`scripts/release.sh`, the `Release` workflow); keeps the roadmap, CHANGELOG and documentation current; administers the repository settings, rulesets and CI; handles vulnerability reports as set out in [SECURITY.md](SECURITY.md); enforces the code of conduct. |
| Code owner | The people listed in [`.github/CODEOWNERS`](.github/CODEOWNERS) (today, the maintainer) | Reviews changes to the paths they own. The `main` ruleset requires a code-owner review. |
| Security contact | The maintainer | Receives private vulnerability reports through GitHub's private reporting form, acknowledges within 5 working days, and coordinates the fix and advisory. |
| Contributor | Anyone who opens an issue or pull request | Follows [CONTRIBUTING.md](CONTRIBUTING.md) and the code of conduct; includes tests and the evidence for each claim; certifies the contribution as described under "Contribution terms" in CONTRIBUTING.md. |

## Becoming a maintainer

A contributor with a record of reviewed, merged changes can be invited by the maintainer to
become a maintainer. A new maintainer is added to `.github/CODEOWNERS` and given the
organization and repository access needed to merge, release and administer the project, and
this file is updated in the same pull request.

## Continuity

All project assets live in the `rust-cp` GitHub organization: the repository, its issues and
releases, the documentation site (GitHub Pages) and the container packages (GitHub Container
Registry). Releases are signed keylessly with Sigstore from the `Release` workflow, so no
private signing key needs to be handed over; anyone with write access to the repository and
the release workflow can publish a release.

Today the maintainer is the only person with administrative access. Until a second
organization owner is added, the project does not meet the goal of continuing within a week
if the maintainer becomes unavailable. Adding a second owner of the `rust-cp` organization is
the change that closes this gap, and this section will name that person when it happens.
