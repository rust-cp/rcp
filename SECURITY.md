# Security policy

## Reporting a vulnerability

Use this repository's
[private vulnerability report form](https://github.com/rust-cp/rcp/security/advisories/new)
in the **Security** tab. Do not open a public issue or pull request for a
suspected vulnerability, and keep credentials and exploit details out of issues
and pull requests.

Include what you can of the following:

- the version or commit you tested;
- the endpoint schemes and options involved;
- the smallest input or sequence of commands that shows the problem;
- what you expected to happen and what happened instead.

Please follow coordinated disclosure: give the project a chance to publish a
fix before describing the issue in public. You will get an acknowledgment
within 5 working days, and a first assessment of severity and scope within 10.

## Supported versions

Fixes land on `main` and ship in the next release. Only the latest release
is supported.

## Scope

rcp moves data between storage systems, so the reports that matter most are
those where it:

- writes, removes or changes anything outside the destination it was given;
- reports success for data that did not arrive intact;
- sends a credential somewhere other than the endpoint it belongs to;
- can be driven by a server, peer or file to allocate or loop without bound.
