# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** by email to **contact@madar-network.com**, with `SECURITY` at the start of the subject line. Do not open a public GitHub issue for security problems.

Please include:

- the affected component and version (or commit),
- steps to reproduce,
- the potential impact.

A PGP key is not published yet.

## Scope

In scope: all source code in this repository — the runtime ([`consensus/`](consensus/), [`admission/`](admission/), [`upgrade-authority/`](upgrade-authority/), [`stamp/`](stamp/)), the node ([`node/`](node/)), core components ([`protocol/`](protocol/), [`identity/`](identity/), [`transactions/`](transactions/), [`ledger/`](ledger/), [`blocks/`](blocks/), [`keystore/`](keystore/)), update and release tooling ([`update/`](update/), [`release-tools/`](release-tools/), [`committee-tools/`](committee-tools/)), and the desktop app and installer ([`node-app/`](node-app/), [`installer/`](installer/)).

Vulnerabilities in unmodified upstream Polkadot SDK crates (`sc-*`, `sp-*`, `frame-*`) should be reported to [paritytech/polkadot-sdk](https://github.com/paritytech/polkadot-sdk) directly. We are still glad to be told, so we can track the issue and upgrade.

## Our process

1. We acknowledge your report as soon as we can.
2. We investigate and, if the issue is confirmed, prepare a fix. Exploit details stay private until the fix is available.
3. We credit reporters who wish to be credited once the fix ships.
4. Severity follows the usual Critical / High / Medium / Low scale. Open Critical or High findings block a mainnet candidate.

## Known, tracked findings

We do not hide known findings. Dependency advisories that cannot be fixed yet (for example, because the fix is blocked upstream in the Polkadot SDK) are listed with their reasoning and closure conditions in [`docs/security/dependency-exceptions.md`](docs/security/dependency-exceptions.md). CI fails on any advisory that is not documented there.

## Verifying releases

Official releases are signed offline. The public keys used to verify them, and their rotation and revocation status, are in [`docs/security/release-trusted-keys.json`](docs/security/release-trusted-keys.json). Use `madar-node check-update` or [`scripts/verify-release.sh`](scripts/verify-release.sh) to check a release before installing it.

## Bug bounty

There is no bug bounty program yet. One is planned before a mainnet candidate (see [ROADMAP.md](ROADMAP.md)).
