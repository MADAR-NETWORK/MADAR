# MADAR Network

**A network owned by the people who run it.**

MADAR is an independent layer-1 blockchain written in Rust on the [Polkadot SDK](https://github.com/paritytech/polkadot-sdk) (Substrate). It gives every approved operator exactly one vote, charges no transaction fees, and has no sudo key: every change to the network's rules requires a 2-of-3 committee approval signed offline.

- Website: https://madar-network.com
- Explorer: https://madar-network.com/explorer.html
- Services: https://madar-network.com/services.html
- Telegram: https://t.me/madarnetwork

> **Status:** public testnet.

## Highlights

| | |
|---|---|
| **Consensus** | BABE block production + GRANDPA finality, unmodified. |
| **One operator, one vote** | Voting power is per approved operator — not per machine and not per balance. |
| **No transaction fees** | Spam resistance comes from an Argon2id proof-of-work at admission plus per-call weight limits. |
| **No sudo** | Runtime upgrades need 2-of-3 committee approval; members sign offline and only the code hash is approved on-chain. |
| **Light hardware** | A full node runs comfortably on modest machines (it has been run on an Android TV box). |

## Services built on MADAR

| Service | What it does | Code |
|---|---|---|
| **Madar Stamp** | Permanent proof-of-existence timestamps. Files never leave the user's device; only their SHA-256 fingerprint is recorded, and the first registration wins. A technical proof, not a legal notarization. | [`stamp/`](stamp/) |
| **Madar Swap** | Non-custodial token swaps at the best available rate, signed in the user's own wallet. | (web front end, not in this repository) |

## Repository layout

| Path | Contents |
|---|---|
| [`consensus/`](consensus/) | The runtime (chain logic) |
| [`node/`](node/) | The `madar-node` binary: node service, operator onboarding (`join`), committee tools, `doctor` diagnostics, stamp CLI |
| [`admission/`](admission/), [`admission-api/`](admission-api/) | Operator admission and membership rules, and their read-only runtime API |
| [`stamp/`](stamp/) | The timestamp pallet |
| [`upgrade-authority/`](upgrade-authority/) | 2-of-3 runtime-upgrade governance |
| [`protocol/`](protocol/), [`identity/`](identity/), [`transactions/`](transactions/), [`ledger/`](ledger/), [`blocks/`](blocks/), [`keystore/`](keystore/) | Core protocol components |
| [`update/`](update/), [`release-tools/`](release-tools/), [`committee-tools/`](committee-tools/) | Signed-update verification and release / committee key tools |
| [`node-app/`](node-app/), [`installer/`](installer/) | The "MADAR Node" desktop app for Windows and its installer |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | High-level architecture overview |
| [`docs/protocol/`](docs/protocol/) | Protocol specification |
| [`docs/security/`](docs/security/) | Dependency exceptions, licensing notes, trusted release keys |
| [`scripts/`](scripts/) | Build, reproducibility and safety scripts; a Linux launcher for a public node |

## Getting started

See **[GETTING_STARTED.md](GETTING_STARTED.md)** to build the node and run it on the public testnet.

Quick build:

```bash
cargo build --release -p madar-node
```

Requirements: the Rust toolchain pinned in [`rust-toolchain.toml`](rust-toolchain.toml), clang/LLVM, and `protoc`.

## Contributing

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md). Planned work is listed in [ROADMAP.md](ROADMAP.md) and changes in [CHANGELOG.md](CHANGELOG.md).

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Public keys for verifying signed releases: [`docs/security/release-trusted-keys.json`](docs/security/release-trusted-keys.json).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Some client components from the Polkadot SDK are GPL-3.0-or-later WITH Classpath-exception-2.0; see [`docs/security/node-licensing.md`](docs/security/node-licensing.md).
