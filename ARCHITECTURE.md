# Architecture

This document gives a high-level map of how MADAR fits together. The precise rules are in the [protocol specification](docs/protocol/PROTOCOL_SPECIFICATION.md).

## Overview

```
                 ┌────────────────────────── madar-node (node/) ──────────────────────────┐
                 │                                                                        │
  peers  ◄──────►│  networking (libp2p)   BABE block authoring   GRANDPA finality   RPC   │◄──── wallets, explorer,
                 │                                                                        │      desktop app, tools
                 │  operator tools: join · committee · stamp · doctor · check-update      │
                 │                                                                        │
                 │   ┌──────────────── runtime (WebAssembly, consensus/) ───────────────┐ │
                 │   │  frame_system · timestamp · balances (no endowment) · session    │ │
                 │   │  babe · grandpa                                                  │ │
                 │   │  madar_admission  (admission/)       — who may vote              │ │
                 │   │  upgrade authority (upgrade-authority/) — 2-of-3 committee       │ │
                 │   │  madar_stamp      (stamp/)           — proof-of-existence        │ │
                 │   └──────────────────────────────────────────────────────────────────┘ │
                 └────────────────────────────────────────────────────────────────────────┘
```

MADAR is built on the [Polkadot SDK](https://github.com/paritytech/polkadot-sdk) (Substrate). The node is a native binary; the chain logic (the *runtime*) is compiled to WebAssembly, stored on-chain, and can be upgraded without a hard fork — but only with committee approval.

## Consensus

- **BABE** produces blocks in fixed slots; **GRANDPA** finalizes them. Both are used unmodified.
- The voter set comes from `pallet_session`, which takes its validators from `madar_admission` at each session rotation. Changes are queued and become active two rotations later, the standard Substrate behavior.
- GRANDPA needs more than two thirds of the voters online to finalize, so voter uptime matters.

## Admission: one operator, one vote

The [`admission/`](admission/) pallet decides who may vote, without any token stake:

1. **Operators** are approved by governance and get a vote cap (at most one vote each).
2. An operator **vouches** for the node it runs.
3. The node solves an **Argon2id puzzle** (memory-hard proof-of-work) bound to its account and the current round, and enters a candidate set ranked by the puzzle output.
4. After candidacy closes, fresh on-chain randomness (BABE VRF output collected *after* closing) runs a fair **lottery**; only a limited number of winners enter per round.
5. Membership expires after a fixed term unless **renewed**; members can also **exit voluntarily**. Proven misbehavior leads to a permanent ban of the key.

Liveness guards make sure no removal ever empties the voter set.

## Governance: no sudo

There is no sudo key. Runtime upgrades go through [`upgrade-authority/`](upgrade-authority/): a 2-of-3 committee approves the **hash** of the new runtime code. Members sign offline on air-gapped machines (`madar-node committee` prepares, signs and submits approvals; signing refuses to run while the machine is online). Administrative shortcuts that existed for development are unreachable in the production runtime.

## No transaction fees

Calls are free. Spam resistance comes from the admission puzzle (only admitted parties can do privileged things), from accurate per-call weights, and from block and transaction-pool limits. Expensive paths such as Argon2id verification are charged for their worst case, and cheap early rejections are refunded.

## Madar Stamp

[`stamp/`](stamp/) records SHA-256 file fingerprints permanently, first registration wins. The user signs the fingerprint with their own wallet (EVM `personal_sign` or Solana `signMessage`) and the runtime verifies that signature on-chain. Submission is limited to committee-approved stamper accounts, and files never leave the user's device.

## Core libraries

| Crate | Role |
|---|---|
| [`protocol/`](protocol/) | Constants, canonical serialization, hashing |
| [`identity/`](identity/) | Account identities and addresses (SS58 prefix 85) |
| [`transactions/`](transactions/), [`ledger/`](ledger/), [`blocks/`](blocks/) | Transaction format, ledger rules and block limits |
| [`keystore/`](keystore/) | Safe on-disk key storage (no silent overwrite, verified writes) |
| [`admission-api/`](admission-api/) | Read-only runtime API for membership status |

## Releases and updates

- [`scripts/build-release.sh`](scripts/build-release.sh) builds the binary, the runtime WASM, an SBOM, a build manifest and checksums. CI builds twice on separate machines and compares the results.
- Releases are signed offline with M-of-N keys ([`release-tools/`](release-tools/)). Nodes verify them with [`update/`](update/) against [`docs/security/release-trusted-keys.json`](docs/security/release-trusted-keys.json), which supports key rotation and revocation. Updates are opt-in: the node never downloads or installs anything by itself.

## Desktop app

[`node-app/`](node-app/) runs a full node on Windows with a tray icon and a local status page; [`installer/`](installer/) packages it.
