# Getting Started

This guide takes you from a fresh machine to a MADAR node that is synced with the public testnet.

A regular (full) node verifies every block and helps the network stay available. It does **not** vote, and it holds no keys or funds. Becoming a voting operator is a separate, approval-based step described at the end.

## 1. Requirements

| | |
|---|---|
| OS | Linux x86-64 (Ubuntu 24.04+, Debian 13+) is the reference platform. macOS and Windows also build. |
| CPU / RAM | 2 cores and 2 GB RAM are enough for a full node. |
| Disk | A few GB with the default pruning settings. |
| Rust | The exact version pinned in [`rust-toolchain.toml`](rust-toolchain.toml). `rustup` installs it automatically, together with the `wasm32v1-none` target. |
| System packages | `clang`/`libclang`, `protobuf-compiler` (`protoc`), `pkg-config`, OpenSSL headers. |

On Debian / Ubuntu:

```bash
sudo apt-get update && sudo apt-get install -y build-essential clang libclang-dev protobuf-compiler pkg-config libssl-dev git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then check that your environment matches the pinned one:

```bash
bash scripts/verify-build-env.sh
```

## 2. Build

```bash
cargo build --locked --release -p madar-node
```

The binary is written to `target/release/madar-node`. The runtime (chain logic) is compiled to WebAssembly and embedded in the binary during this build.

To run the test suite:

```bash
cargo test --locked --workspace
```

## 3. Run a full node on the public testnet

The easiest way is the launcher script, which applies sensible defaults (bootnodes, pruning, safe RPC, limited peers):

```bash
cp target/release/madar-node scripts/public-linux/
cp madar-spec.json scripts/public-linux/
cd scripts/public-linux
./madar-node.sh start --name YOUR_NAME
./madar-node.sh status
```

Other launcher commands:

| Command | What it does |
|---|---|
| `./madar-node.sh stop` | Stops the node |
| `./madar-node.sh log` | Follows the log |
| `./madar-node.sh service` | Installs a user-level systemd service so the node starts with your session |
| `./madar-node.sh start --help-network` | Also accepts inbound connections (open TCP port 30333) |

Node data lives in `~/.local/share/madar-node`. Deleting that folder removes everything.

### Running the binary directly

If you prefer to manage the process yourself, the essential flags are:

```bash
./target/release/madar-node \
  --chain madar-spec.json \
  --name YOUR_NAME \
  --bootnodes /ip4/188.241.241.253/tcp/30333/p2p/12D3KooWDAr7FDtAeUx51zowWytNKeeuQfB5B2cyF4bZmDEp9j9K \
  --bootnodes /ip4/103.254.60.222/tcp/30333/p2p/12D3KooWQqcRoYDfHLGrj7kUcNFQHnHvpcgZvKMfU1RuPRqnhuXS \
  --rpc-methods safe
```

See [`scripts/public-linux/madar-node.sh`](scripts/public-linux/madar-node.sh) for the full set of recommended flags.

## 4. Check your node

`madar-node doctor` is a read-only health check of a running node: sync, finality, peers, role, disk, keys, membership and clock.

```bash
./target/release/madar-node doctor --rpc 127.0.0.1:9944 --expect-role full
```

You can also compare your best and finalized block numbers with the public explorer: https://madar-network.com/explorer.html

## 5. Windows desktop app

[`node-app/`](node-app/) is the "MADAR Node" desktop app for Windows (a tray icon plus a small local status page), and [`installer/`](installer/) builds its installer. Official signed installers are published on https://madar-network.com.

## 6. Becoming a voting operator

MADAR gives **one vote per approved operator**. Joining as a voter takes three things:

1. An operator account approved by the network's governance (the 2-of-3 committee).
2. A node vouched for by that operator.
3. Solving the Argon2id admission puzzle and winning a seat in the admission lottery.

The `join` subcommand guides you through the whole process (account, candidacy, session keys, membership status, renewal and voluntary exit):

```bash
./target/release/madar-node join --help
```

Before starting, contact the team through the channels listed in the [README](README.md). Approval is required, and voter nodes need stable uptime because finality depends on them.

## Need help?

- Bugs and feature requests: open a GitHub issue.
- Questions: the Telegram channel listed in the [README](README.md).
- Security issues: **never** in public. See [SECURITY.md](SECURITY.md).
