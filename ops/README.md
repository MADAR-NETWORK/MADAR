# Madar Ops

Watches Substrate / Polkadot SDK nodes and alerts the operator the moment something is wrong:
node down, no new blocks, finality behind, too few peers, validator syncing, disk almost full.
Alerts go to a phone (ntfy push), Telegram or a JSON webhook — one alert when a problem starts,
a reminder while it lasts, one message when it is resolved.

- Runs next to your node; read-only (safe RPC methods only, no keys, never signs).
- Status page on `127.0.0.1:9620` only. No telemetry.
- One static binary (Linux x86_64 / ARM64, Windows x64).

Install, config builder and downloads: https://madar-network.com/ops/

```sh
madar-ops init                 # write a sample madar-ops.toml
madar-ops check [config]       # one round, printed
madar-ops test-alert [config]  # send a test alert to every channel
madar-ops run [config]         # keep watching
```

Build: `cargo build --release -p madar-ops`. Static Linux builds: `cargo zigbuild --release -p madar-ops --target x86_64-unknown-linux-musl`.
`packaging/` holds the installer and the hardened systemd unit published on the site.

License: Apache-2.0.
