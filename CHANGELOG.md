# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Runtime changes are listed by their on-chain `spec_version`, because that is what nodes on the network actually run.

## [Unreleased]

### Added
- FRAME benchmarks for every MADAR pallet and a runtime-level session-rotation benchmark, behind the `runtime-benchmarks` feature (off by default, never part of a production build). `madar-node benchmark pallet|overhead|storage|machine` is available only in such a build.
- `madar-node committee`: two new 2-of-3 committee decisions, `names-reserve` (reserve or release a name in Madar Names) and `recover-finality` (recover stalled finality through `Grandpa::note_stalled`, refused while finality still runs or while a dead voter is still in the next session's set). Members sign only what the encoded call itself says; a request whose description does not match its call is refused.
- `madar-node join apply` checks that an approved operator has vouched for the account before solving the puzzle, and `join auto-renew --reapply` waits instead of applying while the account is not vouched.
- `madar-node names lock-sale` takes `--pay-amount` and `--rail`, and `names complete-sale` takes `--payment-ref`, for the spec 8 safe sale.
- Desktop node app 2.0.11: an optional "My earnings" card (shown only when the service opens it, or once the node is linked) that links the node to a wallet through a one-time code opened in the user's own browser. The app signs its messages with the node's own network key (`data\node-key`, passed to the node with `--node-key-file`); the key never leaves the computer and is not a wallet key.

### Changed
- Desktop node app 2.0.10 / installer: no hidden PowerShell and no `reg.exe` anywhere. HTTPS goes through the app itself (`ureq` with rustls), processes are handled with Windows calls, links open through the shell, zip files use Windows' own `tar`, the desktop shortcut is written through the Shell Link COM interface, and the "Start with Windows" value and the "Apps" entry are written through the registry API (antivirus behaviour monitors flagged the old approach).
- Desktop node app 2.0.11: the tray opens the existing app window instead of a new one; the background app no longer attaches to the console it was started from; a crash is written to `app.log`.
- Desktop node app 2.0.12 / installer: the installer shows the app's own version, and its last message no longer mentions creating an account on an update.
- Removed the retired second bootnode from `scripts/public-linux/madar-node.sh` and `GETTING_STARTED.md`, and replaced it with the current gateway in the committee tool's online check.
- Desktop node app 2.0.8: the second gateway now points to the current backup entry point (the retired server was removed), and the installer's `VERSION` file lists both gateways.
- Desktop node app 2.0.8: a new "Stuck" state appears after 10 minutes without a new block (or while still at block 0). The page lists likely causes (firewall or antivirus, device clock, outdated version) and a support email link; the app keeps retrying on its own.

### Security
- Updated `wasmtime` from 36.0.16 to 36.0.18 (RUSTSEC-2026-0363; the affected `component-model` feature is not enabled in MADAR). `ruzstd` (RUSTSEC-2026-0344) is present in `Cargo.lock` only and is not compiled. `proc-macro-error2` (RUSTSEC-2026-0173, unmaintained) is pulled in only by the `runtime-benchmarks` feature and is recorded as dependency exception #7.
- Updated `wasmtime` from 36.0.15 to 36.0.16 (RUSTSEC-2026-0316) and replaced the yanked `yoke-derive` 0.8.3 with 0.8.4.

### Fixed
- CI: Linux tests skip the Windows-only desktop app and installer; the build-environment check no longer requires a pre-filled offline cache.

### Added
- First public release of the source code.
- `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `GETTING_STARTED.md`, `ROADMAP.md`, `ARCHITECTURE.md`, and issue / pull request templates.

## Runtime spec 9 — operator vouching and measured weights

### Changed
- Admission: a candidate must be vouched for by an approved operator before it applies. An unvouched candidacy is refused at submission, before the Argon2 check (`NodeNotVouched`), and only vouched candidates enter the draw; a skipped candidate gets an explicit event.
- Admission: the draw also skips candidates whose operator has no room left under its vote cap, so such a winner no longer wastes a round seat.
- An approved operator that has no account yet can create it with its first vouch (only operators approved by the 2-of-3 committee).
- Weights measured with FRAME benchmarks (B1): every declared weight is at least twice the measured median on the worst path, and the block base cost and the per-transaction base cost are measured for MADAR instead of the SDK defaults. The SDK pallets use the larger of the SDK weight and a floor measured on MADAR.
- Names: the v1 safe-sale calls `lock_sale` (index 6) and `complete_sale` (index 7), disabled since spec 8, are removed. Their indices are not reused and storage is unchanged.

## Runtime spec 8 — payment proof for the safe sale

### Added
- Names: `lock_sale_v2` records the exact amount the buyer will pay (micro units, 6 decimals, within the signed price + 0.10) and the payment network in the lock and in the `SaleLockedV2` event. `complete_sale_v2` moves the name only with a payment reference (`<chain>:<tx hash>`) from the lock's network and emits `SaleCompletedV2`, so anyone can match every completed sale with the payment chain. A payment reference can complete only one sale.

### Fixed
- Names: re-registering a name for the same owner can no longer shorten its paid term.

## Runtime spec 7 — Madar Names

### Added
- `names` pallet: short names (`name.madar`) bound to one EVM or Solana wallet, proved by the wallet's own signature (EVM `personal_sign` or Solana `signMessage`) and verified on-chain.
- Each name has a yearly term followed by a grace period during which only its owner can take it back; renewal extends the term without changing the owner.
- Registrar accounts and the reserved-name list are managed by the 2-of-3 upgrade committee. Only the committee can revoke a name, for proven fraud, with a written reason recorded publicly on-chain.
- Safe resale: the seller signs an offer (price, receiving wallet, validity), the buyer signs an acceptance at the same price, and `lock_sale` holds the name for that buyer on-chain for at most 60 minutes. `complete_sale` moves the name once payment arrives and keeps the remaining paid term; `cancel_offer` lets the owner withdraw offers. A per-name nonce is bumped on every owner change or cancellation, so old signatures cannot be reused.
- `madar-node names` subcommand to register, renew and read names, check signatures offline, and handle sale offers.

### Changed
- GRANDPA voting rules: voters now vote one block behind the best block instead of two, so finality trails the best block by about one block. Finality still requires more than two thirds of the voters.

## Runtime spec 6 — Madar Stamp

### Added
- `stamp` pallet: permanent, first-wins proof-of-existence timestamps for SHA-256 file fingerprints. The registrant's wallet signature (EVM `personal_sign` or Solana `signMessage`) is verified on-chain. Only committee-approved stamper accounts may submit, and the file itself never reaches the chain.
- `madar-node stamp` subcommand to submit batches of fingerprints and read a stamp record.
- SS58 address prefix 85 for MADAR accounts.

## Runtime spec 5

### Security
- Closed the remaining administrative calls in the production runtime: they are now unreachable (`EnsureNever`) instead of being guarded by an origin.

### Changed
- Admission: lowered `AdmissionCapPerRound` from 5 to 2, so fewer new voters can enter in a single round.

## Runtime spec 3

### Security
- One vote per operator: winning the admission lottery now also requires a vouch from an approved operator, and each operator has a vote cap. This closes a Sybil gap where one party could gain many votes through many keys.

## Runtime spec 2

### Added
- `MembershipApi`: a read-only, versioned runtime API used by the `join` tooling.
- `madar-node join rotate-keys`: safe session-key rotation.

## Runtime spec 1

- Initial testnet: BABE block production and GRANDPA finality, Argon2id-based admission with a fair lottery, no transaction fees, no sudo, and 2-of-3 committee governance for runtime upgrades with offline signing.
