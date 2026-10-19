# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Runtime changes are listed by their on-chain `spec_version`, because that is what nodes on the network actually run.

## [Unreleased]

### Added
- Desktop node app 2.0.14: one-button voting. An "Enable voting" card turns the node of a committee-approved operator into a voting node; the app runs every step itself (operator account, vouching, applying, session keys, renewal and exit) through `madar-node join` commands, and shows only the stage and the public address. The operator account's passphrase is random, sealed with DPAPI, and handed to each command through a one-time named pipe that only the same Windows account can open; it never appears on screen, on a command line or in a log. The node and its commands run inside a job object, so they stop if the app crashes, and a voting node is refused when that cannot be set up. The app cannot be uninstalled while the node votes or is on its way to voting.
- Desktop node app 2.0.14: no unsafe RPC in any mode. Session keys are generated while the node is stopped and registered with an ownership proof made locally; RPC stays on 127.0.0.1 with `--rpc-methods safe`, and `--rpc-cors` allows only the app's own page.
- Desktop node app 2.0.14: an optional encrypted backup of the operator account (protected by a password the user chooses) and a restore on another computer, which then registers new session keys for that computer. Keys copied together with a data folder are moved aside by renaming and replaced, so two computers never vote with the same keys.
- `madar-node join gen-keys`: generates the BABE and GRANDPA session keys directly in the node's keystore while the node is stopped (refused while its database is held) and prints only the public keys. `join register-keys --keys` (with `--base-path` and `--chain`) builds the ownership proof locally from the keystore files and needs only the safe RPC; without `--keys` the older path is unchanged.
- `madar-node join export` / `join import`: an encrypted backup of the operator account (Argon2id with stronger parameters than the account file, and caps on what a restored file may ask for) and a restore into a new account file with a new passphrase. Existing files are never replaced.
- `madar-node join status --json` also reports `operator_approved` and `vouched` (read at the same block as the status, `null` if they cannot be read), and `--passphrase-file` reads the status of a half-created account whose `.pub` file is missing.
- `madar-node committee`: two more 2-of-3 committee decisions for spec 9, `prepare-admission-params` (`--cap`: new admissions per rotation, or `--max-votes`: votes per operator, both within the runtime's hard limits) and `prepare-legacy-sunset` (the deadline for old v1 signed messages in Madar Names or Madar Stamp: `--stop-now`, or `--until-ms` to shorten or extend by at most 7 days). Both are refused on a chain older than spec 9. The tool built from spec 9 (transaction version 2) can still sign, for a spec 8 chain (transaction version 1), the calls whose encoding did not change, so the committee can approve the upgrade itself.
- `madar-node secret seal` / `secret check` (Windows): seals the voting node's secret file with DPAPI (`CurrentUser` by default, optional `LocalMachine`), reads the sealed file back to verify it, and with `--shred` overwrites and deletes the plain file only after that check. `join auto-renew --sealed-secret-file` unseals it in memory only. DPAPI is called directly through `crypt32`, not through PowerShell.
- `madar-node names`: v2 messages (`sale-message --v2`, `--genesis`, `--valid-until`), `names transfer` with the owner's and the new wallet's signatures, and the spec 9 payment networks. `madar-node stamp` sends `stamp_v2` when the signatures carry `valid_until`.
- Desktop node app 2.0.13: an optional card that shows progress toward a free `.madar` name for nodes that stay online for 7 days; its button opens one fixed page on madar-network.com in the user's own browser.

### Changed
- Desktop node app 2.0.15: a second public gateway (a non-voting door node on the second server, port 30334) replaces the old second bootnode. The app keeps both gateways as reserved peers, so the node always has two independent block sources and no longer gets stuck when one of them drops or refuses it. `scripts/public-linux/madar-node.sh` uses the same two gateways.
- `scripts/public-linux/madar-node.sh`: `service` also installs a stuck check (a systemd user timer every 5 minutes, `madar-node.sh watch`) with the same rule as the desktop app.
- Desktop node app 2.0.13: the self-heal guard also restarts the node when it is at least 40 blocks behind the network and its best block has not moved for 10 minutes (before, a node with a single peer that sent no blocks could stay stuck). The best-block timer is updated by the background monitor, so the guard works with the window closed.

### Fixed
- Installer 2.0.13: the Windows uninstall registry path had lost its backslashes, so the "Apps" entry was written to a wrong key and kept showing an old version. Fixed, with a regression test.

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

## Runtime spec 9 — v2 signatures, name transfer, admission limits and offender disabling

`spec_version` 9, `transaction_version` 2 (calls were removed, so a transaction signed for a removed call before the upgrade does not decode after it).

### Added
- Names and Stamp: v2 signed messages. Every v2 message ends with `network: 0x<hash of block 0>` and `valid until: <UTC ms>`, so a signature cannot be used on another network or after its deadline. New calls: `register_v2`, `lock_sale_v3`, `cancel_offer_v2`, `stamp_v2`.
- Names: `transfer` moves a name to another wallet with two signatures (the owner's transfer message naming the new wallet, and the new wallet's acceptance); the term and registration date stay unchanged and open offers and locks are dropped. `reassign` lets the 2-of-3 committee return a name to its rightful owner after a proven dispute, with a public reason.
- Names: more payment networks for the safe sale (USDC and USDT on Ethereum, Optimism, Polygon and BSC), appended after the five original ones. The v2 sale lock requires a receiving address that is fully valid for its network, and the buyer's acceptance cannot outlive the lock.
- Names: `on_idle` removes expired locks and old v1 locks, a bounded number per block and only when the block has room for the worst case.
- Admission: the cap on new admissions per rotation (default 2, hard limit 16, 0 pauses new admissions) and the cap on votes per operator (default 1, hard limit 4) are stored on chain and can be changed by the 2-of-3 committee within those limits. Lowering a cap evicts nobody.
- Admission: an operator never holds more than `floor((n-1)/3)` of `n` voters (at least 1), on top of its own cap and the committee cap, at the draw and when vouching.
- Admission: at most 3 Argon2 checks per account per round (renewals are counted on the member itself). A wrong solution from a vouched node is now counted as a successful transaction with an event, so its nonce advances and it cannot be replayed for free; extra attempts and unvouched candidates are refused before Argon2.
- Offenders proven by an equivocation report are disabled in BABE immediately (their blocks are rejected), not only after two session rotations. Never more than `floor((n-1)/3)` validators are disabled, and the last remaining producer is never disabled.

### Changed
- Old v1 messages (Names `register`, `cancel_offer`, `lock_sale_v2`, and Stamp `stamp`) are accepted for 72 hours after the upgrade and then refused automatically. The committee can shorten this deadline at any time, or extend it by at most 7 days per decision (`set_legacy_accepted_until`).
- Admission: a candidate must be vouched for by an approved operator before it applies. An unvouched candidacy is refused at submission, before the Argon2 check (`NodeNotVouched`), and only vouched candidates enter the draw; a skipped candidate gets an explicit event.
- Admission: the draw also skips candidates whose operator has no room left under its vote cap, so such a winner no longer wastes a round seat.
- An approved operator that has no account yet can create it with its first vouch (only operators approved by the 2-of-3 committee).
- Weights measured with FRAME benchmarks (B1): every declared weight is at least twice the measured median on the worst path, and the block base cost and the per-transaction base cost are measured for MADAR instead of the SDK defaults. The SDK pallets use the larger of the SDK weight and a floor measured on MADAR.
- Final spec 9 weights re-measured after the review fixes; every declared weight stays at least twice the measured value.

### Removed
- Admission: the closed admin calls `ban_key` (index 2) and `dev_only_force_set_validators` (index 3). Their indices are not reused; banning happens only through equivocation reports.
- Names: the v1 safe-sale calls `lock_sale` (index 6) and `complete_sale` (index 7), disabled since spec 8, are removed. Their indices are not reused and storage is unchanged.
- The one-time seeding migrations `SeedFirstStamper` (spec 6) and `SeedNames` (spec 7), which had already run and were no-ops.

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
