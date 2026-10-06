# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Runtime changes are listed by their on-chain `spec_version`, because that is what nodes on the network actually run.

## [Unreleased]

### Changed
- Desktop node app 2.0.8: the second gateway now points to the current backup entry point (the retired server was removed), and the installer's `VERSION` file lists both gateways.
- Desktop node app 2.0.8: a new "Stuck" state appears after 10 minutes without a new block (or while still at block 0). The page lists likely causes (firewall or antivirus, device clock, outdated version) and a support email link; the app keeps retrying on its own.

### Security
- Updated `wasmtime` from 36.0.15 to 36.0.16 (RUSTSEC-2026-0316) and replaced the yanked `yoke-derive` 0.8.3 with 0.8.4.

### Fixed
- CI: Linux tests skip the Windows-only desktop app and installer; the build-environment check no longer requires a pre-filled offline cache.

### Added
- First public release of the source code.
- `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `GETTING_STARTED.md`, `ROADMAP.md`, `ARCHITECTURE.md`, and issue / pull request templates.

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
