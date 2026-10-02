# `madar-node` licensing — the precise explanation (D42)

> A **permanent** governing document, created when we found that `node/` (the first crate in this project
> that links `sc-*`) introduces the GPL-3.0-or-later WITH Classpath-exception-2.0 license for the first time.
> **The license of code we wrote does not change** — it stays Apache-2.0.

## The governing summary

- **All code written by MADAR Network** (`protocol`, `identity`, `transactions`, `ledger`, `blocks`,
  `consensus`, `admission`, and the code we wrote inside `node/`) — **Apache-2.0, unchanged**.
- **`sc-*` dependencies** (the client/node part of Substrate — `sc-cli`, `sc-service`, `sc-network`,
  `sc-executor`, `sc-consensus-babe` and others, consumed only by `node/`) — **GPL-3.0-or-later WITH
  Classpath-exception-2.0**. This is their original license from `polkadot-sdk` itself, not our choice, and it
  cannot be avoided (there is no non-GPL alternative for a real Substrate client in this SDK version).
- `sp-*` / `frame-*` / `pallet-*` (the foundation of `madar-consensus` and everything below it) —
  **remain Apache-2.0**. GPL appears only with `node/`.

## What the Classpath Exception actually means (the same mechanism as OpenJDK)

The Classpath exception disables the usual "viral" effect of the GPL on any code that **links** to a library
carrying it (without modifying it). Specifically:

1. **Our code (Apache-2.0) is not forced to become GPL** merely because it links with `sc-*` — that is the
   reason the exception exists. Without it, every real Substrate node (including Polkadot and Kusama) would
   force every runtime built on it to be GPL, which has never happened anywhere in the ecosystem — practical
   evidence that this interpretation is correct and applied everywhere.
2. **No obligation to disclose our own source** as a condition of linking — the exception removes exactly that
   obligation for code that only links (does not modify) the files licensed under it.

## The actual obligations when distributing the node binary (`madar-node`)

The compiled executable (`madar-node.exe` / `madar-node`) is a **combination** of our code (Apache-2.0) and
`sc-*` code (GPL-3.0-or-later WITH Classpath-exception-2.0). When **distributing** this binary (not merely
running it internally):

- **Our part stays Apache-2.0** — no additional source disclosure is required for it because of this license
  (Apache-2.0 has its own independent terms, unaffected by this).
- **The GPL part (`sc-*`) carries the standard GPL obligations**: anyone who receives the binary must be able to
  obtain the full source of the GPL-licensed parts — **already satisfied**: the exact `sc-*` source at the pinned
  commit (`polkadot-stable2606-2`) is publicly available at `https://github.com/paritytech/polkadot-sdk`, and no
  further step is needed as long as that code is not modified (it is not — BABE and GRANDPA are used unmodified).
- **No additional restrictions may be imposed** on redistributing the GPL parts themselves (this does not stop us
  from applying the standard Apache-2.0 terms to our own code).
- This is **exactly** the legal setting under which every Substrate-based network operates today (Polkadot,
  Kusama and every parachain) — we are not an exception, and the structure has been tested legally and in
  practice across the whole ecosystem for years.

## What did not change

- The `license` field in every `Cargo.toml` of our code (including `node/Cargo.toml`) stays `"Apache-2.0"` —
  an accurate description of the code we actually wrote in that crate, independent of its dependencies' licenses.

## `cargo deny check licenses`

`GPL-3.0-or-later WITH Classpath-exception-2.0` is allowed in `deny.toml` **only for the named `sc-*` packages**
(an exception list by package name) — it is not added to the global `licenses.allow` list, so no other package can
silently bring in a GPL license.

## Log

| Date | Event |
|---|---|
| 2026-09-18 | Discovered when building `node/` (the first use of `sc-*` in this project). |
| — | Approved by the project owner (D42) and restricted by package name in `deny.toml`. |
