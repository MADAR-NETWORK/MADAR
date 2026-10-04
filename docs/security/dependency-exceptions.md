# Dependency Exception Register

> A **permanent** governing document that applies across every phase of the project — because the root cause
> (unmaintained transitive dependencies forced by the pinned `polkadot-sdk`) will recur as long as we build on the
> same SDK.
>
> **Governing status:** this policy was formally approved by the project owner on **2026-09-17**. Any change to this
> register (adding, editing or removing an exception) requires the same level of explicit approval.

## Rules (non-negotiable)

1. **Tier 1 — an actual vulnerability (RUSTSEC of type `vulnerability`):** permanently and absolutely blocked.
   **There is no exception path for it in this register.** `cargo-deny` itself does not allow lowering its severity.
2. **Tier 2 — an unmaintained dependency with no announced vulnerability (RUSTSEC of type `unmaintained`/`unsound`):**
   eligible for an exception **only** if it meets every eligibility condition below, and it is recorded here with all fields.
3. **Automatic structural override:** any **new** RUSTSEC ID of type `vulnerability` for the same package carries a
   different ID from the one excepted here — so it bypasses any existing exception and fails the gate immediately,
   without any human action (a structural property of RUSTSEC/cargo-deny: an exception is bound to one specific ID,
   not to the package as a whole).
4. **No exception without all four conditions below**, re-verified at every review (never assumed from a previous one):
   - The package is a transitive dependency **forced** by an approved, pinned source (here: a specific `polkadot-sdk`
     Git tag) — not a direct choice of any crate in this repository.
   - There is no RUSTSEC of type `vulnerability` for the same package at review time.
   - `cargo audit` / `cargo deny` confirm there is no safe upgrade ("No safe upgrade is available").
   - It was verified against the **latest stable production release actually available** from the approved source
     (not only the version currently pinned here).

## Mandatory review cycle

Every exception is re-evaluated at the **earliest** of:
- 3 months after the last review, or
- a new `stableYYMM` release of `polkadot-sdk`, or
- any `Cargo.lock` change touching the excepted package's version or entry path.

An exception past its review date without renewal **automatically fails the gate**; it is not treated as
"PASS with documented exceptions" until the review is explicitly renewed.

---

## Active exceptions

> **Note (2026-09-19):** the "entry path / verification" text of entries 1–4 below is historical (written on
> `polkadot-stable2506-12`). The repository is on `polkadot-stable2606-2` today; the four packages still exist at the
> same versions (verified with `cargo audit` on 2026-09-19). The full current status (vulnerabilities, lock-only,
> proposed exceptions) is in the "Status of `polkadot-stable2606-2`" section below.

### 1. `libsecp256k1` 0.7.2 — RUSTSEC-2025-0161

- **Type:** `unmaintained` (no RUSTSEC of type `vulnerability` for this package at review time).
- **Advisory:** 2025-01-14 — "libsecp256k1 is unmaintained"; suggested alternative: `k256` (a general maintainer
  recommendation, not applicable here because it is consumed through `sp-core` itself, not chosen directly by us).
- **Entry path:** `sp-core` (from `polkadot-sdk`) → consumed in `madar-protocol` through `frame-system`/`sp-*`.
- **No safe alternative:** confirmed by `cargo audit` / `cargo deny` ("No safe upgrade is available!").
- **Verified against the latest production SDK:** still present at exactly the same version (0.7.2), including in
  `polkadot-stable2606-2`.
- **Last review:** 2026-09-18, by the project owner (explicit approval).
- **Next mandatory review:** 2026-12-17, a new `polkadot-sdk stableYYMM`, or a change of this package's
  version/path in `Cargo.lock` — whichever comes first.

### 2. `parity-wasm` 0.45.0 — RUSTSEC-2022-0061

- **Type:** `unmaintained` (no RUSTSEC of type `vulnerability`).
- **Advisory:** 2022-10-01 — "Crate `parity-wasm` deprecated by the author"; suggested alternative: `wasm-tools`
  (the author's own decision within `polkadot-sdk`, outside this repository's control).
- **Entry path:** `sp-version` (from `polkadot-sdk`) → `frame-system`/`sp-api`, within the default `std` feature.
- **No safe alternative:** confirmed ("No safe upgrade is available!").
- **Verified against the latest production SDK:** still present at exactly the same version (0.45.0), including in
  `polkadot-stable2606-2`.
- **Last review:** 2026-09-18, by the project owner (explicit approval).
- **Next review:** 2026-12-17, a new SDK release or a Cargo.lock change — whichever comes first.

### 3. `paste` 1.0.15 — RUSTSEC-2024-0436

- **Type:** `unmaintained` (no RUSTSEC of type `vulnerability`).
- **Advisory:** 2024-10-07 — "paste - no longer maintained"; the repository is archived. Suggested alternatives:
  `pastey` (fork), `with_builtin_macros` — neither applicable, because it is used directly by `frame-support`/`sp-core`.
- **Entry path:** a proc-macro used directly (not optionally) by `frame-support` and `sp-core` (from `polkadot-sdk`).
- **No safe alternative:** confirmed ("No safe upgrade is available!").
- **Verified against the latest production SDK:** still present at exactly the same version (1.0.15), even in
  `polkadot-stable2606-2` and the `master` development branch — no announced removal plan.
- **Last review:** 2026-09-18, by the project owner (explicit approval).
- **Next review:** 2026-12-17, a new SDK release or a Cargo.lock change — whichever comes first.

### 4. `proc-macro-error` 1.0.4 — RUSTSEC-2024-0370

- **Type:** `unmaintained` (no RUSTSEC of type `vulnerability`).
- **Advisory:** 2024-09-01 — maintenance stopped (no commits for two years, no releases for four). Suggested
  alternatives: `manyhow`, `proc-macro2-diagnostics` — not applicable, because it is consumed via `aquamarine`
  (a documentation dependency inside `frame-support` itself).
- **Entry path:** `aquamarine` → `frame-support` (from `polkadot-sdk`).
- **No safe alternative:** confirmed ("No safe upgrade is available!").
- **Verified against the latest production SDK:** still present at exactly the same version (1.0.4), also in
  `polkadot-stable2606-2` / `master` — no announced removal plan.
- **Last review:** 2026-09-18, by the project owner (explicit approval).
- **Next review:** 2026-12-17, a new SDK release or a Cargo.lock change — whichever comes first.

### 5. `fxhash` 0.2.1 — RUSTSEC-2025-0057 (temporary, approved 2026-09-19)

- **Type:** `unmaintained` only (no RUSTSEC of type `vulnerability`). The advisory's suggested alternative: `rustc-hash`.
- **Entry path (forced by the SDK):** `sc-executor-wasmtime` → `wasmtime` 36 (the `profiling` feature is enabled
  unconditionally in `sc-executor-wasmtime/Cargo.toml`) → `fxprof-processed-profile` 0.6 → `fxhash`.
- **Actual state:** compiled but **never executed**: the only two strategies (`jitdump`/`perfmap` via
  `WASMTIME_PROFILING_STRATEGY`) do not go through it.
- **Accepted risk:** future lack of maintenance of a package that is not executed; FxHash is not collision-resistant,
  but no untrusted input reaches it.
- **Why there is no alternative now:** there is no stable SDK tag newer than `polkadot-stable2606-2`; the feature cannot
  be disabled on our side; `[patch]` is forbidden.
- **Scope:** version `0.2.1` only; it does not extend automatically to any other version.
- **Removal condition:** as soon as `sc-executor-wasmtime` stops enabling `profiling` or upgrades wasmtime to a version
  without `fxhash` (checked with `cargo tree -i fxhash` at every SDK upgrade) — the line in `deny.toml` and the entry
  here are removed in the same commit.
- **Last review:** 2026-09-19 (owner approval). **Next:** 2026-12-17, a new SDK `stableYYMM` or a package version
  change — whichever comes first.

### 6. `instant` 0.1.13 — RUSTSEC-2024-0384 (temporary, approved 2026-09-19)

- **Type:** `unmaintained` only. Suggested alternative: `web-time`.
- **Entry path (forced by the SDK):** `sc-network` → `wasm-timer` 0.2.5 → `parking_lot` 0.11.2 (and
  `parking_lot_core` 0.8.6) → `instant`.
- **Actual state:** on native hardware it is `pub type Instant = std::time::Instant` (no logic of its own).
- **Accepted risk:** lack of maintenance of a thin wrapper over `std`; no external input, memory handling or cryptography.
- **Why there is no alternative now:** `wasm-timer` sits inside `sc-network` (SDK) and is not an optional feature; no
  newer tag; `[patch]` is forbidden.
- **Scope:** version `0.1.13` only; it does not extend automatically to any other version.
- **Removal condition:** as soon as the SDK replaces `wasm-timer` or upgrades it to a version without
  `parking_lot 0.11`/`instant` (`cargo tree -i instant`) — the line and the entry are removed in the same commit.
- **Last review:** 2026-09-19 (owner approval). **Next:** 2026-12-17, a new SDK `stableYYMM` or a package version
  change — whichever comes first.

---

## License exception (licenses, not advisories) — `option-ext` 0.2.0 (MPL-2.0)

Added with the D40 upgrade (2026-09-18) — a different category from the `[advisories]` exceptions above
(`cargo deny check licenses`, not `check advisories`), documented with the same transparency:

- **Package:** `option-ext` 0.2.0, license `MPL-2.0` (not in the default `allow` list — a weak file-level copyleft,
  legally unproblematic for an Apache-2.0 project, but it requires an explicit entry under our policy).
- **Entry path:** [build-dependencies] only — `substrate-wasm-builder` → `polkavm-linker` → `dirs` → `dirs-sys` →
  `option-ext`. A build tool that runs only on the development machine/CI and is **never shipped or linked** into any
  binary or WASM runtime we produce.
- **Decision:** an exception via `[[licenses.exceptions]]` in `deny.toml` (scoped to this package only; MPL-2.0 is not
  added to the global `allow` list).
- **Why it is not a blocker:** a pure host build tool that does not touch shipped or licensed code; no security risk
  and no obligation on our code (MPL-2.0 only obliges modifications of that package's own files, if modified and
  published — not applicable here).
- **Added:** 2026-09-18. **Reviewed by:** the project owner (as part of approving the D40 upgrade).

---

## Status of `polkadot-stable2606-2` (the SDK actually pinned now) — review item #19, 2026-09-19

> The sections above were originally written on `stable2409` and then `stable2506-12`; the repository is now on
> **`polkadot-stable2606-2`** (the tag of every crate). This review repeated the actual checks (`cargo audit --json` +
> `cargo deny check advisories` + inspecting what is **actually compiled** in `target/`, not a theoretical reading).
> The four exceptions above still exist at the same versions on this tag (`cargo audit` lists them).
> Latest remote SDK tags at review time: `polkadot-stable2606-1/-2` and `polkadot-stable2609-rc1/-rc2` (no stable
> release newer than 2606-2).
>
> **Re-verified 2026-09-28:** `cargo audit` shows the same seven vulnerabilities at the same versions (nothing new),
> and `cargo tree --workspace -e all --target all` confirms that `h2`/`ring`/`rustls-webpki` are not compiled into any
> workspace member. The latest stable tag is still `2606-2` (`2609` at RC2).

### A) Actual vulnerabilities (Tier 1 — no exception in this register) in compiled code

| Package | Vulnerability | Entry path | Why it cannot be fixed locally | Mitigation applied | Status |
|---|---|---|---|---|---|
| `tracing-subscriber` 0.3.19 | RUSTSEC-2025-0055 — ANSI escape sequence injection into logs from untrusted input (fixed in ≥0.3.20) | `sp-tracing`, `sc-tracing` (node log) | `sp-tracing` pins exactly `=0.3.19` (`cargo update --precise 0.3.20` is rejected by the resolver) | Do not view the raw node log in an interactive terminal; read it through a file/`journalctl` or `cat -v`. Our own tools strip control characters (ESC and others) before writing their logs. | Pre-launch blocker (B8) |
| `hickory-proto` 0.24.4 | RUSTSEC-2026-0119 — CPU exhaustion when encoding a DNS message (fixed in ≥0.26.1) | `libp2p-mdns` and `libp2p-dns` (**libp2p** backend only) | libp2p 0.54.1 is pinned by `sc-network` in the SDK | **The `libp2p` backend is rejected at node startup** (`node/src/command.rs`, tested live); the default `litep2p` uses the fixed `hickory-proto 0.26.3`. The vulnerable code is compiled but cannot run under any supported configuration. | Pre-launch blocker (B8) |

### B) Vulnerabilities present in `Cargo.lock` only — **not compiled** (libp2p features disabled)

`cargo audit` scans `Cargo.lock` as a flat list and therefore reports them; `cargo deny` and the actual compilation do
not include them. Verified two ways: (1) `target/**/deps/*.d` mentions none of them, (2) the compiled `libp2p` includes
only `dns/identify/kad/mdns/noise/ping/request-response/tcp/websocket/yamux` (no `quic`, `tls` or `upnp`).

| Package | Vulnerabilities | Cargo.lock path | Becomes real if… |
|---|---|---|---|
| `h2` 0.3.27 | RUSTSEC-2026-0258 | `libp2p-upnp` → `igd-next` → `hyper` 0.14 | the libp2p `upnp` feature is enabled |
| `ring` 0.16.20 | RUSTSEC-2025-0009 (+ unmaintained RUSTSEC-2025-0010) | `libp2p-quic`/`libp2p-tls` → `rcgen` 0.11 | `quic`/`tls` is enabled |
| `rustls-webpki` 0.101.7 | RUSTSEC-2026-0098, RUSTSEC-2026-0099, RUSTSEC-2026-0104 | `libp2p-tls` | `quic`/`tls` is enabled |
| `derivative` 2.2.0 | unmaintained RUSTSEC-2024-0388 | `w3f-bls` → `ark-*` (`bls-experimental` feature in `sp-core`) | `bls-experimental` is enabled |

**Control:** any change that makes one of them appear in `cargo tree -e all -i <crate>@<version>` or in
`target/**/deps/*.d` immediately moves it to section (A). They are closed for good by an SDK upgrade that updates
libp2p or removes these branches from the lock file.

### C) Unmaintained in compiled code: `fxhash` and `instant` — **approved as temporary Tier-2 exceptions (2026-09-19, owner decision)**

Both were examined in detail (see entries #5 and #6 above): both are compiled, unmaintained only with no vulnerability,
and forced by `polkadot-sdk`; they cannot be removed, upgraded or disabled by a feature without changing the SDK
(`[patch]` is forbidden). They were added to `deny.toml` **by package and version** (`fxhash@0.2.1`, `instant@0.1.13`)
with the advisory ID, so any other version that appears in the future is **not covered** by the exception and fails the
gate. No vulnerability is hidden by them (`tracing-subscriber`, `hickory-proto` and the others still fail the gate).

### D) Unsound (`cargo audit` warnings of type `unsound`; not announced vulnerabilities)

| Package | ID | Path | Assessment |
|---|---|---|---|
| `lru` 0.12.5 | RUSTSEC-2026-0002, RUSTSEC-2026-0253 | `libp2p-identify`, `libp2p-swarm` | libp2p backend only ⇒ not executable (the backend is rejected, see A) |
| `lru` 0.7.8 | RUSTSEC-2026-0253 | `tracing-log` (interest-cache feature) | SDK; none of our code uses it directly |
| `memmap2` 0.5.10 | RUSTSEC-2026-0186 | `parity-db` 0.4.13 | the optional ParityDB database; the default setting is RocksDB |

### Full closure condition (B8)

Upgrade `polkadot-sdk` to a tag that updates `sp-tracing` (≥ `tracing-subscriber` 0.3.20) and `libp2p` (hickory ≥
0.26.1) — the closest observed is `stable2609` (currently RC only) — then rerun `cargo audit` and `cargo deny check`
and close (C) by owner decision. No local patch of `tracing-subscriber` (hiding the finding by changing the package
source without changing the affected code is not acceptable, and a local fork of an external package increases the
security-maintenance burden).

---

## Deliberately excluded from this register

### `derivative` 2.2.0 — RUSTSEC-2024-0388

**Not excepted and not listed here as an active exception.** It appears in `cargo audit` (which scans `Cargo.lock` as a
flat list regardless of enabled features) but is **absent** from `cargo deny check advisories` (which builds the actual
enabled graph, like `cargo tree`). Confirmed reason: it is reachable only through the optional `bls-experimental` feature
in `sp-core` (`w3f-bls` → `ark-bls12-377/381` → `ark-ec`/`ark-ff`/`ark-poly` → `derivative`), and that feature is **not
enabled** by any package in this workspace. Since it is not active in the actual build there is no reason to except it —
and listing it here would falsely suggest a decision where there is no actual problem. If the feature is ever enabled,
it must be re-evaluated from scratch under the same eligibility conditions before any exception.

---

## Change log of this document

| Date | Change | Decision source |
|---|---|---|
| 2026-09-17 | Register created; the four exceptions above approved | Explicit owner approval of the proposed policy (Tier 1/Tier 2, the three-part rule, review every 3 months or on a new SDK or a Cargo.lock change, whichever comes first) |
| 2026-09-18 | Polkadot SDK upgraded from `polkadot-stable2409` to `polkadot-stable2506-12` (D40) — the four exceptions re-reviewed and confirmed on the new tag (same packages, same versions, still forced); a new license exception added (`option-ext` 0.2.0, MPL-2.0, build dependency only) | Explicit owner approval of the SDK upgrade as the root fix for a WASM build blocker |
| 2026-09-19 | Review #19 on `polkadot-stable2606-2` (current SDK): actual re-verification with `cargo audit`/`cargo deny`/inspection of compiled code; two compiled Tier-1 vulnerabilities (tracing-subscriber, hickory-proto) documented as blocker B8 with operational mitigation; lock-only vulnerabilities separated; detailed review of fxhash/instant. No change to the four approved exceptions | Audit review #19 (no new exception approved) |
| 2026-09-19 | `fxhash@0.2.1` and `instant@0.1.13` approved as temporary Tier-2 exceptions by package and version (entries #5 and #6), without hiding any vulnerability | Explicit owner decision 2026-09-19 |
| 2026-09-19 | `deny.toml` aligned with the documented policy: the license gate failed (46 packages) after moving to SDK 2606; added `ISC` (permissive) and package-name-scoped exemptions for 41 `sc-*` packages (GPL-3.0-or-later WITH Classpath-exception-2.0, approved in `node-licensing.md`) and for `webpki-roots` (MPL-2.0, file-level) — the license is not added to the global allow list | Implementation of an existing policy (D42), not a new policy |
| 2026-09-28 | Periodic re-verification: `cargo audit` + `cargo tree --workspace -e all --target all` — results identical to the 2026-09-19 review (7 vulnerabilities: two compiled with existing mitigation, five lock-only); no newer stable SDK tag (2609 at RC2) | Periodic review (no change to any exception) |
| 2026-10-04 | `webpki-roots` license exception widened (package-scoped) to also allow `CDLA-Permissive-2.0` — the license of its 0.26 / 1.x releases, pulled in by `ureq` in the new `madar-ops` monitor for https alerts. Fully permissive data license (no copyleft); not added to the global allow list | Adding Madar Ops (owner-approved service) |
