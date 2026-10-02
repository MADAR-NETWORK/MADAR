# MADAR Network — Protocol Specification

**Version: 1.0.1** | **Status: partially frozen (see §0.2 for the explicitly open items)**

> This specification is **independent of the Rust implementation** — it is the formal definition of the network, not a
> description of the code. The Rust code in this repository is the **reference implementation**, not the only
> definition of the network; a third party could in principle build a compatible client from this specification alone.

## 0. Version definition

### 0.1 Source

This document consolidates the original protocol section of the project's design document (v1.0), plus every later
decision that actually affected a field of this specification (for example, D26 fixed the Admission puzzle function,
which was "to be decided" in the original text).

### 0.2 Freeze status — precise, not a blanket claim

| Section | Status | Note |
|---|---|---|
| §1–§8 (encoding, hashing, keys, addresses, genesis hash, domain separation, slot/epoch time) | **Frozen** | Constants locked since genesis; no change without a hard fork |
| §9 (Admission/Weight puzzle) — the cryptographic formula | **Frozen** | Argon2id (D26), implemented and tested |
| §9 — actual weight/benchmark values | **Explicitly open, not frozen** | Development placeholders for now; real measurement on the target hardware (D23) awaits a benchmark phase — **an acknowledged open item, not an oversight** |
| §10 (genesis fields) | **Structurally frozen** (the fields); **their final Mainnet values are not set yet** | Final values (initial validators, etc.) pending §0.3 |
| §11 (invariants) | **Frozen** | INV-1..7 tested across several phases |
| Tokenomics / economics | **Entirely outside the scope of this version** | No economic token/balances are active (D21/D38). `pallet-balances` exists only as infrastructure (D42) |

### 0.3 Items awaiting an explicit external decision or action (not treated as "complete")

- **Admission weight/benchmark values:** see §0.2 above.
- **Tokenomics:** fully deferred.

### 0.4 Version history

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-09-18 | First extraction as a standalone file; §9 updated to reflect D26 (Argon2id) instead of the original "to be decided"; §0 added (version definition / freeze status) |
| 1.0.1 | 2026-10-01 | §5: the network SS58 prefix is **85** since runtime spec 6 (it was the generic Substrate placeholder 42) |

---

## 1. Network identifier (Chain ID / `protocolId`)

A short string in the chain spec, used **only at the libp2p layer** to isolate peer discovery between different
networks. **It is never part of any cryptographic signature.**

## 2. Canonical serialization

**SCALE codec.** Byte-for-byte deterministic, with no additional conversion layers.

## 3. General hash function

**Blake2-256.** Fixed and not open to debate — locked in the Substrate primitives.

> Separate context: hashing of release artifacts uses **SHA-256** specifically (compatible with standard external
> signing tools) — a completely different context, no conflict. See `update/` and `release-tools/`.

## 4. Consensus keys (session keys) — separate from account keys

| Type | Algorithm | Status |
|---|---|---|
| BABE | sr25519 | Mandatory because of the VRF — part of the consensus code, not modified |
| GRANDPA | ed25519 | Mandatory because of the voting algorithm — part of the consensus code, not modified |
| User accounts (default) | sr25519 | Approved (D8); ed25519/ecdsa can additionally be supported via `MultiSigner`/`MultiSignature` without custom code |

**D35 note (entirely separate from this table):** release-signing keys are neither consensus keys nor account keys — a
third, fully independent key space (Ed25519, 2-of-3 multisig architecture).

## 5. Address format

**SS58 as-is, without any modification.** Network prefix: **85** (`madar_protocol::SS58_PREFIX`), active since runtime
spec 6. Local development chains keep the generic prefix 42 (`SS58_PREFIX_DEV`).

## 6. Genesis hash — the actual cryptographic replay protection

The Blake2-256 hash of the complete genesis block, automatically included in every signed transaction via
`CheckGenesis` (`frame_system`, unmodified). A completely different concept from the chain ID (§1).

## 7. Domain separation

| Layer | Existing protection | Extra domain tag? |
|---|---|---|
| Regular transactions | Full `SignedExtra` (`CheckGenesis` + `CheckSpecVersion` + `CheckTxVersion` + `CheckEra` + `CheckNonce`) | No |
| GRANDPA votes | Round number + set ID inside the signed message | No |
| BABE block production | Slot number + epoch randomness inside the VRF | No |
| SS58 checksum | Fixed `"SS58PRE"` context | No |
| **Admission/Weight puzzle** | Nothing exists by default | **Yes:** `madar/admission-puzzle/v1` |

## 8. Slot time and epoch length

**Slot = 8 seconds. Epoch = 900 slots (two hours).** A real constant since genesis — changing it is a hard fork, not a
regular upgrade (D12). Verified in practice via `madar_consensus::{SLOT_DURATION_MILLIS, EPOCH_DURATION_IN_SLOTS}`.

## 9. Admission/Weight puzzle — the full specification (updated per D26)

- **Formula (frozen, implemented):** `Argon2id(pubkey ‖ epoch_seed ‖ nonce)` with a number of leading zeros ≥ a
  threshold (D26) — a real memory-hard function, not plain Blake2-256.
- **Weight:** flat per accepted identity (D6) — not proportional to the strength of the solution.
- **Cryptographic binding:** the solution is bound to `pubkey` + `epoch_seed` + `nonce`.
- **Seed:** BABE's `RandomnessFromOneEpochAgo` (the VRF output of a whole previous epoch, not determined by a single
  block producer). The runtime does not see finality, so the seed is not claimed to come from finalized state; fair
  selection is guaranteed by the lottery at the epoch boundary, not by inclusion timing.
- **Admission cap:** a limited number per epoch, with a fair (VRF) lottery among valid solutions — **the actual number
  is not frozen yet** (see §0.2).
- **Renewal and validity (implemented):** a puzzle of the same difficulty extends `MembershipTermSessions`; it is
  accounted separately from the new-identity cap; after the term ends there is a `RenewalGraceSessions` grace period with
  a warning event, then removal at the epoch boundary — and no removal may empty the set.
- **Voluntary exit:** a signed message; removal at the next epoch boundary.
- **Equivocation:** detected through GRANDPA's Byzantine proof; the key is permanently banned.
- **Isolation from BABE/GRANDPA:** an independent pallet using the standard `SessionManager` — no change to
  `client/consensus/babe` / `client/consensus/grandpa`.
- **Honest, acknowledged gap:** no cryptographic mechanism prevents selling or renting an already-accepted identity key
  — it can only be closed by real stake (outside the scope of this version).
- **Upgrade path:** the weight function can later be replaced by real stake through the same `SessionManager` interface,
  without rebuilding the Byzantine voting layer.

## 10. Genesis — mandatory fields

Chain ID, network prefix (SS58), the initial validator set and weights, the initial seed of the first epoch, slot
duration and epoch length (§8), the initial maximum block/transaction size. Mainnet / Testnet / Dev are completely
separate in: genesis, protocolId, prefix, keys, directories, bootnodes and release channels.

**D42 note (infrastructure, not economics):** `pallet-balances` is structurally enabled (the SDK requires it for
`pallet_session::Config::Currency`) but with no endowment in any genesis preset — `balances: vec![]` in
`consensus/src/genesis_config_presets.rs` and in the tests in `consensus/tests/common/mod.rs`. This **adds no actual
economic field** to this specification.

## 11. Core invariants

| Invariant | Description | Status |
|---|---|---|
| INV-1 | Same input → the same byte-for-byte encoding on any platform/build | Tested |
| INV-2 | A signature valid in one domain always fails in any other domain | Tested |
| INV-3 | A Testnet address is always rejected as a Mainnet address and vice versa | Depends on distinct per-network prefixes |
| INV-4 | A used nonce is never accepted twice for the same account | Tested (`nonce_replay.rs`) |
| INV-5 | Changing one genesis field produces a completely different genesis hash | Implicitly tested through the standard `CheckGenesis` structure |
| INV-6 | An Admission puzzle solution is never accepted for an identity other than the one it was computed for | Tested |
| INV-7 | A BABE key is never accepted as a GRANDPA key or vice versa | Tested (`account_derivation.rs`) |

## 12. Reference files/modules (reference implementation only, not part of the specification itself)

```
protocol/
  ├── chain_spec.rs   // chain ID, genesis fields, network prefix
  └── domains.rs       // the only domain tag: madar/admission-puzzle/v1
```

No custom cryptography files — `sp-core` / `sp-runtime` are used directly.

---

## 13. Towards a conformance suite (outside the scope of v1.0)

Public test vectors and a complete conformance suite are required before Mainnet — they are not done in this version
(v1.0 covers only the frozen textual definition, not a third-party-runnable test suite). This is an explicitly open item
for a later version, not a claim of completeness.
