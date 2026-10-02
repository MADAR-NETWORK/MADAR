//! Reads chain state **via `MembershipApi`** (T5) at a fixed hash — no decoding of chain storage and no built-in membership constants (only compatibility checks remain).
//! All queries in `Reader` are issued at the same hash, so they are consistent from a single block. No silent fallback path: a Runtime without the API or with an unsupported version is rejected with a clear message.

use super::rpc::Transport;
use super::status::{ChainView, Params};
use madar_admission_api::{
    AdmissionParamsV1, MembershipStatusV1, PuzzleChallengeV1, API_NAME, SUPPORTED_API_VERSION,
};
use madar_consensus::{madar_admission, AccountId, Runtime, VERSION};
use parity_scale_codec::{Decode, Encode};
use serde_json::json;

pub struct Reader<'a> {
    pub t: &'a dyn Transport,
    /// The block hash (`0x…`) at which all answers are read.
    pub at: String,
}

/// The API identifier in the `apis` list (blake2_64 of its name).
fn api_id_hex() -> String {
    format!(
        "0x{}",
        hex::encode(sp_crypto_hashing::blake2_64(API_NAME.as_bytes()))
    )
}

/// Extracts the API version number from the `state_getRuntimeVersion` response (`apis: [[id, version], …]`).
pub fn api_version_in(runtime_version: &serde_json::Value) -> Option<u32> {
    let id = api_id_hex();
    runtime_version
        .get("apis")?
        .as_array()?
        .iter()
        .find_map(|e| {
            let pair = e.as_array()?;
            if pair.first()?.as_str()? == id {
                pair.get(1).and_then(|v| v.as_u64()).map(|v| v as u32)
            } else {
                None
            }
        })
}

/// Admission parameters compiled into this executable (for the compatibility check before solving the puzzle only — not for displaying state).
pub fn compiled_puzzle_params() -> (u32, u32, u32) {
    use frame_support::traits::Get;
    (
        <<Runtime as madar_admission::Config>::DifficultyLeadingZeroBits as Get<u32>>::get(),
        <<Runtime as madar_admission::Config>::ArgonMemoryCostKib as Get<u32>>::get(),
        <<Runtime as madar_admission::Config>::ArgonTimeCost as Get<u32>>::get(),
    )
}

impl<'a> Reader<'a> {
    /// Pins the current best block and verifies that the Runtime there supports the API at an understood version and with a transaction version compatible with the signing format in this executable.
    pub fn at_best(t: &'a dyn Transport) -> Result<Reader<'a>, String> {
        let at = t
            .call("chain_getBlockHash", json!([]))?
            .as_str()
            .ok_or("No hash for the best block")?
            .to_string();
        let r = Reader { t, at };
        r.check_compatibility()?;
        Ok(r)
    }

    fn check_compatibility(&self) -> Result<(), String> {
        let v = self.t.call("state_getRuntimeVersion", json!([self.at]))?;
        let spec = v.get("specVersion").and_then(|s| s.as_u64()).unwrap_or(0);
        match api_version_in(&v) {
            None => {
                return Err(format!(
                    "This network's Runtime (spec {spec}) does not declare the interface {API_NAME} — either it is older than this tool (upgrade the network) or it is not a compatible MADAR network. I will not guess the storage layout."
                ))
            },
            Some(ver) if ver != SUPPORTED_API_VERSION => {
                return Err(format!(
                    "The network's {API_NAME} interface version ({ver}) differs from the version this tool understands ({SUPPORTED_API_VERSION}) — update madar-node."
                ))
            },
            Some(_) => {},
        }
        // The signed transaction format is built into this executable: a change to it (transaction_version) requires a new tool; spec_version alone does not (that is the point of the API).
        let tx = v
            .get("transactionVersion")
            .and_then(|s| s.as_u64())
            .unwrap_or(0) as u32;
        if tx != VERSION.transaction_version {
            return Err(format!(
                "transaction_version on the network ({tx}) ≠ the one this executable signs with ({}) — update madar-node before submitting anything.",
                VERSION.transaction_version
            ));
        }
        Ok(())
    }

    fn call<T: Decode>(&self, method: &str, args: Vec<u8>) -> Result<T, String> {
        self.call_named(&format!("{API_NAME}_{method}"), args)
    }

    /// `state_call` with a full name (for standard SDK APIs) at the pinned hash.
    fn call_named<T: Decode>(&self, full: &str, args: Vec<u8>) -> Result<T, String> {
        let raw = self.t.call(
            "state_call",
            json!([full, format!("0x{}", hex::encode(args)), self.at]),
        )?;
        let bytes = hex::decode(
            raw.as_str()
                .ok_or("state_call response is not a string")?
                .trim_start_matches("0x"),
        )
        .map_err(|_| "Invalid state_call response")?;
        T::decode(&mut &bytes[..]).map_err(|_| {
            format!("Could not decode the {full} response (did the API version or type change?)")
        })
    }

    pub fn status(&self, who: &AccountId) -> Result<MembershipStatusV1, String> {
        self.call("membership_status", who.encode())
    }

    pub fn params(&self) -> Result<AdmissionParamsV1, String> {
        self.call("admission_params", vec![])
    }

    pub fn challenge(&self) -> Result<PuzzleChallengeV1, String> {
        self.call("puzzle_challenge", vec![])
    }

    /// The BABE authorities (current Epoch) and GRANDPA authorities active now, via the standard SDK APIs (no raw storage).
    pub fn authorities(&self) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>), String> {
        let epoch: sp_consensus_babe::Epoch = self.call_named("BabeApi_current_epoch", vec![])?;
        let babe = epoch
            .authorities
            .iter()
            .map(|(a, _)| {
                let b: &[u8] = a.as_ref();
                <[u8; 32]>::try_from(b).unwrap_or([0u8; 32])
            })
            .collect();
        let grandpa: Vec<([u8; 32], u64)> =
            self.call_named("GrandpaApi_grandpa_authorities", vec![])?;
        Ok((babe, grandpa.into_iter().map(|(k, _)| k).collect()))
    }

    /// Does the RPC node's Keystore own these (encoded) keys? `None` = could not check (unsafe RPC disabled).
    pub fn node_has_keys(&self, encoded: &[u8]) -> Option<bool> {
        self.t
            .call(
                "author_hasSessionKeys",
                json!([format!("0x{}", hex::encode(encoded))]),
            )
            .ok()
            .and_then(|r| r.as_bool())
    }

    /// The state as the `status` module needs it, plus its parameters, with a check that the node owns the session keys (unsafe RPC; stays unknown if unavailable).
    pub fn view(&self, who: &AccountId) -> Result<(ChainView, Params), String> {
        let s = self.status(who)?;
        let p = self.params()?;
        let keys_held_by_node = s.session_keys.as_ref().and_then(|k| {
            self.t
                .call(
                    "author_hasSessionKeys",
                    json!([format!("0x{}", hex::encode(k))]),
                )
                .ok()
                .and_then(|r| r.as_bool())
        });
        Ok((
            ChainView {
                current_session: s.current_session,
                member: s.is_member,
                active: s.is_active_authority,
                expiry: s.expiry_session,
                banned: s.is_banned,
                exit_pending: s.exit_pending,
                keys_registered: s.session_keys.is_some(),
                keys_held_by_node,
                candidate: s.is_candidate,
            },
            Params {
                term: p.membership_term_sessions,
                grace: p.renewal_grace_sessions,
            },
        ))
    }

    /// Are the puzzle parameters on the network the same ones this tool compiles for solving? (Solving uses the compiled Pallet function; we never produce a solution with different parameters.)
    /// Returns the **current network difficulty** (bits) to solve the puzzle with. The difficulty is read from the chain (`MembershipApi`), not from the compiled code, so the tool works
    /// before and after an upgrade that changes the difficulty without a rebuild. The Argon2 parameters (memory/iterations) define the function itself, so they must match the compiled ones.
    pub fn ensure_puzzle_params_match(&self) -> Result<u32, String> {
        let p = self.params()?;
        let (_, m, t) = compiled_puzzle_params();
        if (p.argon_memory_kib, p.argon_time_cost) != (m, t) {
            return Err(format!(
                "Argon2 parameters on the network ({} KiB × {}) ≠ those compiled into this executable ({m} KiB × {t}) — update madar-node before solving the puzzle (a solution with wrong parameters wastes time and is rejected).",
                p.argon_memory_kib, p.argon_time_cost
            ));
        }
        Ok(p.puzzle_difficulty_bits)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A mock transport that simulates `state_call` at a given hash and records the hash used in every call.
    pub struct Mock {
        pub version: serde_json::Value,
        pub status: MembershipStatusV1,
        pub params: AdmissionParamsV1,
        pub challenge: PuzzleChallengeV1,
        pub has_keys: Option<bool>,
        pub seen_at: Mutex<Vec<String>>,
    }
    impl Transport for Mock {
        fn call(&self, method: &str, p: serde_json::Value) -> Result<serde_json::Value, String> {
            match method {
                "chain_getBlockHash" => Ok(json!("0xaaaa")),
                "state_getRuntimeVersion" => Ok(self.version.clone()),
                "state_call" => {
                    self.seen_at
                        .lock()
                        .unwrap()
                        .push(p[2].as_str().unwrap().to_string());
                    let enc = match p[0].as_str().unwrap() {
                        "MembershipApi_membership_status" => self.status.encode(),
                        "MembershipApi_admission_params" => self.params.encode(),
                        "MembershipApi_puzzle_challenge" => self.challenge.encode(),
                        m => return Err(format!("unknown {m}")),
                    };
                    Ok(json!(format!("0x{}", hex::encode(enc))))
                }
                "author_hasSessionKeys" => self
                    .has_keys
                    .map(|b| json!(b))
                    .ok_or_else(|| "unsafe RPC disabled".to_string()),
                m => Err(format!("unexpected {m}")),
            }
        }
    }

    pub fn version_json(api_ver: Option<u32>, tx: u32) -> serde_json::Value {
        let apis = match api_ver {
            Some(v) => json!([["0x0000000000000000", 1], [api_id_hex(), v]]),
            None => json!([["0x0000000000000000", 1]]),
        };
        json!({"specVersion": 7, "transactionVersion": tx, "apis": apis})
    }

    pub fn mock(api_ver: Option<u32>, tx: u32) -> Mock {
        let (d, m, t) = compiled_puzzle_params();
        Mock {
            version: version_json(api_ver, tx),
            status: MembershipStatusV1 {
                current_session: 12,
                is_member: true,
                is_active_authority: false,
                expiry_session: Some(15),
                is_banned: false,
                exit_pending: true,
                is_candidate: false,
                session_keys: Some(vec![1, 2, 3]),
            },
            params: AdmissionParamsV1 {
                membership_term_sessions: 9,
                renewal_grace_sessions: 3,
                puzzle_difficulty_bits: d,
                argon_memory_kib: m,
                argon_time_cost: t,
                max_validators: 10,
                max_candidates_per_round: 4,
                admission_cap_per_round: 2,
                min_fresh_entropy_blocks: 4,
                epoch_duration_slots: 12,
            },
            challenge: PuzzleChallengeV1 {
                round_seed: sp_core::H256::repeat_byte(5),
                current_session: 12,
                epoch_start_slot: 100,
                epoch_duration_slots: 12,
                current_slot: 103,
            },
            has_keys: Some(true),
            seen_at: Mutex::new(vec![]),
        }
    }

    fn who() -> AccountId {
        AccountId::from([7u8; 32])
    }

    #[test]
    fn a_view_comes_from_the_api_at_one_pinned_block_and_uses_the_chains_parameters() {
        let m = mock(Some(1), VERSION.transaction_version);
        let r = Reader::at_best(&m).unwrap();
        let (v, p) = r.view(&who()).unwrap();
        assert!(
            v.member && v.exit_pending && v.keys_registered && v.keys_held_by_node == Some(true)
        );
        assert_eq!((v.current_session, v.expiry), (12, Some(15)));
        assert_eq!(
            (p.term, p.grace),
            (9, 3),
            "term/grace come from the chain, not from constants compiled into the tool"
        );
        assert!(
            m.seen_at.lock().unwrap().iter().all(|a| a == "0xaaaa")
                && m.seen_at.lock().unwrap().len() == 2,
            "every query at the same block hash"
        );
        assert_eq!(r.challenge().unwrap().slots_remaining(), 9);
    }

    #[test]
    fn a_runtime_without_the_api_or_with_another_version_or_tx_format_is_refused_clearly() {
        let no_api = Reader::at_best(&mock(None, VERSION.transaction_version))
            .err()
            .unwrap();
        assert!(
            no_api.contains("does not declare the interface") && no_api.contains("will not guess"),
            "{no_api}"
        );
        let other = Reader::at_best(&mock(Some(2), VERSION.transaction_version))
            .err()
            .unwrap();
        assert!(
            other.contains("differs from the version") && other.contains("update"),
            "{other}"
        );
        let tx = Reader::at_best(&mock(Some(1), VERSION.transaction_version + 1))
            .err()
            .unwrap();
        assert!(tx.contains("transaction_version"), "{tx}");
        // spec_version alone (7 in the mock ≠ the compiled one) does not block: that is the point of the API.
        assert!(Reader::at_best(&mock(Some(1), VERSION.transaction_version)).is_ok());
    }

    #[test]
    fn puzzle_parameter_drift_is_detected_before_solving() {
        let mut m = mock(Some(1), VERSION.transaction_version);
        let bits = m.params.puzzle_difficulty_bits;
        assert_eq!(
            Reader::at_best(&m).unwrap().ensure_puzzle_params_match(),
            Ok(bits)
        );
        // The difficulty follows the network (an upgrade that changes it does not break the tool).
        m.params.puzzle_difficulty_bits += 1;
        assert_eq!(
            Reader::at_best(&m).unwrap().ensure_puzzle_params_match(),
            Ok(bits + 1)
        );
        // The Argon2 parameters define the function itself: a mismatch is rejected.
        m.params.argon_memory_kib += 1;
        let e = Reader::at_best(&m)
            .unwrap()
            .ensure_puzzle_params_match()
            .unwrap_err();
        assert!(e.contains("update madar-node"), "{e}");
    }

    #[test]
    fn the_api_id_is_the_blake2_64_of_its_name_as_the_runtime_advertises_it() {
        assert_eq!(api_id_hex().len(), 2 + 16);
        assert_eq!(api_version_in(&version_json(Some(1), 1)), Some(1));
        assert_eq!(api_version_in(&version_json(None, 1)), None);
    }
}
