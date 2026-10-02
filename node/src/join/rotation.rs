//! Rotating session keys when moving to another machine (T6): generate new keys inside the Keystore of **the new node**, register them with the existing permission (`set_keys`),
//! follow the registration, wait for actual activation (both new keys appearing among the current BABE/GRANDPA authorities), then confirm the old machine's keys are no longer an authority.
//! **No new key copy/encryption system**: private keys never leave the node's Keystore. Nothing is deleted (old keys stay until the operator decides after activation).
//!
//! **Safe restart:** before any submission a public "intent" (public keys + proof of ownership + the old chain keys) is written to a file next to the account file; on
//! restart it resumes from the actual state (chain + node Keystore), not from memory: no duplicate generation, no double registration, no deletion.
//! The decision (`decide`) is a pure function tested with a table of cases.

use madar_consensus::SessionKeys;
use parity_scale_codec::Decode;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A rotation intent: **public** data only (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    /// The chain's (registered) keys before rotation, Hex.
    pub old_keys: Option<String>,
    /// The new keys generated in the new node's Keystore, Hex.
    pub new_keys: String,
    /// Proof that the account owns the new keys (a signature, not a secret), Hex.
    pub proof: String,
    pub created_at_session: u32,
}

pub fn intent_path(account_file: &Path) -> PathBuf {
    account_file.with_extension("rotation.json")
}

pub fn read_intent(path: &Path) -> Result<Option<Intent>, String> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| format!("The rotation intent file {} is corrupt ({e}) — delete it manually if you are sure no rotation is in progress", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("Could not read {}: {e}", path.display())),
    }
}

/// Atomic write (temporary file then rename) so no half-written file is left behind on interruption.
pub fn write_intent(path: &Path, i: &Intent) -> Result<(), String> {
    let tmp = path.with_extension("rotation.json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(i).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("Could not write the rotation intent: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("Could not commit the rotation intent: {e}"))
}

pub fn clear_intent(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// The raw BABE and GRANDPA keys from the `SessionKeys` encoding.
pub fn raw_keys(encoded: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let k = SessionKeys::decode(&mut &encoded[..]).ok()?;
    let babe: &[u8] = k.babe.as_ref();
    let grandpa: &[u8] = k.grandpa.as_ref();
    Some((babe.try_into().ok()?, grandpa.try_into().ok()?))
}

/// Active = both keys are among the current Epoch/set authorities.
pub fn is_active(
    encoded: &[u8],
    babe_authorities: &[[u8; 32]],
    grandpa_authorities: &[[u8; 32]],
) -> bool {
    raw_keys(encoded).map_or(false, |(b, g)| {
        babe_authorities.contains(&b) && grandpa_authorities.contains(&g)
    })
}

pub struct Inputs<'a> {
    /// The `set_keys` keys currently registered on chain (`None` = no keys).
    pub onchain: Option<&'a [u8]>,
    pub intent: Option<&'a Intent>,
    /// Does this node's Keystore own the keys registered on chain? (`None` = could not verify)
    pub node_holds_onchain: Option<bool>,
    /// Does this node's Keystore own the intent keys?
    pub node_holds_intent: Option<bool>,
    pub babe_active: &'a [[u8; 32]],
    pub grandpa_active: &'a [[u8; 32]],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The chain keys are this node's keys and are active: nothing to do (and this is a safe rerun of a completed rotation).
    Done,
    /// Registered for this node and awaiting activation (authors change after two sessions).
    WaitActivation,
    /// Generate new keys in this node, then register them.
    GenerateAndRegister,
    /// The intent keys are in this node's Keystore but not registered yet: resubmit `set_keys` with the stored ones (no generation).
    RegisterIntent,
    Refuse(String),
}

pub fn decide(i: &Inputs) -> Step {
    let Some(onchain) = i.onchain else {
        return Step::Refuse("No session keys are registered for this account — rotation replaces existing keys; use join register-keys first.".into());
    };
    if i.node_holds_onchain == Some(true) {
        return if is_active(onchain, i.babe_active, i.grandpa_active) {
            Step::Done
        } else {
            Step::WaitActivation
        };
    }
    if let Some(intent) = i.intent {
        let intent_bytes =
            hex::decode(intent.new_keys.trim_start_matches("0x")).unwrap_or_default();
        if intent_bytes == onchain {
            return Step::Refuse(
                "The keys registered on chain belong to a previous rotation, but this node's Keystore does not own them — you are on the wrong node, or the Keystore was lost. Nothing is deleted; check the correct node, or generate new keys by deleting the intent file once you are sure.".into(),
            );
        }
        return match i.node_holds_intent {
            Some(true) => Step::RegisterIntent,
            Some(false) => Step::GenerateAndRegister, // stale intent whose Keystore is gone: generate afresh
            None => Step::Refuse("Could not verify the node's Keystore (author_hasSessionKeys) — enable --rpc-methods unsafe on Loopback".into()),
        };
    }
    match i.node_holds_onchain {
        Some(false) => Step::GenerateAndRegister,
        _ => Step::Refuse("Could not verify that this node owns the registered session keys (author_hasSessionKeys) — enable --rpc-methods unsafe on Loopback".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use madar_consensus::SessionKeys;
    use parity_scale_codec::Encode;

    fn keys(seed: u8) -> Vec<u8> {
        SessionKeys {
            babe: sp_core::sr25519::Public::from_raw([seed; 32]).into(),
            grandpa: sp_core::ed25519::Public::from_raw([seed; 32]).into(),
        }
        .encode()
    }
    fn intent(new: &[u8], old: Option<&[u8]>) -> Intent {
        Intent {
            old_keys: old.map(hex::encode),
            new_keys: hex::encode(new),
            proof: "aa".into(),
            created_at_session: 3,
        }
    }

    #[test]
    fn active_means_both_keys_are_in_the_current_authority_sets() {
        let k = keys(9);
        assert!(is_active(&k, &[[9; 32]], &[[9; 32]]));
        assert!(!is_active(&k, &[[9; 32]], &[[1; 32]]), "grandpa missing");
        assert!(!is_active(&k, &[], &[[9; 32]]), "babe missing");
        assert!(
            !is_active(&[1, 2, 3], &[[9; 32]], &[[9; 32]]),
            "garbage never counts as active"
        );
    }

    fn inputs<'a>(
        onchain: Option<&'a [u8]>,
        intent: Option<&'a Intent>,
        holds_on: Option<bool>,
        holds_int: Option<bool>,
        b: &'a [[u8; 32]],
        g: &'a [[u8; 32]],
    ) -> Inputs<'a> {
        Inputs {
            onchain,
            intent,
            node_holds_onchain: holds_on,
            node_holds_intent: holds_int,
            babe_active: b,
            grandpa_active: g,
        }
    }

    #[test]
    fn the_decision_table_covers_first_run_interruptions_and_completion() {
        let (old, new) = (keys(1), keys(2));
        // No registered keys: refused (the correct path is register-keys).
        assert!(
            matches!(decide(&inputs(None, None, None, None, &[], &[])), Step::Refuse(m) if m.contains("register-keys"))
        );
        // First run on a new machine: this node's Keystore does not own the chain keys ⇒ generate and register.
        assert_eq!(
            decide(&inputs(
                Some(&old),
                None,
                Some(false),
                None,
                &[[1; 32]],
                &[[1; 32]]
            )),
            Step::GenerateAndRegister
        );
        // Interrupted after generation and before/during submission: the intent exists, the Keystore owns it, and the chain is still on the old keys ⇒ resubmit without generation.
        let it = intent(&new, Some(&old));
        assert_eq!(
            decide(&inputs(
                Some(&old),
                Some(&it),
                Some(false),
                Some(true),
                &[[1; 32]],
                &[[1; 32]]
            )),
            Step::RegisterIntent
        );
        // Stale intent and the Keystore lost its keys ⇒ generate afresh (no getting stuck on a dead intent).
        assert_eq!(
            decide(&inputs(
                Some(&old),
                Some(&it),
                Some(false),
                Some(false),
                &[[1; 32]],
                &[[1; 32]]
            )),
            Step::GenerateAndRegister
        );
        // Registered (chain = the new keys and this node owns them) but not active yet ⇒ wait; the old keys are still the authority.
        assert_eq!(
            decide(&inputs(
                Some(&new),
                Some(&it),
                Some(true),
                Some(true),
                &[[1; 32]],
                &[[1; 32]]
            )),
            Step::WaitActivation
        );
        // Activated (both new keys among the authorities) ⇒ complete; rerunning the command afterwards is safe (nothing to do).
        assert_eq!(
            decide(&inputs(
                Some(&new),
                Some(&it),
                Some(true),
                Some(true),
                &[[2; 32]],
                &[[2; 32]]
            )),
            Step::Done
        );
        // The chain is on the intent keys but this node does not own them ⇒ wrong node: explicit refusal without deletion.
        assert!(
            matches!(decide(&inputs(Some(&new), Some(&it), Some(false), Some(false), &[], &[])), Step::Refuse(m) if m.contains("wrong node"))
        );
        // Could not verify the Keystore ⇒ no guessing.
        assert!(matches!(
            decide(&inputs(Some(&old), None, None, None, &[], &[])),
            Step::Refuse(_)
        ));
        assert!(matches!(
            decide(&inputs(Some(&old), Some(&it), Some(false), None, &[], &[])),
            Step::Refuse(_)
        ));
    }

    #[test]
    fn the_intent_file_is_public_data_written_atomically_and_survives_restarts() {
        let dir = std::env::temp_dir().join(format!("madar-rot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let acct = dir.join("me.enc");
        let p = intent_path(&acct);
        assert_eq!(read_intent(&p).unwrap(), None);
        let i = intent(&keys(2), Some(&keys(1)));
        write_intent(&p, &i).unwrap();
        assert_eq!(read_intent(&p).unwrap(), Some(i.clone()));
        assert!(
            !p.with_extension("rotation.json.tmp").exists(),
            "no half-written temp left"
        );
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            !text.to_lowercase().contains("mnemonic")
                && !text.contains("secret")
                && !text.contains("seed"),
            "public data only"
        );
        std::fs::write(&p, b"{corrupt").unwrap();
        assert!(
            read_intent(&p).is_err(),
            "a corrupt intent is reported, never silently replaced"
        );
        clear_intent(&p);
        assert_eq!(read_intent(&p).unwrap(), None);
    }
}
