//! `SessionKeys` (BABE=sr25519 + GRANDPA=ed25519, D8) — proof of type separation
//! (a further generalization of the corrected INV-7/IDN-1 to the level of the full session key
//! bundle, not just the individual account).

use madar_consensus::SessionKeys;
use sp_core::{ed25519, sr25519, Pair};
use sp_runtime::{traits::OpaqueKeys, RuntimeAppPublic};

fn sample_keys() -> SessionKeys {
    let babe_pair = sr25519::Pair::from_seed(&[11u8; 32]);
    let grandpa_pair = ed25519::Pair::from_seed(&[22u8; 32]);
    SessionKeys {
        babe: babe_pair.public().into(),
        grandpa: grandpa_pair.public().into(),
    }
}

#[test]
fn session_keys_expose_exactly_two_distinct_key_type_ids() {
    let ids = SessionKeys::key_ids();
    assert_eq!(
        ids.len(),
        2,
        "SessionKeys must expose exactly BABE + GRANDPA, nothing else at this phase"
    );
    assert_ne!(
        ids[0], ids[1],
        "BABE and GRANDPA key-type IDs must be distinct"
    );
}

/// Actual proof that the BABE (sr25519) and GRANDPA (ed25519) key bytes within the same
/// `SessionKeys` bundle cannot be read interchangeably — each type identifier (KeyTypeId)
/// returns only its own correct key bytes.
#[test]
fn babe_and_grandpa_raw_bytes_are_never_interchangeable_within_session_keys() {
    let keys = sample_keys();

    let babe_id = sp_consensus_babe::AuthorityId::ID;
    let grandpa_id = sp_consensus_grandpa::AuthorityId::ID;

    let babe_raw = keys.get_raw(babe_id);
    let grandpa_raw = keys.get_raw(grandpa_id);

    assert_ne!(
        babe_raw, grandpa_raw,
        "IDN-1/INV-7 (SessionKeys generalization): the BABE and GRANDPA keys must not match byte-wise within the same session bundle"
    );

    let decoded_babe: sp_consensus_babe::AuthorityId = keys
        .get(babe_id)
        .expect("babe key must decode under its own KeyTypeId");
    assert_eq!(decoded_babe, keys.babe);

    let decoded_grandpa: sp_consensus_grandpa::AuthorityId = keys
        .get(grandpa_id)
        .expect("grandpa key must decode under its own KeyTypeId");
    assert_eq!(decoded_grandpa, keys.grandpa);

    // An attempt to read the GRANDPA key interpreted as a BABE structure (and vice versa) must not
    // return the same correct value by mistake.
    let babe_misread_as_grandpa: Option<sp_consensus_grandpa::AuthorityId> = keys.get(babe_id);
    assert_ne!(babe_misread_as_grandpa, Some(keys.grandpa.clone()));
}

/// D11/D12 (locked in advance, Protocol phase): Slot=8s, Epoch=900 — must remain
/// unchanged when actually wired in Consensus, no silent drift.
#[test]
fn locked_slot_and_epoch_constants_are_wired_unchanged() {
    assert_eq!(madar_consensus::SLOT_DURATION_MILLIS, 8_000);
    assert_eq!(madar_consensus::EPOCH_DURATION_IN_SLOTS, 900);
}
