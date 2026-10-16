//! N1 then spec 9 — the Admission admin calls `ban_key` (2) and `dev_only_force_set_validators` (3) were closed
//! (`EnsureNever`) since N1, and were removed from the Pallet in spec 9. Their indices are never reused: any transaction or committee proposal
//! carrying their bytes does not decode at all (it reaches no logic), and banning stays through Equivocation only (`BanOnOffence`).

mod common;

use madar_consensus::RuntimeCall;
use parity_scale_codec::{Decode, Encode};

/// The Admission index in `construct_runtime!` (System 0 … Historical 7, Admission 8).
const ADMISSION_INDEX: u8 = 8;

#[test]
fn the_admission_pallet_index_is_the_one_used_below() {
    let call = RuntimeCall::Admission(madar_admission::Call::voluntary_exit {});
    assert_eq!(
        call.encode(),
        vec![ADMISSION_INDEX, 1],
        "Admission = 8, voluntary_exit = 1"
    );
}

#[test]
fn the_removed_admin_calls_do_not_decode_as_any_runtime_call() {
    let account = common::dev_validator(9).account;
    // ban_key { offender }
    let mut ban = vec![ADMISSION_INDEX, 2];
    ban.extend(account.encode());
    // dev_only_force_set_validators { validators: vec![account] }
    let mut force = vec![ADMISSION_INDEX, 3];
    force.extend(vec![account].encode());
    for bytes in [ban, force] {
        assert!(
            RuntimeCall::decode(&mut &bytes[..]).is_err(),
            "call index {} must stay unused",
            bytes[1]
        );
    }
}

/// A committee proposal wrapping one of the two removed calls (`dispatch_as_root`) does not decode either: there is no way to pass it to any logic.
#[test]
fn a_committee_proposal_wrapping_a_removed_call_does_not_decode() {
    let inner_ok = RuntimeCall::Admission(madar_admission::Call::voluntary_exit {});
    let wrapper = RuntimeCall::UpgradeAuthority(madar_upgrade_authority::Call::dispatch_as_root {
        call: Box::new(inner_ok),
    });
    let mut bytes = wrapper.encode();
    // the last byte is the inner call index (voluntary_exit = 1): point it at the removed `ban_key` (2) + an account
    *bytes.last_mut().unwrap() = 2;
    bytes.extend(common::dev_validator(9).account.encode());
    assert!(RuntimeCall::decode(&mut &bytes[..]).is_err());
}
