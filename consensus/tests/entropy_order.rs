//! Review #5 (1) with the hook order of the **real** Runtime: `Session` precedes `Admission` in `on_initialize`
//! (verified from the Pallet index itself), and BABE writes the block VRF in `on_finalize`. At the close block the VRF of the previous
//! block has not yet been accumulated — it must not count toward the fresh entropy required for the draw (16 in production).

mod common;

use common::{dev_validator, new_test_ext};
use frame_support::traits::{Hooks, PalletInfoAccess};
use madar_consensus::{
    Admission, Runtime, RuntimeOrigin, Session, UpgradeCommitteeInstance, MIN_FRESH_ENTROPY_BLOCKS,
};
use pallet_collective::RawOrigin as CollectiveRawOrigin;

/// A 2-of-3 approval origin (exactly what `OperatorApprovalOrigin` actually requires, D47) —
/// this test has nothing to do with the operator-cap logic itself (it has its own dedicated tests
/// in `admission/tests/operator_caps.rs`); here we only vouch for the synthetic winner
/// so that it is not excluded from the check actually intended (the entropy hook order).
fn committee_origin() -> RuntimeOrigin {
    CollectiveRawOrigin::<sp_runtime::AccountId32, UpgradeCommitteeInstance>::Members(2, 3).into()
}

fn block(rotate: bool) -> u32 {
    let b = frame_system::Pallet::<Runtime>::block_number() + 1;
    frame_system::Pallet::<Runtime>::set_block_number(b);
    // on_initialize in the real order: Session (rotation) first, then Admission.
    if rotate {
        pallet_babe::Initialized::<Runtime>::put(None::<sp_consensus_babe::digests::PreDigest>);
        pallet_session::Pallet::<Runtime>::rotate_session();
        <pallet_grandpa::Pallet<Runtime> as Hooks<u32>>::on_finalize(b);
    }
    <madar_admission::Pallet<Runtime> as Hooks<u32>>::on_initialize(b);
    // BABE `on_finalize`: writes this block's VRF (read in the next block).
    pallet_babe::AuthorVrfRandomness::<Runtime>::put(Some([b as u8 ^ 0xA5; 32]));
    b
}

#[test]
fn a_pre_close_vrf_is_not_fresh_entropy_in_the_real_runtime_hook_order() {
    assert!(
        Session::index() < Admission::index(),
        "premise: Session::on_initialize runs before Admission::on_initialize in this runtime"
    );
    let alice = dev_validator(1);
    let winner = dev_validator(77);
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        pallet_session::NextKeys::<Runtime>::insert(
            &winner.account,
            madar_consensus::SessionKeys {
                babe: winner.babe.clone(),
                grandpa: winner.grandpa.clone(),
            },
        );
        for _ in 0..20 {
            block(false); // history before candidacy
        }
        madar_admission::Round::<Runtime>::put((
            sp_core::H256::zero(),
            frame_support::BoundedVec::try_from(vec![(winner.account.clone(), [0u8; 32])]).unwrap(),
        ));
        // D47/D52: winning the lottery is no longer sufficient on its own — it needs a vouch from
        // an approved operator. **The final approved cap = one vote per operator
        // (D52)** — the operator cannot be `alice` herself because she has been a Validator
        // since Genesis (her seat consumes her entire cap, D49); we use
        // a completely separate operator dedicated to this node only.
        let winner_operator = sp_runtime::AccountId32::from([200u8; 32]);
        madar_admission::Pallet::<Runtime>::approve_operator(
            committee_origin(),
            winner_operator.clone(),
            1,
        )
        .expect("committee approval must succeed");
        madar_admission::Pallet::<Runtime>::vouch_node(
            frame_system::RawOrigin::Signed(winner_operator).into(),
            winner.account.clone(),
        )
        .expect("vouching must succeed");

        let close = block(true); // close block: the previous block's VRF (produced before closing) is not yet accumulated
        let close_count = madar_admission::EntropyCount::<Runtime>::get();
        // Only the VRFs of the close block and later count: we produce MIN-1 blocks after it, then rotation k+1 and rotation k+2.
        for _ in 1..8 {
            block(false);
        }
        block(true); // rotation k+1
        while frame_system::Pallet::<Runtime>::block_number() < close + MIN_FRESH_ENTROPY_BLOCKS - 2
        {
            block(false);
        }
        // Now: the VRFs of blocks close..close+MIN-2 = only MIN-1 fresh. Rotation k+2 at block close+MIN-1:
        block(true);
        let fresh = madar_admission::EntropyCount::<Runtime>::get() - close_count;
        assert_eq!(
            fresh,
            (MIN_FRESH_ENTROPY_BLOCKS - 1) as u64,
            "only VRFs produced at/after the close block count"
        );
        assert!(
            !madar_admission::Pallet::<Runtime>::validators().contains(&winner.account),
            "MIN-1 genuinely fresh VRFs: the draw must still be deferred"
        );
        assert_eq!(
            madar_admission::Pending::<Runtime>::get().len(),
            1,
            "the closed pool keeps waiting"
        );

        block(false);
        block(true); // now MIN fresh VRFs after closing
        assert!(
            madar_admission::Pallet::<Runtime>::validators().contains(&winner.account),
            "MIN fresh VRFs after the close: drawn"
        );
        assert!(madar_admission::Pallet::<Runtime>::validators().contains(&alice.account));
    });
}
