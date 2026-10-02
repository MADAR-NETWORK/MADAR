//! Review issue #3 on the actual Runtime: weights and block limits are actually wired
//! and work through the real pipeline (`Executive`), not isolated tests.

mod common;

use common::{dev_committee_accounts, new_test_ext};
use frame_support::dispatch::{DispatchClass, GetDispatchInfo};
use madar_admission::weights::{WeightInfo as _, ARGON2_PS_PER_KIB_PASS};
use madar_consensus::{
    AccountId, Address, Executive, OnboardingPolicy, Runtime, RuntimeCall, RuntimeOrigin,
    SignedExtra, UncheckedExtrinsic,
};
use parity_scale_codec::Encode;
use sp_core::Pair;
use sp_runtime::{
    generic::Era,
    transaction_validity::{InvalidTransaction, TransactionValidityError},
};

type Admission = madar_admission::weights::ArgonMeteredWeight<Runtime>;

#[test]
fn the_runtime_uses_the_madar_block_limits_and_a_real_db_weight() {
    assert_eq!(
        format!(
            "{:?}",
            <Runtime as frame_system::Config>::BlockWeights::get()
        ),
        format!("{:?}", madar_blocks::MadarBlockWeights::get()),
        "frame_system must use the MADAR block weight limits"
    );
    assert_eq!(
        format!(
            "{:?}",
            <Runtime as frame_system::Config>::BlockLength::get()
        ),
        format!("{:?}", madar_blocks::MadarBlockLength::get()),
        "frame_system must use the MADAR block length limits"
    );
    let db = <Runtime as frame_system::Config>::DbWeight::get();
    assert!(
        db.read > 0 && db.write > 0,
        "storage access must carry a real weight"
    );
}

#[test]
fn admission_solution_weight_covers_the_real_runtime_argon2_work() {
    let one = Admission::submit_admission_solution();
    // m = 19456 KiB, t = 2 (the actual Runtime parameters).
    assert!(one.ref_time() >= 19_456 * 2 * ARGON2_PS_PER_KIB_PASS);
    assert!(
        one.proof_size() >= 32 * 1_000,
        "PoV must cover the Validators vector"
    );

    let call: RuntimeCall =
        madar_admission::Call::<Runtime>::submit_admission_solution { nonce: 0 }.into();
    assert_eq!(
        call.get_dispatch_info().call_weight,
        one,
        "the extrinsic must declare exactly this weight"
    );
}

fn signed(
    pair: &sp_core::sr25519::Pair,
    account: &AccountId,
    call: RuntimeCall,
    nonce: u32,
) -> UncheckedExtrinsic {
    let extra: SignedExtra = (
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        madar_transactions::CheckMortalOnly::<Runtime>::from(Era::mortal(4, 12)),
        madar_transactions::CheckNonceOrOnboard::<Runtime, OnboardingPolicy>::from(nonce),
        frame_system::CheckWeight::<Runtime>::new(),
    );
    let payload = sp_runtime::generic::SignedPayload::new(call.clone(), extra.clone()).unwrap();
    let signature = payload.using_encoded(|p| pair.sign(p));
    UncheckedExtrinsic::new_signed(call, Address::Id(account.clone()), signature.into(), extra)
}

/// A flood of puzzles from new accounts through the real pipeline: the block fills at a
/// bounded count (the real Argon2 weight), and anything beyond is rejected with `ExhaustsResources` — no unbounded
/// exhaustion of block time.
#[test]
fn a_flood_of_admission_solutions_cannot_exceed_the_block_weight_budget() {
    new_test_ext(&[]).execute_with(|| {
        frame_system::Pallet::<Runtime>::set_block_number(13);
        frame_system::BlockHash::<Runtime>::insert(12u32, sp_core::H256::repeat_byte(1));

        let normal_budget = <Runtime as frame_system::Config>::BlockWeights::get()
            .get(DispatchClass::Normal)
            .max_total
            .expect("Normal class must be capped");
        let one = Admission::submit_admission_solution();
        let expected_fit = normal_budget.ref_time() / one.ref_time();
        assert!((1..=20).contains(&expected_fit), "a handful of Argon2 solutions per block: {expected_fit}");

        let mut included = 0u64;
        let mut rejected_for_resources = false;
        for seed in 100u8..140 {
            let pair = sp_core::sr25519::Pair::from_seed(&[seed; 32]);
            let who = AccountId::from(pair.public().0);
            let call = RuntimeCall::Admission(madar_admission::Call::submit_admission_solution { nonce: 0 });
            match Executive::apply_extrinsic(signed(&pair, &who, call, 0)) {
                Ok(_) => included += 1,
                Err(e) => {
                    assert_eq!(e, TransactionValidityError::Invalid(InvalidTransaction::ExhaustsResources));
                    rejected_for_resources = true;
                    break;
                },
            }
        }
        assert!(rejected_for_resources, "the block must fill up instead of accepting unbounded Argon2 work");
        assert!(included >= 1 && included <= expected_fit, "included {included}, budget allows {expected_fit}");
        println!("B1 admission flood: included={included}, next=ExhaustsResources, normal_budget_ps={}, admission_weight_ps={}",
            normal_budget.ref_time(), one.ref_time());
    });
}

/// The weight of the inner call is no longer hidden inside `dispatch_as_root`.
#[test]
fn dispatch_as_root_declares_the_weight_and_class_of_the_inner_call() {
    let inner_weight = |c: &RuntimeCall| c.get_dispatch_info();

    let heavy = RuntimeCall::System(frame_system::Call::set_code { code: vec![0u8; 8] });
    let heavy_info = inner_weight(&heavy);
    let wrapped: RuntimeCall = madar_upgrade_authority::Call::<Runtime>::dispatch_as_root {
        call: Box::new(heavy.clone()),
    }
    .into();
    let wrapped_info = wrapped.get_dispatch_info();

    assert!(
        wrapped_info.call_weight.all_gt(heavy_info.call_weight),
        "wrapper weight must include (and exceed) the inner call weight"
    );
    assert_eq!(
        wrapped_info.class, heavy_info.class,
        "the inner dispatch class must be propagated"
    );
    assert!(
        heavy_info.call_weight.ref_time() > 0,
        "sanity: set_code has a real weight"
    );
}

/// Real proposals (such as `set_code`) fit within the committee proposal weight cap — after
/// accounting for the inner weight (a proof_size cap of 0 would have rejected them).
#[test]
fn a_set_code_proposal_fits_the_committee_max_proposal_weight() {
    let proposal: RuntimeCall = madar_upgrade_authority::Call::<Runtime>::dispatch_as_root {
        call: Box::new(RuntimeCall::System(frame_system::Call::set_code {
            code: vec![0u8; 8],
        })),
    }
    .into();
    let weight = proposal.get_dispatch_info().call_weight;
    let max = <Runtime as pallet_collective::Config<madar_consensus::UpgradeCommitteeInstance>>::MaxProposalWeight::get();
    assert!(
        weight.all_lte(max),
        "runtime-upgrade proposals must be proposable: {weight:?} vs {max:?}"
    );
}

/// The actual weight of the inner call is carried in the result (not swallowed).
#[test]
fn dispatch_as_root_reports_wrapper_plus_actual_inner_weight() {
    new_test_ext(&[]).execute_with(|| {
        let _ = dev_committee_accounts();
        let inner = RuntimeCall::System(frame_system::Call::remark { remark: b"x".to_vec() });
        let info = inner.get_dispatch_info();
        let members: RuntimeOrigin = pallet_collective::RawOrigin::<AccountId, madar_consensus::UpgradeCommitteeInstance>::Members(2, 3).into();
        let post = madar_upgrade_authority::Pallet::<Runtime>::dispatch_as_root(members, Box::new(inner)).unwrap();
        let base = <madar_upgrade_authority::weights::ConservativeWeight<Runtime> as madar_upgrade_authority::weights::WeightInfo>::dispatch_as_root();
        assert_eq!(post.actual_weight, Some(base.saturating_add(info.call_weight)));
    });
}
