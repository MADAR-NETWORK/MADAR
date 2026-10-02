//! Review issue #1: new accounts and upgrade-committee members must be able to start
//! transacting through the real pipeline (the actual `Executive` + `SignedExtra`) **without
//! any manual state injection** (no `inc_providers` and no balance) — everything before the first
//! transaction is Genesis as-is.

mod common;

use common::{dev_committee_accounts, new_test_ext};
use madar_consensus::{
    AccountId, Address, Executive, OnboardingPolicy, Runtime, RuntimeCall, SignedExtra,
    UncheckedExtrinsic,
};
use parity_scale_codec::Encode;
use sp_core::Pair;
use sp_runtime::{
    generic::Era,
    traits::Hash,
    transaction_validity::{InvalidTransaction, TransactionValidityError},
};

type Onboard = madar_transactions::CheckNonceOrOnboard<Runtime, OnboardingPolicy>;

fn signer(seed: u8) -> (sp_core::sr25519::Pair, AccountId) {
    let pair = sp_core::sr25519::Pair::from_seed(&[seed; 32]);
    let account = AccountId::from(pair.public().0);
    (pair, account)
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
        Onboard::from(nonce),
        frame_system::CheckWeight::<Runtime>::new(),
    );
    let payload = sp_runtime::generic::SignedPayload::new(call.clone(), extra.clone()).unwrap();
    let signature = payload.using_encoded(|p| pair.sign(p));
    UncheckedExtrinsic::new_signed(call, Address::Id(account.clone()), signature.into(), extra)
}

fn start_block() {
    frame_system::Pallet::<Runtime>::set_block_number(13);
    frame_system::BlockHash::<Runtime>::insert(12u32, sp_core::H256::repeat_byte(1));
}

fn providers(who: &AccountId) -> u32 {
    frame_system::Account::<Runtime>::get(who).providers
}

fn remark() -> RuntimeCall {
    RuntimeCall::System(frame_system::Call::remark {
        remark: b"madar".to_vec(),
    })
}

/// The extension preserves the standard `CheckNonce` encoding and identifier — so standard wallets
/// and clients (polkadot-js/subxt) can sign our transactions unchanged.
#[test]
fn onboarding_extension_is_wire_compatible_with_the_standard_check_nonce() {
    use sp_runtime::traits::TransactionExtension;
    assert_eq!(
        Onboard::from(5).encode(),
        frame_system::CheckNonce::<Runtime>::from(5).encode()
    );
    assert_eq!(
        <Onboard as TransactionExtension<RuntimeCall>>::IDENTIFIER,
        <frame_system::CheckNonce<Runtime> as TransactionExtension<RuntimeCall>>::IDENTIFIER
    );
}

/// Account creation is not open to every call: an account without a reference that invokes anything
/// other than the onboarding paths is rejected as before, and no account is created for it.
#[test]
fn a_new_account_cannot_create_itself_through_an_arbitrary_call() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let (pair, who) = signer(78);
        let result = Executive::apply_extrinsic(signed(&pair, &who, remark(), 0));
        assert_eq!(
            result.err(),
            Some(TransactionValidityError::Invalid(
                InvalidTransaction::Payment
            ))
        );
        assert_eq!(providers(&who), 0);
        assert_eq!(frame_system::Pallet::<Runtime>::account_nonce(&who), 0);
    });
}

/// Committee calls from non-members do not create an account.
#[test]
fn a_non_member_cannot_create_an_account_through_committee_calls() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let (pair, who) = signer(79);
        let call = RuntimeCall::UpgradeCommittee(pallet_collective::Call::propose {
            threshold: 2,
            proposal: Box::new(remark()),
            length_bound: 1024,
        });
        let result = Executive::apply_extrinsic(signed(&pair, &who, call, 0));
        assert_eq!(
            result.err(),
            Some(TransactionValidityError::Invalid(
                InvalidTransaction::Payment
            ))
        );
        assert_eq!(providers(&who), 0);
    });
}

/// Full governance cycle with real signed transactions from Genesis members (without any prior
/// reference): one member proposes, a second member votes reaching 2-of-3, and the proposal executes with Root origin.
#[test]
fn genesis_committee_members_run_propose_and_vote_with_signed_transactions() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let [member_a, member_b, _] = dev_committee_accounts();
        let (pair_a, pair_b) = (signer(201).0, signer(202).0);
        assert_eq!(
            providers(&member_a),
            0,
            "precondition: committee members have no account reference"
        );
        assert_eq!(providers(&member_b), 0);

        // A real Root proposal that leaves an inspectable trace: writing a raw storage key
        // (`set_storage` is Root-only; `dev_only_force_set_validators` is closed in the Runtime — N1).
        const PROBE: &[u8] = b":madar:test:committee-probe";
        let inner =
            RuntimeCall::UpgradeAuthority(madar_upgrade_authority::Call::dispatch_as_root {
                call: Box::new(RuntimeCall::System(frame_system::Call::set_storage {
                    items: vec![(PROBE.to_vec(), b"executed".to_vec())],
                })),
            });
        let hash = <Runtime as frame_system::Config>::Hashing::hash_of(&inner);

        let propose = RuntimeCall::UpgradeCommittee(pallet_collective::Call::propose {
            threshold: 2,
            proposal: Box::new(inner.clone()),
            length_bound: 1024,
        });
        let r = Executive::apply_extrinsic(signed(&pair_a, &member_a, propose, 0))
            .expect("propose must be includable");
        assert!(r.is_ok(), "propose must dispatch successfully: {r:?}");
        assert_eq!(providers(&member_a), 1);
        assert!(
            frame_support::storage::unhashed::get_raw(PROBE).is_none(),
            "not executed after a single vote"
        );

        let vote = RuntimeCall::UpgradeCommittee(pallet_collective::Call::vote {
            proposal: hash,
            index: 0,
            approve: true,
        });
        // The proposer does not vote automatically in this version: it votes too (Nonce 1), then the second member.
        let r = Executive::apply_extrinsic(signed(&pair_a, &member_a, vote.clone(), 1))
            .expect("vote A includable");
        assert!(r.is_ok(), "vote A must dispatch successfully: {r:?}");
        let r = Executive::apply_extrinsic(signed(&pair_b, &member_b, vote, 0))
            .expect("vote must be includable");
        assert!(r.is_ok(), "vote must dispatch successfully: {r:?}");
        assert_eq!(providers(&member_b), 1);

        // `vote` does not execute by itself in this version of `pallet_collective`; execution happens via `close`
        // (by any member, here a member that now has a reference) once the threshold is reached.
        use frame_support::dispatch::GetDispatchInfo;
        let close = RuntimeCall::UpgradeCommittee(pallet_collective::Call::close {
            proposal_hash: hash,
            index: 0,
            proposal_weight_bound: inner.get_dispatch_info().call_weight,
            length_bound: inner.encoded_size() as u32,
        });
        let r = Executive::apply_extrinsic(signed(&pair_a, &member_a, close, 2))
            .expect("close must be includable");
        assert!(r.is_ok(), "close must dispatch successfully: {r:?}");

        assert_eq!(
            frame_support::storage::unhashed::get_raw(PROBE),
            Some(b"executed".to_vec()),
            "2-of-3 reached: the committee proposal executed as Root through the real pipeline"
        );
    });
}

// ---------------------------------------------------------------------------
// No persistent state from a failed onboarding attempt (the remaining side effect of issue #1)
// ---------------------------------------------------------------------------

use frame_support::traits::Randomness;

/// A genuinely valid Nonce (Argon2id with the real Runtime parameters, 12 bits) for account `seed=77`
/// at block number 13 in this test Genesis. It is deterministic by derivation; if the
/// puzzle parameters or the randomness source change, regenerate it with:
/// `cargo test -p madar-consensus --test account_onboarding find_valid_nonce -- --ignored --nocapture`
const VALID_NONCE_FOR_SEED_77: u64 = 667;

fn round_seed() -> sp_core::H256 {
    <Runtime as madar_admission::Config>::EpochRandomness::random(
        madar_protocol::ADMISSION_PUZZLE_DOMAIN,
    )
    .0
}

fn puzzle_ok(who: &AccountId, nonce: u64) -> bool {
    madar_admission::Pallet::<Runtime>::solution_meets_difficulty(who, &round_seed(), nonce)
}

#[test]
#[ignore = "one-off search (~seconds/minutes); prints the constant above"]
fn find_valid_nonce() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let (_, who) = signer(77);
        let nonce = (0u64..).find(|n| puzzle_ok(&who, *n)).unwrap();
        println!("VALID_NONCE_FOR_SEED_77 = {nonce}");
    });
}

fn account_count() -> usize {
    frame_system::Account::<Runtime>::iter().count()
}

fn admission_state_is_empty() -> bool {
    madar_admission::Validators::<Runtime>::get().is_empty()
        && madar_admission::Round::<Runtime>::get().is_none()
        && madar_admission::BannedKeys::<Runtime>::iter().count() == 0
}

/// Successful onboarding: the solution is accepted, the account is created (one reference + Nonce), and it becomes a member of
/// Validators, and can then make a normal transaction.
#[test]
fn a_successful_admission_creates_the_account_and_enters_the_lottery() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let (pair, who) = signer(77);
        assert!(
            puzzle_ok(&who, VALID_NONCE_FOR_SEED_77),
            "stale constant: regenerate with find_valid_nonce"
        );
        let before = account_count();

        let call = RuntimeCall::Admission(madar_admission::Call::submit_admission_solution {
            nonce: VALID_NONCE_FOR_SEED_77,
        });
        let outcome = Executive::apply_extrinsic(signed(&pair, &who, call, 0)).expect("includable");
        assert!(
            outcome.is_ok(),
            "a valid solution must be accepted: {outcome:?}"
        );

        assert_eq!(providers(&who), 1);
        assert_eq!(frame_system::Pallet::<Runtime>::account_nonce(&who), 1);
        assert_eq!(account_count(), before + 1);
        assert_eq!(
            madar_admission::Pallet::<Runtime>::candidates(),
            vec![who.clone()],
            "accepted as a lottery candidate"
        );

        let follow_up = Executive::apply_extrinsic(signed(&pair, &who, remark(), 1));
        assert!(
            follow_up.is_ok(),
            "the admitted account transacts normally: {follow_up:?}"
        );
    });
}

/// Failed onboarding: the transaction is included (and charged for its weight) but there is no account, no Nonce and no
/// Admission state — no persistent trace at all.
#[test]
fn a_failed_admission_leaves_no_account_nonce_or_admission_state() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let (pair, who) = signer(80);
        let bad = (1u64..).find(|n| !puzzle_ok(&who, *n)).unwrap();
        let before = account_count();

        let call =
            RuntimeCall::Admission(madar_admission::Call::submit_admission_solution { nonce: bad });
        let outcome = Executive::apply_extrinsic(signed(&pair, &who, call, 0)).expect("includable");
        assert!(
            outcome.is_err(),
            "a wrong solution must fail at dispatch: {outcome:?}"
        );

        assert!(
            !frame_system::Account::<Runtime>::contains_key(&who),
            "no Account entry may be created"
        );
        assert_eq!(account_count(), before);
        assert_eq!(frame_system::Pallet::<Runtime>::account_nonce(&who), 0);
        assert!(admission_state_is_empty());
    });
}

/// A large number of failed attempts (across several "blocks") from different new keys: the number
/// of accounts and the Admission state remain exactly as in Genesis — no accumulation.
#[test]
fn many_failed_admissions_never_accumulate_permanent_state() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let baseline = account_count();
        let mut attempts = 0u32;

        for block in 0..8u32 {
            // New block: reset only the consumed weight budget (no account state).
            frame_system::BlockWeight::<Runtime>::kill();
            for i in 0..10u8 {
                let seed = 150 + (block as u8) * 10 + i;
                let (pair, who) = signer(seed);
                let bad = (1_000u64..).find(|n| !puzzle_ok(&who, *n)).unwrap();
                let call =
                    RuntimeCall::Admission(madar_admission::Call::submit_admission_solution {
                        nonce: bad,
                    });
                let outcome =
                    Executive::apply_extrinsic(signed(&pair, &who, call, 0)).expect("includable");
                assert!(outcome.is_err());
                attempts += 1;
            }
            assert_eq!(
                account_count(),
                baseline,
                "block {block}: failed attempts must not add accounts"
            );
            assert!(
                admission_state_is_empty(),
                "block {block}: no admission state may accumulate"
            );
        }
        assert_eq!(attempts, 80);
    });
}

/// A committee member whose first transaction fails (a vote on a nonexistent proposal): no account. Then its
/// valid transaction succeeds and creates the account — the committee path (from issue #1) is sound.
#[test]
fn a_committee_members_failed_first_call_leaves_no_account_and_a_valid_one_still_works() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let [member_a, ..] = dev_committee_accounts();
        let pair_a = signer(201).0;
        let before = account_count();

        let bad_vote = RuntimeCall::UpgradeCommittee(pallet_collective::Call::vote {
            proposal: sp_core::H256::repeat_byte(9),
            index: 0,
            approve: true,
        });
        let outcome = Executive::apply_extrinsic(signed(&pair_a, &member_a, bad_vote, 0))
            .expect("includable");
        assert!(
            outcome.is_err(),
            "voting on a missing proposal fails: {outcome:?}"
        );
        assert!(!frame_system::Account::<Runtime>::contains_key(&member_a));
        assert_eq!(account_count(), before);

        let propose = RuntimeCall::UpgradeCommittee(pallet_collective::Call::propose {
            threshold: 2,
            proposal: Box::new(remark()),
            length_bound: 1024,
        });
        let outcome =
            Executive::apply_extrinsic(signed(&pair_a, &member_a, propose, 0)).expect("includable");
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(providers(&member_a), 1);
        assert_eq!(frame_system::Pallet::<Runtime>::account_nonce(&member_a), 1);
    });
}
