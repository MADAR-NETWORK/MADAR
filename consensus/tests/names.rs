//! Madar Names through the real pipeline (the actual `Executive` + `SignedExtra`): the spec 7 migration seeds
//! the first registrar and the reserved names exactly once, and only the approved registrar has its account created and registers a name
//! for a wallet that proved itself with its own signature.

mod common;

use common::new_test_ext;
use madar_consensus::{
    AccountId, Address, Executive, OnboardingPolicy, Runtime, RuntimeCall, SignedExtra,
    UncheckedExtrinsic,
};
use madar_names::{register_message, NameOf, Names, Wallet, WalletProof};
use parity_scale_codec::Encode;
use sp_core::Pair;
use sp_runtime::{
    generic::Era,
    transaction_validity::{InvalidTransaction, TransactionValidityError},
};

type Onboard = madar_transactions::CheckNonceOrOnboard<Runtime, OnboardingPolicy>;
type Committee = pallet_collective::RawOrigin<AccountId, madar_consensus::UpgradeCommitteeInstance>;

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
    pallet_timestamp::Now::<Runtime>::put(1_790_000_000_000u64);
    run_spec9_upgrade();
}

/// The spec 9 upgrade as it runs on the live chain (Names storage 0 -> 1, Stamp 1 -> 2): v1 messages are accepted until
/// the upgrade time + 72 h (independent review #2). A chain started from genesis with spec 9 code refuses v1 at once.
fn run_spec9_upgrade() {
    use frame_support::traits::{OnRuntimeUpgrade, StorageVersion};
    StorageVersion::new(0).put::<madar_names::Pallet<Runtime>>();
    StorageVersion::new(1).put::<madar_stamp::Pallet<Runtime>>();
    <madar_names::Pallet<Runtime> as OnRuntimeUpgrade>::on_runtime_upgrade();
    <madar_stamp::Pallet<Runtime> as OnRuntimeUpgrade>::on_runtime_upgrade();
}

fn nm(s: &str) -> NameOf {
    NameOf::try_from(s.as_bytes().to_vec()).unwrap()
}

fn evm_proof(seed: u8, msg: &[u8]) -> (WalletProof, Wallet) {
    let pair = sp_core::ecdsa::Pair::from_seed(&[seed; 32]);
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
    prefixed.extend_from_slice(msg);
    let digest = sp_io::hashing::keccak_256(&prefixed);
    let sig: [u8; 65] = pair.sign_prehashed(&digest).0;
    let public = sp_io::crypto::secp256k1_ecdsa_recover(&sig, &digest)
        .ok()
        .expect("recover");
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&sp_io::hashing::keccak_256(&public)[12..]);
    (
        WalletProof::Evm {
            address: addr,
            signature: sig,
        },
        Wallet::Evm(addr),
    )
}

fn register_call(name: &str, proof: WalletProof) -> RuntimeCall {
    RuntimeCall::Names(madar_names::Call::register {
        name: nm(name),
        proof,
        expires: 1_790_000_000_000 + 365 * 86_400_000,
    })
}

#[test]
fn only_an_approved_registrar_is_onboarded_and_registers_for_the_signing_wallet() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let (proof, wallet) = evm_proof(5, &register_message(b"ahmad"));
        // not a registrar: refused before any state is created
        let (pair, who) = signer(91);
        let r = Executive::apply_extrinsic(signed(
            &pair,
            &who,
            register_call("ahmad", proof.clone()),
            0,
        ));
        assert_eq!(
            r.err(),
            Some(TransactionValidityError::Invalid(
                InvalidTransaction::Payment
            ))
        );
        assert_eq!(frame_system::Account::<Runtime>::get(&who).providers, 0);
        assert!(Names::<Runtime>::get(nm("ahmad")).is_none());
        // approved by the committee: its first call creates the account and registers the name
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::add_registrar(
            Committee::Members(2, 3).into(),
            who.clone()
        ));
        assert!(
            Executive::apply_extrinsic(signed(&pair, &who, register_call("ahmad", proof), 0))
                .unwrap()
                .is_ok()
        );
        assert_eq!(Names::<Runtime>::get(nm("ahmad")).unwrap().owner, wallet);
        // a single member cannot revoke; the 2-of-3 committee can
        let reason = sp_runtime::BoundedVec::try_from(b"test".to_vec()).unwrap();
        assert!(madar_names::Pallet::<Runtime>::revoke(
            Committee::Member(who.clone()).into(),
            nm("ahmad"),
            reason.clone()
        )
        .is_err());
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::revoke(
            Committee::Members(2, 3).into(),
            nm("ahmad"),
            reason
        ));
        assert!(Names::<Runtime>::get(nm("ahmad")).is_none());
    });
}

/// spec 9: the two v1 safe-sale calls are gone from the runtime (indices 6 and 7 of Names). Their bytes no longer
/// decode as a call, so nobody can submit them; the v2 calls keep their indices.
#[test]
fn the_v1_safe_sale_calls_no_longer_exist() {
    use parity_scale_codec::{Decode, Encode};
    let v2 = RuntimeCall::Names(madar_names::Call::complete_sale_v2 {
        name: nm("ahmad"),
        payment_ref: sp_runtime::BoundedVec::try_from(b"base:0x00".to_vec()).unwrap(),
    })
    .encode();
    let pallet = v2[0];
    for gone in [6u8, 7] {
        let mut raw = vec![pallet, gone];
        raw.extend_from_slice(&nm("ahmad").encode());
        assert!(
            RuntimeCall::decode(&mut &raw[..]).is_err(),
            "call index {gone} of Names must be gone"
        );
    }
    assert!(
        RuntimeCall::decode(&mut &v2[..]).is_ok(),
        "the v2 completion still decodes"
    );
}

/// spec 8: the v2 safe sale (exact amount + rail in the lock, payment reference to complete) through the real pipeline;
/// only the registrar may submit it, the event carries everything an auditor needs, and a v2 lock refuses the old completion.
#[test]
fn v2_safe_sale_records_the_payment_proof_through_the_real_pipeline() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let now = 1_790_000_000_000u64;
        let (pair, reg) = signer(94);
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::add_registrar(
            Committee::Members(2, 3).into(),
            reg.clone()
        ));
        let (p, seller) = evm_proof(5, &register_message(b"ahmad"));
        assert!(
            Executive::apply_extrinsic(signed(&pair, &reg, register_call("ahmad", p), 0))
                .unwrap()
                .is_ok()
        );
        let pay_to = b"0x00000000000000000000000000000000000000aa".to_vec();
        let n = madar_names::SaleNonce::<Runtime>::get(nm("ahmad"));
        let (sp, _) = evm_proof(
            5,
            &madar_names::sale_message(b"ahmad", n, 2_500, &pay_to, now + 86_400_000),
        );
        let (bp, buyer) = evm_proof(6, &madar_names::buy_message(b"ahmad", n, 2_500));
        let lock = RuntimeCall::Names(madar_names::Call::lock_sale_v2 {
            name: nm("ahmad"),
            seller_proof: sp,
            price_cents: 2_500,
            pay_to: sp_runtime::BoundedVec::try_from(pay_to.clone()).unwrap(),
            offer_until: now + 86_400_000,
            buyer_proof: bp,
            lock_until: now + 50 * 60_000,
            pay_amount: 25_004_200,
            rail: 3,
        });
        // a stranger's account cannot even submit it
        let (spair, stranger) = signer(95);
        let r = Executive::apply_extrinsic(signed(&spair, &stranger, lock.clone(), 0));
        assert_eq!(
            r.err(),
            Some(TransactionValidityError::Invalid(
                InvalidTransaction::Payment
            ))
        );
        assert!(Executive::apply_extrinsic(signed(&pair, &reg, lock, 1))
            .unwrap()
            .is_ok());
        assert_eq!(
            madar_names::LockTerms::<Runtime>::get(nm("ahmad")),
            Some(madar_names::SaleTerms {
                rail: 3,
                pay_amount: 25_004_200
            })
        );
        assert_eq!(Names::<Runtime>::get(nm("ahmad")).unwrap().owner, seller);
        let payment_ref =
            b"arbitrum:0x2222222222222222222222222222222222222222222222222222222222222222".to_vec();
        let done = RuntimeCall::Names(madar_names::Call::complete_sale_v2 {
            name: nm("ahmad"),
            payment_ref: sp_runtime::BoundedVec::try_from(payment_ref.clone()).unwrap(),
        });
        assert!(Executive::apply_extrinsic(signed(&pair, &reg, done, 2))
            .unwrap()
            .is_ok());
        assert_eq!(
            Names::<Runtime>::get(nm("ahmad")).unwrap().owner,
            buyer.clone()
        );
        let want = madar_consensus::RuntimeEvent::Names(madar_names::Event::SaleCompletedV2 {
            name: nm("ahmad"),
            from: seller,
            to: buyer,
            price_cents: 2_500,
            pay_to: sp_runtime::BoundedVec::try_from(pay_to).unwrap(),
            rail: 3,
            amount: 25_004_200,
            payment_ref: sp_runtime::BoundedVec::try_from(payment_ref).unwrap(),
        });
        assert!(
            frame_system::Pallet::<Runtime>::events()
                .iter()
                .any(|e| e.event == want),
            "SaleCompletedV2 with the payment proof"
        );
    });
}

// ---------------------------------------------------------------- spec 9: v2 messages, transfer, reassign, legacy switch

const NOW: u64 = 1_790_000_000_000;
const DAY: u64 = 86_400_000;

/// The chain id the runtime puts in v2 messages: the stored block-0 hash (what `CheckGenesis` uses too).
fn genesis() -> Vec<u8> {
    frame_system::BlockHash::<Runtime>::get(0u32)
        .as_ref()
        .to_vec()
}

fn sol_proof(seed: u8, msg: &[u8]) -> (WalletProof, Wallet) {
    let pair = sp_core::ed25519::Pair::from_seed(&[seed; 32]);
    let public = pair.public().0;
    (
        WalletProof::Solana {
            public,
            signature: pair.sign(msg).0,
        },
        Wallet::Solana(public),
    )
}

fn module_error(r: sp_runtime::ApplyExtrinsicResult) -> Option<&'static str> {
    match r.expect("valid transaction") {
        Err(sp_runtime::DispatchError::Module(m)) => m.message,
        _ => None,
    }
}

/// New calls keep their fixed indices (11..16 in Names, 3..4 in Stamp): clients and the committee tools encode them.
#[test]
fn spec9_call_indices_are_fixed() {
    let p = || WalletProof::Solana {
        public: [0; 32],
        signature: [0; 64],
    };
    let reason = sp_runtime::BoundedVec::try_from(b"r".to_vec()).unwrap();
    let pay_to = sp_runtime::BoundedVec::try_from(b"x".to_vec()).unwrap();
    let calls: Vec<(madar_names::Call<Runtime>, u8)> = vec![
        (
            madar_names::Call::register_v2 {
                name: nm("abc"),
                proof: p(),
                expires: 1,
                valid_until: 1,
            },
            11,
        ),
        (
            madar_names::Call::lock_sale_v3 {
                name: nm("abc"),
                seller_proof: p(),
                price_cents: 1,
                pay_to,
                offer_until: 1,
                buyer_proof: p(),
                accept_until: 1,
                lock_until: 1,
                pay_amount: 1,
                rail: 0,
            },
            12,
        ),
        (
            madar_names::Call::cancel_offer_v2 {
                name: nm("abc"),
                owner_proof: p(),
                valid_until: 1,
            },
            13,
        ),
        (
            madar_names::Call::transfer {
                name: nm("abc"),
                owner_proof: p(),
                new_owner_proof: p(),
                valid_until: 1,
            },
            14,
        ),
        (
            madar_names::Call::reassign {
                name: nm("abc"),
                new_owner: Wallet::Evm([0; 20]),
                reason,
            },
            15,
        ),
        (
            madar_names::Call::set_legacy_accepted_until { until: 0 },
            16,
        ),
    ];
    for (c, idx) in calls {
        assert_eq!(RuntimeCall::Names(c).encode()[1], idx);
    }
    let entries = sp_runtime::BoundedVec::try_from(vec![]).unwrap();
    assert_eq!(
        RuntimeCall::Stamp(madar_stamp::Call::stamp_v2 { entries }).encode()[1],
        3
    );
    assert_eq!(
        RuntimeCall::Stamp(madar_stamp::Call::set_legacy_accepted_until { until: 0 }).encode()[1],
        4
    );
}

#[test]
fn register_v2_through_the_real_pipeline_is_bound_to_this_genesis() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let until = NOW + DAY;
        let call = |proof| {
            RuntimeCall::Names(madar_names::Call::register_v2 {
                name: nm("ahmad"),
                proof,
                expires: NOW + 365 * DAY,
                valid_until: until,
            })
        };
        let (proof, wallet) = evm_proof(
            5,
            &madar_names::register_message_v2(b"ahmad", &genesis(), until),
        );
        // only an approved registrar is onboarded for the new call too
        let (spair, stranger) = signer(96);
        let r = Executive::apply_extrinsic(signed(&spair, &stranger, call(proof.clone()), 0));
        assert_eq!(
            r.err(),
            Some(TransactionValidityError::Invalid(
                InvalidTransaction::Payment
            ))
        );
        let (pair, reg) = signer(97);
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::add_registrar(
            Committee::Members(2, 3).into(),
            reg.clone()
        ));
        // a proof for another chain (another genesis) is refused
        let (other, _) = evm_proof(
            5,
            &madar_names::register_message_v2(b"ahmad", &[0x42; 32], until),
        );
        assert_eq!(
            module_error(Executive::apply_extrinsic(signed(
                &pair,
                &reg,
                call(other),
                0
            ))),
            Some("InvalidProof")
        );
        // a refused first call does not create the account, so its nonce is still 0
        assert!(
            Executive::apply_extrinsic(signed(&pair, &reg, call(proof), 0))
                .unwrap()
                .is_ok()
        );
        assert_eq!(Names::<Runtime>::get(nm("ahmad")).unwrap().owner, wallet);
    });
}

#[test]
fn transfer_through_the_real_pipeline_and_committee_reassign() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let (pair, reg) = signer(98);
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::add_registrar(
            Committee::Members(2, 3).into(),
            reg.clone()
        ));
        let (p, owner) = evm_proof(5, &register_message(b"ahmad"));
        assert!(
            Executive::apply_extrinsic(signed(&pair, &reg, register_call("ahmad", p), 0))
                .unwrap()
                .is_ok()
        );
        let n = madar_names::SaleNonce::<Runtime>::get(nm("ahmad"));
        let until = NOW + 3_600_000;
        let (ap, to) = sol_proof(
            7,
            &madar_names::accept_message(b"ahmad", n, &genesis(), until),
        );
        let (op, _) = evm_proof(
            5,
            &madar_names::transfer_message(b"ahmad", n, &to, &genesis(), until),
        );
        let call = RuntimeCall::Names(madar_names::Call::transfer {
            name: nm("ahmad"),
            owner_proof: op,
            new_owner_proof: ap,
            valid_until: until,
        });
        let (spair, stranger) = signer(99);
        let r = Executive::apply_extrinsic(signed(&spair, &stranger, call.clone(), 0));
        assert_eq!(
            r.err(),
            Some(TransactionValidityError::Invalid(
                InvalidTransaction::Payment
            ))
        );
        assert!(
            Executive::apply_extrinsic(signed(&pair, &reg, call.clone(), 1))
                .unwrap()
                .is_ok()
        );
        let rec = Names::<Runtime>::get(nm("ahmad")).unwrap();
        assert_eq!(
            (rec.owner.clone(), rec.expires),
            (to.clone(), NOW + 365 * DAY)
        );
        let want = madar_consensus::RuntimeEvent::Names(madar_names::Event::Transferred {
            name: nm("ahmad"),
            from: owner.clone(),
            to: to.clone(),
        });
        assert!(frame_system::Pallet::<Runtime>::events()
            .iter()
            .any(|e| e.event == want));
        // replay: refused (the name's number moved on)
        assert_eq!(
            module_error(Executive::apply_extrinsic(signed(&pair, &reg, call, 2))),
            Some("InvalidProof")
        );
        // dispute: one member cannot, the 2-of-3 committee can, with a public reason; the term stays
        let reason: sp_runtime::BoundedVec<u8, _> =
            sp_runtime::BoundedVec::try_from(b"dispute #1".to_vec()).unwrap();
        assert!(madar_names::Pallet::<Runtime>::reassign(
            Committee::Member(reg.clone()).into(),
            nm("ahmad"),
            owner.clone(),
            reason.clone()
        )
        .is_err());
        assert!(madar_names::Pallet::<Runtime>::reassign(
            Committee::Members(1, 3).into(),
            nm("ahmad"),
            owner.clone(),
            reason.clone()
        )
        .is_err());
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::reassign(
            Committee::Members(2, 3).into(),
            nm("ahmad"),
            owner.clone(),
            reason
        ));
        let rec = Names::<Runtime>::get(nm("ahmad")).unwrap();
        assert_eq!((rec.owner, rec.expires), (owner, NOW + 365 * DAY));
    });
}

#[test]
fn v1_stops_72_hours_after_the_upgrade_and_only_the_committee_can_move_the_end_within_bounds() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let end = NOW + madar_stamp::LEGACY_SUNSET_MS;
        assert_eq!(madar_names::LegacyAcceptedUntil::<Runtime>::get(), end);
        assert_eq!(madar_stamp::LegacyAcceptedUntil::<Runtime>::get(), end);
        let (pair, reg) = signer(100);
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::add_registrar(
            Committee::Members(2, 3).into(),
            reg.clone()
        ));
        assert!(madar_names::Pallet::<Runtime>::set_legacy_accepted_until(
            Committee::Member(reg.clone()).into(),
            0
        )
        .is_err());
        assert!(madar_stamp::Pallet::<Runtime>::set_legacy_accepted_until(
            Committee::Members(1, 3).into(),
            0
        )
        .is_err());
        assert!(
            madar_names::Pallet::<Runtime>::set_legacy_accepted_until(
                Committee::Members(2, 3).into(),
                u64::MAX
            )
            .is_err(),
            "no open-ended window"
        );
        // no committee action at all: 72 h after the upgrade v1 is refused
        pallet_timestamp::Now::<Runtime>::put(end);
        let (p, _) = evm_proof(5, &register_message(b"ahmad"));
        assert_eq!(
            module_error(Executive::apply_extrinsic(signed(
                &pair,
                &reg,
                register_call("ahmad", p.clone()),
                0
            ))),
            Some("LegacyMessagesOff")
        );
        // the committee may extend (here by 7 days), and later shorten again
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::set_legacy_accepted_until(
            Committee::Members(2, 3).into(),
            end + 7 * DAY
        ));
        // (the refused first call created no account: still nonce 0)
        assert!(
            Executive::apply_extrinsic(signed(&pair, &reg, register_call("ahmad", p), 0))
                .unwrap()
                .is_ok()
        );
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::set_legacy_accepted_until(
            Committee::Members(2, 3).into(),
            0
        ));
        frame_support::assert_ok!(madar_stamp::Pallet::<Runtime>::set_legacy_accepted_until(
            Committee::Members(2, 3).into(),
            0
        ));
        let (p, _) = evm_proof(6, &register_message(b"bader"));
        assert_eq!(
            module_error(Executive::apply_extrinsic(signed(
                &pair,
                &reg,
                register_call("bader", p),
                1
            ))),
            Some("LegacyMessagesOff")
        );
        pallet_timestamp::Now::<Runtime>::put(NOW);
        let until = NOW + DAY;
        let (p2, w) = evm_proof(
            6,
            &madar_names::register_message_v2(b"bader", &genesis(), until),
        );
        let call = RuntimeCall::Names(madar_names::Call::register_v2 {
            name: nm("bader"),
            proof: p2,
            expires: NOW + 365 * DAY,
            valid_until: until,
        });
        assert!(Executive::apply_extrinsic(signed(&pair, &reg, call, 2))
            .unwrap()
            .is_ok());
        assert_eq!(Names::<Runtime>::get(nm("bader")).unwrap().owner, w);
    });
}

/// Storage hygiene through the runtime: `on_idle` removes lapsed locks within its fixed budget, and that budget is a
/// tiny part of a block.
#[test]
fn on_idle_cleanup_runs_in_the_runtime_within_a_small_fixed_budget() {
    use frame_support::traits::Hooks;
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let lock = madar_names::SaleLock {
            buyer: Wallet::Evm([1; 20]),
            until: NOW - 1,
            price_cents: 1,
            pay_to: sp_runtime::BoundedVec::try_from(
                b"0x00000000000000000000000000000000000000aa".to_vec(),
            )
            .unwrap(),
        };
        madar_names::Locks::<Runtime>::insert(nm("ahmad"), lock);
        let w = <madar_names::Pallet<Runtime> as Hooks<u32>>::on_idle(
            13,
            frame_support::weights::Weight::MAX,
        );
        assert!(madar_names::Locks::<Runtime>::get(nm("ahmad")).is_none());
        let max = <Runtime as frame_system::Config>::BlockWeights::get().max_block;
        assert!(
            w.ref_time() > 0 && w.ref_time() * 100 < max.ref_time(),
            "cleanup reserves less than 1% of a block"
        );
        use frame_support::traits::GetStorageVersion;
        assert_eq!(madar_names::Pallet::<Runtime>::in_code_storage_version(), 1);
    });
}
