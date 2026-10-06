//! Madar Names through the real pipeline (the actual `Executive` + `SignedExtra`): the spec 7 migration seeds
//! the first registrar and the reserved names exactly once, and only the approved registrar has its account created and registers a name
//! for a wallet that proved itself with its own signature.

mod common;

use common::new_test_ext;
use madar_consensus::{
    AccountId, Address, Executive, OnboardingPolicy, Runtime, RuntimeCall, SignedExtra,
    UncheckedExtrinsic,
};
use madar_names::{register_message, NameOf, Names, Reserved, Wallet, WalletProof};
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
fn spec7_migration_seeds_the_first_registrar_and_reserved_names_once() {
    use frame_support::traits::OnRuntimeUpgrade;
    new_test_ext(&[]).execute_with(|| {
        let first = AccountId::from(madar_consensus::FIRST_STAMPER);
        assert!(!madar_names::Pallet::<Runtime>::is_registrar(&first));
        madar_consensus::SeedNames::on_runtime_upgrade();
        assert_eq!(
            madar_names::Registrars::<Runtime>::get().into_inner(),
            vec![first.clone()]
        );
        for n in madar_consensus::NAMES_RESERVED_AT_LAUNCH {
            assert!(
                Reserved::<Runtime>::contains_key(nm(n)),
                "{n} must be reserved"
            );
            assert!(
                madar_names::valid_name(n.as_bytes()),
                "{n} must be a valid name"
            );
        }
        // the committee changes its mind later: running the migration again changes nothing
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::remove_registrar(
            Committee::Members(2, 3).into(),
            first
        ));
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::set_reserved(
            Committee::Members(2, 3).into(),
            nm("support"),
            false
        ));
        madar_consensus::SeedNames::on_runtime_upgrade();
        assert!(madar_names::Registrars::<Runtime>::get().is_empty());
        assert!(!Reserved::<Runtime>::contains_key(nm("support")));
    });
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

#[test]
fn safe_sale_runs_through_the_real_pipeline_for_the_registrar_only() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let now = 1_790_000_000_000u64;
        let (pair, reg) = signer(92);
        frame_support::assert_ok!(madar_names::Pallet::<Runtime>::add_registrar(
            Committee::Members(2, 3).into(),
            reg.clone()
        ));
        let (p, _) = evm_proof(5, &register_message(b"ahmad"));
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
        let lock = RuntimeCall::Names(madar_names::Call::lock_sale {
            name: nm("ahmad"),
            seller_proof: sp,
            price_cents: 2_500,
            pay_to: sp_runtime::BoundedVec::try_from(pay_to).unwrap(),
            offer_until: now + 86_400_000,
            buyer_proof: bp,
            lock_until: now + 50 * 60_000,
        });
        // a stranger's account cannot even submit it
        let (spair, stranger) = signer(93);
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
        let done = RuntimeCall::Names(madar_names::Call::complete_sale { name: nm("ahmad") });
        assert!(Executive::apply_extrinsic(signed(&pair, &reg, done, 2))
            .unwrap()
            .is_ok());
        assert_eq!(Names::<Runtime>::get(nm("ahmad")).unwrap().owner, buyer);
    });
}
