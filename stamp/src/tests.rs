use crate::{self as madar_stamp, *};
use frame_support::{assert_noop, assert_ok, derive_impl, parameter_types, BoundedVec};
use sp_core::{ecdsa, ed25519, Pair};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Stamp: madar_stamp,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

pub struct FixedTime;
impl frame_support::traits::UnixTime for FixedTime {
    fn now() -> core::time::Duration {
        core::time::Duration::from_millis(1_790_000_000_000)
    }
}

parameter_types! {
    pub const MaxBatch: u32 = 4;
    pub const MaxStampers: u32 = 2;
}

impl madar_stamp::Config for Test {
    type AdminOrigin = frame_system::EnsureRoot<u64>;
    type Time = FixedTime;
    type MaxBatch = MaxBatch;
    type MaxStampers = MaxStampers;
    type WeightInfo = ();
}

const STAMPER: u64 = 7;

fn ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    let mut e = sp_io::TestExternalities::new(t);
    e.execute_with(|| {
        System::set_block_number(5);
        // the spec 9 upgrade as on the live chain (storage version 1 -> 2): v1 accepted until now + 72 h
        frame_support::traits::StorageVersion::new(1).put::<Stamp>();
        <Stamp as frame_support::traits::OnRuntimeUpgrade>::on_runtime_upgrade();
        assert_ok!(Stamp::add_stamper(RuntimeOrigin::root(), STAMPER));
    });
    e
}

fn fp(n: u8) -> Fingerprint {
    [n; 32]
}

fn batch(v: Vec<Entry>) -> BoundedVec<Entry, MaxBatch> {
    BoundedVec::try_from(v).unwrap()
}

fn plain(n: u8) -> Entry {
    Entry {
        fingerprint: fp(n),
        name_hash: None,
        proof: None,
    }
}

/// A `personal_sign` signature as produced by MetaMask, and the address derived from the key.
fn evm_sign(pair: &ecdsa::Pair, msg: &[u8], v_offset: u8) -> ([u8; 20], [u8; 65]) {
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
    prefixed.extend_from_slice(msg);
    let digest = sp_io::hashing::keccak_256(&prefixed);
    let mut sig: [u8; 65] = pair.sign_prehashed(&digest).0;
    let public = sp_io::crypto::secp256k1_ecdsa_recover(&sig, &digest)
        .ok()
        .expect("recover");
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&sp_io::hashing::keccak_256(&public)[12..]);
    sig[64] += v_offset;
    (addr, sig)
}

#[test]
fn message_is_stable() {
    let m = signed_message(&[0xab; 32], &None);
    assert_eq!(
        core::str::from_utf8(&m).unwrap(),
        "MADAR Stamp: sign to register this file fingerprint. No funds move.\nfingerprint: abababababababababababababababababababababababababababababababab\nname: none"
    );
}

#[test]
fn stamps_and_rejects_duplicates_first_wins() {
    ext().execute_with(|| {
        assert_ok!(Stamp::stamp(
            RuntimeOrigin::signed(STAMPER),
            batch(vec![plain(1)])
        ));
        let first = Stamps::<Test>::get(fp(1)).unwrap();
        assert_eq!(first.block, 5);
        assert_eq!(first.moment, 1_790_000_000_000);

        System::set_block_number(9);
        assert_ok!(Stamp::stamp(
            RuntimeOrigin::signed(STAMPER),
            batch(vec![plain(1), plain(2)])
        ));
        // The first one stays as it is; the new one was registered.
        assert_eq!(Stamps::<Test>::get(fp(1)).unwrap().block, 5);
        assert_eq!(Stamps::<Test>::get(fp(2)).unwrap().block, 9);
        System::assert_has_event(Event::AlreadyStamped { fingerprint: fp(1) }.into());
    });
}

#[test]
fn only_stampers_and_admin_control() {
    ext().execute_with(|| {
        assert_noop!(
            Stamp::stamp(RuntimeOrigin::signed(99), batch(vec![plain(1)])),
            Error::<Test>::NotStamper
        );
        assert_noop!(
            Stamp::stamp(RuntimeOrigin::signed(STAMPER), batch(vec![])),
            Error::<Test>::EmptyBatch
        );
        assert_noop!(
            Stamp::add_stamper(RuntimeOrigin::signed(STAMPER), 8),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_noop!(
            Stamp::add_stamper(RuntimeOrigin::root(), STAMPER),
            Error::<Test>::AlreadyStamper
        );
        assert_ok!(Stamp::add_stamper(RuntimeOrigin::root(), 8));
        assert_noop!(
            Stamp::add_stamper(RuntimeOrigin::root(), 9),
            Error::<Test>::TooManyStampers
        );
        assert_ok!(Stamp::remove_stamper(RuntimeOrigin::root(), STAMPER));
        assert!(!Stamp::is_stamper(&STAMPER));
        assert_noop!(
            Stamp::stamp(RuntimeOrigin::signed(STAMPER), batch(vec![plain(1)])),
            Error::<Test>::NotStamper
        );
    });
}

#[test]
fn evm_wallet_signature_verified_both_v_forms() {
    ext().execute_with(|| {
        let pair = ecdsa::Pair::from_seed(&[3u8; 32]);
        for (n, v_off) in [(10u8, 0u8), (11, 27)] {
            let name = Some([n.wrapping_add(100); 32]);
            let (address, signature) = evm_sign(&pair, &signed_message(&fp(n), &name), v_off);
            let e = Entry {
                fingerprint: fp(n),
                name_hash: name,
                proof: Some(WalletProof::Evm { address, signature }),
            };
            assert_ok!(Stamp::stamp(RuntimeOrigin::signed(STAMPER), batch(vec![e])));
            let r = Stamps::<Test>::get(fp(n)).unwrap();
            assert_eq!(r.wallet, Some(Wallet::Evm(address)));
            assert_eq!(r.name_hash, name);
        }
    });
}

#[test]
fn evm_signature_for_other_content_is_rejected() {
    ext().execute_with(|| {
        let pair = ecdsa::Pair::from_seed(&[3u8; 32]);
        // Signed over fingerprint 20 but submitted for fingerprint 21.
        let (address, signature) = evm_sign(&pair, &signed_message(&fp(20), &None), 27);
        let e = Entry {
            fingerprint: fp(21),
            name_hash: None,
            proof: Some(WalletProof::Evm { address, signature }),
        };
        assert_ok!(Stamp::stamp(RuntimeOrigin::signed(STAMPER), batch(vec![e])));
        assert!(Stamps::<Test>::get(fp(21)).is_none());
        System::assert_has_event(
            Event::InvalidProof {
                fingerprint: fp(21),
            }
            .into(),
        );
        // A claimed address that does not match the key is not accepted either.
        let (_, sig2) = evm_sign(&pair, &signed_message(&fp(22), &None), 0);
        let e2 = Entry {
            fingerprint: fp(22),
            name_hash: None,
            proof: Some(WalletProof::Evm {
                address: [9; 20],
                signature: sig2,
            }),
        };
        assert_ok!(Stamp::stamp(
            RuntimeOrigin::signed(STAMPER),
            batch(vec![e2])
        ));
        assert!(Stamps::<Test>::get(fp(22)).is_none());
    });
}

#[test]
fn solana_wallet_signature_verified_and_name_bound() {
    ext().execute_with(|| {
        let pair = ed25519::Pair::from_seed(&[5u8; 32]);
        let name = Some([42u8; 32]);
        let sig = pair.sign(&signed_message(&fp(30), &name));
        let proof = WalletProof::Solana {
            public: pair.public().0,
            signature: sig.0,
        };
        // The same signature with a different name = rejected (the name is inside the signed message).
        let forged = Entry {
            fingerprint: fp(30),
            name_hash: Some([43u8; 32]),
            proof: Some(proof.clone()),
        };
        assert_ok!(Stamp::stamp(
            RuntimeOrigin::signed(STAMPER),
            batch(vec![forged])
        ));
        assert!(Stamps::<Test>::get(fp(30)).is_none());
        let ok = Entry {
            fingerprint: fp(30),
            name_hash: name,
            proof: Some(proof),
        };
        assert_ok!(Stamp::stamp(
            RuntimeOrigin::signed(STAMPER),
            batch(vec![ok])
        ));
        assert_eq!(
            Stamps::<Test>::get(fp(30)).unwrap().wallet,
            Some(Wallet::Solana(pair.public().0))
        );
    });
}

// ---------------------------------------------------------------- spec 9: v2 messages (network + expiry)

const NOW: u64 = 1_790_000_000_000;
const DAY: u64 = 24 * 3600 * 1000;

fn net() -> Vec<u8> {
    frame_system::Pallet::<Test>::block_hash(0u64)
        .as_ref()
        .to_vec()
}

fn batch2(v: Vec<EntryV2>) -> BoundedVec<EntryV2, MaxBatch> {
    BoundedVec::try_from(v).unwrap()
}

fn sol_entry(n: u8, network: &[u8], until: u64) -> (EntryV2, Wallet) {
    let pair = ed25519::Pair::from_seed(&[5u8; 32]);
    let name = Some([n.wrapping_add(1); 32]);
    let sig = pair.sign(&signed_message_v2(&fp(n), &name, network, until));
    (
        EntryV2 {
            fingerprint: fp(n),
            name_hash: name,
            proof: Some(WalletProof::Solana {
                public: pair.public().0,
                signature: sig.0,
            }),
            valid_until: until,
        },
        Wallet::Solana(pair.public().0),
    )
}

#[test]
fn v2_message_is_stable() {
    let m = signed_message_v2(&[0xab; 32], &None, &[0xcd; 32], 1_790_000_000_000);
    assert_eq!(
        core::str::from_utf8(&m).unwrap(),
        format!(
            "MADAR Stamp: sign to register this file fingerprint. No funds move.\nfingerprint: {}\nname: none\nnetwork: 0x{}\nvalid until: 1790000000000",
            "ab".repeat(32),
            "cd".repeat(32)
        )
    );
}

#[test]
fn stamp_v2_binds_the_signature_to_this_network_and_its_expiry() {
    ext().execute_with(|| {
        let pair = ecdsa::Pair::from_seed(&[3u8; 32]);
        let (address, signature) = evm_sign(
            &pair,
            &signed_message_v2(&fp(40), &None, &net(), NOW + DAY),
            27,
        );
        let evm = EntryV2 {
            fingerprint: fp(40),
            name_hash: None,
            proof: Some(WalletProof::Evm { address, signature }),
            valid_until: NOW + DAY,
        };
        let (sol, sw) = sol_entry(41, &net(), NOW + 60_000);
        let (other_net, _) = sol_entry(42, &[7u8; 32], NOW + 60_000);
        let (too_far, _) = sol_entry(43, &net(), NOW + DAY + 1);
        let (over, _) = sol_entry(44, &net(), NOW - 1);
        let plain = EntryV2 {
            fingerprint: fp(45),
            name_hash: None,
            proof: None,
            valid_until: 0,
        };
        assert_ok!(Stamp::stamp_v2(
            RuntimeOrigin::signed(STAMPER),
            batch2(vec![evm, sol, other_net, too_far])
        ));
        assert_ok!(Stamp::stamp_v2(
            RuntimeOrigin::signed(STAMPER),
            batch2(vec![over, plain])
        ));
        assert_eq!(
            Stamps::<Test>::get(fp(40)).unwrap().wallet,
            Some(Wallet::Evm(address))
        );
        assert_eq!(Stamps::<Test>::get(fp(41)).unwrap().wallet, Some(sw));
        assert!(
            Stamps::<Test>::get(fp(42)).is_none(),
            "signed for another network"
        );
        System::assert_has_event(
            Event::InvalidProof {
                fingerprint: fp(42),
            }
            .into(),
        );
        for n in [43, 44] {
            assert!(Stamps::<Test>::get(fp(n)).is_none());
            System::assert_has_event(Event::ProofExpired { fingerprint: fp(n) }.into());
        }
        assert_eq!(
            Stamps::<Test>::get(fp(45)).unwrap().wallet,
            None,
            "no signature: existence only"
        );
        // the stamper cannot move the signed time: it is inside the message
        let (mut moved, _) = sol_entry(46, &net(), NOW + 60_000);
        moved.valid_until += 1;
        assert_ok!(Stamp::stamp_v2(
            RuntimeOrigin::signed(STAMPER),
            batch2(vec![moved])
        ));
        assert!(Stamps::<Test>::get(fp(46)).is_none());
        // a v1 signature is not a v2 signature
        let (address, signature) = evm_sign(&pair, &signed_message(&fp(47), &None), 27);
        let v1 = EntryV2 {
            fingerprint: fp(47),
            name_hash: None,
            proof: Some(WalletProof::Evm { address, signature }),
            valid_until: NOW + 1,
        };
        assert_ok!(Stamp::stamp_v2(
            RuntimeOrigin::signed(STAMPER),
            batch2(vec![v1])
        ));
        assert!(Stamps::<Test>::get(fp(47)).is_none());
        // first wins in v2 as well
        let (again, _) = sol_entry(41, &net(), NOW + 60_000);
        assert_ok!(Stamp::stamp_v2(
            RuntimeOrigin::signed(STAMPER),
            batch2(vec![again])
        ));
        System::assert_has_event(
            Event::AlreadyStamped {
                fingerprint: fp(41),
            }
            .into(),
        );
        assert_noop!(
            Stamp::stamp_v2(RuntimeOrigin::signed(99), batch2(vec![])),
            Error::<Test>::NotStamper
        );
        assert_noop!(
            Stamp::stamp_v2(RuntimeOrigin::signed(STAMPER), batch2(vec![])),
            Error::<Test>::EmptyBatch
        );
    });
}

/// Independent review #2: the old `stamp` call is accepted until upgrade time + 72 h, then refused with no committee action;
/// the committee may shorten it or extend it by at most 7 days per call; a fresh chain refuses it from the start.
#[test]
fn the_old_stamp_call_stops_72_hours_after_the_upgrade_and_extensions_are_bounded() {
    ext().execute_with(|| {
        let until = NOW + LEGACY_SUNSET_MS;
        assert_eq!(LegacyAcceptedUntil::<Test>::get(), until);
        System::assert_has_event(Event::LegacyAcceptedUntilSet { until }.into());
        <Stamp as frame_support::traits::OnRuntimeUpgrade>::on_runtime_upgrade();
        assert_eq!(
            LegacyAcceptedUntil::<Test>::get(),
            until,
            "the migration runs once"
        );
        assert_ok!(Stamp::stamp(
            RuntimeOrigin::signed(STAMPER),
            batch(vec![plain(1)])
        ));
        assert_noop!(
            Stamp::set_legacy_accepted_until(RuntimeOrigin::signed(STAMPER), 0),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_noop!(
            Stamp::set_legacy_accepted_until(
                RuntimeOrigin::root(),
                until + MAX_LEGACY_EXTENSION_MS + 1
            ),
            Error::<Test>::LegacyExtensionTooLong
        );
        assert_ok!(Stamp::set_legacy_accepted_until(
            RuntimeOrigin::root(),
            until + MAX_LEGACY_EXTENSION_MS
        ));
        // the clock of this mock is fixed at NOW: a window ending at NOW is over
        assert_ok!(Stamp::set_legacy_accepted_until(RuntimeOrigin::root(), NOW));
        System::assert_has_event(Event::LegacyAcceptedUntilSet { until: NOW }.into());
        assert_noop!(
            Stamp::stamp(RuntimeOrigin::signed(STAMPER), batch(vec![plain(3)])),
            Error::<Test>::LegacyMessagesOff
        );
        let (e, _) = sol_entry(2, &net(), NOW + 1);
        assert_ok!(Stamp::stamp_v2(
            RuntimeOrigin::signed(STAMPER),
            batch2(vec![e])
        ));
        assert!(Stamps::<Test>::get(fp(2)).is_some());
    });
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    sp_io::TestExternalities::new(t).execute_with(|| {
        System::set_block_number(5);
        assert_ok!(Stamp::add_stamper(RuntimeOrigin::root(), STAMPER));
        assert_noop!(
            Stamp::stamp(RuntimeOrigin::signed(STAMPER), batch(vec![plain(1)])),
            Error::<Test>::LegacyMessagesOff
        );
    });
}
