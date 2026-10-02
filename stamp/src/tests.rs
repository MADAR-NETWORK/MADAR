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
