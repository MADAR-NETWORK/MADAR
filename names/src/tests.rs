use crate::{self as madar_names, *};
use frame_support::{assert_noop, assert_ok, derive_impl, parameter_types, BoundedVec};
use sp_core::{ecdsa, ed25519, Pair};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Names: madar_names,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

const DAY: u64 = 24 * 3600 * 1000;
const START: u64 = 1_790_000_000_000;

parameter_types! {
    pub static Now: u64 = START;
    pub const MaxRegistrars: u32 = 2;
    pub const MaxTermMs: u64 = 10 * 366 * DAY;
}

pub struct TestTime;
impl frame_support::traits::UnixTime for TestTime {
    fn now() -> core::time::Duration {
        core::time::Duration::from_millis(Now::get())
    }
}

impl madar_names::Config for Test {
    type AdminOrigin = frame_system::EnsureRoot<u64>;
    type Time = TestTime;
    type MaxRegistrars = MaxRegistrars;
    type MaxTermMs = MaxTermMs;
    type WeightInfo = ();
}

const REG: u64 = 7;

fn ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    let mut e = sp_io::TestExternalities::new(t);
    e.execute_with(|| {
        Now::set(START);
        System::set_block_number(1);
        assert_ok!(Names::add_registrar(RuntimeOrigin::root(), REG));
    });
    e
}

fn nm(s: &str) -> BoundedVec<u8, frame_support::traits::ConstU32<MAX_NAME>> {
    BoundedVec::try_from(s.as_bytes().to_vec()).unwrap()
}

/// `personal_sign` as produced by MetaMask.
fn evm_proof(seed: u8, msg: &[u8]) -> (WalletProof, Wallet) {
    let pair = ecdsa::Pair::from_seed(&[seed; 32]);
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
    prefixed.extend_from_slice(msg);
    let digest = sp_io::hashing::keccak_256(&prefixed);
    let mut sig: [u8; 65] = pair.sign_prehashed(&digest).0;
    let public = sp_io::crypto::secp256k1_ecdsa_recover(&sig, &digest)
        .ok()
        .expect("recover");
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&sp_io::hashing::keccak_256(&public)[12..]);
    sig[64] += 27;
    (
        WalletProof::Evm {
            address: addr,
            signature: sig,
        },
        Wallet::Evm(addr),
    )
}

fn sol_proof(seed: u8, msg: &[u8]) -> (WalletProof, Wallet) {
    let pair = ed25519::Pair::from_seed(&[seed; 32]);
    let public = pair.public().0;
    (
        WalletProof::Solana {
            public,
            signature: pair.sign(msg).0,
        },
        Wallet::Solana(public),
    )
}

#[test]
fn name_rules() {
    for ok in ["abc", "ahmad", "a-b", "x1", "madar-network", "0xfeed"] {
        assert_eq!(valid_name(ok.as_bytes()), ok.len() >= 3, "{ok}");
    }
    for bad in [
        "ab",
        "-abc",
        "abc-",
        "Ahmad",
        "ahm ad",
        "aḥmad",
        "a_b",
        "a.b",
        &"a".repeat(33),
    ] {
        assert!(!valid_name(bad.as_bytes()), "{bad}");
    }
    assert_eq!(
        core::str::from_utf8(&register_message(b"ahmad")).unwrap(),
        "MADAR Names: register ahmad.madar to this wallet. No funds move."
    );
}

#[test]
fn registers_to_the_signing_wallet_evm_and_solana() {
    ext().execute_with(|| {
        let (p, w) = evm_proof(3, &register_message(b"ahmad"));
        assert_ok!(Names::register(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            p,
            START + 365 * DAY
        ));
        let r = madar_names::Names::<Test>::get(nm("ahmad")).unwrap();
        assert_eq!(
            (r.owner, r.registered, r.expires, r.registrar),
            (w, START, START + 365 * DAY, REG)
        );

        let (p, w) = sol_proof(4, &register_message(b"nova"));
        assert_ok!(Names::register(
            RuntimeOrigin::signed(REG),
            nm("nova"),
            p,
            START + 365 * DAY
        ));
        assert_eq!(
            madar_names::Names::<Test>::get(nm("nova")).unwrap().owner,
            w
        );
    });
}

#[test]
fn a_signature_for_another_name_is_rejected() {
    ext().execute_with(|| {
        let (p, _) = evm_proof(3, &register_message(b"ahmad"));
        assert_noop!(
            Names::register(RuntimeOrigin::signed(REG), nm("ahmed"), p, START + DAY),
            Error::<Test>::InvalidProof
        );
        let (p, _) = sol_proof(4, &register_message(b"ahmad"));
        assert_noop!(
            Names::register(RuntimeOrigin::signed(REG), nm("ahmed"), p, START + DAY),
            Error::<Test>::InvalidProof
        );
    });
}

#[test]
fn taken_until_expiry_plus_grace_then_free() {
    ext().execute_with(|| {
        let (a, _) = evm_proof(3, &register_message(b"ahmad"));
        assert_ok!(Names::register(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            a.clone(),
            START + 365 * DAY
        ));
        let (b, wb) = sol_proof(9, &register_message(b"ahmad"));
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                b.clone(),
                START + 400 * DAY
            ),
            Error::<Test>::NameTaken
        );
        // after expiry but inside the 30-day grace: still the owner's
        Now::set(START + 380 * DAY);
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                b.clone(),
                START + 800 * DAY
            ),
            Error::<Test>::NameTaken
        );
        // after the grace: anyone with a valid signature may take it, as a new registration
        Now::set(START + 396 * DAY);
        assert_ok!(Names::register(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            b,
            START + 800 * DAY
        ));
        let r = madar_names::Names::<Test>::get(nm("ahmad")).unwrap();
        assert_eq!((r.owner, r.registered), (wb, START + 396 * DAY));
    });
}

#[test]
fn the_owner_can_register_again_and_keeps_the_original_date() {
    ext().execute_with(|| {
        let (a, _) = evm_proof(3, &register_message(b"ahmad"));
        assert_ok!(Names::register(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            a.clone(),
            START + 365 * DAY
        ));
        Now::set(START + 370 * DAY);
        assert_ok!(Names::register(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            a,
            START + 735 * DAY
        ));
        let r = madar_names::Names::<Test>::get(nm("ahmad")).unwrap();
        assert_eq!((r.registered, r.expires), (START, START + 735 * DAY));
    });
}

/// Security 2026-10-12: a registrar re-sending the owner's old signature with a nearer `expires` must not shorten the paid
/// term (it could then wait for expiry + grace and hand the name to someone else).
#[test]
fn registering_again_for_the_same_owner_never_shortens_the_term() {
    ext().execute_with(|| {
        let (a, w) = evm_proof(3, &register_message(b"ahmad"));
        assert_ok!(Names::register(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            a.clone(),
            START + 3650 * DAY
        ));
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                a.clone(),
                START + 1
            ),
            Error::<Test>::ExpiryShortened
        );
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                a.clone(),
                START + 3649 * DAY
            ),
            Error::<Test>::ExpiryShortened
        );
        // the same term again is harmless, a longer one is an extension
        assert_ok!(Names::register(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            a.clone(),
            START + 3650 * DAY
        ));
        assert_ok!(Names::register(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            a,
            START + 3655 * DAY
        ));
        let r = madar_names::Names::<Test>::get(nm("ahmad")).unwrap();
        assert_eq!((r.owner, r.expires), (w, START + 3655 * DAY));
        // so another wallet still cannot take it a year later
        Now::set(START + 400 * DAY);
        let (b, _) = sol_proof(9, &register_message(b"ahmad"));
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                b,
                START + 800 * DAY
            ),
            Error::<Test>::NameTaken
        );
    });
}

#[test]
fn renew_extends_only_within_the_grace_and_limits() {
    ext().execute_with(|| {
        let (a, w) = evm_proof(3, &register_message(b"ahmad"));
        assert_ok!(Names::register(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            a,
            START + 365 * DAY
        ));
        assert_noop!(
            Names::renew(RuntimeOrigin::signed(REG), nm("ahmad"), START + 100 * DAY),
            Error::<Test>::BadExpiry
        );
        assert_noop!(
            Names::renew(RuntimeOrigin::signed(REG), nm("ahmad"), START + 4000 * DAY),
            Error::<Test>::BadExpiry
        );
        assert_ok!(Names::renew(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            START + 730 * DAY
        ));
        assert_eq!(
            madar_names::Names::<Test>::get(nm("ahmad")).unwrap().owner,
            w,
            "renew never changes the owner"
        );
        assert_noop!(
            Names::renew(RuntimeOrigin::signed(REG), nm("nobody"), START + 730 * DAY),
            Error::<Test>::NotRegistered
        );
        Now::set(START + 761 * DAY); // past expiry + grace
        assert_noop!(
            Names::renew(RuntimeOrigin::signed(REG), nm("ahmad"), START + 1100 * DAY),
            Error::<Test>::NotRegistered
        );
    });
}

#[test]
fn reserved_invalid_expiry_and_origins() {
    ext().execute_with(|| {
        assert_ok!(Names::set_reserved(
            RuntimeOrigin::root(),
            nm("google"),
            true
        ));
        let (p, _) = evm_proof(3, &register_message(b"google"));
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(REG),
                nm("google"),
                p.clone(),
                START + DAY
            ),
            Error::<Test>::NameReserved
        );
        assert_ok!(Names::set_reserved(
            RuntimeOrigin::root(),
            nm("google"),
            false
        ));
        assert_noop!(
            Names::register(RuntimeOrigin::signed(REG), nm("google"), p.clone(), START),
            Error::<Test>::BadExpiry
        );
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(REG),
                nm("google"),
                p.clone(),
                START + 4000 * DAY
            ),
            Error::<Test>::BadExpiry
        );
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(99),
                nm("google"),
                p.clone(),
                START + DAY
            ),
            Error::<Test>::NotRegistrar
        );
        let (q, _) = evm_proof(3, &register_message(b"Go"));
        assert_noop!(
            Names::register(RuntimeOrigin::signed(REG), nm("Go"), q, START + DAY),
            Error::<Test>::InvalidName
        );
        assert_noop!(
            Names::set_reserved(RuntimeOrigin::signed(REG), nm("abc"), true),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_noop!(
            Names::add_registrar(RuntimeOrigin::root(), REG),
            Error::<Test>::AlreadyRegistrar
        );
        assert_ok!(Names::add_registrar(RuntimeOrigin::root(), 8));
        assert_noop!(
            Names::add_registrar(RuntimeOrigin::root(), 9),
            Error::<Test>::TooManyRegistrars
        );
        assert_ok!(Names::remove_registrar(RuntimeOrigin::root(), REG));
        assert_noop!(
            Names::register(RuntimeOrigin::signed(REG), nm("google"), p, START + DAY),
            Error::<Test>::NotRegistrar
        );
    });
}

#[test]
fn committee_can_revoke_a_fraudulent_name_with_a_public_reason() {
    ext().execute_with(|| {
        let (p, w) = evm_proof(3, &register_message(b"bank-help"));
        assert_ok!(Names::register(
            RuntimeOrigin::signed(REG),
            nm("bank-help"),
            p.clone(),
            START + 365 * DAY
        ));
        let reason: BoundedVec<u8, frame_support::traits::ConstU32<256>> =
            BoundedVec::try_from(b"impersonates a bank (report #1)".to_vec()).unwrap();
        assert_noop!(
            Names::revoke(RuntimeOrigin::signed(REG), nm("bank-help"), reason.clone()),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_noop!(
            Names::revoke(
                RuntimeOrigin::root(),
                nm("bank-help"),
                BoundedVec::default()
            ),
            Error::<Test>::ReasonRequired
        );
        assert_ok!(Names::revoke(
            RuntimeOrigin::root(),
            nm("bank-help"),
            reason.clone()
        ));
        assert!(madar_names::Names::<Test>::get(nm("bank-help")).is_none());
        System::assert_has_event(
            Event::Revoked {
                name: nm("bank-help"),
                owner: w,
                reason,
            }
            .into(),
        );
        // reserved afterwards: the same wallet cannot simply register it again
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(REG),
                nm("bank-help"),
                p,
                START + 365 * DAY
            ),
            Error::<Test>::NameReserved
        );
        assert_noop!(
            Names::revoke(
                RuntimeOrigin::root(),
                nm("nobody"),
                BoundedVec::try_from(b"x".to_vec()).unwrap()
            ),
            Error::<Test>::NotRegistered
        );
    });
}

const MIN: u64 = 60 * 1000;

fn pay_to(s: &str) -> BoundedVec<u8, frame_support::traits::ConstU32<MAX_PAY_TO>> {
    BoundedVec::try_from(s.as_bytes().to_vec()).unwrap()
}

/// ahmad.madar registered to the EVM wallet of seed 3 for a year.
fn with_owner() -> Wallet {
    let (p, w) = evm_proof(3, &register_message(b"ahmad"));
    assert_ok!(Names::register(
        RuntimeOrigin::signed(REG),
        nm("ahmad"),
        p,
        START + 365 * DAY
    ));
    w
}

const PAY: &str = "0x00000000000000000000000000000000000000aa";

/// The safe sale as the service sends it since spec 8 (v2 only): the exact amount = the signed price, the rail from the
/// payee (EVM -> base_usdc, Solana -> solana_usdc).
#[allow(clippy::too_many_arguments)]
fn lock1(
    name: NameOf,
    sp: WalletProof,
    price: u64,
    to: BoundedVec<u8, frame_support::traits::ConstU32<MAX_PAY_TO>>,
    offer_until: u64,
    bp: WalletProof,
    lock_until: u64,
) -> sp_runtime::DispatchResult {
    let rail = if to.starts_with(b"0x") { 2 } else { 0 };
    Names::lock_sale_v2(
        RuntimeOrigin::signed(REG),
        name,
        sp,
        price,
        to,
        offer_until,
        bp,
        lock_until,
        price.saturating_mul(MICRO_PER_CENT),
        rail,
    )
}

/// Completes with a payment reference that fits the lock's rail (a fresh base hash per moment).
fn complete1(name: NameOf) -> sp_runtime::DispatchResult {
    let r = match madar_names::LockTerms::<Test>::get(&name) {
        Some(t) if t.rail < 2 => SOL_SIG.to_string(),
        _ => format!("base:0x{:064x}", Now::get()),
    };
    Names::complete_sale_v2(RuntimeOrigin::signed(REG), name, pref(&r))
}

#[test]
fn sale_messages_are_exact() {
    assert_eq!(
        core::str::from_utf8(&sale_message(b"ahmad", 3, 120_050, PAY.as_bytes(), 1_790_000_000_000)).unwrap(),
        "MADAR Names: I offer ahmad.madar for 1200.50 USD, paid to 0x00000000000000000000000000000000000000aa, under the MADAR Names sale terms v1. Offer 3, valid until 1790000000000."
    );
    assert_eq!(
        core::str::from_utf8(&buy_message(b"ahmad", 0, 905)).unwrap(),
        "MADAR Names: I buy ahmad.madar for 9.05 USD plus the MADAR fee, under the MADAR Names sale terms v1. Offer 0. The name comes to this wallet."
    );
    assert_eq!(
        core::str::from_utf8(&cancel_message(b"ahmad", 12)).unwrap(),
        "MADAR Names: cancel my sale offer for ahmad.madar. Offer 12."
    );
}

#[test]
fn safe_sale_locks_then_moves_the_name_keeping_its_term() {
    ext().execute_with(|| {
        let seller = with_owner();
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        let (sp, _) = evm_proof(
            3,
            &sale_message(b"ahmad", n, 50_000, PAY.as_bytes(), START + 30 * DAY),
        );
        let (bp, buyer) = sol_proof(8, &buy_message(b"ahmad", n, 50_000));
        assert_ok!(lock1(
            nm("ahmad"),
            sp.clone(),
            50_000,
            pay_to(PAY),
            START + 30 * DAY,
            bp.clone(),
            START + 60 * MIN
        ));
        assert!(Names::locked(&nm("ahmad"), START));
        // while locked: no second buyer, no cancel
        let (bp2, _) = sol_proof(9, &buy_message(b"ahmad", n, 50_000));
        assert_noop!(
            lock1(
                nm("ahmad"),
                sp.clone(),
                50_000,
                pay_to(PAY),
                START + 30 * DAY,
                bp2,
                START + 60 * MIN
            ),
            Error::<Test>::SaleLocked
        );
        let (cp, _) = evm_proof(3, &cancel_message(b"ahmad", n));
        assert_noop!(
            Names::cancel_offer(RuntimeOrigin::signed(REG), nm("ahmad"), cp),
            Error::<Test>::SaleLocked
        );
        // payment arrived: the name moves, the paid term stays
        Now::set(START + 20 * MIN);
        assert_ok!(complete1(nm("ahmad")));
        let r = madar_names::Names::<Test>::get(nm("ahmad")).unwrap();
        assert_eq!(
            (r.owner.clone(), r.expires, r.registered),
            (buyer.clone(), START + 365 * DAY, START + 20 * MIN)
        );
        System::assert_has_event(
            Event::SaleCompletedV2 {
                name: nm("ahmad"),
                from: seller,
                to: buyer,
                price_cents: 50_000,
                pay_to: pay_to(PAY),
                rail: 2,
                amount: 500_000_000,
                payment_ref: pref(&format!("base:0x{:064x}", START + 20 * MIN)),
            }
            .into(),
        );
        // the old offer and signatures are dead now
        assert!(madar_names::Locks::<Test>::get(nm("ahmad")).is_none());
        assert_noop!(complete1(nm("ahmad")), Error::<Test>::NoSaleLock);
        let (bp3, _) = sol_proof(9, &buy_message(b"ahmad", n, 50_000));
        assert_noop!(
            lock1(
                nm("ahmad"),
                sp,
                50_000,
                pay_to(PAY),
                START + 30 * DAY,
                bp3,
                START + 80 * MIN
            ),
            Error::<Test>::InvalidProof
        );
    });
}

#[test]
fn an_unpaid_lock_lapses_by_itself_within_an_hour() {
    ext().execute_with(|| {
        let seller = with_owner();
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        let (sp, _) = evm_proof(
            3,
            &sale_message(b"ahmad", n, 1_000, PAY.as_bytes(), START + DAY),
        );
        let (bp, _) = sol_proof(8, &buy_message(b"ahmad", n, 1_000));
        // never more than 60 minutes
        assert_noop!(
            lock1(
                nm("ahmad"),
                sp.clone(),
                1_000,
                pay_to(PAY),
                START + DAY,
                bp.clone(),
                START + 61 * MIN
            ),
            Error::<Test>::BadLock
        );
        assert_noop!(
            lock1(
                nm("ahmad"),
                sp.clone(),
                1_000,
                pay_to(PAY),
                START + DAY,
                bp.clone(),
                START
            ),
            Error::<Test>::BadLock
        );
        assert_ok!(lock1(
            nm("ahmad"),
            sp.clone(),
            1_000,
            pay_to(PAY),
            START + DAY,
            bp.clone(),
            START + 60 * MIN
        ));
        // one minute after the deadline: no sale can complete, the name is free for another buyer, owner unchanged
        Now::set(START + 61 * MIN);
        assert!(!Names::locked(&nm("ahmad"), START + 61 * MIN));
        assert_noop!(complete1(nm("ahmad")), Error::<Test>::NoSaleLock);
        assert_eq!(
            madar_names::Names::<Test>::get(nm("ahmad")).unwrap().owner,
            seller
        );
        let (bp2, _) = sol_proof(9, &buy_message(b"ahmad", n, 1_000));
        assert_ok!(lock1(
            nm("ahmad"),
            sp,
            1_000,
            pay_to(PAY),
            START + DAY,
            bp2,
            START + 100 * MIN
        ));
    });
}

#[test]
fn offers_must_come_from_the_owner_match_the_price_and_be_current() {
    ext().execute_with(|| {
        with_owner();
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        let (bp, _) = sol_proof(8, &buy_message(b"ahmad", n, 1_000));
        // someone else's "offer"
        let (fake, _) = evm_proof(
            5,
            &sale_message(b"ahmad", n, 1_000, PAY.as_bytes(), START + DAY),
        );
        assert_noop!(
            lock1(
                nm("ahmad"),
                fake,
                1_000,
                pay_to(PAY),
                START + DAY,
                bp.clone(),
                START + MIN
            ),
            Error::<Test>::BadOffer
        );
        // the registrar cannot change the price or the payee the seller signed
        let (sp, _) = evm_proof(
            3,
            &sale_message(b"ahmad", n, 1_000, PAY.as_bytes(), START + DAY),
        );
        assert_noop!(
            lock1(
                nm("ahmad"),
                sp.clone(),
                900,
                pay_to(PAY),
                START + DAY,
                bp.clone(),
                START + MIN
            ),
            Error::<Test>::InvalidProof
        );
        assert_noop!(
            lock1(
                nm("ahmad"),
                sp.clone(),
                1_000,
                pay_to("0xother"),
                START + DAY,
                bp.clone(),
                START + MIN
            ),
            Error::<Test>::InvalidProof
        );
        // the buyer signed another price
        let (bp_low, _) = sol_proof(8, &buy_message(b"ahmad", n, 500));
        assert_noop!(
            lock1(
                nm("ahmad"),
                sp.clone(),
                1_000,
                pay_to(PAY),
                START + DAY,
                bp_low,
                START + MIN
            ),
            Error::<Test>::InvalidProof
        );
        // the owner cannot buy from himself, zero price is refused, an expired offer is refused
        let (self_buy, _) = evm_proof(3, &buy_message(b"ahmad", n, 1_000));
        assert_noop!(
            lock1(
                nm("ahmad"),
                sp.clone(),
                1_000,
                pay_to(PAY),
                START + DAY,
                self_buy,
                START + MIN
            ),
            Error::<Test>::BadOffer
        );
        assert_noop!(
            lock1(
                nm("ahmad"),
                sp.clone(),
                0,
                pay_to(PAY),
                START + DAY,
                bp.clone(),
                START + MIN
            ),
            Error::<Test>::BadPrice
        );
        Now::set(START + DAY + 1);
        assert_noop!(
            lock1(
                nm("ahmad"),
                sp,
                1_000,
                pay_to(PAY),
                START + DAY,
                bp,
                START + DAY + MIN
            ),
            Error::<Test>::BadOffer
        );
        assert_noop!(
            Names::complete_sale_v2(RuntimeOrigin::signed(99), nm("ahmad"), pref(BASE_TX)),
            Error::<Test>::NotRegistrar
        );
    });
}

#[test]
fn the_owner_can_cancel_offers_and_old_signatures_die() {
    ext().execute_with(|| {
        with_owner();
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        let (sp, _) = evm_proof(
            3,
            &sale_message(b"ahmad", n, 1_000, PAY.as_bytes(), START + DAY),
        );
        let (stranger, _) = evm_proof(5, &cancel_message(b"ahmad", n));
        assert_noop!(
            Names::cancel_offer(RuntimeOrigin::signed(REG), nm("ahmad"), stranger),
            Error::<Test>::BadOffer
        );
        let (cp, _) = evm_proof(3, &cancel_message(b"ahmad", n));
        assert_ok!(Names::cancel_offer(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            cp
        ));
        assert_eq!(madar_names::SaleNonce::<Test>::get(nm("ahmad")), n + 1);
        let (bp, _) = sol_proof(8, &buy_message(b"ahmad", n, 1_000));
        assert_noop!(
            lock1(
                nm("ahmad"),
                sp,
                1_000,
                pay_to(PAY),
                START + DAY,
                bp,
                START + MIN
            ),
            Error::<Test>::InvalidProof
        );
    });
}

// ---------------------------------------------------------------- spec 8: payment proof on chain

const SOL_PAY: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const BASE_TX: &str = "base:0x1111111111111111111111111111111111111111111111111111111111111111";
const SOL_SIG: &str = "solana:5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";

fn pref(s: &str) -> PaymentRef {
    BoundedVec::try_from(s.as_bytes().to_vec()).unwrap()
}

/// Seller (EVM seed 3) offers ahmad.madar for `price`, paid to `to`; buyer (Solana seed 8) accepts.
fn v2_proofs(price: u64, to: &str) -> (WalletProof, WalletProof, Wallet) {
    let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
    let (sp, _) = evm_proof(
        3,
        &sale_message(b"ahmad", n, price, to.as_bytes(), START + DAY),
    );
    let (bp, buyer) = sol_proof(8, &buy_message(b"ahmad", n, price));
    (sp, bp, buyer)
}

fn lock_v2(
    sp: WalletProof,
    bp: WalletProof,
    price: u64,
    to: &str,
    amount: u64,
    rail: u8,
) -> sp_runtime::DispatchResult {
    Names::lock_sale_v2(
        RuntimeOrigin::signed(REG),
        nm("ahmad"),
        sp,
        price,
        pay_to(to),
        START + DAY,
        bp,
        START + 30 * MIN,
        amount,
        rail,
    )
}

#[test]
fn payment_refs_rails_and_amounts_are_checked() {
    assert!(valid_payment_ref(2, BASE_TX.as_bytes()));
    assert!(valid_payment_ref(
        3,
        BASE_TX.replace("base", "arbitrum").as_bytes()
    ));
    assert!(valid_payment_ref(0, SOL_SIG.as_bytes()) && valid_payment_ref(1, SOL_SIG.as_bytes()));
    assert!(
        !valid_payment_ref(3, BASE_TX.as_bytes()),
        "base ref for an arbitrum lock"
    );
    assert!(!valid_payment_ref(0, BASE_TX.as_bytes()));
    assert!(
        !valid_payment_ref(
            2,
            "base:0xABCDEF1111111111111111111111111111111111111111111111111111111111".as_bytes()
        ),
        "upper-case hex refused"
    );
    assert!(!valid_payment_ref(2, b"base:0x1234"), "short hash");
    assert!(!valid_payment_ref(
        2,
        b"base 0x1111111111111111111111111111111111111111111111111111111111111111"
    ));
    assert!(
        !valid_payment_ref(0, b"solana:0OIl000000000000000000000000000000000000"),
        "not base58"
    );
    assert!(!valid_payment_ref(0, b"solana:abc"));
    assert!(!valid_payment_ref(5, SOL_SIG.as_bytes()), "unknown rail");
    assert_eq!(rail_chain(4), Some(&b"arbitrum"[..]));
    assert!(rail_fits_pay_to(2, PAY.as_bytes()) && !rail_fits_pay_to(0, PAY.as_bytes()));
    assert!(
        rail_fits_pay_to(1, SOL_PAY.as_bytes())
            && !rail_fits_pay_to(4, SOL_PAY.as_bytes())
            && !rail_fits_pay_to(9, PAY.as_bytes())
    );
    // $500.00 = 500_000_000 micro; the registrar service adds 0.0001 to 0.0999
    assert!(
        amount_fits_price(500_034_700, 50_000)
            && amount_fits_price(500_000_000, 50_000)
            && amount_fits_price(500_099_999, 50_000)
    );
    assert!(
        !amount_fits_price(499_999_999, 50_000)
            && !amount_fits_price(500_100_000, 50_000)
            && !amount_fits_price(u64::MAX, u64::MAX)
    );
}

#[test]
fn v2_sale_records_amount_rail_and_payment_ref() {
    ext().execute_with(|| {
        let seller = with_owner();
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        let (sp, bp, buyer) = v2_proofs(50_000, PAY);
        assert_ok!(lock_v2(sp, bp, 50_000, PAY, 500_034_700, 2));
        assert_eq!(
            madar_names::LockTerms::<Test>::get(nm("ahmad")),
            Some(SaleTerms {
                rail: 2,
                pay_amount: 500_034_700
            })
        );
        System::assert_has_event(
            Event::SaleLockedV2 {
                name: nm("ahmad"),
                buyer: buyer.clone(),
                price_cents: 50_000,
                until: START + 30 * MIN,
                pay_to: pay_to(PAY),
                rail: 2,
                amount: 500_034_700,
            }
            .into(),
        );
        Now::set(START + 10 * MIN);
        assert_ok!(Names::complete_sale_v2(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            pref(BASE_TX)
        ));
        let r = madar_names::Names::<Test>::get(nm("ahmad")).unwrap();
        assert_eq!(
            (r.owner, r.expires, r.registered),
            (buyer.clone(), START + 365 * DAY, START + 10 * MIN)
        );
        System::assert_has_event(
            Event::SaleCompletedV2 {
                name: nm("ahmad"),
                from: seller,
                to: buyer,
                price_cents: 50_000,
                pay_to: pay_to(PAY),
                rail: 2,
                amount: 500_034_700,
                payment_ref: pref(BASE_TX),
            }
            .into(),
        );
        // the offer number moved on, lock and terms are gone, the payment is remembered
        assert_eq!(madar_names::SaleNonce::<Test>::get(nm("ahmad")), n + 1);
        assert!(
            madar_names::Locks::<Test>::get(nm("ahmad")).is_none()
                && madar_names::LockTerms::<Test>::get(nm("ahmad")).is_none()
        );
        assert_eq!(
            madar_names::UsedPaymentRefs::<Test>::get(sp_io::hashing::blake2_256(
                BASE_TX.as_bytes()
            )),
            Some(nm("ahmad"))
        );
        assert_noop!(
            Names::complete_sale_v2(RuntimeOrigin::signed(REG), nm("ahmad"), pref(BASE_TX)),
            Error::<Test>::NoSaleLock
        );
    });
}

#[test]
fn v2_lock_refuses_a_wrong_rail_or_amount() {
    ext().execute_with(|| {
        with_owner();
        let (sp, bp, _) = v2_proofs(50_000, PAY);
        // EVM payee with a Solana rail, unknown rail
        assert_noop!(
            lock_v2(sp.clone(), bp.clone(), 50_000, PAY, 500_034_700, 0),
            Error::<Test>::BadRail
        );
        assert_noop!(
            lock_v2(sp.clone(), bp.clone(), 50_000, PAY, 500_034_700, 5),
            Error::<Test>::BadRail
        );
        // below the signed price, or 0.10 or more above it
        assert_noop!(
            lock_v2(sp.clone(), bp.clone(), 50_000, PAY, 499_000_000, 2),
            Error::<Test>::BadAmount
        );
        assert_noop!(
            lock_v2(sp.clone(), bp.clone(), 50_000, PAY, 500_100_000, 2),
            Error::<Test>::BadAmount
        );
        // the v1 checks still apply: a price the seller never signed
        assert_noop!(
            lock_v2(sp.clone(), bp.clone(), 40_000, PAY, 400_034_700, 2),
            Error::<Test>::InvalidProof
        );
        assert_noop!(
            Names::lock_sale_v2(
                RuntimeOrigin::signed(99),
                nm("ahmad"),
                sp.clone(),
                50_000,
                pay_to(PAY),
                START + DAY,
                bp.clone(),
                START + MIN,
                500_034_700,
                2
            ),
            Error::<Test>::NotRegistrar
        );
        // a Solana payee on a Solana rail is fine
        let (sp, bp, _) = v2_proofs(1_000, SOL_PAY);
        assert_ok!(lock_v2(sp, bp, 1_000, SOL_PAY, 10_000_100, 1));
    });
}

#[test]
fn v2_complete_refuses_bad_or_reused_refs_and_v1_locks() {
    ext().execute_with(|| {
        with_owner();
        // a v1 lock left from before the upgrade (no amount or rail recorded): not completed by v2, and once it lapses
        // (at most 60 minutes after the upgrade) not by the old call either
        let (_, _, buyer) = v2_proofs(1_000, SOL_PAY);
        madar_names::Locks::<Test>::insert(
            nm("ahmad"),
            SaleLock {
                buyer,
                until: START + 30 * MIN,
                price_cents: 1_000,
                pay_to: pay_to(SOL_PAY),
            },
        );
        assert_noop!(
            Names::complete_sale_v2(RuntimeOrigin::signed(REG), nm("ahmad"), pref(SOL_SIG)),
            Error::<Test>::NotV2Lock
        );
        Now::set(START + 31 * MIN);
        assert_noop!(
            Names::complete_sale_v2(RuntimeOrigin::signed(REG), nm("ahmad"), pref(SOL_SIG)),
            Error::<Test>::NoSaleLock
        );
    });
    ext().execute_with(|| {
        with_owner();
        let (sp, bp, buyer) = v2_proofs(1_000, SOL_PAY);
        assert_ok!(lock_v2(sp, bp, 1_000, SOL_PAY, 10_000_100, 0));
        // wrong chain for the rail, malformed, not a registrar
        assert_noop!(Names::complete_sale_v2(RuntimeOrigin::signed(REG), nm("ahmad"), pref(BASE_TX)), Error::<Test>::BadPaymentRef);
        assert_noop!(Names::complete_sale_v2(RuntimeOrigin::signed(REG), nm("ahmad"), pref("solana:")), Error::<Test>::BadPaymentRef);
        assert_noop!(Names::complete_sale_v2(RuntimeOrigin::signed(99), nm("ahmad"), pref(SOL_SIG)), Error::<Test>::NotRegistrar);
        // a reference already used for another sale is refused
        madar_names::UsedPaymentRefs::<Test>::insert(sp_io::hashing::blake2_256(SOL_SIG.as_bytes()), nm("other"));
        assert_noop!(Names::complete_sale_v2(RuntimeOrigin::signed(REG), nm("ahmad"), pref(SOL_SIG)), Error::<Test>::PaymentRefUsed);
        let other = "solana:4VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";
        // after the lock lapses nothing completes
        Now::set(START + 31 * MIN);
        assert_noop!(Names::complete_sale_v2(RuntimeOrigin::signed(REG), nm("ahmad"), pref(other)), Error::<Test>::NoSaleLock);
        Now::set(START + 20 * MIN);
        assert_ok!(Names::complete_sale_v2(RuntimeOrigin::signed(REG), nm("ahmad"), pref(other)));
        assert_eq!(madar_names::Names::<Test>::get(nm("ahmad")).unwrap().owner, buyer);
    });
}

#[test]
fn a_lapsed_v2_lock_can_be_replaced_and_cancel_clears_terms() {
    ext().execute_with(|| {
        with_owner();
        let (sp, bp, _) = v2_proofs(1_000, PAY);
        assert_ok!(lock_v2(sp.clone(), bp.clone(), 1_000, PAY, 10_000_100, 3));
        Now::set(START + 31 * MIN);
        // the v2 lock lapsed: a new v2 lock may take its place with its own terms
        assert_ok!(Names::lock_sale_v2(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            sp.clone(),
            1_000,
            pay_to(PAY),
            START + DAY,
            bp.clone(),
            START + 50 * MIN,
            10_000_200,
            2
        ));
        assert_eq!(
            madar_names::LockTerms::<Test>::get(nm("ahmad")),
            Some(SaleTerms {
                rail: 2,
                pay_amount: 10_000_200
            })
        );
        Now::set(START + 51 * MIN);
        assert_ok!(Names::lock_sale_v2(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            sp,
            1_000,
            pay_to(PAY),
            START + DAY,
            bp,
            START + 80 * MIN,
            10_000_100,
            4
        ));
        assert!(madar_names::LockTerms::<Test>::get(nm("ahmad")).is_some());
        // lapsed again: cancelling the offers also clears the terms
        Now::set(START + 81 * MIN);
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        let (cp, _) = evm_proof(3, &cancel_message(b"ahmad", n));
        assert_ok!(Names::cancel_offer(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            cp
        ));
        assert!(
            madar_names::LockTerms::<Test>::get(nm("ahmad")).is_none()
                && madar_names::Locks::<Test>::get(nm("ahmad")).is_none()
        );
    });
}
