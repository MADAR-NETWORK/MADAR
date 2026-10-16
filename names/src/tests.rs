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
        // the spec 9 upgrade as on the live chain (storage version 0 -> 1): v1 messages accepted until START + 72 h
        frame_support::traits::StorageVersion::new(0).put::<Names>();
        <Names as frame_support::traits::OnRuntimeUpgrade>::on_runtime_upgrade();
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
        madar_names::LegacyAcceptedUntil::<Test>::put(u64::MAX); // about the name rules over months, not the v1 sunset
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
        madar_names::LegacyAcceptedUntil::<Test>::put(u64::MAX); // about the name rules over months, not the v1 sunset
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
        madar_names::LegacyAcceptedUntil::<Test>::put(u64::MAX); // about the name rules over months, not the v1 sunset
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
        madar_names::LegacyAcceptedUntil::<Test>::put(u64::MAX); // about the name rules over months, not the v1 sunset
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
                pay_to("0x00000000000000000000000000000000000000bb"),
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
    assert!(!valid_payment_ref(13, SOL_SIG.as_bytes()), "unknown rail");
    assert!(
        !valid_payment_ref(5, SOL_SIG.as_bytes()),
        "a Solana ref for an Ethereum lock"
    );
    assert_eq!(rail_chain(4), Some(&b"arbitrum"[..]));
    assert!(rail_fits_pay_to(2, PAY.as_bytes()) && !rail_fits_pay_to(0, PAY.as_bytes()));
    assert!(
        rail_fits_pay_to(1, SOL_PAY.as_bytes())
            && !rail_fits_pay_to(4, SOL_PAY.as_bytes())
            && !rail_fits_pay_to(13, PAY.as_bytes())
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
            lock_v2(sp.clone(), bp.clone(), 50_000, PAY, 500_034_700, 13),
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

// ---------------------------------------------------------------- spec 9: v2 messages, transfer, reassign, cleanup

/// This chain's id in v2 messages (block 0 hash; the mock genesis keeps hash69 there).
fn net() -> Vec<u8> {
    Names::network()
}

const OTHER_NET: [u8; 32] = [7u8; 32];
const SOL_PAY2: &str = "BxMsjB6DM2cZV2vhzPQBETJnBh257ewnvkT61CoZpEMt";

fn reason(s: &str) -> BoundedVec<u8, frame_support::traits::ConstU32<256>> {
    BoundedVec::try_from(s.as_bytes().to_vec()).unwrap()
}

fn s(m: Vec<u8>) -> String {
    String::from_utf8(m).unwrap()
}

#[test]
fn v2_messages_are_exact_and_end_with_network_and_expiry() {
    let n = [0xabu8; 32];
    let tail = format!(
        "\nnetwork: 0x{}\nvalid until: 1790000000000",
        "ab".repeat(32)
    );
    assert_eq!(
        s(register_message_v2(b"ahmad", &n, 1_790_000_000_000)),
        format!("MADAR Names: register ahmad.madar to this wallet. No funds move.{tail}")
    );
    assert_eq!(
        s(sale_message_v2(b"ahmad", 3, 120_050, PAY.as_bytes(), 1_790_000_000_000, &n)),
        format!("MADAR Names: I offer ahmad.madar for 1200.50 USD, paid to {PAY}, under the MADAR Names sale terms v1. Offer 3.{tail}")
    );
    assert_eq!(
        s(buy_message_v2(b"ahmad", 0, 905, PAY.as_bytes(), 1_790_000_000_000, &n)),
        format!("MADAR Names: I buy ahmad.madar for 9.05 USD plus the MADAR fee, paid to {PAY}, under the MADAR Names sale terms v1. Offer 0. The name comes to this wallet.{tail}")
    );
    assert_eq!(
        s(cancel_message_v2(b"ahmad", 12, &n, 1_790_000_000_000)),
        format!("MADAR Names: cancel my sale offer for ahmad.madar. Offer 12.{tail}")
    );
    let evm = Wallet::Evm([0xAB; 20]);
    assert_eq!(
        s(transfer_message(b"ahmad", 4, &evm, &n, 1_790_000_000_000)),
        format!(
            "MADAR Names: transfer ahmad.madar to 0x{}. No funds move. Nonce 4.{tail}",
            "ab".repeat(20)
        )
    );
    let sol = Wallet::Solana(
        base58_decode(SOL_PAY2.as_bytes())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        s(transfer_message(b"ahmad", 4, &sol, &n, 1_790_000_000_000)),
        format!("MADAR Names: transfer ahmad.madar to {SOL_PAY2}. No funds move. Nonce 4.{tail}")
    );
    assert_eq!(
        s(accept_message(b"ahmad", 4, &n, 1_790_000_000_000)),
        format!(
            "MADAR Names: I accept ahmad.madar into this wallet. No funds move. Nonce 4.{tail}"
        )
    );
}

#[test]
fn base58_wallet_text_and_strict_pay_to() {
    for (raw, txt) in [
        (&[0u8, 0, 1][..], "112"),
        (&[][..], ""),
        (&[0xff; 4][..], "7YXq9G"),
    ] {
        assert_eq!(s(base58_encode(raw)), txt);
        assert_eq!(base58_decode(txt.as_bytes()).unwrap(), raw.to_vec());
    }
    let k = base58_decode(SOL_PAY.as_bytes()).unwrap();
    assert_eq!((k.len(), s(base58_encode(&k))), (32, SOL_PAY.to_string()));
    assert!(base58_decode(b"0OIl").is_none());
    // EVM rails: 0x + exactly 40 hex; Solana rails: a 32-byte base58 key
    assert!(
        valid_pay_to(2, PAY.as_bytes())
            && valid_pay_to(12, b"0xB95c91Bb8C58b929d501BD8D0aCcB420F8A7045d")
    );
    assert!(valid_pay_to(0, SOL_PAY.as_bytes()) && valid_pay_to(1, SOL_PAY2.as_bytes()));
    for bad in [
        "0xother",
        "0x00000000000000000000000000000000000000aa0",
        "0x0000000000000000000000000000000000000g00",
        "0x00000000000000000000000000000000000000aa, valid until 9",
    ] {
        assert!(!valid_pay_to(2, bad.as_bytes()), "{bad}");
    }
    assert!(
        !valid_pay_to(0, b"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJos"),
        "not 32 bytes"
    );
    assert!(
        !valid_pay_to(0, PAY.as_bytes())
            && !valid_pay_to(2, SOL_PAY.as_bytes())
            && !valid_pay_to(13, PAY.as_bytes())
    );
    assert!(!valid_pay_to(
        1,
        b"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAs\n"
    ));
}

#[test]
fn register_v2_is_bound_to_this_network_and_its_expiry() {
    ext().execute_with(|| {
        let until = START + DAY;
        let exp = START + 365 * DAY;
        // another network's signature (a drill chain, a future mainnet) does not work here
        let (other, _) = evm_proof(3, &register_message_v2(b"ahmad", &OTHER_NET, until));
        assert_noop!(
            Names::register_v2(RuntimeOrigin::signed(REG), nm("ahmad"), other, exp, until),
            Error::<Test>::InvalidProof
        );
        // a v1 signature is not a v2 signature, and the other way round
        let (v1, _) = evm_proof(3, &register_message(b"ahmad"));
        assert_noop!(
            Names::register_v2(RuntimeOrigin::signed(REG), nm("ahmad"), v1, exp, until),
            Error::<Test>::InvalidProof
        );
        let (p, w) = evm_proof(3, &register_message_v2(b"ahmad", &net(), until));
        assert_noop!(
            Names::register(RuntimeOrigin::signed(REG), nm("ahmad"), p.clone(), exp),
            Error::<Test>::InvalidProof
        );
        // the registrar cannot stretch the window: the signed time is part of the message
        assert_noop!(
            Names::register_v2(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                p.clone(),
                exp,
                until + 1
            ),
            Error::<Test>::InvalidProof
        );
        assert_noop!(
            Names::register_v2(
                RuntimeOrigin::signed(99),
                nm("ahmad"),
                p.clone(),
                exp,
                until
            ),
            Error::<Test>::NotRegistrar
        );
        assert_ok!(Names::register_v2(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            p.clone(),
            exp,
            until
        ));
        assert_eq!(
            madar_names::Names::<Test>::get(nm("ahmad")).unwrap().owner,
            w.clone()
        );
        System::assert_has_event(
            Event::Registered {
                name: nm("ahmad"),
                owner: w,
                expires: exp,
            }
            .into(),
        );
        // too far ahead, or already over
        let far = START + MAX_REGISTER_PROOF_MS + 1;
        let (pf, _) = sol_proof(4, &register_message_v2(b"sara", &net(), far));
        assert_noop!(
            Names::register_v2(RuntimeOrigin::signed(REG), nm("sara"), pf, exp, far),
            Error::<Test>::ProofExpired
        );
        let (ps, _) = sol_proof(4, &register_message_v2(b"sara", &net(), START + 7 * DAY));
        assert_ok!(Names::register_v2(
            RuntimeOrigin::signed(REG),
            nm("sara"),
            ps.clone(),
            exp,
            START + 7 * DAY
        ));
        Now::set(START + 7 * DAY + 1);
        assert_noop!(
            Names::register_v2(
                RuntimeOrigin::signed(REG),
                nm("sara"),
                ps,
                exp + DAY,
                START + 7 * DAY
            ),
            Error::<Test>::ProofExpired
        );
    });
}

/// The attack the v2 expiry closes: a registrar keeps an old register signature and, after the name lapsed (term +
/// grace), writes it back to that wallet years later. With v2 the proof dies after at most 7 days.
#[test]
fn an_old_register_proof_cannot_be_replayed_after_the_name_lapsed() {
    ext().execute_with(|| {
        let until = START + 7 * DAY;
        let (p, _) = evm_proof(3, &register_message_v2(b"ahmad", &net(), until));
        assert_ok!(Names::register_v2(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            p.clone(),
            START + 2 * DAY,
            until
        ));
        Now::set(START + 40 * DAY);
        assert_noop!(
            Names::register_v2(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                p,
                START + 400 * DAY,
                until
            ),
            Error::<Test>::ProofExpired
        );
    });
}

/// Independent review #2: v1 messages stop by themselves 72 h after the spec 9 upgrade (no committee action), the migration
/// runs once, and a fresh chain refuses v1 from block 0.
#[test]
fn legacy_messages_stop_by_themselves_72_hours_after_the_upgrade() {
    ext().execute_with(|| {
        let until = START + madar_stamp::LEGACY_SUNSET_MS;
        assert_eq!(
            madar_names::LegacyAcceptedUntil::<Test>::get(),
            until,
            "set by the spec 9 migration"
        );
        System::assert_has_event(Event::LegacyAcceptedUntilSet { until }.into());
        // the migration runs once: a second upgrade (version already 1) changes nothing, even much later
        Now::set(START + 10 * DAY);
        <Names as frame_support::traits::OnRuntimeUpgrade>::on_runtime_upgrade();
        assert_eq!(madar_names::LegacyAcceptedUntil::<Test>::get(), until);
        Now::set(START);
        let w = with_owner();
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        // one millisecond before the end: still accepted
        Now::set(until - 1);
        let (cp, _) = evm_proof(3, &cancel_message(b"ahmad", n));
        assert_ok!(Names::cancel_offer(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            cp
        ));
        // at the end: every v1 call is refused, nobody had to do anything
        Now::set(until);
        let (p, _) = evm_proof(3, &register_message(b"ahmad"));
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                p,
                START + 400 * DAY
            ),
            Error::<Test>::LegacyMessagesOff
        );
        let (cp, _) = evm_proof(3, &cancel_message(b"ahmad", n + 1));
        assert_noop!(
            Names::cancel_offer(RuntimeOrigin::signed(REG), nm("ahmad"), cp),
            Error::<Test>::LegacyMessagesOff
        );
        let (sp, bp, _) = v2_proofs(1_000, PAY);
        assert_noop!(
            lock_v2(sp, bp, 1_000, PAY, 10_000_100, 2),
            Error::<Test>::LegacyMessagesOff
        );
        // calls without a signed message keep working, and so do the v2 ones
        assert_ok!(Names::renew(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            START + 400 * DAY
        ));
        let (cp2, _) = evm_proof(3, &cancel_message_v2(b"ahmad", n + 1, &net(), until + DAY));
        assert_ok!(Names::cancel_offer_v2(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            cp2,
            until + DAY
        ));
        assert_eq!(
            madar_names::Names::<Test>::get(nm("ahmad")).unwrap().owner,
            w
        );
    });
    // a chain started from genesis with this code never accepts v1
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    sp_io::TestExternalities::new(t).execute_with(|| {
        Now::set(START);
        System::set_block_number(1);
        assert_ok!(Names::add_registrar(RuntimeOrigin::root(), REG));
        let (p, _) = evm_proof(3, &register_message(b"ahmad"));
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                p,
                START + 400 * DAY
            ),
            Error::<Test>::LegacyMessagesOff
        );
    });
}

/// Independent review #2 (attack): a committee decision may shorten the v1 window at will but extend it by at most 7 days
/// past the current end per call — one decision cannot reopen v1 for good.
#[test]
fn the_committee_can_shorten_the_legacy_window_or_extend_it_by_at_most_7_days() {
    ext().execute_with(|| {
        let until = START + madar_stamp::LEGACY_SUNSET_MS;
        assert_noop!(
            Names::set_legacy_accepted_until(RuntimeOrigin::signed(REG), until + DAY),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_noop!(
            Names::set_legacy_accepted_until(RuntimeOrigin::root(), u64::MAX),
            Error::<Test>::LegacyExtensionTooLong
        );
        assert_noop!(
            Names::set_legacy_accepted_until(
                RuntimeOrigin::root(),
                until + madar_stamp::MAX_LEGACY_EXTENSION_MS + 1
            ),
            Error::<Test>::LegacyExtensionTooLong
        );
        assert_ok!(Names::set_legacy_accepted_until(
            RuntimeOrigin::root(),
            until + madar_stamp::MAX_LEGACY_EXTENSION_MS
        ));
        System::assert_has_event(
            Event::LegacyAcceptedUntilSet {
                until: until + madar_stamp::MAX_LEGACY_EXTENSION_MS,
            }
            .into(),
        );
        // shorten to "now": v1 refused at once
        assert_ok!(Names::set_legacy_accepted_until(
            RuntimeOrigin::root(),
            START
        ));
        let (p, _) = evm_proof(3, &register_message(b"ahmad"));
        assert_noop!(
            Names::register(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                p,
                START + 400 * DAY
            ),
            Error::<Test>::LegacyMessagesOff
        );
        // once ended, an extension is still measured from the old end (no jump to an open-ended window)
        assert_noop!(
            Names::set_legacy_accepted_until(
                RuntimeOrigin::root(),
                START + madar_stamp::MAX_LEGACY_EXTENSION_MS + 1
            ),
            Error::<Test>::LegacyExtensionTooLong
        );
    });
}

/// Independent review #2 (attack): the legacy `lock_sale_v2` takes only the 5 original rails, and only a fully valid
/// `pay_to` (before, any of the 13 rails and any text starting with `0x`).
#[test]
fn the_legacy_lock_takes_only_the_original_rails_and_a_valid_pay_to() {
    ext().execute_with(|| {
        with_owner();
        for rail in [5u8, 8, 11, 12] {
            let (sp, bp, _) = v2_proofs(1_000, PAY);
            assert_noop!(
                lock_v2(sp, bp, 1_000, PAY, 10_000_100, rail),
                Error::<Test>::BadRail
            );
        }
        let junk = "0xNOT-AN-ADDRESS-but-signed-text";
        let (sp, bp, _) = v2_proofs(1_000, junk);
        assert_noop!(
            lock_v2(sp, bp, 1_000, junk, 10_000_100, 2),
            Error::<Test>::BadPayTo
        );
        let (sp, bp, _) = v2_proofs(1_000, PAY);
        assert_ok!(lock_v2(sp, bp, 1_000, PAY, 10_000_100, 4));
    });
}

/// Seller (EVM seed 3) offers ahmad.madar v2 for `price` paid to `to`; buyer (Solana `buyer_seed`) accepts until `accept`.
fn v3_proofs(
    price: u64,
    to: &str,
    buyer_seed: u8,
    accept: u64,
) -> (WalletProof, WalletProof, Wallet) {
    let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
    let (sp, _) = evm_proof(
        3,
        &sale_message_v2(b"ahmad", n, price, to.as_bytes(), START + 30 * DAY, &net()),
    );
    let (bp, buyer) = sol_proof(
        buyer_seed,
        &buy_message_v2(b"ahmad", n, price, to.as_bytes(), accept, &net()),
    );
    (sp, bp, buyer)
}

fn lock_v3(
    sp: WalletProof,
    bp: WalletProof,
    price: u64,
    to: &str,
    accept: u64,
    lock_until: u64,
    rail: u8,
) -> sp_runtime::DispatchResult {
    Names::lock_sale_v3(
        RuntimeOrigin::signed(REG),
        nm("ahmad"),
        sp,
        price,
        pay_to(to),
        START + 30 * DAY,
        bp,
        accept,
        lock_until,
        price * MICRO_PER_CENT + 300,
        rail,
    )
}

#[test]
fn v3_sale_locks_and_completes_with_v2_messages() {
    ext().execute_with(|| {
        let seller = with_owner();
        let (sp, bp, buyer) = v3_proofs(50_000, PAY, 8, START + 10 * MIN);
        assert_ok!(lock_v3(
            sp,
            bp,
            50_000,
            PAY,
            START + 10 * MIN,
            START + 59 * MIN,
            2
        ));
        System::assert_has_event(
            Event::SaleLockedV2 {
                name: nm("ahmad"),
                buyer: buyer.clone(),
                price_cents: 50_000,
                until: START + 59 * MIN,
                pay_to: pay_to(PAY),
                rail: 2,
                amount: 500_000_300,
            }
            .into(),
        );
        Now::set(START + 30 * MIN);
        assert_ok!(Names::complete_sale_v2(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            pref(BASE_TX)
        ));
        let r = madar_names::Names::<Test>::get(nm("ahmad")).unwrap();
        assert_eq!((r.owner, r.expires), (buyer.clone(), START + 365 * DAY));
        System::assert_has_event(
            Event::SaleCompletedV2 {
                name: nm("ahmad"),
                from: seller,
                to: buyer,
                price_cents: 50_000,
                pay_to: pay_to(PAY),
                rail: 2,
                amount: 500_000_300,
                payment_ref: pref(BASE_TX),
            }
            .into(),
        );
    });
}

#[test]
fn v3_refuses_wrong_network_bad_windows_and_bad_payees() {
    ext().execute_with(|| {
        with_owner();
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        let acc = START + 10 * MIN;
        let (sp, bp, _) = v3_proofs(1_000, PAY, 8, acc);
        // another network's offer or acceptance
        let (sp_other, _) = evm_proof(
            3,
            &sale_message_v2(
                b"ahmad",
                n,
                1_000,
                PAY.as_bytes(),
                START + 30 * DAY,
                &OTHER_NET,
            ),
        );
        assert_noop!(
            lock_v3(sp_other, bp.clone(), 1_000, PAY, acc, START + 50 * MIN, 2),
            Error::<Test>::InvalidProof
        );
        let (bp_other, _) = sol_proof(
            8,
            &buy_message_v2(b"ahmad", n, 1_000, PAY.as_bytes(), acc, &OTHER_NET),
        );
        assert_noop!(
            lock_v3(sp.clone(), bp_other, 1_000, PAY, acc, START + 50 * MIN, 2),
            Error::<Test>::InvalidProof
        );
        // v2 (spec 8) signatures are not v3 signatures
        let (sp1, bp1, _) = v2_proofs(1_000, PAY);
        assert_noop!(
            lock_v3(sp1, bp1, 1_000, PAY, acc, START + 50 * MIN, 2),
            Error::<Test>::InvalidProof
        );
        // the buyer accepted another payee
        let (bp_pay, _) = sol_proof(
            8,
            &buy_message_v2(
                b"ahmad",
                n,
                1_000,
                b"0x00000000000000000000000000000000000000bb",
                acc,
                &net(),
            ),
        );
        assert_noop!(
            lock_v3(sp.clone(), bp_pay, 1_000, PAY, acc, START + 50 * MIN, 2),
            Error::<Test>::InvalidProof
        );
        // the acceptance must end no later than the lock, and within the hour
        assert_noop!(
            lock_v3(sp.clone(), bp.clone(), 1_000, PAY, acc, START + 9 * MIN, 2),
            Error::<Test>::BadLock
        );
        let late = START + 61 * MIN;
        let (bp_late, _) = sol_proof(
            8,
            &buy_message_v2(b"ahmad", n, 1_000, PAY.as_bytes(), late, &net()),
        );
        assert_noop!(
            lock_v3(sp.clone(), bp_late, 1_000, PAY, late, START + 60 * MIN, 2),
            Error::<Test>::ProofExpired
        );
        // payee must be a real address for the rail; the offer at most 92 days
        let bad = "0x00000000000000000000000000000000000000a";
        let (sp_bad, _) = evm_proof(
            3,
            &sale_message_v2(b"ahmad", n, 1_000, bad.as_bytes(), START + 30 * DAY, &net()),
        );
        assert_noop!(
            lock_v3(sp_bad, bp.clone(), 1_000, bad, acc, START + 50 * MIN, 2),
            Error::<Test>::BadPayTo
        );
        assert_noop!(
            lock_v3(sp.clone(), bp.clone(), 1_000, PAY, acc, START + 50 * MIN, 0),
            Error::<Test>::BadRail
        );
        assert_noop!(
            lock_v3(
                sp.clone(),
                bp.clone(),
                1_000,
                PAY,
                acc,
                START + 50 * MIN,
                13
            ),
            Error::<Test>::BadRail
        );
        let far = START + MAX_OFFER_MS + 1;
        let (sp_far, _) = evm_proof(
            3,
            &sale_message_v2(b"ahmad", n, 1_000, PAY.as_bytes(), far, &net()),
        );
        assert_noop!(
            Names::lock_sale_v3(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                sp_far,
                1_000,
                pay_to(PAY),
                far,
                bp.clone(),
                acc,
                START + 50 * MIN,
                10_000_000,
                2
            ),
            Error::<Test>::BadOffer
        );
        assert_noop!(
            Names::lock_sale_v3(
                RuntimeOrigin::signed(99),
                nm("ahmad"),
                sp.clone(),
                1_000,
                pay_to(PAY),
                START + 30 * DAY,
                bp.clone(),
                acc,
                START + 50 * MIN,
                10_000_000,
                2
            ),
            Error::<Test>::NotRegistrar
        );
        // the acceptance window passed before the registrar sent it
        Now::set(acc + 1);
        assert_noop!(
            lock_v3(sp, bp, 1_000, PAY, acc, acc + 30 * MIN, 2),
            Error::<Test>::ProofExpired
        );
    });
}

/// The 2026-10-12 finding: after an unpaid lock lapses, a registrar re-locked with the same two proofs again and again,
/// keeping the seller stuck. With v3 the acceptance ends no later than the lock, so the same proofs never lock again.
#[test]
fn the_same_buy_proof_never_locks_twice() {
    ext().execute_with(|| {
        with_owner();
        let acc = START + 60 * MIN;
        let (sp, bp, _) = v3_proofs(1_000, PAY, 8, acc);
        assert_ok!(lock_v3(
            sp.clone(),
            bp.clone(),
            1_000,
            PAY,
            acc,
            START + 60 * MIN,
            2
        ));
        // while the lock runs: refused because locked
        Now::set(START + 30 * MIN);
        assert_noop!(
            lock_v3(sp.clone(), bp.clone(), 1_000, PAY, acc, START + 60 * MIN, 2),
            Error::<Test>::SaleLocked
        );
        // right after it lapses the acceptance is over too
        Now::set(START + 60 * MIN + 1);
        assert_noop!(
            lock_v3(sp.clone(), bp, 1_000, PAY, acc, START + 100 * MIN, 2),
            Error::<Test>::ProofExpired
        );
        // a new acceptance (a buyer who really wants it) is needed; the offer itself still stands
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        let acc2 = START + 70 * MIN;
        let (bp2, _) = sol_proof(
            9,
            &buy_message_v2(b"ahmad", n, 1_000, PAY.as_bytes(), acc2, &net()),
        );
        assert_ok!(lock_v3(sp, bp2, 1_000, PAY, acc2, START + 100 * MIN, 2));
    });
}

#[test]
fn new_rails_lock_and_complete_with_their_own_chain_refs() {
    let tx = "0x3333333333333333333333333333333333333333333333333333333333333333";
    for (rail, chain) in [
        (5u8, "ethereum"),
        (6, "ethereum"),
        (7, "optimism"),
        (8, "optimism"),
        (9, "polygon"),
        (10, "polygon"),
        (11, "bsc"),
        (12, "bsc"),
    ] {
        ext().execute_with(|| {
            with_owner();
            assert_eq!(rail_chain(rail), Some(chain.as_bytes()));
            let (sp, bp, buyer) = v3_proofs(2_000, PAY, 8, START + 10 * MIN);
            assert_noop!(
                lock_v3(
                    sp.clone(),
                    bp.clone(),
                    2_000,
                    SOL_PAY,
                    START + 10 * MIN,
                    START + 50 * MIN,
                    rail
                ),
                Error::<Test>::BadRail
            );
            assert_ok!(lock_v3(
                sp,
                bp,
                2_000,
                PAY,
                START + 10 * MIN,
                START + 50 * MIN,
                rail
            ));
            // a reference from another chain (even another EVM chain) is refused
            assert_noop!(
                Names::complete_sale_v2(
                    RuntimeOrigin::signed(REG),
                    nm("ahmad"),
                    pref(&format!("base:{tx}"))
                ),
                Error::<Test>::BadPaymentRef
            );
            assert_ok!(Names::complete_sale_v2(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                pref(&format!("{chain}:{tx}"))
            ));
            assert_eq!(
                madar_names::Names::<Test>::get(nm("ahmad")).unwrap().owner,
                buyer
            );
        });
    }
}

#[test]
fn cancel_offer_v2_is_bound_to_network_and_expiry() {
    ext().execute_with(|| {
        with_owner();
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        let until = START + DAY;
        let (other, _) = evm_proof(3, &cancel_message_v2(b"ahmad", n, &OTHER_NET, until));
        assert_noop!(
            Names::cancel_offer_v2(RuntimeOrigin::signed(REG), nm("ahmad"), other, until),
            Error::<Test>::InvalidProof
        );
        let (stranger, _) = evm_proof(5, &cancel_message_v2(b"ahmad", n, &net(), until));
        assert_noop!(
            Names::cancel_offer_v2(RuntimeOrigin::signed(REG), nm("ahmad"), stranger, until),
            Error::<Test>::BadOffer
        );
        let (cp, _) = evm_proof(3, &cancel_message_v2(b"ahmad", n, &net(), until));
        assert_noop!(
            Names::cancel_offer_v2(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                cp.clone(),
                START + DAY + 1
            ),
            Error::<Test>::ProofExpired
        );
        assert_ok!(Names::cancel_offer_v2(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            cp.clone(),
            until
        ));
        assert_eq!(madar_names::SaleNonce::<Test>::get(nm("ahmad")), n + 1);
        // the same proof is dead now (the number moved on)
        assert_noop!(
            Names::cancel_offer_v2(RuntimeOrigin::signed(REG), nm("ahmad"), cp, until),
            Error::<Test>::InvalidProof
        );
        // and refused during a live lock
        let (sp, bp, _) = v3_proofs(1_000, PAY, 8, START + 10 * MIN);
        assert_ok!(lock_v3(
            sp,
            bp,
            1_000,
            PAY,
            START + 10 * MIN,
            START + 50 * MIN,
            2
        ));
        let (cp2, _) = evm_proof(3, &cancel_message_v2(b"ahmad", n + 1, &net(), until));
        assert_noop!(
            Names::cancel_offer_v2(RuntimeOrigin::signed(REG), nm("ahmad"), cp2, until),
            Error::<Test>::SaleLocked
        );
    });
}

/// Owner (EVM `owner_seed`) transfers ahmad.madar to the Solana wallet `to_sol_seed` that signs the acceptance.
fn transfer_proofs(
    owner_seed: u8,
    to_sol_seed: u8,
    until: u64,
) -> (WalletProof, WalletProof, Wallet) {
    let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
    let (ap, to) = sol_proof(to_sol_seed, &accept_message(b"ahmad", n, &net(), until));
    let (op, _) = evm_proof(
        owner_seed,
        &transfer_message(b"ahmad", n, &to, &net(), until),
    );
    (op, ap, to)
}

#[test]
fn transfer_moves_the_name_with_both_signatures_keeping_the_term() {
    ext().execute_with(|| {
        let from = with_owner();
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        // an open offer of the old owner
        let (sp, _) = evm_proof(
            3,
            &sale_message_v2(b"ahmad", n, 1_000, PAY.as_bytes(), START + 30 * DAY, &net()),
        );
        Now::set(START + DAY);
        let until = START + DAY + 3_600_000;
        let (op, ap, to) = transfer_proofs(3, 8, until);
        assert_noop!(
            Names::transfer(
                RuntimeOrigin::signed(99),
                nm("ahmad"),
                op.clone(),
                ap.clone(),
                until
            ),
            Error::<Test>::NotRegistrar
        );
        assert_ok!(Names::transfer(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            op.clone(),
            ap.clone(),
            until
        ));
        let r = madar_names::Names::<Test>::get(nm("ahmad")).unwrap();
        assert_eq!(
            (r.owner, r.registered, r.expires),
            (to.clone(), START, START + 365 * DAY),
            "term and first date kept"
        );
        System::assert_has_event(
            Event::Transferred {
                name: nm("ahmad"),
                from: from.clone(),
                to: to.clone(),
            }
            .into(),
        );
        assert_eq!(madar_names::SaleNonce::<Test>::get(nm("ahmad")), n + 1);
        // replay of the same two signatures: dead (the number moved on)
        assert_noop!(
            Names::transfer(RuntimeOrigin::signed(REG), nm("ahmad"), op, ap, until),
            Error::<Test>::InvalidProof
        );
        // the old owner's offer is dead too
        let (bp, _) = sol_proof(
            9,
            &buy_message_v2(
                b"ahmad",
                n,
                1_000,
                PAY.as_bytes(),
                START + DAY + 10 * MIN,
                &net(),
            ),
        );
        assert_noop!(
            Names::lock_sale_v3(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                sp,
                1_000,
                pay_to(PAY),
                START + 30 * DAY,
                bp,
                START + DAY + 10 * MIN,
                START + DAY + 50 * MIN,
                10_000_000,
                2
            ),
            Error::<Test>::InvalidProof
        );
        // the new owner (Solana) can transfer it back to an EVM wallet with fresh signatures
        let n2 = n + 1;
        let (ap2, back) = evm_proof(3, &accept_message(b"ahmad", n2, &net(), until));
        let (op2, _) = sol_proof(8, &transfer_message(b"ahmad", n2, &back, &net(), until));
        assert_ok!(Names::transfer(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            op2,
            ap2,
            until
        ));
        assert_eq!(
            madar_names::Names::<Test>::get(nm("ahmad")).unwrap().owner,
            from
        );
    });
}

#[test]
fn transfer_refuses_wrong_signers_locks_expiry_and_lapsed_names() {
    ext().execute_with(|| {
        with_owner();
        let until = START + DAY;
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        // the owner named another wallet than the one that accepted
        let (ap, _) = sol_proof(8, &accept_message(b"ahmad", n, &net(), until));
        let other = Wallet::Solana([1; 32]);
        let (op_other, _) = evm_proof(3, &transfer_message(b"ahmad", n, &other, &net(), until));
        assert_noop!(
            Names::transfer(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                op_other,
                ap.clone(),
                until
            ),
            Error::<Test>::InvalidProof
        );
        // a stranger "owner"
        let (op_s, ap_s, _) = transfer_proofs(5, 8, until);
        assert_noop!(
            Names::transfer(RuntimeOrigin::signed(REG), nm("ahmad"), op_s, ap_s, until),
            Error::<Test>::BadOffer
        );
        // to itself
        let (ap_self, me) = evm_proof(3, &accept_message(b"ahmad", n, &net(), until));
        let (op_self, _) = evm_proof(3, &transfer_message(b"ahmad", n, &me, &net(), until));
        assert_noop!(
            Names::transfer(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                op_self,
                ap_self,
                until
            ),
            Error::<Test>::SameOwner
        );
        // other network, too long a window, an expired window
        let (ap_o, to_o) = sol_proof(8, &accept_message(b"ahmad", n, &OTHER_NET, until));
        let (op_o, _) = evm_proof(3, &transfer_message(b"ahmad", n, &to_o, &OTHER_NET, until));
        assert_noop!(
            Names::transfer(RuntimeOrigin::signed(REG), nm("ahmad"), op_o, ap_o, until),
            Error::<Test>::InvalidProof
        );
        let far = START + MAX_PROOF_MS + 1;
        let (op_f, ap_f, _) = transfer_proofs(3, 8, far);
        assert_noop!(
            Names::transfer(RuntimeOrigin::signed(REG), nm("ahmad"), op_f, ap_f, far),
            Error::<Test>::ProofExpired
        );
        // during a live sale lock
        let (sp, bp, _) = v3_proofs(1_000, PAY, 9, START + 10 * MIN);
        assert_ok!(lock_v3(
            sp,
            bp,
            1_000,
            PAY,
            START + 10 * MIN,
            START + 50 * MIN,
            2
        ));
        let (op, ap, _) = transfer_proofs(3, 8, until);
        assert_noop!(
            Names::transfer(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                op.clone(),
                ap.clone(),
                until
            ),
            Error::<Test>::SaleLocked
        );
        Now::set(until + 1);
        assert_noop!(
            Names::transfer(RuntimeOrigin::signed(REG), nm("ahmad"), op, ap, until),
            Error::<Test>::ProofExpired
        );
        // after the paid term a name cannot be transferred (only renewed or registered again)
        Now::set(START + 366 * DAY);
        let u2 = START + 366 * DAY + 1000;
        let (op2, ap2, _) = transfer_proofs(3, 8, u2);
        assert_noop!(
            Names::transfer(RuntimeOrigin::signed(REG), nm("ahmad"), op2, ap2, u2),
            Error::<Test>::NotRegistered
        );
    });
}

/// EVM vs Solana confusion: the owner names the receiving wallet in its own form (0x + 40 hex, or base58), so a
/// registrar cannot deliver the name to a wallet of the other kind.
#[test]
fn transfer_target_kind_cannot_be_swapped() {
    ext().execute_with(|| {
        with_owner();
        let until = START + DAY;
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        let (ap_sol, sol) = sol_proof(8, &accept_message(b"ahmad", n, &net(), until));
        let (op, _) = evm_proof(3, &transfer_message(b"ahmad", n, &sol, &net(), until));
        // an EVM wallet accepting with the owner's Solana-target signature
        let (ap_evm, _) = evm_proof(6, &accept_message(b"ahmad", n, &net(), until));
        assert_noop!(
            Names::transfer(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                op.clone(),
                ap_evm,
                until
            ),
            Error::<Test>::InvalidProof
        );
        let Wallet::Solana(k) = sol.clone() else {
            unreachable!()
        };
        let mut evm20 = [0u8; 20];
        evm20.copy_from_slice(&k[..20]);
        assert_ne!(
            transfer_message(b"ahmad", n, &sol, &net(), until),
            transfer_message(b"ahmad", n, &Wallet::Evm(evm20), &net(), until)
        );
        assert_ok!(Names::transfer(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            op,
            ap_sol,
            until
        ));
    });
}

/// No message of one kind verifies as another: every v2 kind has its own first words and the same tail.
#[test]
fn a_signature_for_one_kind_of_message_is_useless_for_another() {
    ext().execute_with(|| {
        with_owner();
        let until = START + DAY;
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        // the owner's own register-v2 or accept signature cannot cancel or transfer
        let (reg_sig, _) = evm_proof(3, &register_message_v2(b"ahmad", &net(), until));
        let (acc_sig, _) = evm_proof(3, &accept_message(b"ahmad", n, &net(), until));
        for p in [reg_sig, acc_sig] {
            assert_noop!(Names::cancel_offer_v2(RuntimeOrigin::signed(REG), nm("ahmad"), p.clone(), until), Error::<Test>::InvalidProof);
            let (ap, _) = sol_proof(8, &accept_message(b"ahmad", n, &net(), until));
            assert_noop!(Names::transfer(RuntimeOrigin::signed(REG), nm("ahmad"), p.clone(), ap, until), Error::<Test>::InvalidProof);
        }
        let all = [
            register_message_v2(b"ahmad", &net(), until),
            sale_message_v2(b"ahmad", n, 1_000, PAY.as_bytes(), until, &net()),
            buy_message_v2(b"ahmad", n, 1_000, PAY.as_bytes(), until, &net()),
            cancel_message_v2(b"ahmad", n, &net(), until),
            transfer_message(b"ahmad", n, &Wallet::Evm([1; 20]), &net(), until),
            accept_message(b"ahmad", n, &net(), until),
            madar_stamp::signed_message_v2(&[1; 32], &None, &net(), until),
        ];
        // the first four words name the kind
        let head = |m: &Vec<u8>| -> Vec<u8> { m.split(|c| *c == b' ').take(4).collect::<Vec<_>>().join(&b' ') };
        for i in 0..all.len() {
            for j in 0..all.len() {
                assert!(i == j || head(&all[i]) != head(&all[j]), "kind {i} and {j} share a beginning");
            }
        }
        // the off-chain texts of the service (profile, link, engagement) never carry the v2 tail
        for off in ["MADAR Names: pin the message about base:0xab on sami.madar (moderation 3). No funds move.", "MADAR Names: message for sami.madar about base:0x1 - 00"] {
            assert!(!off.contains("\nnetwork: 0x"));
        }
    });
}

/// Signature malleability: a high-s twin of a used EVM signature recovers the same wallet at most, so it is exactly as
/// dead as the original (nothing on chain is keyed by signature bytes).
#[test]
fn a_malleated_signature_gains_nothing() {
    // secp256k1 group order n
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    fn twin(p: &WalletProof) -> WalletProof {
        let WalletProof::Evm { address, signature } = p else {
            unreachable!()
        };
        let mut sig = *signature;
        let mut borrow = 0i32;
        for i in (0..32).rev() {
            let d = N[i] as i32 - sig[32 + i] as i32 - borrow;
            sig[32 + i] = d.rem_euclid(256) as u8;
            borrow = (d < 0) as i32;
        }
        sig[64] = if sig[64] == 27 { 28 } else { 27 };
        WalletProof::Evm {
            address: *address,
            signature: sig,
        }
    }
    ext().execute_with(|| {
        with_owner();
        let until = START + DAY;
        let (op, ap, to) = transfer_proofs(3, 8, until);
        let m = transfer_message(
            b"ahmad",
            madar_names::SaleNonce::<Test>::get(nm("ahmad")),
            &to,
            &net(),
            until,
        );
        if let Some(w) = verify_proof(&twin(&op), &m) {
            assert_eq!(
                Some(w),
                verify_proof(&op, &m),
                "a twin never names another wallet"
            );
        }
        assert_ok!(Names::transfer(
            RuntimeOrigin::signed(REG),
            nm("ahmad"),
            op.clone(),
            ap.clone(),
            until
        ));
        assert_noop!(
            Names::transfer(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                twin(&op),
                ap,
                until
            ),
            Error::<Test>::InvalidProof
        );
    });
}

#[test]
fn the_committee_reassigns_a_disputed_name_keeping_its_term() {
    ext().execute_with(|| {
        let from = with_owner();
        let rightful = Wallet::Solana([9; 32]);
        // an open lock is dropped with the old owner
        let (sp, bp, _) = v3_proofs(1_000, PAY, 8, START + 10 * MIN);
        assert_ok!(lock_v3(
            sp,
            bp,
            1_000,
            PAY,
            START + 10 * MIN,
            START + 50 * MIN,
            2
        ));
        let n = madar_names::SaleNonce::<Test>::get(nm("ahmad"));
        assert_noop!(
            Names::reassign(
                RuntimeOrigin::signed(REG),
                nm("ahmad"),
                rightful.clone(),
                reason("x")
            ),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_noop!(
            Names::reassign(
                RuntimeOrigin::root(),
                nm("ahmad"),
                rightful.clone(),
                BoundedVec::default()
            ),
            Error::<Test>::ReasonRequired
        );
        assert_noop!(
            Names::reassign(
                RuntimeOrigin::root(),
                nm("ahmad"),
                from.clone(),
                reason("x")
            ),
            Error::<Test>::SameOwner
        );
        assert_noop!(
            Names::reassign(
                RuntimeOrigin::root(),
                nm("nobody"),
                rightful.clone(),
                reason("x")
            ),
            Error::<Test>::NotRegistered
        );
        assert_ok!(Names::reassign(
            RuntimeOrigin::root(),
            nm("ahmad"),
            rightful.clone(),
            reason("dispute #4: stolen wallet, proof on file")
        ));
        let r = madar_names::Names::<Test>::get(nm("ahmad")).unwrap();
        assert_eq!(
            (r.owner, r.registered, r.expires, r.registrar),
            (rightful.clone(), START, START + 365 * DAY, REG)
        );
        System::assert_has_event(
            Event::Reassigned {
                name: nm("ahmad"),
                from,
                to: rightful.clone(),
                reason: reason("dispute #4: stolen wallet, proof on file"),
            }
            .into(),
        );
        assert_eq!(madar_names::SaleNonce::<Test>::get(nm("ahmad")), n + 1);
        assert!(
            madar_names::Locks::<Test>::get(nm("ahmad")).is_none()
                && madar_names::LockTerms::<Test>::get(nm("ahmad")).is_none()
        );
        // a name that already lapsed past its grace is free: not the committee's to hand out this way
        Now::set(START + 396 * DAY);
        assert_noop!(
            Names::reassign(
                RuntimeOrigin::root(),
                nm("ahmad"),
                Wallet::Evm([2; 20]),
                reason("x")
            ),
            Error::<Test>::NotRegistered
        );
    });
}

fn put_lock(name: &str, until: u64, v2: bool) {
    madar_names::Locks::<Test>::insert(
        nm(name),
        SaleLock {
            buyer: Wallet::Evm([1; 20]),
            until,
            price_cents: 1,
            pay_to: pay_to(PAY),
        },
    );
    if v2 {
        madar_names::LockTerms::<Test>::insert(
            nm(name),
            SaleTerms {
                rail: 2,
                pay_amount: 10_000,
            },
        );
    }
}

#[test]
fn on_idle_cleans_expired_and_v1_locks_in_bounded_steps() {
    use frame_support::traits::Hooks;
    use frame_support::weights::Weight;
    ext().execute_with(|| {
        // 20 lapsed v2 locks, 3 v1 locks (one still "live"), 2 live v2 locks
        for i in 0..20 {
            put_lock(&format!("old{i:02}"), START - 1, true);
        }
        put_lock("vone-a", START - 1, false);
        put_lock("vone-b", START + 30 * MIN, false);
        put_lock("vone-c", START - 1, false);
        put_lock("live-a", START + 30 * MIN, true);
        put_lock("live-b", START, true);
        // not enough weight left: nothing is done
        assert_eq!(
            <Names as Hooks<u64>>::on_idle(1, Weight::zero()),
            Weight::zero()
        );
        assert_eq!(madar_names::Locks::<Test>::iter().count(), 25);
        let mut rounds = 0;
        let mut total = 0;
        while madar_names::Locks::<Test>::iter().count() > 2 {
            let removed = Names::cleanup(MAX_CLEANUP);
            assert!(removed <= MAX_CLEANUP);
            total += removed;
            rounds += 1;
            assert!(rounds < 10, "cleanup must make progress");
        }
        assert_eq!(total, 23);
        assert!(
            madar_names::Locks::<Test>::get(nm("live-a")).is_some()
                && madar_names::LockTerms::<Test>::get(nm("live-a")).is_some()
        );
        assert!(
            madar_names::Locks::<Test>::get(nm("live-b")).is_some(),
            "a lock ending exactly now is still live"
        );
        assert_eq!(madar_names::LockTerms::<Test>::iter().count(), 2);
        // through the hook with a full block budget it reports the declared weight
        put_lock("old-x", START - 1, true);
        let w = <Names as Hooks<u64>>::on_idle(1, Weight::MAX);
        assert_eq!(w, <() as crate::weights::WeightInfo>::cleanup());
        for _ in 0..3 {
            <Names as Hooks<u64>>::on_idle(1, Weight::MAX);
        }
        assert!(madar_names::Locks::<Test>::get(nm("old-x")).is_none());
    });
}

#[test]
fn storage_version_is_one_after_the_upgrade() {
    use frame_support::traits::{GetStorageVersion, Hooks, StorageVersion};
    ext().execute_with(|| {
        StorageVersion::new(0).put::<Names>();
        assert_eq!(Names::on_chain_storage_version(), 0);
        <Names as Hooks<u64>>::on_runtime_upgrade();
        assert_eq!(Names::on_chain_storage_version(), 1);
        assert_eq!(Names::in_code_storage_version(), 1);
        <Names as Hooks<u64>>::on_runtime_upgrade();
        assert_eq!(Names::on_chain_storage_version(), 1);
    });
}
