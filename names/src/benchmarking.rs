//! Names benchmarks (FRAME v2) — B1 measurement only, compiled with `runtime-benchmarks`.
//!
//! Worst cases: longest name (`MAX_NAME`), registrar list full with the caller last, EVM wallet proofs (keccak +
//! secp256k1 recovery; a Solana variant of `register` is measured too), longest `pay_to`, longest valid payment reference
//! (Solana, 88 characters) and longest revoke reason. Signatures are made in setup with the benchmark keystore.
//! `cancel_offer` is declared with the `register` weight, the four admin calls with the `admin` weight.

use super::*;
use alloc::{vec, vec::Vec};
use frame_benchmarking::v2::*;
use frame_support::{
    pallet_prelude::*,
    sp_runtime::traits::Zero,
    traits::{EnsureOrigin, Hooks},
};
use frame_system::pallet_prelude::BlockNumberFor;
use frame_system::RawOrigin;
use madar_stamp::benchmarking::{evm_key, evm_proof, solana_key, solana_proof};

const SEED: u32 = 0;

/// Longest valid name (`MAX_NAME` characters).
fn long_name(tag: u8) -> NameOf {
    let mut n = vec![b'a'; MAX_NAME as usize];
    n[0] = b'a' + (tag % 26);
    NameOf::truncate_from(n)
}

/// Full registrar list with `who` last.
fn full_registrars<T: Config>(who: &T::AccountId) {
    let max = T::MaxRegistrars::get();
    let mut s: Vec<T::AccountId> = (1..max).map(|i| account("registrar", i, SEED)).collect();
    s.push(who.clone());
    Registrars::<T>::put(BoundedVec::truncate_from(s));
}

/// Registers `name` to an EVM wallet (directly in storage) and returns the wallet key.
fn registered<T: Config>(name: &NameOf, registrar: &T::AccountId) -> sp_core::ecdsa::Public {
    let key = evm_key();
    let owner = match evm_proof(&key, &register_message(name)) {
        WalletProof::Evm { address, .. } => Wallet::Evm(address),
        _ => unreachable!(),
    };
    Names::<T>::insert(
        name,
        NameRecord {
            owner,
            registered: 1,
            expires: MAX_LOCK_MS * 1000,
            registrar: registrar.clone(),
        },
    );
    key
}

/// Solana-style `pay_to` of the maximum length (base58 characters).
fn solana_pay_to() -> BoundedVec<u8, ConstU32<MAX_PAY_TO>> {
    BoundedVec::truncate_from(vec![b'A'; MAX_PAY_TO as usize])
}

#[benchmarks]
mod benchmarks {
    use super::*;

    /// New name (new-owner path clears nonce/lock/terms), EVM proof.
    #[benchmark]
    fn register() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        let proof = evm_proof(&evm_key(), &register_message(&name));
        LegacyAcceptedUntil::<T>::put(u64::MAX);

        #[extrinsic_call]
        _(RawOrigin::Signed(who), name.clone(), proof, MAX_LOCK_MS);

        assert!(Names::<T>::contains_key(&name));
        Ok(())
    }

    /// Same with a Solana (Ed25519) proof.
    #[benchmark]
    fn register_solana() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        let proof = solana_proof(&solana_key(), &register_message(&name));
        LegacyAcceptedUntil::<T>::put(u64::MAX);

        #[extrinsic_call]
        register(RawOrigin::Signed(who), name.clone(), proof, MAX_LOCK_MS);

        assert!(Names::<T>::contains_key(&name));
        Ok(())
    }

    #[benchmark]
    fn renew() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        registered::<T>(&name, &who);
        let expires = MAX_LOCK_MS * 1000 + 1;

        #[extrinsic_call]
        _(RawOrigin::Signed(who), name.clone(), expires);

        assert_eq!(Names::<T>::get(&name).map(|r| r.expires), Some(expires));
        Ok(())
    }

    #[benchmark]
    fn add_registrar() -> Result<(), BenchmarkError> {
        let max = T::MaxRegistrars::get();
        let s: Vec<T::AccountId> = (1..max).map(|i| account("registrar", i, SEED)).collect();
        Registrars::<T>::put(BoundedVec::truncate_from(s));
        let new: T::AccountId = account("new_registrar", 0, SEED);
        let origin =
            T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, new.clone());

        assert!(Pallet::<T>::is_registrar(&new));
        Ok(())
    }

    #[benchmark]
    fn remove_registrar() -> Result<(), BenchmarkError> {
        let who: T::AccountId = account("last_registrar", 0, SEED);
        full_registrars::<T>(&who);
        let origin =
            T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, who.clone());

        assert!(!Pallet::<T>::is_registrar(&who));
        Ok(())
    }

    #[benchmark]
    fn set_reserved() -> Result<(), BenchmarkError> {
        let name = long_name(0);
        let origin =
            T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, name.clone(), true);

        assert!(Reserved::<T>::contains_key(&name));
        Ok(())
    }

    /// Revoke a registered name with the longest reason.
    #[benchmark]
    fn revoke() -> Result<(), BenchmarkError> {
        let who: T::AccountId = account("registrar", 0, SEED);
        let name = long_name(0);
        registered::<T>(&name, &who);
        let reason = BoundedVec::<u8, ConstU32<256>>::truncate_from(vec![b'r'; 256]);
        let origin =
            T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, name.clone(), reason);

        assert!(!Names::<T>::contains_key(&name));
        Ok(())
    }

    /// Owner cancels offers (EVM proof).
    #[benchmark]
    fn cancel_offer() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        let key = registered::<T>(&name, &who);
        let nonce = SaleNonce::<T>::get(&name);
        let proof = evm_proof(&key, &cancel_message(&name, nonce));
        LegacyAcceptedUntil::<T>::put(u64::MAX);

        #[extrinsic_call]
        _(RawOrigin::Signed(who), name.clone(), proof);

        assert_eq!(SaleNonce::<T>::get(&name), nonce.wrapping_add(1));
        Ok(())
    }

    /// Lock for a buyer: two EVM proofs (seller offer, buyer acceptance), a 42-character EVM payee (spec 9: the legacy call
    /// takes only a full valid `pay_to` on the 5 original rails).
    #[benchmark]
    fn lock_sale_v2() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        let seller = registered::<T>(&name, &who);
        let nonce = SaleNonce::<T>::get(&name);
        let price_cents = 9_999_999u64;
        let pay_to = BoundedVec::<u8, ConstU32<MAX_PAY_TO>>::truncate_from(
            b"0xb95c91Bb8C58b929d501BD8D0aCcB420F8A7045d".to_vec(),
        );
        let offer_until = MAX_LOCK_MS;
        LegacyAcceptedUntil::<T>::put(u64::MAX);
        let seller_proof = evm_proof(
            &seller,
            &sale_message(&name, nonce, price_cents, &pay_to, offer_until),
        );
        let buyer_proof = evm_proof(&evm_key(), &buy_message(&name, nonce, price_cents));
        let pay_amount = price_cents * MICRO_PER_CENT + 99_999;

        #[extrinsic_call]
        _(
            RawOrigin::Signed(who),
            name.clone(),
            seller_proof,
            price_cents,
            pay_to,
            offer_until,
            buyer_proof,
            MAX_LOCK_MS,
            pay_amount,
            2u8,
        );

        assert!(LockTerms::<T>::contains_key(&name));
        Ok(())
    }

    /// Complete a v2 sale with the longest valid payment reference (Solana, 88 base58 characters).
    #[benchmark]
    fn complete_sale_v2() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        registered::<T>(&name, &who);
        let buyer = match evm_proof(&evm_key(), b"buyer") {
            WalletProof::Evm { address, .. } => Wallet::Evm(address),
            _ => unreachable!(),
        };
        let price_cents = 9_999_999u64;
        Locks::<T>::insert(
            &name,
            SaleLock {
                buyer,
                until: MAX_LOCK_MS,
                price_cents,
                pay_to: solana_pay_to(),
            },
        );
        LockTerms::<T>::insert(
            &name,
            SaleTerms {
                rail: 0,
                pay_amount: price_cents * MICRO_PER_CENT,
            },
        );
        let mut r = b"solana:".to_vec();
        r.extend_from_slice(&[b'5'; 88]);
        let payment_ref = PaymentRef::truncate_from(r);

        #[extrinsic_call]
        _(RawOrigin::Signed(who), name.clone(), payment_ref);

        assert!(!Locks::<T>::contains_key(&name));
        Ok(())
    }

    // ---------------------------------------------------------------- spec 9

    /// New name with a v2 register message (EVM proof).
    #[benchmark]
    fn register_v2() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        let until = now::<T>() + MAX_REGISTER_PROOF_MS;
        let proof = evm_proof(
            &evm_key(),
            &register_message_v2(&name, &Pallet::<T>::network(), until),
        );

        #[extrinsic_call]
        _(
            RawOrigin::Signed(who),
            name.clone(),
            proof,
            now::<T>() + MAX_LOCK_MS,
            until,
        );

        assert!(Names::<T>::contains_key(&name));
        Ok(())
    }

    /// Same with a Solana proof.
    #[benchmark]
    fn register_v2_solana() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        let until = now::<T>() + MAX_REGISTER_PROOF_MS;
        let proof = solana_proof(
            &solana_key(),
            &register_message_v2(&name, &Pallet::<T>::network(), until),
        );

        #[extrinsic_call]
        register_v2(
            RawOrigin::Signed(who),
            name.clone(),
            proof,
            now::<T>() + MAX_LOCK_MS,
            until,
        );

        assert!(Names::<T>::contains_key(&name));
        Ok(())
    }

    /// v3 lock: two EVM proofs on v2 messages, a 42-character EVM payee (the longest one `valid_pay_to` accepts).
    #[benchmark]
    fn lock_sale_v3() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        let seller = registered::<T>(&name, &who);
        let nonce = SaleNonce::<T>::get(&name);
        let net = Pallet::<T>::network();
        let t = now::<T>();
        let price_cents = 9_999_999u64;
        let pay_to = BoundedVec::<u8, ConstU32<MAX_PAY_TO>>::truncate_from(
            b"0xb95c91Bb8C58b929d501BD8D0aCcB420F8A7045d".to_vec(),
        );
        let offer_until = t + MAX_OFFER_MS;
        let accept_until = t + MAX_LOCK_MS;
        let seller_proof = evm_proof(
            &seller,
            &sale_message_v2(&name, nonce, price_cents, &pay_to, offer_until, &net),
        );
        let buyer_proof = evm_proof(
            &evm_key(),
            &buy_message_v2(&name, nonce, price_cents, &pay_to, accept_until, &net),
        );
        let pay_amount = price_cents * MICRO_PER_CENT + 99_999;

        #[extrinsic_call]
        _(
            RawOrigin::Signed(who),
            name.clone(),
            seller_proof,
            price_cents,
            pay_to,
            offer_until,
            buyer_proof,
            accept_until,
            t + MAX_LOCK_MS,
            pay_amount,
            11u8,
        );

        assert!(LockTerms::<T>::contains_key(&name));
        Ok(())
    }

    /// Owner cancels offers with a v2 message (EVM proof).
    #[benchmark]
    fn cancel_offer_v2() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        let key = registered::<T>(&name, &who);
        let nonce = SaleNonce::<T>::get(&name);
        let until = now::<T>() + MAX_PROOF_MS;
        let proof = evm_proof(
            &key,
            &cancel_message_v2(&name, nonce, &Pallet::<T>::network(), until),
        );

        #[extrinsic_call]
        _(RawOrigin::Signed(who), name.clone(), proof, until);

        assert_eq!(SaleNonce::<T>::get(&name), nonce.wrapping_add(1));
        Ok(())
    }

    /// Transfer: owner and new wallet both EVM (two keccak + secp256k1 recoveries).
    #[benchmark]
    fn transfer() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        let owner = registered::<T>(&name, &who);
        let nonce = SaleNonce::<T>::get(&name);
        let net = Pallet::<T>::network();
        let until = now::<T>() + MAX_PROOF_MS;
        let accept = evm_proof(&evm_key(), &accept_message(&name, nonce, &net, until));
        let to = match &accept {
            WalletProof::Evm { address, .. } => Wallet::Evm(*address),
            _ => unreachable!(),
        };
        let owner_proof = evm_proof(&owner, &transfer_message(&name, nonce, &to, &net, until));

        #[extrinsic_call]
        _(
            RawOrigin::Signed(who),
            name.clone(),
            owner_proof,
            accept,
            until,
        );

        assert_eq!(Names::<T>::get(&name).map(|r| r.owner), Some(to));
        Ok(())
    }

    /// Transfer to a Solana wallet (base58 in the owner's message, Ed25519 acceptance).
    #[benchmark]
    fn transfer_solana_target() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        let owner = registered::<T>(&name, &who);
        let nonce = SaleNonce::<T>::get(&name);
        let net = Pallet::<T>::network();
        let until = now::<T>() + MAX_PROOF_MS;
        let accept = solana_proof(&solana_key(), &accept_message(&name, nonce, &net, until));
        let to = match &accept {
            WalletProof::Solana { public, .. } => Wallet::Solana(*public),
            _ => unreachable!(),
        };
        let owner_proof = evm_proof(&owner, &transfer_message(&name, nonce, &to, &net, until));

        #[extrinsic_call]
        transfer(
            RawOrigin::Signed(who),
            name.clone(),
            owner_proof,
            accept,
            until,
        );

        assert_eq!(Names::<T>::get(&name).map(|r| r.owner), Some(to));
        Ok(())
    }

    /// Committee reassign with the longest reason.
    #[benchmark]
    fn reassign() -> Result<(), BenchmarkError> {
        let who: T::AccountId = account("registrar", 0, SEED);
        let name = long_name(0);
        registered::<T>(&name, &who);
        let reason = BoundedVec::<u8, ConstU32<256>>::truncate_from(vec![b'r'; 256]);
        let to = Wallet::Solana([7; 32]);
        let origin =
            T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, name.clone(), to.clone(), reason);

        assert_eq!(Names::<T>::get(&name).map(|r| r.owner), Some(to));
        Ok(())
    }

    #[benchmark]
    fn set_legacy_accepted_until() -> Result<(), BenchmarkError> {
        LegacyAcceptedUntil::<T>::put(1_000);
        let origin =
            T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, 0);

        assert_eq!(LegacyAcceptedUntil::<T>::get(), 0);
        Ok(())
    }

    /// `on_idle` cleanup, worst case: `MAX_CLEANUP` stale locks removed (v1 locks: no terms, so removed whatever the
    /// benchmark clock says), one more left behind so the cursor is written.
    #[benchmark]
    fn on_idle_cleanup() -> Result<(), BenchmarkError> {
        for i in 0..=MAX_CLEANUP {
            let name = long_name(i as u8);
            let buyer = Wallet::Evm([1; 20]);
            Locks::<T>::insert(
                &name,
                SaleLock {
                    buyer,
                    until: 0,
                    price_cents: 1,
                    pay_to: solana_pay_to(),
                },
            );
        }
        #[block]
        {
            <Pallet<T> as Hooks<BlockNumberFor<T>>>::on_idle(Zero::zero(), Weight::MAX);
        }
        assert_eq!(Locks::<T>::iter().count(), 1);
        Ok(())
    }
}

fn now<T: Config>() -> u64 {
    use frame_support::traits::UnixTime;
    T::Time::now().as_millis() as u64
}
