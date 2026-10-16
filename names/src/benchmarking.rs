//! Names benchmarks (FRAME v2) — B1 measurement only, compiled with `runtime-benchmarks`.
//!
//! Worst cases: longest name (`MAX_NAME`), registrar list full with the caller last, EVM wallet proofs (keccak +
//! secp256k1 recovery; a Solana variant of `register` is measured too), longest `pay_to`, longest valid payment reference
//! (Solana, 88 characters) and longest revoke reason. Signatures are made in setup with the benchmark keystore.
//! `cancel_offer` is declared with the `register` weight, the four admin calls with the `admin` weight.

use super::*;
use alloc::{vec, vec::Vec};
use frame_benchmarking::v2::*;
use frame_support::{pallet_prelude::*, traits::EnsureOrigin};
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

/// `0x` + 62 hex characters (an EVM-style `pay_to` of the maximum length).
fn evm_pay_to() -> BoundedVec<u8, ConstU32<MAX_PAY_TO>> {
    let mut p = b"0x".to_vec();
    p.resize(MAX_PAY_TO as usize, b'a');
    BoundedVec::truncate_from(p)
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

        #[extrinsic_call]
        _(RawOrigin::Signed(who), name.clone(), proof);

        assert_eq!(SaleNonce::<T>::get(&name), nonce.wrapping_add(1));
        Ok(())
    }

    /// Lock for a buyer: two EVM proofs (seller offer, buyer acceptance), longest `pay_to`.
    #[benchmark]
    fn lock_sale_v2() -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_registrars::<T>(&who);
        let name = long_name(0);
        let seller = registered::<T>(&name, &who);
        let nonce = SaleNonce::<T>::get(&name);
        let price_cents = 9_999_999u64;
        let pay_to = evm_pay_to();
        let offer_until = MAX_LOCK_MS;
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
}
