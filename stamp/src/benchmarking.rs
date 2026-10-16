//! Stamp benchmarks (FRAME v2) — B1 measurement only, compiled with `runtime-benchmarks`.
//!
//! Worst case per entry: new fingerprint, name hash present, wallet proof verified on chain. EVM proofs (keccak +
//! secp256k1 recovery) and Solana proofs (Ed25519) are measured separately. The stamper list is full and the caller is
//! last in it. Signatures are made in setup with the benchmark keystore (`sp_io::crypto`), never inside the measured
//! part. The helpers are public so the Names benchmarks reuse them.

use super::*;
use alloc::vec::Vec;
use frame_benchmarking::v2::*;
use frame_support::{pallet_prelude::*, traits::EnsureOrigin};
use frame_system::RawOrigin;
use sp_core::crypto::KeyTypeId;

const SEED: u32 = 0;
/// Benchmark keystore key type (keys exist only inside a benchmark run).
pub const BENCH_KEY: KeyTypeId = KeyTypeId(*b"mdbn");

/// The EIP-191 `personal_sign` digest, exactly as [`verify_proof`] computes it.
pub fn evm_digest(message: &[u8]) -> [u8; 32] {
    let mut prefixed = Vec::with_capacity(32 + message.len());
    prefixed.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    let mut len = Vec::new();
    let mut n = message.len();
    loop {
        len.push(b'0' + (n % 10) as u8);
        n /= 10;
        if n == 0 {
            break;
        }
    }
    len.reverse();
    prefixed.extend_from_slice(&len);
    prefixed.extend_from_slice(message);
    sp_io::hashing::keccak_256(&prefixed)
}

/// A new secp256k1 key in the benchmark keystore.
pub fn evm_key() -> sp_core::ecdsa::Public {
    sp_io::crypto::ecdsa_generate(BENCH_KEY, None)
}

/// `personal_sign` proof of `message` by `key` (address derived by recovery, as a wallet would show it).
pub fn evm_proof(key: &sp_core::ecdsa::Public, message: &[u8]) -> WalletProof {
    let digest = evm_digest(message);
    let sig = sp_io::crypto::ecdsa_sign_prehashed(BENCH_KEY, key, &digest)
        .expect("benchmark keystore signs");
    let mut signature = [0u8; 65];
    signature.copy_from_slice(sig.as_ref());
    let public = sp_io::crypto::secp256k1_ecdsa_recover(&signature, &digest)
        .ok()
        .expect("fresh signature recovers");
    let mut address = [0u8; 20];
    address.copy_from_slice(&sp_io::hashing::keccak_256(&public)[12..]);
    signature[64] += 27; // as MetaMask returns it
    WalletProof::Evm { address, signature }
}

/// A new Ed25519 key in the benchmark keystore.
pub fn solana_key() -> sp_core::ed25519::Public {
    sp_io::crypto::ed25519_generate(BENCH_KEY, None)
}

/// `signMessage` proof of `message` by `key`.
pub fn solana_proof(key: &sp_core::ed25519::Public, message: &[u8]) -> WalletProof {
    let sig =
        sp_io::crypto::ed25519_sign(BENCH_KEY, key, message).expect("benchmark keystore signs");
    let mut signature = [0u8; 64];
    signature.copy_from_slice(sig.as_ref());
    let mut public = [0u8; 32];
    public.copy_from_slice(key.as_ref());
    WalletProof::Solana { public, signature }
}

fn fingerprint(i: u32) -> Fingerprint {
    sp_io::hashing::blake2_256(&(b"bench-fingerprint", i).encode())
}

/// Full stamper list with `who` last.
fn full_stampers<T: Config>(who: &T::AccountId) {
    let max = T::MaxStampers::get();
    let mut s: Vec<T::AccountId> = (1..max).map(|i| account("stamper", i, SEED)).collect();
    s.push(who.clone());
    Stampers::<T>::put(BoundedVec::truncate_from(s));
}

fn entries(n: u32, evm: bool) -> Vec<Entry> {
    let ekey = evm.then(evm_key);
    let skey = (!evm).then(solana_key);
    (0..n)
        .map(|i| {
            let fp = fingerprint(i);
            let name_hash = Some(sp_io::hashing::blake2_256(&(b"bench-name", i).encode()));
            let msg = signed_message(&fp, &name_hash);
            let proof = match (&ekey, &skey) {
                (Some(k), _) => evm_proof(k, &msg),
                (_, Some(k)) => solana_proof(k, &msg),
                _ => unreachable!(),
            };
            Entry {
                fingerprint: fp,
                name_hash,
                proof: Some(proof),
            }
        })
        .collect()
}

#[benchmarks]
mod benchmarks {
    use super::*;

    /// Batch of `n` new fingerprints, each with an EVM wallet proof (keccak + secp256k1 recovery).
    #[benchmark]
    fn stamp(n: Linear<1, { T::MaxBatch::get() }>) -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_stampers::<T>(&who);
        let batch: BoundedVec<Entry, T::MaxBatch> = BoundedVec::truncate_from(entries(n, true));

        #[extrinsic_call]
        stamp(RawOrigin::Signed(who), batch);

        assert!(Stamps::<T>::contains_key(fingerprint(n - 1)));
        Ok(())
    }

    /// Same with Solana (Ed25519) proofs.
    #[benchmark]
    fn stamp_solana(n: Linear<1, { T::MaxBatch::get() }>) -> Result<(), BenchmarkError> {
        let who: T::AccountId = whitelisted_caller();
        full_stampers::<T>(&who);
        let batch: BoundedVec<Entry, T::MaxBatch> = BoundedVec::truncate_from(entries(n, false));

        #[extrinsic_call]
        stamp(RawOrigin::Signed(who), batch);

        assert!(Stamps::<T>::contains_key(fingerprint(n - 1)));
        Ok(())
    }

    /// `add_stamper` into a list one short of full.
    #[benchmark]
    fn add_stamper() -> Result<(), BenchmarkError> {
        let max = T::MaxStampers::get();
        let s: Vec<T::AccountId> = (1..max).map(|i| account("stamper", i, SEED)).collect();
        Stampers::<T>::put(BoundedVec::truncate_from(s));
        let new: T::AccountId = account("new_stamper", 0, SEED);
        let origin =
            T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, new.clone());

        assert!(Pallet::<T>::is_stamper(&new));
        Ok(())
    }

    /// `remove_stamper` of the last entry of a full list.
    #[benchmark]
    fn remove_stamper() -> Result<(), BenchmarkError> {
        let who: T::AccountId = account("last_stamper", 0, SEED);
        full_stampers::<T>(&who);
        let origin =
            T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, who.clone());

        assert!(!Pallet::<T>::is_stamper(&who));
        Ok(())
    }
}
