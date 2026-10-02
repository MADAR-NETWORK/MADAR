//! Transaction envelope (`SignedExtra`) — the Transactions phase.
//!
//! Per decision sweep D17–D20 (design document):
//! - **D17:** no economic fees for now — no `pallet-transaction-payment` in
//!   `SignedExtra`. Spam protection comes from size/weight limits only
//!   (`frame_system::CheckWeight`, provided out of the box). The architecture is ready to add
//!   `ChargeTransactionPayment` later as an extra member of the tuple without breaking anything
//!   (token-readiness, D38).
//! - **D18:** transactions are mortal only — no `Era::Immortal`. `frame_system` does not
//!   enforce this by default (`CheckMortality` accepts immortal). [`CheckMortalOnly`]
//!   below is the only custom code in this phase: a thin guard that explicitly rejects
//!   `Era::Immortal`, then delegates all the actual logic (binding the birth block,
//!   computing longevity) to the standard `frame_system::CheckMortality` as it is —
//!   no reimplementation of the protection logic itself, just an extra gate on top of it.
//! - **D19:** the maximum transaction size stays a placeholder in
//!   `protocol::chain_spec::GenesisFields::max_transaction_size_bytes` —
//!   no new number here.
//! - **D20:** FIFO ordering of transactions is a policy of the mempool/node service layer
//!   (a later phase), not part of `SignedExtra` itself; there is no code
//!   for it in this phase.
//!
//! **D40/D41 update (SDK upgrade to `polkadot-stable2606-2`):** `SignedExtension`
//! was removed for good in favor of `TransactionExtension` (a standard API change in the SDK itself,
//! unrelated to our logic) — [`CheckMortalOnly`] below was rewritten on the new interface
//! with exactly the same structure: a thin guard that explicitly rejects `Era::Immortal`, then delegates
//! all the actual logic to the standard `frame_system::CheckMortality` as it is (which
//! is also exported as `CheckEra` in this release — the same type). No change in
//! behavior or security guarantees, only an adaptation to the new interface.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec;
use frame_support::{
    dispatch::DispatchInfo,
    pallet_prelude::{DecodeWithMemTracking, TransactionSource, TypeInfo, ValidateResult, Weight},
    CloneNoBound, EqNoBound, PartialEqNoBound,
};
use frame_system::Config;
use parity_scale_codec::{Decode, Encode};
use sp_runtime::{
    generic::Era,
    traits::{
        AsSystemOriginSigner, DispatchInfoOf, DispatchOriginOf, Dispatchable, Implication, One,
        PostDispatchInfoOf, Saturating, TransactionExtension, Zero,
    },
    transaction_validity::{
        InvalidTransaction, TransactionLongevity, TransactionValidityError, ValidTransaction,
    },
    DispatchResult,
};

/// A custom error code for rejecting immortal transactions (§8, D18) — returned within
/// `InvalidTransaction::Custom`.
pub const MORTAL_ONLY_ERROR: u8 = 1;

/// The "mortal only" guard (D18) — the only custom code in this phase. It explicitly rejects
/// `Era::Immortal` and delegates any other logic to the standard `frame_system::CheckMortality`
/// (no reimplementation of birth-block binding or longevity computation).
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct CheckMortalOnly<T: Config + Send + Sync>(pub Era, core::marker::PhantomData<T>);

impl<T: Config + Send + Sync> CheckMortalOnly<T> {
    pub fn from(era: Era) -> Self {
        Self(era, core::marker::PhantomData)
    }

    fn reject_if_immortal(&self) -> Result<(), TransactionValidityError> {
        if matches!(self.0, Era::Immortal) {
            Err(InvalidTransaction::Custom(MORTAL_ONLY_ERROR).into())
        } else {
            Ok(())
        }
    }

    fn inner(&self) -> frame_system::CheckMortality<T> {
        frame_system::CheckMortality::<T>::from(self.0)
    }
}

impl<T: Config + Send + Sync> core::fmt::Debug for CheckMortalOnly<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "CheckMortalOnly({:?})", self.0)
    }
}

impl<T: Config + Send + Sync> TransactionExtension<T::RuntimeCall> for CheckMortalOnly<T> {
    const IDENTIFIER: &'static str = "CheckMortalOnly";
    type Implicit = T::Hash;
    type Val = ();
    type Pre = ();

    fn implicit(&self) -> Result<Self::Implicit, TransactionValidityError> {
        // Immortal is rejected first here too — `implicit` is called while building
        // the signed payload, sometimes before `validate`/`prepare` (exactly matching
        // the position of the old `additional_signed`).
        self.reject_if_immortal()?;
        self.inner().implicit()
    }

    fn weight(&self, call: &T::RuntimeCall) -> Weight {
        self.inner().weight(call)
    }

    fn validate(
        &self,
        origin: DispatchOriginOf<T::RuntimeCall>,
        call: &T::RuntimeCall,
        info: &DispatchInfoOf<T::RuntimeCall>,
        len: usize,
        self_implicit: Self::Implicit,
        inherited_implication: &impl Implication,
        source: TransactionSource,
    ) -> ValidateResult<Self::Val, T::RuntimeCall> {
        self.reject_if_immortal()?;
        self.inner().validate(
            origin,
            call,
            info,
            len,
            self_implicit,
            inherited_implication,
            source,
        )
    }

    fn prepare(
        self,
        val: Self::Val,
        origin: &DispatchOriginOf<T::RuntimeCall>,
        call: &T::RuntimeCall,
        info: &DispatchInfoOf<T::RuntimeCall>,
        len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        self.reject_if_immortal()?;
        self.inner().prepare(val, origin, call, info, len)
    }
}

/// Account-creation policy at the first transaction (review issue #1).
///
/// `frame_system::CheckNonce` rejects any account without a reference (`providers` or
/// `sufficients`) with a `Payment` error — and MADAR has no balance and no existential deposit
/// (D17/D21), so no new account (and no upgrade-committee member) could start any transaction.
/// The root fix: the first reference is created **after the success** of the first transaction (not when it is accepted)
/// and only for explicit onboarding paths defined by this policy (wired by the runtime), not for any call.
/// The default policy `()` always rejects (the standard `CheckNonce` behavior).
pub trait AccountCreationPolicy<AccountId, Call> {
    /// May the account reference of `who` be created to execute `call` as its first transaction?
    fn may_create_account(who: &AccountId, call: &Call) -> bool;
}

impl<AccountId, Call> AccountCreationPolicy<AccountId, Call> for () {
    fn may_create_account(_who: &AccountId, _call: &Call) -> bool {
        false
    }
}

/// A replacement for `frame_system::CheckNonce` with the same binary encoding and the same `IDENTIFIER`
/// (`"CheckNonce"`) — so standard wallets/clients stay compatible — with one difference:
/// an account without a reference is accepted if [`AccountCreationPolicy`] allows its first transaction,
/// and nothing is written for it in `prepare`: only after the call **succeeds** (`post_dispatch`)
/// is a single `provider` created and the nonce committed. A failed call leaves no account, no nonce and no
/// permanent state (the cost: a failed first transaction can be re-included within its limited
/// lifetime, since it consumed no nonce — and its inclusion cost is fully accounted by its weight). Everything else is delegated
/// verbatim to `frame_system::CheckNonce`.
#[derive(
    Encode, Decode, DecodeWithMemTracking, CloneNoBound, EqNoBound, PartialEqNoBound, TypeInfo,
)]
#[scale_info(skip_type_params(T, P))]
pub struct CheckNonceOrOnboard<T: Config, P>(
    #[codec(compact)] pub T::Nonce,
    core::marker::PhantomData<P>,
);

impl<T: Config, P> CheckNonceOrOnboard<T, P> {
    pub fn from(nonce: T::Nonce) -> Self {
        Self(nonce, core::marker::PhantomData)
    }

    fn inner(&self) -> frame_system::CheckNonce<T> {
        frame_system::CheckNonce::<T>::from(self.0)
    }

    fn has_no_reference(who: &T::AccountId) -> bool {
        let account = frame_system::Account::<T>::get(who);
        account.providers.is_zero() && account.sufficients.is_zero()
    }
}

impl<T: Config, P> core::fmt::Debug for CheckNonceOrOnboard<T, P> {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "CheckNonceOrOnboard({})", self.0)
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut core::fmt::Formatter) -> core::fmt::Result {
        Ok(())
    }
}

/// What `validate` carries to `prepare` in [`CheckNonceOrOnboard`].
#[derive(Debug)]
pub enum OnboardVal<AccountId, InnerVal> {
    /// The standard `CheckNonce` path as it is.
    Standard(InnerVal),
    /// An account without a reference accepted for its first transaction (allowed by the policy).
    Onboarding(AccountId),
}

/// What `prepare` carries to `post_dispatch_details`.
#[derive(Debug)]
pub enum OnboardPre<AccountId, InnerPre> {
    Standard(InnerPre),
    /// An account without a reference: **nothing has been written yet** — the reference and the nonce are committed only in
    /// `post_dispatch_details` if the call succeeds.
    Onboarding(AccountId),
    /// The account gained a reference before `prepare` (a completed standard path).
    Applied,
}

impl<T: Config, P> TransactionExtension<T::RuntimeCall> for CheckNonceOrOnboard<T, P>
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo>,
    <T::RuntimeCall as Dispatchable>::RuntimeOrigin: AsSystemOriginSigner<T::AccountId> + Clone,
    P: AccountCreationPolicy<T::AccountId, T::RuntimeCall> + Send + Sync + 'static,
{
    const IDENTIFIER: &'static str = "CheckNonce";
    type Implicit = ();
    type Val = OnboardVal<
        T::AccountId,
        <frame_system::CheckNonce<T> as TransactionExtension<T::RuntimeCall>>::Val,
    >;
    type Pre = OnboardPre<
        T::AccountId,
        <frame_system::CheckNonce<T> as TransactionExtension<T::RuntimeCall>>::Pre,
    >;

    fn weight(&self, call: &T::RuntimeCall) -> Weight {
        self.inner().weight(call)
    }

    fn validate(
        &self,
        origin: DispatchOriginOf<T::RuntimeCall>,
        call: &T::RuntimeCall,
        info: &DispatchInfoOf<T::RuntimeCall>,
        len: usize,
        self_implicit: Self::Implicit,
        inherited_implication: &impl Implication,
        source: TransactionSource,
    ) -> ValidateResult<Self::Val, T::RuntimeCall> {
        let creating = origin
            .as_system_origin_signer()
            .filter(|who| Self::has_no_reference(who))
            .cloned();

        let Some(who) = creating else {
            let (validity, val, origin) = self.inner().validate(
                origin,
                call,
                info,
                len,
                self_implicit,
                inherited_implication,
                source,
            )?;
            return Ok((validity, OnboardVal::Standard(val), origin));
        };

        // An account without a reference: accepted only for an onboarding path allowed by the policy. Its account does not
        // exist yet, so the current nonce is zero; we build `provides/requires` in the same format as
        // the standard `CheckNonce`.
        if !P::may_create_account(&who, call) {
            return Err(InvalidTransaction::Payment.into());
        }
        let nonce = self.0;
        let provides = vec![Encode::encode(&(who.clone(), nonce))];
        let requires = if nonce > T::Nonce::zero() {
            vec![Encode::encode(&(
                who.clone(),
                nonce.saturating_sub(T::Nonce::one()),
            ))]
        } else {
            vec![]
        };
        let validity = ValidTransaction {
            priority: 0,
            requires,
            provides,
            longevity: TransactionLongevity::max_value(),
            propagate: true,
        };
        Ok((validity, OnboardVal::Onboarding(who), origin))
    }

    fn prepare(
        self,
        val: Self::Val,
        origin: &DispatchOriginOf<T::RuntimeCall>,
        call: &T::RuntimeCall,
        info: &DispatchInfoOf<T::RuntimeCall>,
        len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        match val {
            OnboardVal::Standard(inner_val) => self
                .inner()
                .prepare(inner_val, origin, call, info, len)
                .map(OnboardPre::Standard),
            OnboardVal::Onboarding(who) => {
                if !Self::has_no_reference(&who) {
                    // The account gained a reference between `validate` and `prepare`: standard nonce path.
                    frame_system::CheckNonce::<T>::prepare_nonce_for_account(&who, self.0)?;
                    return Ok(OnboardPre::Applied);
                }
                // We do not trust that `validate` ran on matching state: we re-check the policy and the nonce
                // (new account: current nonce is zero). **No state is written here at all**: if the call
                // fails there is no account, no nonce and no permanent effect; the commit happens in `post_dispatch`.
                if !P::may_create_account(&who, call) {
                    return Err(InvalidTransaction::Payment.into());
                }
                if self.0 > frame_system::Account::<T>::get(&who).nonce {
                    return Err(InvalidTransaction::Future.into());
                }
                Ok(OnboardPre::Onboarding(who))
            }
        }
    }

    fn post_dispatch_details(
        pre: Self::Pre,
        info: &DispatchInfo,
        post_info: &PostDispatchInfoOf<T::RuntimeCall>,
        len: usize,
        result: &DispatchResult,
    ) -> Result<Weight, TransactionValidityError> {
        match pre {
            OnboardPre::Standard(inner_pre) => {
                <frame_system::CheckNonce<T> as TransactionExtension<T::RuntimeCall>>::post_dispatch_details(
                    inner_pre, info, post_info, len, result,
                )
            },
            OnboardPre::Applied => Ok(Weight::zero()),
            OnboardPre::Onboarding(who) => {
                // Only the success of a path that deserves an account (an accepted admission solution, or committee work
                // that was executed) => create the first reference and commit the nonce. Failure leaves nothing.
                if result.is_ok() {
                    if Self::has_no_reference(&who) {
                        frame_system::Pallet::<T>::inc_providers(&who);
                    }
                    frame_system::Account::<T>::mutate(&who, |account| {
                        account.nonce = account.nonce.saturating_add(T::Nonce::one());
                    });
                }
                Ok(Weight::zero())
            },
        }
    }
}

/// The official `SignedExtra` bundle of the Transactions phase (D17/D18): no fees,
/// mortal only, standard nonce and weight protection.
///
/// Order: `CheckSpecVersion`, `CheckTxVersion`, `CheckGenesis` (§2.6,
/// Protocol phase), `CheckMortalOnly` (above), `CheckNonce`, `CheckWeight`.
pub type SignedExtra<T, P = ()> = (
    frame_system::CheckSpecVersion<T>,
    frame_system::CheckTxVersion<T>,
    frame_system::CheckGenesis<T>,
    CheckMortalOnly<T>,
    CheckNonceOrOnboard<T, P>,
    frame_system::CheckWeight<T>,
);
