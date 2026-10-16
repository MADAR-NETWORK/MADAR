//! UpgradeAuthority benchmarks (FRAME v2) — B1 measurement only, compiled with `runtime-benchmarks`.
//!
//! `dispatch_as_root` is measured with the cheapest inner call (`System::remark` with an empty remark), so the result is
//! the wrapper cost plus a near-zero inner call; the declared weight adds the inner call's own weight on top.
//! `set_committee_members(p)` replaces all three members while `p` open motions carry a vote from every outgoing member.

use super::*;
use alloc::{boxed::Box, vec, vec::Vec};
use frame_benchmarking::v2::*;
use frame_support::{pallet_prelude::*, traits::EnsureOrigin};

const SEED: u32 = 0;

#[benchmarks(where T: crate::BenchmarkHelper, <T as Config>::RuntimeCall: From<frame_system::Call<T>>)]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn dispatch_as_root() -> Result<(), BenchmarkError> {
        let call: <T as Config>::RuntimeCall =
            frame_system::Call::<T>::remark { remark: vec![] }.into();
        let origin =
            T::ApprovedOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, Box::new(call));

        Ok(())
    }

    #[benchmark]
    fn set_committee_members(
        p: Linear<0, { T::MaxCommitteeProposals::get() }>,
    ) -> Result<(), BenchmarkError> {
        let size = T::CommitteeSize::get();
        let mut old: Vec<T::AccountId> =
            (0..size).map(|i| account("old_member", i, SEED)).collect();
        old.sort();
        T::committee_setup(&old, p);
        let new: Vec<T::AccountId> = (0..size).map(|i| account("new_member", i, SEED)).collect();
        let origin =
            T::ApprovedOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, new.clone());

        let mut sorted = new;
        sorted.sort();
        assert_eq!(T::Committee::members(), sorted);
        Ok(())
    }
}
