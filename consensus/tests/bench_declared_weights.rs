//! B1 benchmarks helper (only with `runtime-benchmarks`): prints the weights the runtime *declares* for every benchmarked
//! call at its worst component values, so they can be compared with `madar-node benchmark pallet` results
//! (the B1 measurement report). Output lines: `declared <pallet> <call> <ref_time ps> <proof_size bytes>`.
//!
//! `cargo test --release -p madar-consensus --features runtime-benchmarks --test bench_declared_weights -- --ignored --nocapture`
#![cfg(feature = "runtime-benchmarks")]

use frame_support::{traits::Get, weights::Weight};
use madar_consensus::Runtime;

fn p(pallet: &str, call: &str, w: Weight) {
    println!(
        "declared {pallet} {call} {} {}",
        w.ref_time(),
        w.proof_size()
    );
}

#[test]
#[ignore = "prints a table; run explicitly"]
fn bench_declared_weights() {
    {
        use madar_admission::weights::WeightInfo;
        type W = <Runtime as madar_admission::Config>::WeightInfo;
        p(
            "madar_admission",
            "submit_admission_solution",
            W::submit_admission_solution(),
        );
        p(
            "madar_admission",
            "submit_admission_rejected_early",
            W::submit_admission_rejected_early(),
        );
        p("madar_admission", "voluntary_exit", W::voluntary_exit());
        p("madar_admission", "ban", W::ban());
        p("madar_admission", "new_session", W::new_session());
        p("madar_admission", "on_initialize", W::on_initialize());
        p("madar_admission", "approve_operator", W::approve_operator());
        p(
            "madar_admission",
            "revoke_operator_approval",
            W::revoke_operator_approval(),
        );
        p("madar_admission", "vouch_node", W::vouch_node());
        p("madar_admission", "revoke_vouch", W::revoke_vouch());
        p(
            "madar_admission",
            "set_admission_param",
            W::set_admission_param(),
        );
    }
    {
        use madar_names::weights::WeightInfo;
        type W = <Runtime as madar_names::Config>::WeightInfo;
        p("madar_names", "register", W::register());
        p("madar_names", "renew", W::renew());
        p("madar_names", "admin", W::admin());
        p("madar_names", "revoke", W::revoke());
        p("madar_names", "sale_v2", W::sale_v2());
        p("madar_names", "complete_v2", W::complete_v2());
        p("madar_names", "register_v2", W::register_v2());
        p("madar_names", "sale_v3", W::sale_v3());
        p("madar_names", "cancel_v2", W::cancel_v2());
        p("madar_names", "transfer", W::transfer());
        p("madar_names", "reassign", W::reassign());
        p("madar_names", "cleanup", W::cleanup());
    }
    {
        use madar_stamp::weights::WeightInfo;
        type W = <Runtime as madar_stamp::Config>::WeightInfo;
        let max_b = <<Runtime as madar_stamp::Config>::MaxBatch as Get<u32>>::get();
        p("madar_stamp", "stamp(1)", W::stamp(1));
        p("madar_stamp", "stamp(max)", W::stamp(max_b));
        p("madar_stamp", "set_stamper", W::set_stamper());
        p("madar_stamp", "stamp_v2(1)", W::stamp_v2(1));
        p("madar_stamp", "stamp_v2(max)", W::stamp_v2(max_b));
    }
    {
        use madar_upgrade_authority::weights::WeightInfo;
        type W = <Runtime as madar_upgrade_authority::Config>::WeightInfo;
        let max_p = <<Runtime as madar_upgrade_authority::Config>::MaxCommitteeProposals as Get<
            u32,
        >>::get();
        p(
            "madar_upgrade_authority",
            "dispatch_as_root",
            W::dispatch_as_root(),
        );
        p(
            "madar_upgrade_authority",
            "set_committee_members(0)",
            W::set_committee_members(0),
        );
        p(
            "madar_upgrade_authority",
            "set_committee_members(max)",
            W::set_committee_members(max_p),
        );
    }
    {
        use pallet_collective::WeightInfo;
        type W = <Runtime as pallet_collective::Config<
            madar_consensus::UpgradeCommitteeInstance,
        >>::WeightInfo;
        let (b, m, pp) = (1024u32, 3u32, 16u32);
        p("pallet_collective", "set_members", W::set_members(m, m, pp));
        p("pallet_collective", "execute", W::execute(b, m));
        p(
            "pallet_collective",
            "propose_execute",
            W::propose_execute(b, m),
        );
        p(
            "pallet_collective",
            "propose_proposed",
            W::propose_proposed(b, m, pp),
        );
        p("pallet_collective", "vote", W::vote(m));
        p(
            "pallet_collective",
            "close_early_disapproved",
            W::close_early_disapproved(m, pp),
        );
        p(
            "pallet_collective",
            "close_early_approved",
            W::close_early_approved(b, m, pp),
        );
        p(
            "pallet_collective",
            "close_disapproved",
            W::close_disapproved(m, pp),
        );
        p(
            "pallet_collective",
            "close_approved",
            W::close_approved(b, m, pp),
        );
        p(
            "pallet_collective",
            "disapprove_proposal",
            W::disapprove_proposal(pp),
        );
        p("pallet_collective", "kill", W::kill(1, pp));
        p(
            "pallet_collective",
            "release_proposal_cost",
            W::release_proposal_cost(),
        );
    }
    {
        use pallet_timestamp::WeightInfo;
        type W = <Runtime as pallet_timestamp::Config>::WeightInfo;
        p("pallet_timestamp", "set", W::set());
        p("pallet_timestamp", "on_finalize", W::on_finalize());
    }
    {
        use frame_system::WeightInfo;
        type W = <Runtime as frame_system::Config>::SystemWeightInfo;
        p("frame_system", "remark(0)", W::remark(0));
        p(
            "frame_system",
            "remark_with_event(0)",
            W::remark_with_event(0),
        );
        p("frame_system", "remark(max)", W::remark(3_932_160));
        p(
            "frame_system",
            "remark_with_event(max)",
            W::remark_with_event(3_932_160),
        );
        p("frame_system", "set_heap_pages", W::set_heap_pages());
        p("frame_system", "set_code", W::set_code());
        p("frame_system", "set_storage(1000)", W::set_storage(1000));
        p("frame_system", "kill_storage(1000)", W::kill_storage(1000));
        p("frame_system", "kill_prefix(1000)", W::kill_prefix(1000));
        p("frame_system", "authorize_upgrade", W::authorize_upgrade());
        p(
            "frame_system",
            "apply_authorized_upgrade",
            W::apply_authorized_upgrade(),
        );
    }
    {
        use pallet_balances::WeightInfo;
        type W = <Runtime as pallet_balances::Config>::WeightInfo;
        p(
            "pallet_balances",
            "transfer_allow_death",
            W::transfer_allow_death(),
        );
        p(
            "pallet_balances",
            "transfer_keep_alive",
            W::transfer_keep_alive(),
        );
        p(
            "pallet_balances",
            "force_set_balance_creating",
            W::force_set_balance_creating(),
        );
        p(
            "pallet_balances",
            "force_set_balance_killing",
            W::force_set_balance_killing(),
        );
        p("pallet_balances", "force_transfer", W::force_transfer());
        p("pallet_balances", "transfer_all", W::transfer_all());
        p("pallet_balances", "force_unreserve", W::force_unreserve());
        p(
            "pallet_balances",
            "upgrade_accounts(1000)",
            W::upgrade_accounts(1000),
        );
        p(
            "pallet_balances",
            "force_adjust_total_issuance",
            W::force_adjust_total_issuance(),
        );
        p("pallet_balances", "burn_allow_death", W::burn_allow_death());
        p("pallet_balances", "burn_keep_alive", W::burn_keep_alive());
    }
    {
        use pallet_grandpa::WeightInfo;
        type W = <Runtime as pallet_grandpa::Config>::WeightInfo;
        p("pallet_grandpa", "note_stalled", W::note_stalled());
        p(
            "pallet_grandpa",
            "report_equivocation(1000,0)",
            W::report_equivocation(1000, 0),
        );
    }
    {
        use pallet_babe::WeightInfo;
        type W = <Runtime as pallet_babe::Config>::WeightInfo;
        p(
            "pallet_babe",
            "report_equivocation(1000,0)",
            W::report_equivocation(1000, 0),
        );
    }
    {
        // spec 9: session keys and the penalty inside an equivocation report (ban + BABE disabling)
        use pallet_session::WeightInfo;
        type W = <Runtime as pallet_session::Config>::WeightInfo;
        p("pallet_session", "set_keys", W::set_keys());
        p("pallet_session", "purge_keys", W::purge_keys());
        p(
            "madar_session_transition",
            "ban_and_disable",
            madar_consensus::sdk_weights::equivocation_penalty(),
        );
    }
    {
        let bw = <Runtime as frame_system::Config>::BlockWeights::get();
        let db = <Runtime as frame_system::Config>::DbWeight::get();
        p(
            "constants",
            "base_block(BlockExecutionWeight)",
            bw.base_block,
        );
        p(
            "constants",
            "base_extrinsic(ExtrinsicBaseWeight)",
            bw.get(frame_support::dispatch::DispatchClass::Normal)
                .base_extrinsic,
        );
        p("constants", "max_block", bw.max_block);
        p("constants", "db_read", db.reads(1));
        p("constants", "db_write", db.writes(1));
    }
}
