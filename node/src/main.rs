//! The actual MADAR Network node — BABE+GRANDPA+P2P as is (§6/§11), with no fees
//! (D17), unmodified wiring of the core Substrate components.

#[cfg(test)]
mod b1_storage;
mod babe_watch;
mod chain_spec;
mod cli;
mod command;
mod committee;
mod doctor;
mod join;
mod names;
mod rpc;
mod service;
mod stamp;

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn SetConsoleCtrlHandler(handler: *const core::ffi::c_void, add: i32) -> i32;
}

fn main() -> sc_cli::Result<()> {
    // Windows: the process inherits "ignore Ctrl+C" from its launcher (Start-Process/a new process group), so graceful shutdown fails and the process is killed forcibly
    // after a timeout (2026-09-28). We re-enable the default Ctrl+C handling so the node closes its database cleanly.
    // SAFETY: a Win32 call with no pointers (NULL = the default handler).
    #[cfg(windows)]
    #[allow(unsafe_code)]
    // The only exception: a single Win32 call with no pointers (as in node-app).
    unsafe {
        SetConsoleCtrlHandler(std::ptr::null(), 0);
    }
    // B5: MADAR tools (join/committee/doctor) write addresses in the MADAR format (85) and accept both formats 85 and 42 (old addresses remain valid;
    // the key itself does not change, only how it is written). Running the node itself sets the format from the Chain Spec as usual.
    sp_core::crypto::set_default_ss58_version(sp_core::crypto::Ss58AddressFormat::custom(
        madar_protocol::SS58_PREFIX,
    ));
    command::run()
}
