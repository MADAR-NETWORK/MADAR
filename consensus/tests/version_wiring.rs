//! A single version source (review issue #2): `frame_system::Config::Version` must
//! match the `VERSION` announced by `Core::version()`, and therefore what
//! `CheckSpecVersion`/`CheckTxVersion` put into the signed payload and the `set_code` check.

use frame_system::{CheckSpecVersion, CheckTxVersion};
use madar_consensus::{Block, Runtime, VERSION};
use sp_api::runtime_decl_for_core::CoreV5;
use sp_runtime::traits::TransactionExtension;

#[test]
fn frame_system_version_is_the_single_declared_runtime_version() {
    let system_version = <Runtime as frame_system::Config>::Version::get();
    assert_eq!(
        system_version, VERSION,
        "frame_system::Config::Version must be VERSION itself"
    );
    assert_eq!(&*system_version.spec_name, "madar");
    assert_eq!(system_version.spec_version, 7);
}

#[test]
fn runtime_api_version_equals_the_version_frame_system_uses() {
    let api_version = <Runtime as CoreV5<Block>>::version();
    assert_eq!(
        api_version,
        <Runtime as frame_system::Config>::Version::get()
    );
}

#[test]
fn signed_payload_versions_come_from_the_declared_version() {
    let spec = CheckSpecVersion::<Runtime>::new().implicit().unwrap();
    let tx = CheckTxVersion::<Runtime>::new().implicit().unwrap();
    assert_eq!(
        spec, VERSION.spec_version,
        "CheckSpecVersion must sign the declared spec_version"
    );
    assert_eq!(
        tx, VERSION.transaction_version,
        "CheckTxVersion must sign the declared transaction_version"
    );
}
