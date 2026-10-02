//! D22 — protection against state bloat through explicit type-level limits, not fees.
//! The mock sets `MaxItemsPerAccount=2` and `MaxItemSize=8` (deliberately small test values
//! to prove both limits easily — not the final production values).

mod common;

use common::{new_test_ext, Ledger, RuntimeOrigin, TestRuntime};

fn account(byte: u8) -> sp_runtime::AccountId32 {
    sp_runtime::AccountId32::from([byte; 32])
}

#[test]
fn storing_an_item_within_both_limits_succeeds() {
    new_test_ext().execute_with(|| {
        let who = account(1);
        assert!(Ledger::store_item(RuntimeOrigin::signed(who.clone()), b"short".to_vec()).is_ok());
        assert_eq!(madar_ledger::ItemsOf::<TestRuntime>::get(&who).len(), 1);
    });
}

/// D22: an item larger than `MaxItemSize` (8 bytes) is rejected explicitly — no silence, no truncation.
#[test]
fn item_larger_than_max_item_size_is_rejected() {
    new_test_ext().execute_with(|| {
        let who = account(2);
        let too_large = vec![0u8; 9]; // 9 > MaxItemSize=8

        let result = Ledger::store_item(RuntimeOrigin::signed(who.clone()), too_large);

        assert_eq!(
            result,
            Err(madar_ledger::Error::<TestRuntime>::ItemTooLarge.into())
        );
        assert_eq!(
            madar_ledger::ItemsOf::<TestRuntime>::get(&who).len(),
            0,
            "rejected item must not be stored partially"
        );
    });
}

/// D22: exceeding `MaxItemsPerAccount` (2) for the same account is rejected — no unbounded growth.
#[test]
fn exceeding_max_items_per_account_is_rejected() {
    new_test_ext().execute_with(|| {
        let who = account(3);

        Ledger::store_item(RuntimeOrigin::signed(who.clone()), b"one".to_vec())
            .expect("1st item within limit");
        Ledger::store_item(RuntimeOrigin::signed(who.clone()), b"two".to_vec())
            .expect("2nd item within limit");

        let third = Ledger::store_item(RuntimeOrigin::signed(who.clone()), b"three".to_vec());

        assert_eq!(
            third,
            Err(madar_ledger::Error::<TestRuntime>::TooManyItems.into()),
            "D22 violated: state growth per account must be bounded, not unlimited"
        );
        assert_eq!(
            madar_ledger::ItemsOf::<TestRuntime>::get(&who).len(),
            2,
            "the rejected 3rd item must not be stored"
        );
    });
}

/// Account isolation: one account hitting its limit does not affect another account.
#[test]
fn per_account_limits_are_independent() {
    new_test_ext().execute_with(|| {
        let who_a = account(4);
        let who_b = account(5);

        Ledger::store_item(RuntimeOrigin::signed(who_a.clone()), b"a1".to_vec()).unwrap();
        Ledger::store_item(RuntimeOrigin::signed(who_a.clone()), b"a2".to_vec()).unwrap();
        assert!(Ledger::store_item(RuntimeOrigin::signed(who_a.clone()), b"a3".to_vec()).is_err());

        // Account B is unaffected by account A being full.
        assert!(Ledger::store_item(RuntimeOrigin::signed(who_b.clone()), b"b1".to_vec()).is_ok());
        assert_eq!(madar_ledger::ItemsOf::<TestRuntime>::get(&who_b).len(), 1);
    });
}
