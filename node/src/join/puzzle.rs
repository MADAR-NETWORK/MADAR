//! Solves the Admission puzzle with the actual Pallet functions: `Argon2id(pubkey ‖ seed ‖ nonce)`.
//! The seed **and the difficulty** come from the chain (`MembershipApi`), not from the compiled code: an upgrade that changes the difficulty does not break the tool.

use madar_consensus::{madar_admission, AccountId, Runtime};
use sp_core::H256;

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Is `nonce` a valid solution at network difficulty `bits`? (The same `Argon2id` the Pallet verifies with.)
pub fn is_solution(who: &AccountId, seed: &H256, nonce: u64, bits: u32) -> bool {
    leading_zero_bits(&madar_admission::Pallet::<Runtime>::compute_puzzle_output(
        who, seed, nonce,
    )) >= bits
}

/// The first valid `nonce` (sequential search). `progress` is called every 64 attempts (to show progress without revealing anything).
pub fn solve(
    who: &AccountId,
    seed: &H256,
    bits: u32,
    max_attempts: u64,
    mut progress: impl FnMut(u64),
) -> Option<u64> {
    for nonce in 0..max_attempts {
        if nonce % 64 == 0 {
            progress(nonce);
        }
        if is_solution(who, seed, nonce, bits) {
            return Some(nonce);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_local_check_agrees_with_the_pallet_at_the_compiled_difficulty() {
        let who = AccountId::from([9u8; 32]);
        let seed = H256::repeat_byte(3);
        let bits = crate::join::chain::compiled_puzzle_params().0;
        for nonce in 0..40u64 {
            assert_eq!(
                is_solution(&who, &seed, nonce, bits),
                madar_admission::Pallet::<Runtime>::solution_meets_difficulty(&who, &seed, nonce)
            );
        }
    }

    #[test]
    fn a_found_nonce_is_valid_at_the_difficulty_it_was_solved_for() {
        let who = AccountId::from([9u8; 32]);
        let seed = H256::repeat_byte(3);
        let mut ticks = 0;
        let nonce =
            solve(&who, &seed, 3, 5_000, |_| ticks += 1).expect("3 bits is solvable quickly");
        assert!(is_solution(&who, &seed, nonce, 3) && ticks >= 1);
        assert_eq!(leading_zero_bits(&[0, 0b0001_0000]), 11);
    }
}
