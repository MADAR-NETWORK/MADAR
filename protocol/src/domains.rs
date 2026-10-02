//! Domain separation tags for MADAR-specific protocol extensions.
//!
//! Per §2.7 of the design document: every signing/verification layer
//! that already exists in Substrate/Polkadot SDK (SignedExtra, GRANDPA votes,
//! BABE VRF, SS58 checksum) already has its own domain-separation protection
//! and needs nothing added by MADAR.
//!
//! The only new component MADAR adds is the Admission/Weight puzzle
//! (§2.9 / §3 Sybil resistance), and it is the only one that needs an explicit domain tag,
//! because no domain protection exists for it at all.
//!
//! **Strict rule (§2.12):** this constant is defined here **only**, in one place,
//! and is never redefined or duplicated in any other file of the project.

/// Domain-separation tag for the Admission/Weight puzzle (§2.9).
///
/// Used as part of the input when computing:
/// `Blake2-256(ADMISSION_PUZZLE_DOMAIN || pubkey || epoch_seed || nonce) < target`
///
/// The actual implementation of the puzzle itself is **not** part of the Protocol phase — it comes in the
/// dedicated Admission/Sybil phase (§36). This constant only formally "reserves" the tag within the
/// protocol specification so it is never silently reinvented or changed later.
pub const ADMISSION_PUZZLE_DOMAIN: &[u8] = b"madar/admission-puzzle/v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tag_matches_spec_exactly() {
        // §2.7 and §2.9 of the design document: the exact text "madar/admission-puzzle/v1".
        assert_eq!(ADMISSION_PUZZLE_DOMAIN, b"madar/admission-puzzle/v1");
    }

    #[test]
    fn domain_tag_is_ascii_and_non_empty() {
        assert!(!ADMISSION_PUZZLE_DOMAIN.is_empty());
        assert!(ADMISSION_PUZZLE_DOMAIN.is_ascii());
    }
}
