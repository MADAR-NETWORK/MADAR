//! Verifying a signed update manifest + an opt-in update check — the Node phase
//! Operations (§14/D32).
//!
//! Per the design document. **No network, no production
//! key, no forced automatic update** — D32 requires opt-in only: this crate
//! only returns "is there a newer, correctly signed manifest?", and the decision (and the actual
//! download/installation) always stays a manual user decision in this phase. Not calling this
//! crate from the node's main run path automatically ensures that "a failing update
//! server never stops the node from working" (§14).

#![deny(unsafe_code)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};

/// The release channel (§14: release channels).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseChannel {
    Development,
    Testnet,
    Stable,
}

/// A downloadable binary within a manifest, for one platform.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseArtifact {
    pub platform: String,
    pub url: String,
    /// SHA-256 in hex (64 characters) — verified by the caller after the actual download;
    /// outside the scope of this crate (no network here).
    pub sha256: String,
}

/// A complete update manifest, before or after signature verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseManifest {
    pub version: String,
    pub channel: ReleaseChannel,
    pub artifacts: Vec<ReleaseArtifact>,
    /// The ID of the signing key used — readiness for update-key rotation (§14):
    /// several trusted keys can coexist, and each manifest declares which one was used.
    pub key_id: String,
}

/// Verification/check errors. No `panic` path is associated with any of them.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// Ed25519 signature verification failed — includes any tampering with a single byte after signing.
    InvalidSignature,
    /// The manifest is correctly signed, but its content is not valid JSON of the expected structure.
    MalformedManifest,
    /// One of the version fields (current/minimum accepted/candidate) is not valid semver.
    MalformedVersion,
    /// The candidate version is lower than `minimum_accepted_version` — rollback
    /// protection (INV-U2); rejected even if the signature is valid.
    Downgrade,
    /// The signature is actually valid, but it belongs to a key listed as revoked in the
    /// trusted-key registry (revocation readiness, D35) — carries the `key_id` of the
    /// revoked key for a precise error message (not just a generic "invalid signature").
    RevokedKey(String),
    /// The number of valid signatures from **different** active keys is lower than the required
    /// minimum (D35 — M-of-N multisig). `valid` carries the number of
    /// unique keys actually satisfied (after de-duplication), not the number of
    /// raw signature byte strings passed.
    InsufficientSignatures { required: usize, valid: usize },
    /// An invalid threshold: zero (accepts without a signature), or larger than the number of unique active keys
    /// (can never be satisfied).
    InvalidThreshold {
        required: usize,
        active_unique_keys: usize,
    },
    /// The registry repeats a single `key_id`.
    DuplicateKeyId(String),
    /// The registry lists the same public key more than once (under two different names, for example): it would let one
    /// signature count as two approvals.
    DuplicatePublicKey(String),
}

/// The format of an entry in the JSON trusted-key registry (`docs/security/release-trusted-keys.json`).
#[derive(Deserialize)]
struct RegistryEntryJson {
    key_id: String,
    public_key_hex: String,
    #[serde(default)]
    revoked: bool,
}

/// Parses the trusted-key registry from JSON and validates it ([`validate_trusted_keys`]) — a single source used
/// by both the node and the dashboard, so the registry is never interpreted differently.
pub fn parse_trusted_keys_registry(json: &[u8]) -> Result<Vec<TrustedKeyEntry>, String> {
    let entries: Vec<RegistryEntryJson> =
        serde_json::from_slice(json).map_err(|e| format!("invalid key registry: {e}"))?;
    if entries.is_empty() {
        return Err("the key registry is empty — no trusted key is listed".to_string());
    }
    let keys = entries
        .into_iter()
        .map(|e| {
            let bytes = hex::decode(&e.public_key_hex)
                .map_err(|err| format!("key {} is invalid: {err}", e.key_id))?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| format!("key {} is not 32 bytes", e.key_id))?;
            let public_key = VerifyingKey::from_bytes(&bytes)
                .map_err(|err| format!("key {} is invalid: {err}", e.key_id))?;
            Ok(TrustedKeyEntry {
                key_id: e.key_id,
                public_key,
                revoked: e.revoked,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    validate_trusted_keys(&keys).map_err(|e| format!("unsound key registry: {e:?}"))?;
    Ok(keys)
}

/// Checks the integrity of the trusted-key registry: a unique `key_id` **and a unique public key**
/// (the independence of approvers is defined by public keys, not by names).
pub fn validate_trusted_keys(keys: &[TrustedKeyEntry]) -> Result<(), UpdateError> {
    let mut ids = std::collections::HashSet::new();
    let mut pubkeys = std::collections::HashSet::new();
    for entry in keys {
        if !ids.insert(entry.key_id.as_str()) {
            return Err(UpdateError::DuplicateKeyId(entry.key_id.clone()));
        }
        if !pubkeys.insert(entry.public_key.to_bytes()) {
            return Err(UpdateError::DuplicatePublicKey(entry.key_id.clone()));
        }
    }
    Ok(())
}

/// One entry of the trusted-key registry (readiness for update-key rotation/revocation,
/// D35). `revoked=true` does not mean "delete the key from the registry" — it means
/// keeping it explicitly so any old, validly made signature belonging to it is rejected with a precise error
/// (`RevokedKey`) instead of a misleading `InvalidSignature`.
pub struct TrustedKeyEntry {
    pub key_id: String,
    pub public_key: VerifyingKey,
    pub revoked: bool,
}

/// Verifies the Ed25519 signature over the raw manifest bytes **before** any JSON parsing
/// (INV-U1), then parses it. `trusted_key` is always passed by the caller — no
/// key is embedded here.
pub fn verify_and_parse_manifest(
    manifest_json: &[u8],
    signature_bytes: &[u8; 64],
    trusted_key: &VerifyingKey,
) -> Result<ReleaseManifest, UpdateError> {
    let signature = Signature::from_bytes(signature_bytes);
    trusted_key
        .verify(manifest_json, &signature)
        .map_err(|_| UpdateError::InvalidSignature)?;

    serde_json::from_slice(manifest_json).map_err(|_| UpdateError::MalformedManifest)
}

/// Like [`verify_and_parse_manifest`], but looks for the first key in
/// `trusted_keys` that matches the signature (key-rotation readiness — several
/// active keys can coexist, D35). If the signature matches a revoked key
/// (`revoked=true`), it is explicitly rejected with `RevokedKey(key_id)` instead of being accepted or
/// treated as a generic invalid signature — an Ed25519 signature is specific to exactly one key,
/// so matching a revoked key means certain knowledge that this is the key actually
/// used, not a guess.
pub fn verify_and_parse_manifest_multi(
    manifest_json: &[u8],
    signature_bytes: &[u8; 64],
    trusted_keys: &[TrustedKeyEntry],
) -> Result<ReleaseManifest, UpdateError> {
    validate_trusted_keys(trusted_keys)?;
    let signature = Signature::from_bytes(signature_bytes);

    for entry in trusted_keys {
        if entry.public_key.verify(manifest_json, &signature).is_ok() {
            if entry.revoked {
                return Err(UpdateError::RevokedKey(entry.key_id.clone()));
            }
            return serde_json::from_slice(manifest_json)
                .map_err(|_| UpdateError::MalformedManifest);
        }
    }

    Err(UpdateError::InvalidSignature)
}

/// **M-of-N multisig (D35 — the approved architecture, needs no specialized
/// hardware).** Requires valid signatures from at least `required` **different** active keys
/// (`revoked=false`) from `trusted_keys`, not from one
/// key. `signatures` is a list of raw Ed25519 signatures (any order; duplicates
/// from the same key are counted once only — the holder of one key cannot
/// "double" their vote). A revoked key never counts, even if its
/// signature is valid, matching the behavior of [`verify_and_parse_manifest_multi`]. This prevents
/// any single party (person or device) from publishing a release alone — real least privilege,
/// not just documentation.
pub fn verify_and_parse_manifest_threshold(
    manifest_json: &[u8],
    signatures: &[[u8; 64]],
    trusted_keys: &[TrustedKeyEntry],
    required: usize,
) -> Result<ReleaseManifest, UpdateError> {
    validate_trusted_keys(trusted_keys)?;
    let active_unique_keys = trusted_keys.iter().filter(|k| !k.revoked).count();
    if required == 0 || required > active_unique_keys {
        return Err(UpdateError::InvalidThreshold {
            required,
            active_unique_keys,
        });
    }

    // The unique **public key** is counted (not `key_id`), so a name cannot double one signature.
    let mut satisfied_keys: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    for signature_bytes in signatures {
        let signature = Signature::from_bytes(signature_bytes);
        for entry in trusted_keys {
            if entry.revoked {
                continue;
            }
            if entry.public_key.verify(manifest_json, &signature).is_ok() {
                satisfied_keys.insert(entry.public_key.to_bytes());
            }
        }
    }

    if satisfied_keys.len() < required {
        return Err(UpdateError::InsufficientSignatures {
            required,
            valid: satisfied_keys.len(),
        });
    }

    serde_json::from_slice(manifest_json).map_err(|_| UpdateError::MalformedManifest)
}

/// Checks whether `manifest` (a manifest **already verified** through
/// [`verify_and_parse_manifest`]) represents an actual available update, according to the operator's
/// configured channel and the minimum accepted version that prevents downgrades.
///
/// `Ok(Some(_))`: a real update is available on the same channel — the decision stays with the user
/// (D32: opt-in). `Ok(None)`: no update (an older/equal version, or a different channel).
/// `Err(Downgrade)`: a candidate version lower than the minimum accepted — an explicit
/// security condition, not merely "no update".
pub fn check_for_update(
    current_version: &str,
    minimum_accepted_version: &str,
    configured_channel: ReleaseChannel,
    manifest: &ReleaseManifest,
) -> Result<Option<ReleaseManifest>, UpdateError> {
    let current = Version::parse(current_version).map_err(|_| UpdateError::MalformedVersion)?;
    let minimum =
        Version::parse(minimum_accepted_version).map_err(|_| UpdateError::MalformedVersion)?;
    let candidate = Version::parse(&manifest.version).map_err(|_| UpdateError::MalformedVersion)?;

    if candidate < minimum {
        return Err(UpdateError::Downgrade);
    }

    if manifest.channel != configured_channel {
        return Ok(None);
    }

    if candidate > current {
        Ok(Some(manifest.clone()))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sample_manifest(version: &str, channel: ReleaseChannel) -> ReleaseManifest {
        ReleaseManifest {
            version: version.to_string(),
            channel,
            artifacts: vec![ReleaseArtifact {
                platform: "x86_64-pc-windows-msvc".to_string(),
                url: "https://example.invalid/madar-node.exe".to_string(),
                sha256: "0".repeat(64),
            }],
            key_id: "test-key-1".to_string(),
        }
    }

    fn sign(manifest: &ReleaseManifest, key: &SigningKey) -> (Vec<u8>, [u8; 64]) {
        let json = serde_json::to_vec(manifest).unwrap();
        let signature = key.sign(&json);
        (json, signature.to_bytes())
    }

    #[test]
    fn valid_signature_newer_version_same_channel_yields_update() {
        let key = signing_key();
        let manifest = sample_manifest("2.0.0", ReleaseChannel::Stable);
        let (json, sig) = sign(&manifest, &key);

        let parsed = verify_and_parse_manifest(&json, &sig, &key.verifying_key()).unwrap();
        let result = check_for_update("1.0.0", "1.0.0", ReleaseChannel::Stable, &parsed).unwrap();
        assert_eq!(result, Some(manifest));
    }

    #[test]
    fn same_or_older_version_yields_no_update() {
        let key = signing_key();
        let manifest = sample_manifest("1.0.0", ReleaseChannel::Stable);
        let (json, sig) = sign(&manifest, &key);
        let parsed = verify_and_parse_manifest(&json, &sig, &key.verifying_key()).unwrap();

        let result = check_for_update("1.0.0", "1.0.0", ReleaseChannel::Stable, &parsed).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn invalid_signature_is_rejected_even_with_well_formed_json() {
        let key = signing_key();
        let wrong_key = SigningKey::from_bytes(&[9u8; 32]);
        let manifest = sample_manifest("2.0.0", ReleaseChannel::Stable);
        let (json, sig) = sign(&manifest, &key);

        let result = verify_and_parse_manifest(&json, &sig, &wrong_key.verifying_key());
        assert_eq!(result.unwrap_err(), UpdateError::InvalidSignature);
    }

    #[test]
    fn tampering_one_byte_after_signing_is_detected() {
        let key = signing_key();
        let manifest = sample_manifest("2.0.0", ReleaseChannel::Stable);
        let (mut json, sig) = sign(&manifest, &key);
        let last = json.len() - 1;
        json[last] ^= 0xFF;

        let result = verify_and_parse_manifest(&json, &sig, &key.verifying_key());
        assert_eq!(result.unwrap_err(), UpdateError::InvalidSignature);
    }

    #[test]
    fn different_channel_yields_no_update_despite_valid_newer_signed_manifest() {
        let key = signing_key();
        let manifest = sample_manifest("2.0.0", ReleaseChannel::Development);
        let (json, sig) = sign(&manifest, &key);
        let parsed = verify_and_parse_manifest(&json, &sig, &key.verifying_key()).unwrap();

        let result = check_for_update("1.0.0", "1.0.0", ReleaseChannel::Stable, &parsed).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn candidate_below_minimum_accepted_is_rejected_as_downgrade_even_with_valid_signature() {
        let key = signing_key();
        let manifest = sample_manifest("0.9.0", ReleaseChannel::Stable);
        let (json, sig) = sign(&manifest, &key);
        let parsed = verify_and_parse_manifest(&json, &sig, &key.verifying_key()).unwrap();

        let result = check_for_update("1.0.0", "1.0.0", ReleaseChannel::Stable, &parsed);
        assert_eq!(result.unwrap_err(), UpdateError::Downgrade);
    }

    #[test]
    fn malformed_version_strings_never_panic() {
        let key = signing_key();
        let manifest = sample_manifest("not-a-semver", ReleaseChannel::Stable);
        let (json, sig) = sign(&manifest, &key);
        let parsed = verify_and_parse_manifest(&json, &sig, &key.verifying_key()).unwrap();

        let result = check_for_update("1.0.0", "1.0.0", ReleaseChannel::Stable, &parsed);
        assert_eq!(result.unwrap_err(), UpdateError::MalformedVersion);

        let result2 = check_for_update("garbage", "1.0.0", ReleaseChannel::Stable, &parsed);
        assert_eq!(result2.unwrap_err(), UpdateError::MalformedVersion);
    }

    #[test]
    fn malformed_json_with_valid_signature_is_rejected() {
        let key = signing_key();
        let json = b"{ not valid json";
        let signature = key.sign(json);

        let result = verify_and_parse_manifest(json, &signature.to_bytes(), &key.verifying_key());
        assert_eq!(result.unwrap_err(), UpdateError::MalformedManifest);
    }

    #[test]
    fn two_independent_trusted_keys_both_verify_their_own_manifests() {
        let key_a = signing_key();
        let key_b = SigningKey::from_bytes(&[42u8; 32]);

        let manifest_a = sample_manifest("2.0.0", ReleaseChannel::Stable);
        let (json_a, sig_a) = sign(&manifest_a, &key_a);
        assert!(verify_and_parse_manifest(&json_a, &sig_a, &key_a.verifying_key()).is_ok());

        let mut manifest_b = sample_manifest("2.0.0", ReleaseChannel::Stable);
        manifest_b.key_id = "test-key-2".to_string();
        let (json_b, sig_b) = sign(&manifest_b, &key_b);
        assert!(verify_and_parse_manifest(&json_b, &sig_b, &key_b.verifying_key()).is_ok());

        // Each key does not verify the other key's manifest (no coexistence that weakens isolation).
        assert_eq!(
            verify_and_parse_manifest(&json_a, &sig_a, &key_b.verifying_key()).unwrap_err(),
            UpdateError::InvalidSignature
        );
    }

    #[test]
    fn multi_key_registry_accepts_manifest_signed_by_any_active_key() {
        let old_key = signing_key();
        let new_key = SigningKey::from_bytes(&[13u8; 32]);
        let manifest = sample_manifest("3.0.0", ReleaseChannel::Stable);
        let (json, sig) = sign(&manifest, &new_key);

        let registry = vec![
            TrustedKeyEntry {
                key_id: "old".to_string(),
                public_key: old_key.verifying_key(),
                revoked: false,
            },
            TrustedKeyEntry {
                key_id: "new".to_string(),
                public_key: new_key.verifying_key(),
                revoked: false,
            },
        ];

        let result = verify_and_parse_manifest_multi(&json, &sig, &registry);
        assert_eq!(result.unwrap(), manifest);
    }

    #[test]
    fn multi_key_registry_rejects_manifest_signed_by_a_revoked_key_with_specific_error() {
        let revoked_key = signing_key();
        let manifest = sample_manifest("3.0.0", ReleaseChannel::Stable);
        let (json, sig) = sign(&manifest, &revoked_key);

        let registry = vec![TrustedKeyEntry {
            key_id: "compromised-2025".to_string(),
            public_key: revoked_key.verifying_key(),
            revoked: true,
        }];

        let result = verify_and_parse_manifest_multi(&json, &sig, &registry);
        assert_eq!(
            result.unwrap_err(),
            UpdateError::RevokedKey("compromised-2025".to_string())
        );
    }

    #[test]
    fn multi_key_registry_rejects_manifest_signed_by_an_unknown_key() {
        let unknown_key = signing_key();
        let manifest = sample_manifest("3.0.0", ReleaseChannel::Stable);
        let (json, sig) = sign(&manifest, &unknown_key);

        let registry = vec![TrustedKeyEntry {
            key_id: "someone-else".to_string(),
            public_key: SigningKey::from_bytes(&[99u8; 32]).verifying_key(),
            revoked: false,
        }];

        let result = verify_and_parse_manifest_multi(&json, &sig, &registry);
        assert_eq!(result.unwrap_err(), UpdateError::InvalidSignature);
    }

    fn three_key_registry() -> (SigningKey, SigningKey, SigningKey, Vec<TrustedKeyEntry>) {
        let key_a = SigningKey::from_bytes(&[1u8; 32]);
        let key_b = SigningKey::from_bytes(&[2u8; 32]);
        let key_c = SigningKey::from_bytes(&[3u8; 32]);
        let registry = vec![
            TrustedKeyEntry {
                key_id: "a".to_string(),
                public_key: key_a.verifying_key(),
                revoked: false,
            },
            TrustedKeyEntry {
                key_id: "b".to_string(),
                public_key: key_b.verifying_key(),
                revoked: false,
            },
            TrustedKeyEntry {
                key_id: "c".to_string(),
                public_key: key_c.verifying_key(),
                revoked: true,
            },
        ];
        (key_a, key_b, key_c, registry)
    }

    #[test]
    fn threshold_two_of_three_accepts_two_independent_active_signatures() {
        let (key_a, key_b, _key_c, registry) = three_key_registry();
        let manifest = sample_manifest("5.0.0", ReleaseChannel::Stable);
        let (json, sig_a) = sign(&manifest, &key_a);
        let sig_b = key_b.sign(&json).to_bytes();

        let result = verify_and_parse_manifest_threshold(&json, &[sig_a, sig_b], &registry, 2);
        assert_eq!(result.unwrap(), manifest);
    }

    #[test]
    fn threshold_rejects_when_only_one_of_two_required_signatures_present() {
        let (key_a, _key_b, _key_c, registry) = three_key_registry();
        let manifest = sample_manifest("5.0.0", ReleaseChannel::Stable);
        let (json, sig_a) = sign(&manifest, &key_a);

        let result = verify_and_parse_manifest_threshold(&json, &[sig_a], &registry, 2);
        assert_eq!(
            result.unwrap_err(),
            UpdateError::InsufficientSignatures {
                required: 2,
                valid: 1
            }
        );
    }

    #[test]
    fn threshold_does_not_let_one_signer_double_count_via_duplicate_signatures() {
        let (key_a, _key_b, _key_c, registry) = three_key_registry();
        let manifest = sample_manifest("5.0.0", ReleaseChannel::Stable);
        let (json, sig_a) = sign(&manifest, &key_a);

        // The same signature repeated twice — must not count as two votes.
        let result = verify_and_parse_manifest_threshold(&json, &[sig_a, sig_a], &registry, 2);
        assert_eq!(
            result.unwrap_err(),
            UpdateError::InsufficientSignatures {
                required: 2,
                valid: 1
            }
        );
    }

    #[test]
    fn threshold_zero_is_rejected_instead_of_accepting_an_unsigned_manifest() {
        let (key_a, _b, _c, registry) = three_key_registry();
        let manifest = sample_manifest("5.0.0", ReleaseChannel::Stable);
        let (json, _sig) = sign(&manifest, &key_a);
        let result = verify_and_parse_manifest_threshold(&json, &[], &registry, 0);
        assert!(
            matches!(
                result,
                Err(UpdateError::InvalidThreshold { required: 0, .. })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn threshold_above_the_active_key_count_is_rejected() {
        let (key_a, _b, _c, registry) = three_key_registry(); // 2 active + 1 revoked
        let manifest = sample_manifest("5.0.0", ReleaseChannel::Stable);
        let (json, sig_a) = sign(&manifest, &key_a);
        let result = verify_and_parse_manifest_threshold(&json, &[sig_a], &registry, 3);
        assert_eq!(
            result.unwrap_err(),
            UpdateError::InvalidThreshold {
                required: 3,
                active_unique_keys: 2
            }
        );
    }

    #[test]
    fn one_public_key_registered_under_two_ids_cannot_count_twice() {
        let (key_a, _b, _c, mut registry) = three_key_registry();
        registry.push(TrustedKeyEntry {
            key_id: "alias-of-a".into(),
            public_key: key_a.verifying_key(),
            revoked: false,
        });
        let manifest = sample_manifest("5.0.0", ReleaseChannel::Stable);
        let (json, sig_a) = sign(&manifest, &key_a);
        let result = verify_and_parse_manifest_threshold(&json, &[sig_a], &registry, 2);
        assert_eq!(
            result.unwrap_err(),
            UpdateError::DuplicatePublicKey("alias-of-a".into())
        );
        assert!(matches!(
            validate_trusted_keys(&registry),
            Err(UpdateError::DuplicatePublicKey(_))
        ));
    }

    #[test]
    fn duplicate_key_ids_in_the_registry_are_rejected() {
        let (_a, _b, _c, mut registry) = three_key_registry();
        let dup = TrustedKeyEntry {
            key_id: registry[0].key_id.clone(),
            public_key: registry[0].public_key,
            revoked: false,
        };
        registry.push(dup);
        assert!(matches!(
            validate_trusted_keys(&registry),
            Err(UpdateError::DuplicateKeyId(_))
        ));
    }

    #[test]
    fn threshold_ignores_valid_signature_from_a_revoked_key() {
        let (key_a, _key_b, key_c, registry) = three_key_registry();
        let manifest = sample_manifest("5.0.0", ReleaseChannel::Stable);
        let (json, sig_a) = sign(&manifest, &key_a);
        let sig_c_revoked = key_c.sign(&json).to_bytes();

        // key_c is revoked — even with its valid signature, it does not count toward the threshold.
        let result =
            verify_and_parse_manifest_threshold(&json, &[sig_a, sig_c_revoked], &registry, 2);
        assert_eq!(
            result.unwrap_err(),
            UpdateError::InsufficientSignatures {
                required: 2,
                valid: 1
            }
        );
    }

    proptest::proptest! {
        /// Property-based (not a repetition of the existing manual tests): completely
        /// random bytes as `manifest_json`, actually signed with our test
        /// key (to pass the signature-verification stage and actually reach
        /// the JSON parsing stage) — verifies that `verify_and_parse_manifest` never
        /// panics whatever the content of the bytes (INV-U1/INV-U4).
        #[test]
        fn verify_and_parse_manifest_never_panics_on_random_signed_bytes(
            random_bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..500)
        ) {
            let key = signing_key();
            let signature = key.sign(&random_bytes);
            let _ = verify_and_parse_manifest(&random_bytes, &signature.to_bytes(), &key.verifying_key());
        }

        /// Completely random version strings (not necessarily semver) in
        /// any of the three fields — generalizes the manual `malformed_version_strings_never_panic`
        /// to a random input space instead of only two fixed cases.
        #[test]
        fn check_for_update_never_panics_on_random_version_strings(
            current in ".*",
            minimum in ".*",
            candidate in ".*",
        ) {
            let manifest = sample_manifest(&candidate, ReleaseChannel::Stable);
            let _ = check_for_update(&current, &minimum, ReleaseChannel::Stable, &manifest);
        }
    }
}
