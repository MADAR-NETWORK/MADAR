//! Double-block watchdog (B4): detects a BABE block producer signing two different blocks in the same Slot, and submits a proof **with both headers sealed**.
//!
//! **Why we need it:** `sc-consensus-babe` (the pinned version, and still so in `2609-rc2`) checks for equivocation on the header **after stripping the seal**, so the
//! proof comes out unsealed and `check_equivocation_proof` in the Runtime rejects it ⇒ no penalty for double block signing. The network's penalty rules already exist
//! (`VerifiedBabeReports` → `BanOnOffence` → permanent ban); the only missing piece is a correct report.
//!
//! **What it does (without any change to BABE):** a wrapper around `BlockImport` that sees every imported block with its seal (in `post_digests`), reassembles the sealed
//! header, and remembers for each (Slot, author) the first header it saw. If a different header arrives for the same key: it verifies locally with `check_equivocation_proof`
//! (the same function as in the Runtime), then generates a key ownership proof and submits the unsigned report via the transaction pool — the same path as GRANDPA.
//! Import always proceeds unchanged: any error in the watchdog is logged and never blocks the block.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use sc_consensus::{BlockCheckParams, BlockImport, BlockImportParams, ImportResult};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_consensus_babe::digests::CompatibleDigestItem;
use sp_consensus_babe::{digests::PreDigest, AuthorityId, BabeApi, EquivocationProof, Slot};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};

const LOG: &str = "madar-babe-watch";
/// We keep only the most recent this-many Slots (bounded memory; equivocation is detected the moment both versions arrive).
const KEEP_SLOTS: u64 = 2_048;

type Seen<H> = BTreeMap<(u64, AuthorityId), H>;

pub struct BabeEquivocationWatch<Block: BlockT, Client, Inner> {
    inner: Inner,
    client: Arc<Client>,
    pool: OffchainTransactionPoolFactory<Block>,
    seen: Arc<Mutex<Seen<Block::Header>>>,
}

impl<Block: BlockT, Client, Inner: Clone> Clone for BabeEquivocationWatch<Block, Client, Inner> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            client: self.client.clone(),
            pool: self.pool.clone(),
            seen: self.seen.clone(),
        }
    }
}

impl<Block: BlockT, Client, Inner> BabeEquivocationWatch<Block, Client, Inner> {
    pub fn new(
        inner: Inner,
        client: Arc<Client>,
        pool: OffchainTransactionPoolFactory<Block>,
    ) -> Self {
        Self {
            inner,
            client,
            pool,
            seen: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

/// The header as the author signed it: the imported header (unsealed) + the BABE seal from `post_digests`. None if there is no seal.
pub fn sealed_header<Block: BlockT>(params: &BlockImportParams<Block>) -> Option<Block::Header> {
    let seal = params
        .post_digests
        .iter()
        .find(|d| d.as_babe_seal().is_some())?
        .clone();
    let mut header = params.header.clone();
    header.digest_mut().push(seal);
    Some(header)
}

fn pre_digest<H: HeaderT>(header: &H) -> Option<PreDigest> {
    header
        .digest()
        .logs()
        .iter()
        .find_map(|l| l.as_babe_pre_digest())
}

/// Records the header and returns an equivocation proof if this author has already signed a different header for the same Slot (pure logic, tested).
pub fn record<H: HeaderT>(
    seen: &mut Seen<H>,
    slot: Slot,
    author: AuthorityId,
    header: H,
) -> Option<EquivocationProof<H>> {
    let s = u64::from(slot);
    let floor = s.saturating_sub(KEEP_SLOTS);
    while let Some(((old, _), _)) = seen.first_key_value() {
        if *old >= floor {
            break;
        }
        seen.pop_first();
    }
    // Comparison is on the content **without the seal**: the sr25519 signature is randomized, so the same block may arrive with two seals of different bytes (duplicate broadcast/re-
    // signing) — that is not equivocation. Equivocation = two different contents in the same Slot from the same author.
    let unsealed = |h: &H| {
        let mut c = h.clone();
        c.digest_mut().pop();
        c.hash()
    };
    match seen.get(&(s, author.clone())) {
        Some(first) if unsealed(first) != unsealed(&header) => Some(EquivocationProof {
            offender: author,
            slot,
            first_header: first.clone(),
            second_header: header,
        }),
        Some(_) => None,
        None => {
            seen.insert((s, author), header);
            None
        }
    }
}

impl<Block, Client, Inner> BabeEquivocationWatch<Block, Client, Inner>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync,
    Client::Api: BabeApi<Block> + ApiExt<Block>,
{
    /// The block author from the authorities of the Epoch the Slot falls in (current or next, read at the parent).
    fn author(&self, parent: Block::Hash, slot: Slot, index: u32) -> Option<AuthorityId> {
        let api = self.client.runtime_api();
        for epoch in [
            api.current_epoch(parent).ok()?,
            api.next_epoch(parent).ok()?,
        ] {
            let start = u64::from(epoch.start_slot);
            let s = u64::from(slot);
            if s >= start && s < start + epoch.duration {
                return epoch
                    .authorities
                    .get(index as usize)
                    .map(|(a, _)| a.clone());
            }
        }
        None
    }

    fn inspect(&self, params: &BlockImportParams<Block>) {
        if params.origin == BlockOrigin::NetworkInitialSync {
            return; // Equivocations during initial sync are usually old (same behavior as BABE).
        }
        let Some(header) = sealed_header(params) else {
            return;
        };
        let Some(pre) = pre_digest(&header) else {
            return;
        };
        let parent = *header.parent_hash();
        let Some(author) = self.author(parent, pre.slot(), pre.authority_index()) else {
            return;
        };
        let proof = {
            let mut seen = self.seen.lock().expect("babe-watch lock");
            record(&mut seen, pre.slot(), author.clone(), header)
        };
        if let Some(proof) = proof {
            self.report(parent, proof);
        }
    }

    fn report(&self, parent: Block::Hash, proof: EquivocationProof<Block::Header>) {
        log::warn!(
            target: LOG,
            "🚨 Double block: author {:?} signed two blocks in Slot {} ({:?} and {:?})",
            proof.offender,
            proof.slot,
            proof.first_header.hash(),
            proof.second_header.hash()
        );
        if !sp_consensus_babe::check_equivocation_proof(proof.clone()) {
            log::warn!(target: LOG, "The proof failed local verification — it will not be submitted.");
            return;
        }
        let best = self.client.info().best_hash;
        let api = self.client.runtime_api();
        let owner = [parent, best].into_iter().find_map(|at| {
            api.generate_key_ownership_proof(at, proof.slot, proof.offender.clone())
                .ok()
                .flatten()
        });
        let Some(owner) = owner else {
            log::warn!(target: LOG, "Could not generate the key ownership proof (not among the authorities?) — no report.");
            return;
        };
        let mut api = self.client.runtime_api();
        api.register_extension(self.pool.offchain_transaction_pool(best));
        match api.submit_report_equivocation_unsigned_extrinsic(best, proof, owner) {
            Ok(Some(())) => {
                log::warn!(target: LOG, "Double-block report submitted (the author is banned once it is included).")
            }
            Ok(None) => log::warn!(target: LOG, "The Runtime refused to submit the report."),
            Err(e) => log::warn!(target: LOG, "Could not submit the report: {e}"),
        }
    }
}

#[async_trait::async_trait]
impl<Block, Client, Inner> BlockImport<Block> for BabeEquivocationWatch<Block, Client, Inner>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync,
    Client::Api: BabeApi<Block> + ApiExt<Block>,
    Inner: BlockImport<Block> + Send + Sync,
{
    type Error = Inner::Error;

    async fn check_block(
        &self,
        block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        self.inner.check_block(block).await
    }

    async fn import_block(
        &self,
        block: BlockImportParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        self.inspect(&block);
        self.inner.import_block(block).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_consensus_babe::digests::SecondaryPlainPreDigest;
    use sp_core::{crypto::Pair, sr25519};
    use sp_runtime::{generic::Header, traits::BlakeTwo256, Digest, DigestItem};

    type H = Header<u32, BlakeTwo256>;

    fn signed_header(pair: &sr25519::Pair, slot: u64, extrinsics_root: u8) -> H {
        let pre = PreDigest::SecondaryPlain(SecondaryPlainPreDigest {
            authority_index: 0,
            slot: slot.into(),
        });
        let mut h = H::new(
            7,
            sp_core::H256::repeat_byte(extrinsics_root),
            Default::default(),
            Default::default(),
            Digest {
                logs: vec![DigestItem::babe_pre_digest(pre)],
            },
        );
        let sig = pair.sign(h.hash().as_ref());
        h.digest_mut().push(DigestItem::babe_seal(sig.into()));
        h
    }

    #[test]
    fn two_different_sealed_headers_in_one_slot_make_a_proof_the_runtime_accepts() {
        let pair = sr25519::Pair::from_seed(&[1u8; 32]);
        let author: AuthorityId = pair.public().into();
        let mut seen = Seen::new();
        assert!(record(
            &mut seen,
            100.into(),
            author.clone(),
            signed_header(&pair, 100, 1)
        )
        .is_none());
        assert!(
            record(
                &mut seen,
                100.into(),
                author.clone(),
                signed_header(&pair, 100, 1)
            )
            .is_none(),
            "same block twice is not an equivocation"
        );
        let proof = record(
            &mut seen,
            100.into(),
            author.clone(),
            signed_header(&pair, 100, 2),
        )
        .expect("a second block in the slot");
        assert!(
            sp_consensus_babe::check_equivocation_proof(proof),
            "sealed headers pass the runtime's own check"
        );
    }

    #[test]
    fn different_slots_or_authors_are_not_equivocations_and_memory_stays_bounded() {
        let a = sr25519::Pair::from_seed(&[1u8; 32]);
        let b = sr25519::Pair::from_seed(&[2u8; 32]);
        let mut seen = Seen::new();
        assert!(record(
            &mut seen,
            5.into(),
            a.public().into(),
            signed_header(&a, 5, 1)
        )
        .is_none());
        assert!(record(
            &mut seen,
            6.into(),
            a.public().into(),
            signed_header(&a, 6, 2)
        )
        .is_none());
        assert!(record(
            &mut seen,
            5.into(),
            b.public().into(),
            signed_header(&b, 5, 3)
        )
        .is_none());
        for s in 10..(10 + KEEP_SLOTS + 50) {
            record(
                &mut seen,
                s.into(),
                a.public().into(),
                signed_header(&a, s, 9),
            );
        }
        assert!(seen.len() as u64 <= KEEP_SLOTS + 1);
    }

    #[test]
    fn an_unsealed_header_like_the_sdk_sends_is_rejected() {
        let pair = sr25519::Pair::from_seed(&[1u8; 32]);
        let author: AuthorityId = pair.public().into();
        let mut first = signed_header(&pair, 9, 1);
        let mut second = signed_header(&pair, 9, 2);
        first.digest_mut().pop();
        second.digest_mut().pop();
        let proof = EquivocationProof {
            offender: author,
            slot: 9.into(),
            first_header: first,
            second_header: second,
        };
        assert!(
            !sp_consensus_babe::check_equivocation_proof(proof),
            "this is exactly why SDK reports fail today"
        );
    }
}
