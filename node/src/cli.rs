#[derive(Debug, clap::Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: Option<Subcommand>,

    #[clap(flatten)]
    pub run: sc_cli::RunCmd,
}

#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
    /// Key management cli utilities.
    #[command(subcommand)]
    Key(sc_cli::KeySubcommand),

    /// Export the chain specification.
    ExportChainSpec(sc_cli::ExportChainSpecCmd),

    /// Validate blocks.
    CheckBlock(sc_cli::CheckBlockCmd),

    /// Export blocks.
    ExportBlocks(sc_cli::ExportBlocksCmd),

    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Import blocks.
    ImportBlocks(sc_cli::ImportBlocksCmd),

    /// Remove the whole chain.
    PurgeChain(sc_cli::PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Db meta columns information.
    ChainInfo(sc_cli::ChainInfoCmd),

    /// Operator onboarding: account, candidacy, session keys, membership status, renewal, exit (`madar-node join --help`).
    #[command(subcommand)]
    Join(crate::join::JoinCmd),

    /// Upgrade-committee approvals (2 of 3) signed offline: prepare, sign (refuses while the machine is online), submit (`madar-node committee --help`).
    #[command(subcommand)]
    Committee(crate::committee::CommitteeCmd),

    /// MADAR Stamp for the server service: submit a batch of fingerprints with the registrar account, and read a stamp record (`madar-node stamp --help`).
    #[command(subcommand)]
    Stamp(crate::stamp::StampCmd),

    /// Madar Names for the server service: register and renew a name with the registrar account, and read a name's record (`madar-node names --help`).
    #[command(subcommand)]
    Names(crate::names::NamesCmd),

    /// Read-only check of a running node: sync, finality, peers, role, disk, keys, membership, clock (`madar-node doctor --help`).
    Doctor(crate::doctor::DoctorCmd),

    /// Verify a signed update manifest locally (§14/D32: opt-in, no network, no
    /// automatic update). The operator fetches `--manifest-file`/`--signature-file`
    /// themselves from any source they trust (no network-fetch code is embedded here, by design).
    CheckUpdate(CheckUpdateCmd),
}

#[derive(Debug, clap::Args)]
pub struct CheckUpdateCmd {
    /// Path to the raw JSON manifest file (exactly as signed, without changing a single byte).
    #[arg(long)]
    pub manifest_file: std::path::PathBuf,

    /// Path to a single Ed25519 signature (64 raw bytes) over `manifest_file` — single-key
    /// mode. Use this **or** `--signature-files` (M-of-N), not
    /// both.
    #[arg(long, conflicts_with = "signature_files")]
    pub signature_file: Option<std::path::PathBuf>,

    /// Paths to several independent Ed25519 signatures (64 raw bytes each) —
    /// **Multisig M-of-N mode (D35, the approved architecture)**: requires
    /// `--required-signatures` and `--trusted-keys-file` together (not accepted with
    /// the single `--trusted-key` — a threshold over one key is meaningless).
    #[arg(
        long,
        conflicts_with_all = ["signature_file", "trusted_key"],
        requires = "trusted_keys_file",
        num_args = 1..
    )]
    pub signature_files: Vec<std::path::PathBuf>,

    /// Minimum number of valid signatures from **distinct** active keys required in
    /// Multisig mode (`--signature-files`). Ignored in single-key mode.
    #[arg(long, requires = "signature_files")]
    pub required_signatures: Option<usize>,

    /// The trusted public key (Hex, 64 characters) that must have signed
    /// the manifest. Use this **or** `--trusted-keys-file`, not both.
    #[arg(long, conflicts_with = "trusted_keys_file")]
    pub trusted_key: Option<String>,

    /// Path to a trusted-key registry (JSON, in the format of
    /// `docs/security/release-trusted-keys.json`) — key rotation/revocation readiness
    /// (D35): accepts any manifest signed by an `active` key in the registry,
    /// and explicitly rejects (with a distinct message) any manifest signed by a `revoked` key.
    #[arg(long, conflicts_with = "trusted_key")]
    pub trusted_keys_file: Option<std::path::PathBuf>,

    /// The version actually running now (Semver). Default: this Binary's version.
    #[arg(long, default_value = env!("CARGO_PKG_VERSION"))]
    pub current_version: String,

    /// Minimum accepted version — any validly signed manifest for a lower version is rejected
    /// (Rollback protection, INV-U2). The operator sets it themselves; there is no default
    /// guessed from this Binary.
    #[arg(long)]
    pub minimum_accepted_version: String,

    /// Requested release channel: development/testnet/stable.
    #[arg(long, default_value = "stable")]
    pub channel: String,
}
