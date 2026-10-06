use crate::{
    chain_spec,
    cli::{CheckUpdateCmd, Cli, Subcommand},
    service,
};
use madar_consensus::opaque::Block;
use sc_cli::SubstrateCli;
use sc_service::PartialComponents;

impl SubstrateCli for Cli {
    fn impl_name() -> String {
        "MADAR Node".into()
    }

    fn impl_version() -> String {
        env!("SUBSTRATE_CLI_IMPL_VERSION").into()
    }

    fn description() -> String {
        env!("CARGO_PKG_DESCRIPTION").into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "https://github.com/".into()
    }

    fn copyright_start_year() -> i32 {
        2026
    }

    fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
        Ok(match id {
            "dev" => Box::new(chain_spec::development_chain_spec()?),
            "" | "local" => Box::new(chain_spec::local_chain_spec()?),
            path => Box::new(chain_spec::ChainSpec::from_json_file(
                std::path::PathBuf::from(path),
            )?),
        })
    }
}

/// Parse and run command-line arguments.
pub fn run() -> sc_cli::Result<()> {
    let cli = Cli::from_args();

    match &cli.subcommand {
        Some(Subcommand::Key(cmd)) => cmd.run(&cli),
        Some(Subcommand::ExportChainSpec(cmd)) => {
            let chain_spec = cli.load_spec(&cmd.chain)?;
            cmd.run(chain_spec)
        }
        Some(Subcommand::CheckBlock(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    import_queue,
                    ..
                } = service::new_partial(&config)?;
                Ok((cmd.run(client, import_queue), task_manager))
            })
        }
        Some(Subcommand::ExportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    ..
                } = service::new_partial(&config)?;
                Ok((cmd.run(client, config.database), task_manager))
            })
        }
        Some(Subcommand::ExportState(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    ..
                } = service::new_partial(&config)?;
                Ok((cmd.run(client, config.chain_spec), task_manager))
            })
        }
        Some(Subcommand::ImportBlocks(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    import_queue,
                    ..
                } = service::new_partial(&config)?;
                Ok((cmd.run(client, import_queue), task_manager))
            })
        }
        Some(Subcommand::PurgeChain(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run(config.database))
        }
        Some(Subcommand::Revert(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.async_run(|config| {
                let PartialComponents {
                    client,
                    task_manager,
                    backend,
                    ..
                } = service::new_partial(&config)?;
                // BABE too (the Epoch changes tree and fork weights), then GRANDPA: reverting GRANDPA alone left auxiliary
                // BABE data ahead of the chain after the revert, especially across Epoch boundaries.
                let aux_revert = Box::new(
                    |client: std::sync::Arc<service::FullClient>,
                     backend: std::sync::Arc<service::FullBackend>,
                     blocks| {
                        sc_consensus_babe::revert(client.clone(), backend, blocks)?;
                        sc_consensus_grandpa::revert(client, blocks)?;
                        Ok(())
                    },
                );
                Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
            })
        }
        Some(Subcommand::ChainInfo(cmd)) => {
            let runner = cli.create_runner(cmd)?;
            runner.sync_run(|config| cmd.run::<Block>(&config))
        }
        Some(Subcommand::CheckUpdate(cmd)) => run_check_update(cmd),
        Some(Subcommand::Doctor(cmd)) => match crate::doctor::run(cmd.clone()) {
            Ok(code) => {
                if code != 0 {
                    std::process::exit(code);
                }
                Ok(())
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(2);
            }
        },
        Some(Subcommand::Committee(cmd)) => {
            if let Err(e) = crate::committee::run(cmd.clone()) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            Ok(())
        }
        Some(Subcommand::Stamp(cmd)) => {
            if let Err(e) = crate::stamp::run(cmd.clone()) {
                eprintln!("{}", serde_json::json!({ "error": e }));
                std::process::exit(1);
            }
            Ok(())
        }
        Some(Subcommand::Names(cmd)) => {
            if let Err(e) = crate::names::run(cmd.clone()) {
                eprintln!("{}", serde_json::json!({ "error": e }));
                std::process::exit(1);
            }
            Ok(())
        }
        Some(Subcommand::Join(cmd)) => {
            // A readable message (Debug escapes non-ASCII text), and a non-zero exit code on failure.
            if let Err(e) = crate::join::run(cmd.clone()) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            Ok(())
        }
        None => {
            let runner = cli.create_runner(&cli.run)?;
            runner.run_node_until_exit(|config| async move {
                match config.network.network_backend {
                    // Review #19: `libp2p` is the only consumer of `hickory-proto 0.24.4` (RUSTSEC-2026-0119) and the SDK pins its version; the default
                    // backend `litep2p` uses the patched `hickory-proto 0.26.x`. We explicitly refuse selecting `libp2p` instead of running code with a known vulnerability
                    // (the dependency stays in Cargo.lock and shows up in `cargo audit` as a pre-launch blocker; we do not hide it).
                    sc_network::config::NetworkBackendType::Libp2p => Err(sc_cli::Error::Input(
                        "--network-backend libp2p is not supported in MADAR (RUSTSEC-2026-0119 in hickory-proto 0.24.4 pinned by the SDK); \
                         use the default litep2p"
                            .into(),
                    )),
                    sc_network::config::NetworkBackendType::Litep2p =>
                        service::new_full::<sc_network::Litep2pNetworkBackend>(config)
                            .map_err(sc_cli::Error::Service),
                }
            })
        }
    }
}

/// Format of a single entry in `docs/security/release-trusted-keys.json` — see
/// that file for the actual registry (currently empty: no production key yet, D35).
#[derive(serde::Deserialize)]
struct TrustedKeyRegistryEntry {
    key_id: String,
    public_key_hex: String,
    #[serde(default)]
    revoked: bool,
}

fn parse_hex_verifying_key(hex_key: &str) -> sc_cli::Result<ed25519_dalek::VerifyingKey> {
    let bytes =
        hex::decode(hex_key).map_err(|e| sc_cli::Error::Input(format!("Invalid Hex key: {e}")))?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        sc_cli::Error::Input("The trusted key must be 32 bytes (64 Hex characters)".into())
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| sc_cli::Error::Input(format!("Invalid Ed25519 key: {e}")))
}

fn load_trusted_keys_registry(
    path: &std::path::Path,
) -> sc_cli::Result<Vec<madar_update::TrustedKeyEntry>> {
    let raw = std::fs::read(path).map_err(|e| {
        sc_cli::Error::Input(format!("Could not read the key registry {path:?}: {e}"))
    })?;
    let entries: Vec<TrustedKeyRegistryEntry> = serde_json::from_slice(&raw)
        .map_err(|e| sc_cli::Error::Input(format!("Invalid key registry ({path:?}): {e}")))?;

    if entries.is_empty() {
        return Err(sc_cli::Error::Input(format!(
            "Key registry {path:?} is empty — no trusted key has been listed yet"
        )));
    }

    entries
        .into_iter()
        .map(|entry| {
            let public_key = parse_hex_verifying_key(&entry.public_key_hex)?;
            Ok(madar_update::TrustedKeyEntry {
                key_id: entry.key_id,
                public_key,
                revoked: entry.revoked,
            })
        })
        .collect()
}

/// Runs `madar-node check-update` — reads local files only (§14/D32: no
/// network request from inside `node/` itself; the operator fetches the manifest/signature
/// by any means they trust). Separates all verification errors (`madar_update::UpdateError`) from
/// file-read/Hex-decoding errors, with a clear message for each case.
fn run_check_update(cmd: &CheckUpdateCmd) -> sc_cli::Result<()> {
    let manifest_bytes = std::fs::read(&cmd.manifest_file).map_err(|e| {
        sc_cli::Error::Input(format!(
            "Could not read the manifest file {:?}: {e}",
            cmd.manifest_file
        ))
    })?;

    let manifest = if !cmd.signature_files.is_empty() {
        // Multisig M-of-N mode (D35) — clap already guarantees that
        // trusted_keys_file is present with it (requires) and that trusted_key/signature_file are absent
        // (conflicts_with), but required_signatures is structurally optional
        // (Option), so we check it here explicitly with a clear message instead of a panic/silent ignore.
        let required = cmd.required_signatures.ok_or_else(|| {
            sc_cli::Error::Input("--required-signatures is required with --signature-files".into())
        })?;
        let registry_path = cmd.trusted_keys_file.as_ref().ok_or_else(|| {
            sc_cli::Error::Input("--trusted-keys-file is required with --signature-files".into())
        })?;
        let registry = load_trusted_keys_registry(registry_path)?;

        let mut signatures = Vec::with_capacity(cmd.signature_files.len());
        for sig_path in &cmd.signature_files {
            let bytes = std::fs::read(sig_path).map_err(|e| {
                sc_cli::Error::Input(format!(
                    "Could not read the signature file {sig_path:?}: {e}"
                ))
            })?;
            let sig: [u8; 64] = bytes.try_into().map_err(|_| {
                sc_cli::Error::Input(format!(
                    "Signature file {sig_path:?} must be exactly 64 raw bytes"
                ))
            })?;
            signatures.push(sig);
        }

        madar_update::verify_and_parse_manifest_threshold(
            &manifest_bytes,
            &signatures,
            &registry,
            required,
        )
        .map_err(|e| sc_cli::Error::Input(format!("Manifest verification failed: {e:?}")))?
    } else {
        let signature_path = cmd.signature_file.as_ref().ok_or_else(|| {
            sc_cli::Error::Input("Specify --signature-file or --signature-files".into())
        })?;
        let signature_bytes = std::fs::read(signature_path).map_err(|e| {
            sc_cli::Error::Input(format!(
                "Could not read the signature file {signature_path:?}: {e}"
            ))
        })?;
        let signature: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            sc_cli::Error::Input("The signature file must be exactly 64 raw bytes".into())
        })?;

        match (&cmd.trusted_key, &cmd.trusted_keys_file) {
            (Some(hex_key), None) => {
                let trusted_key = parse_hex_verifying_key(hex_key)?;
                madar_update::verify_and_parse_manifest(&manifest_bytes, &signature, &trusted_key)
                    .map_err(|e| sc_cli::Error::Input(format!("Manifest verification failed: {e:?}")))?
            }
            (None, Some(registry_path)) => {
                let registry = load_trusted_keys_registry(registry_path)?;
                madar_update::verify_and_parse_manifest_multi(
                    &manifest_bytes,
                    &signature,
                    &registry,
                )
                .map_err(|e| sc_cli::Error::Input(format!("Manifest verification failed: {e:?}")))?
            }
            _ => {
                return Err(sc_cli::Error::Input(
                    "Specify exactly one of --trusted-key or --trusted-keys-file".into(),
                ))
            }
        }
    };

    let channel = match cmd.channel.to_lowercase().as_str() {
        "development" | "dev" => madar_update::ReleaseChannel::Development,
        "testnet" => madar_update::ReleaseChannel::Testnet,
        "stable" => madar_update::ReleaseChannel::Stable,
        other => {
            return Err(sc_cli::Error::Input(format!(
                "Unknown channel: {other} (available: development/testnet/stable)"
            )))
        }
    };

    match madar_update::check_for_update(
        &cmd.current_version,
        &cmd.minimum_accepted_version,
        channel,
        &manifest,
    ) {
        Ok(Some(newer)) => {
            println!(
                "✅ A validly signed update is available: {} -> {} (channel: {:?}, key_id={})",
                cmd.current_version, newer.version, newer.channel, newer.key_id
            );
            println!("Nothing was downloaded or installed automatically (D32: the decision stays with you).");
            Ok(())
        }
        Ok(None) => {
            println!(
                "No new update available on channel {:?} (current: {}).",
                channel, cmd.current_version
            );
            Ok(())
        }
        Err(e) => Err(sc_cli::Error::Input(format!(
            "The manifest was checked but rejected: {e:?}"
        ))),
    }
}
