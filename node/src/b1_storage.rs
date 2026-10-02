//! B1 diagnostic only: real RocksDB + trie, synthetic state, no peers or production data.
//! This measures warm reads and batched imports, NOT FRAME per-key weight calibration.
use clap::Parser;
use sc_cli::SubstrateCli;
use sc_client_api::{Backend, BlockImportOperation, StorageProvider};
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Header as _;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[test]
#[ignore = "disk probe: --release --ignored --nocapture --test-threads=1"]
fn b1_rocksdb_trie_probe() {
    assert!(!cfg!(debug_assertions), "use --release");
    let base = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!(
            "b1-storage-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let cli = crate::cli::Cli::parse_from([
        "madar-node",
        "--chain",
        "dev",
        "--base-path",
        base.to_str().unwrap(),
        "--database",
        "rocksdb",
        "--no-telemetry",
        "--no-prometheus",
    ]);
    let runner = cli.create_runner(&cli.run).unwrap();
    runner.sync_run(|config| -> sc_cli::Result<()> {
        let executor = sc_service::new_wasm_executor::<sp_io::SubstrateHostFunctions>(&config.executor);
        let (client, backend, _keystore, _tasks) = sc_service::new_full_parts::<
            madar_consensus::opaque::Block, madar_consensus::RuntimeApi, _
        >(&config, None, executor, vec![])?;
        let mut parent = client.info().best_hash;
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        for round in 1..=20u32 {
            let mut storage = sp_core::storage::Storage::default();
            for i in 0..1000u32 {
                storage.top.insert(sp_crypto_hashing::blake2_256(&i.to_le_bytes()).to_vec(), vec![round as u8; 64]);
            }
            storage.top.insert(b"b1-large-vector".to_vec(), vec![round as u8; 32_008]);
            let mut op = backend.begin_operation()?;
            backend.begin_state_operation(&mut op, parent)?;
            let start = Instant::now();
            let root = op.reset_storage(storage.clone(), sp_core::storage::StateVersion::V1)?;
            let header = madar_consensus::Header::new(round, Default::default(), root, parent, Default::default());
            parent = header.hash();
            op.set_block_data(header, Some(vec![]), None, None, sc_client_api::NewBlockState::Best, true)?;
            backend.commit_operation(op)?;
            writes.push(start.elapsed().as_nanos() as u64);
            for (key, expected) in &storage.top {
                let start = Instant::now();
                let actual = client.storage(parent, &sp_core::storage::StorageKey(key.clone()))?;
                reads.push(start.elapsed().as_nanos() as u64);
                assert_eq!(actual.unwrap().0, *expected);
            }
        }
        reads.sort_unstable(); writes.sort_unstable();
        println!("B1 RocksDB warm reads n={} p50_ns={} p95_ns={} max_ns={}", reads.len(), reads[reads.len()/2], reads[reads.len()*95/100], reads.last().unwrap());
        println!("B1 RocksDB batch imports (1001 keys, including 32008-byte vector) n=20 p50_ns={} p95_ns={} max_ns={}", writes[9], writes[18], writes[19]);
        println!("B1 diagnostic database retained at {} (synthetic, no secrets); not a cold-cache or per-key write-weight qualification", base.display());
        Ok(())
    }).unwrap();
}
