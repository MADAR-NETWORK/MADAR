//! Calibrating the Argon2id cost for the `ARGON2_PS_PER_KIB_PASS` constant in `weights.rs`.
//!
//! Running (an optimized build is mandatory, and on the D23 target hardware for final approval):
//! `cargo run --release -p madar-admission --example argon2_calibration`
//!
//! Output = ns per KiB-pass; the approved constant must be a conservative multiple of it
//! (WASM is slower than native, and weaker hardware is slower than the development machine).

use argon2::{Algorithm, Argon2, Params, Version};

fn main() {
    assert!(
        !cfg!(debug_assertions),
        "calibration requires --release; never normalize debug timings"
    );
    for (memory_kib, time_cost, runs) in [(19_456u32, 2u32, 20u32), (65_536, 1, 10)] {
        let params = Params::new(memory_kib, time_cost, 1, Some(32)).expect("valid params");
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = [7u8; 16];
        let mut out = [0u8; 32];
        let runs = runs * 5;
        for i in 0..5 {
            argon
                .hash_password_into(&[i as u8; 40], &salt, &mut out)
                .expect("warmup");
        }
        let mut samples = Vec::new();
        for i in 0..runs {
            let start = std::time::Instant::now();
            argon
                .hash_password_into(&[i as u8; 40], &salt, &mut out)
                .expect("hash");
            std::hint::black_box(out);
            samples.push(start.elapsed().as_nanos() as f64);
        }
        samples.sort_by(f64::total_cmp);
        let per_hash_ns = samples.iter().sum::<f64>() / runs as f64;
        let per_kib_pass = per_hash_ns / (memory_kib as f64 * time_cost as f64);
        println!(
            "m={memory_kib} KiB t={time_cost}: {:.2} ms/hash = {per_kib_pass:.1} ns per KiB-pass",
            per_hash_ns / 1e6
        );
        println!("samples={runs} p50={:.3} ms p95={:.3} ms max={:.3} ms (native only; no disk/WASM claim)",
            samples[(runs as usize - 1) / 2] / 1e6,
            samples[(runs as usize * 95).div_ceil(100) - 1] / 1e6,
            samples.last().unwrap() / 1e6);
    }
}
