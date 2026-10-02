#[cfg(feature = "std")]
fn main() {
    // `--allow-undefined`: required here because the `rust-lld` bundled with the recent Rust toolchain
    // actually used (newer than the assumptions of this release of
    // substrate-wasm-builder) rejects undefined symbols by default
    // (`ext_*` from `sp-io` — the real host functions, imported at runtime from
    // the node, not defined inside the WASM itself) instead of leaving them as imports as the old
    // assumption did. This is a pure linker/toolchain compatibility fix — no change to any actual host
    // function or to the runtime logic (see D40/D41).
    substrate_wasm_builder::WasmBuilder::init_with_defaults()
        .append_to_rust_flags("-C link-arg=--allow-undefined")
        .build();
}

/// Following the standard Substrate template pattern (`templates/solochain/runtime/build.rs`):
/// wasm-builder is disabled when this crate itself is compiled for the wasm32 target (no need
/// to build it from inside itself, and it speeds that compilation up).
#[cfg(not(feature = "std"))]
fn main() {}
