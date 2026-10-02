#!/usr/bin/env bash
# Builds the MADAR release binary **locally or in CI with the very same script** (no build logic inside the workflow) and produces a `dist/` folder:
#   madar-node[.exe]            the executable (built with --locked --release)
#   madar_consensus.wasm        the embedded Runtime WASM (compact.compressed)
#   madar-node.cdx.json         SBOM (CycloneDX) of the built product: the actual target and features
#   build-manifest.json         build manifest: commit, compiler, target, features, hashes of everything including the lock file and the toolchain file
#   SHA256SUMS                  hashes of the dist files
# No keys and no signing here: D35 lives on air-gapped machines outside CI; the owner verifies with scripts/verify-release.sh and then signs `SHA256SUMS`+`build-manifest.json` manually.
# Usage: scripts/build-release.sh [--out dist] [--features "a b"] [--skip-env-check]
set -euo pipefail
cd "$(dirname "$0")/.."

out=dist
features=""
skip_env=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --features) features="$2"; shift 2 ;;
    --skip-env-check) skip_env=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ "$skip_env" = 0 ]; then bash scripts/verify-build-env.sh >/dev/null || { echo "❌ the build environment does not match the pinned one (run scripts/verify-build-env.sh)" >&2; exit 1; }; fi
if git rev-parse --git-dir >/dev/null 2>&1 && ! git diff --quiet HEAD -- . ':!dist'; then
  echo "❌ the working tree has uncommitted changes — releases are built from a clean commit only." >&2; exit 1
fi

host=$(rustc -vV | sed -n 's/^host: //p')
exe=madar-node; case "$host" in *windows*) exe=madar-node.exe ;; esac
feat_args=(); [ -n "$features" ] && feat_args=(--features "$features")

# Absolute paths from the build machine (user, CARGO_HOME, RUSTUP_HOME) leak into the binary through panic messages, breaking cross-machine reproducibility and exposing the user name:
# we remap them to fixed paths (for both Rust and the WASM builder).
root=$(pwd -W 2>/dev/null || pwd); cargo_home="${CARGO_HOME:-$HOME/.cargo}"; rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
remap="--remap-path-prefix=$root=/build --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup"
if command -v cygpath >/dev/null 2>&1; then
  remap="$remap --remap-path-prefix=$(cygpath -m "$root")=/build --remap-path-prefix=$(cygpath -m "$cargo_home")=/cargo --remap-path-prefix=$(cygpath -m "$rustup_home")=/rustup"
fi
export RUSTFLAGS="${RUSTFLAGS:-} $remap"
export WASM_BUILD_RUSTFLAGS="${WASM_BUILD_RUSTFLAGS:-} $remap"
echo "== build (--locked --release) for target $host"
cargo build --locked --release -p madar-node "${feat_args[@]}"

rm -rf "$out"; mkdir -p "$out"
cp "target/release/$exe" "$out/$exe"

# The Runtime WASM embedded in this build (the most recently modified under wbuild/madar-consensus).
wasm=$(find target/release/wbuild/madar-consensus -maxdepth 1 -name 'madar_consensus.compact.compressed.wasm' | head -1)
[ -n "$wasm" ] || { echo "❌ compressed Runtime WASM not found" >&2; exit 1; }
cp "$wasm" "$out/madar_consensus.wasm"

echo "== SBOM (CycloneDX) for the actual product, target and features"
# cargo-cyclonedx generates one file per workspace member: we keep the `madar-node` file (the built product) and delete the rest.
cargo cyclonedx --manifest-path node/Cargo.toml --format json --target "$host" ${features:+--features "$features"} --override-filename madar-node.cdx >/dev/null
mv node/madar-node.cdx.json "$out/madar-node.cdx.json"
find . -maxdepth 2 -name 'madar-node.cdx.json' -not -path "./$out/*" -delete

sha() { sha256sum "$1" | cut -d' ' -f1; }
commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
cat > "$out/build-manifest.json" <<EOF
{
  "product": "madar-node",
  "version": "$(sed -n 's/^version = "\(.*\)"/\1/p' node/Cargo.toml | head -1)",
  "git_commit": "$commit",
  "git_describe": "$(git describe --tags --always --dirty 2>/dev/null || echo unknown)",
  "target": "$host",
  "features": "$features",
  "profile": "release",
  "rustc": "$(rustc --version)",
  "cargo": "$(cargo --version)",
  "toolchain_file_sha256": "$(sha rust-toolchain.toml)",
  "cargo_lock_sha256": "$(sha Cargo.lock)",
  "sdk_tag": "$(grep -rhoE 'tag = "polkadot-stable[^"]*"' --include=Cargo.toml node consensus | sort -u | head -1 | sed 's/.*"\(.*\)"/\1/')",
  "artifacts": {
    "$exe": "$(sha "$out/$exe")",
    "madar_consensus.wasm": "$(sha "$out/madar_consensus.wasm")",
    "madar-node.cdx.json": "$(sha "$out/madar-node.cdx.json")"
  },
  "reproducibility": "built once on this machine; NOT claimed reproducible until scripts/compare-builds.sh shows identical hashes from two independent builds",
  "built_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
( cd "$out" && sha256sum "$exe" madar_consensus.wasm madar-node.cdx.json build-manifest.json > SHA256SUMS )
echo "== done: $out/"; cat "$out/SHA256SUMS"
