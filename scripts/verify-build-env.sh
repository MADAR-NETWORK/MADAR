#!/usr/bin/env bash
# Verifies that the build environment matches what is pinned (review #25) — run it before any release build/live test and on any new machine:
#   scripts/verify-build-env.sh
# Exits 0 only if every check passes; otherwise prints every violation (it does not stop at the first one).
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
bad() { echo "❌ $*"; fail=1; }
ok()  { echo "✅ $*"; }

# 1) Compiler version = the channel pinned in rust-toolchain.toml (not a moving `stable`).
pinned=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml | head -1)
if [[ ! "$pinned" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  bad "rust-toolchain.toml must pin an exact version (x.y.z), found: '${pinned}'"
else
  actual=$(rustc --version | awk '{print $2}')
  if [ "$actual" = "$pinned" ]; then ok "rustc $actual matches the pinned version"; else bad "actual rustc $actual ≠ pinned $pinned (rustup toolchain install $pinned)"; fi
fi

# 2) The required WASM targets are installed.
if command -v rustup >/dev/null 2>&1; then
  installed=$(rustup target list --installed 2>/dev/null)
  for t in $(sed -n 's/^targets *= *\[\(.*\)\]/\1/p' rust-toolchain.toml | tr -d '" ' | tr ',' ' '); do
    if grep -qx "$t" <<<"$installed"; then ok "target $t installed"; else bad "target $t not installed (rustup target add $t)"; fi
  done
else
  echo "⚠️  rustup not found — could not check targets (verify wasm32v1-none manually)"
fi

# 3) One Polkadot SDK tag across all crates, and Cargo.lock pins exactly one commit.
tags=$(grep -rhoE 'tag *= *"polkadot-stable[^"]*"' --include=Cargo.toml . 2>/dev/null | grep -v '/target/' | sort -u)
n=$(grep -c . <<<"$tags")
if [ "$n" = "1" ]; then ok "single SDK tag: $tags"; else bad "multiple or missing SDK tags ($n): $tags"; fi
for lock in Cargo.lock; do
  commits=$(grep -oE 'polkadot-sdk\.git\?tag=[^"#]*#[0-9a-f]+' "$lock" | sort -u)
  c=$(grep -c . <<<"$commits")
  if [ "$c" = "1" ]; then ok "$lock pins the SDK to one commit: ${commits#*#}"; else bad "$lock: multiple/missing SDK commits ($c): $commits"; fi
done

# 4) No [patch]/[replace] silently changing the source of any dependency.
if grep -rnE '^\[(patch|replace)' --include=Cargo.toml . 2>/dev/null | grep -v '/target/'; then bad "[patch]/[replace] found in Cargo.toml (silently replaces a dependency source)"; else ok "no [patch]/[replace]"; fi

# 5) The lock file is consistent with Cargo.toml (no update needed) — --locked fails if it would need changes.
if cargo metadata --locked --format-version 1 >/dev/null 2>/tmp/verify-build-env.err; then ok "Cargo.lock consistent (--locked)"; else bad "Cargo.lock inconsistent with Cargo.toml: $(tail -2 /tmp/verify-build-env.err)"; fi


# 6) The lock file is committed to Git with no pending changes.
if git rev-parse --git-dir >/dev/null 2>&1; then
  for lock in Cargo.lock; do
    if ! git ls-files --error-unmatch "$lock" >/dev/null 2>&1; then bad "$lock is not tracked in Git"
    elif ! git diff --quiet -- "$lock"; then bad "$lock is modified and not committed (git diff $lock)"
    else ok "$lock committed with no pending changes"; fi
  done
fi

# 7) Temporary Tier-2 exceptions are bound to the approved version: any other locked version fails the check (requires a new review, docs/security/dependency-exceptions.md).
for pin in "fxhash 0.2.1" "instant 0.1.13"; do
  name=${pin% *}; ver=${pin#* }
  locked=$(awk -v n="$name" '/^name = /{cur=$3} /^version = /{ if (cur=="\""n"\"") print $3 }' Cargo.lock | tr -d '"' | sort -u | paste -sd, -)
  if [ -z "$locked" ]; then ok "$name is no longer in Cargo.lock — remove its exception from deny.toml and the register"; elif [ "$locked" = "$ver" ]; then ok "$name locked to the approved version $ver"; else bad "$name locked to $locked ≠ approved $ver — the exception does not extend automatically; review the register"; fi
done

echo
rustc -vV | sed 's/^/   /'
cargo --version | sed 's/^/   /'
if [ "$fail" -ne 0 ]; then echo "build environment verification failed."; exit 1; fi
echo "build environment matches."
