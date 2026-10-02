#!/usr/bin/env bash
# The owner's verification of CI/local build output **before manual signing** (needs no CI account: works on any copy of dist/):
#   scripts/verify-release.sh dist/
# 1) SHA256SUMS matches the files; 2) build-manifest.json matches the declared hashes and the SBOM; 3) the manifest names a commit, lock file and toolchain file
# that match the current repository (if you are in a clone of it); 4) the SBOM is valid JSON and names the product; 5) the executable contains no build-user paths.
# It signs nothing and uses no key. Exit 0 only if every check passes.
set -uo pipefail
d="${1:-dist}"
fail=0; bad(){ echo "❌ $*"; fail=1; }; ok(){ echo "✅ $*"; }
[ -d "$d" ] || { echo "no folder $d" >&2; exit 2; }
cd "$d" || exit 2

if sha256sum -c SHA256SUMS >/dev/null 2>&1; then ok "SHA256SUMS matches the files"; else bad "SHA256SUMS does not match the files"; fi

field() { sed -n "s/^ *\"$1\": *\"\(.*\)\",\?$/\1/p" build-manifest.json | head -1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
for f in madar_consensus.wasm madar-node.cdx.json madar-node madar-node.exe; do
  [ -f "$f" ] || continue
  declared=$(sed -n "s/^ *\"$f\": *\"\([0-9a-f]*\)\",\?$/\1/p" build-manifest.json | head -1)
  [ -n "$declared" ] || continue   # not an output of this build (e.g. madar-node without .exe on Windows)
  if [ "$declared" = "$(sha "$f")" ]; then ok "manifest matches the hash of $f"; else bad "hash of $f in the manifest ≠ actual"; fi
done

if grep -q '"bomFormat": *"CycloneDX"' madar-node.cdx.json && grep -q 'madar-node' madar-node.cdx.json; then ok "CycloneDX SBOM names the product"; else bad "invalid SBOM"; fi

if git -C .. rev-parse --git-dir >/dev/null 2>&1 && [ -f ../Cargo.lock ]; then
  m_commit=$(field git_commit); m_lock=$(field cargo_lock_sha256)
  if git -C .. cat-file -e "$m_commit^{commit}" 2>/dev/null; then
    ok "commit $m_commit exists in this repository"
    lock_at=$(git -C .. show "$m_commit:Cargo.lock" | sha256sum | cut -d' ' -f1)
    tc_at=$(git -C .. show "$m_commit:rust-toolchain.toml" | sha256sum | cut -d' ' -f1)
    [ "$lock_at" = "$m_lock" ] && ok "manifest lock = that commit's lock" || bad "manifest lock ≠ the commit's lock"
    [ "$tc_at" = "$(field toolchain_file_sha256)" ] && ok "toolchain file = that commit's file" || bad "toolchain file ≠ the commit's file"
  else bad "the manifest's commit is not present locally (fetch the full repository)"; fi
fi

bin=madar-node; [ -f madar-node.exe ] && bin=madar-node.exe
if [ -f "$bin" ]; then
  if grep -a -qiE '(/home/[a-z0-9_.-]+/|/Users/[A-Za-z0-9_.-]+/|C:\\Users\\[A-Za-z0-9_.-]+\\)' "$bin"; then
    echo "⚠️  the executable contains user paths from the build environment (minor information leak, and an obstacle to cross-machine reproducibility)"
  else ok "no user paths inside the executable"; fi
fi
echo; grep -E '"(rustc|target|features|git_describe|reproducibility)"' build-manifest.json | sed 's/^ */   /'
[ "$fail" = 0 ] && { echo "verification passed — you can now sign SHA256SUMS and build-manifest.json manually (D35, air-gapped machine)."; exit 0; } || { echo "verification failed — do not sign."; exit 1; }
