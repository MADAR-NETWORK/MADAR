#!/usr/bin/env bash
# Compares the output of two **independent** builds (two dist/ folders) to prove real reproducibility: scripts/compare-builds.sh distA distB
# "Buildable on two systems" is one thing; matching hashes between two independent builds is another — this script judges only the second.
# It compares: the Runtime WASM (must match across systems), the executable (not expected to match across different systems), and the manifest fields that must match.
set -uo pipefail
a="${1:?distA}"; b="${2:?distB}"
f() { sed -n "s/^ *\"$2\": *\"\(.*\)\",\?$/\1/p" "$1/build-manifest.json" | head -1; }
res=0
for k in git_commit cargo_lock_sha256 toolchain_file_sha256 features rustc; do
  if [ "$(f "$a" $k)" = "$(f "$b" $k)" ]; then echo "✅ $k matches"; else echo "❌ $k differs: $(f "$a" $k) ≠ $(f "$b" $k)"; res=1; fi
done
wa=$(sha256sum "$a/madar_consensus.wasm" | cut -d' ' -f1); wb=$(sha256sum "$b/madar_consensus.wasm" | cut -d' ' -f1)
if [ "$wa" = "$wb" ]; then echo "✅ Runtime WASM matches ($wa): the Runtime is truly reproducible"; else echo "❌ Runtime WASM differs (note: a different source path alone changes the hash — compare from a fixed path such as /build)"; res=1; fi
ta=$(f "$a" target); tb=$(f "$b" target)
ba=$(ls "$a"/madar-node* 2>/dev/null | grep -v cdx | head -1); bb=$(ls "$b"/madar-node* 2>/dev/null | grep -v cdx | head -1)
if [ "$ta" = "$tb" ]; then
  if [ "$(sha256sum "$ba" | cut -d' ' -f1)" = "$(sha256sum "$bb" | cut -d' ' -f1)" ]; then echo "✅ executable matches (same target)"; else echo "⚠️  executable differs despite the same target (paths/build stamps?) — do not claim binary reproducibility"; res=1; fi
else echo "ℹ️  two different targets ($ta / $tb): binaries are not compared; the binding comparison is the WASM"; fi
exit $res
