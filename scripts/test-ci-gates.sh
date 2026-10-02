#!/usr/bin/env bash
# Proves that the CI gates **actually fail** on deliberate violations, in an isolated temporary copy of the repository (the original is never touched):
#   1) a dummy secret staged for commit ⇒ the secret check fails   2) an undocumented advisory ⇒ check-advisories fails
#   3) changing the locked fxhash version ⇒ verify-build-env fails   4) an uncommitted modified lock ⇒ verify-build-env fails
#   5) editing Cargo.toml without updating the lock ⇒ cargo build --locked fails   6) the clean state passes (a control against false positives)
# Usage: scripts/test-ci-gates.sh   (needs cargo-audit and a local advisory database)
set -uo pipefail
src="$(cd "$(dirname "$0")/.." && pwd)"
tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
git clone -q --local "$src" "$tmp/r" && cd "$tmp/r" || exit 2
git config user.email t@t; git config user.name t; git config core.autocrlf false
cp "$src/scripts/"*.sh scripts/ 2>/dev/null; cp "$src/docs/security/dependency-exceptions.md" docs/security/; cp "$src/deny.toml" .
git add -A; git commit -qm base --no-verify 2>/dev/null

pass=0; failn=0
expect() { # description  expected(0|1)  command...
  local d="$1" want="$2"; shift 2
  "$@" >/tmp/ci-gate.out 2>&1; local got=$?
  [ "$got" != 0 ] && got=1
  if [ "$got" = "$want" ]; then pass=$((pass+1)); echo "  ok   $d"; else failn=$((failn+1)); echo "  FAIL $d (exited $got, expected $want)"; tail -5 /tmp/ci-gate.out | sed 's/^/       /'; fi
}
reset() { git reset -q --hard; git clean -fdq; }

echo "— clean state (control):"
expect "secret check --all on the clean copy" 0 bash scripts/check-no-secrets.sh --all
expect "verify-build-env on the clean copy" 0 bash scripts/verify-build-env.sh
expect "check-advisories on the clean copy" 0 bash scripts/check-advisories.sh

echo "— deliberate violations (the gates must fail):"
reset; printf 'seed %s\n' "$(printf 'ab%.0s' $(seq 1 32))" > leak.txt; git add leak.txt
expect "staged dummy secret" 1 bash scripts/check-no-secrets.sh
reset; sed -i 's/RUSTSEC-2026-0119/RUSTSEC-9999-0000/g' docs/security/dependency-exceptions.md
expect "advisory not documented in the register" 1 bash scripts/check-advisories.sh
reset; sed -i '/RUSTSEC-2025-0057/d' deny.toml
expect "removing an approved exception makes fxhash undocumented" 1 bash scripts/check-advisories.sh
reset; sed -i '/name = "fxhash"/{n;s/version = "0.2.1"/version = "0.2.2"/}' Cargo.lock; git commit -qam lock --no-verify
expect "locked fxhash version left the approved one" 1 bash scripts/verify-build-env.sh
reset; echo "# x" >> Cargo.lock
expect "modified, uncommitted lock" 1 bash scripts/verify-build-env.sh
reset; sed -i '0,/^hex = "0.4"/s//hex = "0.4"\nitoa = "1"/' keystore/Cargo.toml 2>/dev/null; git diff --quiet keystore/Cargo.toml && sed -i '0,/^\[dependencies\]/s//[dependencies]\nitoa = "1"/' keystore/Cargo.toml
expect "editing Cargo.toml without updating the lock is rejected by --locked" 1 cargo metadata --locked --offline --format-version 1
reset

echo; echo "result: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
