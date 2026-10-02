#!/usr/bin/env bash
# Advisory gate: fails on **any** RUSTSEC advisory (vulnerability/unmaintained/unsound) that is not documented in the governing register — and passes only on documented ones, printing them.
# It hides nothing: documented advisories are printed every time (and `cargo deny check advisories` still fails on the two known vulnerabilities on purpose — vulnerabilities get no exception).
#   documented = an ID that appears in: (a) sections A/B/D of "Status of polkadot-stable2606-2" in docs/security/dependency-exceptions.md, or (b) an uncommented `id = "RUSTSEC-…"`
#            in deny.toml (approved Tier-2 exceptions).
# Any new advisory (which happens when Cargo.lock changes to an affected package) fails the gate until it is documented or fixed. A lock change by itself is not a failure.
set -uo pipefail
cd "$(dirname "$0")/.."
reg=docs/security/dependency-exceptions.md
[ -f "$reg" ] || { echo "❌ dependency register missing" >&2; exit 2; }

sect=$(tr -d '\r' < "$reg" | awk '/^## Status of `polkadot-stable2606/{on=1} on&&/^### C\)/{skip=1} on&&/^### D\)/{skip=0} on&&/^---$/{on=0} on&&!skip{print}')
documented=$( { printf '%s\n' "$sect" | grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}'; tr -d '\r' < deny.toml | grep -v '^\s*#' | grep -oE 'id = "RUSTSEC-[0-9]{4}-[0-9]{4}"' | grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}'; } | sort -u)
[ -n "$documented" ] || { echo "❌ no documented ID extracted (did the register format change?)" >&2; exit 2; }

args=(); for id in $documented; do args+=(--ignore "$id"); done
echo "== documented in the register ($(echo "$documented" | wc -l) IDs):"; echo "$documented" | tr '\n' ' '; echo
echo "== cargo audit (fails on undocumented advisories, including unmaintained/unsound warnings)"
cargo audit -D warnings "${args[@]}"
code=$?
if [ "$code" -ne 0 ]; then echo "❌ undocumented security advisory (or the check failed). Document it in the register with a tier, or fix it."; exit 1; fi
echo "✅ no undocumented advisory. (The documented ones above still show in: cargo audit / cargo deny check advisories)"
