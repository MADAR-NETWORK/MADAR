#!/usr/bin/env bash
# Reports Cargo.lock changes between two refs (default HEAD~1..HEAD): added/removed/upgraded packages. **Informational only, never fails**: lock changes are legitimate,
# and they are judged by the real gates (cargo deny, check-advisories, --locked build, tests), not by the mere fact that they changed.
# Usage: scripts/lock-diff-report.sh [base] [head]
set -uo pipefail
cd "$(dirname "$0")/.."
base="${1:-HEAD~1}"; head="${2:-HEAD}"
list() { git show "$1:$2" 2>/dev/null | tr -d '\r' | awk '/^name = /{n=$3} /^version = /{gsub(/"/,"",n); v=$3; gsub(/"/,"",v); print n" "v}' | sort -u; }
for lock in Cargo.lock; do
  git diff --quiet "$base" "$head" -- "$lock" 2>/dev/null && continue
  echo "### $lock ($base → $head)"
  a=$(mktemp); b=$(mktemp); list "$base" "$lock" > "$a"; list "$head" "$lock" > "$b"
  echo "added:";  comm -13 "$a" "$b" | sed 's/^/  + /'
  echo "removed:"; comm -23 "$a" "$b" | sed 's/^/  - /'
  rm -f "$a" "$b"
done
exit 0
