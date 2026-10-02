#!/usr/bin/env bash
# Secret-material check before a commit (D35: keys/encrypted copies never enter Git). **An extra defense, not a substitute for manual care.**
#
# Usage:
#   scripts/check-no-secrets.sh            # scans what is staged for commit (the actual index content, not the working-tree copy)
#   scripts/check-no-secrets.sh --all      # scans every file tracked in Git (periodic audit / before a release)
# Exit: 0 clean, 1 findings, 2 usage error. Never prints the secret value itself (file:line:rule only) so terminal/CI logs cannot leak it.
#
# A reviewed false-positive exception: a line in scripts/secret-scan-allowlist.txt in the form  path|rule|reason  (the reason is mandatory and non-empty).
# Without it the check cannot be bypassed.

set -uo pipefail

mode="staged"
case "${1:-}" in
  "" | --staged) mode="staged" ;;
  --all) mode="all" ;;
  *) echo "usage: $0 [--staged|--all]" >&2; exit 2 ;;
esac

root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "not inside a Git repository" >&2; exit 2; }
cd "$root" || exit 2
allowlist="scripts/secret-scan-allowlist.txt"

# --- Reviewed exceptions: (path|rule) -> reason; an empty reason is rejected.
declare -A allowed=()
if [ -f "$allowlist" ]; then
  while IFS='|' read -r a_path a_rule a_reason || [ -n "${a_path:-}" ]; do
    a_path="${a_path%$'\r'}"; a_reason="${a_reason%$'\r'}"
    case "${a_path:-#}" in "#"*) continue ;; esac
    if [ -z "${a_rule:-}" ] || [ -z "${a_reason// /}" ]; then
      echo "❌ $allowlist: line '$a_path' has no rule or no reason — an exception without a reason is rejected" >&2
      exit 2
    fi
    allowed["$a_path|$a_rule"]=1
  done < "$allowlist"
fi

found=0
report() { # file, rule, description, [line]
  local f="$1" rule="$2" msg="$3" line="${4:-}"
  if [ -n "${allowed["$f|$rule"]:-}" ]; then return; fi
  echo "❌ [$rule] $msg: $f${line:+:$line}"
  found=1
}

# --- Name rules (regardless of content).
check_name() {
  local f="$1" base
  base=$(basename -- "$f")
  case "$base" in
    *.enc)                                   report "$f" name-enc "encrypted key file (.enc) must not enter Git (D35)" ;;
    *.pem | *.key | *.p12 | *.pfx | *.jks | *.keystore | *.kdbx | *.gpg | *.asc)
                                             report "$f" name-keyfile "private key/certificate file by extension" ;;
    id_rsa | id_rsa.* | id_ed25519 | id_ed25519.* | id_ecdsa | id_ecdsa.* | id_dsa | id_dsa.*)
                                             case "$base" in *.pub) ;; *) report "$f" name-ssh "private SSH key" ;; esac ;;
    credentials.json | .netrc | .npmrc | .pgpass | .git-credentials)
                                             report "$f" name-credentials "local credentials file" ;;
    .env | .env.*)                           case "$base" in *.example | *.sample | *.template) ;; *) report "$f" name-env "environment file that may contain secrets" ;; esac ;;
    secret_ed25519 | node-key | *.node-key | secret_ed25519.*)
                                             report "$f" name-nodekey "private node network (P2P) key" ;;
  esac
  # Substrate keystore files: the name is a long hex string (key-type prefix + public key) and the content is the seed.
  if [[ "$base" =~ ^[0-9a-f]{72,}$ ]]; then report "$f" name-keystore "name matches a Substrate keystore file (contains a seed)"; fi
}

# --- Content rules (applied to text only; binaries are skipped with -I).
KW='(secret|private|passphrase|pass phrase|seed|suri|mnemonic|password|api[_-]?key|token)'
scan_content() { # file (name for the report) and stdin = content
  local f="$1" tmp hit
  tmp=$(mktemp) || return
  cat > "$tmp"
  grep -qI . "$tmp" 2>/dev/null || { rm -f "$tmp"; return; } # binary/empty

  rule() { # rule-id  regex  description  [-i]
    hit=$(grep -nIE ${4:-} -m1 -- "$2" "$tmp" 2>/dev/null | head -1 | cut -d: -f1)
    [ -n "$hit" ] && report "$f" "$1" "$3" "$hit"
  }
  rule pem-private '-----BEGIN ((RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY( BLOCK)?-----' "private key block"
  # A raw 32-byte seed/key (64 hex, with/without 0x) on a line containing a secret-indicating word (the earlier version used [^\n], which wrongly matched any character except n).
  # (\b does not work with the 0x prefix: there is no word boundary between x and the first hex digit, so explicit boundaries are used.)
  H64='(^|[^0-9A-Za-z])(0x)?[0-9a-fA-F]{64}($|[^0-9A-Za-z])'
  rule hex-secret "${KW}.{0,60}${H64}|${H64}.{0,60}${KW}" "64-character hex value next to a secret word" -i
  # A recovery phrase (12/15/18/21/24 lowercase English words) on a line containing an indicating word.
  rule mnemonic "${KW}.{0,40}\\b([a-z]{3,8} ){11,23}[a-z]{3,8}\\b" "possible recovery phrase (mnemonic)" -i
  # A real Argon2 password hash (not explanatory text).
  case "$f" in
    *.md | *.example.* | *.sample | *.txt) ;;
    *) rule argon-hash '\$argon2(id|i|d)\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]{20,}' "Argon2 password hash" ;;
  esac
  rule token-github '\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|github_pat_[A-Za-z0-9_]{60,}' "GitHub token"
  rule token-aws '\bAKIA[0-9A-Z]{16}\b' "AWS access key ID"
  rule token-slack '\bxox[baprs]-[A-Za-z0-9-]{10,}' "Slack token"
  rule token-openai '\bsk-[A-Za-z0-9]{32,}\b' "sk- style API key"
  rule token-anthropic '\bsk-ant-[A-Za-z0-9_-]{20,}' "Anthropic key"
  rm -f "$tmp"
}

# --- File list (NUL-separated: supports spaces and newlines in names).
if [ "$mode" = "staged" ]; then
  list_cmd=(git diff --cached --name-only -z --diff-filter=ACMR)
else
  list_cmd=(git ls-files -z)
fi

count=0
while IFS= read -r -d '' f; do
  count=$((count + 1))
  check_name "$f"
  # Content comes from the index (what will actually be committed), not from the working tree, which may differ after staging. Process substitution
  # (not a pipe) so that the value of `found` stays in this shell.
  if git cat-file -e ":$f" 2>/dev/null; then
    scan_content "$f" < <(git show ":$f" 2>/dev/null)
  fi
done < <("${list_cmd[@]}")

if [ "$found" -ne 0 ]; then
  echo >&2
  echo "stopped because of the findings above ($count files scanned). Do not put the secret in Git; if it is a false positive, record it in $allowlist with an explicit reason." >&2
  exit 1
fi
echo "✅ no secret material ($count files scanned, mode: $mode)"
exit 0
