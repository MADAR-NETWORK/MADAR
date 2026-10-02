#!/usr/bin/env bash
# Self-test for scripts/check-no-secrets.sh (review #27) in an isolated temporary repository: every rule detects, clean files/examples are not rejected,
# the check reads the index rather than the working tree, and it never prints the secret value. Run: scripts/test-check-no-secrets.sh
set -uo pipefail
src="$(cd "$(dirname "$0")" && pwd)/check-no-secrets.sh"
tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
cd "$tmp" && git init -q . && git config user.email t@t && git config user.name t && git config core.autocrlf false
mkdir scripts && cp "$src" scripts/check-no-secrets.sh

pass=0; failn=0
HEX=$(printf 'ab%.0s' $(seq 1 32))                      # 64 dummy hex characters
check() { # description  expected-exit  [new files as name=content ...]
  local desc="$1" want="$2"; shift 2
  git reset -q; git clean -fdq -e scripts >/dev/null 2>&1; find . -mindepth 1 -maxdepth 1 ! -name .git ! -name scripts -exec rm -rf {} +
  local kv name content
  for kv in "$@"; do name="${kv%%=*}"; content="${kv#*=}"; mkdir -p "$(dirname "$name")"; printf '%s\n' "$content" > "$name"; done
  git add -A . ':!scripts' 2>/dev/null
  out=$(bash scripts/check-no-secrets.sh 2>&1); got=$?
  if [ "$got" = "$want" ] && ! grep -qF "$HEX" <<<"$out"; then pass=$((pass+1)); echo "  ok   $desc"
  else failn=$((failn+1)); echo "  FAIL $desc (exited $got, expected $want)"; echo "$out" | sed 's/^/       /'; fi
}

echo "— must be rejected (1):"
check "PEM private key"          1 "k.txt=-----BEGIN PRIVATE KEY-----"
check "OPENSSH private key"      1 "k.txt=-----BEGIN OPENSSH PRIVATE KEY-----"
check "Hex 64 after 'seed'"      1 "n.md=the seed is $HEX ok"
check "Hex 64 before 'secret'"   1 "n.md=0x$HEX  # secret"
check "12-word mnemonic"         1 "n.md=mnemonic: legal winner thank year wave sausage worth useful legal winner thank yellow"
check "real Argon2 hash"         1 'cfg.json={"password_hash": "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"}'
check "GitHub token"             1 "t.txt=ghp_abcdefghijklmnopqrstuvwxyz0123456789"
check "AWS key ID"               1 "t.txt=AKIAABCDEFGHIJKLMNOP"
check ".enc file"                1 "keys/a.enc=x"
check "credentials.json file"    1 "dashboard/credentials.json={}"
check "node-key network key"     1 "d/node-key=x"
PUBHEX=$(printf 'cd%.0s' $(seq 1 32))                        # a public key (keystore file name), not the secret itself
check "hex keystore name"        1 "ks/6772616e$PUBHEX=x"
check ".env file"                1 ".env=A=1"
check "name with a space"        1 "my keys/id_rsa=x"

echo "— must pass (0):"
check "clean file"               0 "a.rs=fn main() {}"
check "public hash, no secret word" 0 "n.md=commit $HEX"
check "12 words, no indicator word" 0 "n.md=legal winner thank year wave sausage worth useful legal winner thank yellow"
check "credentials.example.json" 0 'credentials.example.json={"email":"you@example.com","password_hash":"<placeholder>"}'
check ".env.example"             0 ".env.example=A=1"
check "doc explaining an Argon2 hash" 0 'n.md=$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g'

echo "— the check reads the index, not the working tree:"
git reset -q; find . -mindepth 1 -maxdepth 1 ! -name .git ! -name scripts -exec rm -rf {} +
printf 'seed %s\n' "$HEX" > leak.txt; git add leak.txt; echo "innocent" > leak.txt
out=$(bash scripts/check-no-secrets.sh 2>&1); got=$?
if [ "$got" = 1 ]; then pass=$((pass+1)); echo "  ok   a staged secret replaced in the working tree is still detected"; else failn=$((failn+1)); echo "  FAIL bypass by editing after staging"; fi
git reset -q; rm -f leak.txt; echo "innocent" > leak.txt; git add leak.txt; printf 'seed %s\n' "$HEX" > leak.txt
out=$(bash scripts/check-no-secrets.sh 2>&1); got=$?
if [ "$got" = 0 ]; then pass=$((pass+1)); echo "  ok   clean staged content is not rejected because of an unstaged edit"; else failn=$((failn+1)); echo "  FAIL rejected because of the working tree"; fi

echo "— reviewed exceptions:"
git reset -q; git clean -fdq -e scripts; printf 'seed %s\n' "$HEX" > pub.md; git add pub.md
printf 'pub.md|hex-secret|public test vector\n' > scripts/secret-scan-allowlist.txt
bash scripts/check-no-secrets.sh >/dev/null 2>&1; got=$?
if [ "$got" = 0 ]; then pass=$((pass+1)); echo "  ok   an exception with an explicit reason is accepted"; else failn=$((failn+1)); echo "  FAIL the reasoned exception was not accepted"; fi
printf 'pub.md|hex-secret|\n' > scripts/secret-scan-allowlist.txt
bash scripts/check-no-secrets.sh >/dev/null 2>&1; got=$?
if [ "$got" = 2 ]; then pass=$((pass+1)); echo "  ok   an exception without a reason is rejected (usage error)"; else failn=$((failn+1)); echo "  FAIL an exception without a reason was accepted ($got)"; fi
rm -f scripts/secret-scan-allowlist.txt

echo "— --all mode scans everything tracked:"
git reset -q; git clean -fdq -e scripts; printf 'seed %s\n' "$HEX" > tracked.md; git add tracked.md; git commit -qm x --no-verify
bash scripts/check-no-secrets.sh --all >/dev/null 2>&1; got=$?
if [ "$got" = 1 ]; then pass=$((pass+1)); echo "  ok   --all detects a previously committed secret"; else failn=$((failn+1)); echo "  FAIL --all did not detect ($got)"; fi

echo
echo "result: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
