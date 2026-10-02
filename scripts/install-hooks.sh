#!/usr/bin/env bash
# Installs the secret-material check as local hooks (opt-in, run knowingly by the developer; nothing in the repository modifies .git/hooks unless this is run explicitly):
#   pre-commit : scripts/check-no-secrets.sh          (what is staged for commit)
#   pre-push   : scripts/check-no-secrets.sh --all    (everything tracked, before pushing — a safety net if a commit was missed)
# Note: local hooks are not enforced on anyone who has not installed them; the full `--all` scan is also run manually before every release.

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
hooks="$repo_root/.git/hooks"

cat > "$hooks/pre-commit" <<'EOF'
#!/usr/bin/env bash
exec bash "$(git rev-parse --show-toplevel)/scripts/check-no-secrets.sh"
EOF
cat > "$hooks/pre-push" <<'EOF'
#!/usr/bin/env bash
exec bash "$(git rev-parse --show-toplevel)/scripts/check-no-secrets.sh" --all
EOF
chmod +x "$hooks/pre-commit" "$hooks/pre-push"
echo "installed pre-commit and pre-push in: $hooks"
