#!/usr/bin/env bash
# =============================================================================
# check_secrets.sh — best-effort hygiene scan for leaked credentials
# Project: soc-alert-triage-automation
#
# Scans git-tracked files for common credential patterns and verifies basic
# .env hygiene. Exit code 1 on any finding. Intentionally conservative:
# a hit means "review this line", not "the repo is compromised".
#
# This is a helper, not a guarantee — always review diffs before merging.
# =============================================================================
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
fail=0

# --- Patterns -----------------------------------------------------------------
# Order matters only for reporting. Keep conservative to limit false positives.
PATTERNS=(
  'AKIA[0-9A-Z]{16}'                                   # AWS access key id
  'ASIA[0-9A-Z]{16}'                                   # AWS temporary key id
  'gh[pousr]_[A-Za-z0-9]{16,}'                         # GitHub tokens
  'github_pat_[A-Za-z0-9_]{20,}'                       # GitHub fine-grained PAT
  'sk-[A-Za-z0-9]{20,}'                                # OpenAI-style API keys
  'xox[baprs]-[A-Za-z0-9-]{10,}'                       # Slack tokens
  'AIza[0-9A-Za-z_-]{35}'                              # Google API keys
  'glpat-[A-Za-z0-9_-]{20,}'                           # GitLab PATs
  'dop_v1_[a-f0-9]{64}'                                # DigitalOcean tokens
  '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
  'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}'  # JWTs
  '(password|passwd|secret|api_key|apikey|access_token|auth_token)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9/+_]{16,}["'"'"']?'
)

# Files never worth scanning (vendored/binaries). Tracked files only anyway.
SKIP_RE='(\.lock|package-lock\.json|\.min\.(js|css))$'

if git rev-parse --git-dir >/dev/null 2>&1; then
  mapfile -t FILES < <(git ls-files --cached --others --exclude-standard)
else
  mapfile -t FILES < <(find . -type f -not -path './.git/*')
fi

echo "==> Scanning ${#FILES[@]} tracked/untracked-but-visible files for credential patterns..."

for f in "${FILES[@]}"; do
  [[ -z "$f" ]] && continue
  [[ "$f" =~ $SKIP_RE ]] && continue
  [[ ! -f "$f" ]] && continue
  for i in "${!PATTERNS[@]}"; do
    # grep per pattern so we can name it; -I skips binaries
    while IFS= read -r line; do
      printf "${RED}HIT${NC} [%s] %s:%s\n" "$((i + 1))" "$f" "$line"
      fail=1
    done < <(grep -InE "${PATTERNS[$i]}" -I -- "$f" 2>/dev/null | head -5 || true)
  done
done

# --- .env hygiene --------------------------------------------------------------
if git ls-files --cached 2>/dev/null | grep -qx '.env'; then
  printf "${RED}HIT${NC} .env is tracked by git — remove it and rotate anything inside\n"
  fail=1
fi

if [[ ! -f .env.example ]]; then
  printf "${YELLOW}WARN${NC} .env.example is missing\n"
else
  # The template must not contain real-looking assignments (placeholder runs are short)
  while IFS= read -r line; do
    printf "${RED}HIT${NC} .env.example looks like it holds a real value: %s\n" "$line"
    fail=1
  done < <(grep -nE '^[A-Z0-9_]+=(change-me.*)?$' .env.example | grep -vE '=(change-me.*|[a-z0-9.@/-]{0,24})$' || true)
fi

if [[ $fail -eq 1 ]]; then
  printf "\n${RED}FAIL${NC}: potential secrets found — review the lines above.\n"
  printf "If a hit is a documented false positive, narrow the value or note it in the PR.\n"
  exit 1
else
  printf "${GREEN}OK${NC}: no credential patterns found.\n"
fi
