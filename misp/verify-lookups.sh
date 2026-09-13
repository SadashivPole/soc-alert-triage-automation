#!/usr/bin/env bash
# =============================================================================
# misp/verify-lookups.sh — read-only MISP smoke check for the seeded fixture
#
# Project: soc-alert-triage-automation
#
# Looks up every attribute value in misp/fixtures/synthetic-events.json with
# `GET /attributes/restSearch` — the exact endpoint and shape the enrichment
# provider uses — and prints the match count, event ids and tag names.
#
# READ-ONLY BY DESIGN: this script issues GET requests only. It never creates,
# updates, publishes, or deletes anything in MISP (SECURITY.md §1). The
# platform itself is lookup-only too; seeding is a documented human action
# (misp/seeding.md).
#
# Usage:
#   MISP_URL=http://127.0.0.1:8080 MISP_API_KEY=<key> ./misp/verify-lookups.sh
#
# Exit codes: 0 = every seeded value matched, 1 = a value did not match or the
# instance was unreachable, 2 = missing tooling/environment.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE="${HERE}/fixtures/synthetic-events.json"

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }
[ -f "${FIXTURE}" ] || { echo "fixture not found: ${FIXTURE}" >&2; exit 2; }

: "${MISP_URL:?Set MISP_URL (e.g. http://127.0.0.1:8080)}"
: "${MISP_API_KEY:?Set MISP_API_KEY in the environment (never commit it)}"

TIMEOUT="${MISP_TIMEOUT_SECONDS:-5}"
ENDPOINT="${MISP_URL%/}/attributes/restSearch"

echo "==> Read-only restSearch check against ${ENDPOINT}"
printf '%-9s %-70s %s\n' "TYPE" "VALUE" "RESULT"

missing=0
while IFS=$'\t' read -r ioc_type value; do
  response="$(curl -sS -G --max-time "${TIMEOUT}" \
    --data-urlencode "value=${value}" \
    --data-urlencode "returnFormat=json" \
    -H "Authorization: ${MISP_API_KEY}" \
    -H "Accept: application/json" \
    "${ENDPOINT}")" || { echo "request failed for ${value}" >&2; exit 1; }

  summary="$(printf '%s' "${response}" | python3 -c '
import json, sys

try:
    body = json.load(sys.stdin)
except ValueError:
    print("ERROR: response was not JSON")
    raise SystemExit(0)

response = body.get("response")
attributes = response.get("Attribute", []) if isinstance(response, dict) else []
attributes = [a for a in attributes if isinstance(a, dict)]

event_ids = sorted({str(a["event_id"]) for a in attributes if a.get("event_id") is not None})
tags = sorted(
    {t["name"] for a in attributes for t in (a.get("tags") or []) if isinstance(t, dict) and t.get("name")}
)
print(
    "matches={} events={} tags={}".format(
        len(attributes), ",".join(event_ids) or "-", ",".join(tags) or "-"
    )
)
')"

  printf '%-9s %-70s %s\n' "${ioc_type}" "${value}" "${summary}"
  case "${summary}" in
    "matches=0 "*) missing=$((missing + 1)) ;;
  esac
done < <(python3 - "${FIXTURE}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    events = json.load(handle)

for event in events:
    for attribute in event.get("Event", {}).get("Attribute", []):
        print(f"{attribute['type']}\t{attribute['value']}")
PY
)

if [ "${missing}" -ne 0 ]; then
  echo "FAIL: ${missing} seeded value(s) had no MISP match — see misp/seeding.md" >&2
  exit 1
fi

echo "OK: every seeded synthetic value is present (read-only lookup)."
