#!/bin/sh
# Phase 2C lab helper: import and activate the checked-in n8n workflows.
#
# Lab-focused startup step for docker-compose. It deliberately imports only the
# four canonical lab workflows (WF1/WF2/WF3/WF5) so generated or unrelated JSON
# files are never picked up. The workflow files contain stable ids, so re-running
# this on an existing n8n-data volume updates those workflows instead of creating
# duplicates. No secrets are hardcoded here or in the workflow JSON; the JSONs
# continue to resolve secrets from environment/credential references ($env.*).
set -eu

WORKFLOW_DIR="${N8N_WORKFLOW_DIR:-/workflows}"

echo "==> Importing n8n workflows from ${WORKFLOW_DIR}"
for name in \
  WF1_soc-triage-router.json \
  WF2_soc-analyst-notify.json \
  WF3_soc-incident-escalation.json \
  WF5_soc-analyst-feedback.json
do
  file="${WORKFLOW_DIR}/${name}"
  if [ ! -f "${file}" ]; then
    echo "ERROR: Expected workflow file not found: ${file}" >&2
    exit 1
  fi
  echo "==> Importing ${file}"
  n8n import:workflow --input="${file}"
done

# n8n deactivates imported workflows by default. Activate them before the n8n
# server starts so webhooks are registered on first boot.
echo "==> Activating imported n8n workflows"
n8n update:workflow --all --active=true

echo "==> n8n workflow import/activation complete"
