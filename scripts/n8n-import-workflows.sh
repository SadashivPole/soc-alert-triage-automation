#!/bin/sh
# Phase 2 lab helper: provision the lab SMTP credential, then import and
# activate the checked-in n8n workflows.
#
# Lab-focused startup step for docker-compose. It deliberately imports only the
# four canonical lab workflows (WF1/WF2/WF3/WF5) so generated or unrelated JSON
# files are never picked up. The workflow files contain stable ids, so re-running
# this on an existing n8n-data volume updates those workflows instead of creating
# duplicates.
#
# Phase 2D: the Send Email (emailSend) nodes in WF2/WF3/WF5 require an n8n SMTP
# credential. n8n refuses to execute an email node that has no credential bound,
# so before importing workflows we provision a single lab credential
# ("SMTP Lab Mailpit") pointing at the local Mailpit sink (mailpit:1025, no auth).
# The credential is rendered from environment at startup (SMTP_HOST/SMTP_PORT/
# SMTP_USER/SMTP_PASS/SMTP_SECURE) so no connection details or secrets live in
# the checked-in JSON; the checked-in n8n/credentials/smtp_lab_mailpit.json is
# the documented default. n8n encrypts the imported data at rest.
#
# Credential format (verified against n8n 1.85.0): `n8n import:credentials`
# requires the input file to be a top-level JSON **array** of credential
# objects — an object envelope around the array is rejected with "File does not
# seem to contain credentials. Make sure the credentials are contained in an
# array." The `id` ("smtp-lab-mailpit") must match the id bound to every
# emailSend node in WF2/WF3/WF5; 1.85.0 upserts credentials by id, so re-running
# this helper updates the existing credential instead of failing.
set -eu

WORKFLOW_DIR="${N8N_WORKFLOW_DIR:-/workflows}"
CREDENTIAL_FILE="${N8N_SMTP_CREDENTIAL_FILE:-/credentials/smtp_lab_mailpit.json}"

# --- SMTP credential (Phase 2D) ----------------------------------------------
# Render a single SMTP credential from env, defaulting to the local Mailpit sink.
# The name must match the `credentials.smtp.name` referenced by every email node.
echo "==> Provisioning lab SMTP credential (SMTP Lab Mailpit)"
SMTP_HOST="${SMTP_HOST:-mailpit}"
SMTP_PORT="${SMTP_PORT:-1025}"
SMTP_SECURE="${SMTP_SECURE:-false}"
SMTP_USER="${SMTP_USER:-${SMTP_USERNAME:-}}"
SMTP_PASS="${SMTP_PASS:-${SMTP_PASSWORD:-}}"

# BusyBox mktemp (Alpine-based n8nio/n8n:1.85.0) rejects templates whose
# trailing XXXXXX is followed by a suffix (e.g. "/tmp/smtp-cred.XXXXXX.json"
# -> "mktemp: Invalid argument"). Use the plain trailing-XXXXXX form; n8n
# reads the rendered JSON regardless of the filename suffix.
RENDERED_CRED="$(mktemp /tmp/smtp-cred.XXXXXX)"
trap 'rm -f "$RENDERED_CRED"' EXIT

cat > "$RENDERED_CRED" <<EOF
[
  {
    "id": "smtp-lab-mailpit",
    "name": "SMTP Lab Mailpit",
    "type": "smtp",
    "data": {
      "host": "$SMTP_HOST",
      "port": $SMTP_PORT,
      "secure": $SMTP_SECURE,
      "user": "$SMTP_USER",
      "password": "$SMTP_PASS"
    }
  }
]
EOF

# Import the credential. n8n 1.85.0 upserts credentials by id, so re-runs
# (restart with persistent volume) update the existing credential instead of
# failing or duplicating it.
if n8n import:credentials --input="$RENDERED_CRED"; then
  echo "==> SMTP credential imported"
else
  echo "==> SMTP credential import skipped (already provisioned or import not supported)"
fi

# --- Workflows ----------------------------------------------------------------
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

echo "==> n8n credential import, workflow import/activation complete"
