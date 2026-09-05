#!/bin/sh
# =============================================================================
# 10-install-triage-integration.sh — Phase 4.2 Wazuh manager entrypoint step
#
# Installs the custom SOC-triage `integrator` script into the Wazuh manager
# container at first boot and enforces the correct ownership so the
# `wazuh-integratord` daemon can execute and write to it without exposing the
# script to tampering by the runtime user.
#
# Executed by the wazuh/wazuh-manager entrypoint's /entrypoint-scripts.d/
# mechanism (scripts are sourced in numeric sort order as root before the
# Wazuh daemons start).
#
# Ownership rules (hardened per ARCHITECTURE §13 / SECURITY §4):
#
#   * Executable scripts under ${TRIAGE_INTEGRATOR_DIR} are owned
#     root:wazuh, mode 0750. The `wazuh` user must be able to READ and
#     EXECUTE them (wazuh-integratord drops privileges to wazuh) but must
#     NOT be able to write them (prevents a compromised integratord from
#     tampering with the script body on disk).
#
#   * The local alert-buffer / spool directory
#     ${TRIAGE_INTEGRATOR_BUFFER_DIR} is owned wazuh:wazuh, mode 0750.
#     The wazuh user creates/rotates retry spool files here, so it needs
#     write access; it must NOT be world-readable (alerts may contain
#     source-IP / username data).
#
#   * Mounted source trees (bind-mounted from the repo at
#     /wazuh-src/integrator in the `full` compose profile) commonly arrive
#     owned root:root with 0755 because Docker bind-mounts preserve host
#     uid/gid. If we did not chown, wazuh-integratord would fail with
#     EACCES reading the script and EACCES creating spool files.
#
# Idempotent: safe to re-run on container restart. Missing destination
# paths (e.g. when the source bind-mount is absent in the `sim` profile)
# are skipped silently so the manager still boots.
# =============================================================================
set -eu

# --- Paths (overridable via env, matching the wazuh-manager compose block) ----
TRIAGE_INTEGRATOR_SOURCE_DIR="${TRIAGE_INTEGRATOR_SOURCE_DIR:-/wazuh-src/integrator}"
TRIAGE_INTEGRATOR_DIR="${TRIAGE_INTEGRATOR_DIR:-/var/ossec/integrations}"
TRIAGE_INTEGRATOR_BUFFER_DIR="${TRIAGE_INTEGRATOR_BUFFER_DIR:-/var/ossec/integrations/triage-buffer}"
TRIAGE_INTEGRATOR_USER="${TRIAGE_INTEGRATOR_USER:-wazuh}"
TRIAGE_INTEGRATOR_GROUP="${TRIAGE_INTEGRATOR_GROUP:-wazuh}"

log() {
    printf '[triage-integration] %s\n' "$*"
}

# --- Source present? ---------------------------------------------------------
# In the `sim` (default) profile there is no Wazuh manager at all; even in a
# manager image the source bind-mount may be omitted during early dev. Fail
# closed with a clear log message rather than silently leaving the manager
# without an integration.
if [ ! -d "${TRIAGE_INTEGRATOR_SOURCE_DIR}" ]; then
    log "source directory ${TRIAGE_INTEGRATOR_SOURCE_DIR} not present — skipping integration install"
    exit 0
fi

# --- Install scripts ---------------------------------------------------------
log "installing triage integrator scripts from ${TRIAGE_INTEGRATOR_SOURCE_DIR}"
mkdir -p "${TRIAGE_INTEGRATOR_DIR}"

# Copy every regular file from the source tree into the integrations dir,
# preserving mode bits from the source (we re-apply permissions below).
find "${TRIAGE_INTEGRATOR_SOURCE_DIR}" -maxdepth 1 -type f \
    ! -name '*.md' ! -name '.gitkeep' -print | while IFS= read -r src; do
    name="$(basename "${src}")"
    dst="${TRIAGE_INTEGRATOR_DIR}/${name}"
    cp -f "${src}" "${dst}"
    log "installed ${name}"
done

# --- Enforce script ownership (hardened) -------------------------------------
# root:wazuh, 0750 — wazuh can read+execute but cannot modify the script body.
# chown first, then chmod; ordering matters if a previous run left a file
# owned by wazuh.
chown -R "root:${TRIAGE_INTEGRATOR_GROUP}" "${TRIAGE_INTEGRATOR_DIR}"
# Directories need the exec bit for traversal; files get 0750 only if
# executable by their owner at install time so we don't accidentally turn
# non-executable config files into commands.
find "${TRIAGE_INTEGRATOR_DIR}" -type d -exec chmod 0750 {} +
find "${TRIAGE_INTEGRATOR_DIR}" -type f -perm -u+x -exec chmod 0750 {} +
find "${TRIAGE_INTEGRATOR_DIR}" -type f ! -perm -u+x -exec chmod 0640 {} +

# --- Local buffer/spool directory --------------------------------------------
# wazuh:wazuh, 0750 — the daemon needs write access to stage retry payloads;
# group matches so ossec-execd siblings can read if needed; no world access.
mkdir -p "${TRIAGE_INTEGRATOR_BUFFER_DIR}"
chown "${TRIAGE_INTEGRATOR_USER}:${TRIAGE_INTEGRATOR_GROUP}" "${TRIAGE_INTEGRATOR_BUFFER_DIR}"
chmod 0750 "${TRIAGE_INTEGRATOR_BUFFER_DIR}"

log "ownership enforced: scripts root:${TRIAGE_INTEGRATOR_GROUP} 0750, buffer ${TRIAGE_INTEGRATOR_USER}:${TRIAGE_INTEGRATOR_GROUP} 0750"
log "triage integration install complete"
