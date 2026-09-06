#!/bin/bash
# =============================================================================
# 10-install-triage-integration.sh — install the custom-triage integrator
# (Phase 4.2). Mounted into the `full` compose profile at /entrypoint-scripts/.
#
# The wazuh-manager image runs every /entrypoint-scripts/*.sh in lexicographic
# order BEFORE `wazuh-control start` (config/etc/cont-init.d/2-manager,
# function_entrypoint_scripts), which is the supported hook for this.
#
# Why a copy instead of using the read-only bind mount directly:
#
#   * wazuh-integratord resolves the script as `integrations/<name>` relative to
#     /var/ossec, so it MUST exist at /var/ossec/integrations/custom-triage.
#     A subdirectory or symlink into a :ro mount is not the documented layout.
#   * Wazuh requires integration scripts to be owned root:wazuh with mode 750;
#     a bind mount carries the host's ownership, which is usually wrong.
#
# Copying at startup keeps this repository the source of truth (the mount stays
# read-only) while giving Wazuh exactly the file/ownership/mode it expects.
#
# Defensive-only: installs a detection-forwarding script. No containment.
# Secrets: none. Credentials are read from the process environment at runtime.
# =============================================================================
set -euo pipefail

SRC_DIR=${TRIAGE_INTEGRATION_SRC:-/triage-integration}
DEST_DIR=/var/ossec/integrations
LOG_FILE=/var/ossec/logs/integrations.log

log() { echo "[triage-integration] $*"; }

if [ ! -d "$SRC_DIR" ]; then
  log "ERROR: source directory $SRC_DIR is not mounted; integration NOT installed"
  exit 0 # never block manager startup
fi

for name in custom-triage custom-triage.py; do
  if [ ! -f "${SRC_DIR}/${name}" ]; then
    log "ERROR: ${SRC_DIR}/${name} missing; integration NOT installed"
    exit 0
  fi
done

install -d -m 750 "$DEST_DIR"
chown root:wazuh "$DEST_DIR"
chmod 0750 "$DEST_DIR"

# Wazuh's documented contract for integration scripts: root:wazuh, mode 750.
install -m 750 -o root -g wazuh "${SRC_DIR}/custom-triage" "${DEST_DIR}/custom-triage"
install -m 750 -o root -g wazuh "${SRC_DIR}/custom-triage.py" "${DEST_DIR}/custom-triage.py"

# integratord runs the script as the `wazuh` user, so the log file must be
# group-writable by wazuh. Create it up front with tight permissions rather
# than letting it be created ad hoc.
touch "$LOG_FILE"
chown root:wazuh "$LOG_FILE"
chmod 660 "$LOG_FILE"

# The spool holds alert bodies: owned by wazuh, never world-readable.
SPOOL_DIR=${WAZUH_INTEGRATOR_SPOOL_DIR:-/var/ossec/logs/triage-spool}
install -d -m 700 -o wazuh -g wazuh "$SPOOL_DIR"

log "installed custom-triage (root:wazuh 750), spool=${SPOOL_DIR}"
