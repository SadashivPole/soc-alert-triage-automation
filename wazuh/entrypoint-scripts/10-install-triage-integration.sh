#!/bin/sh
# Wazuh custom-triage integration installer
# Runs from /entrypoint-scripts at container startup as root.
# Ensures /var/ossec/integrations is traversable by the wazuh user (root:wazuh 0750)
# and installs the custom integration files with secure ownership/permissions.
#
# Defensive-only: detection forwarding, no autonomous containment.
set -eu

DEST_DIR="/var/ossec/integrations"
# Source directory is provided via read-only bind mount of the repository.
# Allow override for testing; default matches the expected compose mount.
SRC_DIR="${WAZUH_INTEGRATOR_SRC:-/wazuh/integrator}"

# Fallback: if default src does not exist, try alternative locations that
# may be used in different compose layouts (keeps the script robust).
if [ ! -d "$SRC_DIR" ]; then
  for candidate in "/usr/share/wazuh/integrator" "./wazuh/integrator" "/wazuh_integrator"; do
    if [ -d "$candidate" ]; then
      SRC_DIR="$candidate"
      break
    fi
  done
fi

# Enforce directory ownership and mode explicitly.
# install -d does not guarantee ownership when the directory already exists,
# so we must enforce it to allow wazuh user traversal.
install -d -m 750 "$DEST_DIR"
chown root:wazuh "$DEST_DIR"
chmod 0750 "$DEST_DIR"

# Install integration files with secure ownership/mode.
# Both files must be root:wazuh 0750 (not writable by wazuh, not world-accessible).
if [ -f "$SRC_DIR/custom-triage" ]; then
  install -o root -g wazuh -m 0750 "$SRC_DIR/custom-triage" "$DEST_DIR/custom-triage"
else
  echo "WARN: source $SRC_DIR/custom-triage not found, skipping file install" >&2
fi

if [ -f "$SRC_DIR/custom-triage.py" ]; then
  install -o root -g wazuh -m 0750 "$SRC_DIR/custom-triage.py" "$DEST_DIR/custom-triage.py"
else
  echo "WARN: source $SRC_DIR/custom-triage.py not found, skipping file install" >&2
fi

echo "custom-triage integration installed to $DEST_DIR"
