#!/bin/sh
# Phase 3.7 (D11) — Prometheus container entrypoint for the optional
# `observability` compose profile.
#
# Purpose: keep the checked-in Prometheus configuration secret-free while
# supporting the existing METRICS_SCRAPE_TOKEN model (decision D1).
#
#   * Default (METRICS_SCRAPE_TOKEN empty): serve the checked-in
#     /etc/prometheus/prometheus.yml unchanged — no Authorization header is
#     sent, matching the API's "empty token = auth disabled" behavior.
#   * Token set: write the token to a runtime-only file inside the container
#     (tmpfs, 0600) and generate /tmp/prometheus.yml from the checked-in
#     template. The marker line `# __SCRAPE_AUTH__` becomes an
#     `authorization.credentials_file` block, so the token VALUE is never
#     inlined into any configuration file.
#
# No secrets are required in the repository for either path; nothing here
# reads or writes the API, network or host side; this script only prepares
# the scrape configuration and then execs the Prometheus binary.

set -eu

template_file=/etc/prometheus/prometheus.yml
token_file=/tmp/.soc-tri-scrape-token
config_file="$template_file"

if [ -n "${METRICS_SCRAPE_TOKEN:-}" ]; then
  # Runtime-only credential store: tmpfs, owner-only, never mounted, never
  # written to a checked-in or persistent path.
  umask 077
  printf '%s' "$METRICS_SCRAPE_TOKEN" > "$token_file"

  generated=/tmp/prometheus.yml
  : > "$generated"
  while IFS= read -r line || [ -n "$line" ]; do
    # Match the marker by content, ignoring its YAML indentation: only the
    # anchored marker line is replaced (header comments are never touched).
    trimmed="${line#"${line%%[![:space:]]*}"}"
    if [ "$trimmed" = "# __SCRAPE_AUTH__" ]; then
      printf '%s\n' \
        '    authorization:' \
        '      type: Bearer' \
        "      credentials_file: $token_file"
    else
      printf '%s\n' "$line"
    fi
  done < "$template_file" > "$generated"
  config_file="$generated"
fi

# The compose CMD carries --config.file=/etc/prometheus/prometheus.yml as its
# first argument; the entrypoint chooses the effective file (the generated
# copy when auth is enabled) and drops the duplicate flag.
case "${1:-}" in
  --config.file=*) shift ;;
esac

exec /bin/prometheus --config.file="$config_file" "$@"
