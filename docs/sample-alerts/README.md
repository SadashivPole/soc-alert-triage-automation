# Sample Alerts — Safe Synthetic Test Data

**Every file in this directory is 100% synthetic.** These payloads approximate the shape
of Wazuh 4.x alert JSON for development, demos, and CI contract tests. No real hosts,
users, networks, or malware are represented.

## Safety conventions used in ALL samples

| Field | Convention |
| --- | --- |
| Source/attacker IPs | RFC 5737 documentation ranges only: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| Internal host IPs | RFC 1918 lab ranges (`10.0.x.x`) with fictional hostnames |
| File hashes | SHA/MD5 of benign placeholder strings (e.g., `"soc-lab-synthetic-sample-01"`) |
| Domains/users | Clearly synthetic (`jdoe-lab`, `svc_deploy`, `CORP-LAB`) |
| Timestamps | Fixed dates in 2026 for deterministic tests |
| Rule IDs | Illustrative Wazuh-style IDs — verify against your Wazuh version before using with a real manager |

## Scenario catalog

| File | Scenario | Rule (id / level) | Expected triage behavior (v1 scoring target) |
| --- | --- | --- | --- |
| `01_wazuh_ssh_brute_force.json` | SSH brute-force attempts against a tier-1 web server | 5710 / 5 | dedupe group forms as it repeats; medium→high as recurrence grows; VT/MISP lookup of `203.0.113.50` in Phase 2 raises `threat_intel` |
| `02_wazuh_ssh_brute_force_success.json` | Auth **success** for a service account from the same brute-forcing IP shortly after (send after 01 ×N) | 5715 / 3 | correlated context should escalate the pair — a demo of why recurrence + correlation matter |
| `03_wazuh_fim_etc_passwd_change.json` | FIM: `/etc/passwd` modified on a critical DB server | 550 / 7 | `asset_criticality` (critical) + rule level push score to incident range |
| `04_wazuh_malware_hash_virustotal.json` | File hash with VirusTotal verdict (malicious 38/70) on a workstation | 87105 / 12 | high rule level + `threat_intel` → SEV1/SEV2 incident |
| `05_wazuh_web_sql_injection.json` | Web attack (SQL injection pattern) from external IP | 31103 / 10 | high band from rule level; external-IP enrichment in Phase 2 |
| `06_wazuh_windows_user_created.json` | Windows Event 4720 — new local account on a critical finance server | 60180 / 5 | medium band; `asset_criticality` lifts it; requires analyst review |
| `07_wazuh_ssh_brute_force_recurrence.json` | Same SSH brute-force behavior as 01 on a second tier-1 host (`web-prod-02`); evaluation corpus replays it as 3 distinct deliveries | 5710 / 5 | first delivery 43/low/monitor (identical to 01); third occurrence crosses the rapid-burst recurrence threshold (+12) → 55/medium/`queue_l1` (Phase 6.3) |
| `08_wazuh_ssh_session_opened.json` | Benign SSH session-opened baseline event; no suspicious groups, no MITRE, no indicators, no asset-tier labels | 5716 / 3 | informational band (unknown-asset fallback only) → `monitor`; must never escalate (Phase 6.3) |
| `09_wazuh_malware_hash_critical_server.json` | Same malware verdict as 04 on a critical finance server (`fin-db-01`) | 87105 / 12 | critical band → SEV1 `open_incident`; pins the critical tier end-to-end (Phase 6.3) |
| `10_wazuh_web_sql_injection_staging.json` | Same SQL-injection behavior as 05 against a tier-3 staging host (`web-stg-01`) | 31103 / 10 | low asset-criticality band keeps it medium → `queue_l1`; pins the `low` asset band (Phase 6.3) |

## Usage (once Phase 1 lands)

```bash
# send one sample with the ingest API key
./scripts/send_test_alert docs/sample-alerts/01_wazuh_ssh_brute_force.json

# simulate a brute-force burst (dedupe demo)
./scripts/send_test_alert --repeat 10 docs/sample-alerts/01_wazuh_ssh_brute_force.json
```

Until then, these files are design references for the normalizer (ARCHITECTURE.md §6)
and will become pytest fixtures (`app/tests/fixtures/`) in Phase 1.

## Rules for adding new samples

1. Follow the safety conventions above — no exceptions.
2. Add a row to the scenario catalog, including expected triage behavior.
3. Keep payloads deterministic (fixed timestamps, no randomness) so golden tests stay stable.
