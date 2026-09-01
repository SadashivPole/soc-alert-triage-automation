# Security Policy

**Project:** AI-Assisted SOC Alert Triage & Incident Response Automation

This document defines the security rules for developing and running this project, the
platform's own threat model, and how to report vulnerabilities. It applies to every
contribution and every phase in DEVELOPMENT_PLAN.md.

---

## 1. Scope & Charter (Defensive-Only)

This project is **exclusively defensive** SOC tooling: alert triage, enrichment, risk
scoring, analyst notification, and human-approved incident response.

**Will never be accepted in this repository:**

- Exploits, payloads, or proof-of-concept attack code targeting real systems.
- Malware, malware-generation, obfuscation, or any offensive tooling.
- Capability to launch attacks (DoS, brute-forcing targets, scanning third parties).
- Real credentials, customer data, victim data, or non-synthetic personal data.
- Autonomous destructive response actions (anything that modifies a production host or
  account without explicit human approval).

Where the pipeline performs active responses (Phase 4), they are **proposals** requiring
explicit analyst approval, fully audit-logged.

## 2. Secrets Management

**Rules (non-negotiable):**

1. No secrets in code, tests, docs, n8n workflow JSONs, sample data, commit messages,
   issue text, or log output. Ever.
2. Secrets enter only via environment variables (`.env`, git-ignored) or an orchestrator
   secret store. `.env.example` documents every variable with **placeholder values only**.
3. Placeholder convention: `change-me…` values must **fail fast** at startup — the app
   refuses to run with them in `SOC_ENV != development`.
4. Optional integrations are disabled when their key is empty; no key, no call.
5. `scripts/check_secrets.sh` scans tracked files for credential patterns; CI runs it on
   every PR (Phase 1+).
6. n8n credentials are stored in n8n's encrypted store (`N8N_ENCRYPTION_KEY`); exported
   workflow JSON may contain only credential *references* — reviewers verify this.
   Generate the key once into `.env` and keep it stable. Changing
   `N8N_ENCRYPTION_KEY` while reusing the existing `n8n-data` volume causes a
   mismatch crash. Do not hardcode the key in compose; do not automatically
   delete persistent n8n data from the application.
7. If a secret is ever committed: rotate it immediately, then clean history. Treat every
   pushed secret as compromised.

**What counts as a secret:** API keys (VirusTotal, MISP, TheHive, LLM), passwords, API
tokens, webhook URLs containing tokens, private keys, `N8N_ENCRYPTION_KEY`, session
cookies.

## 3. Authentication & Authorization

| Surface | Phase | Mechanism | Notes |
| --- | --- | --- | --- |
| `POST /api/v1/alerts/ingest` | 1 | `X-API-Key`, constant-time compare, per-key rate limit (default 120/min) | upgrade path: per-source keys + HMAC-SHA256 (`X-Signature`: body + timestamp, ±5 min window) |
| n8n → API callbacks (feedback, incident create, stats) | 1–3 | `N8N_CALLBACK_TOKEN` header | distinct from ingest key; least privilege per endpoint |
| Analyst console/read APIs | 3 | separate analyst token; read-mostly scopes | SSO/OIDC documented as future work |
| Containment approval | 4 | explicit authenticated approval endpoint, two-step confirm, audit | never callable by workflows autonomously |
| n8n UI | 1 | n8n's own auth; bind behind `soc-edge`; do not expose publicly | lab-only exposure guidance below |

All endpoints: explicit authz matrix test in CI; deny-by-default; uniform error bodies
that don't leak internals; rate limiting everywhere.

## 4. Network & Container Security

- Two Docker networks: `soc-edge` (published: n8n 5678, triage-api 8000, Mailpit UI
  8025) and `soc-core` (internal only: DB, MISP, Postgres, Wazuh manager).
- No service exposes the Docker socket; no `--privileged`; no host network mode.
- Containers run as non-root users with dropped capabilities; filesystems read-only
  where possible (writable named volumes for state only).
- Images pinned by tag (digest pin at release); base images minimal (`slim`/`alpine`);
  dependency scanning (`pip-audit`) in CI from Phase 1; container scanning (trivy) on
  release builds from Phase 3.
- Healthchecks + resource limits on every service; `restart: unless-stopped`.
- **Lab exposure guidance:** do not port-forward this stack to the internet. If remote
  access is needed, use a VPN or tunnel; Wazuh agent ports publish only in the `full`
  profile on a trusted LAN.

## 5. Data Handling & Test-Data Policy

- **Synthetic-only default:** every sample/alert in this repo is fabricated. IPs use
  documentation ranges (IPv4 `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`;
  IPv6 `2001:db8::/32`); domains use `.example`/`.invalid` or reserved lab names;
  hashes are of benign strings; usernames are clearly synthetic (`svc_backup`,
  `jdoe-lab`).
- Contributing real-world IOCs (hashes, IPs) is allowed only as *reputation references*
  in MISP seeding docs, never as embedded live data.
- The platform stores what Wazuh logs (`full_log`) — no additional user PII is collected
  by this codebase. Retention (Phase 3+): raw alert payloads 30 days, aggregates 12
  months, audit log retained; a sweeper job enforces this.
- Notification messages carry IOCs and scores only — never credentials or full raw logs.

## 6. Platform Threat Model (STRIDE-lite)

| Threat | Vector | Mitigation (phase) |
| --- | --- | --- |
| Spoofed ingest | attacker POSTs fake alerts to exhaust/quota-burn or distract | API key (1) → HMAC per-source (3+) · rate limits · schema validation · dead-letter audit |
| Tampering | forged n8n callbacks altering alert state/feedback | callback token (1) · separate tokens per operation (3) · audit with before/after |
| Repudiation | "who closed/contained this?" | append-only audit log for every state change (1) |
| Information disclosure | secrets in logs; alert data via unauthenticated read APIs | allow-listed log fields + canary test (1) · authz matrix (1+) · no-PII policy |
| Denial of service | alert floods, giant payloads | body size cap 256 KiB (1) · rate limits (1) · dedupe absorbs floods (1) · resource limits (1) |
| Elevation of privilege | n8n workflow hijack → containment abuse | workflows contain no secrets; approval endpoint requires explicit human auth (4) · n8n not exposed publicly |
| Supply chain | malicious dependency or image | pinned versions, `pip-audit`, lockfiles, review checklist (1+) · trivy on releases (3+) |

## 7. Logging & Audit Security

- Structured logs with allow-listed fields; a CI test injects canary secret values into
  the environment and asserts they never appear in output.
- Security-relevant events (auth failures, rate-limit trips, dead letters, config
  reloads, containment approvals) are logged at `WARNING`+ and duplicated to `audit_log`.
- Log floods are themselves rate-limited (per-source suppression with counters).

## 8. Reporting Vulnerabilities

If you find a security issue in this project:

1. **Do not open a public issue or PR that includes exploit details.**
2. Contact the maintainer privately via GitHub security advisory
   ("Security → Report a vulnerability" on the repository), including reproduction steps
   and affected files.
3. Please allow up to 14 days for an initial response before any external disclosure.
4. Reports about third-party dependencies should include the OSV/GHSA identifier.

We credit reporters in release notes (opt-in). This is a portfolio project — there is no
bounty program, and no production system is claimed to be protected by this code.

## 9. Security Review Checklist (every PR)

- [ ] No secrets, tokens, or real-world personal/victim data introduced
- [ ] New endpoints have auth, rate limits, validation, and authz-matrix coverage
- [ ] Sample/test data uses documentation ranges & synthetic values
- [ ] Errors handled per ARCHITECTURE §16; no stack traces leak to clients
- [ ] Logs use structured allow-listed fields (no free-form secret interpolation)
- [ ] Dependencies added consciously, pinned, scanned
- [ ] No offensive capability added (charter §1)
- [ ] Docs updated if security-relevant behavior changed
