# misp/seeding.md — Deterministic synthetic seeding guide

This guide creates a **reproducible, synthetic-only** MISP dataset for the
optional `intel` compose profile (Phase 2.4). It is written for a lab /
portfolio deployment.

**Ground rules (SECURITY.md §5):**

- Seed **only** documentation-range indicators (IPv4 RFC 5737 `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`), `.example`/`.invalid`-style names, and
  hashes of synthetic benign strings. Never import real IOCs, real customer
  data, or live malware hashes.
- The platform is **lookup-only**: it reads `/attributes/restSearch` and never
  writes, publishes, or pushes to MISP. Seeding below is a *human* action
  performed in the MISP UI (or with the operator's own tooling), never by this
  repository's code.
- Never commit `MISP_API_KEY` or any MISP credential. Every MISP value in
  `docker-compose.yml` is read from the environment with an empty default, and
  the profile's one-shot `misp-preflight` container refuses to start the stack
  when any of them is missing — values live only in the git-ignored `.env`.
  (Required-variable interpolation, `${VAR:?…}`, is deliberately *not* used:
  Compose interpolates the whole file before it filters inactive profiles, so it
  would break the default `docker compose up -d`. See misp/README.md.)

## 0. What "deterministic" means here

| Source of nondeterminism | How the profile removes it |
| --- | --- |
| Random MISP UUIDs on every import | `misp/fixtures/synthetic-events.json` pins every event/attribute UUID |
| Random admin API key at first boot | `MISP_ADMIN_KEY` is set by the operator (fixed value, same as `MISP_API_KEY`) |
| Timestamps drifting with "today" | Every fixture `date`/`timestamp` is fixed (`2026-09-01` / `1788220800`) |
| Background feed fetches changing the dataset | `ENABLE_BACKGROUND_UPDATES=false`; no feeds/sync servers are configured |
| Plaintext credential echo into logs | `DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true` |

The lookup inputs are the repository's synthetic corpus alerts
(`docs/sample-alerts/`, `app/tests/fixtures/`), so a replay of the same alert
against the same seed produces the same enrichment provenance.

## 1. Configure `.env` (secrets only, never committed)

The `intel` profile requires the following variables. Generate each value
locally; do not reuse any credential from another system.

```bash
# ~/.env next to docker-compose.yml (git-ignored)

# MISP instance identity (internal-only default; see step 3)
MISP_BASE_URL=http://misp-nginx:8080
MISP_ADMIN_EMAIL=soc-admin@lab.invalid
MISP_ADMIN_ORG=SOC Lab Synthetic
MISP_ADMIN_PASSWORD=$(openssl rand -base64 24)
MISP_GPG_PASSPHRASE=$(openssl rand -hex 24)
MISP_ENCRYPTION_KEY=$(openssl rand -hex 32)

# The API key user #1 authenticates with. Set it explicitly so the instance is
# deterministic; the platform uses the SAME value as MISP_API_KEY.
MISP_ADMIN_KEY=$(openssl rand -hex 20)
MISP_API_KEY=$(openssl rand -hex 20)      # must equal MISP_ADMIN_KEY

# MariaDB / Valkey credentials for the MISP stack
MISP_DB_USER=misp
MISP_DB_NAME=misp
MISP_DB_PASSWORD=$(openssl rand -base64 24)
MISP_DB_ROOT_PASSWORD=$(openssl rand -base64 24)
MISP_REDIS_PASSWORD=$(openssl rand -base64 24)

# Point the Triage API at the profile (internal service name + the key above).
# Empty values keep MISP lookups disabled (zero-external fallback).
MISP_URL=http://misp-nginx:8080
MISP_VERIFY_TLS=1
```

Rules of thumb:

- `MISP_API_KEY` and `MISP_ADMIN_KEY` **must be the same value** (one secret,
  two consumers: the MISP container initializes user #1 with it, the Triage API
  authenticates with it). `openssl rand -hex 20` yields MISP's 40-hex-character
  key shape.
- `MISP_URL` stays **empty** unless you actually want MISP lookups; both
  `MISP_URL` and `MISP_API_KEY` must be non-empty for the provider to enable
  (disable-by-empty, ARCHITECTURE.md §14).
- `docker-compose.yml` also passes `MISP_URL`/`MISP_API_KEY`/`MISP_VERIFY_TLS`
  into `triage-api`, so the existing service container picks them up on the next
  `up`/`restart`.
- If MISP restarts on a *wiped* volume (`misp-core-*` deleted), the pinned
  `ADMIN_KEY` re-initializes identically — but any events you imported are gone
  and must be re-imported from the fixture.

## 2. Start the profile

```bash
# Optional profile only — the default stack is unchanged.
docker compose --profile intel up -d

# MISP is heavy: misp-core has a 180 s health start period.
docker compose --profile intel ps
```

The first container to run is `misp-preflight`: a pinned, network-less one-shot
guard that checks the eight required `MISP_*` values are present (and non-empty)
before anything else starts. If a value is missing the profile stops with an
explicit message naming every missing variable and no MISP container ever comes
up — upstream MISP would otherwise fall back to its own defaults
(`MYSQL_PASSWORD=example`, `REDIS_PASSWORD=redispassword`,
`GPG_PASSPHRASE=passphrase`, generated admin password/API key). Inspect it with:

```bash
docker compose --profile intel logs misp-preflight   # "…secrets are present" on success
docker compose --profile intel ps                    # misp-preflight exits 0; the rest run
```

First boot initializes the database, GPG key and admin user (a few minutes).
Nothing is published to the host: `misp-core` (FastCGI 9002) and
`misp-nginx` (HTTP 8080) live only on the internal `soc-core` network, so the
Triage API reaches MISP at `http://misp-nginx:8080`.

## 3. Reach the MISP UI for one-off seeding (operator-local, opt-in)

The committed compose file intentionally publishes **no** MISP ports
(ARCHITECTURE.md §13). To seed by hand, opt in explicitly with a scratch
override that binds loopback only — create it outside the repository or delete
it afterwards; never commit it:

```yaml
# /tmp/misp-ui.override.yml   (NOT part of this repository)
services:
  misp-nginx:
    ports:
      - "127.0.0.1:8080:8080"   # loopback only; remove when seeding is done
```

```bash
docker compose -f docker-compose.yml -f /tmp/misp-ui.override.yml --profile intel up -d
# UI:      http://127.0.0.1:8080  (log in with MISP_ADMIN_EMAIL / MISP_ADMIN_PASSWORD)
# Cleanup: docker compose -f docker-compose.yml -f /tmp/misp-ui.override.yml \
#            --profile intel up -d --remove-orphans   # re-run without the file
```

Because the override binds `127.0.0.1`, nothing on the network can reach MISP
even while you seed.

## 4. Seed the two synthetic events

Reference payload: [`fixtures/synthetic-events.json`](fixtures/synthetic-events.json)
(two events, pinned UUIDs, fixed timestamps, documentation ranges only).

Import it in the UI (`Add Event` → MISP JSON import / `Events` → *Import from
MISP JSON*). If your MISP version's importer is picky about a field, create the
two events through the ordinary **Add Event** form and enter exactly the values
below — the resulting lookups are identical either way.

**Event 1 — `SYNTHETIC LAB — SSH brute-force source IPs`** (uuid
`11111111-1111-4111-8111-111111111101`, date `2026-09-01`, distribution *Your
organisation only*, threat level *Low*, **not published**, tags
`synthetic:true`, `lab:documentation-ranges`, `workflow:deterministic-seed`):

| Type (`ip-src`) | Value | Category | to_ids |
| --- | --- | --- | --- |
| ip-src | `203.0.113.50` | Network activity | false |
| ip-src | `203.0.113.60` | Network activity | false |
| ip-src | `203.0.113.61` | Network activity | false |

**Event 2 — `SYNTHETIC LAB — web attack sources + benign-string sample hashes`**
(uuid `11111111-1111-4111-8111-111111111102`, same date/distribution/threat
level, **not published**, tags `synthetic:true`, `lab:benign-string-hashes`,
`tlp:clear`):

| Type | Value | Category | to_ids |
| --- | --- | --- | --- |
| ip-src | `198.51.100.77` | Network activity | false |
| ip-src | `198.51.100.78` | Network activity | false |
| ip-src | `198.51.100.80` | Network activity | false |
| ip-src | `198.51.100.81` | Network activity | false |
| md5 | `bc478d7a48bfab117da4b9bdcb5aee36` | Payload delivery | false |
| sha1 | `87c151c211facd64c46da2004bccfc31f52128bd` | Payload delivery | false |
| sha256 | `23b3c5642480341d8bb98c40b6edb136f59088a7ae4e57ef6518789908769f0f` | Payload delivery | false |

These are exactly the indicators extracted from the synthetic corpus
(`203.0.113.50` from alerts 01/02/07, `198.51.100.77` from 05/10, the
malware-sample triple from 04/09, the remaining IPs from the near-miss
scenarios). Keeping the seed aligned with the corpus is what makes the demo
reproducible.

## 5. Verify lookups (read-only)

`misp/verify-lookups.sh` reads every value in the fixture and calls **only**
`GET /attributes/restSearch`. It performs no writes and needs no MISP admin
rights beyond the read key.

```bash
MISP_URL=http://127.0.0.1:8080 \
MISP_API_KEY="$MISP_API_KEY" \
  ./misp/verify-lookups.sh
```

Expected output: one line per seeded value with the matching attribute count and
distinct event ids (10 values). A miss prints `0` — check the event is
unpublished-but-visible to your key and that the attribute `value` matches
exactly.

Platform-side end-to-end (optional): send a synthetic corpus alert through the
normal ingest path and confirm the response reports MISP provenance:

```bash
curl -sS -X POST http://localhost:8000/api/v1/alerts/ingest \
  -H "X-API-Key: $TRIAGE_INGEST_API_KEY" -H 'Content-Type: application/json' \
  --data @docs/sample-alerts/01_wazuh_ssh_brute_force.json | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['enrichment_status'])"
```

With the seed in place the `203.0.113.50` indicator carries a `misp` record with
`lookup_status: found`, capped event ids and the seeded tags. Only sanitized
metadata is stored — never the attribute payload and never the API key.

## 6. Operating notes

- **Disable without deleting:** unset `MISP_URL`/`MISP_API_KEY` in `.env` and
  restart `triage-api`; the provider reports `skipped` and ingestion performs
  zero external calls again.
- **Stop the profile:** `docker compose --profile intel down` (state volumes are
  kept). `down -v` deletes `misp-db-data`, `misp-redis-data`, `misp-core-config`,
  `misp-core-files`, `misp-core-gnupg` — re-seed from the fixture afterwards.
- **Sizing:** the profile is sized for a workstation (core ≤ 2 CPU / 2 GB, db
  ≤ 1 CPU / 1 GB, redis ≤ 0.5 CPU / 256 MB, nginx ≤ 0.5 CPU / 256 MB, guard
  ≤ 0.25 CPU / 32 MB). MISP first boot is CPU-heavy; allow several minutes
  before declaring failure.
- **No mail relay is part of the profile.** MISP's own email notifications
  cannot be delivered; the platform never depends on them.
- **No feeds, no sync servers, no modules.** That is deliberate: it keeps the
  seeded dataset byte-stable and keeps this integration read-only.
- **Validation status:** the profile and guide are statically validated
  (compose structure, pinned images, internal-only networking, secret handling,
  fixture safety — see `app/tests/unit/test_misp_intel_profile.py`, which also
  executes the `misp-preflight` guard script for the missing/partial/complete
  secret cases). Live startup of MISP has not been performed in this
  repository's CI: no Docker daemon is available in the project's development
  sandbox.
