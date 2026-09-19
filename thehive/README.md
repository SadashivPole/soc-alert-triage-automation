# thehive/ — TheHive 5 Community Edition Case Export (Optional `thehive` profile)

TheHive is an **optional** compose profile (`thehive`, **Phase 4.6 —
implemented**). It provides a self-hosted, **Community Edition** TheHive 5
instance for incident case management. The platform's deterministic triage,
scoring, and decision path runs fully without it, and outbound case export is
**disabled unless configured** (disable-by-empty).

**Status — implemented, source- and test-validated only; no live CE run is
claimed.** The code path (`app/src/soc_triage/thehive/`), the export API
(`POST /api/v1/incidents/{incident_id}/thehive`), and this compose profile are
implemented and exercised by fake-transport/static tests. **TheHive CE has not
been started in this repository's validation environment** — the development
sandbox has no Docker daemon, so **live TheHive startup is operator-side work
and is not claimed anywhere**. This is exactly the same posture as the MISP
`intel` and PostgreSQL `postgres` profiles.

## Community Edition only — never Premium

- `strangebee/thehive` is the free, open-source TheHive 5 **Community Edition**
  image. No license key is required to run it.
- **TheHive Premium is never required.** No Premium image, connector, feature,
  or license reference exists anywhere in this repository, and none is added
  here. This is a charter constraint recorded in `DEVELOPMENT_PLAN.md`.
- TheHive 5 depends on **Cassandra** (database) and **Elasticsearch** (index).
  They are part of the `thehive` profile for that reason; neither is used by the
  `triage-api` service itself.

## What the profile adds

| Service | Image (pinned) | Purpose | Host ports |
| --- | --- | --- | --- |
| `thehive-preflight` | `busybox:1.37.0` | one-shot secret guard: refuses to start the profile when a required value is missing (no network, exits 0) | none |
| `thehive-cassandra` | `cassandra:4.1.12` | TheHive database | none |
| `thehive-elasticsearch` | `docker.elastic.co/elasticsearch/elasticsearch:8.19.21` | TheHive index | none |
| `thehive` | `strangebee/thehive:5.7.6` | TheHive application (CE) | none |

Image tags are pinned to the exact versions from the upstream
`StrangeBeeCorp/docker` repository `versions.env` (audited 2026-09-19); no
floating/`latest` tags are used.

All four run **only** under `--profile thehive`, only on the internal `soc-core`
network (`thehive-preflight` has no network at all), and publish **no** host ports
(ARCHITECTURE.md §13). No default service gains a `depends_on` on them, so the
default stack and the zero-external fallback are unchanged. The three containers
`depends_on` the guard with `condition: service_completed_successfully`, so
nothing starts before the `.env` values have been validated.

```bash
docker compose --profile thehive up -d    # optional; nothing by default
docker compose up -d                      # default stack — TheHive never starts
```

> **Lab posture, not production.** The profile mirrors the vendor's own
> `testing`/`prod` stacks: Cassandra runs as a single node with the official
> image's default `cassandra` / `cassandra` superuser (the same default the
> vendor's healthcheck and TheHive `--cql-username`/`--cql-password` use), and
> Elasticsearch runs single-node with an `.env`-supplied `elastic` superuser
> password. TheHive reaches both only over the internal `soc-core` network.
> This profile makes **no production claim** and is not sized, secured, or
> TLS-terminated as production would be.

## Required environment variables

Add these to `.env` (never commit `.env`; see `.env.example` and SECURITY.md §2):

| Variable | Purpose | How to generate |
| --- | --- | --- |
| `THEHIVE_SECRET` | TheHive Play session secret (entrypoint `--secret`) | `openssl rand -hex 32` |
| `THEHIVE_ORG_NAME` | Organisation name you will create at first login (kept in sync with `THEHIVE_ORGANISATION`) | your choice, e.g. `soc-lab` |
| `THEHIVE_ADMIN_USERNAME` | TheHive admin login you will create at first login (not pre-created by the image) | your choice, e.g. `admin@lab.internal` |
| `THEHIVE_ADMIN_PASSWORD` | TheHive admin password you will set at first login (operator-side, never committed) | `openssl rand -base64 24` |
| `THEHIVE_API_KEY` | API key the platform authenticates with (see below) | see "API key source & creation" |
| `ELASTICSEARCH_PASSWORD` | Elasticsearch `elastic` superuser password, also passed as `--es-password` | `openssl rand -base64 24` |

Everything above is empty by default in `.env.example`. The `thehive-preflight`
guard refuses to start the profile (with a message naming every missing value)
if any of them is unset — the same fail-fast pattern as `misp-preflight` and
`postgres-preflight`. Compose interpolates the whole file before it filters
inactive profiles, so a required-variable reference (`${VAR:?…}`) would make
even the default `docker compose up -d` fail; that is why the profile uses empty
defaults plus a guard instead.

## How to configure the platform (existing settings — no second config)

TheHive settings already exist in `app/src/soc_triage/core/config.py` and are
passed through `docker-compose.yml`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `THEHIVE_URL` | empty | TheHive base URL. **Disable-by-empty**: leave empty (or set empty) to disable outbound case export entirely. |
| `THEHIVE_API_KEY` | empty | Bearer API key used as `Authorization: Bearer <key>` (from `.env` only; never committed). |
| `THEHIVE_ORGANISATION` | empty | Optional `X-Organisation` header (must match the TheHive organisation the user belongs to). |
| `THEHIVE_VERIFY_TLS` | `1` | TLS verification for outbound requests (keep `1`). |
| `THEHIVE_TIMEOUT_SECONDS` | `10` | Outbound request timeout in seconds. |

In the lab profile, `THEHIVE_URL` may point at `http://thehive:9000` (internal
`TRIAGE_API_BASE_URL`-style address). Nothing is published to the host, so the
export flows through the internal `soc-core` network only. **Both `THEHIVE_URL`
and `THEHIVE_API_KEY` must be non-empty to enable export** — otherwise
`POST /api/v1/incidents/{incident_id}/thehive` returns `503
integration_not_configured`, and import/`.env.example` defaults leave both
empty, so export stays off until an operator opts in.

## API-key source & creation

TheHive 5 advises API-key authentication for the API:

1. Complete the CE first-login setup (create the admin account and the
   organisation you chose as `THEHIVE_ORG_NAME`). See the vendor's
   "Perform the initial setup as an admin" guide (first login with TheHive's
   documentation defaults).
2. Create a service/organisation user for the platform (do not use the admin for
   automations).
3. Generate its API key via the TheHive UI (user settings) or `POST
   /api/v1/user/{userId}/key/renew`; retrieve it with `GET
   /api/v1/user/{userId}/key` (it is a bearer token).
4. Copy that key into `.env` as `THEHIVE_API_KEY`.

The API key is the same value on both sides: the TheHive instance's user and the
platform's `THEHIVE_API_KEY`. It never appears in committed files, logs, or
container environment dumps (the API-side client never logs secrets).

## Export behavior (deterministic, read-only outward)

`POST /api/v1/incidents/{incident_id}/thehive` (n8n-token protected):

- builds a safe case export from the incident's alert IDs, sanitized IOC
  summaries, assignment, notes, and timeline summary
  (`app/src/soc_triage/thehive/export.py`);
- **never** forwards `full_log`, secrets, credentials, or tokens;
- maps severity `SEV1..SEV4` to TheHive `4..1`, TLP/PAP to `2/2` (lab defaults);
- creates the case via `POST /api/v1/case`, then one observable per allowed IOC
  type (ip/domain/hostname/url/hash/mail only);
- repeated exports of the same incident return the existing case id
  (`duplicate: true`) instead of creating a second case;
- records an `incident.thehive_exported` audit row with the case id.

## Security constraints

- Defensive-only: the platform only ever **creates** cases/observables in
  TheHive; nothing deletes, closes, or otherwise modifies cases, and nothing
  reads TheHive back into the triage decision path.
- CE only, `soc-core` only, no host ports, `no-new-privileges:true`, `cap_drop: ALL`
  on every profile service, pinned images only.
- TheHive never serves as the `triage-api` database: **SQLite remains the default
  `TRIAGE_DB_URL`**, and the TheHive profile changes nothing about triage-api
  persistence.
- No production claims, no offensive capability, no AI/LLM in the decision path.

## Known status & cleanup

- Live validation is **operator-side**: start the profile once with a real
  Docker host, complete the CE first login, create the service user/API key,
  point `THEHIVE_URL`/`THEHIVE_API_KEY` at it, and exercise one export. Until
  then the profile is static/test-validated only, and **no live TheHive CE run
  is claimed anywhere in this repository**.
- Tear down/cleanup (removes the containers **and the lab data volumes**):

  ```bash
  docker compose --profile thehive down
  docker compose --profile thehive down -v
  ```

- Case data must follow SECURITY.md §5: synthetic lab data only, never real
  IOCs, customer data, or credentials (the export path already refuses
  `full_log`).
