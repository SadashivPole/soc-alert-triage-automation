# misp/ — Self-Hosted Threat Intelligence (Optional `intel` profile)

MISP is an **optional** compose profile (`intel`, **Phase 2.4 — implemented**).
It provides self-hosted, free, open-source threat-intel lookups
(`GET /attributes/restSearch`) for the enrichment chain. The platform runs fully
without it. Design: [ARCHITECTURE.md §7](../ARCHITECTURE.md#7-enrichment-subsystem)
and [§13](../ARCHITECTURE.md#13-docker--deployment-architecture).

**Status:** the compose profile, the deterministic synthetic seeding guide and
the read-only verification helper are implemented and statically validated
(compose structure, pinned images, internal-only networking, secret handling,
fixture safety). **Live MISP startup has not been exercised in this
repository's CI** — the development sandbox has no Docker daemon, so no live
lookup is claimed anywhere.

## What the profile adds

| Service | Image (pinned) | Purpose | Host ports |
| --- | --- | --- | --- |
| `misp-preflight` | `busybox:1.37.0` | one-shot secret guard: refuses to start the profile when a required `MISP_*` value is missing (no network, exits 0) | none |
| `misp-db` | `mariadb:10.11.19` | MISP database | none |
| `misp-redis` | `valkey/valkey:7.2.14` | cache / queues (password required) | none |
| `misp-core` | `ghcr.io/misp/misp-docker/misp-core:v2.5.46` | MISP application (FastCGI 9002) | none |
| `misp-nginx` | `ghcr.io/misp/misp-docker/misp-nginx:v2.5.46` | internal HTTP front end (8080) | none |

All five run **only** under `--profile intel`, only on the internal `soc-core`
network (`misp-preflight` has no network at all), and publish **no** host ports
(ARCHITECTURE.md §13). No default service gains a `depends_on` on them, so the
default stack and the zero-external fallback are unchanged. The four containers
`depends_on` the guard with `condition: service_completed_successfully`, so
nothing starts before the `.env` values have been validated.

```bash
docker compose --profile intel up -d      # optional; nothing by default
docker compose up -d                      # default stack — MISP never starts
```

## Lookup-only policy

- The integration **reads** attributes via `GET /attributes/restSearch` only.
  There is no create/update/publish/push code path in this repository, and
  `misp/verify-lookups.sh` is read-only as well.
- Seeding events is an explicit, documented **human** action
  ([`seeding.md`](seeding.md)); it is not automated here.
- The provider is **disabled by default**: both `MISP_URL` and `MISP_API_KEY`
  must be non-empty (disable-by-empty, ARCHITECTURE.md §14). Empty ⇒
  `enrichment_status: skipped` and zero external calls.
- Credentials live only in `.env` / the secret store; nothing is committed
  (SECURITY.md §2, §4). Compose interpolates the whole file before it filters
  inactive profiles, so a required-variable reference (`${VAR:?…}`) inside the
  MISP block would make even the default `docker compose up -d` fail. The
  `misp-preflight` one-shot guard provides the same fail-fast behaviour at
  profile start and names every missing variable, which also prevents MISP from
  silently booting with upstream defaults (`MYSQL_PASSWORD=example`,
  `REDIS_PASSWORD=redispassword`, `GPG_PASSPHRASE=passphrase`, generated admin
  credentials).

## Files

| File | Purpose |
| --- | --- |
| `fixtures/synthetic-events.json` | Two deterministic synthetic events (pinned UUIDs/timestamps) built only from documentation-range IPs and hashes of benign strings (SECURITY.md §5) |
| `seeding.md` | Deterministic seeding guide: `.env` variables, profile startup, operator-local UI access, exact seed values, verification, cleanup |
| `verify-lookups.sh` | Read-only smoke check: looks up every fixture value via `restSearch` and reports match counts/event ids/tags |
| `README.md` | This file |

Data rules from [SECURITY.md §5](../SECURITY.md#5-data-handling--test-data-policy)
apply to any seeded events: synthetic values only, never real IOCs or customer
data.
