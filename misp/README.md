# misp/ — Self-Hosted Threat Intelligence (Optional)

MISP is an **optional** compose profile (`intel`, Phase 2). It provides self-hosted,
free, open-source threat-intel lookups (`/attributes/restSearch`) for the enrichment
chain. The platform runs fully without it. Design:
[ARCHITECTURE.md §7](../ARCHITECTURE.md#7-enrichment-subsystem).

**Status: scaffolded — compose fragments and seeding guide land in Phase 2.**

Planned contents:

- Compose fragment for the MISP stack (internal network only, no published ports by default).
- Seeding guide: how to enable public feeds and/or create clearly-labeled **synthetic**
  lab events (e.g., documentation-range IPs and benign-string hashes) for demos.
- Lookup-only API policy: this integration only **reads** attributes/events — it never
  publishes anything to MISP without explicit human action.

Data rules from [SECURITY.md §5](../SECURITY.md#5-data-handling--test-data-policy) apply
to any seeded events.
