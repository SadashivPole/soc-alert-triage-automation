# docs/specs/ — Phase Specifications

Specification documents for individual roadmap items, following the Spec Kit loop:

1. **Specify** — a phase/feature specification (`WHY`, MUST HAVE, MUST NOT HAVE,
   acceptance criteria).
2. **Plan** — small, independently testable implementation steps.
3. **Tasks** — ordered tasks with explicit acceptance criteria.
4. **Implement** — code lands per stage, gated and reviewable.

Rules for every file here:

- `DEVELOPMENT_PLAN.md` (phase roadmap + acceptance gates), `ARCHITECTURE.md` (system
  design source of truth), `SECURITY.md`, and `CONTRIBUTING.md` remain **authoritative**.
  A spec never overrides them and never invents architecture.
- Specs describe work that is already scoped by the roadmap; new design areas go through
  an issue/discussion first (CONTRIBUTING.md).
- A spec carries its acceptance criteria and its risk table; implementation PRs reference
  the spec and update ARCHITECTURE.md when behavior changes.

## Documents

- [phase-3.7-prometheus-observability.md](phase-3.7-prometheus-observability.md) —
  Phase 3.7 — Prometheus `/metrics` + optional Grafana profile.
