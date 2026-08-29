# Contributing Guide

Thanks for contributing to **SOC Alert Triage & Incident Response Automation**!
This is a defensive-security portfolio project — read [SECURITY.md](SECURITY.md) first;
its rules (especially the defensive-only charter and secrets policy) bind every
contribution.

---

## Ground Rules

1. **Defensive only.** PRs adding offensive capability (exploits, attack tooling,
   autonomous destructive response) will be closed without review.
2. **No secrets.** No real API keys, tokens, passwords, or personal/victim data — in
   code, tests, docs, sample data, or screenshots. Use `.env.example` placeholders and
   synthetic values (documentation IP ranges, `.example` domains).
3. **No fake claims.** Don't add wording implying production deployment, certified
   compliance, or enterprise usage. The project states honestly that it is a lab/portfolio.
4. **Stay in phase scope.** Check [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) — if your
   idea belongs to a later phase or a new design area, open an issue/discussion first.

## Getting Started

```bash
git clone https://github.com/SadashivPole/soc-alert-triage-automation.git
cd soc-alert-triage-automation
cp .env.example .env   # fill placeholders for local dev (never commit .env)
```

During the foundation stage there is nothing to run yet — Phase 1 introduces the
compose stack and test suite (see DEVELOPMENT_PLAN.md Phase 1 for the toolchain:
Python 3.11+, ruff, pytest).

## Workflow

- **Trunk-based:** short-lived branches off `main`, merged via PR.
- **Branch naming:** `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `sec/<topic>`.
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) —
  `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `sec:`.
  Keep commits atomic; write the "why" in the body.
- **PRs:** small and reviewable (< ~400 lines of diff where practical), with:
  - what changed & why (link the issue),
  - test evidence (unit/integration green; new behavior covered),
  - docs updated (ARCHITECTURE / README / config samples) when behavior changes.

## Code Style (Python — active from Phase 1)

- Formatting & linting: **ruff** (config in `pyproject.toml`); type hints required on
  public functions; **mypy** runs in strict mode on `scoring/` and `decisions/` (the
  correctness-critical packages) and default mode elsewhere.
- Naming: `snake_case`; constants `UPPER_SNAKE`; Pydantic models `PascalCase`.
- Docstrings on every module and public function (one line minimum).
- No `print()` — use `structlog` loggers with allow-listed fields.
- No blocking I/O in async paths; all external calls via injected clients.

## Design Changes

Anything that changes component responsibilities, data flow, schemas, scoring factors,
or security posture requires an **ARCHITECTURE.md update in the same PR** (new/edited
ADR row if it's a real decision). Docs are the contract; drift is treated as a bug.

## Testing Requirements

- Every bug fix ships with a regression test.
- New pipeline behavior ships with unit + integration coverage; scoring changes must
  update golden files explicitly (see DEVELOPMENT_PLAN.md testing gates).
- CI (from Phase 1) must be green: lint, tests, `scripts/check_secrets.sh`.
- Unit/integration tests must not touch real networks — use fakes for VirusTotal/MISP.

## Sample Data Rules

- Synthetic only: documentation IP ranges, `.example`/`.invalid` domains, benign-string
  hashes, obviously fake usernames/hostnames.
- New sample alerts go in `docs/sample-alerts/` with an entry in its README table,
  including the expected triage outcome.

## Reporting Security Issues

Do **not** report vulnerabilities via public issues or PRs — follow the private process
in [SECURITY.md §8](SECURITY.md#8-reporting-vulnerabilities).

## Code of Conduct (short form)

Be professional and kind. No harassment, discrimination, or hostile "help." Maintainers
may remove comments or contributors that make the project unpleasant. When in doubt,
critique code, not people.

---

**Review checklist quick reference** — every PR must pass the checklist in
[SECURITY.md §9](SECURITY.md#9-security-review-checklist-every-pr). Thank you for
helping build a realistic, safe, and honest SOC automation project!
