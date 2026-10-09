---
name: local-dev
description: How to set up, run, and verify laxmipsarva/secure-build-scanner locally (no services required)
---

# local-dev — laxmipsarva/secure-build-scanner

Recorded from the Autobuild onboarding run, 2026-10-09. This repo is a pure
static-analysis CLI: there is no database, server, queue, or external service,
and no env vars or secrets are needed. "Local dev healthy" = deps installed,
build + typecheck clean, tests green, CLI runs end-to-end.

## Setup steps

1. **Install** — `npm ci` (npm is canonical; `package-lock.json` is the lockfile
   of record, and `action.yml` uses `npm ci`). A stray `bun.lock` from a
   bootstrap install was removed; never commit it. First `npm ci` attempt hit
   EACCES because the bootstrap `node_modules/` was root-owned — fixed with
   `sudo rm -rf node_modules` before reinstalling.
2. **Build** — `npm run build` (`tsc` → `dist/`). Required before running
   `node dist/cli.js`; `npm run dev` uses tsx and skips the build.
3. **Typecheck** — `npm run typecheck`.

## Verify (primary flows)

All commands from repo root; expected results from the onboarding run:

| Flow | Expected |
|---|---|
| `node dist/cli.js rules` | 9 rules listed, exit 0 |
| `node dist/cli.js tests/fixtures/sql-injection.vuln.js` | text report, 2 HIGH SQL-injection findings, exit 0 |
| `node dist/cli.js tests/fixtures/sql-injection.vuln.js --fail-on high` | exit 1 (CI gate) |
| `node dist/cli.js tests/fixtures/sql-injection.safe.js --fail-on high` | "No findings.", exit 0 |
| `node dist/cli.js tests/fixtures --format json` | valid `ScanResult` JSON, 108 files, 120 findings |
| `npm test` | 121/121 tests pass (15 files) |

## Validation Summary (2026-10-09)

- `npm ci`: pass (69 packages, after removing root-owned `node_modules/`)
- `npm run build` (tsc): pass, no errors
- `npm run typecheck`: pass, no errors
- `npm test` (vitest): pass — 121/121 in 15 files (~1s)
- CLI `rules` subcommand: pass — 9 rules, exit 0
- CLI scan of vulnerable fixture: pass — 2 HIGH findings, exit 0
- CLI `--fail-on high` gate: pass — exit 1 on vulnerable, exit 0 on safe
- CLI JSON scan of all fixtures: pass — 108 files scanned, 120 findings

Evidence captured in `.obvious-install/evidence/` (not committed): `test-run.log`,
`cli-run.log`.

## Gotchas

- No lint script exists in `package.json` (typecheck + tests are the quality gates).
- Without `--fail-on`, the CLI always exits 0 even with critical findings — CI
  gating is opt-in via that flag.
- `dist/` is gitignored; a clean checkout must build before running the compiled CLI.
