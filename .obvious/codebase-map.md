# Codebase map — laxmipsarva/secure-build-scanner

Depth-2 folder overview. Single CLI app; no sub-apps, no services.

| Path | Kind | Contents |
|---|---|---|
| `action.yml` | file | Composite GitHub Action: installs deps, builds, runs `dist/cli.js` against caller's checkout |
| `package.json` / `package-lock.json` / `tsconfig.json` | files | npm manifests (name `build-scanner`) and TS config (strict, ES2022, NodeNext) |
| `.github/workflows/test-action.yml` | file | CI: on push/PR to `main`, runs the composite action against `tests/fixtures` with `format: json` |
| `src/` | dir | TypeScript source; entrypoints `cli.ts` (commander CLI) and `index.ts` (programmatic API) |
| `src/core/` | dir | Scanner engine: `scanner.ts` (orchestration), `walker.ts` (file traversal), `helpers.ts`, `report.ts` (text/JSON formatters), `types.ts` |
| `src/rules/` | dir | 9 rule modules (sql-injection, nosql-injection, graphql, cors, csp, csrf, api-vulnerabilities, bot-handling, user-agent) + `index.ts` registry exporting `allRules` |
| `tests/unit/` | dir | vitest unit tests — 15 files, 121 tests |
| `tests/fixtures/` | dir | Vulnerable/safe sample files (`*.vuln.js`, `*.safe.js`, scenario dirs, Next.js shapes) used by tests, CI, and manual scans |
| `dist/` | dir (generated) | Build output; gitignored — regenerate with `npm run build` |
