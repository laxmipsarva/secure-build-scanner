# secure-build-scanner

Modern web apps ship through build pipelines, bundlers, and CI/CD
systems fast enough that the most common, highest-impact vulnerability
classes — SQL/NoSQL injection, permissive CORS, weak CSP, missing CSRF
protection — routinely slip through because catching them requires someone
to actually read the source. build-scanner finds them automatically, in
seconds, before they reach a PR review or production:

- **Shift-left, not bolt-on.** Runs as a CLI locally or as a GitHub Action
  in CI, so findings surface before merge instead of during an incident.
- **Zero setup, zero infrastructure.** Pure static source scan — no sandbox,
  no live target, no API keys, no service to stand up. Point it at a folder
  and get a report in seconds.
- **CI-native output.** Human-readable text, JSON for tooling/dashboards,
  and a `--fail-on` severity gate so a pipeline can hard-fail on real risk
  without wiring up a full SAST platform.
- **Framework-aware, not just a regex sweep.** Dedicated rules for
  Express-style servers, Next.js (App Router, Pages API, Server Actions,
  `middleware.ts`), and Vite/CRA — see the coverage tables below for exactly
  what's recognized in each.
- **Honest about what it is.** A fast, heuristic first pass that flags the
  code patterns behind classic vulnerabilities — unparameterized queries,
  wildcard/reflected CORS, `unsafe-inline`/`unsafe-eval` CSP, unprotected
  state-changing routes — meant to complement, not replace, full SAST/DAST
  tooling and manual security review.

It flags these patterns:

- **SQL Injection** — string-concatenated or template-literal SQL queries,
  raw DB errors leaked to the client, and denylist-style SQLi filters
- **NoSQL Injection** — raw request objects passed into MongoDB-style
  queries (operator injection), and `$where` clauses built from dynamic
  strings (JS injection)
- **GraphQL** — introspection left enabled, missing query depth/complexity
  limiting, resolver arguments piped into `exec`/`eval`
- **CORS** — wildcard or reflected `Access-Control-Allow-Origin`, wildcard
  origin combined with credentials
- **CSP** — `unsafe-inline`/`unsafe-eval`, wildcard directive sources, CSP
  disabled entirely
- **CSRF** — state-changing routes with no CSRF protection referenced,
  cookies set with `SameSite=None`
- **API** — exposed Swagger/OpenAPI docs UIs, deprecated endpoints left
  mounted, mass assignment (`req.body` passed straight into
  `create`/`save`/`update`/`assign` calls), and unsanitized `req.query`/
  `req.params` spliced into outbound backend request URLs (server-side
  parameter pollution)

This is a heuristic, regex-based static scanner intended to catch common
mistakes quickly — it is not a substitute for a full SAST/DAST tool or a
manual security review, and it can produce false positives/negatives.

### Vite/CRA and Next.js coverage

Beyond Express-style server code, the CSP/CORS/CSRF rules also recognize:

- **Vite/CRA**: a `<meta http-equiv="Content-Security-Policy" content="...">`
  tag in `index.html` (attribute order doesn't matter).
- **Next.js CSP**: `next.config.js` `headers()` entries in the
  `{ key: 'Content-Security-Policy', value: "..." }` shape (literal or a
  variable), and a `middleware.ts` policy built into a variable and applied
  via `headers.set('Content-Security-Policy', cspVar)`.
- **Next.js CORS**: `headers.set('Access-Control-Allow-Origin', ...)` (dot-set,
  as used in `middleware.ts` and Route Handlers), object-literal headers
  passed to `NextResponse.json()`/`Response`, and the `next.config.js`
  `headers()` equivalent.
- **Next.js CSRF**: App Router Route Handlers (`export function POST(...)` /
  `export const POST = ...` in a file literally named `route.ts`) and Pages
  API routes (`req.method === 'POST'` / `switch` under `pages/api/`). Files
  containing the `"use server"` directive (Server Actions) are treated as
  already protected, since Next.js applies automatic Origin-header CSRF
  protection to them.

Known limitations: CSP/CORS values built through multi-step indirection
(`.join()`, `.replace()`, imports from another file) aren't resolved — only a
single `const`/`let`/`var` string or template-literal assignment in the same
file is. Generic `request.method === 'POST'` branching outside `pages/api/`
(e.g. in `middleware.ts`) isn't flagged, since that shape is too common in
unrelated auth/redirect logic to scope safely.

## Install

```bash
npm install
npm run build
```

## Usage

```bash
# Scan a directory
node dist/cli.js ./path/to/project

# Scan a single file
node dist/cli.js ./path/to/project/server.js

# JSON output (for CI / tooling)
node dist/cli.js ./path/to/project --format json

# Run only specific rules
node dist/cli.js ./path/to/project --rules sql-injection,csrf-vulnerabilities

# List available rules
node dist/cli.js rules

# Exit non-zero if a finding at or above a severity is present (for CI gating)
node dist/cli.js ./path/to/project --fail-on high
```

If you `npm link` (or install it globally), the same commands are available
via the `build-scanner` binary instead of `node dist/cli.js`.

## Input / Output reference

### CLI

| Input | Values | Output / behavior |
|---|---|---|
| `<path>` (positional, default `.`) | directory or file path | Scans that directory (recursively) or single file |
| `-f, --format <format>` | `text` (default) \| `json` | `text`: human-readable report on stdout. `json`: the full `ScanResult` object serialized to stdout |
| `-r, --rules <ids>` | comma-separated rule IDs | Only the listed rules run; an unknown id prints a warning to stderr and contributes no findings |
| `--fail-on <severity>` | `critical`\|`high`\|`medium`\|`low`\|`info` | Report is printed as usual; process exit code is `1` if any finding at or above that severity exists, `0` otherwise. An invalid value prints an error to stderr and exits `2` |
| `-l, --list-files` | flag | Text format only: appends the full list of scanned files to the report |
| `rules` (subcommand) | none | Prints `id`, `category`, `description` (tab-separated) for every registered rule, one per line — no scan is run |
| no flags at all | — | Scans `.`, runs every rule, prints the text report, exits `0` regardless of findings |

### GitHub Action

| Input | Default | Output / behavior |
|---|---|---|
| `path` | `.` | Directory or file scanned, relative to the caller repo checkout |
| `format` | `text` | `text` or `json` report written to the job log |
| `rules` | `''` (all rules) | Comma-separated rule IDs to run |
| `fail-on` | `''` (never fails) | Step fails (non-zero exit) if a finding at or above this severity is present |
| `list-files` | `false` | `true` appends the scanned-file list to the log (text format only) |

The action has no `outputs:` — results are only available via the job log and the step's exit code, not as a downstream-consumable output variable.

### Programmatic API

| Function | Input | Output |
|---|---|---|
| `scan(options, rules)` | `options: { root, include?, exclude?, ruleIds? }`, `rules: Rule[]` (e.g. `allRules`) | `Promise<ScanResult>` — `{ root, filesScanned, scannedFiles, findings, durationMs }` |
| `formatText(result, opts?)` | `result: ScanResult`, `opts?: { listFiles?: boolean }` | `string` — human-readable report |
| `formatJson(result)` | `result: ScanResult` | `string` — JSON-serialized `ScanResult` |
| `allRules` | — | `Rule[]` — every registered rule |

Each `Finding` in `ScanResult.findings` is `{ ruleId, category, severity, message, file, line, column?, snippet, recommendation }` (see `src/core/types.ts`).

## Use as a GitHub Action

Any other repo can run the scanner in CI without installing anything itself:

```yaml
- uses: actions/checkout@v7
- uses: laxmipsarva/secure-build-scanner@v1
  with:
    path: .
    fail-on: high
```

Inputs mirror the CLI flags above: `path` (default `.`), `format` (`text` |
`json`, default `text`), `rules` (comma-separated rule IDs), `fail-on`
(`critical|high|medium|low|info`), and `list-files` (`true`/`false`). The
action installs its own dependencies and builds from source on each run, so
the job fails exactly the way a local `--fail-on` run would.

`@v1` tracks the latest `v1.x` release (currently `v1.0`); pin to an exact
tag (e.g. `@v1.0`) or a commit SHA if you want the version fixed.

## Development

```bash
npm test        # run the test suite (vitest)
npm run typecheck
```

## License

MIT — see [LICENSE](LICENSE).
