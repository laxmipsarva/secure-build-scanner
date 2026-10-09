# build-scanner

Most static scanners look for dangerous code that is present. build-scanner
also flags the protections that are **missing**: login, signup, and checkout
routes with no rate limiting or CAPTCHA, state-changing routes with no CSRF
defense, security decisions trusted to a spoofable User-Agent header, error
handlers that leak stack traces, and `robots.txt` files that point bots
straight at `/admin`. It covers the classic vulnerability classes too —
SQL/NoSQL injection, permissive CORS, weak CSP, GraphQL and API
misconfigurations — and finds them in seconds, before they reach a PR review
or production:

- **Missing-control checks, not just bad patterns.** The Bot Handling,
  User-Agent Security, and CSRF rules flag sensitive routes that lack a
  defense — the kind of gap pattern-matching SAST tools rarely report.
- **Framework-aware, not just a regex sweep.** Dedicated rules for
  Express-style servers, Next.js (App Router, Pages API, Server Actions,
  `middleware.ts`), and Vite/CRA — see the coverage tables below for exactly
  what's recognized in each.
- **Zero setup, zero infrastructure.** Pure static source scan — no sandbox,
  no live target, no API keys, no account, no ruleset to choose. Point it at
  a folder and get a report in seconds.
- **CI-native output.** Human-readable text, JSON for tooling/dashboards,
  SARIF for GitHub Code Scanning, and a `--fail-on` severity gate so a
  pipeline can hard-fail on real risk without wiring up a full SAST platform.
- **Honest about what it is.** A fast, heuristic first pass meant to run
  alongside, not replace, semantic SAST (CodeQL, Semgrep, Snyk Code), DAST,
  and manual security review.

It flags these missing controls:

- **Bot Handling** — sensitive/abuse-prone routes (login, signup, password
  reset, checkout, contact forms) with no rate-limiting or CAPTCHA
  referenced, error handlers that leak `err.stack` to the client, and
  `robots.txt` entries that disclose sensitive paths (e.g. `/admin`) via
  `Disallow`
- **User-Agent Security** — security decisions (auth/rate-limit bypass) based
  on a spoofable User-Agent header value (CWE-807), and sensitive routes with
  no User-Agent-based filtering of known malicious scanner/bot signatures at
  all
- **CSRF** — state-changing routes with no CSRF protection referenced,
  cookies set with `SameSite=None`

And these vulnerable patterns:

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
- **API** — exposed API documentation UIs, deprecated/legacy endpoints left
  mounted, mass-assignment sinks (raw `req.body` into create/update/assign),
  and unsanitized request values spliced into outbound backend request URLs
  (server-side parameter pollution)

This is a heuristic, regex-based static scanner intended to catch common
mistakes quickly — it is not a substitute for a full SAST/DAST tool or a
manual security review, and it can produce false positives/negatives.

### Vite/CRA and Next.js coverage

Beyond Express-style server code, the CSP/CORS/CSRF/Bot Handling rules also
recognize:

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
- **Next.js Bot Handling**: the same App Router Route Handler and Pages API
  detection as CSRF, filtered to routes whose path looks sensitive
  (login, signup, password reset, checkout, contact, etc.).
- **Next.js User-Agent Security**: the same App Router Route Handler and
  Pages API sensitive-route detection as Bot Handling, checked for the
  absence of any User-Agent-based filtering.

Known limitations: CSP/CORS values built through multi-step indirection
(`.join()`, `.replace()`, imports from another file) aren't resolved — only a
single `const`/`let`/`var` string or template-literal assignment in the same
file is. Generic `request.method === 'POST'` branching outside `pages/api/`
(e.g. in `middleware.ts`) isn't flagged, since that shape is too common in
unrelated auth/redirect logic to scope safely. Bot Handling's rate-limit/CAPTCHA
check is a same-file heuristic like CSRF's — rate-limiting applied globally in
a separate middleware-setup file rather than per-route isn't seen. User-Agent
Security's bad-bot-filtering check is the same kind of same-file heuristic, and
User-Agent filtering is itself a weak, easily-spoofed control — that finding is
defense-in-depth advice, not a fix on its own.

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

# SARIF output (for GitHub Code Scanning or any SARIF viewer)
node dist/cli.js ./path/to/project --format sarif > build-scanner.sarif

# Run only specific rules
node dist/cli.js ./path/to/project --rules sql-injection,csrf-vulnerabilities

# List available rules
node dist/cli.js rules

# Exit non-zero if a finding at or above a severity is present (for CI gating)
node dist/cli.js ./path/to/project --fail-on high
```

If you `npm link` (or install it globally), the same commands are available
via the `build-scanner` binary instead of `node dist/cli.js`.

## Example scan results

Running the scanner against a file with an interpolated SQL query:

```
$ build-scanner tests/fixtures/sql-injection.vuln.js

build-scanner: 1 files scanned in 9ms

 HIGH  SQL Injection — SQL query built from a template literal with interpolated values — likely SQL injection.
  sql-injection.vuln.js:2:19
  │ return db.query(`SELECT * FROM users WHERE id = ${userId}`);
  fix: Use a parameterized query / prepared statement (e.g. `db.query('... WHERE id = ?', [id])`) instead of interpolating values into the SQL string.

Total: 1 (critical: 0, high: 1, medium: 0, low: 0, info: 0)
```

`--format json` produces the same findings as a single serialized `ScanResult`
object instead (see the Programmatic API table below for its shape) — this is
the form to use when a downstream step or dashboard needs to parse results.

`--format sarif` writes a SARIF 2.1.0 log instead. File paths in it are
relative to the current directory, so run it from the repo root to have
GitHub Code Scanning map findings onto your source. Each finding's level is
`error` (critical/high), `warning` (medium), or `note` (low/info). Each rule
gets a `security-severity` score from its most severe finding in the run,
which GitHub uses to show it as Critical, High, Medium, or Low.

### Exit-code behavior

| Scenario | Exit code |
|---|---|
| Scan completes, `--fail-on` not passed | `0`, regardless of findings |
| Scan completes, no finding at/above `--fail-on` severity | `0` |
| Scan completes, a finding at/above `--fail-on` severity exists | `1` |
| Invalid `--fail-on` value | `2`, error printed to stderr, no scan runs |

Only `--fail-on` makes the process exit non-zero on findings — without it,
build-scanner reports and exits `0` even when it finds critical issues, so CI
gating is opt-in via that flag (or the Action's `fail-on` input).

## Input / Output reference

### CLI

| Input | Values | Output / behavior |
|---|---|---|
| `<path>` (positional, default `.`) | directory or file path | Scans that directory (recursively) or single file |
| `-f, --format <format>` | `text` (default) \| `json` \| `sarif` | `text`: human-readable report on stdout. `json`: the full `ScanResult` object serialized to stdout. `sarif`: a SARIF 2.1.0 log on stdout, with paths relative to the current directory |
| `-r, --rules <ids>` | comma-separated rule IDs | Only the listed rules run; an unknown id prints a warning to stderr and contributes no findings |
| `--fail-on <severity>` | `critical`\|`high`\|`medium`\|`low`\|`info` | Report is printed as usual; process exit code is `1` if any finding at or above that severity exists, `0` otherwise. An invalid value prints an error to stderr and exits `2` |
| `-l, --list-files` | flag | Text format only: appends the full list of scanned files to the report |
| `rules` (subcommand) | none | Prints `id`, `category`, `description` (tab-separated) for every registered rule, one per line — no scan is run |
| no flags at all | — | Scans `.`, runs every rule, prints the text report, exits `0` regardless of findings |

### GitHub Action

| Input | Default | Output / behavior |
|---|---|---|
| `path` | `.` | Directory or file scanned, relative to the caller repo checkout |
| `format` | `text` | `text` or `json` report written to the job log, or `sarif` written to `sarif-file` |
| `sarif-file` | `build-scanner.sarif` | Where the SARIF report is written when `format` is `sarif`, relative to the workspace |
| `upload-sarif` | `true` | When `format` is `sarif`, upload the report to GitHub Code Scanning (needs `security-events: write`) |
| `rules` | `''` (all rules) | Comma-separated rule IDs to run |
| `fail-on` | `''` (never fails) | Step fails (non-zero exit) if a finding at or above this severity is present |
| `list-files` | `false` | `true` appends the scanned-file list to the log (text format only) |

The action has one output, `sarif-file`: the path to the SARIF report, set only when `format` is `sarif`. Otherwise results are only available via the job log and the step's exit code.

### Programmatic API

| Function | Input | Output |
|---|---|---|
| `scan(options, rules)` | `options: { root, include?, exclude?, ruleIds? }`, `rules: Rule[]` (e.g. `allRules`) | `Promise<ScanResult>` — `{ root, filesScanned, scannedFiles, findings, durationMs }` |
| `formatText(result, opts?)` | `result: ScanResult`, `opts?: { listFiles?: boolean }` | `string` — human-readable report |
| `formatJson(result)` | `result: ScanResult` | `string` — JSON-serialized `ScanResult` |
| `formatSarif(result, rules, opts?)` | `result: ScanResult`, `rules: Rule[]`, `opts?: { sourceRoot?, baseDir? }` | `string` — SARIF 2.1.0 log; URIs are relative to `baseDir` (default: `sourceRoot`, which defaults to `result.root`) |
| `allRules` | — | `Rule[]` — every registered rule |

Each `Finding` in `ScanResult.findings` is `{ ruleId, category, severity, message, file, line, column?, snippet, recommendation }` (see `src/core/types.ts`).

## Use as a GitHub Action

Any other repo can run the scanner in CI without installing anything itself:

```yaml
name: Security scan

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v7

      - name: Secure Build Scanner
        uses: laxmipsarva/secure-build-scanner@v1.1.1
        with:
          path: .
          fail-on: high
```

To see findings in the repo's **Security → Code scanning** tab, next to
CodeQL's, use SARIF output. The action uploads the report for you:

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v7

      - name: Secure Build Scanner
        uses: laxmipsarva/secure-build-scanner@v1.1.1
        with:
          path: .
          format: sarif
          fail-on: high
```

With `fail-on` set, the report is still uploaded before the step fails, so
the alerts that tripped the gate show up in Code Scanning. Set
`upload-sarif: false` to only write the file (exposed as the `sarif-file`
output) and handle it yourself.

### Required permissions

With `text` or `json` output, the scan only reads the checked-out source, so
`contents: read` is sufficient. With `format: sarif` and the default
`upload-sarif: true`, the job also needs `security-events: write`. Private
repositories also need `actions: read` and GitHub Code Scanning enabled
(part of GitHub Advanced Security).

Inputs mirror the CLI flags above: `path` (default `.`), `format` (`text` |
`json`, default `text`), `rules` (comma-separated rule IDs), `fail-on`
(`critical|high|medium|low|info`), and `list-files` (`true`/`false`), plus
the action-only `sarif-file` and `upload-sarif`. Apart from the `sarif-file`
output, results are only available via the job log and the step's exit code
(see [Exit-code behavior](#exit-code-behavior) above).
The action installs its own dependencies and builds from source on each run,
so the job fails exactly the way a local `--fail-on` run would.

## Supported operating systems

The Action runs the scanner under Node.js via `actions/setup-node`, so it
works on any GitHub-hosted or self-hosted runner with a POSIX shell —
`ubuntu-*` and `macos-*` runners are supported and tested against
`ubuntu-latest` in this repo's own CI. `windows-*` runners are not currently
tested; the `bash`-scripted steps in `action.yml` require a `bash` shell to
be available (present by default via Git Bash on `windows-latest`, but
unverified here). The CLI itself (`node dist/cli.js`) is pure Node.js/`fs`
and has no OS-specific dependencies.

## Version and release policy

Releases are tagged on the `main` branch, which always contains the current
implementation. Point releases (`v1.1`, `v1.1.1`, ...) are tagged as work
lands; `package.json` is the source of truth for the current version number.
The current release is `v1.1.1`. A rolling major-version tag (e.g. `@v1`) that
automatically tracks the latest `v1.x` release is planned but not yet
published — until then, pin to an exact tag (as in the example above) or a
commit SHA rather than `main`, since `main` can change without notice.

## Development

```bash
npm test        # run the test suite (vitest)
npm run typecheck
```

## License

MIT — see [LICENSE](LICENSE).
