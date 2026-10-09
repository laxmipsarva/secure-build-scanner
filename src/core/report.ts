import { createRequire } from "node:module";
import { isAbsolute, join, relative, sep } from "node:path";
import { pathToFileURL } from "node:url";
import pc from "picocolors";
import type { Finding, Rule, ScanResult, Severity } from "./types.js";

const { version } = createRequire(import.meta.url)("../../package.json") as { version: string };

const severityColor: Record<Severity, (s: string) => string> = {
  critical: pc.bgRed,
  high: pc.red,
  medium: pc.yellow,
  low: pc.cyan,
  info: pc.gray,
};

export function formatText(result: ScanResult, options: { listFiles?: boolean } = {}): string {
  const lines: string[] = [];
  lines.push(
    pc.bold(`build-scanner: ${result.filesScanned} files scanned in ${result.durationMs}ms`),
  );

  if (options.listFiles) {
    for (const file of result.scannedFiles) lines.push(`  ${pc.dim(file)}`);
  }

  if (result.findings.length === 0) {
    lines.push(pc.green("No findings."));
    return lines.join("\n");
  }

  for (const f of result.findings) {
    const badge = severityColor[f.severity](` ${f.severity.toUpperCase()} `);
    lines.push("");
    lines.push(`${badge} ${pc.bold(f.category)} — ${f.message}`);
    lines.push(`  ${pc.dim(`${f.file}:${f.line}${f.column ? ":" + f.column : ""}`)}`);
    if (f.snippet) lines.push(`  ${pc.dim("│")} ${f.snippet}`);
    lines.push(`  ${pc.dim("fix:")} ${f.recommendation}`);
  }

  lines.push("");
  lines.push(pc.bold(summarize(result.findings)));
  return lines.join("\n");
}

function summarize(findings: Finding[]): string {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return `Total: ${findings.length} (critical: ${counts.critical}, high: ${counts.high}, medium: ${counts.medium}, low: ${counts.low}, info: ${counts.info})`;
}

export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

const sarifLevel: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

// GitHub Code Scanning buckets security-severity scores: >= 9.0 critical, 7.0-8.9 high,
// 4.0-6.9 medium, 0.1-3.9 low. Info findings get no score and show as plain notes.
const securitySeverity: Record<Severity, string | undefined> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "2.0",
  info: undefined,
};

const severityRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export interface SarifOptions {
  /** Directory that each finding's `file` is relative to. Defaults to `result.root`. */
  sourceRoot?: string;
  /** Directory artifact URIs are written relative to (e.g. the repo checkout). Defaults to `sourceRoot`. */
  baseDir?: string;
}

/**
 * Serializes a scan as SARIF 2.1.0 for GitHub Code Scanning and other SARIF consumers.
 * Files outside `baseDir` are written as absolute file:// URIs.
 */
export function formatSarif(result: ScanResult, rules: Rule[], options: SarifOptions = {}): string {
  const sourceRoot = options.sourceRoot ?? result.root;
  const baseDir = options.baseDir ?? sourceRoot;

  // security-severity lives on the rule, not the result, so a rule takes the score of its most
  // severe finding in this run; each result still carries its own level.
  const worst = new Map<string, Severity>();
  for (const f of result.findings) {
    const current = worst.get(f.ruleId);
    if (!current || severityRank[f.severity] < severityRank[current]) worst.set(f.ruleId, f.severity);
  }

  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  const toUri = (file: string): string => {
    const absolute = join(sourceRoot, file);
    const rel = relative(baseDir, absolute);
    if (rel.startsWith("..") || isAbsolute(rel)) return pathToFileURL(absolute).href;
    return rel.split(sep).join("/");
  };

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "build-scanner",
            version,
            informationUri: "https://github.com/laxmipsarva/secure-build-scanner",
            rules: rules.map((r) => {
              const score = securitySeverity[worst.get(r.id) ?? "info"];
              return {
                id: r.id,
                name: r.category,
                shortDescription: { text: r.category },
                fullDescription: { text: r.description },
                properties: {
                  tags: ["security"],
                  ...(score ? { "security-severity": score } : {}),
                },
              };
            }),
          },
        },
        columnKind: "utf16CodeUnits",
        results: result.findings.map((f) => ({
          ruleId: f.ruleId,
          ...(ruleIndex.has(f.ruleId) ? { ruleIndex: ruleIndex.get(f.ruleId) } : {}),
          level: sarifLevel[f.severity],
          message: { text: `${f.message} Fix: ${f.recommendation}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: toUri(f.file) },
                region: {
                  startLine: f.line,
                  ...(f.column ? { startColumn: f.column } : {}),
                  ...(f.snippet ? { snippet: { text: f.snippet } } : {}),
                },
              },
            },
          ],
          properties: { severity: f.severity },
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
