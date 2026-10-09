import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "../../src/core/scanner.js";
import { formatSarif } from "../../src/core/report.js";
import { allRules } from "../../src/rules/index.js";

const fixtures = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures");

describe("sarif report", () => {
  it("emits a SARIF 2.1.0 run with every rule and one result per finding", async () => {
    const result = await scan({ root: fixtures }, allRules);
    const sarif = JSON.parse(formatSarif(result, allRules));

    expect(sarif.version).toBe("2.1.0");
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("build-scanner");
    expect(run.tool.driver.rules.map((r: { id: string }) => r.id)).toEqual(allRules.map((r) => r.id));
    expect(run.results).toHaveLength(result.findings.length);
  });

  it("maps severity, rule index, and location for a finding", async () => {
    const result = await scan({ root: join(fixtures, "sql-injection.vuln.js") }, allRules);
    const sarif = JSON.parse(formatSarif(result, allRules, { sourceRoot: fixtures, baseDir: join(fixtures, "..") }));
    const run = sarif.runs[0];
    const first = run.results[0];
    const finding = result.findings[0]!;

    expect(first.ruleId).toBe(finding.ruleId);
    expect(run.tool.driver.rules[first.ruleIndex].id).toBe(finding.ruleId);
    expect(first.level).toBe("error");
    expect(first.locations[0].physicalLocation.artifactLocation.uri).toBe("fixtures/sql-injection.vuln.js");
    expect(first.locations[0].physicalLocation.region.startLine).toBe(finding.line);

    const sqlRule = run.tool.driver.rules.find((r: { id: string }) => r.id === "sql-injection");
    expect(sqlRule.properties["security-severity"]).toBe("8.0");
  });

  it("writes files outside baseDir as absolute file URIs", async () => {
    const result = await scan({ root: join(fixtures, "sql-injection.vuln.js") }, allRules);
    const sarif = JSON.parse(formatSarif(result, allRules, { sourceRoot: fixtures, baseDir: join(fixtures, "csp-scenarios") }));
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toMatch(/^file:\/\/.*sql-injection\.vuln\.js$/);
  });
});
