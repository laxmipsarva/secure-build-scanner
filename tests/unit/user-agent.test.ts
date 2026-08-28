import { describe, expect, it } from "vitest";
import rule from "../../src/rules/user-agent.js";
import { runRule } from "./test-utils.js";

describe("user-agent-security rule", () => {
  it("flags a security decision based on a spoofable User-Agent value", () => {
    const findings = runRule(rule, "user-agent.vuln.js");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag User-Agent used only for bad-bot signature blocking", () => {
    const findings = runRule(rule, "user-agent.safe.js");
    expect(findings).toHaveLength(0);
  });

  it("flags a sensitive route with no User-Agent-based bad-bot filtering", () => {
    const findings = runRule(rule, "user-agent-nextjs/app-vuln/login/route.ts");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag a sensitive route that references User-Agent filtering", () => {
    const findings = runRule(rule, "user-agent-nextjs/app-safe/login/route.ts");
    expect(findings).toHaveLength(0);
  });
});
