import { describe, expect, it } from "vitest";
import rule from "../../src/rules/bot-handling.js";
import { runRule } from "./test-utils.js";

describe("bot-handling rule", () => {
  it("flags an unprotected login route and a leaked error stack", () => {
    const findings = runRule(rule, "bot-handling.vuln.js");
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it("does not flag a login route behind rate-limiting or a generic error response", () => {
    const findings = runRule(rule, "bot-handling.safe.js");
    expect(findings).toHaveLength(0);
  });

  it("flags an unprotected Next.js App Router login handler", () => {
    const findings = runRule(rule, "bot-handling-nextjs/app-vuln/login/route.ts");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag an App Router login handler that references rate-limiting", () => {
    const findings = runRule(rule, "bot-handling-nextjs/app-safe/login/route.ts");
    expect(findings).toHaveLength(0);
  });

  it("flags an unprotected Next.js Pages API login handler", () => {
    const findings = runRule(rule, "bot-handling-nextjs/pages-api-vuln/pages/api/login.ts");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag a Pages API login handler that references rate-limiting", () => {
    const findings = runRule(rule, "bot-handling-nextjs/pages-api-safe/pages/api/login.ts");
    expect(findings).toHaveLength(0);
  });

  it("flags a robots.txt that discloses a sensitive path", () => {
    const findings = runRule(rule, "robots-txt-vuln/robots.txt");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does not flag a robots.txt with only non-sensitive paths", () => {
    const findings = runRule(rule, "robots-txt-safe/robots.txt");
    expect(findings).toHaveLength(0);
  });
});
