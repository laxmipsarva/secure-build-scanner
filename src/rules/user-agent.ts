import { makeFinding, matchAll } from "../core/helpers.js";
import type { Finding, Rule } from "../core/types.js";

// A User-Agent read compared against a bot/service-like string, followed within a short
// window by a keyword indicating a security control is being skipped/bypassed as a result.
// User-Agent is fully attacker-controlled and trivially spoofed, so branching a security
// decision on it (CWE-807) provides no real protection — anyone can set their UA to
// "internal-service" or "Googlebot" and get the same treatment as the real thing.
const UA_TRUST_BYPASS =
  /\b(?:user-?agent|userAgent)\b[\s\S]{0,120}?(?:===|==|\.includes\(|\.indexOf\(|\.startsWith\()\s*['"][^'"]*(?:bot|crawler|spider|googlebot|bingbot|internal|trusted|monitor|healthcheck|service)[^'"]*['"][\s\S]{0,250}?\b(?:skip|bypass|allow|next\(\)|isTrusted\s*=\s*true|noAuth|disableAuth|rateLimit\w*\s*=\s*false)\b/gi;

// State-changing Express/Router routes (same shape as the CSRF/Bot Handling rules' route
// detection).
const STATE_CHANGING_ROUTE = /\b(?:app|router)\.(post|put|patch|delete)\s*\(\s*(['"`])([^'"`]*)\2/g;

// Next.js App Router route handlers, e.g. `export async function POST(request) {...}`.
const APP_ROUTER_HANDLER =
  /\bexport\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\s*\(|\bexport\s+const\s+(POST|PUT|PATCH|DELETE)\s*=/g;

// Next.js Pages Router API routes branching on req.method.
const PAGES_API_METHOD_BRANCH =
  /\breq\.method\s*===?\s*(['"])(POST|PUT|PATCH|DELETE)\1|case\s*(['"])(POST|PUT|PATCH|DELETE)\3\s*:/g;

// Route/file paths that look like abuse-prone endpoints — same list Bot Handling uses.
const SENSITIVE_PATH_KEYWORDS =
  /\b(?:auth|log-?in|sign-?in|sign-?up|register|password|forgot|reset|checkout|payment|contact|subscribe|newsletter)\b/i;

// Any mention of the User-Agent header anywhere in the file — used as a same-file signal
// that some form of UA-based filtering exists, however weak.
const MENTIONS_USER_AGENT = /user-?agent|navigator\.userAgent/i;

const rule: Rule = {
  id: "user-agent-security",
  category: "User-Agent Security",
  description:
    "Flags security decisions (auth/rate-limit bypass) based on a spoofable User-Agent header value (CWE-807), and sensitive routes with no User-Agent-based filtering of known malicious scanner/bot signatures at all.",
  extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  check(file): Finding[] {
    const findings: Finding[] = [];

    for (const match of matchAll(file.content, UA_TRUST_BYPASS)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "high",
          "A security decision (auth/rate-limit bypass) is based on the User-Agent header value — User-Agent is fully attacker-controlled and trivially spoofed, so this check provides no real protection (CWE-807).",
          match.index,
          "Authenticate/authorize via a verified mechanism (API key, mTLS, signed token) instead of a spoofable header like User-Agent.",
        ),
      );
    }

    if (!MENTIONS_USER_AGENT.test(file.content)) {
      const normalizedPath = file.relativePath.replace(/\\/g, "/");
      const isAppRouterHandler = /(^|\/)route\.(ts|tsx|js|jsx)$/.test(normalizedPath);
      const isPagesApiRoute = /(^|\/)pages\/api(\/|$)/.test(normalizedPath);
      const pathLooksSensitive = SENSITIVE_PATH_KEYWORDS.test(normalizedPath);

      for (const match of matchAll(file.content, STATE_CHANGING_ROUTE)) {
        const method = (match[1] ?? "").toUpperCase();
        const routePath = match[3] ?? "";
        if (!SENSITIVE_PATH_KEYWORDS.test(routePath)) continue;
        findings.push(
          makeFinding(
            rule,
            file,
            "low",
            `${method} route '${routePath}' has no User-Agent-based filtering of known malicious scanner/bot signatures (sqlmap, nikto, nmap, masscan, curl/python-requests scripts) at all.`,
            match.index,
            "Consider rejecting requests whose User-Agent matches known attack-tool signatures as defense-in-depth — this is a weak, easily-spoofed control that should supplement, not replace, rate-limiting/CAPTCHA and WAF/edge-level filtering.",
          ),
        );
      }

      if (isAppRouterHandler && pathLooksSensitive) {
        for (const match of matchAll(file.content, APP_ROUTER_HANDLER)) {
          const method = (match[1] ?? match[2] ?? "").toUpperCase();
          findings.push(
            makeFinding(
              rule,
              file,
              "low",
              `${method} route handler in '${file.relativePath}' has no User-Agent-based filtering of known malicious scanner/bot signatures at all.`,
              match.index,
              "Consider rejecting requests whose User-Agent matches known attack-tool signatures as defense-in-depth — this is a weak, easily-spoofed control that should supplement, not replace, rate-limiting/CAPTCHA and WAF/edge-level filtering.",
            ),
          );
        }
      }

      if (isPagesApiRoute && pathLooksSensitive) {
        for (const match of matchAll(file.content, PAGES_API_METHOD_BRANCH)) {
          const method = (match[2] ?? match[4] ?? "").toUpperCase();
          findings.push(
            makeFinding(
              rule,
              file,
              "low",
              `${method} handler in Pages API route '${file.relativePath}' has no User-Agent-based filtering of known malicious scanner/bot signatures at all.`,
              match.index,
              "Consider rejecting requests whose User-Agent matches known attack-tool signatures as defense-in-depth — this is a weak, easily-spoofed control that should supplement, not replace, rate-limiting/CAPTCHA and WAF/edge-level filtering.",
            ),
          );
        }
      }
    }

    return findings;
  },
};

export default rule;
