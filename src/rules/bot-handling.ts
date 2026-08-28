import { makeFinding, matchAll } from "../core/helpers.js";
import type { Finding, Rule } from "../core/types.js";

// State-changing Express/Router routes (same shape as the CSRF rule's route detection).
const STATE_CHANGING_ROUTE = /\b(?:app|router)\.(post|put|patch|delete)\s*\(\s*(['"`])([^'"`]*)\2/g;

// Next.js App Router route handlers, e.g. `export async function POST(request) {...}`.
const APP_ROUTER_HANDLER =
  /\bexport\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\s*\(|\bexport\s+const\s+(POST|PUT|PATCH|DELETE)\s*=/g;

// Next.js Pages Router API routes branching on req.method.
const PAGES_API_METHOD_BRANCH =
  /\breq\.method\s*===?\s*(['"])(POST|PUT|PATCH|DELETE)\1|case\s*(['"])(POST|PUT|PATCH|DELETE)\3\s*:/g;

// Route/file paths that look like abuse-prone endpoints — auth, payment, or contact/subscribe
// forms are the ones bots (credential stuffing, spam, scraping) actually go after.
const SENSITIVE_PATH_KEYWORDS =
  /\b(?:auth|log-?in|sign-?in|sign-?up|register|password|forgot|reset|checkout|payment|contact|subscribe|newsletter)\b/i;

// Any mention of rate-limiting or a CAPTCHA/challenge anywhere in the file — a same-file
// heuristic, same idiom as the CSRF rule's MENTIONS_CSRF signal.
const MENTIONS_ANTI_ABUSE = /rate[-\s]?limit|slow-?down|recaptcha|hcaptcha|turnstile|captcha/i;

// err.stack (or an equivalent error object) sent straight back to the client — leaks internal
// file paths, line numbers, and library versions to anyone (including bots/scanners) probing
// the endpoint. Distinct from the SQL-injection rule's query-adjacent raw-DB-error check: this
// fires on any error-handling code path, not just ones near a query call.
const STACK_TRACE_LEAK =
  /\bres(?:ponse)?\.(?:status\s*\([^)]*\)\s*\.)?(?:json|send)\s*\([^)]*\b(?:err(?:or)?)\.stack\b[^)]*\)/g;

// robots.txt Disallow lines whose path looks sensitive.
const ROBOTS_DISALLOW_LINE = /^\s*Disallow\s*:\s*(\/\S*)/gim;
const SENSITIVE_DISALLOW_PATH = /\b(?:admin|internal|private|backup|\.env|config|secrets?)\b/i;

const rule: Rule = {
  id: "bot-handling",
  category: "Bot Handling",
  description:
    "Flags sensitive/abuse-prone routes (login, signup, password reset, checkout, contact forms) with no rate-limiting or CAPTCHA referenced, error handlers that leak err.stack to the client, and robots.txt entries that disclose sensitive paths.",
  extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".txt"],
  check(file): Finding[] {
    const findings: Finding[] = [];
    const normalizedPath = file.relativePath.replace(/\\/g, "/");
    const isRobotsTxt = /(^|\/)robots\.txt$/.test(normalizedPath);

    if (isRobotsTxt) {
      for (const match of matchAll(file.content, ROBOTS_DISALLOW_LINE)) {
        const disallowedPath = match[1] ?? "";
        if (!SENSITIVE_DISALLOW_PATH.test(disallowedPath)) continue;
        findings.push(
          makeFinding(
            rule,
            file,
            "low",
            `robots.txt discloses a sensitive-looking path ('${disallowedPath}') via Disallow — this points bots (including malicious ones, which routinely ignore robots.txt) straight at it instead of hiding it.`,
            match.index,
            "Don't rely on robots.txt to hide sensitive paths — it's public and well-behaved crawlers are the only ones who honor it. Protect the path with authentication and remove it from robots.txt.",
          ),
        );
      }
      return findings;
    }

    const hasAntiAbuseSignal = MENTIONS_ANTI_ABUSE.test(file.content);
    const isAppRouterHandler = /(^|\/)route\.(ts|tsx|js|jsx)$/.test(normalizedPath);
    const isPagesApiRoute = /(^|\/)pages\/api(\/|$)/.test(normalizedPath);
    const pathLooksSensitive = SENSITIVE_PATH_KEYWORDS.test(normalizedPath);

    if (!hasAntiAbuseSignal) {
      for (const match of matchAll(file.content, STATE_CHANGING_ROUTE)) {
        const method = (match[1] ?? "").toUpperCase();
        const routePath = match[3] ?? "";
        if (!SENSITIVE_PATH_KEYWORDS.test(routePath)) continue;
        findings.push(
          makeFinding(
            rule,
            file,
            "medium",
            `${method} route '${routePath}' looks like a sensitive/abuse-prone endpoint (auth, payment, or contact form) with no rate-limiting or CAPTCHA referenced in this file.`,
            match.index,
            "Apply rate-limiting middleware (e.g. express-rate-limit) and/or a CAPTCHA/challenge (e.g. reCAPTCHA, hCaptcha, Turnstile) to this route to slow down automated abuse.",
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
              "medium",
              `${method} route handler in '${file.relativePath}' looks like a sensitive/abuse-prone endpoint with no rate-limiting or CAPTCHA referenced in this file.`,
              match.index,
              "Apply rate-limiting (e.g. via middleware, or an edge/WAF rule) and/or a CAPTCHA/challenge to this route to slow down automated abuse.",
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
              "medium",
              `${method} handler in Pages API route '${file.relativePath}' looks like a sensitive/abuse-prone endpoint with no rate-limiting or CAPTCHA referenced in this file.`,
              match.index,
              "Apply rate-limiting (e.g. via middleware, or an edge/WAF rule) and/or a CAPTCHA/challenge to this route to slow down automated abuse.",
            ),
          );
        }
      }
    }

    for (const match of matchAll(file.content, STACK_TRACE_LEAK)) {
      findings.push(
        makeFinding(
          rule,
          file,
          "low",
          "Error stack trace is sent directly to the client — leaks internal file paths, line numbers, and library versions to anyone (including bots/scanners) probing this endpoint.",
          match.index,
          "Log the full error server-side and send a generic error message to the client instead of err.stack.",
        ),
      );
    }

    return findings;
  },
};

export default rule;
