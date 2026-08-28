import type { Rule } from "../core/types.js";
import sqlInjection from "./sql-injection.js";
import nosqlInjection from "./nosql-injection.js";
import graphql from "./graphql.js";
import cors from "./cors.js";
import csp from "./csp.js";
import csrf from "./csrf.js";
import apiVulnerabilities from "./api-vulnerabilities.js";
import botHandling from "./bot-handling.js";
import userAgent from "./user-agent.js";

export const allRules: Rule[] = [
  sqlInjection,
  nosqlInjection,
  graphql,
  cors,
  csp,
  csrf,
  apiVulnerabilities,
  botHandling,
  userAgent,
];
