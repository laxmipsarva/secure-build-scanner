import { readFile, stat } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import fg from "fast-glob";
import type { SourceFile } from "./types.js";

const DEFAULT_INCLUDE = [
  "**/*.js",
  "**/*.jsx",
  "**/*.ts",
  "**/*.tsx",
  "**/*.mjs",
  "**/*.cjs",
  "**/*.graphql",
  "**/*.gql",
  "**/*.json",
  "**/*.html",
  "**/robots.txt",
];

const DEFAULT_EXCLUDE = [
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/.git/**",
  "**/coverage/**",
  "**/*.min.js",
];

async function readSourceFile(path: string, relativeTo: string): Promise<SourceFile | undefined> {
  let content: string;
  try {
    content = await readFile(path, "utf8");
  } catch {
    return undefined;
  }
  return {
    path,
    relativePath: relative(relativeTo, path),
    content,
    lines: content.split(/\r?\n/),
  };
}

export async function collectSourceFiles(
  root: string,
  include: string[] = DEFAULT_INCLUDE,
  exclude: string[] = DEFAULT_EXCLUDE,
): Promise<SourceFile[]> {
  const absoluteRoot = resolve(root);
  const rootStat = await stat(absoluteRoot);

  if (rootStat.isFile()) {
    const file = await readSourceFile(absoluteRoot, dirname(absoluteRoot));
    return file ? [file] : [];
  }

  const paths = await fg(include, {
    cwd: absoluteRoot,
    ignore: exclude,
    absolute: true,
    dot: false,
    onlyFiles: true,
  });

  const files: SourceFile[] = [];
  for (const path of paths) {
    const file = await readSourceFile(path, absoluteRoot);
    if (file) files.push(file);
  }
  return files;
}
