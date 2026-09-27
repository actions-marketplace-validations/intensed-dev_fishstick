import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import type { Finding, Rule } from "./types.js";
import { secretRules } from "./rules/secrets.js";
import { javascriptRules } from "./rules/javascript.js";

const rules: Rule[] = [...secretRules, ...javascriptRules];

const ignoredDirectories = new Set([
  ".git", "node_modules", "dist", "build", "coverage", ".next", ".svelte-kit",
  ".godot", "target", "vendor"
]);

const ignoredExtensions = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".zip", ".gz",
  ".pdf", ".mp4", ".mov", ".woff", ".woff2", ".ttf", ".otf", ".lock"
]);

export async function scanDirectory(root: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  await walk(root, root, findings);
  return findings.sort((a, b) =>
    severityRank(b.severity) - severityRank(a.severity) ||
    a.file.localeCompare(b.file) ||
    a.line - b.line
  );
}

async function walk(root: string, directory: string, findings: Finding[]) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const fullPath = join(directory, entry.name);

    if (entry.isDirectory()) {
      await walk(root, fullPath, findings);
      continue;
    }

    const extension = extname(entry.name).toLowerCase();
    if (ignoredExtensions.has(extension)) continue;

    let content: string;
    try {
      content = await readFile(fullPath, "utf8");
    } catch {
      continue;
    }

    if (content.includes("\0")) continue;

    const file = relative(root, fullPath);
    for (const rule of rules) {
      if (rule.extensions.includes("*") || rule.extensions.includes(extension)) {
        findings.push(...rule.scan({ file, content }));
      }
    }
  }
}

function severityRank(severity: string): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[severity] ?? 0;
}
