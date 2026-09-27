#!/usr/bin/env node
import { resolve } from "node:path";
import { scanDirectory } from "./scanner.js";
import type { Finding, Severity } from "./types.js";

const args = process.argv.slice(2);
const command = args[0];

if (!command || command === "--help" || command === "-h") {
  printHelp();
  process.exit(command ? 0 : 1);
}

if (command !== "scan") {
  console.error(`Unknown command: ${command}`);
  process.exit(1);
}

const target = args[1] ?? ".";
const json = args.includes("--json");
const failOn = getOption("--fail-on") as Severity | undefined;

try {
  const root = resolve(target);
  const findings = await scanDirectory(root);

  if (json) {
    console.log(JSON.stringify({
      tool: "fishstick",
      version: "0.1.0",
      findings,
      summary: summarize(findings)
    }, null, 2));
  } else {
    printReport(root, findings);
  }

  if (process.env.GITHUB_ACTIONS === "true" && !json) {
    for (const finding of findings) {
      const level = "warning";
      console.log(`::${level} file=${finding.file},line=${finding.line},title=Fishstick ${finding.severity}: ${finding.ruleId}::${finding.message}`);
    }
  }

  if (failOn && findings.some(f => severityRank(f.severity) >= severityRank(failOn))) {
    process.exitCode = 1;
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}

function printReport(root: string, findings: Finding[]) {
  console.log("\nFishstick Security Scanner");
  console.log(`Scanning: ${root}\n`);

  if (findings.length === 0) {
    console.log("No findings.");
    return;
  }

  for (const finding of findings) {
    console.log(`${finding.severity.toUpperCase().padEnd(8)} ${finding.ruleId}`);
    console.log(`  ${finding.file}:${finding.line}`);
    console.log(`  ${finding.title} — ${finding.message}`);
    if (finding.suggestion) console.log(`  Fix: ${finding.suggestion}`);
    console.log();
  }

  const summary = summarize(findings);
  console.log(`${findings.length} finding(s): ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low`);
}

function summarize(findings: Finding[]) {
  return {
    critical: findings.filter(f => f.severity === "critical").length,
    high: findings.filter(f => f.severity === "high").length,
    medium: findings.filter(f => f.severity === "medium").length,
    low: findings.filter(f => f.severity === "low").length,
    info: findings.filter(f => f.severity === "info").length
  };
}

function getOption(name: string): string | undefined {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

function severityRank(severity: string): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[severity] ?? 0;
}

function printHelp() {
  console.log(`Fishstick — find security vulnerabilities and bugs

Usage:
  fishstick scan [path]
  fishstick scan [path] --json
  fishstick scan [path] --fail-on high

Options:
  --json             Output machine-readable JSON
  --fail-on <level>  Exit with code 1 at or above this severity
`);
}
