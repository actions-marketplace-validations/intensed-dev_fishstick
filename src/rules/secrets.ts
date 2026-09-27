import type { Finding, Rule } from "../types.js";

const patterns: Array<{ id: string; title: string; regex: RegExp; suggestion: string }> = [
  {
    id: "SECRET-GITHUB-001",
    title: "Possible GitHub token",
    regex: /\bgh[pousr]_[A-Za-z0-9_\-]{20,}\b/g,
    suggestion: "Remove the token from source control and rotate it."
  },
  {
    id: "SECRET-AWS-001",
    title: "Possible AWS access key",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    suggestion: "Remove the credential from source control and rotate it."
  },
  {
    id: "SECRET-PRIVATE-001",
    title: "Private key detected",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    suggestion: "Remove the private key from source control and rotate or revoke it."
  }
];

export const secretRules: Rule[] = [{
  id: "SECRET",
  title: "Secret detection",
  severity: "high",
  extensions: ["*"],
  scan({ file, content }) {
    const findings: Finding[] = [];
    for (const pattern of patterns) {
      for (const match of content.matchAll(pattern.regex)) {
        const before = content.slice(0, match.index ?? 0);
        const line = before.split("\n").length;
        const column = (match.index ?? 0) - before.lastIndexOf("\n");
        findings.push({
          ruleId: pattern.id,
          severity: "high",
          title: pattern.title,
          message: `A value matching a known credential pattern was found.`,
          suggestion: pattern.suggestion,
          file,
          line,
          column
        });
      }
    }
    return findings;
  }
}];
