import type { Finding, Rule } from "../types.js";

type SecretPattern = {
  id: string;
  title: string;
  regex: RegExp;
  severity: Finding["severity"];
  suggestion: string;
};

const patterns: SecretPattern[] = [
  {
    id: "SECRET-GITHUB-001",
    title: "Possible GitHub token",
    regex: /\bgh[pousr]_[A-Za-z0-9_-]{20,}\b/g,
    severity: "high",
    suggestion: "Remove the token from source control and rotate it."
  },
  {
    id: "SECRET-AWS-001",
    title: "Possible AWS access key",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: "high",
    suggestion: "Remove the credential from source control and rotate it."
  },
  {
    id: "SECRET-AWS-002",
    title: "Possible AWS secret access key",
    regex: /\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"][A-Za-z0-9/+=]{30,}['"]/g,
    severity: "critical",
    suggestion: "Remove the credential and rotate it immediately."
  },
  {
    id: "SECRET-PRIVATE-001",
    title: "Private key detected",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    severity: "critical",
    suggestion: "Remove the private key from source control and revoke or rotate it."
  },
  {
    id: "SECRET-SLACK-001",
    title: "Possible Slack token",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
    severity: "high",
    suggestion: "Remove the token and rotate it in Slack."
  },
  {
    id: "SECRET-NPM-001",
    title: "Possible npm token",
    regex: /\bnpm_[A-Za-z0-9]{20,}\b/g,
    severity: "high",
    suggestion: "Remove the token and rotate it in npm."
  },
  {
    id: "SECRET-JWT-001",
    title: "Possible JWT",
    regex: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    severity: "medium",
    suggestion: "Do not commit live authentication tokens. Rotate the token if it is valid."
  },
  {
    id: "SECRET-DATABASE-001",
    title: "Database connection string with credentials",
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s'"<>]+:[^\s'"<>]+@/gi,
    severity: "high",
    suggestion: "Move database credentials to environment variables or a secret manager."
  },
  {
    id: "SECRET-GENERIC-001",
    title: "Possible hardcoded secret",
    regex: /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-/+=]{20,}['"]/gi,
    severity: "medium",
    suggestion: "Move secrets to environment variables or a secret manager."
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
        findings.push({
          ruleId: pattern.id,
          severity: pattern.severity,
          title: pattern.title,
          message: "A value matching a known credential or secret pattern was found.",
          suggestion: pattern.suggestion,
          file,
          line: before.split("\n").length,
          column: (match.index ?? 0) - before.lastIndexOf("\n")
        });
      }
    }
    return findings;
  }
}];
