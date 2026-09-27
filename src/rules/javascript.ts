import type { Finding, Rule } from "../types.js";

const extensions = [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"];

const rules: Rule[] = [
  rule("JS-EVAL-001", "Dynamic code execution", "high", /\beval\s*\(/g, "eval() executes strings as JavaScript.", "Avoid eval()."),
  rule("JS-FUNCTION-001", "Dynamic Function constructor", "high", /\bnew\s+Function\s*\(/g, "The Function constructor creates executable code from strings.", "Avoid dynamic code generation."),
  rule("JS-INNERHTML-001", "Potential unsafe HTML injection", "medium", /\.innerHTML\s*=/g, "innerHTML can introduce XSS when the value contains untrusted data.", "Prefer textContent or sanitize untrusted HTML."),
  rule("JS-INSERTADJ-001", "Potential unsafe DOM injection", "medium", /\.insertAdjacentHTML\s*\(/g, "insertAdjacentHTML parses a string as HTML.", "Prefer DOM APIs or sanitize untrusted HTML."),
  rule("JS-DOCUMENT-WRITE-001", "Unsafe document.write", "medium", /\bdocument\.write(?:ln)?\s*\(/g, "document.write injects HTML into the document.", "Use DOM APIs instead."),
  rule("JS-EXEC-001", "Shell command execution", "high", /\bexec(?:Sync)?\s*\(/g, "Shell execution can become command injection when command strings contain untrusted input.", "Prefer spawn with an argument array and validate external input."),
  rule("JS-CHILD-SHELL-001", "Shell mode enabled for child process", "high", /\bshell\s*:\s*true\b/g, "shell: true increases command-injection risk.", "Avoid shell mode unless required and input is strictly controlled."),
  rule("JS-DANGEROUS-HTML-001", "Potential unsafe React HTML injection", "medium", /dangerouslySetInnerHTML\s*=\s*\{/g, "dangerouslySetInnerHTML bypasses React's normal HTML escaping.", "Prefer normal JSX text or sanitize HTML."),
  rule("JS-SQL-CONCAT-001", "Potential SQL injection", "high", /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n;]*(?:\+|\$\{)[A-Za-z_$][\w$]*/gi, "SQL text appears to include a JavaScript value directly.", "Use parameterized queries or prepared statements."),
  rule("JS-INSECURE-RANDOM-001", "Insecure randomness", "low", /\bMath\.random\s*\(/g, "Math.random() is not suitable for security-sensitive values.", "Use crypto.randomUUID() or cryptographically secure random bytes."),
  rule("JS-TLS-001", "TLS certificate verification disabled", "high", /\brejectUnauthorized\s*:\s*false\b/g, "TLS certificate verification is disabled.", "Keep certificate verification enabled."),
  rule("JS-PROTOTYPE-001", "Potential prototype pollution", "medium", /(?:\[\s*['"]__proto__['"]\s*\]|\.\s*__proto__)\s*=/g, "Direct assignment to __proto__ can modify an object's prototype.", "Avoid __proto__ assignments."),
  rule("JS-SETTIMEOUT-001", "Dynamic code passed to timer", "medium", /\b(?:setTimeout|setInterval)\s*\(\s*['"]/g, "Passing a string to a timer evaluates it as code in browsers.", "Pass a function instead."),
  rule("JS-REDIRECT-001", "Potential open redirect", "medium", /\b(?:location(?:\.href|\.assign|\.replace)|window\.open)\s*\([^\n;]*(?:req|request|query|params|input|url)/gi, "A user-controlled URL may be used for navigation.", "Validate URLs against an allowlist before redirecting."),
  rule("JS-HTTP-001", "Unencrypted HTTP URL", "low", /['"]http:\/\/[^'"]+['"]/gi, "Plain HTTP does not provide transport encryption.", "Use HTTPS unless HTTP is explicitly required."),
  rule("JS-COOKIE-001", "Cookie without security attributes", "low", /document\.cookie\s*=\s*[^;\n]+/g, "Client cookies should use appropriate security attributes where applicable.", "Prefer server-set cookies with Secure, HttpOnly and SameSite where appropriate."),
  rule("JS-TLS-ENV-001", "TLS rejection disabled through environment", "high", /\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/g, "Node.js TLS certificate verification is disabled.", "Do not disable TLS verification."),
  rule("JS-HARDCODED-PASSWORD-001", "Possible hardcoded password", "medium", /\b(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]/gi, "A password-like value appears to be hardcoded.", "Load credentials from environment variables or a secret manager.")
];

function rule(
  id: string,
  title: string,
  severity: Finding["severity"],
  regex: RegExp,
  message: string,
  suggestion: string
): Rule {
  return {
    id,
    title,
    severity,
    extensions,
    scan({ file, content }) {
      return find(content, file, regex, {
        ruleId: id,
        severity,
        title,
        message,
        suggestion
      });
    }
  };
}

function find(content: string, file: string, regex: RegExp, base: Omit<Finding, "file" | "line" | "column">): Finding[] {
  return [...content.matchAll(regex)].map(match => {
    const index = match.index ?? 0;
    const before = content.slice(0, index);
    return {
      ...base,
      file,
      line: before.split("\n").length,
      column: index - before.lastIndexOf("\n")
    };
  });
}

export const javascriptRules = rules;
