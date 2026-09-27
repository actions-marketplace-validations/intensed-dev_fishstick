import type { Finding, Rule } from "../types.js";

const rules: Rule[] = [
  {
    id: "JS-EVAL-001",
    title: "Dynamic code execution",
    severity: "high",
    extensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"],
    scan({ file, content }) {
      return find(content, file, /\beval\s*\(/g, {
        ruleId: "JS-EVAL-001",
        severity: "high",
        title: "Dynamic code execution",
        message: "eval() executes a string as JavaScript and can turn untrusted input into code execution.",
        suggestion: "Avoid eval(). Prefer explicit parsing or data structures."
      });
    }
  },
  {
    id: "JS-INNERHTML-001",
    title: "Potential unsafe HTML injection",
    severity: "medium",
    extensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"],
    scan({ file, content }) {
      return find(content, file, /\.innerHTML\s*=/g, {
        ruleId: "JS-INNERHTML-001",
        severity: "medium",
        title: "Potential unsafe HTML injection",
        message: "Assigning to innerHTML can introduce XSS when the value contains untrusted data.",
        suggestion: "Prefer textContent or sanitize untrusted HTML before inserting it."
      });
    }
  },
  {
    id: "JS-EXEC-001",
    title: "Shell command execution",
    severity: "high",
    extensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"],
    scan({ file, content }) {
      return find(content, file, /\bexec(?:Sync)?\s*\(/g, {
        ruleId: "JS-EXEC-001",
        severity: "high",
        title: "Shell command execution",
        message: "Shell execution can become command injection when command strings contain untrusted input.",
        suggestion: "Prefer spawn with an argument array and validate all external input."
      });
    }
  },
  {
    id: "JS-CHILD-SHELL-001",
    title: "Shell mode enabled for child process",
    severity: "high",
    extensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"],
    scan({ file, content }) {
      return find(content, file, /\bshell\s*:\s*true\b/g, {
        ruleId: "JS-CHILD-SHELL-001",
        severity: "high",
        title: "Shell mode enabled for child process",
        message: "Enabling shell mode increases command-injection risk when arguments contain untrusted input.",
        suggestion: "Avoid shell: true unless it is required and all input is strictly controlled."
      });
    }
  },
  {
    id: "JS-DANGEROUS-HTML-001",
    title: "Potential unsafe React HTML injection",
    severity: "medium",
    extensions: [".js", ".jsx", ".ts", ".tsx"],
    scan({ file, content }) {
      return find(content, file, /dangerouslySetInnerHTML\s*=\s*\{/g, {
        ruleId: "JS-DANGEROUS-HTML-001",
        severity: "medium",
        title: "Potential unsafe React HTML injection",
        message: "dangerouslySetInnerHTML bypasses React's normal HTML escaping.",
        suggestion: "Prefer normal JSX text or sanitize HTML with a trusted sanitizer."
      });
    }
  },
  {
    id: "JS-SQL-CONCAT-001",
    title: "Potential SQL injection",
    severity: "high",
    extensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"],
    scan({ file, content }) {
      return find(content, file, /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n;]*\+\s*[A-Za-z_$][\w$]*/gi, {
        ruleId: "JS-SQL-CONCAT-001",
        severity: "high",
        title: "Potential SQL injection",
        message: "SQL text appears to be constructed by concatenating a JavaScript value.",
        suggestion: "Use parameterized queries or prepared statements."
      });
    }
  },
  {
    id: "JS-INSECURE-RANDOM-001",
    title: "Insecure randomness",
    severity: "low",
    extensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"],
    scan({ file, content }) {
      return find(content, file, /\bMath\.random\s*\(/g, {
        ruleId: "JS-INSECURE-RANDOM-001",
        severity: "low",
        title: "Insecure randomness",
        message: "Math.random() is not suitable for security-sensitive tokens or secrets.",
        suggestion: "Use crypto.randomUUID() or cryptographically secure random bytes for security-sensitive values."
      });
    }
  },
  {
    id: "JS-TLS-001",
    title: "TLS certificate verification disabled",
    severity: "high",
    extensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"],
    scan({ file, content }) {
      return find(content, file, /\brejectUnauthorized\s*:\s*false\b/g, {
        ruleId: "JS-TLS-001",
        severity: "high",
        title: "TLS certificate verification disabled",
        message: "Disabling TLS certificate verification can allow man-in-the-middle attacks.",
        suggestion: "Keep certificate verification enabled in production."
      });
    }
  },
  {
    id: "JS-PROTOTYPE-001",
    title: "Potential prototype pollution",
    severity: "medium",
    extensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"],
    scan({ file, content }) {
      return find(content, file, /(?:\[\s*['"]__proto__['"]\s*\]|\.\s*__proto__)\s*=/g, {
        ruleId: "JS-PROTOTYPE-001",
        severity: "medium",
        title: "Potential prototype pollution",
        message: "Directly assigning to __proto__ can modify an object's prototype.",
        suggestion: "Avoid __proto__ assignments and use safe object construction patterns."
      });
    }
  },
  {
    id: "JS-HARDCODED-PASSWORD-001",
    title: "Possible hardcoded password",
    severity: "medium",
    extensions: [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json"],
    scan({ file, content }) {
      return find(content, file, /\b(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]/gi, {
        ruleId: "JS-HARDCODED-PASSWORD-001",
        severity: "medium",
        title: "Possible hardcoded password",
        message: "A password-like value appears to be hardcoded in source.",
        suggestion: "Load credentials from environment variables or a secret manager."
      });
    }
  }
];

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
