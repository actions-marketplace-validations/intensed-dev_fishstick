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
