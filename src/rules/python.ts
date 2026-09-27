import type { Finding, Rule } from "../types.js";

const extensions = [".py", ".pyw"];

const rules: Rule[] = [
  rule("PY-EVAL-001", "Dynamic code execution", "high", /\beval\s*\(/g, "eval() executes Python code from a string.", "Avoid eval() and parse data explicitly."),
  rule("PY-EXEC-001", "Dynamic code execution", "high", /\bexec\s*\(/g, "exec() executes Python code dynamically.", "Avoid exec() with untrusted input."),
  rule("PY-PICKLE-001", "Unsafe pickle deserialization", "high", /\bpickle\.loads?\s*\(/g, "pickle can execute arbitrary code when loading untrusted data.", "Use a safe data format such as JSON for untrusted input."),
  rule("PY-SUBPROCESS-001", "Shell command execution", "high", /\bsubprocess\.(?:run|call|Popen|check_call|check_output)\s*\(/g, "Subprocess execution can become command injection with untrusted input.", "Pass arguments as a list and avoid shell=True."),
  rule("PY-SHELL-001", "Shell mode enabled", "high", /\bshell\s*=\s*True\b/g, "shell=True makes command injection easier.", "Avoid shell=True and pass arguments directly."),
  rule("PY-YAML-001", "Unsafe YAML loading", "high", /\byaml\.load\s*\(/g, "Unsafe YAML loading can construct arbitrary Python objects.", "Use yaml.safe_load() for untrusted YAML."),
  rule("PY-TLS-001", "TLS verification disabled", "high", /\bverify\s*=\s*False\b/g, "TLS certificate verification is disabled.", "Keep TLS verification enabled."),
  rule("PY-SQL-001", "Potential SQL injection", "high", /\b(?:execute|executemany)\s*\([^\n;]*(?:%|\+|\.format\s*\(|f['"])/g, "SQL may be constructed using string formatting or concatenation.", "Use parameterized queries."),
  rule("PY-ASSERT-001", "Security-sensitive assert", "low", /\bassert\s+[^\n]+/g, "Assertions can be disabled with Python optimization flags.", "Do not use assert for authorization or input validation."),
  rule("PY-TEMPFILE-001", "Insecure temporary file creation", "medium", /\btempfile\.(?:mktemp|mktemp\s*)\(/g, "mktemp can introduce a race condition between creation and use.", "Use NamedTemporaryFile or TemporaryDirectory.")
];

function rule(id: string, title: string, severity: Finding["severity"], regex: RegExp, message: string, suggestion: string): Rule {
  return {
    id,
    title,
    severity,
    extensions,
    scan({ file, content }) {
      return [...content.matchAll(regex)].map(match => {
        const index = match.index ?? 0;
        const before = content.slice(0, index);
        return {
          ruleId: id,
          severity,
          title,
          message,
          suggestion,
          file,
          line: before.split("\n").length,
          column: index - before.lastIndexOf("\n")
        };
      });
    }
  };
}

export const pythonRules = rules;
