import type { Finding, Rule } from "../types.js";

const extensions = [".java"];

const rules: Rule[] = [
  rule("JAVA-RUNTIME-001", "Runtime command execution", "high", /\bRuntime\.getRuntime\(\)\.exec\s*\(/g, "Java is executing an operating-system command.", "Avoid shell execution with untrusted input."),
  rule("JAVA-PROCESS-001", "ProcessBuilder command execution", "high", /\bnew\s+ProcessBuilder\s*\(/g, "ProcessBuilder can execute operating-system commands.", "Validate command arguments and avoid passing untrusted strings."),
  rule("JAVA-DESERIALIZE-001", "Java object deserialization", "high", /\bObjectInputStream\s*\(/g, "Java native deserialization can execute dangerous gadget chains with untrusted data.", "Avoid Java native serialization for untrusted input."),
  rule("JAVA-REFLECTION-001", "Dynamic class loading", "medium", /\bClass\.forName\s*\(/g, "Dynamic class loading can become dangerous when the class name is user-controlled.", "Use an allowlist of permitted classes."),
  rule("JAVA-HTTP-001", "Unencrypted HTTP connection", "low", /['"]http:\/\/[^'"]+['"]/g, "Plain HTTP does not provide transport encryption.", "Use HTTPS unless HTTP is explicitly required."),
  rule("JAVA-TLS-001", "TLS certificate verification disabled", "high", /(?:TrustManager|HostnameVerifier|checkServerTrusted|verify\s*\([^)]*\)\s*\{\s*\})/g, "Custom TLS verification code may disable certificate validation.", "Use the platform's default certificate and hostname verification."),
  rule("JAVA-SQL-001", "Potential SQL injection", "high", /\b(?:Statement|createStatement)\b[^\n]*(?:execute|executeQuery|executeUpdate)\s*\([^\n]*(?:\+|String\.format)/g, "SQL appears to be built dynamically.", "Use PreparedStatement parameters."),
  rule("JAVA-LOG-001", "Potential secret exposure in logs", "medium", /\b(?:password|token|secret|apiKey|accessToken)\b[^\n]*(?:System\.out|LOGGER|logger)\b/gi, "A credential-like value may be written to logs.", "Never log credentials, access tokens, or private keys."),
  rule("FABRIC-COMMAND-001", "Potentially unsafe command input", "medium", /\.executes?\s*\([^\n]*(?:getString|StringArgumentType|getArgument|parse)/g, "A command argument appears to reach command execution logic.", "Validate and constrain command arguments before using them in sensitive operations."),
  rule("FABRIC-CHAT-001", "Untrusted chat text used as command", "high", /(?:sendCommand|executeCommand|dispatchCommand)\s*\([^\n]*(?:getString|getMessage|getContent)/g, "Player or chat-controlled text may be executed as a command.", "Never pass untrusted player text directly to command execution."),
  rule("FABRIC-NETWORK-001", "Unvalidated network packet data", "medium", /(?:PacketByteBuf|FriendlyByteBuf|RegistryByteBuf)[^\n]*(?:readString|readUtf|readInt|readLong)/g, "Network packet data is being read without an obvious validation boundary.", "Validate lengths, ranges, identifiers, and permissions before using packet data."),
  rule("FABRIC-LOGGER-001", "Potential sensitive data in mod logs", "low", /\b(?:LOGGER|log(?:ger)?)\.(?:info|warn|error|debug)\s*\([^\n]*(?:password|token|secret|accessToken|privateKey)/gi, "Sensitive-looking data may be written to a Minecraft mod log.", "Remove secrets and credentials from log messages."),
  rule("FABRIC-OP-001", "Server command without permission check", "medium", /(?:CommandRegistrationCallback|register\s*\()[\s\S]{0,500}(?:executes?|runs?)\s*\([^\n]*\{/g, "A server command handler was found without an obvious permission check.", "Require appropriate operator or permission checks for privileged commands.")
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

export const javaRules = rules;
