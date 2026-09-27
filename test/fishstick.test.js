import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";

test("Fishstick can scan itself", async () => {
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["dist/cli.js", "scan", ".", "--json"], {
      stdio: ["ignore", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", code => resolve({ code, stdout, stderr }));
  });

  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.tool, "fishstick");
  assert.ok(Array.isArray(report.findings));
});
