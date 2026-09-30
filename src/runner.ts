/**
 * Conformance vector runner.
 * Usage: node --input-type=module < src/runner.ts
 * Or:    node src/runner.ts
 */

import { readFileSync, readdirSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  opCanonicalize,
  opNarrows,
  opSatisfies,
  opVerifyWrit,
  opVerifyChain,
  opVerifyCall,
  opVerifyTally,
  opVerifyRevoke,
} from "./ops.ts";

const VECTORS_DIR = new URL("../conformance/vectors", import.meta.url).pathname;

interface Vector {
  name: string;
  op: string;
  input: Record<string, unknown>;
  expect: "accept" | "reject";
  reason?: string;
  now?: number;
}

function runVector(v: Vector): { pass: boolean; got: string; expected: string } {
  const { op, input, expect, reason, now } = v;
  let result: { verdict: string; reason?: string };

  try {
    switch (op) {
      case "canonicalize":   result = opCanonicalize(input); break;
      case "narrows":        result = opNarrows(input); break;
      case "satisfies":      result = opSatisfies(input); break;
      case "verify_writ":    result = opVerifyWrit(input); break;
      case "verify_chain":   result = opVerifyChain(input, now); break;
      case "verify_call":    result = opVerifyCall(input, now); break;
      case "verify_tally":   result = opVerifyTally(input); break;
      case "verify_revoke":  result = opVerifyRevoke(input); break;
      default:
        result = { verdict: "skip", reason: `unknown op: ${op}` };
    }
  } catch (e) {
    result = { verdict: "error", reason: String(e) };
  }

  const expectedStr = expect === "reject" ? `reject(${reason ?? "?"})` : "accept";
  const gotStr =
    result.verdict === "accept"
      ? "accept"
      : result.verdict === "reject"
        ? `reject(${result.reason ?? "?"})`
        : `${result.verdict}(${result.reason ?? ""})`;

  let pass = false;
  if (expect === "accept") {
    pass = result.verdict === "accept";
  } else {
    pass = result.verdict === "reject" && result.reason === reason;
  }

  return { pass, got: gotStr, expected: expectedStr };
}

function main(): void {
  const files = readdirSync(VECTORS_DIR).filter((f) => f.endsWith(".json")).sort();
  let passed = 0;
  let failed = 0;
  const lines: string[] = [];

  for (const file of files) {
    const path = join(VECTORS_DIR, file);
    let v: Vector;
    try {
      v = JSON.parse(readFileSync(path, "utf8")) as Vector;
    } catch (e) {
      console.error(`Failed to parse ${file}: ${e}`);
      continue;
    }

    const { pass, got, expected } = runVector(v);
    const status = pass ? "PASS" : "FAIL";
    const line = pass
      ? `${status} ${file}: ${v.name}`
      : `${status} ${file}: ${v.name}\n       expected: ${expected}\n       got:      ${got}`;
    lines.push(line);
    if (pass) passed++;
    else failed++;
  }

  const total = passed + failed;
  const summary = `\nTotal: ${total}  Passed: ${passed}  Failed: ${failed}\n`;
  lines.push(summary);

  const report = lines.join("\n");
  console.log(report);

  // write to reports/
  const outPath = process.env["REPORT_OUT"] ?? "reports/first-run.txt";
  mkdirSync("reports", { recursive: true });
  writeFileSync(outPath, report, "utf8");
  console.error(`\nReport written to ${outPath}`);
}

main();
