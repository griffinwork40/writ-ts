/**
 * Scenario driver: for each file in conformance/scenarios/, run steps against
 * a fresh executor and write out/<filename> with one answer per step.
 *
 * Usage: node src/scenario-driver.ts
 */

import { readFileSync, readdirSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { buildPrivKey } from "./sign-tally.ts";
import { objectIdentity } from "./sign-tally.ts";
import { Executor } from "./executor.ts";
import type { AppOutcome } from "./exec-types.ts";

const SCENARIOS_DIR = new URL("../conformance/scenarios", import.meta.url).pathname;
const OUT_DIR = new URL("../out", import.meta.url).pathname;

// ── Scenario types ────────────────────────────────────────────────────────────

interface AppScript {
  st: string;
  code?: string;
  res?: unknown;
  used?: Record<string, number>;
  rev?: number;
  hold?: boolean;
}

interface Step {
  do: string;
  now?: number;
  call?: Record<string, unknown>;
  revoke?: Record<string, unknown>;
  app?: AppScript;
  peer?: string;
  // finish
  signaled?: boolean;
}

interface Scenario {
  name: string;
  executor: {
    seed: string;
    accept: string[];
    peers?: Record<string, string[]>;
  };
  steps: Step[];
}

// ── Answer shapes (section 14.1) ──────────────────────────────────────────────

type Answer =
  | { error: string }
  | { tally: Record<string, unknown> }
  | { tally: Record<string, unknown>; res: unknown }
  | { inflight: true }
  | { tallies: Record<string, unknown>[] }
  | { resolved: number };

// ── Driver ────────────────────────────────────────────────────────────────────

async function runScenario(scenario: Scenario): Promise<Answer[]> {
  const { privKey, did } = buildPrivKey(scenario.executor.seed);
  const ex = new Executor(privKey, did, scenario.executor.accept, scenario.executor.peers);

  const answers: Answer[] = [];

  // Map from call identity to whether it was held (for finish step)
  const heldCallIdentities = new Map<string, string>(); // stepCallId -> callIdentity
  // Map scenario "call" object -> identity for finish steps
  const callObjToIdentity = new Map<string, string>(); // JSON key -> identity

  for (let i = 0; i < scenario.steps.length; i++) {
    const step = scenario.steps[i];

    try {
      if (step.do === "call") {
        const callObj = step.call!;
        const app = stepToApp(step.app);
        const peer = step.peer;
        const now = step.now!;

        if (app?.hold) {
          // Held operation: start it, get inflight, then wait for finish
          const callIdentity = objectIdentity(callObj);
          // Register before calling so finish can find it
          const resultPromise = ex.executeCall(callObj, now, app, peer);
          // The executeCall will block until finishHeld is called.
          // We return inflight for this step, and when finish comes we get the result.
          // Store the identity for the finish step to use.
          const idStr = callIdentity;
          heldCallIdentities.set(idStr, idStr);
          // We need to store the promise and resolve it when finish comes
          // Use a callback-based approach via the held op mechanism
          answers.push({ inflight: true });

          // Store the pending promise for later
          (ex as any)["__pendingPromise_" + idStr] = resultPromise;
          continue;
        }

        const result = await ex.executeCall(callObj, now, app, peer);
        answers.push(resultToAnswer(result));

      } else if (step.do === "revoke") {
        const revokeObj = step.revoke!;
        const result = ex.receiveRevoke(revokeObj, step.now!);
        answers.push(resultToAnswer(result));

      } else if (step.do === "finish") {
        // Find the held call by identity
        // step.call is a call identity hash (the id field) — actually step.call is a call identity (hash)
        const callIdHash = step.call as unknown as string;
        const app = stepToApp(step.app);

        // Resolve the held operation
        ex.finishHeld(callIdHash, app!);

        // Now retrieve the result from the stored promise
        const resultPromise = (ex as any)["__pendingPromise_" + callIdHash] as Promise<any>;
        if (!resultPromise) {
          answers.push({ error: "no pending promise for finish" } as any);
          continue;
        }
        const result = await resultPromise;
        delete (ex as any)["__pendingPromise_" + callIdHash];

        const ans = resultToAnswer(result);
        answers.push(ans);

      } else if (step.do === "restart") {
        const result = ex.restart();
        answers.push(resultToAnswer(result));

      } else {
        answers.push({ error: `unknown do: ${step.do}` } as any);
      }
    } catch (e) {
      answers.push({ error: String(e) } as any);
    }
  }

  return answers;
}

function stepToApp(app?: AppScript): AppOutcome | undefined {
  if (!app) return undefined;
  return {
    st: app.st as any,
    code: app.code,
    res: app.res,
    used: app.used,
    rev: app.rev,
    hold: app.hold,
  };
}

function resultToAnswer(result: any): Answer {
  switch (result.kind) {
    case "error":   return { error: result.reason };
    case "tally": {
      if (result.res !== undefined) return { tally: result.tally, res: result.res };
      return { tally: result.tally };
    }
    case "inflight":  return { inflight: true };
    case "tallies":   return { tallies: result.tallies };
    case "resolved":  return { resolved: result.count };
    default: return { error: `unknown kind: ${result.kind}` } as any;
  }
}

async function main() {
  mkdirSync(OUT_DIR, { recursive: true });

  const files = readdirSync(SCENARIOS_DIR).filter((f) => f.endsWith(".json")).sort();
  let ok = 0;
  let err = 0;

  for (const file of files) {
    const scenarioPath = join(SCENARIOS_DIR, file);
    const outPath = join(OUT_DIR, file);

    let scenario: Scenario;
    try {
      scenario = JSON.parse(readFileSync(scenarioPath, "utf8")) as Scenario;
    } catch (e) {
      console.error(`PARSE ERROR ${file}: ${e}`);
      writeFileSync(outPath, JSON.stringify([{ error: String(e) }], null, 2));
      err++;
      continue;
    }

    let answers: Answer[];
    try {
      answers = await runScenario(scenario);
    } catch (e) {
      console.error(`RUN ERROR ${file}: ${e}`);
      answers = [{ error: String(e) }];
      err++;
    }

    writeFileSync(outPath, JSON.stringify(answers, null, 2));
    console.log(`DONE ${file}: ${answers.length} steps`);
    ok++;
  }

  console.log(`\nTotal: ${ok + err}  OK: ${ok}  Errors: ${err}`);
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
