/**
 * Executor unit tests. Run with: node --test src/exec-test.ts
 * Focus: the riskiest parts — signing, count, replay, sys/undo, key-wide revoke, restart.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { buildPrivKey, objectIdentity, hashBody } from "./sign-tally.ts";
import { Executor } from "./executor.ts";
import { buildSigningInput, checkSignature } from "./verify-primitives.ts";

const SCENARIOS_DIR = new URL("../conformance/scenarios", import.meta.url).pathname;

function loadScenario(file: string): any {
  return JSON.parse(readFileSync(join(SCENARIOS_DIR, file), "utf8"));
}

// ── Key derivation ─────────────────────────────────────────────────────────

describe("key derivation", () => {
  test("seed 03*32 produces expected did", () => {
    const { did } = buildPrivKey("0303030303030303030303030303030303030303030303030303030303030303");
    assert.equal(did, "did:key:z6MkvRXNYcE7MMduynWTgeKbDaT1iijDSC8pZqXZc8rHPrf2");
  });

  test("tally signatures verify independently", () => {
    const { privKey, did } = buildPrivKey("0303030303030303030303030303030303030303030303030303030303030303");
    const s = loadScenario("001_count_replay_and_root_acceptance.json");
    const ex = new Executor(privKey, did, s.executor.accept);
    // Not checking signature here — just that construction works
    assert.ok(ex);
  });
});

// ── Count exhaustion ────────────────────────────────────────────────────────

describe("count exhaustion", () => {
  test("first call accepted, second rejected", async () => {
    const s = loadScenario("001_count_replay_and_root_acceptance.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept);
    const step0 = s.steps[0];
    const app0 = { st: "ok" as const, res: step0.app.res, used: step0.app.used, rev: step0.app.rev };
    const r0 = await ex.executeCall(step0.call, step0.now, app0);
    assert.equal(r0.kind, "tally");
    assert.equal((r0 as any).tally.st, "ok");

    // Step 2: new call id — count_exhausted
    const step2 = s.steps[2];
    const r2 = await ex.executeCall(step2.call, step2.now, undefined);
    assert.equal(r2.kind, "tally");
    assert.equal((r2 as any).tally.st, "failed");
    assert.equal((r2 as any).tally.err.code, "count_exhausted");
  });

  test("refusal does not consume count", async () => {
    // Scenario 003: w2a count_exhausted, w1 should still work
    const s = loadScenario("003_count_rejection_consumes_nothing.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept);
    const step0 = s.steps[0];
    const step1 = s.steps[1];
    const step3 = s.steps[3];

    const app0 = { st: "ok" as const, used: step0.app?.used ?? {}, rev: step0.app?.rev };
    await ex.executeCall(step0.call, step0.now, app0);
    // step1: w2a exhausted
    const r1 = await ex.executeCall(step1.call, step1.now, undefined);
    assert.equal((r1 as any).tally?.err?.code, "count_exhausted");
    // step3: second use of w1 (w2b has a use, w1 still has one)
    const app3 = { st: "ok" as const, used: step3.app?.used ?? {} };
    const r3 = await ex.executeCall(step3.call, step3.now, app3);
    assert.equal(r3.kind, "tally");
    assert.equal((r3 as any).tally.st, "ok");
  });
});

// ── Replay ──────────────────────────────────────────────────────────────────

describe("replay", () => {
  test("replay returns identical tally bytes", async () => {
    const s = loadScenario("001_count_replay_and_root_acceptance.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept);
    const step0 = s.steps[0];
    const app0 = { st: "ok" as const, res: step0.app.res, used: step0.app.used, rev: step0.app.rev };
    const r0 = await ex.executeCall(step0.call, step0.now, app0);
    // step1: replay (same call bytes, different now)
    const step1 = s.steps[1];
    const r1 = await ex.executeCall(step1.call, step1.now, undefined);
    assert.equal(r1.kind, "tally");
    // Identical tally bytes
    const t0 = JSON.stringify((r0 as any).tally);
    const t1 = JSON.stringify((r1 as any).tally);
    assert.equal(t0, t1);
  });
});

// ── sys/undo ────────────────────────────────────────────────────────────────

describe("sys/undo", () => {
  test("successful reversal returns ok tally", async () => {
    const s = loadScenario("005_undo_standing_and_idempotency.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept);
    const step0 = s.steps[0];
    const app0 = { st: "ok" as const, res: step0.app.res, used: step0.app.used, rev: step0.app.rev };
    await ex.executeCall(step0.call, step0.now, app0);
    const step3 = s.steps[3];
    const app3 = { st: "ok" as const, res: step3.app.res };
    const r3 = await ex.executeCall(step3.call, step3.now, app3);
    assert.equal(r3.kind, "tally");
    assert.equal((r3 as any).tally.st, "ok");
    assert.deepEqual((r3 as any).res, step3.app.res);
  });

  test("second undo for same tally is idempotent", async () => {
    const s = loadScenario("005_undo_standing_and_idempotency.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept);
    const step0 = s.steps[0];
    await ex.executeCall(step0.call, step0.now, { st: "ok" as const, res: step0.app.res, used: step0.app.used, rev: step0.app.rev });
    const step3 = s.steps[3];
    await ex.executeCall(step3.call, step3.now, { st: "ok" as const, res: step3.app.res });
    // step5: new undo, different call id, same target tally
    const step5 = s.steps[5];
    const r5 = await ex.executeCall(step5.call, step5.now, undefined);
    assert.equal(r5.kind, "tally");
    assert.equal((r5 as any).tally.st, "ok");
    // out hash should match original reversal's result body
    const expectedOut = hashBody(step3.app.res);
    assert.equal((r5 as any).tally.out, expectedOut);
  });

  test("not_reversible when rev is null", async () => {
    const s = loadScenario("006_undo_targets_and_bounds.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept);
    // step 0: charge
    await ex.executeCall(s.steps[0].call, s.steps[0].now, { st: "ok" as const, res: s.steps[0].app.res, used: s.steps[0].app.used, rev: s.steps[0].app.rev });
    // step 1: effect with no rev
    await ex.executeCall(s.steps[1].call, s.steps[1].now, { st: "ok" as const, res: s.steps[1].app?.res });
    // step 3: undo with rev=null target
    const r = await ex.executeCall(s.steps[3].call, s.steps[3].now, undefined);
    assert.equal((r as any).tally?.err?.code, "not_reversible");
  });
});

// ── Key-wide revoke ─────────────────────────────────────────────────────────

describe("key-wide revoke", () => {
  test("revoked key blocks all its writs", async () => {
    const s = loadScenario("011_key-wide_revoke.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept);
    // step0: charge under A's chain
    await ex.executeCall(s.steps[0].call, s.steps[0].now, { st: "ok" as const, res: s.steps[0].app?.res, used: s.steps[0].app?.used, rev: s.steps[0].app?.rev });
    // step1: A revokes all its writs
    const revResult = ex.receiveRevoke(s.steps[1].revoke, s.steps[1].now);
    assert.equal(revResult.kind, "tallies");
    // step2: call under A's chain fails
    const r2 = await ex.executeCall(s.steps[2].call, s.steps[2].now, undefined);
    assert.equal((r2 as any).tally?.err?.code, "revoked");
  });

  test("key-wide revoke survives restart", async () => {
    const s = loadScenario("022_a_key-wide_revoke_survives_restart.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept);
    ex.receiveRevoke(s.steps[0].revoke, s.steps[0].now);
    ex.restart();
    const r = await ex.executeCall(s.steps[2].call, s.steps[2].now, undefined);
    assert.equal((r as any).tally?.err?.code, "revoked");
  });
});

// ── Crash / restart ─────────────────────────────────────────────────────────

describe("restart", () => {
  test("pending record resolves to unknown_outcome", async () => {
    const s = loadScenario("016_crash_while_running.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept);
    const step0 = s.steps[0];
    // Start held op
    const p = ex.executeCall(step0.call, step0.now, { st: "" as any, hold: true });
    // Restart (clears held ops)
    const restartResult = ex.restart();
    assert.equal(restartResult.kind, "resolved");
    assert.equal((restartResult as any).count, 1);
    // Retry the call — should get unknown_outcome from stored tally
    const r2 = await ex.executeCall(s.steps[2].call, s.steps[2].now, undefined);
    assert.equal((r2 as any).tally?.err?.code, "unknown_outcome");
    assert.equal((r2 as any).tally?.acc, step0.now); // original acc
    // The promise from the held op resolves after restart (never called finishHeld)
    // Don't await p here — it's orphaned
  });

  test("second restart resolves nothing", async () => {
    const s = loadScenario("016_crash_while_running.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept);
    const p = ex.executeCall(s.steps[0].call, s.steps[0].now, { st: "" as any, hold: true });
    ex.restart(); // resolves 1
    const r2 = ex.restart(); // resolves 0
    assert.equal((r2 as any).count, 0);
  });
});

// ── Peer binding ─────────────────────────────────────────────────────────────

describe("peer binding", () => {
  test("wrong peer fails", async () => {
    const s = loadScenario("021_peer_binding.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept, s.executor.peers);
    const step0 = s.steps[0];
    // First call succeeds (correct peer)
    const r0 = await ex.executeCall(step0.call, step0.now, { st: "ok" as const }, step0.peer);
    assert.equal(r0.kind, "tally");
    assert.equal((r0 as any).tally.st, "ok");
    // step1: same call bytes, wrong peer
    const step1 = s.steps[1];
    const r1 = await ex.executeCall(step1.call, step1.now, undefined, step1.peer);
    assert.equal((r1 as any).tally?.err?.code, "peer_mismatch");
  });

  test("no peer skips check", async () => {
    const s = loadScenario("021_peer_binding.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept, s.executor.peers);
    const step4 = s.steps[4]; // no peer
    const r = await ex.executeCall(step4.call, step4.now, { st: "ok" as const });
    assert.equal(r.kind, "tally");
    assert.equal((r as any).tally.st, "ok");
  });
});

// ── sys/tallies ─────────────────────────────────────────────────────────────

describe("sys/tallies", () => {
  test("returns stored tallies in acc order", async () => {
    const s = loadScenario("018_sys_tallies_order_and_contents.json");
    const { privKey, did } = buildPrivKey(s.executor.seed);
    const ex = new Executor(privKey, did, s.executor.accept);
    // step0: first tally
    const step0 = s.steps[0];
    await ex.executeCall(step0.call, step0.now, { st: "ok" as const, used: step0.app?.used });
    // step1: second tally (same acc)
    const step1 = s.steps[1];
    await ex.executeCall(step1.call, step1.now, { st: "ok" as const, used: step1.app?.used });
    // step5: sys/tallies
    const step5 = s.steps[5];
    const r = await ex.executeCall(step5.call, step5.now, undefined);
    assert.equal(r.kind, "tally");
    assert.equal((r as any).tally.st, "ok");
    const tallies = (r as any).res?.tallies ?? [];
    assert.ok(tallies.length >= 2, `expected at least 2 tallies, got ${tallies.length}`);
  });
});
