/**
 * Writ executor (sections 7, 8, 9).
 * Stores: call, count, tally, revoke, reversal.
 * Operations: forward call, sys/undo, sys/tallies, revoke, restart.
 */

import { VerifyError } from "./verify-primitives.ts";
import { verifyChain } from "./verify-writ.ts";
import { verifyRevoke } from "./verify-tally.ts";
import { buildTally, objectIdentity, hashBody, type PrivKey } from "./sign-tally.ts";
import { prefixMatches } from "./bounds.ts";
import type { AppOutcome } from "./exec-types.ts";
import {
  verifyCallPre, verifyCallSig, checkArgsAgainstBounds, verifyTallyAs6_1,
} from "./exec-helpers.ts";

// ── Store entry types ─────────────────────────────────────────────────────────

interface CallEntry {
  state: "pending" | "final";
  acc: number;
  tallyObj?: Record<string, unknown>;
  resObj?: unknown;
  callObj: Record<string, unknown>;
  leafWritId: string;
  callId: string;
}

interface ReversalEntry {
  state: "begun" | "succeeded";
  resultBody?: unknown;
}

// ── Public result union ───────────────────────────────────────────────────────

export type ExecResult =
  | { kind: "error"; reason: string }
  | { kind: "tally"; tally: Record<string, unknown>; res?: unknown }
  | { kind: "inflight" }
  | { kind: "tallies"; tallies: Record<string, unknown>[] }
  | { kind: "resolved"; count: number };

// ── Executor class ────────────────────────────────────────────────────────────

export class Executor {
  private privKey: PrivKey;
  private did: string;
  private acceptedRoots: Set<string>;
  private peers: Map<string, string[]>;

  // Durable stores (survive restart)
  private callStore = new Map<string, CallEntry>();
  private countStore = new Map<string, number>();
  private tallyStore = new Map<string, { tally: Record<string, unknown>; res?: unknown }>();
  private writIndex = new Map<string, Set<string>>();  // writId -> Set<tallyId>
  private revokeStore = new Set<string>();             // revoked writ identities
  private revokedKeys = new Set<string>();             // key-wide revoked keys
  private reversalStore = new Map<string, ReversalEntry>();

  // Volatile (lost on restart)
  private heldOps = new Map<string, { resolve: (app: AppOutcome) => void; signaled: boolean }>();

  constructor(privKey: PrivKey, did: string, acceptedRoots: string[], peers?: Record<string, string[]>) {
    this.privKey = privKey; this.did = did;
    this.acceptedRoots = new Set(acceptedRoots);
    this.peers = new Map(Object.entries(peers ?? {}));
  }

  // ── Main entry point: execute a call (section 7) ─────────────────────────

  async executeCall(callObj: Record<string, unknown>, now: number, app: AppOutcome | undefined, peer?: string): Promise<ExecResult> {
    // Steps 1+2: unsigned errors
    try { verifyCallPre(callObj); } catch (e) { if (e instanceof VerifyError) return { kind: "error", reason: e.reason }; throw e; }
    try { verifyCallSig(callObj); } catch (e) { if (e instanceof VerifyError) return { kind: "error", reason: e.reason }; throw e; }

    const chain = callObj["chain"] as Record<string, unknown>[];
    const leafWrit = chain[chain.length - 1];
    const leafWritId = objectIdentity(leafWrit);
    const callId = callObj["id"] as string;
    const op = callObj["op"] as string;
    const isForward = !op.startsWith("sys/");
    const from = callObj["from"] as string;
    const callIdentity = objectIdentity(callObj);

    const failedTally = (code: string): ExecResult => ({
      kind: "tally",
      tally: buildTally({ call: callIdentity, writ: leafWritId, op, acc: now, st: "failed", err: { code }, out: null, used: {}, rev: null, sub: [], wrt: [] }, this.privKey),
    });

    // Step 3: chain verification
    try { verifyChain(chain, undefined); } catch (e) { if (e instanceof VerifyError) return failedTally(e.reason); throw e; }

    // Step 4: forward expiry
    if (isForward) { for (const w of chain) { if (now >= (w["exp"] as number)) return failedTally("expired"); } }

    // Step 5: root acceptance
    if (!this.acceptedRoots.has(chain[0]["iss"] as string)) return failedTally("root_not_accepted");

    // Step 6: executor is leaf hld
    if (leafWrit["hld"] !== this.did) return failedTally("wrong_executor");

    // Step 7: forward — no writ revoked
    if (isForward) {
      for (const w of chain) {
        if (this.revokeStore.has(objectIdentity(w))) return failedTally("revoked");
        if (this.revokedKeys.has(w["iss"] as string)) return failedTally("revoked");
      }
    }

    // Step 8: peer binding + forward/standing checks
    if (peer !== undefined) {
      const keys = this.peers.get(peer);
      if (!keys || !keys.includes(from)) return failedTally("peer_mismatch");
    }
    if (isForward) {
      if (from !== leafWrit["iss"]) return failedTally("no_standing");
      const act = ((leafWrit["bnd"] as Record<string, unknown>)["act"] as { t: string; v: string });
      if (!prefixMatches(act.v, op)) return failedTally("forbidden_op");
      const err = checkArgsAgainstBounds(callObj, leafWrit);
      if (err) return failedTally(err);
    } else {
      if (!chain.some((w) => w["iss"] === from)) return failedTally("no_standing");
      if (op !== "sys/undo" && op !== "sys/tallies") return failedTally("forbidden_op");
    }

    // Step 9: replay
    const storeKey = `${leafWritId}|${callId}`;
    const existing = this.callStore.get(storeKey);
    if (existing) {
      if (existing.state === "final") return { kind: "tally", tally: existing.tallyObj!, res: existing.resObj };
      return { kind: "tally", tally: buildTally({ call: callIdentity, writ: leafWritId, op, acc: existing.acc, st: "pending", err: { code: "pending" }, out: null, used: {}, rev: null, sub: [], wrt: [] }, this.privKey) };
    }

    // Step 10: count (forward only)
    if (isForward) {
      for (const w of chain) {
        const wId = objectIdentity(w);
        for (const b of Object.values(w["bnd"] as Record<string, unknown>)) {
          if ((b as { t: string }).t !== "count") continue;
          if ((this.countStore.get(wId) ?? 0) >= (b as { t: string; v: number }).v) return failedTally("count_exhausted");
        }
      }
      for (const w of chain) {
        const wId = objectIdentity(w);
        if (Object.values(w["bnd"] as Record<string, unknown>).some((b) => (b as { t: string }).t === "count"))
          this.countStore.set(wId, (this.countStore.get(wId) ?? 0) + 1);
      }
    }

    // Step 11: record pending, perform operation
    const acc = now;
    const entry: CallEntry = { state: "pending", acc, callObj, leafWritId, callId };
    this.callStore.set(storeKey, entry);

    // sys/tallies: never invokes app
    if (op === "sys/tallies") {
      const r = this.doSysTallies(callObj, chain, from, leafWritId, callIdentity, acc);
      this.finalize(storeKey, entry, r.tally, r.res, chain);
      return { kind: "tally", tally: r.tally, res: r.res };
    }

    // sys/undo: checks then held or immediate
    if (op === "sys/undo") {
      const check = this.checkSysUndo(callObj, leafWritId, callIdentity, acc);
      if (check.kind === "fail") { this.finalize(storeKey, entry, check.tally, undefined, chain); return { kind: "tally", tally: check.tally }; }
      this.reversalStore.set(check.targetId, { state: "begun" });
      if (!app || app.hold) {
        await new Promise<void>((res) => { this.heldOps.set(callIdentity, { resolve: (outcome) => { const r = this.completeUndo(outcome, check.targetId, callIdentity, leafWritId, acc); this.finalize(storeKey, entry, r.tally, r.res, chain); res(); }, signaled: false }); });
        const fe = this.callStore.get(storeKey)!;
        return { kind: "tally", tally: fe.tallyObj!, res: fe.resObj };
      }
      const r = this.completeUndo(app, check.targetId, callIdentity, leafWritId, acc);
      this.finalize(storeKey, entry, r.tally, r.res, chain);
      return { kind: "tally", tally: r.tally, res: r.res };
    }

    // Forward call: held or immediate
    if (!app || app.hold || app.st === "") {
      await new Promise<void>((res) => { this.heldOps.set(callIdentity, { resolve: (outcome) => { const r = this.buildFinalFromApp(outcome, callIdentity, leafWritId, op, acc); this.finalize(storeKey, entry, r.tally, r.res, chain); res(); }, signaled: false }); });
      const fe = this.callStore.get(storeKey)!;
      return { kind: "tally", tally: fe.tallyObj!, res: fe.resObj };
    }
    const r = this.buildFinalFromApp(app, callIdentity, leafWritId, op, acc);
    this.finalize(storeKey, entry, r.tally, r.res, chain);
    return { kind: "tally", tally: r.tally, res: r.res };
  }

  // ── Revoke handling (section 9.1) ─────────────────────────────────────────

  receiveRevoke(revokeObj: Record<string, unknown>, now: number): ExecResult {
    try { verifyRevoke(revokeObj); } catch (e) { if (e instanceof VerifyError) return { kind: "error", reason: e.reason }; throw e; }
    const writField = revokeObj["writ"] as string;
    const isKeyWide = writField === "*";
    const iss = revokeObj["iss"] as string;
    if (isKeyWide) this.revokedKeys.add(iss); else this.revokeStore.add(writField);

    const pending = this.collectPendingForRevoke(isKeyWide ? null : writField, isKeyWide ? iss : null);
    pending.sort((a, b) => { const ia = objectIdentity(a.callObj), ib = objectIdentity(b.callObj); return ia < ib ? -1 : ia > ib ? 1 : 0; });

    const tallies: Record<string, unknown>[] = [];
    for (const p of pending) {
      const callIdentity = objectIdentity(p.callObj);
      const op = p.callObj["op"] as string;
      const chain = p.callObj["chain"] as Record<string, unknown>[];
      const storeKey = `${p.leafWritId}|${p.callId}`;
      const held = this.heldOps.get(callIdentity);
      if (held) {
        held.signaled = true;
        tallies.push(buildTally({ call: callIdentity, writ: p.leafWritId, op, acc: p.acc, st: "pending", err: { code: "pending" }, out: null, used: {}, rev: null, sub: [], wrt: [] }, this.privKey));
      } else {
        const ct = buildTally({ call: callIdentity, writ: p.leafWritId, op, acc: now, st: "canceled", err: { code: "canceled" }, out: null, used: {}, rev: null, sub: [], wrt: [] }, this.privKey);
        this.callStore.set(storeKey, { state: "final", acc: now, tallyObj: ct, callObj: p.callObj, leafWritId: p.leafWritId, callId: p.callId });
        this.storeTally(objectIdentity(ct), ct, undefined, chain);
        tallies.push(ct);
      }
    }
    return { kind: "tallies", tallies };
  }

  finishHeld(callIdentity: string, app: AppOutcome): void {
    const held = this.heldOps.get(callIdentity);
    if (!held) throw new Error(`No held op: ${callIdentity}`);
    this.heldOps.delete(callIdentity);
    held.resolve(app);
  }

  wasSignaled(callIdentity: string): boolean { return this.heldOps.get(callIdentity)?.signaled ?? false; }

  // ── Restart (section 9) ────────────────────────────────────────────────────

  restart(): ExecResult {
    this.heldOps.clear();
    let resolved = 0;
    for (const [storeKey, entry] of this.callStore) {
      if (entry.state !== "pending") continue;
      const callIdentity = objectIdentity(entry.callObj);
      const op = entry.callObj["op"] as string;
      const chain = entry.callObj["chain"] as Record<string, unknown>[];
      const t = buildTally({ call: callIdentity, writ: entry.leafWritId, op, acc: entry.acc, st: "failed", err: { code: "unknown_outcome" }, out: null, used: {}, rev: null, sub: [], wrt: [] }, this.privKey);
      this.callStore.set(storeKey, { ...entry, state: "final", tallyObj: t });
      this.storeTally(objectIdentity(t), t, undefined, chain);
      resolved++;
    }
    return { kind: "resolved", count: resolved };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private finalize(storeKey: string, entry: CallEntry, tally: Record<string, unknown>, res: unknown, chain: Record<string, unknown>[]): void {
    this.callStore.set(storeKey, { ...entry, state: "final", tallyObj: tally, resObj: res });
    this.storeTally(objectIdentity(tally), tally, res, chain);
  }

  private buildFinalFromApp(app: AppOutcome, callId: string, leafWritId: string, op: string, acc: number): { tally: Record<string, unknown>; res?: unknown } {
    const st = app.st as "ok" | "failed" | "canceled";
    const t = buildTally({ call: callId, writ: leafWritId, op, acc, st, err: st !== "ok" ? { code: app.code ?? "app_error" } : null, out: app.res !== undefined ? hashBody(app.res) : null, used: app.used ?? {}, rev: app.rev != null ? { until: app.rev } : null, sub: [], wrt: [] }, this.privKey);
    return { tally: t, res: app.res };
  }

  private storeTally(tallyId: string, tally: Record<string, unknown>, res: unknown, chain: Record<string, unknown>[]): void {
    this.tallyStore.set(tallyId, { tally, res });
    for (const w of chain) { const wId = objectIdentity(w); if (!this.writIndex.has(wId)) this.writIndex.set(wId, new Set()); this.writIndex.get(wId)!.add(tallyId); }
  }

  private collectPendingForRevoke(writId: string | null, revokedKey: string | null): CallEntry[] {
    const result: CallEntry[] = [];
    for (const entry of this.callStore.values()) {
      if (entry.state === "final") continue;
      if ((entry.callObj["op"] as string).startsWith("sys/")) continue;
      const chain = entry.callObj["chain"] as Record<string, unknown>[];
      let matches = writId ? chain.some((w) => objectIdentity(w) === writId) : revokedKey ? chain.some((w) => (w["iss"] as string) === revokedKey) : false;
      if (matches) result.push(entry);
    }
    return result;
  }

  private doSysTallies(callObj: Record<string, unknown>, chain: Record<string, unknown>[], from: string, leafWritId: string, callIdentity: string, acc: number): { tally: Record<string, unknown>; res?: unknown } {
    const op = "sys/tallies";
    const failT = (code: string) => ({ tally: buildTally({ call: callIdentity, writ: leafWritId, op, acc, st: "failed" as const, err: { code }, out: null, used: {}, rev: null, sub: [], wrt: [] }, this.privKey), res: undefined });
    const writHashArg = (callObj["args"] as Record<string, unknown>)?.["writ"];
    if (typeof writHashArg !== "string") return failT("tally_mismatch");
    const fromIssuedIndices: number[] = [];
    for (let i = 0; i < chain.length; i++) { if (chain[i]["iss"] === from) fromIssuedIndices.push(i); }
    let targetFound = false;
    for (let i = 0; i < chain.length; i++) {
      if (objectIdentity(chain[i]) === writHashArg) {
        if (fromIssuedIndices.some((fi) => i >= fi)) { targetFound = true; } break;
      }
    }
    if (!targetFound) return failT("tally_mismatch");
    const rows: Array<{ id: string; acc: number; tally: Record<string, unknown> }> = [];
    for (const tid of this.writIndex.get(writHashArg) ?? new Set<string>()) {
      const stored = this.tallyStore.get(tid);
      if (stored) rows.push({ id: tid, acc: stored.tally["acc"] as number, tally: stored.tally });
    }
    rows.sort((a, b) => a.acc !== b.acc ? a.acc - b.acc : a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
    const body = { tallies: rows.map((r) => r.tally) };
    const t = buildTally({ call: callIdentity, writ: leafWritId, op, acc, st: "ok", err: null, out: hashBody(body), used: {}, rev: null, sub: [], wrt: [] }, this.privKey);
    return { tally: t, res: body };
  }

  private checkSysUndo(callObj: Record<string, unknown>, leafWritId: string, callIdentity: string, acc: number): { kind: "ok"; targetId: string } | { kind: "fail"; tally: Record<string, unknown> } {
    const op = "sys/undo";
    const failT = (code: string) => ({ kind: "fail" as const, tally: buildTally({ call: callIdentity, writ: leafWritId, op, acc, st: "failed" as const, err: { code }, out: null, used: {}, rev: null, sub: [], wrt: [] }, this.privKey) });
    const targetTallyRaw = (callObj["args"] as Record<string, unknown>)?.["tally"];
    if (targetTallyRaw === null || typeof targetTallyRaw !== "object" || Array.isArray(targetTallyRaw)) return failT("malformed");
    const tt = targetTallyRaw as Record<string, unknown>;
    try { verifyTallyAs6_1(tt, this.did); } catch { return failT("not_reversible"); }
    if (tt["writ"] !== leafWritId) return failT("tally_mismatch");
    const ttRev = tt["rev"];
    if (!ttRev || typeof ttRev !== "object") return failT("not_reversible");
    if (acc >= (ttRev as { until: number }).until) return failT("not_reversible");
    if (tt["st"] !== "ok") return failT("not_reversible");
    const targetId = objectIdentity(tt);
    if (!this.tallyStore.has(targetId)) return failT("not_reversible");
    const rev = this.reversalStore.get(targetId);
    if (rev?.state === "succeeded") {
      const outHash = rev.resultBody !== undefined ? hashBody(rev.resultBody) : null;
      return { kind: "fail", tally: buildTally({ call: callIdentity, writ: leafWritId, op, acc, st: "ok", err: null, out: outHash, used: {}, rev: null, sub: [], wrt: [] }, this.privKey) };
    }
    if (rev?.state === "begun") return failT("unknown_outcome");
    return { kind: "ok", targetId };
  }

  private completeUndo(app: AppOutcome, targetId: string, callIdentity: string, leafWritId: string, acc: number): { tally: Record<string, unknown>; res?: unknown } {
    const op = "sys/undo";
    if (app.st === "ok") {
      this.reversalStore.set(targetId, { state: "succeeded", resultBody: app.res });
      const t = buildTally({ call: callIdentity, writ: leafWritId, op, acc, st: "ok", err: null, out: app.res !== undefined ? hashBody(app.res) : null, used: {}, rev: null, sub: [], wrt: [] }, this.privKey);
      return { tally: t, res: app.res };
    }
    this.reversalStore.delete(targetId); // failed: can retry
    return { tally: buildTally({ call: callIdentity, writ: leafWritId, op, acc, st: "failed", err: { code: app.code ?? "app_error" }, out: null, used: {}, rev: null, sub: [], wrt: [] }, this.privKey) };
  }
}
