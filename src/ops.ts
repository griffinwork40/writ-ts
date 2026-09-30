/**
 * Vector operation implementations.
 * Handles: canonicalize, narrows, satisfies, verify_writ, verify_chain,
 *          verify_call, verify_tally, verify_revoke.
 */

import { CanonicalizeError, parseAndCanonicalize } from "./jcs.ts";
import { BoundError, checkNarrows, checkSatisfies } from "./bounds.ts";
import {
  VerifyError,
  verifySingleWrit,
  verifyChain,
  verifyTallyTree,
  verifyRevoke,
  verifyCallFull,
} from "./verify.ts";

export type Verdict = "accept" | "reject";
export interface Result {
  verdict: Verdict;
  reason?: string;
}

function accept(): Result { return { verdict: "accept" }; }
function reject(reason: string): Result { return { verdict: "reject", reason }; }

function catchToResult(e: unknown): Result {
  if (e instanceof VerifyError) return reject(e.reason);
  if (e instanceof BoundError) return reject(e.reason);
  if (e instanceof CanonicalizeError) return reject(e.reason);
  throw e;
}

// ── canonicalize ─────────────────────────────────────────────────────────────

export function opCanonicalize(input: Record<string, unknown>): Result {
  const raw = input["raw"] as string;
  const expected = input["canonical"] as string;
  try {
    const { canonical } = parseAndCanonicalize(raw);
    const got = new TextDecoder().decode(canonical);
    return got === expected ? accept() : reject("noncanonical");
  } catch (e) {
    return catchToResult(e);
  }
}

// ── narrows ──────────────────────────────────────────────────────────────────

export function opNarrows(input: Record<string, unknown>): Result {
  try {
    checkNarrows(input["child"], input["parent"]);
    return accept();
  } catch (e) {
    return catchToResult(e);
  }
}

// ── satisfies ────────────────────────────────────────────────────────────────

export function opSatisfies(input: Record<string, unknown>): Result {
  try {
    checkSatisfies(input["bound"], input["arg"]);
    return accept();
  } catch (e) {
    return catchToResult(e);
  }
}

// ── verify_writ ───────────────────────────────────────────────────────────────

export function opVerifyWrit(input: Record<string, unknown>): Result {
  try {
    verifySingleWrit(input["writ"] as Record<string, unknown>);
    return accept();
  } catch (e) {
    return catchToResult(e);
  }
}

// ── verify_chain ─────────────────────────────────────────────────────────────

export function opVerifyChain(input: Record<string, unknown>, now?: number): Result {
  try {
    const chainRaw = input["chain"];
    if (!Array.isArray(chainRaw)) return reject("malformed");
    if (chainRaw.length > 8) return reject("too_large");
    for (let i = 0; i < chainRaw.length; i++) {
      const el = chainRaw[i];
      if (el === null || typeof el !== "object" || Array.isArray(el)) return reject("malformed");
    }
    if (chainRaw.length === 0) return reject("malformed");
    verifyChain(chainRaw as Record<string, unknown>[], now);
    return accept();
  } catch (e) {
    return catchToResult(e);
  }
}

// ── verify_call ───────────────────────────────────────────────────────────────

export function opVerifyCall(input: Record<string, unknown>, now?: number): Result {
  try {
    const callRaw = input["call"];
    if (callRaw === null || typeof callRaw !== "object" || Array.isArray(callRaw)) {
      return reject("malformed");
    }
    verifyCallFull(callRaw as Record<string, unknown>, now);
    return accept();
  } catch (e) {
    return catchToResult(e);
  }
}

// ── verify_tally ──────────────────────────────────────────────────────────────

export function opVerifyTally(input: Record<string, unknown>): Result {
  try {
    const leafWrit = input["writ"] as Record<string, unknown>;
    const callObj = input["call"] as Record<string, unknown>;
    const tally = input["tally"];
    const res = "res" in input ? input["res"] : undefined;
    const chain = callObj["chain"] as Record<string, unknown>[];
    verifySingleWrit(leafWrit);
    verifyTallyTree(leafWrit, callObj, tally, chain, res);
    return accept();
  } catch (e) {
    return catchToResult(e);
  }
}

// ── verify_revoke ─────────────────────────────────────────────────────────────

export function opVerifyRevoke(input: Record<string, unknown>): Result {
  try {
    verifyRevoke(input["revoke"]);
    return accept();
  } catch (e) {
    return catchToResult(e);
  }
}
