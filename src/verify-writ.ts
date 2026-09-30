/**
 * Writ (section 6.1), chain (section 4), and call (sections 5, 7) verification.
 */

import { BoundError, checkBound, checkSatisfies, prefixMatches } from "./bounds.ts";
import { canonicalize, CanonicalizeError } from "./jcs.ts";
import { isValidDidKey } from "./encoding.ts";
import {
  type Reason, fail,
  SIZE_LIMITS, MAX_CHAIN,
  checkNestingDepth, checkBinaryStr, buildSigningInput, checkSignature,
  checkCrit, writIdentity, checkAttenuation, checkDepthBound,
} from "./verify-primitives.ts";

export { type Reason, VerifyError, checkNestingDepth } from "./verify-primitives.ts";

// ── writ step 5: bnd members ──────────────────────────────────────────────────

function checkBndMembers(bnd: Record<string, unknown>): void {
  if (!("act" in bnd)) fail("malformed", "bnd must contain act");
  const boundKeys = Object.keys(bnd).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  for (const key of boundKeys) {
    try {
      checkBound(bnd[key]);
    } catch (e) {
      if (e instanceof BoundError) fail(e.reason as Reason, `bnd.${key}: ${e.message}`);
      throw e;
    }
  }
  // Reserved names (section 3.2) — after all bounds pass section 3
  const actBound = checkBound(bnd["act"]);
  if (actBound.t !== "prefix") fail("malformed", "bnd.act must be prefix type");
  if ("hld" in bnd) {
    const hldBound = checkBound(bnd["hld"]);
    if (hldBound.t !== "set") fail("malformed", "bnd.hld must be set type");
    for (const el of hldBound.v as unknown[]) {
      if (!isValidDidKey(el)) fail("bad_key", `bnd.hld element not a valid did:key: ${el}`);
    }
  }
  if ("depth" in bnd) {
    const db = checkBound(bnd["depth"]);
    if (db.t !== "max") fail("malformed", "bnd.depth must be max type");
  }
}

// ── section 6.1 single object verification ───────────────────────────────────

/** Verify a single writ object (6.1). Returns the verified writ. */
export function verifySingleWrit(writ: Record<string, unknown>): Record<string, unknown> {
  // Step 1: depth and byte length
  checkNestingDepth(writ, 1);
  let can: Uint8Array;
  try { can = canonicalize(writ); } catch (e) {
    if (e instanceof CanonicalizeError) { if (e.reason === "too_large") fail("too_large", e.message); else fail("noncanonical", e.message); }
    throw e;
  }
  if (can.length > SIZE_LIMITS["writ"]) fail("too_large", `writ too large`);

  // Step 2: binary members that are strings (sig, prv, nnc)
  checkBinaryStr(writ["sig"], "sig", 64);
  if ("prv" in writ && writ["prv"] !== null) {
    if (typeof writ["prv"] !== "string") {
      // not a string — left for step 5, but step 5 will catch it as malformed
    } else {
      checkBinaryStr(writ["prv"], "prv", 32);
    }
  }
  if ("nnc" in writ && typeof writ["nnc"] === "string") {
    checkBinaryStr(writ["nnc"], "nnc", undefined, true);
  }

  // Step 3: v and typ
  if (!("v" in writ) || writ["v"] !== 1) fail("unsupported_version", `writ.v must be 1`);
  if (!("typ" in writ) || writ["typ"] !== "writ") fail("wrong_type", `typ must be writ`);

  // Step 4: crit
  checkCrit(writ);

  // Step 5: members in table order
  // iss
  if (!("iss" in writ)) fail("malformed", "missing iss");
  if (!isValidDidKey(writ["iss"])) fail("bad_key", `iss not valid did:key`);
  // hld
  if (!("hld" in writ)) fail("malformed", "missing hld");
  if (!isValidDidKey(writ["hld"])) fail("bad_key", `hld not valid did:key`);
  // bnd
  if (!("bnd" in writ)) fail("malformed", "missing bnd");
  const bnd = writ["bnd"];
  if (bnd === null || typeof bnd !== "object" || Array.isArray(bnd)) fail("malformed", "bnd must be object");
  checkBndMembers(bnd as Record<string, unknown>);
  // prv
  if (!("prv" in writ)) fail("malformed", "missing prv");
  const prv = writ["prv"];
  if (prv !== null) {
    if (typeof prv !== "string") fail("malformed", "prv must be hash or null");
    // already checked binary at step 2 if string
  }
  // exp
  if (!("exp" in writ)) fail("malformed", "missing exp");
  if (typeof writ["exp"] !== "number" || !Number.isInteger(writ["exp"])) fail("malformed", "exp must be integer");
  // nnc
  if (!("nnc" in writ)) fail("malformed", "missing nnc");
  if (typeof writ["nnc"] !== "string") fail("malformed", "nnc must be string");
  // already checked binary at step 2

  // Step 6: signature
  const si = buildSigningInput("writ", 1, writ);
  checkSignature(writ["iss"] as string, writ["sig"] as string, si);

  return writ;
}

/** Verify a full chain: all writs, attenuation, depth. Expiry checked if now given. */
export function verifyChain(chain: Record<string, unknown>[], now?: number): Record<string, unknown>[] {
  // Writs verified in order
  for (let i = 0; i < chain.length; i++) {
    verifySingleWrit(chain[i]);
  }
  // root prv null
  if (chain[0]["prv"] !== null) fail("chain_broken", "root writ prv must be null");
  // adjacent pairs
  for (let i = 0; i + 1 < chain.length; i++) {
    checkAttenuation(chain[i], chain[i + 1], writIdentity(chain[i]));
  }
  // depth
  checkDepthBound(chain);
  // expiry
  if (now !== undefined) {
    for (const w of chain) {
      if (now >= (w["exp"] as number)) fail("expired", `expired at ${w["exp"]}`);
    }
  }
  return chain;
}

// ── verify_call ───────────────────────────────────────────────────────────────

/** Full call verification per section 14 (verify_call vector). */
export function verifyCallFull(call: Record<string, unknown>, now?: number): void {
  // Step 1: 6.1 steps 1-5 on the call (not sig yet)
  checkNestingDepth(call, 1);
  let can: Uint8Array;
  try { can = canonicalize(call); } catch (e) {
    if (e instanceof CanonicalizeError) { if (e.reason === "too_large") fail("too_large", e.message); else fail("noncanonical", e.message); }
    throw e;
  }
  if (can.length > SIZE_LIMITS["call"]) fail("too_large", "call too large");

  // Rule 5 binary members: sig, id
  checkBinaryStr(call["sig"], "sig", 64);
  if ("id" in call && typeof call["id"] === "string") {
    checkBinaryStr(call["id"], "id", undefined, true);
  }

  // Step 3: v, typ
  if (!("v" in call) || call["v"] !== 1) fail("unsupported_version", "call.v must be 1");
  if (!("typ" in call) || call["typ"] !== "call") fail("wrong_type", "typ must be call");

  // Step 4: crit
  checkCrit(call);

  // Step 5: members (id, chain, from, op, args)
  if (!("id" in call)) fail("malformed", "missing id");
  if (typeof call["id"] !== "string") fail("malformed", "id must be string");
  // already checked binary

  if (!("chain" in call)) fail("malformed", "missing chain");
  const chain = call["chain"];
  if (!Array.isArray(chain)) fail("malformed", "chain must be array");
  if ((chain as unknown[]).length > MAX_CHAIN) fail("too_large", "chain too long");
  for (let i = 0; i < (chain as unknown[]).length; i++) {
    const el = (chain as unknown[])[i];
    if (el === null || typeof el !== "object" || Array.isArray(el)) {
      fail("malformed", `chain[${i}] must be object`);
    }
  }
  if ((chain as unknown[]).length === 0) fail("malformed", "chain must not be empty");

  if (!("from" in call)) fail("malformed", "missing from");
  if (!isValidDidKey(call["from"])) fail("bad_key", "from not valid did:key");

  if (!("op" in call)) fail("malformed", "missing op");
  if (typeof call["op"] !== "string") fail("malformed", "op must be string");

  if (!("args" in call)) fail("malformed", "missing args");
  const args = call["args"];
  if (args === null || typeof args !== "object" || Array.isArray(args)) {
    fail("malformed", "args must be object");
  }

  // Step 2: every writ in chain passes 6.1
  const chainArr = chain as Record<string, unknown>[];
  for (let i = 0; i < chainArr.length; i++) {
    verifySingleWrit(chainArr[i]);
  }

  // call.sig verifies
  const si = buildSigningInput("call", 1, call);
  checkSignature(call["from"] as string, call["sig"] as string, si);

  // Step 3 (section 4): full chain verification
  const writs = verifyChain(chainArr, undefined);

  // Expiry for forward calls
  const op = call["op"] as string;
  const isForward = !op.startsWith("sys/");
  if (isForward && now !== undefined) {
    for (const w of writs) {
      if (now >= (w["exp"] as number)) fail("expired", `writ expired`);
    }
  }

  // Section 5 forward/standing checks
  const leafWrit = writs[writs.length - 1];
  const from = call["from"] as string;

  if (isForward) {
    // from must equal leaf.iss
    if (from !== leafWrit["iss"]) fail("no_standing", "from != leaf.iss");
    // op matched by leaf.act
    const actBound = (leafWrit["bnd"] as Record<string, unknown>)["act"] as { t: string; v: string };
    if (!prefixMatches(actBound.v, op)) fail("forbidden_op", `op not matched by act`);
    // args satisfy bounds (section 7.2)
    const argsObj = call["args"] as Record<string, unknown>;
    const bnd = leafWrit["bnd"] as Record<string, unknown>;
    const appBounds: [string, unknown][] = [];
    for (const [name, bound] of Object.entries(bnd)) {
      if (name === "act" || name === "hld" || name === "depth") continue;
      const b = bound as { t: string; v: unknown };
      if (b.t === "count") continue;
      appBounds.push([name, bound]);
    }
    appBounds.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    // pass 1: presence
    for (const [name] of appBounds) {
      if (!(name in argsObj)) fail("missing_arg", `missing arg: ${name}`);
    }
    // pass 2: satisfaction
    for (const [name, bound] of appBounds) {
      try {
        checkSatisfies(bound, argsObj[name]);
      } catch (e) {
        if (e instanceof BoundError) fail(e.reason as Reason, `arg ${name}: ${e.message}`);
        throw e;
      }
    }
  } else {
    // standing call
    const isIssuer = writs.some((w) => w["iss"] === from);
    if (!isIssuer) fail("no_standing", "from not an issuer on chain");
    const defined = new Set(["sys/undo", "sys/tallies"]);
    if (!defined.has(op)) fail("forbidden_op", `undefined sys op: ${op}`);
  }
}

