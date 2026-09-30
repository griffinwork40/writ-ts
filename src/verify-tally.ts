/**
 * Tally tree verification (section 6.2) and revoke verification (section 9.1).
 */

import { canonicalize, CanonicalizeError } from "./jcs.ts";
import { isValidDidKey, hashIdentity } from "./encoding.ts";
import {
  type Reason, fail,
  SIZE_LIMITS, MAX_CHAIN,
  checkNestingDepth, checkBinaryStr, buildSigningInput, checkSignature,
  checkCrit, writIdentity, checkAttenuation, checkDepthBound,
} from "./verify-primitives.ts";
import { verifySingleWrit } from "./verify-writ.ts";

// ── tally tree verification (section 6.2) ────────────────────────────────────

export function verifyTallyTree(
  leafWrit: Record<string, unknown>,
  callObj: Record<string, unknown>,
  tally: unknown,
  chainToLeaf: Record<string, unknown>[],
  res?: unknown
): void {
  verifyTallyNode(leafWrit, callObj, tally, chainToLeaf, false, res);
}

function verifyTallyNode(
  W: Record<string, unknown>,
  K: Record<string, unknown>,
  tallyRaw: unknown,
  chainToW: Record<string, unknown>[],
  isSub: boolean,
  res?: unknown
): void {
  if (tallyRaw === null || typeof tallyRaw !== "object" || Array.isArray(tallyRaw)) {
    fail("malformed", "tally must be an object");
  }
  const t = tallyRaw as Record<string, unknown>;

  // 6.1 step 1
  checkNestingDepth(t, 1);
  let can: Uint8Array;
  try { can = canonicalize(t); } catch (e) {
    if (e instanceof CanonicalizeError) { if (e.reason === "too_large") fail("too_large", e.message); else fail("noncanonical", e.message); }
    throw e;
  }
  if (can.length > SIZE_LIMITS["tally"]) fail("too_large", "tally too large");

  // 6.1 step 2: binary members
  checkBinaryStr(t["sig"], "sig", 64);
  if ("call" in t && typeof t["call"] === "string") checkBinaryStr(t["call"], "call", 32);
  if ("writ" in t && typeof t["writ"] === "string") checkBinaryStr(t["writ"], "writ", 32);
  if ("out" in t && typeof t["out"] === "string") checkBinaryStr(t["out"], "out", 32);
  if ("err" in t && t["err"] !== null && typeof t["err"] === "object" && !Array.isArray(t["err"])) {
    const errObj = t["err"] as Record<string, unknown>;
    if ("ref" in errObj && typeof errObj["ref"] === "string") checkBinaryStr(errObj["ref"], "err.ref", 32);
  }

  // 6.1 step 3
  if (!("v" in t) || t["v"] !== 1) fail("unsupported_version", "tally v must be 1");
  if (!("typ" in t) || t["typ"] !== "tally") fail("wrong_type", "typ must be tally");

  // 6.1 step 4
  checkCrit(t);

  // 6.1 step 5: tally members
  verifyTallyMembers(t);

  // 6.1 step 6: sig by W.hld
  const si = buildSigningInput("tally", 1, t);
  checkSignature(W["hld"] as string, t["sig"] as string, si);

  // 6.2 step 2: T.call == identity of K (root only)
  if (!isSub) {
    const kId = hashIdentity(canonicalize(K));
    if (t["call"] !== kId) fail("tally_mismatch", "tally.call != call identity");
  }

  // 6.2 step 3: T.writ == identity of W
  const wId = hashIdentity(canonicalize(W));
  if (t["writ"] !== wId) fail("tally_mismatch", "tally.writ != writ identity");

  // 6.2 step 4: T.op == K.op (root only)
  if (!isSub) {
    if (t["op"] !== K["op"]) fail("tally_mismatch", "tally.op != call.op");
  }

  // 6.2 step 5: if not sys/, T.acc < W.exp
  const top = t["op"] as string;
  if (!top.startsWith("sys/")) {
    if ((t["acc"] as number) >= (W["exp"] as number)) fail("expired", "tally.acc >= writ.exp");
  }

  // 6.2 step 6: if res present, T.out == hash of res
  if (res !== undefined && res !== null) {
    if (t["out"] === null) fail("tally_mismatch", "tally.out null but res present");
    const rId = hashIdentity(canonicalize(res));
    if (t["out"] !== rId) fail("tally_mismatch", "tally.out != hash of res");
  }

  // 6.2 step 7: for each max bound N in W.bnd, T.used[N] <= W.bnd[N].v
  const wBnd = W["bnd"] as Record<string, unknown>;
  const tUsed = (t["used"] ?? {}) as Record<string, number>;
  for (const [name, bound] of Object.entries(wBnd)) {
    const b = bound as { t: string; v: number };
    if (b.t === "max") {
      const u = tUsed[name] ?? 0;
      if (u > b.v) fail("out_of_bounds", `used.${name} ${u} > bound ${b.v}`);
    }
  }

  // 6.2 step 8: every writ X in T.wrt
  const wrt = (t["wrt"] ?? []) as unknown[];
  const wrtObjs: Record<string, unknown>[] = [];
  const wrtIds: string[] = [];
  for (let i = 0; i < wrt.length; i++) {
    const xRaw = wrt[i];
    if (xRaw === null || typeof xRaw !== "object" || Array.isArray(xRaw)) {
      fail("malformed", `wrt[${i}] not an object`);
    }
    const X = xRaw as Record<string, unknown>;
    verifySingleWrit(X);
    checkAttenuation(W, X, wId);
    const chainToX = [...chainToW, X];
    checkDepthBound(chainToX);
    wrtObjs.push(X);
    wrtIds.push(hashIdentity(canonicalize(X)));
  }

  // 6.2 step 9: every tally S in T.sub
  const sub = (t["sub"] ?? []) as unknown[];
  for (let i = 0; i < sub.length; i++) {
    const sRaw = sub[i];
    if (sRaw === null || typeof sRaw !== "object" || Array.isArray(sRaw)) {
      fail("sub_unmatched", `sub[${i}] not an object`);
    }
    const S = sRaw as Record<string, unknown>;
    const sWrit = S["writ"];
    if (typeof sWrit !== "string") fail("sub_unmatched", `sub[${i}].writ not a string`);
    const xIdx = wrtIds.indexOf(sWrit as string);
    if (xIdx === -1) fail("sub_unmatched", `sub[${i}].writ not in wrt`);
    const X = wrtObjs[xIdx];
    const chainToX = [...chainToW, X];
    verifyTallyNode(X, K, S, chainToX, true, undefined);
  }

  // 6.2 step 10: sum of sub.used[N] <= T.used[N]
  for (const [name, bound] of Object.entries(wBnd)) {
    const b = bound as { t: string; v: number };
    if (b.t === "max") {
      let sum = 0;
      for (const sRaw of sub) {
        const S = sRaw as Record<string, unknown>;
        const sUsed = (S["used"] ?? {}) as Record<string, number>;
        sum += sUsed[name] ?? 0;
      }
      const parentUsed = tUsed[name] ?? 0;
      if (sum > parentUsed) fail("out_of_bounds", `sub sum of ${name} ${sum} > tally used ${parentUsed}`);
    }
  }
}

function verifyTallyMembers(t: Record<string, unknown>): void {
  if (!("call" in t)) fail("malformed", "missing call");
  if (typeof t["call"] !== "string") fail("malformed", "call must be string");
  if (!("writ" in t)) fail("malformed", "missing writ");
  if (typeof t["writ"] !== "string") fail("malformed", "writ must be string");
  if (!("op" in t)) fail("malformed", "missing op");
  if (typeof t["op"] !== "string") fail("malformed", "op must be string");
  if (!("acc" in t)) fail("malformed", "missing acc");
  if (typeof t["acc"] !== "number" || !Number.isInteger(t["acc"])) fail("malformed", "acc must be integer");
  if (!("st" in t)) fail("malformed", "missing st");
  const st = t["st"];
  if (!["ok","failed","canceled","pending"].includes(st as string)) fail("malformed", `invalid st: ${st}`);
  if (!("err" in t)) fail("malformed", "missing err");
  const err = t["err"];
  if (st === "ok") {
    if (err !== null) fail("malformed", "err must be null when st=ok");
  } else {
    if (err === null || typeof err !== "object" || Array.isArray(err)) fail("malformed", "err must be object when st!=ok");
    const errObj = err as Record<string, unknown>;
    if (!("code" in errObj) || typeof errObj["code"] !== "string") fail("malformed", "err.code must be string");
  }
  if (!("out" in t)) fail("malformed", "missing out");
  if (t["out"] !== null && typeof t["out"] !== "string") fail("malformed", "out must be string or null");
  if (!("used" in t)) fail("malformed", "missing used");
  const used = t["used"];
  if (used === null || typeof used !== "object" || Array.isArray(used)) fail("malformed", "used must be object");
  for (const [k, v] of Object.entries(used as Record<string, unknown>)) {
    if (typeof v !== "number" || !Number.isInteger(v) || (v as number) < 0) {
      fail("malformed", `used.${k} must be non-negative integer`);
    }
  }
  if (!("rev" in t)) fail("malformed", "missing rev");
  const rev = t["rev"];
  if (rev !== null) {
    if (typeof rev !== "object" || Array.isArray(rev)) fail("malformed", "rev must be null or object");
    const revObj = rev as Record<string, unknown>;
    if (!("until" in revObj) || typeof revObj["until"] !== "number" || !Number.isInteger(revObj["until"] as number)) {
      fail("malformed", "rev.until must be integer");
    }
  }
  if (!("sub" in t)) fail("malformed", "missing sub");
  if (!Array.isArray(t["sub"])) fail("malformed", "sub must be array");
  for (let i = 0; i < (t["sub"] as unknown[]).length; i++) {
    const el = (t["sub"] as unknown[])[i];
    if (el === null || typeof el !== "object" || Array.isArray(el)) fail("malformed", `sub[${i}] must be object`);
  }
  if (!("wrt" in t)) fail("malformed", "missing wrt");
  if (!Array.isArray(t["wrt"])) fail("malformed", "wrt must be array");
  for (let i = 0; i < (t["wrt"] as unknown[]).length; i++) {
    const el = (t["wrt"] as unknown[])[i];
    if (el === null || typeof el !== "object" || Array.isArray(el)) fail("malformed", `wrt[${i}] must be object`);
  }
  // pending constraints
  if (st === "pending") {
    const errObj = err as Record<string, unknown>;
    if (errObj["code"] !== "pending") fail("malformed", "pending tally err.code must be 'pending'");
    if (Object.keys(used as object).length !== 0) fail("malformed", "pending tally used must be empty");
    if (t["out"] !== null) fail("malformed", "pending tally out must be null");
    if (rev !== null) fail("malformed", "pending tally rev must be null");
    if ((t["sub"] as unknown[]).length !== 0) fail("malformed", "pending tally sub must be empty");
    if ((t["wrt"] as unknown[]).length !== 0) fail("malformed", "pending tally wrt must be empty");
  }
}

// ── revoke verification (section 9.1) ────────────────────────────────────────

export function verifyRevoke(revokeRaw: unknown): void {
  if (revokeRaw === null || typeof revokeRaw !== "object" || Array.isArray(revokeRaw)) {
    fail("malformed", "revoke must be object");
  }
  const r = revokeRaw as Record<string, unknown>;

  // 9.1 step 1: 6.1 steps 1-5
  checkNestingDepth(r, 1);
  let can: Uint8Array;
  try { can = canonicalize(r); } catch (e) {
    if (e instanceof CanonicalizeError) { if (e.reason === "too_large") fail("too_large", e.message); else fail("noncanonical", e.message); }
    throw e;
  }
  if (can.length > SIZE_LIMITS["revoke"]) fail("too_large", "revoke too large");

  // binary members
  checkBinaryStr(r["sig"], "sig", 64);
  if ("writ" in r && r["writ"] !== "*" && typeof r["writ"] === "string") {
    checkBinaryStr(r["writ"], "writ", 32);
  }

  // v, typ
  if (!("v" in r) || r["v"] !== 1) fail("unsupported_version", "revoke.v must be 1");
  if (!("typ" in r) || r["typ"] !== "revoke") fail("wrong_type", "typ must be revoke");

  // crit
  checkCrit(r);

  // step 5 members: writ, iss, chain
  if (!("writ" in r)) fail("malformed", "missing writ");
  const writ = r["writ"];
  if (writ !== "*" && typeof writ !== "string") fail("malformed", "writ must be hash or '*'");

  if (!("iss" in r)) fail("malformed", "missing iss");
  if (!isValidDidKey(r["iss"])) fail("bad_key", "iss not valid did:key");

  if (!("chain" in r)) fail("malformed", "missing chain");
  const chain = r["chain"];
  if (!Array.isArray(chain)) fail("malformed", "chain must be array");
  if ((chain as unknown[]).length > MAX_CHAIN) fail("too_large", "revoke chain too long");
  for (let i = 0; i < (chain as unknown[]).length; i++) {
    const el = (chain as unknown[])[i];
    if (el === null || typeof el !== "object" || Array.isArray(el)) {
      fail("malformed", `chain[${i}] must be object`);
    }
  }
  if (writ === "*") {
    if ((chain as unknown[]).length !== 0) fail("malformed", "key-wide revoke must have empty chain");
  } else {
    if ((chain as unknown[]).length === 0) fail("malformed", "specific revoke must have non-empty chain");
  }

  // 9.1 step 2: every writ in chain passes 6.1
  const chainArr = chain as Record<string, unknown>[];
  for (let i = 0; i < chainArr.length; i++) {
    verifySingleWrit(chainArr[i]);
  }

  // 9.1 step 3: signature
  const si = buildSigningInput("revoke", 1, r);
  checkSignature(r["iss"] as string, r["sig"] as string, si);

  // 9.1 step 4: if writ != "*"
  if (writ !== "*") {
    if (chainArr[0]["prv"] !== null) fail("chain_broken", "revoke chain root prv must be null");
    for (let i = 0; i + 1 < chainArr.length; i++) {
      checkAttenuation(chainArr[i], chainArr[i + 1], writIdentity(chainArr[i]));
    }
    checkDepthBound(chainArr);
    const leafId = writIdentity(chainArr[chainArr.length - 1]);
    if (leafId !== writ) fail("chain_broken", `chain leaf ${leafId} != writ ${writ}`);
    const iss = r["iss"] as string;
    if (!chainArr.some((w) => w["iss"] === iss)) {
      fail("no_standing", "iss not an issuer in revoke chain");
    }
  }
}
