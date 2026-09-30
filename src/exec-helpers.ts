/**
 * Helper functions for the executor: call pre-check, signature check,
 * argument bounds check, and 6.1 tally verification with a given signer.
 */

import { canonicalize } from "./jcs.ts";
import { isValidDidKey } from "./encoding.ts";
import {
  VerifyError, type Reason,
  checkNestingDepth, checkBinaryStr, buildSigningInput, checkSignature,
  checkCrit, SIZE_LIMITS, MAX_CHAIN,
} from "./verify-primitives.ts";
import { verifySingleWrit } from "./verify-writ.ts";
import { checkSatisfies, BoundError } from "./bounds.ts";

/** Section 7 step 1: verify call structure (6.1 steps 1-5), unsigned error on failure. */
export function verifyCallPre(callObj: Record<string, unknown>): void {
  checkNestingDepth(callObj, 1);
  const can = canonicalize(callObj);
  if (can.length > SIZE_LIMITS["call"]) throw new VerifyError("too_large", "call too large");

  checkBinaryStr(callObj["sig"], "sig", 64);
  if (typeof callObj["id"] === "string") checkBinaryStr(callObj["id"], "id", undefined, true);

  if (callObj["v"] !== 1) throw new VerifyError("unsupported_version", "v must be 1");
  if (callObj["typ"] !== "call") throw new VerifyError("wrong_type", "wrong type");

  checkCrit(callObj);

  if (!("id" in callObj)) throw new VerifyError("malformed", "missing id");
  if (typeof callObj["id"] !== "string") throw new VerifyError("malformed", "id not string");
  if (!("chain" in callObj)) throw new VerifyError("malformed", "missing chain");
  const chain = callObj["chain"];
  if (!Array.isArray(chain)) throw new VerifyError("malformed", "chain not array");
  if ((chain as unknown[]).length > MAX_CHAIN) throw new VerifyError("too_large", "chain too long");
  for (let i = 0; i < (chain as unknown[]).length; i++) {
    const el = (chain as unknown[])[i];
    if (el === null || typeof el !== "object" || Array.isArray(el)) {
      throw new VerifyError("malformed", `chain[${i}] not object`);
    }
  }
  if ((chain as unknown[]).length === 0) throw new VerifyError("malformed", "chain empty");
  if (!("from" in callObj)) throw new VerifyError("malformed", "missing from");
  if (!isValidDidKey(callObj["from"])) throw new VerifyError("bad_key", "from not valid did:key");
  if (!("op" in callObj)) throw new VerifyError("malformed", "missing op");
  if (typeof callObj["op"] !== "string") throw new VerifyError("malformed", "op not string");
  if (!("args" in callObj)) throw new VerifyError("malformed", "missing args");
  const args = callObj["args"];
  if (args === null || typeof args !== "object" || Array.isArray(args)) {
    throw new VerifyError("malformed", "args not object");
  }
}

/** Section 7 step 2: verify each writ in chain and the call signature. */
export function verifyCallSig(callObj: Record<string, unknown>): void {
  const chain = callObj["chain"] as Record<string, unknown>[];
  for (const w of chain) verifySingleWrit(w);
  const si = buildSigningInput("call", 1, callObj);
  checkSignature(callObj["from"] as string, callObj["sig"] as string, si);
}

/** Section 7.2: check args satisfy leaf bounds. Returns reason code or null. */
export function checkArgsAgainstBounds(
  callObj: Record<string, unknown>,
  leafWrit: Record<string, unknown>
): Reason | null {
  const bnd = leafWrit["bnd"] as Record<string, unknown>;
  const argsObj = callObj["args"] as Record<string, unknown>;
  const appBounds: [string, unknown][] = [];
  for (const [name, bound] of Object.entries(bnd)) {
    if (name === "act" || name === "hld" || name === "depth") continue;
    if ((bound as { t: string }).t === "count") continue;
    appBounds.push([name, bound]);
  }
  appBounds.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  for (const [name] of appBounds) {
    if (!(name in argsObj)) return "missing_arg";
  }
  for (const [name, bound] of appBounds) {
    try {
      checkSatisfies(bound, argsObj[name]);
    } catch (e) {
      if (e instanceof BoundError) return e.reason as Reason;
      throw e;
    }
  }
  return null;
}

/**
 * Section 6.1 tally verification with a given signer DID.
 * Used by sys/undo to check the target tally.
 */
export function verifyTallyAs6_1(tt: Record<string, unknown>, signerDid: string): void {
  checkNestingDepth(tt, 1);
  const can = canonicalize(tt);
  if (can.length > SIZE_LIMITS["tally"]) throw new VerifyError("too_large", "tally too large");

  checkBinaryStr(tt["sig"], "sig", 64);
  if (typeof tt["call"] === "string") checkBinaryStr(tt["call"], "call", 32);
  if (typeof tt["writ"] === "string") checkBinaryStr(tt["writ"], "writ", 32);
  if (typeof tt["out"] === "string") checkBinaryStr(tt["out"], "out", 32);

  if (tt["v"] !== 1) throw new VerifyError("unsupported_version", "v must be 1");
  if (tt["typ"] !== "tally") throw new VerifyError("wrong_type", "wrong type");

  checkCrit(tt);

  const required = ["call","writ","op","acc","st","err","out","used","rev","sub","wrt"];
  for (const m of required) {
    if (!(m in tt)) throw new VerifyError("malformed", `missing ${m}`);
  }
  if (typeof tt["call"] !== "string") throw new VerifyError("malformed", "call not string");
  if (typeof tt["writ"] !== "string") throw new VerifyError("malformed", "writ not string");
  if (typeof tt["op"] !== "string") throw new VerifyError("malformed", "op not string");
  if (typeof tt["acc"] !== "number") throw new VerifyError("malformed", "acc not number");
  const validSt = new Set(["ok","failed","canceled","pending"]);
  if (!validSt.has(tt["st"] as string)) throw new VerifyError("malformed", "invalid st");
  const st = tt["st"] as string;
  if (st === "ok") {
    if (tt["err"] !== null) throw new VerifyError("malformed", "err not null for ok");
  } else {
    if (tt["err"] === null || typeof tt["err"] !== "object") {
      throw new VerifyError("malformed", "err must be object for non-ok");
    }
    const err = tt["err"] as Record<string, unknown>;
    if (typeof err["code"] !== "string") throw new VerifyError("malformed", "err.code not string");
  }
  if (!Array.isArray(tt["sub"])) throw new VerifyError("malformed", "sub not array");
  if (!Array.isArray(tt["wrt"])) throw new VerifyError("malformed", "wrt not array");
  if (tt["used"] === null || typeof tt["used"] !== "object" || Array.isArray(tt["used"])) {
    throw new VerifyError("malformed", "used not object");
  }
  if (st === "pending") {
    const err = tt["err"] as Record<string, unknown>;
    if (err["code"] !== "pending") throw new VerifyError("malformed", "pending code not pending");
    if (Object.keys(tt["used"] as object).length !== 0) throw new VerifyError("malformed", "pending used not empty");
    if (tt["rev"] !== null) throw new VerifyError("malformed", "pending rev not null");
    if (tt["out"] !== null) throw new VerifyError("malformed", "pending out not null");
    if ((tt["sub"] as unknown[]).length !== 0) throw new VerifyError("malformed", "pending sub not empty");
    if ((tt["wrt"] as unknown[]).length !== 0) throw new VerifyError("malformed", "pending wrt not empty");
  }

  const si = buildSigningInput("tally", 1, tt);
  checkSignature(signerDid, tt["sig"] as string, si);
}
