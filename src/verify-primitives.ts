/**
 * Shared primitives for verification: types, depth check, binary validation,
 * signing input, signature check, crit, identity, section 4 attenuation.
 */

import {
  base64urlDecode,
  base64urlEncode,
  extractPublicKey,
  hashIdentity,
  isValidDidKey,
  verifyEd25519,
} from "./encoding.ts";
import { BoundError, checkNarrows } from "./bounds.ts";
import { canonicalize, CanonicalizeError } from "./jcs.ts";

export type Reason =
  | "too_large" | "noncanonical" | "unsupported_version" | "wrong_type"
  | "unsupported_critical" | "malformed" | "bad_key" | "bad_signature"
  | "chain_broken" | "not_narrowed" | "unknown_bound" | "expired"
  | "root_not_accepted" | "wrong_executor" | "peer_mismatch" | "no_standing"
  | "forbidden_op" | "missing_arg" | "out_of_bounds" | "count_exhausted"
  | "tally_mismatch" | "sub_unmatched" | "not_reversible" | "undeliverable"
  | "unknown_outcome" | "pending";

export class VerifyError extends Error {
  readonly reason: Reason;
  constructor(reason: Reason, message: string) {
    super(message);
    this.reason = reason;
    this.name = "VerifyError";
  }
}

export const SIZE_LIMITS: Record<string, number> = {
  writ: 4096, call: 65536, tally: 262144, revoke: 65536,
};

export const MAX_CHAIN = 8;

export function fail(reason: Reason, msg: string): never {
  throw new VerifyError(reason, msg);
}

export function canFail(e: unknown, msg: string): never {
  if (e instanceof CanonicalizeError) {
    if (e.reason === "too_large") fail("too_large", e.message);
    else fail("noncanonical", e.message);
  }
  throw e;
}

// ── nesting depth (section 1.1 rule 7) ──────────────────────────────────────

export function checkNestingDepth(value: unknown, depth: number): void {
  if (Array.isArray(value)) {
    if (depth > 64) fail("too_large", `array depth ${depth} exceeds 64`);
    for (const el of value) checkNestingDepth(el, depth + 1);
  } else if (value !== null && typeof value === "object") {
    if (depth > 64) fail("too_large", `object depth ${depth} exceeds 64`);
    for (const v of Object.values(value as Record<string, unknown>)) {
      checkNestingDepth(v, depth + 1);
    }
  }
}

// ── base64url binary member validation (section 1.1 rule 5) ─────────────────

const B64URL_RE = /^[A-Za-z0-9\-_]+$/;
const B64_VALS: Record<string, number> = {};
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
  .split("").forEach((c, i) => { B64_VALS[c] = i; });
function b64Val(c: string): number { return B64_VALS[c] ?? 0; }

export function checkBinaryStr(
  raw: unknown,
  field: string,
  expectedBytes?: number,
  isNonce?: boolean
): string {
  if (typeof raw !== "string") fail("malformed", `${field} must be a string`);
  const s = raw as string;
  if (s.length === 0) fail("noncanonical", `${field} is empty`);
  if (s.length % 4 === 1) fail("noncanonical", `${field} has invalid length (len%4==1)`);
  if (!B64URL_RE.test(s)) fail("noncanonical", `${field} contains invalid base64url chars`);
  const rem = s.length % 4;
  if (rem === 2 && (b64Val(s[s.length - 1]) & 0xf) !== 0)
    fail("noncanonical", `${field} has non-zero trailing bits`);
  if (rem === 3 && (b64Val(s[s.length - 1]) & 0x3) !== 0)
    fail("noncanonical", `${field} has non-zero trailing bits`);
  const decoded = base64urlDecode(s);
  if (!decoded) fail("noncanonical", `${field} not valid base64url`);
  if (base64urlEncode(decoded!) !== s) fail("noncanonical", `${field} does not round-trip`);
  if (isNonce) {
    if (decoded!.length < 16) fail("malformed", `${field} must be at least 16 bytes`);
  } else if (expectedBytes !== undefined && decoded!.length !== expectedBytes) {
    fail("malformed", `${field} decoded to ${decoded!.length} bytes, expected ${expectedBytes}`);
  }
  return s;
}

// ── signing input (section 1.4) and Ed25519 signature check ─────────────────

export function buildSigningInput(typ: string, v: number, obj: Record<string, unknown>): Uint8Array {
  const prefix = new TextEncoder().encode(`${typ}/${v}\0`);
  const withoutSig: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(obj)) {
    if (k !== "sig") withoutSig[k] = val;
  }
  const c = canonicalize(withoutSig);
  const result = new Uint8Array(prefix.length + c.length);
  result.set(prefix);
  result.set(c, prefix.length);
  return result;
}

export function checkSignature(signerDid: string, sigStr: string, input: Uint8Array): void {
  const pub = extractPublicKey(signerDid);
  if (!pub) fail("bad_signature", "cannot extract public key");
  const sig = base64urlDecode(sigStr);
  if (!sig || sig.length !== 64) fail("bad_signature", "sig not 64 bytes");
  if (!verifyEd25519(pub, input, sig)) fail("bad_signature", "signature mismatch");
}

// ── crit (section 1.7) ───────────────────────────────────────────────────────

const UNDERSTOOD = new Set([
  "v","typ","iss","hld","bnd","prv","exp","nnc","crit","sig",
  "id","chain","from","op","args",
  "call","writ","acc","st","err","out","used","rev","sub","wrt",
]);

export function checkCrit(obj: Record<string, unknown>): void {
  if (!("crit" in obj)) return;
  const crit = obj["crit"];
  if (!Array.isArray(crit)) fail("malformed", "crit must be an array");
  for (const el of crit as unknown[]) {
    if (typeof el !== "string") fail("malformed", "crit element must be string");
  }
  for (const name of crit as string[]) {
    if (!UNDERSTOOD.has(name)) fail("unsupported_critical", `unknown crit: ${name}`);
    if (!(name in obj)) fail("malformed", `crit names absent member: ${name}`);
  }
}

// ── identity (section 1.5) ───────────────────────────────────────────────────

export function writIdentity(writ: Record<string, unknown>): string {
  return hashIdentity(canonicalize(writ));
}

// ── section 4: attenuation ───────────────────────────────────────────────────

export function checkAttenuation(
  P: Record<string, unknown>,
  C: Record<string, unknown>,
  pId: string
): void {
  if (C["iss"] !== P["hld"]) fail("chain_broken", `C.iss != P.hld`);
  if (C["prv"] !== pId) fail("chain_broken", `C.prv != identity of P`);
  if ((C["exp"] as number) > (P["exp"] as number)) fail("not_narrowed", `C.exp > P.exp`);
  const pbnd = P["bnd"] as Record<string, unknown>;
  const cbnd = C["bnd"] as Record<string, unknown>;
  const pKeys = Object.keys(pbnd).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  for (const name of pKeys) {
    if (!(name in cbnd)) fail("not_narrowed", `C.bnd missing ${name}`);
    try {
      checkNarrows(cbnd[name], pbnd[name]);
    } catch (e) {
      if (e instanceof BoundError) fail(e.reason as Reason, `${name}: ${e.message}`);
      throw e;
    }
  }
  if ("hld" in pbnd) {
    const hldBound = pbnd["hld"] as { t: string; v: unknown[] };
    if (!hldBound.v.includes(C["hld"])) fail("not_narrowed", `C.hld not in P.bnd.hld`);
  }
}

export function checkDepthBound(writs: Record<string, unknown>[]): void {
  const n = writs.length;
  for (let i = 0; i < n; i++) {
    const bnd = writs[i]["bnd"] as Record<string, unknown>;
    if ("depth" in bnd) {
      const db = bnd["depth"] as { t: string; v: number };
      if ((n - 1 - i) > db.v) fail("not_narrowed", `writ at ${i} has depth ${db.v} but ${n - 1 - i} below`);
    }
  }
}

export { isValidDidKey };
