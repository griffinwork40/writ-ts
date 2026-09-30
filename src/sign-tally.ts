/**
 * Signing utilities for the executor's tally production (section 6, 1.4).
 * Zero dependencies beyond node:crypto and local encoding/jcs.
 */

import { sign as cryptoSign, createPrivateKey, createPublicKey } from "node:crypto";
import { base64urlEncode, hashIdentity, base58btcEncode } from "./encoding.ts";
import { canonicalize } from "./jcs.ts";

// PKCS#8 DER prefix for Ed25519 private key: 302e020100300506032b657004220420
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export type PrivKey = ReturnType<typeof createPrivateKey>;

/** Build a signing keypair from a 32-byte seed (hex). */
export function buildPrivKey(seedHex: string): { privKey: PrivKey; did: string } {
  const seed = Buffer.from(seedHex, "hex");
  if (seed.length !== 32) throw new Error(`seed must be 32 bytes, got ${seed.length}`);
  const der = Buffer.concat([PKCS8_PREFIX, seed]);
  const privKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const pub = createPublicKey(privKey);
  const spki = pub.export({ type: "spki", format: "der" }) as Buffer;
  // SPKI for Ed25519: 12-byte header + 32-byte key
  const pubBytes = new Uint8Array(spki.slice(12));
  const multicodec = new Uint8Array(34);
  multicodec[0] = 0xed; multicodec[1] = 0x01;
  multicodec.set(pubBytes, 2);
  const did = "did:key:z" + base58btcEncode(multicodec);
  return { privKey, did };
}

/** Sign a Writ protocol object (section 1.4): typ/v\0canonical(obj-without-sig). */
export function signObject(
  typ: string,
  v: number,
  obj: Record<string, unknown>,
  privKey: PrivKey
): string {
  const prefix = new TextEncoder().encode(`${typ}/${v}\0`);
  const withoutSig: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(obj)) {
    if (k !== "sig") withoutSig[k] = val;
  }
  const canonical = canonicalize(withoutSig);
  const input = Buffer.concat([Buffer.from(prefix), Buffer.from(canonical)]);
  const sig = cryptoSign(null, input, privKey);
  return base64urlEncode(new Uint8Array(sig));
}

/** Compute hash-identity of a signed object (section 1.5). */
export function objectIdentity(obj: Record<string, unknown>): string {
  return hashIdentity(canonicalize(obj));
}

/** Build and sign a tally object. */
export function buildTally(
  fields: {
    call: string;
    writ: string;
    op: string;
    acc: number;
    st: "ok" | "failed" | "canceled" | "pending";
    err: { code: string; ref?: string } | null;
    out: string | null;
    used: Record<string, number>;
    rev: { until: number } | null;
    sub: Record<string, unknown>[];
    wrt: Record<string, unknown>[];
  },
  privKey: PrivKey
): Record<string, unknown> {
  const obj: Record<string, unknown> = {
    v: 1,
    typ: "tally",
    call: fields.call,
    writ: fields.writ,
    op: fields.op,
    acc: fields.acc,
    st: fields.st,
    err: fields.err,
    out: fields.out,
    used: fields.used,
    rev: fields.rev,
    sub: fields.sub,
    wrt: fields.wrt,
    sig: "",
  };
  obj["sig"] = signObject("tally", 1, obj, privKey);
  return obj;
}

/** Hash a result body (canonical JSON). Returns base64url hash or null. */
export function hashBody(body: unknown): string {
  return hashIdentity(canonicalize(body as Record<string, unknown>));
}
