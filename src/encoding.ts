/**
 * Encoding utilities: base64url, base58btc, did:key, SHA-256, Ed25519.
 * Zero runtime dependencies — uses node:crypto only.
 */
import { createHash, verify as cryptoVerify, createPublicKey } from "node:crypto";

// ── base64url (RFC 4648 §5, no padding) ─────────────────────────────────────

const B64URL_CHARS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_MAP: Record<string, number> = {};
for (let i = 0; i < B64URL_CHARS.length; i++) B64URL_MAP[B64URL_CHARS[i]] = i;

export function base64urlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64URL_CHARS[b0 >> 2];
    out += B64URL_CHARS[((b0 & 3) << 4) | (b1 >> 4)];
    if (i + 1 < bytes.length) out += B64URL_CHARS[((b1 & 0xf) << 2) | (b2 >> 6)];
    if (i + 2 < bytes.length) out += B64URL_CHARS[b2 & 0x3f];
  }
  return out;
}

/**
 * Validates and decodes a base64url string.
 * Returns null if invalid (padding, bad chars, bad trailing bits, len%4==1).
 */
export function base64urlDecode(s: string): Uint8Array | null {
  if (s.length === 0) return null;
  // length congruent to 1 mod 4 is undecodable
  if (s.length % 4 === 1) return null;
  for (const ch of s) {
    if (B64URL_MAP[ch] === undefined) return null; // includes padding '='
  }
  // check trailing bits: last char encodes only 2 or 4 useful bits
  const rem = s.length % 4;
  if (rem === 2) {
    // last char contributes 2 bits of padding, must be zero
    const last = B64URL_MAP[s[s.length - 1]];
    if ((last & 0xf) !== 0) return null;
  } else if (rem === 3) {
    // last char contributes 4 bits of padding, must be zero
    const last = B64URL_MAP[s[s.length - 1]];
    if ((last & 0x3) !== 0) return null;
  }
  // decode
  const byteLen =
    rem === 0
      ? (s.length / 4) * 3
      : rem === 2
        ? Math.floor(s.length / 4) * 3 + 1
        : Math.floor(s.length / 4) * 3 + 2;
  const out = new Uint8Array(byteLen);
  let pos = 0;
  for (let i = 0; i < s.length; ) {
    const c0 = B64URL_MAP[s[i++]] ?? 0;
    const c1 = B64URL_MAP[s[i++]] ?? 0;
    const c2 = i < s.length ? (B64URL_MAP[s[i++]] ?? 0) : 0;
    const c3 = i < s.length ? (B64URL_MAP[s[i++]] ?? 0) : 0;
    out[pos++] = (c0 << 2) | (c1 >> 4);
    if (pos < byteLen) out[pos++] = ((c1 & 0xf) << 4) | (c2 >> 2);
    if (pos < byteLen) out[pos++] = ((c2 & 3) << 6) | c3;
  }
  return out;
}

// ── base58btc ────────────────────────────────────────────────────────────────

const B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP: Record<string, number> = {};
for (let i = 0; i < B58_CHARS.length; i++) B58_MAP[B58_CHARS[i]] = i;

export function base58btcEncode(bytes: Uint8Array): string {
  let leading = 0;
  while (leading < bytes.length && bytes[leading] === 0) leading++;
  const digits: number[] = [];
  for (let i = leading; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] * 256;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  return (
    "1".repeat(leading) +
    digits
      .reverse()
      .map((d) => B58_CHARS[d])
      .join("")
  );
}

export function base58btcDecode(s: string): Uint8Array | null {
  let leading = 0;
  while (leading < s.length && s[leading] === "1") leading++;
  const bytes: number[] = [];
  for (let i = leading; i < s.length; i++) {
    const v = B58_MAP[s[i]];
    if (v === undefined) return null;
    let carry = v;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const result = new Uint8Array(leading + bytes.length);
  for (let i = 0; i < bytes.length; i++)
    result[leading + i] = bytes[bytes.length - 1 - i];
  return result;
}

// ── did:key (Ed25519) ────────────────────────────────────────────────────────

const DID_KEY_PREFIX = "did:key:z";
// multicodec prefix for Ed25519 public key: 0xed 0x01
const ED25519_PREFIX = new Uint8Array([0xed, 0x01]);

export function isValidDidKey(s: unknown): s is string {
  if (typeof s !== "string") return false;
  if (!s.startsWith(DID_KEY_PREFIX)) return false;
  const encoded = s.slice(DID_KEY_PREFIX.length); // the z+base58btc part
  const decoded = base58btcDecode(encoded);
  if (!decoded) return false;
  if (decoded.length !== 34) return false; // 2 prefix + 32 key bytes
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) return false;
  return true;
}

export function extractPublicKey(did: string): Uint8Array | null {
  if (!isValidDidKey(did)) return null;
  const encoded = did.slice(DID_KEY_PREFIX.length);
  const decoded = base58btcDecode(encoded);
  if (!decoded) return null;
  return decoded.slice(2); // skip 0xed 0x01
}

// ── SHA-256 and hash identity ────────────────────────────────────────────────

export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

export function hashIdentity(canonicalBytes: Uint8Array): string {
  return base64urlEncode(sha256(canonicalBytes));
}

// ── Ed25519 signature verification ──────────────────────────────────────────

// Ed25519 SPKI DER prefix: 30 2a 30 05 06 03 2b 65 70 03 21 00
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function verifyEd25519(
  publicKeyBytes: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): boolean {
  try {
    const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyBytes)]);
    const pubKey = createPublicKey({ key: der, format: "der", type: "spki" });
    return cryptoVerify(null, Buffer.from(message), pubKey, Buffer.from(signature));
  } catch {
    return false;
  }
}
