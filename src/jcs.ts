/**
 * JSON Canonicalization Scheme (RFC 8785) with Writ integer restrictions.
 * Section 1.2: member names sorted by UTF-16 code units, no whitespace,
 * strings escaped per RFC 8785 §3.2.2.2, integers in shortest decimal form.
 * Section 1.1 rule 2: numbers must be integers in [-2^53+1, 2^53-1].
 * Section 1.1 rule 7: nesting depth at most 64 (outermost = level 1).
 */

export class CanonicalizeError extends Error {
  readonly reason: "noncanonical" | "too_large";
  constructor(reason: "noncanonical" | "too_large", message: string) {
    super(message);
    this.reason = reason;
    this.name = "CanonicalizeError";
  }
}

const MAX_SAFE = 2 ** 53 - 1; // 9007199254740991

/** RFC 8785 §3.2.2.2 string escaping */
function escapeString(s: string): string {
// RFC 8785 §3.2.2.2 named escapes for specific control chars
const NAMED_ESCAPES: Record<number, string> = {
  0x08: "\\b", 0x09: "\\t", 0x0a: "\\n", 0x0c: "\\f", 0x0d: "\\r",
};

  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    if (cp === 0x22) {
      out += '\\"';
    } else if (cp === 0x5c) {
      out += "\\\\";
    } else if (cp < 0x20) {
      // control characters: named escapes for specific ones, \uXXXX for others
      out += NAMED_ESCAPES[cp] ?? ("\\u" + cp.toString(16).padStart(4, "0"));
    } else if (cp >= 0xd800 && cp <= 0xdbff) {
      // High surrogate — check if followed by low surrogate (valid pair)
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        // Valid surrogate pair: emit both chars (they will encode as emoji in UTF-8)
        out += s[i] + s[i + 1];
        i++; // skip low surrogate
      } else {
        // Lone high surrogate — spec says reject (should have been caught by checkStringForSurrogates)
        out += "\\u" + cp.toString(16).padStart(4, "0");
      }
    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
      // Lone low surrogate
      out += "\\u" + cp.toString(16).padStart(4, "0");
    } else {
      out += s[i];
    }
  }
  out += '"';
  return out;
}

/** Validate a string for unpaired surrogates. Returns error string or null. */
function checkStringForSurrogates(s: string): string | null {
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff) {
      // high surrogate — must be followed by low surrogate
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return `lone high surrogate at ${i}`;
      i++; // skip low surrogate
    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
      // lone low surrogate
      return `lone low surrogate at ${i}`;
    }
  }
  return null;
}

function canonicalizeValue(value: unknown, depth: number): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";

  if (typeof value === "number") {
    // Must be an integer in safe range
    if (!Number.isInteger(value)) {
      throw new CanonicalizeError(
        "noncanonical",
        `non-integer number: ${value}`
      );
    }
    if (value > MAX_SAFE || value < -MAX_SAFE) {
      throw new CanonicalizeError(
        "noncanonical",
        `integer out of range: ${value}`
      );
    }
    // -0 canonicalizes to 0
    if (Object.is(value, -0)) return "0";
    return value.toString();
  }

  if (typeof value === "string") {
    const surrogateErr = checkStringForSurrogates(value);
    if (surrogateErr) {
      throw new CanonicalizeError("noncanonical", surrogateErr);
    }
    return escapeString(value);
  }

  if (Array.isArray(value)) {
    if (depth > 64) throw new CanonicalizeError("too_large", `array depth ${depth} exceeds 64`);
    const items = value.map((v) => canonicalizeValue(v, depth + 1));
    return "[" + items.join(",") + "]";
  }

  if (typeof value === "object") {
    if (depth > 64) throw new CanonicalizeError("too_large", `object depth ${depth} exceeds 64`);
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);
    // Sort by UTF-16 code units (JS string comparison is already UTF-16)
    keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const members = keys.map(
      (k) => escapeString(k) + ":" + canonicalizeValue(obj[k], depth + 1)
    );
    return "{" + members.join(",") + "}";
  }

  throw new CanonicalizeError("noncanonical", `unsupported value type: ${typeof value}`);
}

/**
 * Parse JSON text and check for rule violations (duplicate keys, surrogates, etc.)
 * Returns the parsed value and checks rules 2-4 of section 1.1.
 */
export function parseAndValidate(
  text: string
): { value: unknown; duplicateKey?: string } {
  // We need to detect duplicate keys — JS JSON.parse silently takes the last value.
  // We implement a simple recursive descent to check for duplicates.
  return { value: parseWithDupCheck(text.trim()) };
}

function parseWithDupCheck(text: string): unknown {
  const parser = new JsonParser(text);
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (parser.pos < parser.text.length) {
    throw new CanonicalizeError(
      "noncanonical",
      `trailing data at position ${parser.pos}`
    );
  }
  return value;
}

class JsonParser {
  pos = 0;
  depth = 0; // current nesting depth; incremented on entering arrays/objects
  readonly text: string;
  constructor(text: string) { this.text = text; }

  skipWhitespace(): void {
    while (
      this.pos < this.text.length &&
      (this.text[this.pos] === " " ||
        this.text[this.pos] === "\t" ||
        this.text[this.pos] === "\n" ||
        this.text[this.pos] === "\r")
    ) {
      this.pos++;
    }
  }

  parseValue(): unknown {
    this.skipWhitespace();
    const ch = this.text[this.pos];
    if (ch === "{") return this.parseObject();
    if (ch === "[") return this.parseArray();
    if (ch === '"') return this.parseString();
    if (ch === "t") return this.parseLiteral("true", true);
    if (ch === "f") return this.parseLiteral("false", false);
    if (ch === "n") return this.parseLiteral("null", null);
    if (ch === "-" || (ch >= "0" && ch <= "9")) return this.parseNumber();
    throw new CanonicalizeError("noncanonical", `unexpected char '${ch}' at ${this.pos}`);
  }

  parseLiteral(word: string, val: unknown): unknown {
    if (this.text.slice(this.pos, this.pos + word.length) !== word) {
      throw new CanonicalizeError("noncanonical", `expected '${word}' at ${this.pos}`);
    }
    this.pos += word.length;
    return val;
  }

  parseNumber(): number {
    const start = this.pos;
    if (this.text[this.pos] === "-") this.pos++;
    const numStart = this.pos;
    while (this.pos < this.text.length && this.text[this.pos] >= "0" && this.text[this.pos] <= "9")
      this.pos++;
    // Check for fraction or exponent
    if (this.pos < this.text.length && (this.text[this.pos] === "." || this.text[this.pos] === "e" || this.text[this.pos] === "E")) {
      // consume them for error reporting
      while (this.pos < this.text.length && !(" \t\n\r,}]".includes(this.text[this.pos])))
        this.pos++;
      throw new CanonicalizeError("noncanonical", `non-integer number at ${start}`);
    }
    const raw = this.text.slice(start, this.pos);
    const n = Number(raw);
    if (!Number.isInteger(n) || n > MAX_SAFE || n < -MAX_SAFE) {
      if (raw === "-0") return -0;
      throw new CanonicalizeError("noncanonical", `number out of range: ${raw}`);
    }
    if (raw === "-0") return -0;
    return n;
  }

  parseString(): string {
    this.pos++; // skip opening "
    let result = "";
    while (this.pos < this.text.length && this.text[this.pos] !== '"') {
      if (this.text[this.pos] === "\\") {
        this.pos++;
        const esc = this.text[this.pos];
        if (esc === '"') { result += '"'; this.pos++; }
        else if (esc === "\\") { result += "\\"; this.pos++; }
        else if (esc === "/") { result += "/"; this.pos++; }
        else if (esc === "b") { result += "\b"; this.pos++; }
        else if (esc === "f") { result += "\f"; this.pos++; }
        else if (esc === "n") { result += "\n"; this.pos++; }
        else if (esc === "r") { result += "\r"; this.pos++; }
        else if (esc === "t") { result += "\t"; this.pos++; }
        else if (esc === "u") {
          this.pos++;
          const hex = this.text.slice(this.pos, this.pos + 4);
          this.pos += 4;
          const cp = parseInt(hex, 16);
          result += String.fromCharCode(cp);
        } else {
          throw new CanonicalizeError("noncanonical", `bad escape \\${esc}`);
        }
      } else {
        result += this.text[this.pos++];
      }
    }
    this.pos++; // skip closing "
    return result;
  }

  parseArray(): unknown[] {
    this.depth++;
    if (this.depth > 64) throw new CanonicalizeError("too_large", `nesting depth ${this.depth} exceeds 64`);
    this.pos++; // skip [
    const arr: unknown[] = [];
    this.skipWhitespace();
    if (this.text[this.pos] === "]") { this.pos++; this.depth--; return arr; }
    while (true) {
      arr.push(this.parseValue());
      this.skipWhitespace();
      if (this.text[this.pos] === "]") { this.pos++; break; }
      if (this.text[this.pos] !== ",") throw new CanonicalizeError("noncanonical", `expected , or ]`);
      this.pos++;
    }
    this.depth--;
    return arr;
  }

  parseObject(): Record<string, unknown> {
    this.depth++;
    if (this.depth > 64) throw new CanonicalizeError("too_large", `nesting depth ${this.depth} exceeds 64`);
    this.pos++; // skip {
    const obj: Record<string, unknown> = {};
    const seen = new Set<string>();
    this.skipWhitespace();
    if (this.text[this.pos] === "}") { this.pos++; this.depth--; return obj; }
    while (true) {
      this.skipWhitespace();
      if (this.text[this.pos] !== '"') throw new CanonicalizeError("noncanonical", `expected string key`);
      const key = this.parseString();
      if (seen.has(key)) {
        throw new CanonicalizeError("noncanonical", `duplicate key: "${key}"`);
      }
      seen.add(key);
      this.skipWhitespace();
      if (this.text[this.pos] !== ":") throw new CanonicalizeError("noncanonical", `expected :`);
      this.pos++;
      const val = this.parseValue();
      obj[key] = val;
      this.skipWhitespace();
      if (this.text[this.pos] === "}") { this.pos++; break; }
      if (this.text[this.pos] !== ",") throw new CanonicalizeError("noncanonical", `expected , or }`);
      this.pos++;
    }
    this.depth--;
    return obj;
  }
}

/**
 * Canonicalize parsed JSON value to bytes.
 * Throws CanonicalizeError on violations.
 */
export function canonicalize(value: unknown): Uint8Array {
  const s = canonicalizeValue(value, 1);
  return new TextEncoder().encode(s);
}

/**
 * Full pipeline: parse text (checking rules 2-4), then canonicalize.
 * Returns canonical bytes or throws CanonicalizeError.
 */
export function parseAndCanonicalize(text: string): {
  value: unknown;
  canonical: Uint8Array;
} {
  const value = parseWithDupCheck(text);
  const canonical = canonicalize(value);
  return { value, canonical };
}
