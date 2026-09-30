/**
 * Bound checking: section 3 of the Writ spec.
 * Covers: checkBound(), narrowsBound(), satisfiesBound().
 */

export type BoundType = "max" | "count" | "prefix" | "set" | "window";

export interface Bound {
  t: BoundType;
  v: unknown;
}

// Reason codes used here
export type BoundReason =
  | "malformed"
  | "noncanonical"
  | "unknown_bound"
  | "not_narrowed"
  | "out_of_bounds"
  | "bad_key";

export class BoundError extends Error {
  readonly reason: BoundReason;
  constructor(reason: BoundReason, message: string) {
    super(message);
    this.reason = reason;
    this.name = "BoundError";
  }
}

const KNOWN_TYPES = new Set<string>(["max", "count", "prefix", "set", "window"]);

/**
 * Check that a raw value is a valid bound per section 3.
 * Order: object, members exactly t+v, t is string (malformed);
 *        t in table (unknown_bound); v has correct JSON type (malformed);
 *        value rule (noncanonical).
 * For `set`: element by element in array order, each element type (malformed)
 *            before duplicate check (noncanonical).
 * For `window`: shape check (malformed) before lo <= hi (noncanonical).
 */
export function checkBound(raw: unknown): Bound {
  // Must be an object
  if (
    raw === null ||
    typeof raw !== "object" ||
    Array.isArray(raw)
  ) {
    throw new BoundError("malformed", "bound must be an object");
  }
  const obj = raw as Record<string, unknown>;
  const keys = Object.keys(obj);
  // Must have exactly "t" and "v" — no more, no less
  if (keys.length !== 2 || !("t" in obj) || !("v" in obj)) {
    throw new BoundError(
      "malformed",
      `bound must have exactly t and v, got: ${keys.join(",")}`
    );
  }
  // t must be a string
  if (typeof obj["t"] !== "string") {
    throw new BoundError("malformed", "bound.t must be a string");
  }
  const t = obj["t"] as string;
  // t must be in the table
  if (!KNOWN_TYPES.has(t)) {
    throw new BoundError("unknown_bound", `unknown bound type: ${t}`);
  }
  const v = obj["v"];
  // v must have the right JSON type for t
  switch (t) {
    case "max":
    case "count":
      if (typeof v !== "number" || !Number.isInteger(v)) {
        throw new BoundError("malformed", `${t}.v must be an integer`);
      }
      if ((v as number) < 0) {
        throw new BoundError("noncanonical", `${t}.v must be >= 0`);
      }
      break;
    case "prefix":
      if (typeof v !== "string") {
        throw new BoundError("malformed", "prefix.v must be a string");
      }
      break;
    case "set":
      if (!Array.isArray(v)) {
        throw new BoundError("malformed", "set.v must be an array");
      }
      checkSetElements(v);
      break;
    case "window": {
      // Shape: array of two integers (malformed before lo <= hi check)
      if (!Array.isArray(v) || v.length !== 2) {
        throw new BoundError(
          "malformed",
          "window.v must be an array of two elements"
        );
      }
      if (typeof v[0] !== "number" || !Number.isInteger(v[0])) {
        throw new BoundError("malformed", "window lo must be an integer");
      }
      if (typeof v[1] !== "number" || !Number.isInteger(v[1])) {
        throw new BoundError("malformed", "window hi must be an integer");
      }
      if ((v[0] as number) > (v[1] as number)) {
        throw new BoundError(
          "noncanonical",
          `window lo ${v[0]} > hi ${v[1]}`
        );
      }
      break;
    }
  }
  return { t: t as BoundType, v };
}

/** Check set elements: type (malformed) then duplicate (noncanonical). */
function checkSetElements(arr: unknown[]): void {
  const seen: unknown[] = [];
  for (let i = 0; i < arr.length; i++) {
    const el = arr[i];
    if (typeof el !== "string" && (typeof el !== "number" || !Number.isInteger(el))) {
      throw new BoundError(
        "malformed",
        `set element at ${i} must be a string or integer`
      );
    }
    // Check duplicate: must match by value AND type
    for (const prev of seen) {
      if (prev === el) {
        throw new BoundError(
          "noncanonical",
          `duplicate element in set: ${JSON.stringify(el)}`
        );
      }
    }
    seen.push(el);
  }
}

/**
 * Section 3.1: prefix match.
 * P matches S when: S==P, or P ends with "/" and S starts with P,
 * or S starts with P+"/".
 */
export function prefixMatches(P: string, S: string): boolean {
  if (S === P) return true;
  if (P.endsWith("/") && S.startsWith(P)) return true;
  if (S.startsWith(P + "/")) return true;
  return false;
}

/**
 * Section 3 narrowing table: does child narrow parent?
 * Throws BoundError("not_narrowed") if not.
 * Both child and parent must already be valid bounds of the same type.
 * Type mismatch throws not_narrowed.
 */
export function checkNarrows(childRaw: unknown, parentRaw: unknown): void {
  // Validate child first (section 14: "section 3 on the child, then parent, then type change, then rule")
  const child = checkBound(childRaw);
  const parent = checkBound(parentRaw);

  if (child.t !== parent.t) {
    throw new BoundError("not_narrowed", `type mismatch: ${child.t} vs ${parent.t}`);
  }

  switch (child.t) {
    case "max":
    case "count": {
      const cv = child.v as number;
      const pv = parent.v as number;
      if (cv > pv) {
        throw new BoundError(
          "not_narrowed",
          `${child.t} child ${cv} > parent ${pv}`
        );
      }
      break;
    }
    case "prefix": {
      const cv = child.v as string;
      const pv = parent.v as string;
      // parent matches child means: child.v is "more specific" than parent.v
      // i.e. parent.v matches child.v under section 3.1
      if (!prefixMatches(pv, cv)) {
        throw new BoundError(
          "not_narrowed",
          `prefix child "${cv}" does not narrow parent "${pv}"`
        );
      }
      break;
    }
    case "set": {
      const cv = child.v as unknown[];
      const pv = parent.v as unknown[];
      // Every child element must be in parent
      for (const el of cv) {
        let found = false;
        for (const pel of pv) {
          if (el === pel) { found = true; break; }
        }
        if (!found) {
          throw new BoundError(
            "not_narrowed",
            `set child element ${JSON.stringify(el)} not in parent`
          );
        }
      }
      break;
    }
    case "window": {
      const [clo, chi] = child.v as [number, number];
      const [plo, phi] = parent.v as [number, number];
      if (clo < plo || chi > phi) {
        throw new BoundError(
          "not_narrowed",
          `window [${clo},${chi}] not inside parent [${plo},${phi}]`
        );
      }
      break;
    }
  }
}

/**
 * Section 3: does arg satisfy bound?
 * Throws BoundError("out_of_bounds") if not.
 * Not defined for count (never called for count).
 */
export function checkSatisfies(boundRaw: unknown, arg: unknown): void {
  const bound = checkBound(boundRaw);
  switch (bound.t) {
    case "max": {
      const v = bound.v as number;
      if (typeof arg !== "number" || !Number.isInteger(arg)) {
        throw new BoundError("out_of_bounds", `max requires integer arg, got ${typeof arg}`);
      }
      if ((arg as number) < 0 || (arg as number) > v) {
        throw new BoundError("out_of_bounds", `${arg} not in [0, ${v}]`);
      }
      break;
    }
    case "prefix": {
      const v = bound.v as string;
      if (typeof arg !== "string") {
        throw new BoundError("out_of_bounds", `prefix requires string arg`);
      }
      if (!prefixMatches(v, arg as string)) {
        throw new BoundError("out_of_bounds", `"${arg}" not matched by prefix "${v}"`);
      }
      break;
    }
    case "set": {
      const v = bound.v as unknown[];
      let found = false;
      for (const el of v) {
        if (el === arg) { found = true; break; }
      }
      if (!found) {
        throw new BoundError("out_of_bounds", `${JSON.stringify(arg)} not in set`);
      }
      break;
    }
    case "window": {
      const [lo, hi] = bound.v as [number, number];
      if (typeof arg !== "number" || !Number.isInteger(arg)) {
        throw new BoundError("out_of_bounds", `window requires integer arg`);
      }
      if ((arg as number) < lo || (arg as number) > hi) {
        throw new BoundError("out_of_bounds", `${arg} not in [${lo}, ${hi}]`);
      }
      break;
    }
    case "count":
      throw new BoundError("malformed", "satisfies not defined for count");
  }
}
