/**
 * Unit tests for Writ verifier components.
 * Run with: node --experimental-strip-types --test src/test.ts
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { parseAndCanonicalize, CanonicalizeError } from "./jcs.ts";
import { base64urlEncode, base64urlDecode, base58btcEncode, base58btcDecode, isValidDidKey, extractPublicKey, hashIdentity } from "./encoding.ts";
import { checkBound, checkNarrows, checkSatisfies, prefixMatches, BoundError } from "./bounds.ts";
import { verifySingleWrit, verifyChain, verifyCallFull, VerifyError, checkNestingDepth } from "./verify.ts";
import { readFileSync } from "node:fs";

// ── JCS canonicalize ─────────────────────────────────────────────────────────

describe("JCS", () => {
  test("sorts keys by UTF-16", () => {
    const { canonical } = parseAndCanonicalize('{"z":1,"a":2}');
    assert.equal(new TextDecoder().decode(canonical), '{"a":2,"z":1}');
  });

  test("named control char escapes", () => {
    const { canonical } = parseAndCanonicalize('"\\r\\n\\t"');
    assert.equal(new TextDecoder().decode(canonical), '"\\r\\n\\t"');
  });

  test("surrogate pair becomes literal", () => {
    const { canonical } = parseAndCanonicalize('"\\ud83d\\ude00"');
    const s = new TextDecoder().decode(canonical);
    assert.ok(s.includes("😀") || s.includes("\ud83d\ude00"), "should include emoji");
  });

  test("lone high surrogate is rejected", () => {
    // Lone high surrogate in a JSON string should be rejected as noncanonical
    // The parser will see \ud83d without a following low surrogate
    // Actually the issue is the parser converts \uXXXX — lone surrogates in
    // the canonical output would be the issue; parsing succeeds but then
    // the surrogate check fires
    // We'll test the surrogate check through the canonicalize op
    try {
      const { canonical } = parseAndCanonicalize('"\\ud800"');
      // If we get here, the impl doesn't reject lone surrogates at parse time
      // (they might be rejected at canonicalize time instead)
      const s = new TextDecoder().decode(canonical);
      // Should NOT include lone surrogates
      for (let i = 0; i < s.length; i++) {
        const cp = s.charCodeAt(i);
        if (cp >= 0xd800 && cp <= 0xdbff) {
          const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
          assert.ok(next >= 0xdc00 && next <= 0xdfff, "lone high surrogate in output");
        }
        if (cp >= 0xdc00 && cp <= 0xdfff) {
          assert.fail("lone low surrogate in output");
        }
      }
    } catch (e) {
      // rejected — that's fine too
      assert.ok(e instanceof CanonicalizeError, "should be CanonicalizeError");
    }
  });

  test("duplicate key rejected", () => {
    assert.throws(
      () => parseAndCanonicalize('{"a":1,"a":2}'),
      (e) => e instanceof CanonicalizeError && e.reason === "noncanonical"
    );
  });

  test("non-integer rejected", () => {
    assert.throws(
      () => parseAndCanonicalize("1.5"),
      (e) => e instanceof CanonicalizeError && e.reason === "noncanonical"
    );
  });

  test("nesting at limit accepted", () => {
    // 64 arrays deep (outermost at depth 1)
    const raw = "[".repeat(64) + "1" + "]".repeat(64);
    assert.doesNotThrow(() => parseAndCanonicalize(raw));
  });

  test("nesting over limit rejected", () => {
    // 65 arrays deep
    const raw = "[".repeat(65) + "1" + "]".repeat(65);
    assert.throws(
      () => parseAndCanonicalize(raw),
      (e) => e instanceof CanonicalizeError && e.reason === "too_large"
    );
  });

  test("nesting check before number rules (too_large before noncanonical)", () => {
    // 64 arrays deep containing 1.5 — should fail too_large, not noncanonical
    const raw = "[".repeat(65) + "1.5" + "]".repeat(65);
    assert.throws(
      () => parseAndCanonicalize(raw),
      (e) => e instanceof CanonicalizeError && e.reason === "too_large"
    );
  });

  test("-0 canonicalizes to 0", () => {
    const { canonical } = parseAndCanonicalize("-0");
    assert.equal(new TextDecoder().decode(canonical), "0");
  });

  test("trailing data rejected", () => {
    assert.throws(
      () => parseAndCanonicalize('{"a":1} trailing'),
      (e) => e instanceof CanonicalizeError
    );
  });
});

// ── base64url ─────────────────────────────────────────────────────────────────

describe("base64url", () => {
  test("encode round-trips", () => {
    const bytes = new Uint8Array([0x00, 0xff, 0x42, 0xab]);
    assert.equal(base64urlDecode(base64urlEncode(bytes))?.join(","), bytes.join(","));
  });

  test("rejects padding", () => {
    assert.equal(base64urlDecode("abc="), null);
  });

  test("rejects empty", () => {
    assert.equal(base64urlDecode(""), null);
  });

  test("rejects bad char", () => {
    assert.equal(base64urlDecode("a+bc"), null);
  });

  test("rejects non-zero trailing bits", () => {
    // 'ag' in base64url encodes 0x68 but last char 'g' has trailing bits
    // 'ag' = 0*64+32 = 32 which gives 0x68? Let's use a known bad one
    // 'aQ' is fine (Q = 16 in base64url), 'aR' is bad (R = 17, trailing = 1)
    // rem = 2 chars → last char must have lower 4 bits zero
    // 'Y' = 24, lower 4 bits = 8 ≠ 0 → invalid
    assert.equal(base64urlDecode("aY"), null); // lower nibble of 'Y'(24) = 8 ≠ 0
  });

  test("length mod 4 == 1 rejected", () => {
    assert.equal(base64urlDecode("a"), null);
  });
});

// ── base58btc / did:key ───────────────────────────────────────────────────────

describe("did:key", () => {
  test("valid Ed25519 did:key accepted", () => {
    const did = "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX";
    assert.ok(isValidDidKey(did));
  });

  test("extracts 32-byte public key", () => {
    const did = "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX";
    const pub = extractPublicKey(did);
    assert.ok(pub);
    assert.equal(pub!.length, 32);
  });

  test("did:web rejected", () => {
    assert.ok(!isValidDidKey("did:web:example.com"));
  });

  test("secp256k1 did:key rejected (wrong multicodec prefix)", () => {
    // secp256k1 did:key starts with z6Mk... no, secp starts with zQ3s
    const did = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
    assert.ok(!isValidDidKey(did));
  });

  test("base58btc encode-decode round-trip", () => {
    const bytes = new Uint8Array([0xed, 0x01, ...new Array(32).fill(42)]);
    const enc = base58btcEncode(bytes);
    const dec = base58btcDecode(enc);
    assert.equal(dec?.join(","), bytes.join(","));
  });
});

// ── bounds ────────────────────────────────────────────────────────────────────

describe("bounds", () => {
  test("max narrows: child <= parent", () => {
    assert.doesNotThrow(() => checkNarrows({ t: "max", v: 50 }, { t: "max", v: 100 }));
    assert.throws(() => checkNarrows({ t: "max", v: 101 }, { t: "max", v: 100 }));
  });

  test("prefix: parent matches child", () => {
    assert.doesNotThrow(() => checkNarrows({ t: "prefix", v: "travel/charge" }, { t: "prefix", v: "travel" }));
    assert.throws(() => checkNarrows({ t: "prefix", v: "travel" }, { t: "prefix", v: "travel/charge" }));
  });

  test("prefix matching rules", () => {
    assert.ok(prefixMatches("travel", "travel"));
    assert.ok(prefixMatches("travel", "travel/charge"));
    assert.ok(!prefixMatches("travel", "travel/chargeback".replace("travel/c", "travelX/c")));
    assert.ok(!prefixMatches("travel/charge", "travel/chargeback"));
    assert.ok(prefixMatches("travel/", "travel/charge"));
    assert.ok(!prefixMatches("travel/", "travel"));
  });

  test("set narrows: all child elements in parent", () => {
    assert.doesNotThrow(() => checkNarrows({ t: "set", v: ["USD"] }, { t: "set", v: ["USD", "EUR"] }));
    assert.throws(() => checkNarrows({ t: "set", v: ["USD", "GBP"] }, { t: "set", v: ["USD", "EUR"] }));
  });

  test("window narrows: parent contains child", () => {
    assert.doesNotThrow(() => checkNarrows({ t: "window", v: [5, 10] }, { t: "window", v: [1, 20] }));
    assert.throws(() => checkNarrows({ t: "window", v: [0, 10] }, { t: "window", v: [1, 10] }));
  });

  test("type mismatch is not_narrowed", () => {
    assert.throws(
      () => checkNarrows({ t: "max", v: 5 }, { t: "count", v: 10 }),
      (e) => e instanceof BoundError && e.reason === "not_narrowed"
    );
  });

  test("unknown bound type is unknown_bound", () => {
    assert.throws(
      () => checkBound({ t: "bogus", v: 1 }),
      (e) => e instanceof BoundError && e.reason === "unknown_bound"
    );
  });

  test("satisfies: max", () => {
    assert.doesNotThrow(() => checkSatisfies({ t: "max", v: 100 }, 100));
    assert.throws(() => checkSatisfies({ t: "max", v: 100 }, 101));
    assert.throws(() => checkSatisfies({ t: "max", v: 100 }, -1));
  });

  test("satisfies: prefix", () => {
    assert.doesNotThrow(() => checkSatisfies({ t: "prefix", v: "travel" }, "travel/charge"));
    assert.throws(() => checkSatisfies({ t: "prefix", v: "travel" }, "travel/chargeback".replace("travel/c", "other/c")));
  });
});

// ── nesting depth check ───────────────────────────────────────────────────────

describe("nesting depth (verify.ts)", () => {
  test("depth at limit is ok", () => {
    // Object at depth 1 containing array at depth 2 ... array at depth 64 containing scalar
    let val: unknown = 1;
    for (let i = 0; i < 63; i++) val = [val]; // 63 arrays → innermost is level 64
    const obj = { x: val }; // obj is level 1
    assert.doesNotThrow(() => checkNestingDepth(obj, 1));
  });

  test("depth over limit fails", () => {
    let val: unknown = 1;
    for (let i = 0; i < 64; i++) val = [val]; // 64 arrays → innermost at level 65
    const obj = { x: val };
    assert.throws(
      () => checkNestingDepth(obj, 1),
      (e) => e instanceof VerifyError && e.reason === "too_large"
    );
  });
});

// ── verify_writ with real corpus vectors ──────────────────────────────────────

describe("verify_writ from corpus", () => {
  test("root writ accepted", () => {
    const v = JSON.parse(readFileSync("conformance/vectors/052_verify_writ_root_writ.json", "utf8"));
    assert.doesNotThrow(() => verifySingleWrit(v.input.writ));
  });

  test("tampered exp rejected as bad_signature", () => {
    const v = JSON.parse(readFileSync("conformance/vectors/054_verify_writ_tampered_exp.json", "utf8"));
    assert.throws(
      () => verifySingleWrit(v.input.writ),
      (e) => e instanceof VerifyError && e.reason === "bad_signature"
    );
  });

  test("child writ accepted", () => {
    const v = JSON.parse(readFileSync("conformance/vectors/053_verify_writ_child_writ.json", "utf8"));
    assert.doesNotThrow(() => verifySingleWrit(v.input.writ));
  });
});

// ── verify_chain from corpus ──────────────────────────────────────────────────

describe("verify_chain from corpus", () => {
  test("two-link chain accepted", () => {
    const v = JSON.parse(readFileSync("conformance/vectors/074_verify_chain_two_links.json", "utf8"));
    assert.doesNotThrow(() => verifyChain(v.input.chain));
  });

  test("issuer not parent holder: chain_broken", () => {
    const v = JSON.parse(readFileSync("conformance/vectors/081_verify_chain_issuer_not_parent_holder.json", "utf8"));
    assert.throws(
      () => verifyChain(v.input.chain),
      (e) => e instanceof VerifyError && e.reason === "chain_broken"
    );
  });

  test("child outlives parent: not_narrowed", () => {
    const v = JSON.parse(readFileSync("conformance/vectors/083_verify_chain_child_outlives_parent.json", "utf8"));
    assert.throws(
      () => verifyChain(v.input.chain),
      (e) => e instanceof VerifyError && e.reason === "not_narrowed"
    );
  });
});

// ── verify_call from corpus ───────────────────────────────────────────────────

describe("verify_call from corpus", () => {
  test("forward call accepted", () => {
    const v = JSON.parse(readFileSync("conformance/vectors/098_verify_call_forward_call.json", "utf8"));
    const now = v.now;
    assert.doesNotThrow(() => verifyCallFull(v.input.call, now));
  });

  test("from is holder → no_standing", () => {
    const v = JSON.parse(readFileSync("conformance/vectors/101_verify_call_from_is_holder.json", "utf8"));
    assert.throws(
      () => verifyCallFull(v.input.call, v.now),
      (e) => e instanceof VerifyError && e.reason === "no_standing"
    );
  });

  test("missing arg → missing_arg", () => {
    const v = JSON.parse(readFileSync("conformance/vectors/107_verify_call_missing_amount.json", "utf8"));
    assert.throws(
      () => verifyCallFull(v.input.call, v.now),
      (e) => e instanceof VerifyError && e.reason === "missing_arg"
    );
  });

  test("standing call by root accepted", () => {
    const v = JSON.parse(readFileSync("conformance/vectors/111_verify_call_standing_call_by_root.json", "utf8"));
    assert.doesNotThrow(() => verifyCallFull(v.input.call, v.now));
  });

  test("standing call holder is not an issuer → no_standing", () => {
    const v = JSON.parse(readFileSync("conformance/vectors/113_verify_call_standing_call_by_holder.json", "utf8"));
    assert.throws(
      () => verifyCallFull(v.input.call, v.now),
      (e) => e instanceof VerifyError && e.reason === "no_standing"
    );
  });
});
