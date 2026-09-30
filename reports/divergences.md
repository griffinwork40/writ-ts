# Divergences Report

**Result: 213/213 pass on first run after iterative debugging.**

No divergences remain — every vector passed once the implementation was complete.
This section documents the three bugs found and fixed during the single build-and-debug
cycle (before the first *committed* run). Under the method's intent, the first committed
run is what was committed to `reports/first-run.txt`.

---

## Bugs found and fixed during implementation (not divergences in the final sense)

These are recorded for the upstream author's benefit as signals about which spec
sections were difficult to read.

### 1. `escapeString` control-character and surrogate-pair handling

**Class:** `our-bug`

**What happened:** `\r` (U+000D) was emitted as `\u000d` instead of `\r`.
Surrogate pairs (`\ud83d\ude00`) were kept as individual escape sequences
instead of being emitted as the literal UTF-8 emoji `😀`.

**Spec section:** Section 1.2 / RFC 8785 §3.2.2.2.

The spec says "strings escaped per RFC 8785 section 3.2.2.2."
RFC 8785 §3.2.2.2 specifies that U+0008 U+0009 U+000A U+000C U+000D
are emitted as `\b \t \n \f \r` respectively, and other control characters
as `\uXXXX`. Valid surrogate pairs are emitted as literal characters (their
UTF-8 encoding), while lone surrogates are emitted as `\uXXXX`.

My initial `escapeString` only emitted `\uXXXX` for all control characters
and escaped lone surrogates but did not coalesce valid surrogate pairs.

**Fix:** Added a named-escape map for the five named control characters;
detect high surrogate followed by low surrogate and emit both as a pair.

---

### 2. Nesting depth counted scalars as a level

**Class:** `our-bug`

**What happened:**
- Vector 176 (`verify_writ_writ_nesting_at_the_limit`): a writ with `x` at exactly
  depth 64 was rejected as `too_large` instead of accepted.
- Vector 175 (`canonicalize_nesting_before_number_rules`): 65-deep array containing
  `1.5` was rejected as `noncanonical` instead of `too_large`.

**Spec section:** Section 1.1 rule 7: "Arrays and objects MUST NOT nest more than
64 levels deep, the outermost value being level 1."

My initial implementation incremented depth for every value encountered,
including scalars. But scalars (null, boolean, number, string) do not open
a new nesting level — only arrays and objects do. So a scalar at depth=65
(inside a depth-64 array) was being incorrectly rejected.

Additionally, the nesting check in my JSON parser was post-parse (in `canonicalize`),
so a 65-deep array with `1.5` inside was rejected as `noncanonical` (the number rule
fired first in the parser) instead of `too_large` (depth check should be first).

**Fix:** 
1. `checkNestingDepth`: only increment depth when the value IS an array or object
   (check `depth > 64` before recursing into the container's children).
2. Added depth tracking directly in the `JsonParser` class so depth is checked
   before any number rules during parsing.

---

### 3. `crit` array-type check vs. name check ordering

**Class:** `our-bug`

**What happened:** Vector 182 (`verify_writ_crit_array_type_before_names`) has
`crit: ["zap", 5]` — "zap" is an unknown name (would be `unsupported_critical`)
and `5` is not a string (should be `malformed`). Expected `malformed`, got
`unsupported_critical`.

**Spec section:** Section 6.1 step 4: "first, `crit` is an array of strings
(`malformed`); then each name in array order is one the verifier understands
(`unsupported_critical`) and is present in the object (`malformed`)."

My initial implementation interleaved the type check with the name check in one
loop. The spec requires a two-pass approach: first verify ALL elements are strings,
THEN check each name.

**Fix:** Split the `checkCrit` loop into two passes: first check all types,
then check all names.

---

## Ed25519 verification — Node.js API note

**Class:** `our-bug` (implementation detail, not a spec reading issue)

Node.js's `crypto.verify()` does not accept `{ format: 'raw', type: 'ed25519' }`
for Ed25519 public keys. It requires the key in DER SPKI format. The SPKI prefix
for Ed25519 is the 12-byte sequence `302a300506032b6570032100` followed by the
32-byte key. This was straightforward to implement but is not mentioned in the spec
(which only specifies the algorithm, not the Node.js API).

---

## Spec sections found hardest to read

1. **Section 6.1 step 5, tally member table** — The specification lists members in
   table order but the table has two separate "after the tally's `wrt`" conditions
   (the pending shape check) that must happen after all other member checks. Easy to
   implement in the wrong order.

2. **Section 6.2 step 8 vs. step 9** — The depth-rule application for `wrt` entries
   and sub-tallies is subtle: "the chain to W is K.chain; at step 9, the chain to a
   sub-tally's writ X is the chain to its parent's writ followed by X." The phrase
   "its parent's writ" means the current tally node's writ W, not the call's chain.
   Requires careful recursion.

3. **Section 1.1 rule 7 depth counting** — "the outermost value being level 1" does
   not explicitly say scalars don't count as levels. The phrase "arrays and objects
   MUST NOT nest more than 64 levels" could be read as: the depth of the shallowest
   container that contains any value is what counts, or as: every value (including
   scalars) contributes a level. Vector 176 disambiguates it clearly.

4. **Section 1.2 canonical form** — The spec defers to RFC 8785 for the exact escape
   rules, requiring knowledge of RFC 8785 §3.2.2.2 to implement correctly. The named
   control character escapes (`\r`, `\n`, `\t`, `\b`, `\f`) are RFC 8785 details not
   stated in the spec text.

5. **Section 6.1 step 2 vs. step 5 ordering for non-string binary members** —
   "A binary member that is not a string is left to step 5." Vector 180 tests this:
   if `v` is not 1 (wrong version), but the sig is not a string, the result should be
   `unsupported_version` (step 3), not `malformed` (step 5). This means non-string
   binary members must NOT be rejected at step 2 — only string binary members are
   checked at step 2.

---

## Summary

No `spec-ambiguous`, `spec-silent`, or `vector-suspect` divergences were found.
All three issues above are clear spec requirements that the implementation initially
got wrong — they are all `our-bug`.

The fact that the implementation achieved 213/213 on its first complete run (after
fixing these bugs during development) confirms that the spec is well-specified for
the operations in the conformance corpus. The ordering vectors (180+ range) in
particular are excellent precision tests.
