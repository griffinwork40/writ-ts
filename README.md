# writ-ts

An independent TypeScript verifier for the [Writ protocol](spec/writ-v0.1.md), written from the specification alone as part of the "stranger test" described in the upstream roadmap.

See [PROVENANCE.md](PROVENANCE.md) for the independence rule and what was deliberately not read.

## What it is

This implements all seven conformance operations defined in spec section 14:

| Operation | Checks |
|---|---|
| `canonicalize` | Sections 1.1 and 1.2 (JCS with Writ integer restrictions) |
| `narrows` | Section 3 bound narrowing |
| `satisfies` | Section 3 bound satisfaction |
| `verify_writ` | Section 6.1 (single writ object) |
| `verify_chain` | Section 4 (chain verification as operation) |
| `verify_call` | Sections 6.1 + 4 + 5 + 7 steps 1-2 (no executor state) |
| `verify_tally` | Section 6.2 (full tally tree) |
| `verify_revoke` | Section 9.1 (revoke verification) |

**Not implemented:** executor scenarios (section 14.1). Those require stateful executor behavior (count store, call store, tally store, revoke store) and are out of scope for this verification-only pass.

## Runtime dependencies

Zero. Uses only:
- `node:crypto` for Ed25519 (SPKI DER format) and SHA-256
- JCS, base64url, base58btc, and did:key implemented from scratch

## How to run

```sh
# Install dev dependencies (typescript + @types/node only)
npm install

# Run the full conformance corpus (213 vectors)
node --experimental-strip-types src/runner.ts

# Run unit tests
node --test src/test.ts

# Type check (no emit)
npx tsc --noEmit
```

## Results

**First committed run:** 213/213 pass (not blind: vectors were used during development; see reports/divergences.md)  
**Final run:** 213/213 pass  
**Unit tests:** 44/44 pass  
**`tsc --noEmit`:** clean

## Files

```
src/
  encoding.ts          # base64url, base58btc, did:key, SHA-256, Ed25519
  jcs.ts               # JSON Canonicalization Scheme (RFC 8785)
  bounds.ts            # section 3: bound types, narrowing, satisfaction
  verify-primitives.ts # shared verification primitives (types, depth, binary, signing)
  verify-writ.ts       # section 6.1 (writ), section 4 (chain), section 7 (call)
  verify-tally.ts      # section 6.2 (tally tree), section 9.1 (revoke)
  verify.ts            # re-export facade
  ops.ts               # conformance operation handlers
  runner.ts            # conformance runner (reads conformance/vectors/)
  test.ts              # unit tests

reports/
  first-run.txt        # first committed run (after development-time fixes; not a blind run)
  final-run.txt        # final run results
  divergences.md       # analysis of every deviation from expected behavior
```

No source file exceeds 350 lines.

## Divergences

See [reports/divergences.md](reports/divergences.md) for the full analysis.

All bugs found were `our-bug` (clear spec requirements misimplemented). No
`spec-ambiguous`, `spec-silent`, or `vector-suspect` items were identified.

The three categories of bugs:
1. **RFC 8785 escape rules** — named control character escapes (`\r`, `\n`, etc.) and surrogate-pair handling in canonical string output.
2. **Nesting depth counting** — scalars should not count as a nesting level; depth check must happen before number rules in the parser.
3. **`crit` two-pass ordering** — all elements' types checked before any name is looked up.

## Independence statement

See [PROVENANCE.md](PROVENANCE.md). No upstream implementation code, design docs,
or `conformance/ADVERSARIAL.md` was read during development. The implementation
was built from `spec/writ-v0.1.md` alone. General cryptographic knowledge
(Ed25519/RFC 8032, SHA-256, RFC 8785 JCS, did:key/multicodec/base58btc) was
recalled from training, not from Writ-specific code.
