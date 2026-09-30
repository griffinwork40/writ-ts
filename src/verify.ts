/**
 * Main verification exports — re-exports from split modules.
 * Split for the 350-line limit:
 *   verify-primitives.ts: types, depth, binary, signing, crit, attenuation
 *   verify-writ.ts:       section 6.1 (writ), section 4 (chain), section 7 (call)
 *   verify-tally.ts:      section 6.2 (tally tree), section 9.1 (revoke)
 */

export type { Reason } from "./verify-primitives.ts";
export { VerifyError, checkNestingDepth, checkBinaryStr, buildSigningInput,
         checkSignature, checkCrit, writIdentity, checkAttenuation,
         checkDepthBound } from "./verify-primitives.ts";
export { verifySingleWrit, verifyChain, verifyCallFull } from "./verify-writ.ts";
export { verifyTallyTree, verifyRevoke } from "./verify-tally.ts";
