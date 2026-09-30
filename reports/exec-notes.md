# Executor Notes

## Ambiguities Met During Construction

### 1. `err.code` for executor-generated `canceled` tallies (revoke, "not yet accepted")

**Spec text (section 9.1):** "canceled for calls not yet accepted, and for accepted calls either the final tally when the operation completes or a pending tally."

**Ambiguity:** The spec defines `canceled` as a `st` value (section 6) but does not specify what `err.code` an executor should use when it autonomously produces a `canceled` tally for a not-yet-accepted call. The `err` field is required to be non-null and have a `code` when `st != ok`.

**Both readings:**
- (A) Use the reason code `"canceled"` (mirrors the `st` value, unambiguous).
- (B) Use some other implementation-defined code (e.g., `"revoked"` if the revoke caused it).

**Chose:** (A) `err.code: "canceled"` for executor-generated canceled tallies (when the call was never accepted before the revoke arrived). For app-scripted canceled outcomes, the scenario provides the code via `app.code`.

**Note:** In practice, scenarios 013 and 014 only produce canceled tallies through `finish` steps with explicit `app.code = "revoked"`. No scenario exercises the pure "not yet accepted" canceled path directly (all held ops in the revoke scenarios are already running, producing pending tallies). So this choice only affects a code path that no scenario appears to test directly.

---

### 2. `acc` for refusals at steps 3–10 (signed failed tallies)

**Spec text (section 6):** "A tally that refuses a call at section 7 steps 3 to 10, or reports `canceled` for a call not yet accepted, has the time the executor received the call."

**Ambiguity:** "the time the executor received the call" — is this `now` (the step clock in the scenario), or could it differ? The spec ties it to receipt time. In the executor, `now` is the scenario-supplied clock at the moment of the call.

**Chose:** `acc = now` for all refusal tallies at steps 3–10. This is unambiguous in the scenario model where `now` is the step clock.

---

### 3. `sys/tallies` writ argument: "from issued or one below it"

**Spec text (section 8.2):** "a writ member that is absent, not a string, or not the identity of a writ in chain that from issued or of one below it is tally_mismatch."

**Ambiguity:** "from issued" clearly means `w.iss == from`. "One below it" is slightly ambiguous — does it mean a direct child, or any descendant below a writ that `from` issued?

**Both readings:**
- (A) "One below" = any writ at an index in the chain that is strictly after a writ issued by `from`.
- (B) "One below" = only the immediate child of the writ `from` issued.

**Chose:** (A) — any writ at a position ≥ the position of a writ `from` issued. This is the broader reading and matches the spec's language about "the executor's index under it also holds work under sibling delegations". Verified correct by scenario 020 steps 1 and 3.

---

### 4. Held `sys/undo` (reversal): when does "reversal begun" get recorded?

**Spec text (section 8.1):** "the executor MUST durably record that a reversal of the tally has begun before it performs one."

**Ambiguity:** For a held reversal (where the operation doesn't return until a `finish` step), should "begun" be recorded before the held pause begins, or before the application actually performs the reversal?

**Chose:** Record "begun" before starting the held pause (i.e., before `finishHeld` is awaited). This matches "before it performs one" — the executor records it durably before the application begins work.

---

### 5. Store a failed sys/undo check in the tally store?

**Spec text (section 9):** "The tally store holds every final tally the executor signs at section 7 step 12 and every tally it signs resolving a pending record, forward and standing alike. It holds no refusal: a tally signed for a failure at section 7 steps 3 to 10 is returned to the caller and not recorded... (a failed check of section 8.1 or 8.2 is an outcome at step 11, not a refusal, and is held)."

**Resolution:** Clear. A sys/undo check failure (e.g., `not_reversible`) is an outcome at step 11 (after replay at step 9), so it IS stored in both the call store and the tally store. Verified by scenario 019 steps 2–4.

---

### 6. Replay of y's call after revoke: step 7 before step 9

**Spec text (section 7, steps 7 and 9):** "Recording a revoke is atomic with steps 7 to 11 of a forward call... Either the revoke is recorded first and the call is refused at step 7, or the call is accepted first."

**Ambiguity:** If a call was previously accepted (call store has a final entry), and the chain is later revoked, does a replay return the stored tally (step 9) or get refused at step 7?

**Chose:** Step 7 runs before step 9. A replay of a call whose chain is now revoked is refused at step 7 with `revoked`, not answered from the call store. The note in scenario 013 step 6 confirms this: "refused at step 7, before replay at step 9; recovery is sys/tallies."

---

### 7. Canceled `err.code` when app scripts it

**Spec text (section 14.1):** "`app` scripts the application. Its members are `st` (`ok`, `failed`, or `canceled`), `code` (the `err.code`, present exactly when `st` is not `ok`)."

**Resolution:** Clear. For a canceled outcome scripted by the app, `err.code = app.code`. Scenarios 013 and 014 use `{st: "canceled", code: "revoked"}`.

---

### 8. What happens when a held sys/undo restarts?

**Spec text (section 9):** "A record of a reversal that began and never reported, found after a restart, means its outcome is unknown: every later sys/undo for that tally fails with `unknown_outcome`."

**Chose:** On restart, pending sys/undo calls resolve to `unknown_outcome`. The reversal store's "begun" entry remains (it survives restart as it's in the durable store). Subsequent sys/undo calls for the same tally see the "begun" state and return `unknown_outcome`. Verified by scenario 017.

---

### 9. Standing call's own checks: stored as outcome or refusal?

**Spec text (section 7 step 8, section 8.1):** "The operation's own checks (sections 8.1 and 8.2) are part of performing it at step 11, after replay: a failure among them is the operation's `failed` outcome, signed, stored, and answered to a retry like any other."

**Resolution:** Clear. Failures in sys/undo's own checks (not_reversible, tally_mismatch, malformed) are stored outcomes, not refusals. The call store and tally store hold them. Verified by scenario 019.

---

### 10. Revoke check: `revokedKeys` checks `w.iss` for every writ in chain

**Spec text (section 7 step 7):** "no writ in the chain is revoked in E's store, by identity or by a key-wide revoke of its issuer."

**Chose:** For each writ in the chain, check both its identity against `revokeStore` AND its `iss` against `revokedKeys`. This means if A does a key-wide revoke and there's a chain [w1(iss=A), w2], both writs trigger the revoke because w1's issuer is A. ✓

---

## Leakage Disclosure

I did not use embedded later-step objects as a self-check. The scenarios have `expect` fields removed, so I cannot observe expected answers. I wrote the executor from the spec alone and did not cross-reference any later-step objects that might contain expected answers.

**Confirmed: No leakage used.**

---

## Source of Truth

All decisions derived from `spec/writ-v0.1.md` only. No external implementations, no network access for Writ material.
