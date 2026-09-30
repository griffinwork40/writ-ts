Stranger test: TypeScript verifier and executor. Blind executor run 19/22, two spec findings

Hi Pete, following up from the Threads thread. Here's a stranger test report: an independent TypeScript implementation of both the verifier and the executor, built from `docs/spec/writ-v0.1.md` and the conformance corpus at 6552968.

Code: REPO_URL

## Disclosure first
It was written by an AI coding agent (agent-afk, a Claude model) that I directed, in a workspace holding only the spec and the corpus. It never read `impl/`, the design docs, or `conformance/ADVERSARIAL.md`, including the two impl files the spec itself points to. So this is an independent reading of the text, not a human stranger, and possibly not a different model family from your tooling. `PROVENANCE.md` has the details.

## Results
| | Blind first run | Final |
|---|---|---|
| Verifier, 213 vectors | not blind | 213/213 |
| Executor, 22 scenarios / 140 steps | **19/22, 136/140** | 22/22, 140/140 |

- **Verifier:** the agent used the vectors while developing, so I can't give you a clean first-contact count. I'm saying that upfront rather than reporting a number that looks better than it is.
- **Executor:** this one is blind. It was built in a copy where every scenario step's `expect` was removed. I held the answers and scored its first output once. Every tally it signed matched yours byte for byte.
- **The one executor miss** was ours, and section 8.2 is explicit about it: a repeat `sys/undo` after a successful reversal returned the right tally but left out `res`.
- **Blindness caveat:** later steps sometimes carry earlier objects (an undo carries the tally it reverses), so the blinding isn't perfect.

## Finding 1: section 9.1, the `err.code` of a revoke's `canceled` tally for a call not yet accepted (spec-silent)
Section 9.1 says a revoke answers "`canceled` for calls not yet accepted", but nothing says what `err.code` that tally carries. `canceled` isn't a section 11 reason code. The 2026-09-23 revision pinned the pending tally's `err` (`{"code":"pending"}`) but not this one, and no vector or scenario reaches this path. Our executor picked `"canceled"`; `revoked` looks like the natural choice. Either way, two conforming executors can sign different bytes here today.

Suggested fix: name the code in 9.1, and add a scenario where a revoke arrives for a call received but not yet accepted.

## Finding 2: section 1.1 rule 7, how nesting depth is counted (ambiguous)
> Arrays and objects MUST NOT nest more than 64 levels deep, the outermost value being level 1.

"The outermost *value*" gives levels to values, which supports reading a scalar inside a level-64 array as level 65, and so as `too_large`. The sentence's subject ("arrays and objects") supports the reading vector 176 encodes. We first took the value reading.

Suggested wording: "the outermost array or object being level 1; a scalar does not add a level."

## Read correctly, but took care
- **6.1 step 2 vs step 5** ("a binary member that is not a string is left to step 5"): easy to miss, and vector 180 is what catches it.
- **6.2 steps 8 and 9**: the chain accumulating through sub-tallies is the densest paragraph to implement.
- **1.2**: deferring the escape rules to RFC 8785 section 3.2.2.2 is fine, but a one-line reminder about the five named escapes would save a trip.

Happy to turn either finding into a PR (spec text plus the vector or scenario) if you'd like one. Otherwise, nice work: the executor section in particular reads very tightly.
