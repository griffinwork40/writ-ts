DRAFT, not posted. Title: Stranger test: TypeScript verifier, 213/213, one spec ambiguity (section 1.1 rule 7)

## What was built
A verifier in TypeScript (Node 24, zero runtime dependencies), written from `docs/spec/writ-v0.1.md`
at commit 6552968 plus the `conformance/vectors/` corpus. It never read `impl/`, the design docs, or
`conformance/ADVERSARIAL.md`, including the two impl files the spec itself points to.
Executor scenarios are not attempted yet.

Disclosure, since it affects how much this counts: it was written by an AI coding agent (agent-afk,
a Claude model) that I directed, in a workspace holding only the spec and the corpus. So it is an
independent reading of the text, but not a human stranger, and possibly not a different model
family from your own tooling.

## Result
213/213 vectors agree, verdict and reason. One caveat I want to be upfront about: the run was not
blind. The agent used the vectors while developing, so I can't give you a clean "first contact"
divergence count. Three issues came up along the way; two were plain misreadings of explicit text,
and one is a real ambiguity.

## Finding: section 1.1 rule 7, how nesting depth is counted
> Arrays and objects MUST NOT nest more than 64 levels deep, the outermost value being level 1.

"The outermost *value* being level 1" gives levels to values, which supports reading a scalar inside a
level-64 array as level 65, and so as `too_large`. The subject of the sentence ("arrays and objects")
supports the reading vector 176 encodes, where only containers count. Our implementation first took
the value reading and failed 176.

Suggested wording: "the outermost array or object being level 1; a scalar does not add a level."
Or add a vector with a scalar at level 65 inside a level-64 array, named for the rule.

## Places that read correctly but took care
(From the implementer's notes; not divergences.)
- Section 6.1 step 2 vs step 5: "a binary member that is not a string is left to step 5" is easy to
  miss, and vector 180 is what catches it.
- Section 6.2 steps 8 and 9: "the chain to a sub-tally's writ X is the chain to its parent's writ
  followed by X" is precise, but it is the densest paragraph to implement.
- Section 1.2 defers the escape rules to RFC 8785 section 3.2.2.2. That's fine, but a one-line
  reminder that the five named escapes (\b \t \n \f \r) apply would save a stranger a trip.

## Code
<link once published>. Next: the executor scenarios.
