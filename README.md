# writ-ts

An independent TypeScript implementation of the [Writ protocol](https://github.com/pete-builds/writ-protocol)
(spec v0.1): a verifier and an executor, written from the specification alone for the "stranger test"
in the upstream roadmap. It has zero runtime dependencies (Node 24, `node:crypto` only).

Read [PROVENANCE.md](PROVENANCE.md) first. It says what was and was not read, how the blind executor
run was set up, and that the code was written by an AI coding agent under human direction.

## Results against the upstream corpus (commit 6552968)

| Part | Blind first run | Final | Notes |
|---|---|---|---|
| Verifier, 213 vectors | not blind (see below) | 213/213 | vectors were used during development |
| Executor, 22 scenarios (140 steps) | **19/22 scenarios, 136/140 steps** | 22/22, 140/140 | one bug, one cause: a repeat `sys/undo` omitted the stored reversal's result body |

Every tally signature in the blind executor run that the scenarios check matched upstream byte for byte.

Spec findings for upstream are in [reports/divergences.md](reports/divergences.md):
- **Section 1.1 rule 7** (spec-ambiguous): "the outermost value being level 1" allows two readings of
  whether a scalar adds a nesting level. Vector 176 encodes one.
- **Section 9.1** (spec-silent): the `err.code` of the `canceled` tally a revoke answers for a call not
  yet accepted is never stated, and `canceled` is not a section 11 reason code. No vector or scenario
  covers it, so two conforming executors can sign different bytes.

## Run it

```sh
npm install                 # dev dependencies only: typescript, @types/node
npm run conformance         # verifier: 213 vectors -> reports/latest-run.txt
npm run scenarios:score     # executor: runs the 22 scenarios into out/ and scores them
npm test                    # 59 unit tests
npm run typecheck
```

## Layout

```
spec/                 upstream spec, unmodified
conformance/          upstream vectors and scenarios, unmodified
src/                  jcs, encoding (base64url, base58btc, did:key, Ed25519), bounds,
                      verify-*, ops, runner; executor, exec-*, sign-tally, scenario-driver
scripts/score-scenarios.py   compares out/ with the scenarios' expected answers
reports/
  first-run.txt, final-run.txt       verifier runs
  exec-first-run-score.txt           blind executor score, untouched
  exec-first-run-out/                the blind executor output, untouched
  exec-final-run-score.txt           after the one fix
  exec-notes.md                      ambiguities the executor builder recorded while building
  divergences.md                     findings, with a coordinator review of each classification
```

No source file exceeds 350 lines. Apache 2.0, the same license as upstream.
