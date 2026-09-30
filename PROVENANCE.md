# Provenance and independence

This is an independent TypeScript implementation of the Writ protocol, written for the
"stranger test" in the upstream roadmap (github.com/pete-builds/writ-protocol, README, step 2).

## Inputs copied from upstream (commit 655296860f415ecc067b7ea9b500beac6dce7cdb, Apache-2.0)
- `spec/writ-v0.1.md`: docs/spec/writ-v0.1.md, unmodified
- `conformance/vectors/`: conformance/vectors/, unmodified (213 files)
- `conformance/scenarios/`: conformance/scenarios/, unmodified (22 files)
- `LICENSE`: upstream Apache 2.0 license

## Independence rule
The implementation is written from `spec/` alone. No part of upstream `impl/` (the Go reference
or the Python second implementation), upstream `conformance/ADVERSARIAL.md`, or upstream design
docs was read while building it. Where the spec points at an upstream implementation file (for
example impl/python/DIVERGENCES.md at spec line 10, and impl/go/jws in Appendix D), that file
was deliberately not consulted.

## How it was built
Written by an AI coding agent (agent-afk, a Claude model) directed by Griffin Long, in a
workspace that contained only the files listed above. Disclosed so reviewers can weigh the
result: this counts as an independent reading of the text, not as a human stranger.
