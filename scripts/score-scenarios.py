#!/usr/bin/env python3
"""Score a builder's executor answers against the held Writ scenario answers.

Usage: writ-score.py <answers_dir> <builder_out_dir> [report_path]
builder_out_dir/<scenario file name> must be a JSON array with one answer per step.
Equality is parsed-JSON equality, which matches canonical-form comparison for
Writ objects (integers only, no duplicate keys).
"""
import json, os, sys

ans_dir, out_dir = sys.argv[1], sys.argv[2]
report = sys.argv[3] if len(sys.argv) > 3 else None
lines, passed, total_steps, ok_steps = [], 0, 0, 0
files = sorted(f for f in os.listdir(ans_dir) if f.endswith(".json"))
for f in files:
    steps = json.load(open(os.path.join(ans_dir, f)))["steps"]
    path = os.path.join(out_dir, f)
    if not os.path.exists(path):
        lines.append(f"FAIL {f}: no output file")
        total_steps += len(steps)
        continue
    try:
        got = json.load(open(path))
    except Exception as e:
        lines.append(f"FAIL {f}: unreadable output ({e})")
        total_steps += len(steps)
        continue
    first_bad = None
    for i, s in enumerate(steps):
        total_steps += 1
        g = got[i] if isinstance(got, list) and i < len(got) else None
        if g == s["expect"]:
            ok_steps += 1
        elif first_bad is None:
            first_bad = (i, s, g)
    if first_bad is None:
        passed += 1
        lines.append(f"PASS {f}")
    else:
        i, s, g = first_bad
        lines.append(f"FAIL {f}: first bad step {i} (do={s['do']}, note={s.get('note','')!r})")
        lines.append(f"     expected: {json.dumps(s['expect'], sort_keys=True)[:600]}")
        lines.append(f"     got:      {json.dumps(g, sort_keys=True)[:600]}")
lines.append(f"Scenarios: {passed}/{len(files)} pass; steps: {ok_steps}/{total_steps} match")
text = "\n".join(lines)
print(text)
if report:
    open(report, "w").write(text + "\n")
